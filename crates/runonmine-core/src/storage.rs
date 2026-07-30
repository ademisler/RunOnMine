use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::approval::{
    ApprovalDecision, ApprovalPrincipal, ApprovalRequest, ApprovalStatus, ApprovalTimeoutResult,
    PersistentGrant,
};
use crate::approval_notifications::{
    ApprovalNotificationMetrics, ApprovalNotificationSubscription, ApprovalNotifications,
};
use crate::audit::{AuditEvent, AuditOutcome};
use crate::audit_mac::AuditMacKey;

pub const AUDIT_RETENTION_DAYS: i64 = 30;
pub const AUDIT_MAX_BYTES: u64 = 100 * 1024 * 1024;
const STATE_SCHEMA_VERSION: i64 = 4;
const STATE_DB_QUEUE_CAPACITY: usize = 128;
const STATE_DB_ENQUEUE_TIMEOUT: StdDuration = StdDuration::from_secs(1);
const STATE_DB_ENQUEUE_RETRY: StdDuration = StdDuration::from_millis(1);

#[path = "storage/audit_store.rs"]
mod audit_store;
#[path = "storage/migration.rs"]
mod migration;

use audit_store::{
    append_audit_connection, append_audit_row, audit_tail_connection, prune_audit_connection,
    verify_audit_chain_full_connection, verify_audit_chain_incremental_connection,
};
use migration::migrate;

type DbJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

enum DbMessage {
    Run(DbJob),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct StateStoreMetrics {
    pub queue_capacity: usize,
    pub queued: usize,
    pub active: usize,
    pub high_watermark: usize,
    pub rejected: u64,
    pub completed: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, serde::Serialize)]
pub struct AuditVerificationReport {
    pub valid: bool,
    pub full: bool,
    pub checkpoint_sequence: u64,
    pub tail_sequence: u64,
    pub records_verified: usize,
}

#[derive(Debug, Default)]
struct WorkerCounters {
    queued: usize,
    active: usize,
    high_watermark: usize,
    rejected: u64,
    completed: u64,
}

struct SqliteWorker {
    sender: Option<mpsc::SyncSender<DbMessage>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    counters: Arc<Mutex<WorkerCounters>>,
    queue_capacity: usize,
    enqueue_timeout: StdDuration,
}

impl std::fmt::Debug for SqliteWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteWorker")
            .field("metrics", &self.metrics())
            .field("enqueue_timeout", &self.enqueue_timeout)
            .finish_non_exhaustive()
    }
}

impl SqliteWorker {
    fn start(connection: Connection) -> Result<Self> {
        Self::start_with_options(
            connection,
            STATE_DB_QUEUE_CAPACITY,
            STATE_DB_ENQUEUE_TIMEOUT,
        )
    }

    fn start_with_options(
        mut connection: Connection,
        queue_capacity: usize,
        enqueue_timeout: StdDuration,
    ) -> Result<Self> {
        if queue_capacity == 0 {
            bail!("state database worker queue capacity must be positive");
        }
        if enqueue_timeout.is_zero() {
            bail!("state database worker enqueue timeout must be positive");
        }
        let (sender, receiver) = mpsc::sync_channel::<DbMessage>(queue_capacity);
        let counters = Arc::new(Mutex::new(WorkerCounters::default()));
        let worker_counters = Arc::clone(&counters);
        let thread = std::thread::Builder::new()
            .name("runonmine-state-db".to_owned())
            .spawn(move || {
                while let Ok(DbMessage::Run(job)) = receiver.recv() {
                    {
                        let mut counters = lock_counters(&worker_counters);
                        counters.queued = counters.queued.saturating_sub(1);
                        counters.active = counters.active.saturating_add(1);
                    }
                    job(&mut connection);
                    let mut counters = lock_counters(&worker_counters);
                    counters.active = counters.active.saturating_sub(1);
                    counters.completed = counters.completed.saturating_add(1);
                }
            })
            .context("failed to start state database worker")?;
        Ok(Self {
            sender: Some(sender),
            thread: Mutex::new(Some(thread)),
            counters,
            queue_capacity,
            enqueue_timeout,
        })
    }

    fn call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, receive) = mpsc::sync_channel(1);
        self.enqueue_sync(DbMessage::Run(Box::new(move |connection| {
            let _ignored = reply.send(operation(connection));
        })))?;
        receive
            .recv()
            .map_err(|_| anyhow!("state database worker stopped unexpectedly"))?
    }

    async fn call_async<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, receive) = oneshot::channel();
        self.enqueue_async(DbMessage::Run(Box::new(move |connection| {
            let _ignored = reply.send(operation(connection));
        })))
        .await?;
        receive
            .await
            .map_err(|_| anyhow!("state database worker stopped unexpectedly"))?
    }

    fn enqueue_sync(&self, mut message: DbMessage) -> Result<()> {
        let sender = self
            .sender
            .as_ref()
            .context("state database worker is unavailable")?
            .clone();
        let deadline = Instant::now() + self.enqueue_timeout;
        loop {
            match self.try_enqueue(&sender, message) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    message = returned;
                    if Instant::now() >= deadline {
                        self.record_rejected();
                        bail!(
                            "state database worker queue remained full for {} ms",
                            self.enqueue_timeout.as_millis()
                        );
                    }
                    std::thread::sleep(STATE_DB_ENQUEUE_RETRY);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.record_rejected();
                    bail!("state database worker is unavailable");
                }
            }
        }
    }

    async fn enqueue_async(&self, mut message: DbMessage) -> Result<()> {
        let sender = self
            .sender
            .as_ref()
            .context("state database worker is unavailable")?
            .clone();
        let deadline = Instant::now() + self.enqueue_timeout;
        loop {
            match self.try_enqueue(&sender, message) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Full(returned)) => {
                    message = returned;
                    if Instant::now() >= deadline {
                        self.record_rejected();
                        bail!(
                            "state database worker queue remained full for {} ms",
                            self.enqueue_timeout.as_millis()
                        );
                    }
                    tokio::time::sleep(STATE_DB_ENQUEUE_RETRY).await;
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    self.record_rejected();
                    bail!("state database worker is unavailable");
                }
            }
        }
    }

    fn try_enqueue(
        &self,
        sender: &mpsc::SyncSender<DbMessage>,
        message: DbMessage,
    ) -> std::result::Result<(), mpsc::TrySendError<DbMessage>> {
        let mut counters = self.lock_counters();
        if counters.queued >= self.queue_capacity {
            return Err(mpsc::TrySendError::Full(message));
        }
        match sender.try_send(message) {
            Ok(()) => {
                counters.queued = counters.queued.saturating_add(1);
                counters.high_watermark = counters.high_watermark.max(counters.queued);
                Ok(())
            }
            Err(error) => Err(error),
        }
    }

    fn record_rejected(&self) {
        let mut counters = self.lock_counters();
        counters.rejected = counters.rejected.saturating_add(1);
    }

    fn metrics(&self) -> StateStoreMetrics {
        let counters = self.lock_counters();
        StateStoreMetrics {
            queue_capacity: self.queue_capacity,
            queued: counters.queued,
            active: counters.active,
            high_watermark: counters.high_watermark,
            rejected: counters.rejected,
            completed: counters.completed,
        }
    }

    fn lock_counters(&self) -> MutexGuard<'_, WorkerCounters> {
        lock_counters(&self.counters)
    }
}

fn lock_counters(counters: &Mutex<WorkerCounters>) -> MutexGuard<'_, WorkerCounters> {
    counters
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Drop for SqliteWorker {
    fn drop(&mut self) {
        self.sender.take();
        if let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ignored = thread.join();
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub event: AuditEvent,
    pub previous_hash: String,
    pub record_hash: String,
    pub record_mac: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConnectorAuthorizationCleanup {
    pub approvals: usize,
    pub temporary_grants: usize,
    pub persistent_grants: usize,
}

impl ConnectorAuthorizationCleanup {
    #[must_use]
    pub const fn total(self) -> usize {
        self.approvals + self.temporary_grants + self.persistent_grants
    }
}

#[derive(Debug)]
struct StateMigrationLock(File);

impl StateMigrationLock {
    fn acquire(database: &Path) -> Result<Self> {
        let path = state_migration_lock_path(database);
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to use a symlinked state migration lock");
        }
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let file = options.open(&path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        file.lock_exclusive()
            .context("failed to lock state schema migration")?;
        Ok(Self(file))
    }
}

impl Drop for StateMigrationLock {
    fn drop(&mut self) {
        let _ignored = self.0.unlock();
    }
}

fn state_migration_lock_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(".migration.lock");
    PathBuf::from(path)
}

#[derive(Clone, Debug)]
pub struct StateStore {
    worker: Arc<SqliteWorker>,
    audit_mac: AuditMacKey,
    approval_notifications: ApprovalNotifications,
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        if path
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            bail!(
                "refusing to open symlinked state database: {}",
                path.display()
            );
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            restrict_directory(parent)?;
        }
        let audit_mac = AuditMacKey::load_or_create(path)?;
        let _migration_lock = StateMigrationLock::acquire(path)?;
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open state database at {}", path.display()))?;
        configure_connection(&connection)?;
        migrate(&connection, &audit_mac)?;
        restrict_sqlite_files(path)?;
        let approval_notifications = ApprovalNotifications::for_state_db(path)?;
        Ok(Self {
            worker: Arc::new(SqliteWorker::start(connection)?),
            audit_mac,
            approval_notifications,
        })
    }

    pub fn in_memory() -> Result<Self> {
        let audit_mac = AuditMacKey::generate()?;
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        migrate(&connection, &audit_mac)?;
        Ok(Self {
            worker: Arc::new(SqliteWorker::start(connection)?),
            audit_mac,
            approval_notifications: ApprovalNotifications::in_memory(),
        })
    }

    fn call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        self.worker.call(operation)
    }

    async fn call_async<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        self.worker.call_async(operation).await
    }

    #[must_use]
    pub fn worker_metrics(&self) -> StateStoreMetrics {
        self.worker.metrics()
    }

    #[must_use]
    pub fn subscribe_approval_changes(&self) -> ApprovalNotificationSubscription {
        self.approval_notifications.subscribe()
    }

    #[must_use]
    pub fn approval_notification_metrics(&self) -> ApprovalNotificationMetrics {
        self.approval_notifications.metrics()
    }

    pub fn insert_approval(&self, request: &ApprovalRequest) -> Result<()> {
        let request = request.clone();
        self.call(move |connection| insert_approval_connection(connection, &request))?;
        self.approval_notifications.notify();
        Ok(())
    }

    pub async fn insert_approval_async(&self, request: ApprovalRequest) -> Result<()> {
        self.call_async(move |connection| insert_approval_connection(connection, &request))
            .await?;
        self.approval_notifications.notify();
        Ok(())
    }

    pub fn resolve_approval(&self, id: Uuid, decision: ApprovalDecision) -> Result<bool> {
        let resolved =
            self.call(move |connection| resolve_approval_connection(connection, id, decision))?;
        if resolved {
            self.approval_notifications.notify();
        }
        Ok(resolved)
    }

    pub async fn resolve_approval_async(
        &self,
        id: Uuid,
        decision: ApprovalDecision,
    ) -> Result<bool> {
        let resolved = self
            .call_async(move |connection| resolve_approval_connection(connection, id, decision))
            .await?;
        if resolved {
            self.approval_notifications.notify();
        }
        Ok(resolved)
    }

    pub fn complete_approval_timeout(
        &self,
        id: Uuid,
        event: &AuditEvent,
    ) -> Result<Option<ApprovalTimeoutResult>> {
        let event = event.clone();
        let audit_mac = self.audit_mac.clone();
        let completion = self.call(move |connection| {
            complete_approval_timeout_connection(connection, id, &event, &audit_mac)
        })?;
        if matches!(completion, Some(ApprovalTimeoutResult::ExpiredNow)) {
            self.approval_notifications.notify();
        }
        Ok(completion)
    }

    pub async fn complete_approval_timeout_async(
        &self,
        id: Uuid,
        event: AuditEvent,
    ) -> Result<Option<ApprovalTimeoutResult>> {
        let audit_mac = self.audit_mac.clone();
        let completion = self
            .call_async(move |connection| {
                complete_approval_timeout_connection(connection, id, &event, &audit_mac)
            })
            .await?;
        if matches!(completion, Some(ApprovalTimeoutResult::ExpiredNow)) {
            self.approval_notifications.notify();
        }
        Ok(completion)
    }

    pub fn grant_allows(
        &self,
        connector_id: &str,
        principal: &ApprovalPrincipal,
        tool_name: &str,
        argument_hash: &str,
    ) -> Result<bool> {
        let connector_id = connector_id.to_owned();
        let principal_fingerprint = principal.fingerprint();
        let tool_name = tool_name.to_owned();
        let argument_hash = argument_hash.to_owned();
        self.call(move |connection| {
            grant_allows_connection(
                connection,
                &connector_id,
                &principal_fingerprint,
                &tool_name,
                &argument_hash,
            )
        })
    }

    pub async fn grant_allows_async(
        &self,
        connector_id: String,
        principal: ApprovalPrincipal,
        tool_name: String,
        argument_hash: String,
    ) -> Result<bool> {
        let principal_fingerprint = principal.fingerprint();
        self.call_async(move |connection| {
            grant_allows_connection(
                connection,
                &connector_id,
                &principal_fingerprint,
                &tool_name,
                &argument_hash,
            )
        })
        .await
    }

    pub fn temporary_grant_allows(
        &self,
        connector_id: &str,
        principal: &ApprovalPrincipal,
        tool_name: &str,
        argument_hash: &str,
    ) -> Result<bool> {
        self.grant_allows(connector_id, principal, tool_name, argument_hash)
    }

    pub fn persistent_grants(&self, connector_id: Option<&str>) -> Result<Vec<PersistentGrant>> {
        let connector_filter = connector_id.map(str::to_owned);
        self.call(move |connection| {
            persistent_grants_connection(connection, connector_filter.as_deref())
        })
    }

    pub fn delete_persistent_grant(
        &self,
        connector_id: &str,
        principal_fingerprint: &str,
        tool_name: &str,
        argument_hash: &str,
    ) -> Result<bool> {
        let connector_id = connector_id.to_owned();
        let principal_fingerprint = principal_fingerprint.to_owned();
        let tool_name = tool_name.to_owned();
        let argument_hash = argument_hash.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "DELETE FROM persistent_grants WHERE connector_id = ?1 AND principal_fingerprint = ?2 AND tool_name = ?3 AND argument_hash = ?4",
                params![connector_id, principal_fingerprint, tool_name, argument_hash],
            )? == 1)
        })
    }

    pub fn clear_persistent_grants(&self, connector_id: Option<&str>) -> Result<usize> {
        let connector_id = connector_id.map(str::to_owned);
        self.call(move |connection| {
            connector_id.as_deref().map_or_else(
                || {
                    connection
                        .execute("DELETE FROM persistent_grants", [])
                        .map_err(Into::into)
                },
                |id| {
                    connection
                        .execute(
                            "DELETE FROM persistent_grants WHERE connector_id = ?1",
                            [id],
                        )
                        .map_err(Into::into)
                },
            )
        })
    }

    pub fn clear_connector_authorization(
        &self,
        connector_id: &str,
    ) -> Result<ConnectorAuthorizationCleanup> {
        crate::validate_connector_id(connector_id)?;
        let connector_id = connector_id.to_owned();
        let cleanup = self.call(move |connection| {
            let transaction = connection.transaction()?;
            let approvals = transaction.execute(
                "DELETE FROM approvals WHERE connector_id = ?1",
                [&connector_id],
            )?;
            let temporary_grants = transaction.execute(
                "DELETE FROM temporary_grants WHERE connector_id = ?1",
                [&connector_id],
            )?;
            let persistent_grants = transaction.execute(
                "DELETE FROM persistent_grants WHERE connector_id = ?1",
                [&connector_id],
            )?;
            transaction.commit()?;
            Ok(ConnectorAuthorizationCleanup {
                approvals,
                temporary_grants,
                persistent_grants,
            })
        })?;
        if cleanup.approvals > 0 {
            self.approval_notifications.notify();
        }
        Ok(cleanup)
    }

    pub fn approval_status(&self, id: Uuid) -> Result<Option<ApprovalRequest>> {
        self.call(move |connection| approval_status_connection(connection, id))
    }

    pub async fn approval_status_async(&self, id: Uuid) -> Result<Option<ApprovalRequest>> {
        self.call_async(move |connection| approval_status_connection(connection, id))
            .await
    }

    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRequest>> {
        self.call(pending_approvals_connection)
    }

    pub fn emergency_lock(&self) -> Result<(usize, usize)> {
        let result = self.call(|connection| {
            let transaction=connection.transaction()?; let now=Utc::now().to_rfc3339();
            let denied=transaction.execute("UPDATE approvals SET status = 'denied', resolved_at = ?1, decision = 'deny' WHERE status = 'pending'", [&now])?;
            let cleared=transaction.execute("DELETE FROM temporary_grants", [])?; transaction.commit()?; Ok((denied,cleared))
        })?;
        if result.0 > 0 {
            self.approval_notifications.notify();
        }
        Ok(result)
    }

    pub fn append_audit(&self, event: &AuditEvent) -> Result<String> {
        let event = event.clone();
        let audit_mac = self.audit_mac.clone();
        self.call(move |connection| append_audit_connection(connection, &event, &audit_mac))
    }

    pub async fn append_audit_async(&self, event: AuditEvent) -> Result<String> {
        let audit_mac = self.audit_mac.clone();
        self.call_async(move |connection| append_audit_connection(connection, &event, &audit_mac))
            .await
    }

    pub fn prune_audit(&self) -> Result<usize> {
        let audit_mac = self.audit_mac.clone();
        self.call(move |connection| {
            prune_audit_connection(
                connection,
                chrono::Duration::days(AUDIT_RETENTION_DAYS),
                AUDIT_MAX_BYTES,
                &audit_mac,
            )
        })
    }

    pub fn verify_audit_chain(&self) -> Result<bool> {
        let audit_mac = self.audit_mac.clone();
        self.call(move |connection| {
            Ok(verify_audit_chain_full_connection(connection, &audit_mac)?.valid)
        })
    }

    pub fn verify_audit_chain_incremental(&self) -> Result<AuditVerificationReport> {
        let audit_mac = self.audit_mac.clone();
        self.call(move |connection| {
            verify_audit_chain_incremental_connection(connection, &audit_mac)
        })
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        self.call(move |connection| audit_tail_connection(connection, limit))
    }

    #[cfg(test)]
    fn test_call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        self.call(operation)
    }
}

fn insert_approval_connection(
    connection: &mut Connection,
    request: &ApprovalRequest,
) -> Result<()> {
    connection.execute(
        "INSERT INTO approvals (
            id, connector_id, principal_kind, oauth_client_id, oauth_subject,
            principal_fingerprint, tool_name, argument_summary, argument_hash,
            status, created_at, expires_at, resolved_at, decision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, NULL, NULL)",
        params![
            request.id.to_string(),
            request.connector_id,
            request.principal.storage_kind(),
            request.principal.oauth_client_id(),
            request.principal.oauth_subject(),
            request.principal_fingerprint,
            request.tool_name,
            request.argument_summary,
            request.argument_hash,
            status_name(request.status),
            request.created_at.to_rfc3339(),
            request.expires_at.to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn resolve_approval_connection(
    connection: &mut Connection,
    id: Uuid,
    decision: ApprovalDecision,
) -> Result<bool> {
    let transaction = connection.transaction()?;
    let now = Utc::now().to_rfc3339();
    let status = if decision == ApprovalDecision::Deny {
        "denied"
    } else {
        "approved"
    };
    let changed = transaction.execute(
        "UPDATE approvals SET status = ?1, resolved_at = ?2, decision = ?3
         WHERE id = ?4 AND status = 'pending' AND expires_at > ?2",
        params![status, now, decision_name(decision), id.to_string()],
    )?;
    if changed == 1 && decision == ApprovalDecision::ForTenMinutes {
        transaction.execute(
            "INSERT INTO temporary_grants (
                connector_id, principal_kind, oauth_client_id, oauth_subject,
                principal_fingerprint, tool_name, argument_hash, expires_at
             )
             SELECT connector_id, principal_kind, oauth_client_id, oauth_subject,
                    principal_fingerprint, tool_name, argument_hash, ?1
             FROM approvals WHERE id = ?2
             ON CONFLICT(connector_id, principal_fingerprint, tool_name, argument_hash)
             DO UPDATE SET expires_at = excluded.expires_at",
            params![
                (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                id.to_string()
            ],
        )?;
    } else if changed == 1 && decision == ApprovalDecision::Always {
        transaction.execute(
            "INSERT INTO persistent_grants (
                connector_id, principal_kind, oauth_client_id, oauth_subject,
                principal_fingerprint, tool_name, argument_hash, argument_summary, created_at
             )
             SELECT connector_id, principal_kind, oauth_client_id, oauth_subject,
                    principal_fingerprint, tool_name, argument_hash, argument_summary, ?1
             FROM approvals WHERE id = ?2
             ON CONFLICT(connector_id, principal_fingerprint, tool_name, argument_hash)
             DO UPDATE SET argument_summary = excluded.argument_summary,
                           created_at = excluded.created_at",
            params![Utc::now().to_rfc3339(), id.to_string()],
        )?;
    }
    transaction.commit()?;
    Ok(changed == 1)
}

fn complete_approval_timeout_connection(
    connection: &mut Connection,
    id: Uuid,
    event: &AuditEvent,
    audit_mac: &AuditMacKey,
) -> Result<Option<ApprovalTimeoutResult>> {
    if event.outcome != AuditOutcome::TimedOut {
        bail!("approval timeout audit event must use the timed_out outcome");
    }
    let transaction = connection.transaction()?;
    let stored = transaction
        .query_row(
            "SELECT connector_id, tool_name, argument_hash, status
             FROM approvals WHERE id = ?1",
            [id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let Some((connector_id, tool_name, argument_hash, status)) = stored else {
        return Ok(None);
    };
    if event.connector_id != connector_id
        || event.tool_name != tool_name
        || event.argument_hash != argument_hash
    {
        bail!("approval timeout audit identity does not match the approval row");
    }
    let status = parse_status(&status)?;
    if status != ApprovalStatus::Pending {
        transaction.commit()?;
        return Ok(Some(ApprovalTimeoutResult::Existing(status)));
    }

    let changed = transaction.execute(
        "UPDATE approvals
         SET status = 'expired', resolved_at = ?1, decision = NULL
         WHERE id = ?2 AND status = 'pending'",
        params![event.timestamp.to_rfc3339(), id.to_string()],
    )?;
    if changed != 1 {
        bail!("pending approval timeout transition did not update exactly one row");
    }
    let (_, sequence) = append_audit_row(&transaction, event, audit_mac)?;
    transaction.commit()?;
    if sequence % 128 == 0 {
        let _ignored = prune_audit_connection(
            connection,
            chrono::Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
            audit_mac,
        );
    }
    Ok(Some(ApprovalTimeoutResult::ExpiredNow))
}

fn grant_allows_connection(
    connection: &mut Connection,
    connector_id: &str,
    principal_fingerprint: &str,
    tool_name: &str,
    argument_hash: &str,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "DELETE FROM temporary_grants WHERE expires_at <= ?1",
        [&now],
    )?;
    Ok(connection
        .query_row(
            "SELECT 1 FROM temporary_grants
             WHERE connector_id = ?1 AND principal_fingerprint = ?2
               AND tool_name = ?3 AND argument_hash = ?4 AND expires_at > ?5
             UNION ALL
             SELECT 1 FROM persistent_grants
             WHERE connector_id = ?1 AND principal_fingerprint = ?2
               AND tool_name = ?3 AND argument_hash = ?4
             LIMIT 1",
            params![
                connector_id,
                principal_fingerprint,
                tool_name,
                argument_hash,
                now
            ],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn persistent_grants_connection(
    connection: &mut Connection,
    connector_id: Option<&str>,
) -> Result<Vec<PersistentGrant>> {
    let mut statement = connection.prepare(
        "SELECT connector_id, principal_kind, oauth_client_id, oauth_subject,
                principal_fingerprint, tool_name, argument_summary, argument_hash, created_at
         FROM persistent_grants
         WHERE (?1 IS NULL OR connector_id = ?1)
         ORDER BY created_at DESC, connector_id, principal_fingerprint, tool_name",
    )?;
    let rows = statement.query_map([connector_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
        ))
    })?;
    rows.map(|row| {
        let (connector_id, kind, client_id, subject, fingerprint, tool, summary, hash, created) =
            row?;
        let principal = ApprovalPrincipal::from_storage(&kind, client_id, subject)?;
        if principal.fingerprint() != fingerprint {
            bail!("persistent grant principal fingerprint does not match its identity");
        }
        Ok(PersistentGrant {
            connector_id,
            principal,
            principal_fingerprint: fingerprint,
            tool_name: tool,
            argument_summary: summary,
            argument_hash: hash,
            created_at: DateTime::<Utc>::from_str(&created)
                .context("persistent grant has an invalid timestamp")?,
        })
    })
    .collect()
}

fn approval_status_connection(
    connection: &mut Connection,
    id: Uuid,
) -> Result<Option<ApprovalRequest>> {
    connection
        .query_row(
            "SELECT id, connector_id, principal_kind, oauth_client_id, oauth_subject,
                    principal_fingerprint, tool_name, argument_summary, argument_hash,
                    status, created_at, expires_at, resolved_at, decision
             FROM approvals WHERE id = ?1",
            [id.to_string()],
            map_approval,
        )
        .optional()
        .map_err(Into::into)
}

fn pending_approvals_connection(connection: &mut Connection) -> Result<Vec<ApprovalRequest>> {
    let now = Utc::now().to_rfc3339();
    let mut statement = connection.prepare(
        "SELECT id, connector_id, principal_kind, oauth_client_id, oauth_subject,
                principal_fingerprint, tool_name, argument_summary, argument_hash,
                status, created_at, expires_at, resolved_at, decision
         FROM approvals
         WHERE status = 'pending' AND expires_at > ?1
         ORDER BY created_at",
    )?;
    let rows = statement.query_map([now], map_approval)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

fn map_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRequest> {
    let parse_error = |index: usize, error: anyhow::Error| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, error.into())
    };
    let id_text: String = row.get(0)?;
    let principal_kind: String = row.get(2)?;
    let oauth_client_id: Option<String> = row.get(3)?;
    let oauth_subject: Option<String> = row.get(4)?;
    let principal_fingerprint: String = row.get(5)?;
    let status_text: String = row.get(9)?;
    let created_text: String = row.get(10)?;
    let expires_text: String = row.get(11)?;
    let resolved_text: Option<String> = row.get(12)?;
    let decision_text: Option<String> = row.get(13)?;
    let principal =
        ApprovalPrincipal::from_storage(&principal_kind, oauth_client_id, oauth_subject)
            .map_err(|error| parse_error(2, error))?;
    if principal.fingerprint() != principal_fingerprint {
        return Err(parse_error(
            5,
            anyhow!("approval principal fingerprint does not match its identity"),
        ));
    }
    Ok(ApprovalRequest {
        id: Uuid::parse_str(&id_text).map_err(|error| parse_error(0, error.into()))?,
        connector_id: row.get(1)?,
        principal,
        principal_fingerprint,
        tool_name: row.get(6)?,
        argument_summary: row.get(7)?,
        argument_hash: row.get(8)?,
        status: parse_status(&status_text).map_err(|error| parse_error(9, error))?,
        created_at: DateTime::<Utc>::from_str(&created_text)
            .map_err(|error| parse_error(10, error.into()))?,
        expires_at: DateTime::<Utc>::from_str(&expires_text)
            .map_err(|error| parse_error(11, error.into()))?,
        resolved_at: resolved_text
            .map(|value| {
                DateTime::<Utc>::from_str(&value).map_err(|error| parse_error(12, error.into()))
            })
            .transpose()?,
        decision: decision_text
            .map(|value| parse_decision(&value).map_err(|error| parse_error(13, error)))
            .transpose()?,
    })
}

fn status_name(status: ApprovalStatus) -> &'static str {
    match status {
        ApprovalStatus::Pending => "pending",
        ApprovalStatus::Approved => "approved",
        ApprovalStatus::Denied => "denied",
        ApprovalStatus::Expired => "expired",
    }
}

fn parse_status(value: &str) -> Result<ApprovalStatus> {
    match value {
        "pending" => Ok(ApprovalStatus::Pending),
        "approved" => Ok(ApprovalStatus::Approved),
        "denied" => Ok(ApprovalStatus::Denied),
        "expired" => Ok(ApprovalStatus::Expired),
        _ => bail!("unknown approval status: {value}"),
    }
}

fn decision_name(decision: ApprovalDecision) -> &'static str {
    match decision {
        ApprovalDecision::Once => "once",
        ApprovalDecision::ForTenMinutes => "for_ten_minutes",
        ApprovalDecision::Always => "always",
        ApprovalDecision::Deny => "deny",
    }
}

fn parse_decision(value: &str) -> Result<ApprovalDecision> {
    match value {
        "once" => Ok(ApprovalDecision::Once),
        "for_ten_minutes" => Ok(ApprovalDecision::ForTenMinutes),
        "always" => Ok(ApprovalDecision::Always),
        "deny" => Ok(ApprovalDecision::Deny),
        _ => bail!("unknown approval decision: {value}"),
    }
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    std::path::PathBuf::from(value)
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_sqlite_files(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    for candidate in [
        path.to_path_buf(),
        sqlite_sidecar(path, "-wal"),
        sqlite_sidecar(path, "-shm"),
    ] {
        match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("SQLite state path must be a regular, non-symlink file")
            }
            Ok(_) => std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_sqlite_files(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "storage/tests.rs"]
mod tests;
