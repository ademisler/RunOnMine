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

#[derive(Debug)]
struct StoredAuditRow {
    sequence: u64,
    id: String,
    timestamp: String,
    connector_id: String,
    tool_name: String,
    capability: String,
    outcome: String,
    argument_hash: String,
    summary: String,
    duration_ms: Option<i64>,
    output_bytes: Option<i64>,
    previous_hash: String,
    record_hash: String,
    payload: Vec<u8>,
    record_mac: String,
}

#[derive(Debug)]
struct AuditTailState {
    anchor_hash: String,
    sequence: u64,
    record_hash: String,
    record_mac: String,
    tail_mac: String,
}

fn append_audit_connection(
    connection: &mut Connection,
    event: &AuditEvent,
    audit_mac: &AuditMacKey,
) -> Result<String> {
    let transaction = connection.transaction()?;
    let (record_hash, sequence) = append_audit_row(&transaction, event, audit_mac)?;
    transaction.commit()?;
    if sequence % 128 == 0 {
        prune_audit_connection(
            connection,
            chrono::Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
            audit_mac,
        )?;
    }
    Ok(record_hash)
}

fn append_audit_row(
    connection: &Connection,
    event: &AuditEvent,
    audit_mac: &AuditMacKey,
) -> Result<(String, i64)> {
    let previous: String = connection
        .query_row(
            "SELECT record_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(audit_anchor(connection)?);
    let sequence = next_audit_sequence(connection)?;
    let payload = serde_json::to_vec(event)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous.as_bytes());
    hasher.update(&payload);
    let record_hash = hasher.finalize().to_hex().to_string();
    let record_mac = audit_mac.record_mac(
        u64::try_from(sequence).context("audit sequence is negative")?,
        &previous,
        &record_hash,
        &payload,
    );
    let duration_ms = audit_optional_u64_to_i64(event.duration_ms, "duration")?;
    let output_bytes = audit_optional_u64_to_i64(event.output_bytes, "output size")?;
    connection.execute(
        "INSERT INTO audit_events (
            sequence, id, timestamp, connector_id, tool_name, capability, outcome,
            argument_hash, summary, duration_ms, output_bytes, previous_hash,
            record_hash, payload, record_mac
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            sequence,
            event.id.to_string(),
            event.timestamp.to_rfc3339(),
            event.connector_id,
            event.tool_name,
            event.capability,
            serde_json::to_string(&event.outcome)?,
            event.argument_hash,
            event.summary,
            duration_ms,
            output_bytes,
            previous,
            record_hash,
            payload,
            record_mac,
        ],
    )?;
    update_audit_tail(
        connection,
        audit_mac,
        u64::try_from(sequence).context("audit sequence is negative")?,
        &record_hash,
        &record_mac,
    )?;
    Ok((record_hash, sequence))
}

#[derive(Clone, Debug)]
struct AuditVerificationCheckpoint {
    sequence: u64,
    record_hash: String,
    record_mac: String,
    checkpoint_mac: String,
}

fn verify_audit_chain_full_connection(
    connection: &mut Connection,
    audit_mac: &AuditMacKey,
) -> Result<AuditVerificationReport> {
    let tail = audit_tail_state(connection)?;
    let mut statement = connection.prepare(
        "SELECT sequence, id, timestamp, connector_id, tool_name, capability,
                outcome, argument_hash, summary, duration_ms, output_bytes,
                previous_hash, record_hash, payload, record_mac
         FROM audit_events ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut expected_previous = tail.anchor_hash.clone();
    let mut last = None;
    let mut records_verified = 0_usize;
    while let Some(row) = rows.next()? {
        let stored = map_stored_audit_row(row)?;
        if !verify_stored_audit_row(&stored, &expected_previous, audit_mac)? {
            return Ok(AuditVerificationReport {
                valid: false,
                full: true,
                checkpoint_sequence: 0,
                tail_sequence: tail.sequence,
                records_verified,
            });
        }
        expected_previous.clone_from(&stored.record_hash);
        last = Some((stored.sequence, stored.record_hash, stored.record_mac));
        records_verified = records_verified.saturating_add(1);
    }
    let valid_tail = match last {
        Some((sequence, ref record_hash, ref record_mac)) => {
            tail.sequence == sequence
                && tail.record_hash == *record_hash
                && tail.record_mac == *record_mac
        }
        None => {
            tail.sequence == 0 && tail.record_hash == tail.anchor_hash && tail.record_mac.is_empty()
        }
    } && audit_mac.verifies_tail(
        &tail.tail_mac,
        &tail.anchor_hash,
        tail.sequence,
        &tail.record_hash,
        &tail.record_mac,
    );
    if valid_tail {
        update_audit_verification_checkpoint(connection, audit_mac, &tail)?;
    }
    Ok(AuditVerificationReport {
        valid: valid_tail,
        full: true,
        checkpoint_sequence: 0,
        tail_sequence: tail.sequence,
        records_verified,
    })
}

fn verify_audit_chain_incremental_connection(
    connection: &mut Connection,
    audit_mac: &AuditMacKey,
) -> Result<AuditVerificationReport> {
    let tail = audit_tail_state(connection)?;
    let Some(checkpoint) = load_audit_verification_checkpoint(connection)? else {
        return verify_audit_chain_full_connection(connection, audit_mac);
    };
    if checkpoint.sequence > tail.sequence
        || !audit_mac.verifies_tail(
            &checkpoint.checkpoint_mac,
            &tail.anchor_hash,
            checkpoint.sequence,
            &checkpoint.record_hash,
            &checkpoint.record_mac,
        )
        || !checkpoint_matches_audit_row(connection, audit_mac, &tail, &checkpoint)?
    {
        return Ok(AuditVerificationReport {
            valid: false,
            full: false,
            checkpoint_sequence: checkpoint.sequence,
            tail_sequence: tail.sequence,
            records_verified: 0,
        });
    }

    let mut statement = connection.prepare(
        "SELECT sequence, id, timestamp, connector_id, tool_name, capability,
                outcome, argument_hash, summary, duration_ms, output_bytes,
                previous_hash, record_hash, payload, record_mac
         FROM audit_events WHERE sequence > ?1 ORDER BY sequence",
    )?;
    let mut rows = statement.query([i64::try_from(checkpoint.sequence)
        .context("audit verification checkpoint sequence is too large")?])?;
    let mut expected_previous = checkpoint.record_hash.clone();
    let mut last = (
        checkpoint.sequence,
        checkpoint.record_hash,
        checkpoint.record_mac,
    );
    let mut records_verified = 0_usize;
    while let Some(row) = rows.next()? {
        let stored = map_stored_audit_row(row)?;
        if !verify_stored_audit_row(&stored, &expected_previous, audit_mac)? {
            return Ok(AuditVerificationReport {
                valid: false,
                full: false,
                checkpoint_sequence: checkpoint.sequence,
                tail_sequence: tail.sequence,
                records_verified,
            });
        }
        expected_previous.clone_from(&stored.record_hash);
        last = (stored.sequence, stored.record_hash, stored.record_mac);
        records_verified = records_verified.saturating_add(1);
    }
    let valid = last.0 == tail.sequence
        && last.1 == tail.record_hash
        && last.2 == tail.record_mac
        && audit_mac.verifies_tail(
            &tail.tail_mac,
            &tail.anchor_hash,
            tail.sequence,
            &tail.record_hash,
            &tail.record_mac,
        );
    if valid {
        update_audit_verification_checkpoint(connection, audit_mac, &tail)?;
    }
    Ok(AuditVerificationReport {
        valid,
        full: false,
        checkpoint_sequence: checkpoint.sequence,
        tail_sequence: tail.sequence,
        records_verified,
    })
}

fn verify_stored_audit_row(
    stored: &StoredAuditRow,
    expected_previous: &str,
    audit_mac: &AuditMacKey,
) -> Result<bool> {
    if stored.previous_hash != expected_previous || !stored_audit_row_is_authentic(stored)? {
        return Ok(false);
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(stored.previous_hash.as_bytes());
    hasher.update(&stored.payload);
    Ok(hasher.finalize().to_hex().as_str() == stored.record_hash
        && audit_mac.verifies_record(
            &stored.record_mac,
            stored.sequence,
            &stored.previous_hash,
            &stored.record_hash,
            &stored.payload,
        ))
}

fn load_audit_verification_checkpoint(
    connection: &Connection,
) -> Result<Option<AuditVerificationCheckpoint>> {
    connection
        .query_row(
            "SELECT sequence, record_hash, record_mac, checkpoint_mac
             FROM audit_verification_checkpoint WHERE id = 1",
            [],
            |row| {
                Ok(AuditVerificationCheckpoint {
                    sequence: u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })?,
                    record_hash: row.get(1)?,
                    record_mac: row.get(2)?,
                    checkpoint_mac: row.get(3)?,
                })
            },
        )
        .optional()
        .context("failed to load audit verification checkpoint")
}

fn checkpoint_matches_audit_row(
    connection: &Connection,
    audit_mac: &AuditMacKey,
    tail: &AuditTailState,
    checkpoint: &AuditVerificationCheckpoint,
) -> Result<bool> {
    if checkpoint.sequence == 0 {
        return Ok(checkpoint.record_hash == tail.anchor_hash && checkpoint.record_mac.is_empty());
    }
    let mut statement = connection.prepare(
        "SELECT sequence, id, timestamp, connector_id, tool_name, capability,
                outcome, argument_hash, summary, duration_ms, output_bytes,
                previous_hash, record_hash, payload, record_mac
         FROM audit_events WHERE sequence = ?1",
    )?;
    let mut rows = statement.query([i64::try_from(checkpoint.sequence)
        .context("audit verification checkpoint sequence is too large")?])?;
    let stored = rows.next()?.map(map_stored_audit_row).transpose()?;
    let Some(stored) = stored else {
        return Ok(false);
    };
    Ok(stored.record_hash == checkpoint.record_hash
        && stored.record_mac == checkpoint.record_mac
        && stored_audit_row_is_authentic(&stored)?
        && audit_mac.verifies_record(
            &stored.record_mac,
            stored.sequence,
            &stored.previous_hash,
            &stored.record_hash,
            &stored.payload,
        ))
}

fn update_audit_verification_checkpoint(
    connection: &Connection,
    audit_mac: &AuditMacKey,
    tail: &AuditTailState,
) -> Result<()> {
    let checkpoint_mac = audit_mac.tail_mac(
        &tail.anchor_hash,
        tail.sequence,
        &tail.record_hash,
        &tail.record_mac,
    );
    connection.execute(
        "INSERT INTO audit_verification_checkpoint (
            id, sequence, record_hash, record_mac, checkpoint_mac, verified_at
         ) VALUES (1, ?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(id) DO UPDATE SET
            sequence = excluded.sequence,
            record_hash = excluded.record_hash,
            record_mac = excluded.record_mac,
            checkpoint_mac = excluded.checkpoint_mac,
            verified_at = excluded.verified_at",
        params![
            i64::try_from(tail.sequence).context("audit verification sequence is too large")?,
            tail.record_hash,
            tail.record_mac,
            checkpoint_mac,
            Utc::now().to_rfc3339(),
        ],
    )?;
    Ok(())
}

fn map_stored_audit_row(row: &rusqlite::Row<'_>) -> Result<StoredAuditRow> {
    Ok(StoredAuditRow {
        sequence: u64::try_from(row.get::<_, i64>(0)?).context("audit sequence is negative")?,
        id: row.get(1)?,
        timestamp: row.get(2)?,
        connector_id: row.get(3)?,
        tool_name: row.get(4)?,
        capability: row.get(5)?,
        outcome: row.get(6)?,
        argument_hash: row.get(7)?,
        summary: row.get(8)?,
        duration_ms: row.get(9)?,
        output_bytes: row.get(10)?,
        previous_hash: row.get(11)?,
        record_hash: row.get(12)?,
        payload: row.get(13)?,
        record_mac: row.get(14)?,
    })
}

fn stored_audit_row_is_authentic(stored: &StoredAuditRow) -> Result<bool> {
    let event: AuditEvent =
        serde_json::from_slice(&stored.payload).context("audit payload is not a valid event")?;
    let canonical = serde_json::to_vec(&event)?;
    let duration_ms = audit_optional_u64_to_i64(event.duration_ms, "duration")?;
    let output_bytes = audit_optional_u64_to_i64(event.output_bytes, "output size")?;
    Ok(canonical == stored.payload
        && stored.id == event.id.to_string()
        && stored.timestamp == event.timestamp.to_rfc3339()
        && stored.connector_id == event.connector_id
        && stored.tool_name == event.tool_name
        && stored.capability == event.capability
        && stored.outcome == serde_json::to_string(&event.outcome)?
        && stored.argument_hash == event.argument_hash
        && stored.summary == event.summary
        && stored.duration_ms == duration_ms
        && stored.output_bytes == output_bytes)
}

fn audit_optional_u64_to_i64(value: Option<u64>, label: &str) -> Result<Option<i64>> {
    value
        .map(|value| i64::try_from(value).with_context(|| format!("audit {label} is too large")))
        .transpose()
}

fn next_audit_sequence(connection: &Connection) -> Result<i64> {
    connection
        .query_row(
            "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'), 0) + 1",
            [],
            |row| row.get(0),
        )
        .context("failed to allocate the next audit sequence")
}

fn audit_tail_state(connection: &Connection) -> Result<AuditTailState> {
    connection
        .query_row(
            "SELECT anchor_hash, tail_sequence, tail_hash, tail_record_mac, tail_mac
             FROM audit_chain_state WHERE id = 1",
            [],
            |row| {
                let sequence = u64::try_from(row.get::<_, i64>(1)?).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        1,
                        rusqlite::types::Type::Integer,
                        Box::new(error),
                    )
                })?;
                Ok(AuditTailState {
                    anchor_hash: row.get(0)?,
                    sequence,
                    record_hash: row.get(2)?,
                    record_mac: row.get(3)?,
                    tail_mac: row.get(4)?,
                })
            },
        )
        .context("authenticated audit chain state is missing")
}

fn update_audit_tail(
    connection: &Connection,
    audit_mac: &AuditMacKey,
    sequence: u64,
    record_hash: &str,
    record_mac: &str,
) -> Result<()> {
    let anchor = audit_anchor(connection)?;
    let tail_mac = audit_mac.tail_mac(&anchor, sequence, record_hash, record_mac);
    let changed = connection.execute(
        "UPDATE audit_chain_state
         SET tail_sequence = ?1, tail_hash = ?2, tail_record_mac = ?3, tail_mac = ?4
         WHERE id = 1",
        params![
            i64::try_from(sequence).context("audit sequence is too large")?,
            record_hash,
            record_mac,
            tail_mac,
        ],
    )?;
    if changed != 1 {
        bail!("authenticated audit chain state is missing");
    }
    Ok(())
}

fn audit_tail_connection(connection: &mut Connection, limit: usize) -> Result<Vec<AuditRecord>> {
    let limit = i64::try_from(limit.clamp(1, 10_000)).unwrap_or(10_000);
    let mut statement = connection.prepare(
        "SELECT sequence, payload, previous_hash, record_hash, record_mac
         FROM audit_events ORDER BY sequence DESC LIMIT ?1",
    )?;
    let rows = statement.query_map([limit], |row| {
        let sequence = u64::try_from(row.get::<_, i64>(0)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?;
        let payload: Vec<u8> = row.get(1)?;
        let event = serde_json::from_slice::<AuditEvent>(&payload).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Blob,
                Box::new(error),
            )
        })?;
        Ok(AuditRecord {
            sequence,
            event,
            previous_hash: row.get(2)?,
            record_hash: row.get(3)?,
            record_mac: row.get(4)?,
        })
    })?;
    let mut records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    records.reverse();
    Ok(records)
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

fn migrate(connection: &Connection, audit_mac: &AuditMacKey) -> Result<()> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_versions (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL CHECK (version >= 0)
        );",
    )?;
    let current = transaction
        .query_row(
            "SELECT version FROM schema_versions WHERE component = 'core_state'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    if current > STATE_SCHEMA_VERSION {
        bail!(
            "state database schema version {current} is newer than supported version {STATE_SCHEMA_VERSION}"
        );
    }

    migrate_principal_bound_approvals(&transaction)?;
    remove_legacy_connector_wide_grants(&transaction)?;
    create_grant_and_audit_tables(&transaction)?;
    if current < 3 {
        migrate_audit_integrity_v3(&transaction, audit_mac)?;
    } else {
        validate_audit_integrity_v3_schema(&transaction)?;
    }
    create_audit_verification_checkpoint_table(&transaction)?;
    transaction.execute(
        "INSERT INTO schema_versions(component, version) VALUES ('core_state', ?1)
         ON CONFLICT(component) DO UPDATE SET version = excluded.version",
        [STATE_SCHEMA_VERSION],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_principal_bound_approvals(connection: &Connection) -> Result<()> {
    if !table_exists(connection, "approvals")?
        || table_has_column(connection, "approvals", "principal_fingerprint")?
    {
        return create_approvals_table(connection);
    }
    connection.execute("DROP INDEX IF EXISTS approvals_pending_idx", [])?;
    connection.execute(
        "ALTER TABLE approvals RENAME TO approvals_pre_principal",
        [],
    )?;
    create_approvals_table(connection)?;
    let legacy_fingerprint = ApprovalPrincipal::Legacy.fingerprint();
    let migrated_at = Utc::now().to_rfc3339();
    connection.execute(
        "INSERT INTO approvals (
            id, connector_id, principal_kind, oauth_client_id, oauth_subject,
            principal_fingerprint, tool_name, argument_summary, argument_hash,
            status, created_at, expires_at, resolved_at, decision
         )
         SELECT id, connector_id, 'legacy', NULL, NULL, ?1,
                tool_name, argument_summary, argument_hash,
                CASE WHEN status = 'pending' THEN 'expired' ELSE status END,
                created_at, expires_at,
                CASE WHEN status = 'pending' THEN ?2 ELSE resolved_at END,
                CASE WHEN status = 'pending' THEN NULL ELSE decision END
         FROM approvals_pre_principal",
        params![legacy_fingerprint, migrated_at],
    )?;
    connection.execute("DROP TABLE approvals_pre_principal", [])?;
    Ok(())
}

fn remove_legacy_connector_wide_grants(connection: &Connection) -> Result<()> {
    for table in ["temporary_grants", "persistent_grants"] {
        if table_exists(connection, table)?
            && !table_has_column(connection, table, "principal_fingerprint")?
        {
            // Grants created before principal binding are connector-wide and
            // cannot be migrated safely. Drop them fail-closed.
            connection.execute(&format!("DROP TABLE {table}"), [])?;
        }
    }
    Ok(())
}

fn create_grant_and_audit_tables(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS temporary_grants (
            connector_id TEXT NOT NULL,
            principal_kind TEXT NOT NULL,
            oauth_client_id TEXT,
            oauth_subject TEXT,
            principal_fingerprint TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            argument_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, principal_fingerprint, tool_name, argument_hash)
        );
        CREATE INDEX IF NOT EXISTS temporary_grants_expiry_idx
            ON temporary_grants(expires_at);
        CREATE TABLE IF NOT EXISTS persistent_grants (
            connector_id TEXT NOT NULL,
            principal_kind TEXT NOT NULL,
            oauth_client_id TEXT,
            oauth_subject TEXT,
            principal_fingerprint TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            argument_hash TEXT NOT NULL,
            argument_summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, principal_fingerprint, tool_name, argument_hash)
        );
        CREATE INDEX IF NOT EXISTS persistent_grants_connector_idx
            ON persistent_grants(connector_id, principal_fingerprint, tool_name);
        CREATE TABLE IF NOT EXISTS audit_events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            timestamp TEXT NOT NULL,
            connector_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            capability TEXT NOT NULL,
            outcome TEXT NOT NULL,
            argument_hash TEXT NOT NULL,
            summary TEXT NOT NULL,
            duration_ms INTEGER,
            output_bytes INTEGER,
            previous_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL UNIQUE,
            payload BLOB NOT NULL,
            record_mac TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_chain_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            anchor_hash TEXT NOT NULL,
            tail_sequence INTEGER NOT NULL CHECK (tail_sequence >= 0),
            tail_hash TEXT NOT NULL,
            tail_record_mac TEXT NOT NULL,
            tail_mac TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_verification_checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sequence INTEGER NOT NULL CHECK (sequence >= 0),
            record_hash TEXT NOT NULL,
            record_mac TEXT NOT NULL,
            checkpoint_mac TEXT NOT NULL,
            verified_at TEXT NOT NULL
        );",
    )?;
    Ok(())
}

fn create_audit_verification_checkpoint_table(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_verification_checkpoint (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            sequence INTEGER NOT NULL CHECK (sequence >= 0),
            record_hash TEXT NOT NULL,
            record_mac TEXT NOT NULL,
            checkpoint_mac TEXT NOT NULL,
            verified_at TEXT NOT NULL
        );",
    )?;
    Ok(())
}

fn migrate_audit_integrity_v3(connection: &Connection, audit_mac: &AuditMacKey) -> Result<()> {
    for (table, column, definition) in [
        ("audit_events", "record_mac", "record_mac TEXT"),
        (
            "audit_chain_state",
            "tail_sequence",
            "tail_sequence INTEGER",
        ),
        ("audit_chain_state", "tail_hash", "tail_hash TEXT"),
        (
            "audit_chain_state",
            "tail_record_mac",
            "tail_record_mac TEXT",
        ),
        ("audit_chain_state", "tail_mac", "tail_mac TEXT"),
    ] {
        if !table_has_column(connection, table, column)? {
            connection.execute(&format!("ALTER TABLE {table} ADD COLUMN {definition}"), [])?;
        }
    }
    connection.execute(
        "INSERT OR IGNORE INTO audit_chain_state (
            id, anchor_hash, tail_sequence, tail_hash, tail_record_mac, tail_mac
         ) VALUES (1, 'GENESIS', 0, 'GENESIS', '', '')",
        [],
    )?;
    if !verify_legacy_audit_chain(connection)? {
        bail!("legacy audit chain failed verification before MAC migration");
    }
    let rows = {
        let mut statement = connection.prepare(
            "SELECT sequence, previous_hash, record_hash, payload
             FROM audit_events ORDER BY sequence",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (sequence, previous_hash, record_hash, payload) in &rows {
        let sequence_u64 = u64::try_from(*sequence).context("legacy audit sequence is negative")?;
        let record_mac = audit_mac.record_mac(sequence_u64, previous_hash, record_hash, payload);
        let changed = connection.execute(
            "UPDATE audit_events SET record_mac = ?1 WHERE sequence = ?2",
            params![record_mac, sequence],
        )?;
        if changed != 1 {
            bail!("legacy audit MAC migration did not update exactly one row");
        }
    }
    let anchor = audit_anchor(connection)?;
    let (sequence, record_hash, record_mac) = match rows.last() {
        Some((sequence, _, record_hash, _)) => {
            let record_mac: String = connection.query_row(
                "SELECT record_mac FROM audit_events WHERE sequence = ?1",
                [sequence],
                |row| row.get(0),
            )?;
            (
                u64::try_from(*sequence).context("legacy audit tail sequence is negative")?,
                record_hash.clone(),
                record_mac,
            )
        }
        None => (0, anchor.clone(), String::new()),
    };
    let tail_mac = audit_mac.tail_mac(&anchor, sequence, &record_hash, &record_mac);
    let changed = connection.execute(
        "UPDATE audit_chain_state
         SET tail_sequence = ?1, tail_hash = ?2, tail_record_mac = ?3, tail_mac = ?4
         WHERE id = 1",
        params![
            i64::try_from(sequence).context("legacy audit tail sequence is too large")?,
            record_hash,
            record_mac,
            tail_mac,
        ],
    )?;
    if changed != 1 {
        bail!("legacy audit tail migration did not update exactly one row");
    }
    Ok(())
}

fn validate_audit_integrity_v3_schema(connection: &Connection) -> Result<()> {
    for (table, column) in [
        ("audit_events", "record_mac"),
        ("audit_chain_state", "tail_sequence"),
        ("audit_chain_state", "tail_hash"),
        ("audit_chain_state", "tail_record_mac"),
        ("audit_chain_state", "tail_mac"),
    ] {
        if !table_has_column(connection, table, column)? {
            bail!("version-3 audit integrity column {table}.{column} is missing");
        }
    }
    let invalid_records: i64 = connection.query_row(
        "SELECT COUNT(*) FROM audit_events
         WHERE record_mac IS NULL OR length(record_mac) != 64",
        [],
        |row| row.get(0),
    )?;
    if invalid_records != 0 {
        bail!("version-3 audit records contain missing or invalid MAC data");
    }
    let valid_state: i64 = connection.query_row(
        "SELECT COUNT(*) FROM audit_chain_state
         WHERE id = 1 AND tail_sequence IS NOT NULL AND tail_sequence >= 0
           AND tail_hash IS NOT NULL AND tail_record_mac IS NOT NULL
           AND tail_mac IS NOT NULL AND length(tail_mac) = 64",
        [],
        |row| row.get(0),
    )?;
    if valid_state != 1 {
        bail!("version-3 authenticated audit tail state is missing or invalid");
    }
    Ok(())
}

fn verify_legacy_audit_chain(connection: &Connection) -> Result<bool> {
    let mut statement = connection.prepare(
        "SELECT previous_hash, record_hash, payload FROM audit_events ORDER BY sequence",
    )?;
    let mut rows = statement.query([])?;
    let mut expected = audit_anchor(connection)?;
    while let Some(row) = rows.next()? {
        let previous: String = row.get(0)?;
        let record_hash: String = row.get(1)?;
        let payload: Vec<u8> = row.get(2)?;
        if previous != expected {
            return Ok(false);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(previous.as_bytes());
        hasher.update(&payload);
        if hasher.finalize().to_hex().as_str() != record_hash {
            return Ok(false);
        }
        expected = record_hash;
    }
    Ok(true)
}

fn create_approvals_table(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            connector_id TEXT NOT NULL,
            principal_kind TEXT NOT NULL,
            oauth_client_id TEXT,
            oauth_subject TEXT,
            principal_fingerprint TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            argument_summary TEXT NOT NULL,
            argument_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            resolved_at TEXT,
            decision TEXT
        );
        CREATE INDEX IF NOT EXISTS approvals_pending_idx
            ON approvals(status, expires_at);",
    )?;
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn table_has_column(connection: &Connection, table: &str, column: &str) -> Result<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|candidate| candidate == column))
}

fn audit_anchor(connection: &Connection) -> Result<String> {
    connection
        .query_row(
            "SELECT anchor_hash FROM audit_chain_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .context("audit chain anchor is missing")
}

fn prune_audit_connection(
    connection: &mut Connection,
    max_age: chrono::Duration,
    max_bytes: u64,
    audit_mac: &AuditMacKey,
) -> Result<usize> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT sequence, timestamp, record_hash, record_mac,
                    length(payload) + length(previous_hash) + length(record_hash) +
                    length(record_mac) + length(connector_id) + length(tool_name) +
                    length(capability) + length(outcome) + length(argument_hash) +
                    length(summary) + 128
             FROM audit_events ORDER BY sequence",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if rows.is_empty() {
        return Ok(0);
    }

    let cutoff = Utc::now() - max_age;
    let mut delete_count = 0_usize;
    for (_, timestamp, _, _, _) in &rows {
        let parsed = DateTime::<Utc>::from_str(timestamp)
            .context("audit event contains an invalid timestamp")?;
        if parsed >= cutoff {
            break;
        }
        delete_count += 1;
    }
    let mut retained_bytes = rows[delete_count..].iter().try_fold(0_u64, |total, row| {
        let bytes = u64::try_from(row.4).context("audit event size is invalid")?;
        Ok::<u64, anyhow::Error>(total.saturating_add(bytes))
    })?;
    while delete_count < rows.len() && retained_bytes > max_bytes {
        let bytes = u64::try_from(rows[delete_count].4).context("audit event size is invalid")?;
        retained_bytes = retained_bytes.saturating_sub(bytes);
        delete_count += 1;
    }
    if delete_count == 0 {
        return Ok(0);
    }

    let (last_sequence, _, anchor_hash, _, _) = &rows[delete_count - 1];
    let (tail_sequence, tail_hash, tail_record_mac) = if delete_count == rows.len() {
        (0_i64, anchor_hash.clone(), String::new())
    } else {
        let (sequence, _, record_hash, record_mac, _) = rows
            .last()
            .context("audit rows disappeared during pruning")?;
        (*sequence, record_hash.clone(), record_mac.clone())
    };
    let tail_mac = audit_mac.tail_mac(
        anchor_hash,
        u64::try_from(tail_sequence).context("audit tail sequence is negative")?,
        &tail_hash,
        &tail_record_mac,
    );
    let transaction = connection.transaction()?;
    transaction.execute("DELETE FROM audit_verification_checkpoint", [])?;
    transaction.execute(
        "DELETE FROM audit_events WHERE sequence <= ?1",
        [last_sequence],
    )?;
    let changed = transaction.execute(
        "UPDATE audit_chain_state
         SET anchor_hash = ?1, tail_sequence = ?2, tail_hash = ?3,
             tail_record_mac = ?4, tail_mac = ?5
         WHERE id = 1",
        params![
            anchor_hash,
            tail_sequence,
            tail_hash,
            tail_record_mac,
            tail_mac,
        ],
    )?;
    if changed != 1 {
        bail!("authenticated audit chain state is missing during pruning");
    }
    transaction.commit()?;
    Ok(delete_count)
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
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::audit::{AuditEvent, AuditOutcome};

    #[tokio::test]
    async fn bounded_worker_rejects_overload_and_reports_metrics() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        let worker = Arc::new(SqliteWorker::start_with_options(
            connection,
            1,
            StdDuration::from_millis(25),
        )?);
        let (started_sender, started_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let first_worker = Arc::clone(&worker);
        let first = std::thread::spawn(move || {
            first_worker.call(move |_connection| {
                started_sender
                    .send(())
                    .map_err(|_| anyhow!("failed to signal blocking database operation"))?;
                release_receiver
                    .recv()
                    .map_err(|_| anyhow!("failed to release blocking database operation"))?;
                Ok(())
            })
        });
        started_receiver
            .recv_timeout(StdDuration::from_secs(1))
            .map_err(|_| anyhow!("database worker did not start the blocking operation"))?;

        let second_worker = Arc::clone(&worker);
        let second = std::thread::spawn(move || second_worker.call(|_connection| Ok(())));
        let queued_deadline = Instant::now() + StdDuration::from_secs(1);
        while worker.metrics().queued != 1 {
            if Instant::now() >= queued_deadline {
                bail!("second database operation was not queued");
            }
            std::thread::sleep(StdDuration::from_millis(1));
        }

        let sync_overload: Result<()> = worker.call(|_connection| Ok(()));
        assert!(sync_overload.is_err());
        let async_overload: Result<()> = worker.call_async(|_connection| Ok(())).await;
        assert!(async_overload.is_err());
        let overloaded = worker.metrics();
        assert_eq!(overloaded.queue_capacity, 1);
        assert_eq!(overloaded.queued, 1);
        assert_eq!(overloaded.active, 1);
        assert_eq!(overloaded.high_watermark, 1);
        assert_eq!(overloaded.rejected, 2);

        release_sender
            .send(())
            .map_err(|_| anyhow!("failed to release database worker"))?;
        first
            .join()
            .map_err(|_| anyhow!("first database caller panicked"))??;
        second
            .join()
            .map_err(|_| anyhow!("second database caller panicked"))??;
        let completed = worker.metrics();
        assert_eq!(completed.queued, 0);
        assert_eq!(completed.active, 0);
        assert_eq!(completed.completed, 2);
        assert_eq!(completed.rejected, 2);
        Ok(())
    }

    #[tokio::test]
    async fn async_worker_handles_authorization_state_without_blocking_connection_ownership()
    -> Result<()> {
        let store = StateStore::in_memory()?;
        let approval = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "fs_write",
            "write a file",
            "async-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval_async(approval.clone()).await?;
        assert!(
            store
                .resolve_approval_async(approval.id, ApprovalDecision::ForTenMinutes)
                .await?
        );
        assert!(
            store
                .grant_allows_async(
                    "local".to_owned(),
                    ApprovalPrincipal::LocalStdio,
                    "fs_write".to_owned(),
                    "async-hash".to_owned(),
                )
                .await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn approval_resolution_wakes_another_store_process_view() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        let waiting_store = StateStore::open(&database)?;
        let resolving_store = StateStore::open(&database)?;
        assert!(
            waiting_store
                .approval_notification_metrics()
                .native_watcher_active
        );
        let approval = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "fs_write",
            "write a file",
            "cross-process-notification",
            Utc::now() + Duration::seconds(90),
        );
        waiting_store.insert_approval(&approval)?;
        let mut subscription = waiting_store.subscribe_approval_changes();
        assert!(resolving_store.resolve_approval(approval.id, ApprovalDecision::Once)?);
        tokio::time::timeout(StdDuration::from_secs(5), subscription.changed())
            .await
            .context("cross-process approval notification timed out")??;
        assert_eq!(
            waiting_store
                .approval_status(approval.id)?
                .map(|item| item.status),
            Some(ApprovalStatus::Approved)
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_database_and_sidecars_are_private() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let state_directory = directory.path().join("state");
        let database = state_directory.join("state.db");
        let store = StateStore::open(&database)?;
        store.append_audit(&AuditEvent::new(
            "test",
            "system_info",
            "system_read",
            AuditOutcome::Allowed,
            "hash",
            "permission test",
        ))?;
        assert_eq!(
            std::fs::metadata(&state_directory)?.permissions().mode() & 0o777,
            0o700
        );
        for path in [
            database.clone(),
            sqlite_sidecar(&database, "-wal"),
            sqlite_sidecar(&database, "-shm"),
        ] {
            if path.exists() {
                assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
            }
        }
        Ok(())
    }

    #[test]
    fn approval_can_only_be_resolved_once() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approval = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "run a command",
            "hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        assert!(store.resolve_approval(approval.id, ApprovalDecision::Once)?);
        assert!(!store.resolve_approval(approval.id, ApprovalDecision::Once)?);
        assert_eq!(
            store.approval_status(approval.id)?.map(|item| item.status),
            Some(ApprovalStatus::Approved)
        );
        Ok(())
    }

    #[test]
    fn ten_minute_approval_creates_a_temporary_tool_grant() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approval = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "run a command",
            "hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        assert!(store.resolve_approval(approval.id, ApprovalDecision::ForTenMinutes)?);
        assert!(store.temporary_grant_allows(
            "local",
            &ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "hash",
        )?);
        assert!(!store.temporary_grant_allows(
            "local",
            &ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "different-hash",
        )?);
        assert!(!store.temporary_grant_allows(
            "local",
            &ApprovalPrincipal::LocalStdio,
            "fs_write",
            "hash",
        )?);
        Ok(())
    }

    #[test]
    fn timeout_state_and_audit_commit_atomically_and_block_late_grants() -> Result<()> {
        let store = StateStore::in_memory()?;
        let principal = ApprovalPrincipal::LocalStdio;
        let approval = ApprovalRequest::new(
            "local",
            principal.clone(),
            "shell_exec",
            "run a command",
            "timeout-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        let event = AuditEvent::new(
            "local",
            "shell_exec",
            "shell_exec",
            AuditOutcome::TimedOut,
            "timeout-hash",
            "local approval timed out",
        );

        assert_eq!(
            store.complete_approval_timeout(approval.id, &event)?,
            Some(ApprovalTimeoutResult::ExpiredNow)
        );
        assert_eq!(
            store.complete_approval_timeout(approval.id, &event)?,
            Some(ApprovalTimeoutResult::Existing(ApprovalStatus::Expired))
        );
        let expired = store
            .approval_status(approval.id)?
            .context("expired approval disappeared")?;
        assert_eq!(expired.status, ApprovalStatus::Expired);
        assert_eq!(expired.resolved_at, Some(event.timestamp));
        assert_eq!(expired.decision, None);
        let records = store.audit_tail(10)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event.id, event.id);
        assert_eq!(records[0].event.outcome, AuditOutcome::TimedOut);
        assert!(store.verify_audit_chain()?);

        assert!(!store.resolve_approval(approval.id, ApprovalDecision::ForTenMinutes)?);
        assert!(!store.temporary_grant_allows(
            "local",
            &principal,
            "shell_exec",
            "timeout-hash"
        )?);
        assert!(store.persistent_grants(Some("local"))?.is_empty());
        Ok(())
    }

    #[test]
    fn timeout_audit_failure_rolls_back_the_state_transition() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approval = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "run a command",
            "rollback-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        let event = AuditEvent::new(
            "local",
            "shell_exec",
            "shell_exec",
            AuditOutcome::TimedOut,
            "rollback-hash",
            "local approval timed out",
        );
        store.append_audit(&event)?;

        assert!(
            store
                .complete_approval_timeout(approval.id, &event)
                .is_err()
        );
        let unchanged = store
            .approval_status(approval.id)?
            .context("approval disappeared after transaction rollback")?;
        assert_eq!(unchanged.status, ApprovalStatus::Pending);
        assert_eq!(unchanged.resolved_at, None);
        assert_eq!(store.audit_tail(10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn connector_authorization_cleanup_is_scoped_and_idempotent() -> Result<()> {
        let store = StateStore::in_memory()?;
        for connector_id in ["remove-me", "keep-me"] {
            let approval = ApprovalRequest::new(
                connector_id,
                ApprovalPrincipal::LocalStdio,
                "shell_exec",
                "run a command",
                format!("{connector_id}-temporary"),
                Utc::now() + Duration::seconds(90),
            );
            store.insert_approval(&approval)?;
            assert!(store.resolve_approval(approval.id, ApprovalDecision::ForTenMinutes,)?);
            let persistent = ApprovalRequest::new(
                connector_id,
                ApprovalPrincipal::LocalStdio,
                "fs_write",
                "write a file",
                format!("{connector_id}-persistent"),
                Utc::now() + Duration::seconds(90),
            );
            store.insert_approval(&persistent)?;
            assert!(store.resolve_approval(persistent.id, ApprovalDecision::Always)?);
        }

        let removed = store.clear_connector_authorization("remove-me")?;
        assert_eq!(removed.approvals, 2);
        assert_eq!(removed.temporary_grants, 1);
        assert_eq!(removed.persistent_grants, 1);
        assert_eq!(removed.total(), 4);
        assert_eq!(store.clear_connector_authorization("remove-me")?.total(), 0);
        assert_eq!(store.pending_approvals()?.len(), 0);
        assert_eq!(store.persistent_grants(Some("keep-me"))?.len(), 1);
        assert!(store.temporary_grant_allows(
            "keep-me",
            &ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "keep-me-temporary",
        )?);
        Ok(())
    }

    #[test]
    fn emergency_lock_denies_pending_and_clears_temporary_grants() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approved = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "run a command",
            "approved-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approved)?;
        assert!(store.resolve_approval(approved.id, ApprovalDecision::ForTenMinutes)?);
        let pending = ApprovalRequest::new(
            "local",
            ApprovalPrincipal::LocalStdio,
            "fs_write",
            "write a file",
            "pending-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&pending)?;

        let (denied, cleared) = store.emergency_lock()?;
        assert_eq!(denied, 1);
        assert_eq!(cleared, 1);
        assert_eq!(
            store.approval_status(pending.id)?.map(|item| item.status),
            Some(ApprovalStatus::Denied)
        );
        assert!(!store.temporary_grant_allows(
            "local",
            &ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "approved-hash",
        )?);
        Ok(())
    }

    #[test]
    fn audit_chain_verifies() -> Result<()> {
        let store = StateStore::in_memory()?;
        let event = AuditEvent::new(
            "local",
            "machine_info",
            "system_read",
            AuditOutcome::Succeeded,
            "hash",
            "machine info",
        );
        store.append_audit(&event)?;
        assert!(store.verify_audit_chain()?);
        let records = store.audit_tail(10)?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].event.tool_name, "machine_info");
        Ok(())
    }

    #[test]
    fn audit_pruning_preserves_the_remaining_chain_anchor() -> Result<()> {
        let store = StateStore::in_memory()?;
        let mut old = AuditEvent::new(
            "local",
            "machine_info",
            "system_read",
            AuditOutcome::Succeeded,
            "old-hash",
            "old event",
        );
        old.timestamp = Utc::now() - Duration::days(31);
        store.append_audit(&old)?;
        let current = AuditEvent::new(
            "local",
            "machine_info",
            "system_read",
            AuditOutcome::Succeeded,
            "new-hash",
            "current event",
        );
        store.append_audit(&current)?;
        let audit_mac = store.audit_mac.clone();
        let removed = store.test_call(move |connection| {
            prune_audit_connection(
                connection,
                Duration::days(AUDIT_RETENTION_DAYS),
                AUDIT_MAX_BYTES,
                &audit_mac,
            )
        })?;
        assert_eq!(removed, 1);
        assert!(store.verify_audit_chain()?);
        assert_eq!(store.audit_tail(10)?.len(), 1);
        Ok(())
    }

    #[test]
    fn audit_pruning_enforces_the_byte_limit() -> Result<()> {
        let store = StateStore::in_memory()?;
        for index in 0..3 {
            store.append_audit(&AuditEvent::new(
                "local",
                "machine_info",
                "system_read",
                AuditOutcome::Succeeded,
                format!("hash-{index}"),
                "x".repeat(1_024),
            ))?;
        }
        let audit_mac = store.audit_mac.clone();
        let removed = store.test_call(move |connection| {
            prune_audit_connection(
                connection,
                Duration::days(AUDIT_RETENTION_DAYS),
                1_600,
                &audit_mac,
            )
        })?;
        assert!(removed >= 2);
        assert!(store.verify_audit_chain()?);
        Ok(())
    }
    #[test]
    fn always_approval_creates_only_an_exact_persistent_grant() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approval = ApprovalRequest::new(
            "connector",
            ApprovalPrincipal::LocalStdio,
            "fs_write",
            "Path: /tmp/a.txt",
            "exact-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        assert!(store.resolve_approval(approval.id, ApprovalDecision::Always)?);
        assert!(store.grant_allows(
            "connector",
            &ApprovalPrincipal::LocalStdio,
            "fs_write",
            "exact-hash",
        )?);
        assert!(!store.grant_allows(
            "connector",
            &ApprovalPrincipal::LocalStdio,
            "fs_write",
            "other-hash",
        )?);
        assert!(!store.grant_allows(
            "connector",
            &ApprovalPrincipal::LocalStdio,
            "shell_exec",
            "exact-hash",
        )?);

        let grants = store.persistent_grants(Some("connector"))?;
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].argument_hash, "exact-hash");
        assert!(store.delete_persistent_grant(
            "connector",
            &ApprovalPrincipal::LocalStdio.fingerprint(),
            "fs_write",
            "exact-hash",
        )?);
        assert!(!store.grant_allows(
            "connector",
            &ApprovalPrincipal::LocalStdio,
            "fs_write",
            "exact-hash",
        )?);
        Ok(())
    }
    #[test]
    fn exact_grants_are_isolated_by_oauth_client_and_subject() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approved = ApprovalPrincipal::OAuth {
            client_id: "client-a".to_owned(),
            subject: "github:42".to_owned(),
        };
        let other_client = ApprovalPrincipal::OAuth {
            client_id: "client-b".to_owned(),
            subject: "github:42".to_owned(),
        };
        let other_subject = ApprovalPrincipal::OAuth {
            client_id: "client-a".to_owned(),
            subject: "github:99".to_owned(),
        };
        let approval = ApprovalRequest::new(
            "oauth-connector",
            approved.clone(),
            "fs_write",
            "Path: /tmp/a.txt",
            "same-arguments",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        assert!(store.resolve_approval(approval.id, ApprovalDecision::Always)?);

        assert!(store.grant_allows("oauth-connector", &approved, "fs_write", "same-arguments",)?);
        assert!(!store.grant_allows(
            "oauth-connector",
            &other_client,
            "fs_write",
            "same-arguments",
        )?);
        assert!(!store.grant_allows(
            "oauth-connector",
            &other_subject,
            "fs_write",
            "same-arguments",
        )?);
        assert!(!store.grant_allows(
            "oauth-connector",
            &ApprovalPrincipal::LocalStdio,
            "fs_write",
            "same-arguments",
        )?);
        let grants = store.persistent_grants(Some("oauth-connector"))?;
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].principal, approved);
        assert_eq!(
            grants[0].principal_fingerprint,
            grants[0].principal.fingerprint()
        );
        Ok(())
    }

    #[test]
    fn core_state_beta_v0_fixture_migrates_without_preserving_broad_grants() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state").join("state.db");
        std::fs::create_dir_all(
            database
                .parent()
                .context("fixture database has no parent")?,
        )?;
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch(include_str!("../tests/fixtures/core_state_beta_v0.sql"))?;
        }

        let store = StateStore::open(&database)?;
        assert!(store.pending_approvals()?.is_empty());
        let migrated_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111")?;
        let migrated = store
            .approval_status(migrated_id)?
            .context("migrated approval is missing")?;
        assert_eq!(migrated.connector_id, "beta-local");
        assert_eq!(migrated.tool_name, "fs_write");
        assert_eq!(migrated.argument_hash, "approval-hash-v0");
        assert_eq!(migrated.status, ApprovalStatus::Expired);
        assert_eq!(migrated.principal, ApprovalPrincipal::Legacy);
        assert!(migrated.resolved_at.is_some());

        assert!(store.persistent_grants(Some("beta-local"))?.is_empty());
        assert!(!store.grant_allows(
            "beta-local",
            &ApprovalPrincipal::LocalStdio,
            "fs_write",
            "persistent-hash-v0",
        )?);

        let (version, temporary_count, persistent_count, temporary_columns, anchor): (
            i64,
            i64,
            i64,
            Vec<String>,
            String,
        ) = store.test_call(|connection| {
            let version = connection.query_row(
                "SELECT version FROM schema_versions WHERE component = 'core_state'",
                [],
                |row| row.get(0),
            )?;
            let temporary_count =
                connection.query_row("SELECT COUNT(*) FROM temporary_grants", [], |row| {
                    row.get(0)
                })?;
            let persistent_count =
                connection.query_row("SELECT COUNT(*) FROM persistent_grants", [], |row| {
                    row.get(0)
                })?;
            let temporary_columns = connection
                .prepare("PRAGMA table_info(temporary_grants)")?
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let anchor = connection.query_row(
                "SELECT anchor_hash FROM audit_chain_state WHERE id = 1",
                [],
                |row| row.get(0),
            )?;
            Ok((
                version,
                temporary_count,
                persistent_count,
                temporary_columns,
                anchor,
            ))
        })?;
        assert_eq!(version, STATE_SCHEMA_VERSION);
        assert_eq!(temporary_count, 0);
        assert_eq!(persistent_count, 0);
        assert!(
            temporary_columns
                .iter()
                .any(|column| column == "argument_hash")
        );
        assert!(
            temporary_columns
                .iter()
                .any(|column| column == "principal_fingerprint")
        );
        assert_eq!(anchor, "GENESIS");
        assert!(store.verify_audit_chain()?);
        Ok(())
    }

    #[test]
    fn corrupt_state_database_fails_without_replacing_bytes() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        let corrupt = b"not-a-sqlite-database-and-must-not-be-replaced".to_vec();
        std::fs::write(&database, &corrupt)?;

        assert!(StateStore::open(&database).is_err());
        assert_eq!(std::fs::read(&database)?, corrupt);
        Ok(())
    }

    #[test]
    fn trusted_state_backup_can_restore_after_corruption() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        let backup = directory.path().join("state.db.backup");
        {
            let store = StateStore::open(&database)?;
            store.append_audit(&test_audit_event("backup survives"))?;
            assert!(store.verify_audit_chain()?);
        }
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        }
        std::fs::copy(&database, &backup)?;
        std::fs::write(&database, b"corrupt")?;
        assert!(StateStore::open(&database).is_err());

        std::fs::copy(&backup, &database)?;
        let restored = StateStore::open(&database)?;
        assert_eq!(restored.audit_tail(10)?.len(), 1);
        assert!(restored.verify_audit_chain()?);
        Ok(())
    }

    #[test]
    fn concurrent_legacy_migration_is_serialized_and_idempotent() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state").join("state.db");
        std::fs::create_dir_all(
            database
                .parent()
                .context("fixture database has no parent")?,
        )?;
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch(include_str!("../tests/fixtures/core_state_beta_v0.sql"))?;
        }
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let database = database.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || -> Result<StateStore> {
                barrier.wait();
                StateStore::open(&database)
            }));
        }
        barrier.wait();
        let mut stores = Vec::new();
        for thread in threads {
            stores.push(
                thread
                    .join()
                    .map_err(|_| anyhow!("migration thread panicked"))??,
            );
        }
        for store in &stores {
            assert!(store.pending_approvals()?.is_empty());
            assert!(store.persistent_grants(Some("beta-local"))?.is_empty());
        }
        let version: i64 = stores[0].test_call(|connection| {
            Ok(connection.query_row(
                "SELECT version FROM schema_versions WHERE component = 'core_state'",
                [],
                |row| row.get(0),
            )?)
        })?;
        assert_eq!(version, STATE_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn malformed_wal_never_causes_silent_empty_state_fallback() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        {
            let store = StateStore::open(&database)?;
            store.append_audit(&test_audit_event("persisted before malformed wal"))?;
        }
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        }
        let wal = sqlite_sidecar(&database, "-wal");
        std::fs::write(&wal, b"malformed-wal-header")?;
        match StateStore::open(&database) {
            Ok(store) => {
                let records = store.audit_tail(10)?;
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].event.summary, "persisted before malformed wal");
                assert!(store.verify_audit_chain()?);
            }
            Err(_) => {
                assert!(database.is_file());
            }
        }
        Ok(())
    }

    #[test]
    fn state_schema_version_is_recorded_and_future_versions_are_rejected() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        let audit_mac = AuditMacKey::generate()?;
        migrate(&connection, &audit_mac)?;
        let version: i64 = connection.query_row(
            "SELECT version FROM schema_versions WHERE component = 'core_state'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(version, STATE_SCHEMA_VERSION);
        connection.execute(
            "UPDATE schema_versions SET version = 999 WHERE component = 'core_state'",
            [],
        )?;
        assert!(migrate(&connection, &audit_mac).is_err());
        Ok(())
    }
    fn test_audit_event(summary: &str) -> AuditEvent {
        AuditEvent::new(
            "test-connector",
            "fs_write",
            "files_write",
            crate::AuditOutcome::Succeeded,
            "argument-hash",
            summary,
        )
    }

    #[test]
    fn incremental_audit_verification_advances_authenticated_checkpoint() -> Result<()> {
        let store = StateStore::in_memory()?;
        store.append_audit(&test_audit_event("first"))?;
        store.append_audit(&test_audit_event("second"))?;
        assert!(store.verify_audit_chain()?);
        let checkpoint: i64 = store.test_call(|connection| {
            Ok(connection.query_row(
                "SELECT sequence FROM audit_verification_checkpoint WHERE id = 1",
                [],
                |row| row.get(0),
            )?)
        })?;
        assert_eq!(checkpoint, 2);

        store.append_audit(&test_audit_event("third"))?;
        let report = store.verify_audit_chain_incremental()?;
        assert!(report.valid);
        assert!(!report.full);
        assert_eq!(report.checkpoint_sequence, 2);
        assert_eq!(report.tail_sequence, 3);
        assert_eq!(report.records_verified, 1);
        let advanced: i64 = store.test_call(|connection| {
            Ok(connection.query_row(
                "SELECT sequence FROM audit_verification_checkpoint WHERE id = 1",
                [],
                |row| row.get(0),
            )?)
        })?;
        assert_eq!(advanced, 3);
        Ok(())
    }

    #[test]
    fn incremental_audit_verification_rejects_checkpoint_row_tampering() -> Result<()> {
        let store = StateStore::in_memory()?;
        store.append_audit(&test_audit_event("checkpointed"))?;
        assert!(store.verify_audit_chain()?);
        store.test_call(|connection| {
            connection.execute(
                "UPDATE audit_events SET summary = 'tampered before checkpoint' WHERE sequence = 1",
                [],
            )?;
            Ok(())
        })?;
        let report = store.verify_audit_chain_incremental()?;
        assert!(!report.valid);
        assert!(!report.full);
        assert_eq!(report.records_verified, 0);
        Ok(())
    }

    #[test]
    fn audit_pruning_invalidates_checkpoint_and_forces_full_verification() -> Result<()> {
        let store = StateStore::in_memory()?;
        store.append_audit(&test_audit_event("old"))?;
        assert!(store.verify_audit_chain()?);
        store.test_call(|connection| {
            connection.execute(
                "UPDATE audit_events SET timestamp = '2000-01-01T00:00:00+00:00' WHERE sequence = 1",
                [],
            )?;
            let audit_mac = AuditMacKey::generate()?;
            let _ = audit_mac;
            Ok(())
        })?;
        // The public pruning path authenticates and re-anchors the retained chain, then deletes
        // any checkpoint that was bound to the previous anchor.
        let audit_mac = store.audit_mac.clone();
        store.test_call(move |connection| {
            let _ = prune_audit_connection(
                connection,
                chrono::Duration::zero(),
                AUDIT_MAX_BYTES,
                &audit_mac,
            )?;
            Ok(())
        })?;
        let checkpoint_count: i64 = store.test_call(|connection| {
            Ok(connection.query_row(
                "SELECT COUNT(*) FROM audit_verification_checkpoint",
                [],
                |row| row.get(0),
            )?)
        })?;
        assert_eq!(checkpoint_count, 0);
        let report = store.verify_audit_chain_incremental()?;
        assert!(report.valid);
        assert!(report.full);
        Ok(())
    }

    #[test]
    #[ignore = "scheduled large-state soak"]
    fn large_audit_chain_incremental_verification_soak() -> Result<()> {
        const INITIAL: usize = 20_000;
        const INCREMENTAL: usize = 2_000;
        let store = StateStore::in_memory()?;
        for index in 0..INITIAL {
            store.append_audit(&test_audit_event(&format!("initial-{index}")))?;
        }
        let full = store.verify_audit_chain_incremental()?;
        assert!(full.valid);
        assert!(full.full);
        assert_eq!(full.records_verified, INITIAL);
        for index in 0..INCREMENTAL {
            store.append_audit(&test_audit_event(&format!("incremental-{index}")))?;
        }
        let incremental = store.verify_audit_chain_incremental()?;
        assert!(incremental.valid);
        assert!(!incremental.full);
        assert_eq!(incremental.records_verified, INCREMENTAL);
        assert_eq!(
            usize::try_from(incremental.tail_sequence)?,
            INITIAL + INCREMENTAL
        );
        assert_eq!(store.audit_tail(100)?.len(), 100);
        Ok(())
    }

    #[test]
    fn audit_integrity_rejects_denormalized_column_tampering() -> Result<()> {
        let store = StateStore::in_memory()?;
        store.append_audit(&test_audit_event("original summary"))?;
        assert!(store.verify_audit_chain()?);
        store.test_call(|connection| {
            connection.execute(
                "UPDATE audit_events SET summary = 'tampered summary' WHERE sequence = 1",
                [],
            )?;
            Ok(())
        })?;
        assert!(!store.verify_audit_chain()?);
        Ok(())
    }

    #[test]
    fn audit_integrity_rejects_tail_truncation() -> Result<()> {
        let store = StateStore::in_memory()?;
        store.append_audit(&test_audit_event("first"))?;
        store.append_audit(&test_audit_event("second"))?;
        assert!(store.verify_audit_chain()?);
        store.test_call(|connection| {
            connection.execute(
                "DELETE FROM audit_events WHERE sequence = (SELECT MAX(sequence) FROM audit_events)",
                [],
            )?;
            Ok(())
        })?;
        assert!(!store.verify_audit_chain()?);
        Ok(())
    }

    #[test]
    fn version_three_reopen_does_not_backfill_a_truncated_tail() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        {
            let store = StateStore::open(&database)?;
            store.append_audit(&test_audit_event("first"))?;
            store.append_audit(&test_audit_event("second"))?;
            assert!(store.verify_audit_chain()?);
        }
        {
            let connection = Connection::open(&database)?;
            connection.execute(
                "DELETE FROM audit_events WHERE sequence = (SELECT MAX(sequence) FROM audit_events)",
                [],
            )?;
        }
        let reopened = StateStore::open(&database)?;
        assert!(!reopened.verify_audit_chain()?);
        Ok(())
    }

    #[test]
    fn audit_integrity_rejects_record_mac_tampering() -> Result<()> {
        let store = StateStore::in_memory()?;
        store.append_audit(&test_audit_event("mac protected"))?;
        assert!(store.verify_audit_chain()?);
        store.test_call(|connection| {
            connection.execute(
                "UPDATE audit_events SET record_mac = printf('%064d', 0) WHERE sequence = 1",
                [],
            )?;
            Ok(())
        })?;
        assert!(!store.verify_audit_chain()?);
        Ok(())
    }
}
