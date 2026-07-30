use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, mpsc};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::approval::{
    ApprovalDecision, ApprovalPrincipal, ApprovalRequest, ApprovalStatus, ApprovalTimeoutResult,
    PersistentGrant,
};
use crate::audit::{AuditEvent, AuditOutcome};

pub const AUDIT_RETENTION_DAYS: i64 = 30;
pub const AUDIT_MAX_BYTES: u64 = 100 * 1024 * 1024;
const STATE_SCHEMA_VERSION: i64 = 3;

type DbJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

enum DbMessage {
    Run(DbJob),
    Shutdown,
}

struct SqliteWorker {
    sender: Option<mpsc::Sender<DbMessage>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for SqliteWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteWorker")
            .finish_non_exhaustive()
    }
}

impl SqliteWorker {
    fn start(mut connection: Connection) -> Result<Self> {
        let (sender, receiver) = mpsc::channel::<DbMessage>();
        let thread = std::thread::Builder::new()
            .name("runonmine-state-db".to_owned())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    match message {
                        DbMessage::Run(job) => job(&mut connection),
                        DbMessage::Shutdown => break,
                    }
                }
            })
            .context("failed to start state database worker")?;
        Ok(Self {
            sender: Some(sender),
            thread: Mutex::new(Some(thread)),
        })
    }

    fn call<T, F>(&self, operation: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let (reply, receive) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .context("state database worker is unavailable")?
            .send(DbMessage::Run(Box::new(move |connection| {
                let _ignored = reply.send(operation(connection));
            })))
            .map_err(|_| anyhow!("state database worker is unavailable"))?;
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
        self.sender
            .as_ref()
            .context("state database worker is unavailable")?
            .send(DbMessage::Run(Box::new(move |connection| {
                let _ignored = reply.send(operation(connection));
            })))
            .map_err(|_| anyhow!("state database worker is unavailable"))?;
        receive
            .await
            .map_err(|_| anyhow!("state database worker stopped unexpectedly"))?
    }
}

impl Drop for SqliteWorker {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ignored = sender.send(DbMessage::Shutdown);
        }
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
}

#[derive(Clone, Debug)]
pub struct StateStore {
    worker: Arc<SqliteWorker>,
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
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open state database at {}", path.display()))?;
        configure_connection(&connection)?;
        migrate(&connection)?;
        restrict_sqlite_files(path)?;
        Ok(Self {
            worker: Arc::new(SqliteWorker::start(connection)?),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        migrate(&connection)?;
        Ok(Self {
            worker: Arc::new(SqliteWorker::start(connection)?),
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

    pub fn insert_approval(&self, request: &ApprovalRequest) -> Result<()> {
        let request = request.clone();
        self.call(move |connection| insert_approval_connection(connection, &request))
    }

    pub async fn insert_approval_async(&self, request: ApprovalRequest) -> Result<()> {
        self.call_async(move |connection| insert_approval_connection(connection, &request))
            .await
    }

    pub fn resolve_approval(&self, id: Uuid, decision: ApprovalDecision) -> Result<bool> {
        self.call(move |connection| resolve_approval_connection(connection, id, decision))
    }

    pub async fn resolve_approval_async(
        &self,
        id: Uuid,
        decision: ApprovalDecision,
    ) -> Result<bool> {
        self.call_async(move |connection| resolve_approval_connection(connection, id, decision))
            .await
    }

    pub fn complete_approval_timeout(
        &self,
        id: Uuid,
        event: &AuditEvent,
    ) -> Result<Option<ApprovalTimeoutResult>> {
        let event = event.clone();
        self.call(move |connection| complete_approval_timeout_connection(connection, id, &event))
    }

    pub async fn complete_approval_timeout_async(
        &self,
        id: Uuid,
        event: AuditEvent,
    ) -> Result<Option<ApprovalTimeoutResult>> {
        self.call_async(move |connection| {
            complete_approval_timeout_connection(connection, id, &event)
        })
        .await
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
        self.call(|connection| {
            let transaction=connection.transaction()?; let now=Utc::now().to_rfc3339();
            let denied=transaction.execute("UPDATE approvals SET status = 'denied', resolved_at = ?1, decision = 'deny' WHERE status = 'pending'", [&now])?;
            let cleared=transaction.execute("DELETE FROM temporary_grants", [])?; transaction.commit()?; Ok((denied,cleared))
        })
    }

    pub fn append_audit(&self, event: &AuditEvent) -> Result<String> {
        let event = event.clone();
        self.call(move |connection| append_audit_connection(connection, &event))
    }

    pub async fn append_audit_async(&self, event: AuditEvent) -> Result<String> {
        self.call_async(move |connection| append_audit_connection(connection, &event))
            .await
    }

    pub fn prune_audit(&self) -> Result<usize> {
        self.call(|connection| {
            prune_audit_connection(
                connection,
                chrono::Duration::days(AUDIT_RETENTION_DAYS),
                AUDIT_MAX_BYTES,
            )
        })
    }

    pub fn verify_audit_chain(&self) -> Result<bool> {
        self.call(verify_audit_chain_connection)
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
    let (_, sequence) = append_audit_row(&transaction, event)?;
    transaction.commit()?;
    if sequence % 128 == 0 {
        let _ignored = prune_audit_connection(
            connection,
            chrono::Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
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

fn append_audit_connection(connection: &mut Connection, event: &AuditEvent) -> Result<String> {
    let (record_hash, sequence) = append_audit_row(connection, event)?;
    if sequence % 128 == 0 {
        prune_audit_connection(
            connection,
            chrono::Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
        )?;
    }
    Ok(record_hash)
}

fn append_audit_row(connection: &Connection, event: &AuditEvent) -> Result<(String, i64)> {
    let previous: String = connection
        .query_row(
            "SELECT record_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(audit_anchor(connection)?);
    let payload = serde_json::to_vec(event)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(previous.as_bytes());
    hasher.update(&payload);
    let record_hash = hasher.finalize().to_hex().to_string();
    connection.execute("INSERT INTO audit_events (id, timestamp, connector_id, tool_name, capability, outcome, argument_hash, summary, duration_ms, output_bytes, previous_hash, record_hash, payload) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",params![event.id.to_string(),event.timestamp.to_rfc3339(),event.connector_id,event.tool_name,event.capability,serde_json::to_string(&event.outcome)?,event.argument_hash,event.summary,event.duration_ms.and_then(|v|i64::try_from(v).ok()),event.output_bytes.and_then(|v|i64::try_from(v).ok()),previous,record_hash,payload])?;
    Ok((record_hash, connection.last_insert_rowid()))
}

fn verify_audit_chain_connection(connection: &mut Connection) -> Result<bool> {
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

fn audit_tail_connection(connection: &mut Connection, limit: usize) -> Result<Vec<AuditRecord>> {
    let limit = i64::try_from(limit.clamp(1, 10_000)).unwrap_or(10_000);
    let mut statement=connection.prepare("SELECT sequence, payload, previous_hash, record_hash FROM audit_events ORDER BY sequence DESC LIMIT ?1")?;
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

fn migrate(connection: &Connection) -> Result<()> {
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
            payload BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_chain_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            anchor_hash TEXT NOT NULL
        );
        INSERT OR IGNORE INTO audit_chain_state (id, anchor_hash)
            VALUES (1, 'GENESIS');",
    )?;
    Ok(())
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
) -> Result<usize> {
    let rows = {
        let mut statement = connection.prepare(
            "SELECT sequence, timestamp, record_hash,
                    length(payload) + length(previous_hash) + length(record_hash) +
                    length(connector_id) + length(tool_name) + length(capability) +
                    length(outcome) + length(argument_hash) + length(summary) + 128
             FROM audit_events ORDER BY sequence",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if rows.is_empty() {
        return Ok(0);
    }

    let cutoff = Utc::now() - max_age;
    let mut delete_count = 0_usize;
    for (_, timestamp, _, _) in &rows {
        let parsed = DateTime::<Utc>::from_str(timestamp)
            .context("audit event contains an invalid timestamp")?;
        if parsed >= cutoff {
            break;
        }
        delete_count += 1;
    }
    let mut retained_bytes = rows[delete_count..].iter().try_fold(0_u64, |total, row| {
        let bytes = u64::try_from(row.3).context("audit event size is invalid")?;
        Ok::<u64, anyhow::Error>(total.saturating_add(bytes))
    })?;
    while delete_count < rows.len() && retained_bytes > max_bytes {
        let bytes = u64::try_from(rows[delete_count].3).context("audit event size is invalid")?;
        retained_bytes = retained_bytes.saturating_sub(bytes);
        delete_count += 1;
    }
    if delete_count == 0 {
        return Ok(0);
    }

    let (last_sequence, _, anchor_hash, _) = &rows[delete_count - 1];
    let transaction = connection.transaction()?;
    transaction.execute(
        "DELETE FROM audit_events WHERE sequence <= ?1",
        [last_sequence],
    )?;
    transaction.execute(
        "UPDATE audit_chain_state SET anchor_hash = ?1 WHERE id = 1",
        [anchor_hash],
    )?;
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
        let removed = store.test_call(|connection| {
            prune_audit_connection(
                connection,
                Duration::days(AUDIT_RETENTION_DAYS),
                AUDIT_MAX_BYTES,
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
        let removed = store.test_call(|connection| {
            prune_audit_connection(connection, Duration::days(AUDIT_RETENTION_DAYS), 1_600)
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
    fn state_schema_version_is_recorded_and_future_versions_are_rejected() -> Result<()> {
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        migrate(&connection)?;
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
        assert!(migrate(&connection).is_err());
        Ok(())
    }    fn test_audit_event(summary: &str) -> AuditEvent {
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
