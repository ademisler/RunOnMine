use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, mpsc};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use tokio::sync::oneshot;
use uuid::Uuid;

use crate::approval::{ApprovalDecision, ApprovalRequest, ApprovalStatus, PersistentGrant};
use crate::audit::AuditEvent;

pub const AUDIT_RETENTION_DAYS: i64 = 30;
pub const AUDIT_MAX_BYTES: u64 = 100 * 1024 * 1024;
const STATE_SCHEMA_VERSION: i64 = 2;

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

    pub fn grant_allows(
        &self,
        connector_id: &str,
        tool_name: &str,
        argument_hash: &str,
    ) -> Result<bool> {
        let connector_id = connector_id.to_owned();
        let tool_name = tool_name.to_owned();
        let argument_hash = argument_hash.to_owned();
        self.call(move |connection| {
            grant_allows_connection(connection, &connector_id, &tool_name, &argument_hash)
        })
    }

    pub async fn grant_allows_async(
        &self,
        connector_id: String,
        tool_name: String,
        argument_hash: String,
    ) -> Result<bool> {
        self.call_async(move |connection| {
            grant_allows_connection(connection, &connector_id, &tool_name, &argument_hash)
        })
        .await
    }

    pub fn temporary_grant_allows(
        &self,
        connector_id: &str,
        tool_name: &str,
        argument_hash: &str,
    ) -> Result<bool> {
        self.grant_allows(connector_id, tool_name, argument_hash)
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
        tool_name: &str,
        argument_hash: &str,
    ) -> Result<bool> {
        let connector_id = connector_id.to_owned();
        let tool_name = tool_name.to_owned();
        let argument_hash = argument_hash.to_owned();
        self.call(move |connection| Ok(connection.execute("DELETE FROM persistent_grants WHERE connector_id = ?1 AND tool_name = ?2 AND argument_hash = ?3", params![connector_id, tool_name, argument_hash])? == 1))
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
    connection.execute("INSERT INTO approvals (id, connector_id, tool_name, argument_summary, argument_hash, status, created_at, expires_at, resolved_at, decision) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)", params![request.id.to_string(), request.connector_id, request.tool_name, request.argument_summary, request.argument_hash, status_name(request.status), request.created_at.to_rfc3339(), request.expires_at.to_rfc3339()])?;
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
    let changed=transaction.execute("UPDATE approvals SET status = ?1, resolved_at = ?2, decision = ?3 WHERE id = ?4 AND status = 'pending' AND expires_at > ?2", params![status, now, decision_name(decision), id.to_string()])?;
    if changed == 1 && decision == ApprovalDecision::ForTenMinutes {
        transaction.execute("INSERT INTO temporary_grants (connector_id, tool_name, argument_hash, expires_at) SELECT connector_id, tool_name, argument_hash, ?1 FROM approvals WHERE id = ?2 ON CONFLICT(connector_id, tool_name, argument_hash) DO UPDATE SET expires_at = excluded.expires_at", params![(Utc::now()+chrono::Duration::minutes(10)).to_rfc3339(), id.to_string()])?;
    } else if changed == 1 && decision == ApprovalDecision::Always {
        transaction.execute("INSERT INTO persistent_grants (connector_id, tool_name, argument_hash, argument_summary, created_at) SELECT connector_id, tool_name, argument_hash, argument_summary, ?1 FROM approvals WHERE id = ?2 ON CONFLICT(connector_id, tool_name, argument_hash) DO UPDATE SET argument_summary = excluded.argument_summary, created_at = excluded.created_at", params![Utc::now().to_rfc3339(), id.to_string()])?;
    }
    transaction.commit()?;
    Ok(changed == 1)
}

fn grant_allows_connection(
    connection: &mut Connection,
    connector_id: &str,
    tool_name: &str,
    argument_hash: &str,
) -> Result<bool> {
    let now = Utc::now().to_rfc3339();
    connection.execute(
        "DELETE FROM temporary_grants WHERE expires_at <= ?1",
        [&now],
    )?;
    Ok(connection.query_row("SELECT 1 FROM temporary_grants WHERE connector_id = ?1 AND tool_name = ?2 AND argument_hash = ?3 AND expires_at > ?4 UNION ALL SELECT 1 FROM persistent_grants WHERE connector_id = ?1 AND tool_name = ?2 AND argument_hash = ?3 LIMIT 1",params![connector_id,tool_name,argument_hash,now], |_|Ok(())).optional()?.is_some())
}

fn persistent_grants_connection(
    connection: &mut Connection,
    connector_id: Option<&str>,
) -> Result<Vec<PersistentGrant>> {
    let mut statement=connection.prepare("SELECT connector_id, tool_name, argument_summary, argument_hash, created_at FROM persistent_grants WHERE (?1 IS NULL OR connector_id = ?1) ORDER BY created_at DESC, connector_id, tool_name")?;
    let rows = statement.query_map([connector_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    rows.map(|row| {
        let (c, t, s, h, created) = row?;
        Ok(PersistentGrant {
            connector_id: c,
            tool_name: t,
            argument_summary: s,
            argument_hash: h,
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
    expire_approvals(connection)?;
    connection.query_row("SELECT id, connector_id, tool_name, argument_summary, argument_hash, status, created_at, expires_at, resolved_at, decision FROM approvals WHERE id = ?1",[id.to_string()],map_approval).optional().map_err(Into::into)
}
fn pending_approvals_connection(connection: &mut Connection) -> Result<Vec<ApprovalRequest>> {
    expire_approvals(connection)?;
    let mut statement=connection.prepare("SELECT id, connector_id, tool_name, argument_summary, argument_hash, status, created_at, expires_at, resolved_at, decision FROM approvals WHERE status = 'pending' ORDER BY created_at")?;
    let rows = statement.query_map([], map_approval)?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn append_audit_connection(connection: &mut Connection, event: &AuditEvent) -> Result<String> {
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
    if connection.last_insert_rowid() % 128 == 0 {
        prune_audit_connection(
            connection,
            chrono::Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
        )?;
    }
    Ok(record_hash)
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
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_versions (
            component TEXT PRIMARY KEY,
            version INTEGER NOT NULL CHECK (version >= 0)
        );",
    )?;
    let current = connection
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

    let temporary_grants_has_argument_hash = connection
        .prepare("PRAGMA table_info(temporary_grants)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|column| column == "argument_hash");
    if !temporary_grants_has_argument_hash {
        // Temporary grants are intentionally ephemeral. Dropping the legacy
        // tool-wide table prevents an old broad grant from surviving upgrade.
        connection.execute("DROP TABLE IF EXISTS temporary_grants", [])?;
    }
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS approvals (
            id TEXT PRIMARY KEY,
            connector_id TEXT NOT NULL,
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
            ON approvals(status, expires_at);
        CREATE TABLE IF NOT EXISTS temporary_grants (
            connector_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            argument_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, tool_name, argument_hash)
        );
        CREATE INDEX IF NOT EXISTS temporary_grants_expiry_idx
            ON temporary_grants(expires_at);
        CREATE TABLE IF NOT EXISTS persistent_grants (
            connector_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            argument_hash TEXT NOT NULL,
            argument_summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, tool_name, argument_hash)
        );
        CREATE INDEX IF NOT EXISTS persistent_grants_connector_idx
            ON persistent_grants(connector_id, tool_name);
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
    connection.execute(
        "INSERT INTO schema_versions(component, version) VALUES ('core_state', ?1)
         ON CONFLICT(component) DO UPDATE SET version = excluded.version",
        [STATE_SCHEMA_VERSION],
    )?;
    Ok(())
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

fn expire_approvals(connection: &Connection) -> Result<()> {
    connection.execute(
        "UPDATE approvals SET status = 'expired'
         WHERE status = 'pending' AND expires_at <= ?1",
        [Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn map_approval(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRequest> {
    let parse_error = |index: usize, error: anyhow::Error| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, error.into())
    };
    let id_text: String = row.get(0)?;
    let status_text: String = row.get(5)?;
    let created_text: String = row.get(6)?;
    let expires_text: String = row.get(7)?;
    let resolved_text: Option<String> = row.get(8)?;
    let decision_text: Option<String> = row.get(9)?;
    Ok(ApprovalRequest {
        id: Uuid::parse_str(&id_text).map_err(|error| parse_error(0, error.into()))?,
        connector_id: row.get(1)?,
        tool_name: row.get(2)?,
        argument_summary: row.get(3)?,
        argument_hash: row.get(4)?,
        status: parse_status(&status_text).map_err(|error| parse_error(5, error))?,
        created_at: DateTime::<Utc>::from_str(&created_text)
            .map_err(|error| parse_error(6, error.into()))?,
        expires_at: DateTime::<Utc>::from_str(&expires_text)
            .map_err(|error| parse_error(7, error.into()))?,
        resolved_at: resolved_text
            .map(|value| {
                DateTime::<Utc>::from_str(&value).map_err(|error| parse_error(8, error.into()))
            })
            .transpose()?,
        decision: decision_text
            .map(|value| parse_decision(&value).map_err(|error| parse_error(9, error)))
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
            "shell_exec",
            "run a command",
            "hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        assert!(store.resolve_approval(approval.id, ApprovalDecision::ForTenMinutes)?);
        assert!(store.temporary_grant_allows("local", "shell_exec", "hash")?);
        assert!(!store.temporary_grant_allows("local", "shell_exec", "different-hash")?);
        assert!(!store.temporary_grant_allows("local", "fs_write", "hash")?);
        Ok(())
    }

    #[test]
    fn emergency_lock_denies_pending_and_clears_temporary_grants() -> Result<()> {
        let store = StateStore::in_memory()?;
        let approved = ApprovalRequest::new(
            "local",
            "shell_exec",
            "run a command",
            "approved-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approved)?;
        assert!(store.resolve_approval(approved.id, ApprovalDecision::ForTenMinutes)?);
        let pending = ApprovalRequest::new(
            "local",
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
        assert!(!store.temporary_grant_allows("local", "shell_exec", "approved-hash")?);
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
            "fs_write",
            "Path: /tmp/a.txt",
            "exact-hash",
            Utc::now() + Duration::seconds(90),
        );
        store.insert_approval(&approval)?;
        assert!(store.resolve_approval(approval.id, ApprovalDecision::Always)?);
        assert!(store.grant_allows("connector", "fs_write", "exact-hash")?);
        assert!(!store.grant_allows("connector", "fs_write", "other-hash")?);
        assert!(!store.grant_allows("connector", "shell_exec", "exact-hash")?);

        let grants = store.persistent_grants(Some("connector"))?;
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].argument_hash, "exact-hash");
        assert!(store.delete_persistent_grant("connector", "fs_write", "exact-hash")?);
        assert!(!store.grant_allows("connector", "fs_write", "exact-hash")?);
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
        let approvals = store.pending_approvals()?;
        assert_eq!(approvals.len(), 1);
        assert_eq!(
            approvals[0].id,
            Uuid::parse_str("11111111-1111-4111-8111-111111111111")?
        );
        assert_eq!(approvals[0].connector_id, "beta-local");
        assert_eq!(approvals[0].tool_name, "fs_write");
        assert_eq!(approvals[0].argument_hash, "approval-hash-v0");
        assert_eq!(approvals[0].status, ApprovalStatus::Pending);

        let grants = store.persistent_grants(Some("beta-local"))?;
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].tool_name, "fs_write");
        assert_eq!(grants[0].argument_hash, "persistent-hash-v0");
        assert!(store.grant_allows("beta-local", "fs_write", "persistent-hash-v0")?);
        assert!(!store.grant_allows("beta-local", "shell_exec", "any-argument")?);

        let (version, temporary_count, temporary_columns, anchor): (i64, i64, Vec<String>, String) =
            store.test_call(|connection| {
                let version = connection.query_row(
                    "SELECT version FROM schema_versions WHERE component = 'core_state'",
                    [],
                    |row| row.get(0),
                )?;
                let temporary_count =
                    connection.query_row("SELECT COUNT(*) FROM temporary_grants", [], |row| {
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
                Ok((version, temporary_count, temporary_columns, anchor))
            })?;
        assert_eq!(version, STATE_SCHEMA_VERSION);
        assert_eq!(temporary_count, 0);
        assert!(
            temporary_columns
                .iter()
                .any(|column| column == "argument_hash")
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
    }
}
