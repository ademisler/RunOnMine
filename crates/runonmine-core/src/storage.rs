use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};
use uuid::Uuid;

use crate::approval::{ApprovalDecision, ApprovalRequest, ApprovalStatus};
use crate::audit::AuditEvent;

pub const AUDIT_RETENTION_DAYS: i64 = 30;
pub const AUDIT_MAX_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Clone, Debug, serde::Serialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub event: AuditEvent,
    pub previous_hash: String,
    pub record_hash: String,
}

#[derive(Clone, Debug)]
pub struct StateStore {
    connection: Arc<Mutex<Connection>>,
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
        }
        let connection = Connection::open(path)
            .with_context(|| format!("failed to open state database at {}", path.display()))?;
        configure_connection(&connection)?;
        migrate(&connection)?;
        restrict_file(path)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let connection = Connection::open_in_memory()?;
        configure_connection(&connection)?;
        migrate(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow!("state database lock is poisoned"))
    }

    pub fn insert_approval(&self, request: &ApprovalRequest) -> Result<()> {
        self.lock()?.execute(
            "INSERT INTO approvals (
                id, connector_id, tool_name, argument_summary, argument_hash,
                status, created_at, expires_at, resolved_at, decision
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL)",
            params![
                request.id.to_string(),
                request.connector_id,
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

    pub fn resolve_approval(&self, id: Uuid, decision: ApprovalDecision) -> Result<bool> {
        let mut connection = self.lock()?;
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
                "INSERT INTO temporary_grants (connector_id, tool_name, expires_at)
                 SELECT connector_id, tool_name, ?1 FROM approvals WHERE id = ?2
                 ON CONFLICT(connector_id, tool_name)
                 DO UPDATE SET expires_at = excluded.expires_at",
                params![
                    (Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                    id.to_string()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(changed == 1)
    }

    pub fn temporary_grant_allows(&self, connector_id: &str, tool_name: &str) -> Result<bool> {
        let connection = self.lock()?;
        connection.execute(
            "DELETE FROM temporary_grants WHERE expires_at <= ?1",
            [Utc::now().to_rfc3339()],
        )?;
        let exists = connection
            .query_row(
                "SELECT 1 FROM temporary_grants
                 WHERE connector_id = ?1 AND tool_name = ?2 AND expires_at > ?3",
                params![connector_id, tool_name, Utc::now().to_rfc3339()],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(exists)
    }

    pub fn approval_status(&self, id: Uuid) -> Result<Option<ApprovalRequest>> {
        let connection = self.lock()?;
        expire_approvals(&connection)?;
        connection
            .query_row(
                "SELECT id, connector_id, tool_name, argument_summary, argument_hash,
                        status, created_at, expires_at, resolved_at, decision
                 FROM approvals WHERE id = ?1",
                [id.to_string()],
                map_approval,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn pending_approvals(&self) -> Result<Vec<ApprovalRequest>> {
        let connection = self.lock()?;
        expire_approvals(&connection)?;
        let mut statement = connection.prepare(
            "SELECT id, connector_id, tool_name, argument_summary, argument_hash,
                    status, created_at, expires_at, resolved_at, decision
             FROM approvals WHERE status = 'pending' ORDER BY created_at",
        )?;
        let rows = statement.query_map([], map_approval)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn append_audit(&self, event: &AuditEvent) -> Result<String> {
        let mut connection = self.lock()?;
        let previous: String = connection
            .query_row(
                "SELECT record_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(audit_anchor(&connection)?);
        let payload = serde_json::to_vec(event)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(previous.as_bytes());
        hasher.update(&payload);
        let record_hash = hasher.finalize().to_hex().to_string();
        connection.execute(
            "INSERT INTO audit_events (
                id, timestamp, connector_id, tool_name, capability, outcome,
                argument_hash, summary, duration_ms, output_bytes,
                previous_hash, record_hash, payload
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                event.id.to_string(),
                event.timestamp.to_rfc3339(),
                event.connector_id,
                event.tool_name,
                event.capability,
                serde_json::to_string(&event.outcome)?,
                event.argument_hash,
                event.summary,
                event
                    .duration_ms
                    .and_then(|value| i64::try_from(value).ok()),
                event
                    .output_bytes
                    .and_then(|value| i64::try_from(value).ok()),
                previous,
                record_hash,
                payload,
            ],
        )?;
        if connection.last_insert_rowid() % 128 == 0 {
            prune_audit_connection(
                &mut connection,
                chrono::Duration::days(AUDIT_RETENTION_DAYS),
                AUDIT_MAX_BYTES,
            )?;
        }
        Ok(record_hash)
    }

    /// Apply the default age and storage limits to the audit log.
    pub fn prune_audit(&self) -> Result<usize> {
        let mut connection = self.lock()?;
        prune_audit_connection(
            &mut connection,
            chrono::Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
        )
    }

    pub fn verify_audit_chain(&self) -> Result<bool> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT previous_hash, record_hash, payload FROM audit_events ORDER BY sequence",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_previous = audit_anchor(&connection)?;
        while let Some(row) = rows.next()? {
            let previous: String = row.get(0)?;
            let record_hash: String = row.get(1)?;
            let payload: Vec<u8> = row.get(2)?;
            if previous != expected_previous {
                return Ok(false);
            }
            let mut hasher = blake3::Hasher::new();
            hasher.update(previous.as_bytes());
            hasher.update(&payload);
            if hasher.finalize().to_hex().as_str() != record_hash {
                return Ok(false);
            }
            expected_previous = record_hash;
        }
        Ok(true)
    }

    pub fn audit_tail(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let limit = i64::try_from(limit.clamp(1, 10_000)).unwrap_or(10_000);
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT sequence, payload, previous_hash, record_hash
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
            })
        })?;
        let mut records = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        records.reverse();
        Ok(records)
    }
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
            expires_at TEXT NOT NULL,
            PRIMARY KEY (connector_id, tool_name)
        );
        CREATE INDEX IF NOT EXISTS temporary_grants_expiry_idx
            ON temporary_grants(expires_at);
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

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::audit::{AuditEvent, AuditOutcome};

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
        assert!(store.temporary_grant_allows("local", "shell_exec")?);
        assert!(!store.temporary_grant_allows("local", "fs_write")?);
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
        let mut connection = store.lock()?;
        let removed = prune_audit_connection(
            &mut connection,
            Duration::days(AUDIT_RETENTION_DAYS),
            AUDIT_MAX_BYTES,
        )?;
        drop(connection);
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
        let mut connection = store.lock()?;
        let removed =
            prune_audit_connection(&mut connection, Duration::days(AUDIT_RETENTION_DAYS), 1_600)?;
        drop(connection);
        assert!(removed >= 2);
        assert!(store.verify_audit_chain()?);
        Ok(())
    }
}
