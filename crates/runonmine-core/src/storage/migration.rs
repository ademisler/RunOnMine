use anyhow::{Context, Result, bail};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};

use super::audit_store::audit_anchor;
use super::{ApprovalPrincipal, AuditMacKey, STATE_SCHEMA_VERSION};

pub(super) fn migrate(connection: &Connection, audit_mac: &AuditMacKey) -> Result<()> {
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
