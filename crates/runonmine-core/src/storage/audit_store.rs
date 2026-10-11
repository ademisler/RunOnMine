use std::str::FromStr;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, params};

use super::{
    AUDIT_MAX_BYTES, AUDIT_RETENTION_DAYS, AuditEvent, AuditMacKey, AuditRecord,
    AuditVerificationReport,
};

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

pub(super) fn append_audit_connection(
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

pub(super) fn append_audit_row(
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

pub(super) fn verify_audit_chain_full_connection(
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

pub(super) fn verify_audit_chain_incremental_connection(
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

pub(super) fn audit_tail_connection(
    connection: &mut Connection,
    limit: usize,
) -> Result<Vec<AuditRecord>> {
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

pub(super) fn audit_anchor(connection: &Connection) -> Result<String> {
    connection
        .query_row(
            "SELECT anchor_hash FROM audit_chain_state WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .context("audit chain anchor is missing")
}

pub(super) fn prune_audit_connection(
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
