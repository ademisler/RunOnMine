use chrono::Duration;
use proptest::prelude::*;

use super::*;
use crate::audit::{AuditEvent, AuditOutcome};

#[tokio::test]
async fn async_status_and_pending_inventory_report_inserted_approval() -> Result<()> {
    let store = StateStore::in_memory()?;
    let approval = ApprovalRequest::new(
        "inventory-connector",
        ApprovalPrincipal::LocalHttp,
        "fs_write",
        "write inventory target",
        "inventory-argument-hash",
        Utc::now() + chrono::Duration::hours(1),
    );
    store.insert_approval(&approval)?;

    let status = store
        .approval_status_async(approval.id)
        .await?
        .context("inserted approval was missing from async status")?;
    assert_eq!(status.id, approval.id);
    assert_eq!(status.status, ApprovalStatus::Pending);

    let pending = store.pending_approvals()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].id, approval.id);
    Ok(())
}

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
    assert!(!store.temporary_grant_allows("local", &principal, "shell_exec", "timeout-hash")?);
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
        connection.execute_batch(include_str!("../../tests/fixtures/core_state_beta_v0.sql"))?;
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
        connection.execute_batch(include_str!("../../tests/fixtures/core_state_beta_v0.sql"))?;
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
proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn approval_resolution_matches_reference_model(operations in prop::collection::vec(any::<u8>(), 0..64)) {
        let Ok(store) = StateStore::in_memory() else {
            return Err(TestCaseError::fail("could not create in-memory state store"));
        };
        let principal = ApprovalPrincipal::OAuth {
            client_id: "property-client".to_owned(),
            subject: "property-owner".to_owned(),
        };
        let approval = ApprovalRequest::new(
            "property-connector",
            principal.clone(),
            "fs_write",
            "write property target",
            "property-argument-hash",
            Utc::now() + chrono::Duration::hours(1),
        );
        if store.insert_approval(&approval).is_err() {
            return Err(TestCaseError::fail("could not insert property approval"));
        }

        let mut expected_status = ApprovalStatus::Pending;
        let mut expected_decision = None;
        let mut grant_active = false;
        for operation in operations {
            match operation % 7 {
                0..=3 => {
                    let decision = match operation % 4 {
                        0 => ApprovalDecision::Once,
                        1 => ApprovalDecision::ForTenMinutes,
                        2 => ApprovalDecision::Always,
                        _ => ApprovalDecision::Deny,
                    };
                    let Ok(resolved) = store.resolve_approval(approval.id, decision) else {
                        return Err(TestCaseError::fail("could not resolve property approval"));
                    };
                    prop_assert_eq!(resolved, expected_status == ApprovalStatus::Pending);
                    if resolved {
                        expected_status = if decision == ApprovalDecision::Deny {
                            ApprovalStatus::Denied
                        } else {
                            ApprovalStatus::Approved
                        };
                        expected_decision = Some(decision);
                        grant_active = matches!(
                            decision,
                            ApprovalDecision::ForTenMinutes | ApprovalDecision::Always
                        );
                    }
                }
                4 => {
                    let Ok(Some(stored)) = store.approval_status(approval.id) else {
                        return Err(TestCaseError::fail("property approval disappeared"));
                    };
                    prop_assert_eq!(stored.status, expected_status);
                    prop_assert_eq!(stored.decision, expected_decision);
                    prop_assert_eq!(stored.principal_fingerprint, principal.fingerprint());
                }
                5 => {
                    let Ok(allowed) = store.grant_allows(
                        "property-connector",
                        &principal,
                        "fs_write",
                        "property-argument-hash",
                    ) else {
                        return Err(TestCaseError::fail("could not query property grant"));
                    };
                    prop_assert_eq!(allowed, grant_active);
                }
                _ => {
                    if store
                        .clear_persistent_grants(Some("property-connector"))
                        .is_err()
                    {
                        return Err(TestCaseError::fail(
                            "could not clear property persistent grants",
                        ));
                    }
                    if expected_decision == Some(ApprovalDecision::Always) {
                        grant_active = false;
                    }
                }
            }
        }
    }
}
