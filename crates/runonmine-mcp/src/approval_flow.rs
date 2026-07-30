use std::time::Duration;

use anyhow::Result as AnyResult;
use async_trait::async_trait;
use chrono::Utc;
use rmcp::ErrorData as McpError;
use runonmine_core::{
    ApprovalDecision, ApprovalNotificationSubscription, ApprovalPrincipal, ApprovalRequest,
    ApprovalStatus, ApprovalTimeoutResult, AuditEvent, AuditOutcome, Capability, StateStore,
};
use serde::Serialize;
use uuid::Uuid;

use crate::audit::AuditRecorder;
use crate::validation::{approval_preview, capability_name};

const APPROVAL_RECOVERY_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[async_trait]
trait ApprovalRepository: Send + Sync {
    fn subscribe(&self) -> ApprovalNotificationSubscription;
    async fn insert(&self, request: ApprovalRequest) -> AnyResult<()>;
    async fn deny(&self, id: Uuid) -> AnyResult<()>;
    async fn complete_timeout(
        &self,
        id: Uuid,
        event: AuditEvent,
    ) -> AnyResult<Option<ApprovalTimeoutResult>>;
    async fn status(&self, id: Uuid) -> AnyResult<Option<ApprovalRequest>>;
}

#[async_trait]
impl ApprovalRepository for StateStore {
    fn subscribe(&self) -> ApprovalNotificationSubscription {
        self.subscribe_approval_changes()
    }

    async fn insert(&self, request: ApprovalRequest) -> AnyResult<()> {
        self.insert_approval_async(request).await
    }

    async fn deny(&self, id: Uuid) -> AnyResult<()> {
        self.resolve_approval_async(id, ApprovalDecision::Deny)
            .await
            .map(|_| ())
    }

    async fn complete_timeout(
        &self,
        id: Uuid,
        event: AuditEvent,
    ) -> AnyResult<Option<ApprovalTimeoutResult>> {
        self.complete_approval_timeout_async(id, event).await
    }

    async fn status(&self, id: Uuid) -> AnyResult<Option<ApprovalRequest>> {
        self.approval_status_async(id).await
    }
}

#[async_trait]
trait ApprovalAudit: Send + Sync {
    async fn record_required(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) -> Result<(), McpError>;
}

#[async_trait]
impl ApprovalAudit for AuditRecorder {
    async fn record_required(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) -> Result<(), McpError> {
        AuditRecorder::record_required(self, tool_name, capability, outcome, argument_hash, summary)
            .await
    }
}

#[derive(Clone, Debug)]
pub(super) struct ApprovalFlow {
    connector_id: String,
    store: StateStore,
    audit: AuditRecorder,
    timeout: Duration,
}

impl ApprovalFlow {
    pub(super) fn new(
        connector_id: impl Into<String>,
        store: StateStore,
        audit: AuditRecorder,
        timeout: Duration,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            store,
            audit,
            timeout,
        }
    }

    pub(super) async fn request<T: Serialize>(
        &self,
        principal: &ApprovalPrincipal,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        argument_hash: &str,
        arguments: &T,
    ) -> Result<(), McpError> {
        request_with(
            &self.store,
            &self.audit,
            &self.connector_id,
            principal,
            self.timeout,
            APPROVAL_RECOVERY_POLL_INTERVAL,
            tool_name,
            capability,
            summary,
            argument_hash,
            arguments,
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn request_with<R, A, T>(
    repository: &R,
    audit: &A,
    connector_id: &str,
    principal: &ApprovalPrincipal,
    timeout: Duration,
    recovery_poll_interval: Duration,
    tool_name: &str,
    capability: Capability,
    summary: &str,
    argument_hash: &str,
    arguments: &T,
) -> Result<(), McpError>
where
    R: ApprovalRepository,
    A: ApprovalAudit,
    T: Serialize,
{
    let chrono_timeout = chrono::Duration::from_std(timeout)
        .map_err(|_| McpError::internal_error("Invalid local approval timeout", None))?;
    let approval = ApprovalRequest::new(
        connector_id,
        principal.clone(),
        tool_name,
        approval_preview(tool_name, arguments),
        argument_hash,
        Utc::now() + chrono_timeout,
    );
    repository
        .insert(approval.clone())
        .await
        .map_err(|_| McpError::internal_error("Could not create a local approval request", None))?;

    if let Err(error) = audit
        .record_required(
            tool_name,
            capability,
            AuditOutcome::PendingApproval,
            argument_hash,
            summary,
        )
        .await
    {
        let _ignored = repository.deny(approval.id).await;
        return Err(error);
    }

    wait_for_approval(
        repository,
        audit,
        &approval,
        timeout,
        recovery_poll_interval,
        ApprovalAuditContext {
            connector_id,
            tool_name,
            capability,
            argument_hash,
            summary,
        },
    )
    .await
}

#[derive(Clone, Copy)]
struct ApprovalAuditContext<'a> {
    connector_id: &'a str,
    tool_name: &'a str,
    capability: Capability,
    argument_hash: &'a str,
    summary: &'a str,
}

async fn wait_for_approval<R, A>(
    repository: &R,
    audit: &A,
    approval: &ApprovalRequest,
    timeout: Duration,
    recovery_poll_interval: Duration,
    context: ApprovalAuditContext<'_>,
) -> Result<(), McpError>
where
    R: ApprovalRepository,
    A: ApprovalAudit,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut notifications = repository.subscribe();
    let mut notification_channel_active = true;
    loop {
        let status = repository
            .status(approval.id)
            .await
            .map_err(|_| McpError::internal_error("Could not read local approval", None))?
            .map_or(ApprovalStatus::Expired, |request| request.status);
        if complete_existing_status(audit, status, context).await? {
            return Ok(());
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return complete_timeout(repository, audit, approval.id, context).await;
        }
        let wait = recovery_poll_interval.min(deadline.saturating_duration_since(now));
        if notification_channel_active {
            tokio::select! {
                result = notifications.changed() => {
                    if result.is_err() {
                        notification_channel_active = false;
                    }
                }
                () = tokio::time::sleep(wait) => {}
            }
        } else {
            tokio::time::sleep(wait).await;
        }
    }
}

async fn complete_timeout<R, A>(
    repository: &R,
    audit: &A,
    approval_id: Uuid,
    context: ApprovalAuditContext<'_>,
) -> Result<(), McpError>
where
    R: ApprovalRepository,
    A: ApprovalAudit,
{
    let event = AuditEvent::new(
        context.connector_id,
        context.tool_name,
        capability_name(context.capability),
        AuditOutcome::TimedOut,
        context.argument_hash,
        "local approval timed out",
    );
    let completion = repository
        .complete_timeout(approval_id, event)
        .await
        .map_err(|_| {
            McpError::internal_error(
                "Could not atomically expire and audit the local approval",
                None,
            )
        })?
        .ok_or_else(|| {
            McpError::internal_error("Local approval disappeared before timeout", None)
        })?;
    match completion {
        ApprovalTimeoutResult::ExpiredNow
        | ApprovalTimeoutResult::Existing(ApprovalStatus::Expired) => {
            Err(McpError::invalid_request("Local approval timed out", None))
        }
        ApprovalTimeoutResult::Existing(status) => {
            if complete_existing_status(audit, status, context).await? {
                return Ok(());
            }
            Err(McpError::internal_error(
                "Timed-out local approval remained pending",
                None,
            ))
        }
    }
}

async fn complete_existing_status<A: ApprovalAudit>(
    audit: &A,
    status: ApprovalStatus,
    context: ApprovalAuditContext<'_>,
) -> Result<bool, McpError> {
    match status {
        ApprovalStatus::Approved => {
            audit
                .record_required(
                    context.tool_name,
                    context.capability,
                    AuditOutcome::Allowed,
                    context.argument_hash,
                    context.summary,
                )
                .await?;
            Ok(true)
        }
        ApprovalStatus::Denied => {
            audit
                .record_required(
                    context.tool_name,
                    context.capability,
                    AuditOutcome::Denied,
                    context.argument_hash,
                    "denied by the machine owner",
                )
                .await?;
            Err(McpError::invalid_request(
                "Denied by the machine owner",
                None,
            ))
        }
        ApprovalStatus::Expired => Err(McpError::invalid_request("Local approval timed out", None)),
        ApprovalStatus::Pending => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::anyhow;
    use serde_json::json;

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct TestRepository {
        request: Arc<Mutex<Option<ApprovalRequest>>>,
        timeout_audits: Arc<Mutex<Vec<AuditEvent>>>,
        notifications: runonmine_core::ApprovalNotifications,
    }

    impl TestRepository {
        fn request(&self) -> AnyResult<Option<ApprovalRequest>> {
            self.request
                .lock()
                .map(|request| request.clone())
                .map_err(|_| anyhow!("test approval mutex was poisoned"))
        }

        fn timeout_audits(&self) -> AnyResult<Vec<AuditEvent>> {
            self.timeout_audits
                .lock()
                .map(|events| events.clone())
                .map_err(|_| anyhow!("test timeout audit mutex was poisoned"))
        }

        fn set_status(&self, status: ApprovalStatus) -> AnyResult<()> {
            self.set_status_inner(status, true)
        }

        fn set_status_without_notification(&self, status: ApprovalStatus) -> AnyResult<()> {
            self.set_status_inner(status, false)
        }

        fn set_status_inner(&self, status: ApprovalStatus, notify: bool) -> AnyResult<()> {
            let mut request = self
                .request
                .lock()
                .map_err(|_| anyhow!("test approval mutex was poisoned"))?;
            if let Some(request) = request.as_mut() {
                request.status = status;
            }
            drop(request);
            if notify {
                self.notifications.notify();
            }
            Ok(())
        }
    }

    #[async_trait]
    impl ApprovalRepository for TestRepository {
        fn subscribe(&self) -> ApprovalNotificationSubscription {
            self.notifications.subscribe()
        }

        async fn insert(&self, request: ApprovalRequest) -> AnyResult<()> {
            let mut slot = self
                .request
                .lock()
                .map_err(|_| anyhow!("test approval mutex was poisoned"))?;
            *slot = Some(request);
            drop(slot);
            self.notifications.notify();
            Ok(())
        }

        async fn deny(&self, _id: Uuid) -> AnyResult<()> {
            self.set_status(ApprovalStatus::Denied)
        }

        async fn complete_timeout(
            &self,
            _id: Uuid,
            event: AuditEvent,
        ) -> AnyResult<Option<ApprovalTimeoutResult>> {
            let mut request_slot = self
                .request
                .lock()
                .map_err(|_| anyhow!("test approval mutex was poisoned"))?;
            let Some(request) = request_slot.as_mut() else {
                return Ok(None);
            };
            if request.status != ApprovalStatus::Pending {
                return Ok(Some(ApprovalTimeoutResult::Existing(request.status)));
            }
            if event.connector_id != request.connector_id
                || event.tool_name != request.tool_name
                || event.argument_hash != request.argument_hash
                || event.outcome != AuditOutcome::TimedOut
            {
                return Err(anyhow!("test timeout audit identity mismatch"));
            }
            let mut timeout_audits = self
                .timeout_audits
                .lock()
                .map_err(|_| anyhow!("test timeout audit mutex was poisoned"))?;
            request.status = ApprovalStatus::Expired;
            request.resolved_at = Some(event.timestamp);
            request.decision = None;
            timeout_audits.push(event);
            drop(timeout_audits);
            drop(request_slot);
            self.notifications.notify();
            Ok(Some(ApprovalTimeoutResult::ExpiredNow))
        }

        async fn status(&self, _id: Uuid) -> AnyResult<Option<ApprovalRequest>> {
            self.request()
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct RecordedAudit {
        tool_name: String,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: String,
        summary: String,
    }

    #[derive(Clone, Debug, Default)]
    struct TestAudit {
        fail: bool,
        records: Arc<Mutex<Vec<RecordedAudit>>>,
    }

    impl TestAudit {
        fn failing() -> Self {
            Self {
                fail: true,
                records: Arc::default(),
            }
        }

        fn records(&self) -> AnyResult<Vec<RecordedAudit>> {
            self.records
                .lock()
                .map(|records| records.clone())
                .map_err(|_| anyhow!("test audit mutex was poisoned"))
        }
    }

    #[async_trait]
    impl ApprovalAudit for TestAudit {
        async fn record_required(
            &self,
            tool_name: &str,
            capability: Capability,
            outcome: AuditOutcome,
            argument_hash: &str,
            summary: &str,
        ) -> Result<(), McpError> {
            let mut records = self
                .records
                .lock()
                .map_err(|_| McpError::internal_error("Test audit mutex was poisoned", None))?;
            records.push(RecordedAudit {
                tool_name: tool_name.to_owned(),
                capability,
                outcome,
                argument_hash: argument_hash.to_owned(),
                summary: summary.to_owned(),
            });
            if self.fail {
                return Err(McpError::internal_error("audit unavailable", None));
            }
            Ok(())
        }
    }

    async fn wait_for_request(repository: &TestRepository) -> AnyResult<ApprovalRequest> {
        for _ in 0..1_000 {
            if let Some(request) = repository.request()? {
                return Ok(request);
            }
            tokio::task::yield_now().await;
        }
        Err(anyhow!("approval request was not created"))
    }

    #[tokio::test]
    async fn approved_request_preserves_identity_and_audit_transitions() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let arguments = json!({"path": "/allowed/file.txt", "token": "abc123"});
        let resolver = async {
            let request = wait_for_request(&repository).await?;
            repository.set_status(ApprovalStatus::Approved)?;
            Ok::<_, anyhow::Error>(request)
        };
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(200),
            Duration::from_millis(1),
            "fs_write",
            Capability::FilesWrite,
            "write requested",
            "argument-hash",
            &arguments,
        );

        let (result, request) = tokio::join!(approval, resolver);
        let request = request?;
        assert!(result.is_ok());
        assert_eq!(request.connector_id, "connector-a");
        assert_eq!(request.principal, ApprovalPrincipal::LocalStdio);
        assert_eq!(
            request.principal_fingerprint,
            ApprovalPrincipal::LocalStdio.fingerprint()
        );
        assert_eq!(request.tool_name, "fs_write");
        assert_eq!(request.argument_hash, "argument-hash");
        assert!(request.argument_summary.contains("/allowed/file.txt"));
        assert!(!request.argument_summary.contains("abc123"));
        let records = audit.records()?;
        assert_eq!(
            records
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![AuditOutcome::PendingApproval, AuditOutcome::Allowed]
        );
        assert!(records.iter().all(|record| record.tool_name == "fs_write"));
        assert!(
            records
                .iter()
                .all(|record| record.capability == Capability::FilesWrite)
        );
        assert!(
            records
                .iter()
                .all(|record| record.argument_hash == "argument-hash")
        );
        assert!(
            records
                .iter()
                .all(|record| record.summary == "write requested")
        );
        Ok(())
    }

    #[tokio::test]
    async fn notification_wakes_before_the_recovery_poll() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let resolver = async {
            wait_for_request(&repository).await?;
            repository.set_status(ApprovalStatus::Approved)?;
            Ok::<_, anyhow::Error>(())
        };
        let arguments = json!({"path": "/allowed/file.txt"});
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(250),
            Duration::from_secs(30),
            "fs_write",
            Capability::FilesWrite,
            "write requested",
            "notification-hash",
            &arguments,
        );
        let combined = async {
            let (result, resolver_result) = tokio::join!(approval, resolver);
            resolver_result?;
            result.map_err(|error| anyhow!(error.to_string()))
        };
        tokio::time::timeout(Duration::from_millis(100), combined)
            .await
            .map_err(|_| anyhow!("approval did not wake from its notification"))??;
        Ok(())
    }

    #[tokio::test]
    async fn recovery_poll_observes_a_missed_notification() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let resolver = async {
            wait_for_request(&repository).await?;
            repository.set_status_without_notification(ApprovalStatus::Approved)?;
            Ok::<_, anyhow::Error>(())
        };
        let arguments = json!({"path": "/allowed/file.txt"});
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(250),
            Duration::from_millis(10),
            "fs_write",
            Capability::FilesWrite,
            "write requested",
            "recovery-hash",
            &arguments,
        );
        let (result, resolver_result) = tokio::join!(approval, resolver);
        resolver_result?;
        assert!(result.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn owner_denial_records_the_denied_transition() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let resolver = async {
            wait_for_request(&repository).await?;
            repository.set_status(ApprovalStatus::Denied)?;
            Ok::<_, anyhow::Error>(())
        };
        let arguments = json!({"command": "printf ok"});
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(200),
            Duration::from_millis(1),
            "shell_exec",
            Capability::ShellExec,
            "command requested",
            "argument-hash",
            &arguments,
        );

        let (result, resolver_result) = tokio::join!(approval, resolver);
        resolver_result?;
        assert!(result.is_err());
        let records = audit.records()?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].outcome, AuditOutcome::Denied);
        assert_eq!(records[1].summary, "denied by the machine owner");
        Ok(())
    }

    #[tokio::test]
    async fn already_expired_request_does_not_duplicate_terminal_audit() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let resolver = async {
            let request = wait_for_request(&repository).await?;
            let event = AuditEvent::new(
                &request.connector_id,
                &request.tool_name,
                capability_name(Capability::FilesWrite),
                AuditOutcome::TimedOut,
                &request.argument_hash,
                "local approval timed out",
            );
            assert_eq!(
                repository.complete_timeout(request.id, event).await?,
                Some(ApprovalTimeoutResult::ExpiredNow)
            );
            Ok::<_, anyhow::Error>(())
        };
        let arguments = json!({"path": "/allowed/file.txt"});
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_secs(5),
            Duration::from_millis(1),
            "fs_write",
            Capability::FilesWrite,
            "write requested",
            "argument-hash",
            &arguments,
        );

        let (result, resolver_result) = tokio::join!(approval, resolver);
        resolver_result?;
        assert!(result.is_err());
        let records = audit.records()?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, AuditOutcome::PendingApproval);
        let timeout_audits = repository.timeout_audits()?;
        assert_eq!(timeout_audits.len(), 1);
        assert_eq!(timeout_audits[0].outcome, AuditOutcome::TimedOut);
        Ok(())
    }

    #[tokio::test]
    async fn timeout_records_timed_out_without_widening_the_grant() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let result = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(5),
            Duration::from_millis(1),
            "fs_write",
            Capability::FilesWrite,
            "write requested",
            "argument-hash",
            &json!({"path": "/allowed/file.txt"}),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            repository.request()?.map(|request| request.status),
            Some(ApprovalStatus::Expired)
        );
        let records = audit.records()?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, AuditOutcome::PendingApproval);
        let timeout_audits = repository.timeout_audits()?;
        assert_eq!(timeout_audits.len(), 1);
        assert_eq!(timeout_audits[0].outcome, AuditOutcome::TimedOut);
        assert_eq!(timeout_audits[0].summary, "local approval timed out");
        let request = repository
            .request()?
            .ok_or_else(|| anyhow!("timed-out approval disappeared"))?;
        assert!(request.resolved_at.is_some());
        assert_eq!(request.decision, None);
        Ok(())
    }

    #[tokio::test]
    async fn owner_decision_that_commits_before_timeout_wins_the_race() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let resolver = async {
            wait_for_request(&repository).await?;
            repository.set_status(ApprovalStatus::Approved)?;
            tokio::time::sleep(Duration::from_millis(10)).await;
            Ok::<_, anyhow::Error>(())
        };
        let arguments = json!({"path": "/allowed/file.txt"});
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(5),
            Duration::from_millis(10),
            "fs_write",
            Capability::FilesWrite,
            "write requested",
            "argument-hash",
            &arguments,
        );

        let (result, resolver_result) = tokio::join!(approval, resolver);
        resolver_result?;
        assert!(result.is_ok());
        assert_eq!(
            repository.request()?.map(|request| request.status),
            Some(ApprovalStatus::Approved)
        );
        let records = audit.records()?;
        assert_eq!(
            records
                .iter()
                .map(|record| record.outcome)
                .collect::<Vec<_>>(),
            vec![AuditOutcome::PendingApproval, AuditOutcome::Allowed]
        );
        assert!(repository.timeout_audits()?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn pending_audit_failure_denies_the_created_request() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::failing();
        let result = request_with(
            &repository,
            &audit,
            "connector-a",
            &ApprovalPrincipal::LocalStdio,
            Duration::from_millis(200),
            Duration::from_millis(1),
            "shell_exec",
            Capability::ShellExec,
            "command requested",
            "argument-hash",
            &json!({"command": "printf ok"}),
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            repository.request()?.map(|request| request.status),
            Some(ApprovalStatus::Denied)
        );
        let records = audit.records()?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, AuditOutcome::PendingApproval);
        Ok(())
    }
}
