use std::time::{Duration, Instant};

use anyhow::Result as AnyResult;
use async_trait::async_trait;
use chrono::Utc;
use rmcp::ErrorData as McpError;
use runonmine_core::{
    ApprovalDecision, ApprovalRequest, ApprovalStatus, AuditOutcome, Capability, StateStore,
};
use serde::Serialize;
use uuid::Uuid;

use crate::audit::AuditRecorder;
use crate::validation::approval_preview;

const APPROVAL_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[async_trait]
trait ApprovalRepository: Send + Sync {
    async fn insert(&self, request: ApprovalRequest) -> AnyResult<()>;
    async fn deny(&self, id: Uuid) -> AnyResult<()>;
    async fn status(&self, id: Uuid) -> AnyResult<Option<ApprovalRequest>>;
}

#[async_trait]
impl ApprovalRepository for StateStore {
    async fn insert(&self, request: ApprovalRequest) -> AnyResult<()> {
        self.insert_approval_async(request).await
    }

    async fn deny(&self, id: Uuid) -> AnyResult<()> {
        self.resolve_approval_async(id, ApprovalDecision::Deny)
            .await
            .map(|_| ())
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
            self.timeout,
            APPROVAL_POLL_INTERVAL,
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
    timeout: Duration,
    poll_interval: Duration,
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

    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            audit
                .record_required(
                    tool_name,
                    capability,
                    AuditOutcome::Denied,
                    argument_hash,
                    "local approval timed out",
                )
                .await?;
            return Err(McpError::invalid_request("Local approval timed out", None));
        }

        tokio::time::sleep(poll_interval).await;
        let status = repository
            .status(approval.id)
            .await
            .map_err(|_| McpError::internal_error("Could not read local approval", None))?
            .map_or(ApprovalStatus::Expired, |request| request.status);
        match status {
            ApprovalStatus::Approved => {
                audit
                    .record_required(
                        tool_name,
                        capability,
                        AuditOutcome::Allowed,
                        argument_hash,
                        summary,
                    )
                    .await?;
                return Ok(());
            }
            ApprovalStatus::Denied => {
                audit
                    .record_required(
                        tool_name,
                        capability,
                        AuditOutcome::Denied,
                        argument_hash,
                        "denied by the machine owner",
                    )
                    .await?;
                return Err(McpError::invalid_request(
                    "Denied by the machine owner",
                    None,
                ));
            }
            ApprovalStatus::Expired => {
                audit
                    .record_required(
                        tool_name,
                        capability,
                        AuditOutcome::Denied,
                        argument_hash,
                        "local approval expired",
                    )
                    .await?;
                return Err(McpError::invalid_request("Local approval timed out", None));
            }
            ApprovalStatus::Pending => {}
        }
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
    }

    impl TestRepository {
        fn request(&self) -> AnyResult<Option<ApprovalRequest>> {
            self.request
                .lock()
                .map(|request| request.clone())
                .map_err(|_| anyhow!("test approval mutex was poisoned"))
        }

        fn set_status(&self, status: ApprovalStatus) -> AnyResult<()> {
            let mut request = self
                .request
                .lock()
                .map_err(|_| anyhow!("test approval mutex was poisoned"))?;
            if let Some(request) = request.as_mut() {
                request.status = status;
            }
            Ok(())
        }
    }

    #[async_trait]
    impl ApprovalRepository for TestRepository {
        async fn insert(&self, request: ApprovalRequest) -> AnyResult<()> {
            let mut slot = self
                .request
                .lock()
                .map_err(|_| anyhow!("test approval mutex was poisoned"))?;
            *slot = Some(request);
            Ok(())
        }

        async fn deny(&self, _id: Uuid) -> AnyResult<()> {
            self.set_status(ApprovalStatus::Denied)
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
    async fn expired_request_records_the_expired_transition() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let resolver = async {
            wait_for_request(&repository).await?;
            repository.set_status(ApprovalStatus::Expired)?;
            Ok::<_, anyhow::Error>(())
        };
        let arguments = json!({"path": "/allowed/file.txt"});
        let approval = request_with(
            &repository,
            &audit,
            "connector-a",
            Duration::from_millis(200),
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
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].outcome, AuditOutcome::Denied);
        assert_eq!(records[1].summary, "local approval expired");
        Ok(())
    }

    #[tokio::test]
    async fn timeout_records_denial_without_widening_the_grant() -> AnyResult<()> {
        let repository = TestRepository::default();
        let audit = TestAudit::default();
        let result = request_with(
            &repository,
            &audit,
            "connector-a",
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
            Some(ApprovalStatus::Pending)
        );
        let records = audit.records()?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].outcome, AuditOutcome::Denied);
        assert_eq!(records[1].summary, "local approval timed out");
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
