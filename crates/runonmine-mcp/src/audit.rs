use anyhow::Result as AnyResult;
use async_trait::async_trait;
use rmcp::ErrorData as McpError;
use runonmine_core::{AuditEvent, AuditOutcome, Capability, StateStore};
use serde::Serialize;

use crate::validation::{argument_hash, capability_name, capability_requires_reliable_audit};

#[async_trait]
trait AuditSink: Send + Sync {
    async fn append(&self, event: AuditEvent) -> AnyResult<()>;
}

#[async_trait]
impl AuditSink for StateStore {
    async fn append(&self, event: AuditEvent) -> AnyResult<()> {
        self.append_audit_async(event).await.map(|_| ())
    }
}

#[derive(Clone, Debug)]
pub(super) struct AuditRecorder {
    connector_id: String,
    store: StateStore,
}

impl AuditRecorder {
    pub(super) fn new(connector_id: impl Into<String>, store: StateStore) -> Self {
        Self {
            connector_id: connector_id.into(),
            store,
        }
    }

    pub(super) async fn record_required(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) -> Result<(), McpError> {
        append_required(
            &self.store,
            self.event(tool_name, capability, outcome, argument_hash, summary),
            capability,
        )
        .await
    }

    pub(super) fn record<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        arguments: &T,
        summary: &str,
    ) {
        match argument_hash(arguments) {
            Ok(hash) => self.record_with_hash(tool_name, capability, outcome, &hash, summary),
            Err(error) => tracing::error!(
                %error,
                tool_name,
                "failed to serialize tool arguments for audit"
            ),
        }
    }

    fn record_with_hash(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) {
        let event = self.event(tool_name, capability, outcome, argument_hash, summary);
        let store = self.store.clone();
        tokio::spawn(async move {
            if let Err(error) = store.append_audit_async(event).await {
                tracing::error!(%error, "failed to append audit event");
            }
        });
    }

    fn event(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) -> AuditEvent {
        AuditEvent::new(
            &self.connector_id,
            tool_name,
            capability_name(capability),
            outcome,
            argument_hash,
            summary,
        )
    }
}

async fn append_required(
    sink: &dyn AuditSink,
    event: AuditEvent,
    capability: Capability,
) -> Result<(), McpError> {
    match sink.append(event).await {
        Ok(()) => Ok(()),
        Err(error) if capability_requires_reliable_audit(capability) => {
            tracing::error!(%error, "refusing dangerous tool call because audit is unavailable");
            Err(McpError::internal_error(
                "Local audit storage is unavailable; the tool call was blocked",
                None,
            ))
        }
        Err(error) => {
            tracing::error!(%error, "failed to append audit event");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use anyhow::{Result, anyhow};

    use super::*;

    #[derive(Clone, Debug, Default)]
    struct TestSink {
        fail: Arc<AtomicBool>,
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl TestSink {
        fn failing() -> Self {
            Self {
                fail: Arc::new(AtomicBool::new(true)),
                events: Arc::default(),
            }
        }
    }

    #[async_trait]
    impl AuditSink for TestSink {
        async fn append(&self, event: AuditEvent) -> AnyResult<()> {
            self.events
                .lock()
                .map_err(|_| anyhow!("test audit mutex was poisoned"))?
                .push(event);
            if self.fail.load(Ordering::SeqCst) {
                return Err(anyhow!("audit unavailable"));
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn dangerous_capabilities_fail_closed_when_audit_is_unavailable() {
        for capability in [
            Capability::FilesWrite,
            Capability::ShellExec,
            Capability::BrowserAct,
            Capability::DesktopControl,
            Capability::PlatformNative,
            Capability::AdminExec,
        ] {
            let result = append_required(
                &TestSink::failing(),
                AuditEvent::new(
                    "connector",
                    "dangerous_tool",
                    capability_name(capability),
                    AuditOutcome::Allowed,
                    "hash",
                    "summary",
                ),
                capability,
            )
            .await;

            assert!(result.is_err(), "{capability:?} must fail closed");
        }
    }

    #[tokio::test]
    async fn read_only_capabilities_continue_when_audit_is_unavailable() {
        for capability in [
            Capability::SystemRead,
            Capability::FilesRead,
            Capability::BrowserRead,
        ] {
            let result = append_required(
                &TestSink::failing(),
                AuditEvent::new(
                    "connector",
                    "read_only_tool",
                    capability_name(capability),
                    AuditOutcome::Allowed,
                    "hash",
                    "summary",
                ),
                capability,
            )
            .await;

            assert!(result.is_ok(), "{capability:?} should remain best effort");
        }
    }

    #[tokio::test]
    async fn recorder_persists_complete_audit_identity() -> Result<()> {
        let store = StateStore::in_memory()?;
        let recorder = AuditRecorder::new("connector-a", store.clone());
        recorder
            .record_required(
                "fs_write",
                Capability::FilesWrite,
                AuditOutcome::PendingApproval,
                "argument-hash",
                "write requested",
            )
            .await
            .map_err(|error| anyhow!(error.to_string()))?;

        let records = store.audit_tail(1)?;
        assert_eq!(records.len(), 1);
        let event = &records[0].event;
        assert_eq!(event.connector_id, "connector-a");
        assert_eq!(event.tool_name, "fs_write");
        assert_eq!(event.capability, "files_write");
        assert_eq!(event.outcome, AuditOutcome::PendingApproval);
        assert_eq!(event.argument_hash, "argument-hash");
        assert_eq!(event.summary, "write requested");
        Ok(())
    }
}
