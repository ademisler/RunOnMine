//! Bounded, non-secret correlation for internal MCP failures.

use std::future::Future;

use rmcp::ErrorData as McpError;
use serde_json::json;
use uuid::Uuid;

const PUBLIC_INTERNAL_ERROR: &str = "Tool failed; inspect the local RunOnMine logs";

tokio::task_local! {
    static REQUEST_REFERENCE: Uuid;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DiagnosticCategory {
    Approval,
    AuditStorage,
    Authorization,
    Browser,
    ConnectorConfig,
    Desktop,
    Filesystem,
    OutputEncoding,
    PlatformNative,
    PrivilegedHelper,
    Process,
    RuntimeTask,
    Storage,
}

impl DiagnosticCategory {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::AuditStorage => "audit_storage",
            Self::Authorization => "authorization",
            Self::Browser => "browser",
            Self::ConnectorConfig => "connector_config",
            Self::Desktop => "desktop",
            Self::Filesystem => "filesystem",
            Self::OutputEncoding => "output_encoding",
            Self::PlatformNative => "platform_native",
            Self::PrivilegedHelper => "privileged_helper",
            Self::Process => "process",
            Self::RuntimeTask => "runtime_task",
            Self::Storage => "storage",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DiagnosticReference {
    pub(super) incident_id: Uuid,
    pub(super) request_id: Uuid,
}

pub(super) async fn scope_request<T>(future: impl Future<Output = T>) -> T {
    if REQUEST_REFERENCE.try_with(|_| ()).is_ok() {
        future.await
    } else {
        REQUEST_REFERENCE.scope(Uuid::new_v4(), future).await
    }
}

pub(super) fn current_request_id() -> Uuid {
    REQUEST_REFERENCE
        .try_with(|request_id| *request_id)
        .unwrap_or_else(|_| Uuid::new_v4())
}

pub(super) fn internal_error(
    connector_id: &str,
    category: DiagnosticCategory,
    operation: &'static str,
    tool_name: Option<&str>,
    audit_id: Option<Uuid>,
    public_message: &'static str,
) -> McpError {
    let reference = log_internal(
        current_request_id(),
        connector_id,
        category,
        operation,
        tool_name,
        audit_id,
    );
    McpError::internal_error(
        public_message,
        Some(json!({"reference": reference.incident_id.to_string()})),
    )
}

pub(super) fn tool_error(
    connector_id: &str,
    category: DiagnosticCategory,
    operation: &'static str,
    tool_name: &str,
    audit_id: Option<Uuid>,
) -> McpError {
    internal_error(
        connector_id,
        category,
        operation,
        Some(tool_name),
        audit_id,
        PUBLIC_INTERNAL_ERROR,
    )
}

pub(super) fn log_internal(
    request_id: Uuid,
    connector_id: &str,
    category: DiagnosticCategory,
    operation: &'static str,
    tool_name: Option<&str>,
    audit_id: Option<Uuid>,
) -> DiagnosticReference {
    let reference = DiagnosticReference {
        incident_id: Uuid::new_v4(),
        request_id,
    };
    let tool_name = tool_name.unwrap_or("none");
    let audit_id = audit_id.map_or_else(|| "none".to_owned(), |value| value.to_string());
    tracing::error!(
        incident_id = %reference.incident_id,
        request_id = %reference.request_id,
        connector_id,
        audit_id,
        category = category.as_str(),
        operation,
        tool_name,
        "RunOnMine internal operation failed"
    );
    reference
}

#[cfg(test)]
mod tests {
    use anyhow::{Context as _, Result};

    use super::*;

    #[tokio::test]
    async fn request_scope_is_stable_and_incident_reference_is_publicly_bounded() -> Result<()> {
        let request_id = Uuid::new_v4();
        let result = REQUEST_REFERENCE
            .scope(request_id, async {
                internal_error(
                    "connector-a",
                    DiagnosticCategory::Filesystem,
                    "read_file",
                    Some("fs_read"),
                    Some(Uuid::new_v4()),
                    PUBLIC_INTERNAL_ERROR,
                )
            })
            .await;
        assert_ne!(current_request_id(), request_id);
        assert_eq!(result.message, PUBLIC_INTERNAL_ERROR);
        let data = result
            .data
            .context("diagnostic reference data is missing")?;
        let reference = data
            .get("reference")
            .and_then(serde_json::Value::as_str)
            .context("diagnostic reference is missing")?;
        assert!(Uuid::parse_str(reference).is_ok());
        assert_eq!(data.as_object().map(serde_json::Map::len), Some(1));
        Ok(())
    }

    #[test]
    fn categories_are_static_and_bounded() {
        for category in [
            DiagnosticCategory::Approval,
            DiagnosticCategory::AuditStorage,
            DiagnosticCategory::Authorization,
            DiagnosticCategory::Browser,
            DiagnosticCategory::ConnectorConfig,
            DiagnosticCategory::Desktop,
            DiagnosticCategory::Filesystem,
            DiagnosticCategory::OutputEncoding,
            DiagnosticCategory::PlatformNative,
            DiagnosticCategory::PrivilegedHelper,
            DiagnosticCategory::Process,
            DiagnosticCategory::RuntimeTask,
            DiagnosticCategory::Storage,
        ] {
            let value = category.as_str();
            assert!(value.len() <= 32);
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }
}
