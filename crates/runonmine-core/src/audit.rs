use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Allowed,
    Denied,
    PendingApproval,
    Succeeded,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub connector_id: String,
    pub tool_name: String,
    pub capability: String,
    pub outcome: AuditOutcome,
    pub argument_hash: String,
    pub summary: String,
    pub duration_ms: Option<u64>,
    pub output_bytes: Option<u64>,
}

impl AuditEvent {
    pub fn new(
        connector_id: impl Into<String>,
        tool_name: impl Into<String>,
        capability: impl Into<String>,
        outcome: AuditOutcome,
        argument_hash: impl Into<String>,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            connector_id: connector_id.into(),
            tool_name: tool_name.into(),
            capability: capability.into(),
            outcome,
            argument_hash: argument_hash.into(),
            summary: summary.into(),
            duration_ms: None,
            output_bytes: None,
        }
    }
}
