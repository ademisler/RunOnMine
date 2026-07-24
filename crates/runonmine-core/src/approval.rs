use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Once,
    ForTenMinutes,
    Always,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistentGrant {
    pub connector_id: String,
    pub tool_name: String,
    pub argument_summary: String,
    pub argument_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub connector_id: String,
    pub tool_name: String,
    pub argument_summary: String,
    pub argument_hash: String,
    pub status: ApprovalStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub decision: Option<ApprovalDecision>,
}

impl ApprovalRequest {
    pub fn new(
        connector_id: impl Into<String>,
        tool_name: impl Into<String>,
        argument_summary: impl Into<String>,
        argument_hash: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            connector_id: connector_id.into(),
            tool_name: tool_name.into(),
            argument_summary: argument_summary.into(),
            argument_hash: argument_hash.into(),
            status: ApprovalStatus::Pending,
            created_at: Utc::now(),
            expires_at,
            resolved_at: None,
            decision: None,
        }
    }
}
