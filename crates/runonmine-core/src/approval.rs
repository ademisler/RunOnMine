use anyhow::{Result, bail};
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalPrincipal {
    LocalStdio,
    LocalHttp,
    QuickTunnel,
    OAuth {
        client_id: String,
        subject: String,
    },
    /// Migration-only identity for historical approvals created before
    /// principal-bound authorization. It is never used for new requests.
    Legacy,
}

impl ApprovalPrincipal {
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        match self {
            Self::LocalStdio => "local_stdio",
            Self::LocalHttp => "local_http",
            Self::QuickTunnel => "quick_tunnel",
            Self::OAuth { .. } => "oauth",
            Self::Legacy => "legacy",
        }
    }

    #[must_use]
    pub fn oauth_client_id(&self) -> Option<&str> {
        match self {
            Self::OAuth { client_id, .. } => Some(client_id),
            _ => None,
        }
    }

    #[must_use]
    pub fn oauth_subject(&self) -> Option<&str> {
        match self {
            Self::OAuth { subject, .. } => Some(subject),
            _ => None,
        }
    }

    #[must_use]
    pub fn fingerprint(&self) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"runonmine.approval-principal.v1\0");
        update_fingerprint_part(&mut hasher, self.storage_kind().as_bytes());
        update_fingerprint_part(
            &mut hasher,
            self.oauth_client_id().unwrap_or_default().as_bytes(),
        );
        update_fingerprint_part(
            &mut hasher,
            self.oauth_subject().unwrap_or_default().as_bytes(),
        );
        hasher.finalize().to_hex().to_string()
    }

    #[must_use]
    pub fn display_label(&self) -> String {
        match self {
            Self::LocalStdio => "Local stdio client".to_owned(),
            Self::LocalHttp => "Local HTTP client".to_owned(),
            Self::QuickTunnel => "Cloudflare Quick Tunnel client".to_owned(),
            Self::OAuth { client_id, subject } => {
                format!("OAuth client {client_id} · subject {subject}")
            }
            Self::Legacy => "Legacy pre-principal approval".to_owned(),
        }
    }

    pub fn from_storage(
        kind: &str,
        client_id: Option<String>,
        subject: Option<String>,
    ) -> Result<Self> {
        match kind {
            "local_stdio" if client_id.is_none() && subject.is_none() => Ok(Self::LocalStdio),
            "local_http" if client_id.is_none() && subject.is_none() => Ok(Self::LocalHttp),
            "quick_tunnel" if client_id.is_none() && subject.is_none() => Ok(Self::QuickTunnel),
            "oauth" => {
                let client_id = client_id.filter(|value| !value.is_empty());
                let subject = subject.filter(|value| !value.is_empty());
                match (client_id, subject) {
                    (Some(client_id), Some(subject)) => Ok(Self::OAuth { client_id, subject }),
                    _ => bail!("stored OAuth approval principal is incomplete"),
                }
            }
            "legacy" if client_id.is_none() && subject.is_none() => Ok(Self::Legacy),
            _ => bail!("stored approval principal is invalid"),
        }
    }
}

fn update_fingerprint_part(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistentGrant {
    pub connector_id: String,
    pub principal: ApprovalPrincipal,
    pub principal_fingerprint: String,
    pub tool_name: String,
    pub argument_summary: String,
    pub argument_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub connector_id: String,
    pub principal: ApprovalPrincipal,
    pub principal_fingerprint: String,
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
        principal: ApprovalPrincipal,
        tool_name: impl Into<String>,
        argument_summary: impl Into<String>,
        argument_hash: impl Into<String>,
        expires_at: DateTime<Utc>,
    ) -> Self {
        let principal_fingerprint = principal.fingerprint();
        Self {
            id: Uuid::new_v4(),
            connector_id: connector_id.into(),
            principal,
            principal_fingerprint,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_fingerprints_are_stable_and_isolate_oauth_callers() {
        let first = ApprovalPrincipal::OAuth {
            client_id: "client-a".to_owned(),
            subject: "github:42".to_owned(),
        };
        let same = ApprovalPrincipal::OAuth {
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

        assert_eq!(first.fingerprint(), same.fingerprint());
        assert_ne!(first.fingerprint(), other_client.fingerprint());
        assert_ne!(first.fingerprint(), other_subject.fingerprint());
        assert_ne!(
            ApprovalPrincipal::LocalStdio.fingerprint(),
            ApprovalPrincipal::LocalHttp.fingerprint()
        );
    }

    #[test]
    fn stored_principals_require_complete_oauth_identity() {
        assert!(
            ApprovalPrincipal::from_storage(
                "oauth",
                Some("client".to_owned()),
                Some("subject".to_owned())
            )
            .is_ok()
        );
        assert!(ApprovalPrincipal::from_storage("oauth", Some("client".to_owned()), None).is_err());
        assert!(ApprovalPrincipal::from_storage("unknown", None, None).is_err());
    }
}
