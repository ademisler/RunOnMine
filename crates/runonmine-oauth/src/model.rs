use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::{ScopeSet, SecretHash};

#[derive(Clone, Debug, Deserialize)]
pub struct DynamicClientRequest {
    pub redirect_uris: Vec<Url>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DynamicClientResponse {
    pub client_id: String,
    pub client_id_issued_at: i64,
    pub redirect_uris: Vec<Url>,
    pub client_name: String,
    pub token_endpoint_auth_method: &'static str,
    pub grant_types: Vec<&'static str>,
    pub response_types: Vec<&'static str>,
    pub scope: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    pub redirect_uri: Url,
    pub scope: String,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    #[serde(default)]
    pub resource: Option<Url>,
}

#[derive(Clone)]
pub struct GitHubAuthorization {
    pub redirect: Url,
    pub provider_state: SecretString,
}

impl std::fmt::Debug for GitHubAuthorization {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubAuthorization")
            .field("redirect", &self.redirect)
            .field("provider_state", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct GitHubCallback {
    pub code: String,
    pub state: String,
}

#[derive(Clone)]
pub struct ConsentChallenge {
    pub id: Uuid,
    pub csrf: SecretString,
    /// A display name supplied by the dynamic client and not verified by `RunOnMine`.
    pub claimed_client_name: String,
    pub client_id_fingerprint: String,
    pub registered_at: DateTime<Utc>,
    pub requested_redirect_origin: String,
    pub registered_redirect_origins: Vec<String>,
    pub scopes: ScopeSet,
}

impl std::fmt::Debug for ConsentChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConsentChallenge")
            .field("id", &self.id)
            .field("csrf", &"[REDACTED]")
            .field("claimed_client_name", &self.claimed_client_name)
            .field("client_id_fingerprint", &self.client_id_fingerprint)
            .field("registered_at", &self.registered_at)
            .field("requested_redirect_origin", &self.requested_redirect_origin)
            .field(
                "registered_redirect_origins",
                &self.registered_redirect_origins,
            )
            .field("scopes", &self.scopes)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsentDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug)]
pub struct ConsentResult {
    pub redirect: Url,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConsentSubmission {
    pub consent_id: Uuid,
    pub csrf: String,
    pub decision: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub client_id: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<Url>,
    #[serde(default)]
    pub code_verifier: Option<String>,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

pub struct IssuedToken {
    pub access_token: SecretString,
    pub refresh_token: SecretString,
    pub token_type: &'static str,
    pub expires_in: u64,
    pub scope: ScopeSet,
}

impl std::fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct RevocationRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct AccessGrant {
    pub client_id: String,
    pub subject: String,
    pub scopes: ScopeSet,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegisteredClient {
    pub connector_id: String,
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<Url>,
    pub scopes: ScopeSet,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub registration_source_hash: String,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct RegistrationLimits {
    pub now: DateTime<Utc>,
    pub window_seconds: i64,
    pub per_source_limit: usize,
    pub global_limit: usize,
    pub max_clients: usize,
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationOutcome {
    Registered,
    RateLimited,
    CapacityReached,
}

#[derive(Clone, Debug, Serialize)]
pub struct OAuthSession {
    pub connector_id: String,
    pub family_id: Uuid,
    pub client_id: String,
    pub subject: String,
    pub scopes: ScopeSet,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub active: bool,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct PendingAuthorization {
    pub provider_state_hash: SecretHash,
    pub client_id: String,
    pub redirect_uri: Url,
    pub client_state: String,
    pub scopes: ScopeSet,
    pub code_challenge: String,
    pub expires_at: DateTime<Utc>,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct PendingConsent {
    pub id: Uuid,
    pub csrf_hash: SecretHash,
    pub client_id: String,
    pub redirect_uri: Url,
    pub client_state: String,
    pub scopes: ScopeSet,
    pub code_challenge: String,
    pub subject: String,
    pub expires_at: DateTime<Utc>,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct AuthorizationCodeGrant {
    pub code_hash: SecretHash,
    pub client_id: String,
    pub redirect_uri: Url,
    pub scopes: ScopeSet,
    pub code_challenge: String,
    pub subject: String,
    pub expires_at: DateTime<Utc>,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct TokenPairDraft {
    pub access_hash: SecretHash,
    pub refresh_hash: SecretHash,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_expires_at: DateTime<Utc>,
}

#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct TokenGrant {
    pub scopes: ScopeSet,
}
