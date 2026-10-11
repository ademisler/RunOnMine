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
pub struct AuthorizationClaim {
    pub claim_id: Uuid,
    pub provider_code_hash: SecretHash,
    pub pending: PendingAuthorization,
    pub claim_expires_at: DateTime<Utc>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret as _;

    #[test]
    fn secret_bearing_debug_outputs_redact_values() -> Result<(), Box<dyn std::error::Error>> {
        let authorization = GitHubAuthorization {
            redirect: Url::parse("https://github.com/login/oauth/authorize")?,
            provider_state: SecretString::from("provider-secret".to_owned()),
        };
        let debug = format!("{authorization:?}");
        assert!(debug.contains("github.com"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(authorization.provider_state.expose_secret()));

        let challenge = ConsentChallenge {
            id: Uuid::nil(),
            csrf: SecretString::from("csrf-secret".to_owned()),
            claimed_client_name: "Client".to_owned(),
            client_id_fingerprint: "sha256:fingerprint".to_owned(),
            registered_at: DateTime::from_timestamp(1_700_000_000, 0).ok_or("timestamp")?,
            requested_redirect_origin: "https://client.example".to_owned(),
            registered_redirect_origins: vec!["https://client.example".to_owned()],
            scopes: ScopeSet::machine_read(),
        };
        let debug = format!("{challenge:?}");
        assert!(debug.contains("Client"));
        assert!(debug.contains("sha256:fingerprint"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(challenge.csrf.expose_secret()));

        let issued = IssuedToken {
            access_token: SecretString::from("access-secret".to_owned()),
            refresh_token: SecretString::from("refresh-secret".to_owned()),
            token_type: "Bearer",
            expires_in: 900,
            scope: ScopeSet::machine_read(),
        };
        let debug = format!("{issued:?}");
        assert!(debug.contains("Bearer"));
        assert!(debug.contains("900"));
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(issued.access_token.expose_secret()));
        assert!(!debug.contains(issued.refresh_token.expose_secret()));
        Ok(())
    }

    #[test]
    fn public_oauth_models_round_trip_expected_wire_fields()
    -> Result<(), Box<dyn std::error::Error>> {
        let dynamic: DynamicClientRequest = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["https://client.example/callback"],
            "client_name": "Example",
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": "machine:read"
        }))?;
        assert_eq!(dynamic.redirect_uris.len(), 1);
        assert_eq!(dynamic.client_name.as_deref(), Some("Example"));
        assert_eq!(dynamic.token_endpoint_auth_method.as_deref(), Some("none"));
        assert_eq!(dynamic.grant_types.as_deref().map(<[_]>::len), Some(2));
        assert_eq!(dynamic.response_types.as_deref().map(<[_]>::len), Some(1));
        assert_eq!(dynamic.scope.as_deref(), Some("machine:read"));

        let authorization: AuthorizationRequest = serde_json::from_value(serde_json::json!({
            "response_type": "code",
            "client_id": "client-id",
            "redirect_uri": "https://client.example/callback",
            "scope": "machine:read",
            "state": "state",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "resource": "https://mine.example/mcp"
        }))?;
        assert_eq!(authorization.response_type, "code");
        assert_eq!(authorization.client_id, "client-id");
        assert_eq!(authorization.state, "state");
        assert_eq!(authorization.code_challenge_method, "S256");
        assert_eq!(
            authorization.redirect_uri.host_str(),
            Some("client.example")
        );
        assert_eq!(
            authorization
                .resource
                .and_then(|url| url.host_str().map(str::to_owned))
                .as_deref(),
            Some("mine.example")
        );

        let callback: GitHubCallback =
            serde_json::from_value(serde_json::json!({"code":"code","state":"state"}))?;
        assert_eq!(callback.code, "code");
        assert_eq!(callback.state, "state");
        let consent: ConsentSubmission = serde_json::from_value(serde_json::json!({
            "consent_id": Uuid::nil(), "csrf": "csrf", "decision": "allow"
        }))?;
        assert_eq!(consent.consent_id, Uuid::nil());
        assert_eq!(consent.csrf, "csrf");
        assert_eq!(consent.decision, "allow");

        let token: TokenRequest = serde_json::from_value(serde_json::json!({
            "grant_type": "authorization_code",
            "client_id": "client-id",
            "code": "code",
            "redirect_uri": "https://client.example/callback",
            "code_verifier": "verifier",
            "refresh_token": "refresh",
            "scope": "machine:read"
        }))?;
        assert_eq!(token.grant_type, "authorization_code");
        assert_eq!(token.code.as_deref(), Some("code"));
        assert_eq!(token.code_verifier.as_deref(), Some("verifier"));
        assert_eq!(token.refresh_token.as_deref(), Some("refresh"));
        assert_eq!(token.scope.as_deref(), Some("machine:read"));
        assert_eq!(
            token
                .redirect_uri
                .and_then(|url| url.host_str().map(str::to_owned))
                .as_deref(),
            Some("client.example")
        );

        let revocation: RevocationRequest = serde_json::from_value(serde_json::json!({
            "token": "token", "token_type_hint": "refresh_token"
        }))?;
        assert_eq!(revocation.token, "token");
        assert_eq!(revocation.token_type_hint.as_deref(), Some("refresh_token"));

        let response = DynamicClientResponse {
            client_id: "generated".to_owned(),
            client_id_issued_at: 1_700_000_000,
            redirect_uris: dynamic.redirect_uris,
            client_name: "Example".to_owned(),
            token_endpoint_auth_method: "none",
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            scope: "machine:read".to_owned(),
        };
        let serialized = serde_json::to_value(response)?;
        assert_eq!(serialized["client_id"], "generated");
        assert_eq!(serialized["token_endpoint_auth_method"], "none");
        assert_eq!(serialized["grant_types"].as_array().map(Vec::len), Some(2));
        Ok(())
    }
}
