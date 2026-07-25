use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretString};
use url::Url;
use uuid::Uuid;

use crate::crypto::validate_pkce_challenge;
use crate::model::{
    AuthorizationCodeGrant, ConsentChallenge, PendingAuthorization, PendingConsent,
    RegisteredClient, TokenGrant, TokenPairDraft,
};
use crate::{
    AccessGrant, AuthorizationRequest, AuthorizationServerMetadata, ConsentDecision, ConsentResult,
    DynamicClientRequest, DynamicClientResponse, GitHubAuthorization, GitHubCallback,
    GitHubOwnerVerifier, HashPurpose, IssuedToken, OAuthError, OAuthStore,
    ProtectedResourceMetadata, RevocationRequest, Scope, ScopeSet, StoreError, TokenHasher,
    TokenRequest, generate_secret,
};

const ACCESS_TOKEN_TTL: Duration = Duration::minutes(15);
const REFRESH_TOKEN_TTL: Duration = Duration::days(30);
const AUTHORIZATION_TRANSACTION_TTL: Duration = Duration::minutes(10);
const CONSENT_TTL: Duration = Duration::minutes(5);
const AUTHORIZATION_CODE_TTL: Duration = Duration::minutes(5);
const REGISTRATION_WINDOW_SECONDS: i64 = 60;
const REGISTRATIONS_PER_WINDOW: usize = 20;
const MAX_REGISTERED_CLIENTS: usize = 256;

#[derive(Clone, Debug)]
pub struct OAuthServiceConfig {
    pub issuer: Url,
    pub protected_resource: Url,
    pub github_client_id: String,
    pub github_callback_url: Url,
}

impl OAuthServiceConfig {
    pub fn validate(&self) -> Result<(), OAuthError> {
        validate_public_url(&self.issuer, false)?;
        validate_public_url(&self.protected_resource, true)?;
        validate_public_url(&self.github_callback_url, true)?;
        if self.issuer.path() != "/" {
            return Err(OAuthError::configuration());
        }
        if self.github_client_id.trim().is_empty() || self.github_client_id.len() > 256 {
            return Err(OAuthError::configuration());
        }
        if origin(&self.issuer) != origin(&self.protected_resource)
            || origin(&self.issuer) != origin(&self.github_callback_url)
        {
            return Err(OAuthError::configuration());
        }
        Ok(())
    }
}

pub struct OAuthService {
    config: OAuthServiceConfig,
    store: Arc<dyn OAuthStore>,
    hasher: TokenHasher,
    github: Arc<dyn GitHubOwnerVerifier>,
}

impl std::fmt::Debug for OAuthService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthService")
            .field("config", &self.config)
            .field("store", &"dyn OAuthStore")
            .field("hasher", &self.hasher)
            .field("github", &"dyn GitHubOwnerVerifier")
            .finish()
    }
}

impl OAuthService {
    pub fn new(
        config: OAuthServiceConfig,
        store: Arc<dyn OAuthStore>,
        hasher: TokenHasher,
        github: Arc<dyn GitHubOwnerVerifier>,
    ) -> Result<Self, OAuthError> {
        config.validate()?;
        Ok(Self {
            config,
            store,
            hasher,
            github,
        })
    }

    #[must_use]
    pub fn authorization_server_metadata(&self) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata::new(&self.config.issuer, &self.config.protected_resource)
    }

    #[must_use]
    pub fn protected_resource_metadata(&self) -> ProtectedResourceMetadata {
        ProtectedResourceMetadata::new(&self.config.issuer, &self.config.protected_resource)
    }

    #[must_use]
    pub fn github_callback_url(&self) -> &Url {
        &self.config.github_callback_url
    }

    #[must_use]
    pub fn consent_endpoint(&self) -> Url {
        endpoint(&self.config.issuer, "oauth/consent")
    }

    pub fn register_client(
        &self,
        request: DynamicClientRequest,
    ) -> Result<DynamicClientResponse, OAuthError> {
        self.check_registration_limits()?;
        if request.redirect_uris.is_empty() || request.redirect_uris.len() > 16 {
            return Err(OAuthError::invalid_request());
        }
        let mut seen = BTreeSet::new();
        for redirect in &request.redirect_uris {
            validate_redirect_uri(redirect)?;
            if !seen.insert(redirect.as_str().to_owned()) {
                return Err(OAuthError::invalid_request());
            }
        }
        if request
            .token_endpoint_auth_method
            .as_deref()
            .is_some_and(|value| value != "none")
        {
            return Err(OAuthError::invalid_client());
        }
        if request.grant_types.as_ref().is_some_and(|grants| {
            grants.is_empty()
                || grants
                    .iter()
                    .any(|grant| grant != "authorization_code" && grant != "refresh_token")
        }) {
            return Err(OAuthError::invalid_request());
        }
        if request.response_types.as_ref().is_some_and(|types| {
            types.is_empty() || types.iter().any(|response| response != "code")
        }) {
            return Err(OAuthError::invalid_request());
        }
        let scopes = request
            .scope
            .as_deref()
            .map(ScopeSet::parse)
            .transpose()?
            .unwrap_or_else(ScopeSet::all);
        if scopes.is_empty() || !scopes.is_subset(&ScopeSet::all()) {
            return Err(OAuthError::invalid_scope());
        }
        let client_name = request
            .client_name
            .as_deref()
            .unwrap_or("Dynamic MCP client")
            .trim()
            .to_owned();
        if client_name.is_empty()
            || client_name.len() > 100
            || client_name.chars().any(char::is_control)
        {
            return Err(OAuthError::invalid_request());
        }
        let client_id_secret = generate_secret()?;
        let client_id = format!("rom_{}", client_id_secret.expose_secret());
        let issued_at = Utc::now();
        let client = RegisteredClient {
            client_id: client_id.clone(),
            client_name: client_name.clone(),
            redirect_uris: request.redirect_uris.clone(),
            scopes: scopes.clone(),
            issued_at,
        };
        self.store
            .register_client(&client)
            .map_err(map_store_server_error)?;
        Ok(DynamicClientResponse {
            client_id,
            client_id_issued_at: issued_at.timestamp(),
            redirect_uris: request.redirect_uris,
            client_name,
            token_endpoint_auth_method: "none",
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            scope: scopes.to_space_delimited(),
        })
    }

    fn check_registration_limits(&self) -> Result<(), OAuthError> {
        if self
            .store
            .registered_client_count()
            .map_err(map_store_server_error)?
            >= MAX_REGISTERED_CLIENTS
        {
            return Err(OAuthError::temporarily_unavailable());
        }
        let allowed = self
            .store
            .consume_registration_slot(
                Utc::now(),
                REGISTRATION_WINDOW_SECONDS,
                REGISTRATIONS_PER_WINDOW,
            )
            .map_err(map_store_server_error)?;
        if !allowed {
            return Err(OAuthError::temporarily_unavailable());
        }
        Ok(())
    }

    pub fn begin_authorization(
        &self,
        request: AuthorizationRequest,
    ) -> Result<GitHubAuthorization, OAuthError> {
        if request.response_type != "code"
            || request.client_id.len() > 256
            || request.state.len() < 16
            || request.state.len() > 1_024
            || request.state.chars().any(char::is_control)
            || request.code_challenge_method != "S256"
            || !validate_pkce_challenge(&request.code_challenge)
        {
            return Err(OAuthError::invalid_request());
        }
        if request
            .resource
            .as_ref()
            .is_some_and(|resource| resource != &self.config.protected_resource)
        {
            return Err(OAuthError::invalid_request());
        }
        let client = self
            .store
            .client(&request.client_id)
            .map_err(map_store_server_error)?
            .ok_or_else(OAuthError::invalid_client)?;
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(OAuthError::invalid_request());
        }
        let scopes = ScopeSet::parse(&request.scope)?;
        if scopes.is_empty() || !scopes.is_subset(&client.scopes) {
            return Err(OAuthError::invalid_scope());
        }
        let provider_state = generate_secret()?;
        self.store
            .put_authorization(&PendingAuthorization {
                provider_state_hash: self
                    .hasher
                    .hash(HashPurpose::GitHubState, provider_state.expose_secret()),
                client_id: request.client_id,
                redirect_uri: request.redirect_uri,
                client_state: request.state,
                scopes,
                code_challenge: request.code_challenge,
                expires_at: Utc::now() + AUTHORIZATION_TRANSACTION_TTL,
            })
            .map_err(map_store_server_error)?;

        let mut redirect = Url::parse("https://github.com/login/oauth/authorize")
            .map_err(|_| OAuthError::configuration())?;
        redirect
            .query_pairs_mut()
            .append_pair("client_id", &self.config.github_client_id)
            .append_pair("redirect_uri", self.config.github_callback_url.as_str())
            .append_pair("state", provider_state.expose_secret())
            .append_pair("allow_signup", "false");
        Ok(GitHubAuthorization {
            redirect,
            provider_state,
        })
    }

    pub async fn complete_github_callback(
        &self,
        callback: GitHubCallback,
    ) -> Result<ConsentChallenge, OAuthError> {
        if callback.state.len() > 1_024 || callback.code.is_empty() || callback.code.len() > 2_048 {
            return Err(OAuthError::invalid_request());
        }
        let pending = self
            .store
            .take_authorization(
                &self.hasher.hash(HashPurpose::GitHubState, &callback.state),
                Utc::now(),
            )
            .map_err(|error| match error {
                StoreError::NotFound | StoreError::InvalidGrant => OAuthError::access_denied(),
                _ => OAuthError::server(),
            })?;
        let identity = self
            .github
            .verify_code(
                SecretString::from(callback.code),
                &self.config.github_callback_url,
            )
            .await?;
        let client = self
            .store
            .client(&pending.client_id)
            .map_err(map_store_server_error)?
            .ok_or_else(OAuthError::invalid_client)?;
        let csrf = generate_secret()?;
        let id = Uuid::new_v4();
        self.store
            .put_consent(&PendingConsent {
                id,
                csrf_hash: self
                    .hasher
                    .hash(HashPurpose::ConsentCsrf, csrf.expose_secret()),
                client_id: pending.client_id,
                redirect_uri: pending.redirect_uri,
                client_state: pending.client_state,
                scopes: pending.scopes.clone(),
                code_challenge: pending.code_challenge,
                subject: format!("github:{}", identity.id),
                expires_at: Utc::now() + CONSENT_TTL,
            })
            .map_err(map_store_server_error)?;
        Ok(ConsentChallenge {
            id,
            csrf,
            client_name: client.client_name,
            scopes: pending.scopes,
        })
    }

    pub fn submit_consent(
        &self,
        id: Uuid,
        csrf: &str,
        decision: ConsentDecision,
    ) -> Result<ConsentResult, OAuthError> {
        if csrf.is_empty() || csrf.len() > 1_024 {
            return Err(OAuthError::invalid_request());
        }
        let consent = self
            .store
            .take_consent(
                id,
                &self.hasher.hash(HashPurpose::ConsentCsrf, csrf),
                Utc::now(),
            )
            .map_err(|error| match error {
                StoreError::NotFound | StoreError::InvalidGrant => OAuthError::access_denied(),
                _ => OAuthError::server(),
            })?;
        if decision == ConsentDecision::Deny {
            return Ok(ConsentResult {
                redirect: authorization_error_redirect(
                    consent.redirect_uri,
                    "access_denied",
                    &consent.client_state,
                    &self.config.issuer,
                ),
            });
        }
        let code = generate_secret()?;
        self.store
            .put_authorization_code(&AuthorizationCodeGrant {
                code_hash: self
                    .hasher
                    .hash(HashPurpose::AuthorizationCode, code.expose_secret()),
                client_id: consent.client_id,
                redirect_uri: consent.redirect_uri.clone(),
                scopes: consent.scopes,
                code_challenge: consent.code_challenge,
                subject: consent.subject,
                expires_at: Utc::now() + AUTHORIZATION_CODE_TTL,
            })
            .map_err(map_store_server_error)?;
        let mut redirect = consent.redirect_uri;
        redirect
            .query_pairs_mut()
            .append_pair("code", code.expose_secret())
            .append_pair("state", &consent.client_state)
            .append_pair("iss", self.config.issuer.as_str());
        Ok(ConsentResult { redirect })
    }

    pub fn issue_token(&self, request: &TokenRequest) -> Result<IssuedToken, OAuthError> {
        if request.client_id.is_empty() || request.client_id.len() > 256 {
            return Err(OAuthError::invalid_client());
        }
        let access = generate_secret()?;
        let refresh = generate_secret()?;
        let now = Utc::now();
        let drafts = TokenPairDraft {
            access_hash: self
                .hasher
                .hash(HashPurpose::AccessToken, access.expose_secret()),
            refresh_hash: self
                .hasher
                .hash(HashPurpose::RefreshToken, refresh.expose_secret()),
            access_expires_at: now + ACCESS_TOKEN_TTL,
            refresh_expires_at: now + REFRESH_TOKEN_TTL,
        };
        let grant = match request.grant_type.as_str() {
            "authorization_code" => {
                let code = request
                    .code
                    .as_deref()
                    .ok_or_else(OAuthError::invalid_request)?;
                let redirect = request
                    .redirect_uri
                    .as_ref()
                    .ok_or_else(OAuthError::invalid_request)?;
                let verifier = request
                    .code_verifier
                    .as_deref()
                    .ok_or_else(OAuthError::invalid_request)?;
                if code.len() > 2_048 {
                    return Err(OAuthError::invalid_grant());
                }
                self.store.exchange_authorization_code(
                    &self.hasher.hash(HashPurpose::AuthorizationCode, code),
                    &request.client_id,
                    redirect,
                    verifier,
                    &drafts,
                    now,
                )
            }
            "refresh_token" => {
                let token = request
                    .refresh_token
                    .as_deref()
                    .ok_or_else(OAuthError::invalid_request)?;
                if token.len() > 2_048 {
                    return Err(OAuthError::invalid_grant());
                }
                let requested_scopes = request.scope.as_deref().map(ScopeSet::parse).transpose()?;
                self.store.rotate_refresh_token(
                    &self.hasher.hash(HashPurpose::RefreshToken, token),
                    &request.client_id,
                    requested_scopes.as_ref(),
                    &drafts,
                    now,
                )
            }
            _ => return Err(OAuthError::unsupported_grant()),
        }
        .map_err(|error| map_store_grant_error(&error))?;
        Ok(token_response(access, refresh, grant))
    }

    pub fn revoke(&self, request: &RevocationRequest) -> Result<(), OAuthError> {
        if request.token.is_empty() || request.token.len() > 2_048 {
            return Ok(());
        }
        // RFC 7009 defines `token_type_hint` as a hint only. Always check both
        // domain-separated token hashes so an incorrect hint cannot prevent
        // revocation.
        self.store
            .revoke_token(&self.hasher.hash(HashPurpose::AccessToken, &request.token))
            .map_err(map_store_server_error)?;
        self.store
            .revoke_token(&self.hasher.hash(HashPurpose::RefreshToken, &request.token))
            .map_err(map_store_server_error)
    }

    pub fn authenticate_access(
        &self,
        raw_token: &str,
        required_scope: Scope,
        local_policy: &ScopeSet,
    ) -> Result<AccessGrant, OAuthError> {
        let grant = self.authenticate_access_token(raw_token, local_policy)?;
        if !grant.scopes.contains(required_scope) {
            return Err(OAuthError::access_denied());
        }
        Ok(grant)
    }

    pub fn authenticate_access_token(
        &self,
        raw_token: &str,
        local_policy: &ScopeSet,
    ) -> Result<AccessGrant, OAuthError> {
        if raw_token.is_empty() || raw_token.len() > 2_048 {
            return Err(OAuthError::invalid_grant());
        }
        let mut grant = self
            .store
            .access_grant(
                &self.hasher.hash(HashPurpose::AccessToken, raw_token),
                Utc::now(),
            )
            .map_err(map_store_server_error)?
            .ok_or_else(OAuthError::invalid_grant)?;
        grant.scopes = grant.scopes.constrained_by(local_policy);
        Ok(grant)
    }
}

fn token_response(
    access_token: SecretString,
    refresh_token: SecretString,
    grant: TokenGrant,
) -> IssuedToken {
    IssuedToken {
        access_token,
        refresh_token,
        token_type: "Bearer",
        expires_in: ACCESS_TOKEN_TTL.num_seconds().try_into().unwrap_or(900),
        scope: grant.scopes,
    }
}

fn validate_public_url(url: &Url, allow_query: bool) -> Result<(), OAuthError> {
    if url.scheme() != "https"
        || url.host_str().is_none()
        || url.fragment().is_some()
        || (!allow_query && url.query().is_some())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(OAuthError::configuration());
    }
    Ok(())
}

fn validate_redirect_uri(url: &Url) -> Result<(), OAuthError> {
    if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(OAuthError::invalid_request());
    }
    if url.scheme() == "https" && url.host_str().is_some() {
        return Ok(());
    }
    if url.scheme() == "http" && url.host_str().is_some_and(is_loopback_host) {
        return Ok(());
    }
    Err(OAuthError::invalid_request())
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn origin(url: &Url) -> (&str, Option<&str>, Option<u16>) {
    (url.scheme(), url.host_str(), url.port_or_known_default())
}

fn endpoint(issuer: &Url, path: &str) -> Url {
    let mut endpoint = issuer.clone();
    let prefix = issuer.path().trim_end_matches('/');
    endpoint.set_path(&format!("{prefix}/{path}"));
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
}

fn authorization_error_redirect(mut redirect: Url, error: &str, state: &str, issuer: &Url) -> Url {
    redirect
        .query_pairs_mut()
        .append_pair("error", error)
        .append_pair("state", state)
        .append_pair("iss", issuer.as_str());
    redirect
}

fn map_store_server_error(_error: StoreError) -> OAuthError {
    OAuthError::server()
}

fn map_store_grant_error(error: &StoreError) -> OAuthError {
    match error {
        StoreError::InvalidGrant | StoreError::NotFound | StoreError::RefreshReuse => {
            OAuthError::invalid_grant()
        }
        _ => OAuthError::server(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitHubIdentity, SqliteOAuthStore};
    use async_trait::async_trait;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    #[derive(Debug)]
    struct Owner;

    #[async_trait]
    impl GitHubOwnerVerifier for Owner {
        async fn verify_code(
            &self,
            _code: SecretString,
            _callback_url: &Url,
        ) -> Result<GitHubIdentity, OAuthError> {
            Ok(GitHubIdentity {
                id: 42,
                login: "owner".to_owned(),
            })
        }
    }

    fn service_with_store(store: Arc<dyn OAuthStore>) -> Result<OAuthService, OAuthError> {
        let config = OAuthServiceConfig {
            issuer: Url::parse("https://mine.example").map_err(|_| OAuthError::configuration())?,
            protected_resource: Url::parse("https://mine.example/mcp")
                .map_err(|_| OAuthError::configuration())?,
            github_client_id: "github-client".to_owned(),
            github_callback_url: Url::parse("https://mine.example/oauth/github/callback")
                .map_err(|_| OAuthError::configuration())?,
        };
        OAuthService::new(
            config,
            store,
            TokenHasher::new([9_u8; 32])?,
            Arc::new(Owner),
        )
    }

    fn service() -> Result<OAuthService, OAuthError> {
        let store = SqliteOAuthStore::in_memory().map_err(map_store_server_error)?;
        service_with_store(Arc::new(store))
    }

    fn verifier() -> String {
        "a".repeat(64)
    }

    fn challenge(verifier: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn register(service: &OAuthService) -> Result<DynamicClientResponse, OAuthError> {
        service.register_client(DynamicClientRequest {
            redirect_uris: vec![
                Url::parse("https://client.example/callback")
                    .map_err(|_| OAuthError::invalid_request())?,
            ],
            client_name: Some("Test client".to_owned()),
            token_endpoint_auth_method: Some("none".to_owned()),
            grant_types: Some(vec![
                "authorization_code".to_owned(),
                "refresh_token".to_owned(),
            ]),
            response_types: Some(vec!["code".to_owned()]),
            scope: Some("machine:read files:read files:write".to_owned()),
        })
    }

    async fn authorize(service: &OAuthService, client_id: &str) -> Result<String, OAuthError> {
        let verifier = verifier();
        let start = service.begin_authorization(AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: client_id.to_owned(),
            redirect_uri: Url::parse("https://client.example/callback")
                .map_err(|_| OAuthError::invalid_request())?,
            scope: "machine:read files:read".to_owned(),
            state: "client-csrf-state-123456789".to_owned(),
            code_challenge: challenge(&verifier),
            code_challenge_method: "S256".to_owned(),
            resource: Some(
                Url::parse("https://mine.example/mcp")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
        })?;
        let consent = service
            .complete_github_callback(GitHubCallback {
                code: "github-code".to_owned(),
                state: start.provider_state.expose_secret().to_owned(),
            })
            .await?;
        let result = service.submit_consent(
            consent.id,
            consent.csrf.expose_secret(),
            ConsentDecision::Allow,
        )?;
        result
            .redirect
            .query_pairs()
            .find_map(|(key, value)| (key == "code").then(|| value.into_owned()))
            .ok_or_else(OAuthError::server)
    }

    #[tokio::test]
    async fn complete_flow_rotates_refresh_and_rejects_reuse() -> Result<(), OAuthError> {
        let service = service()?;
        let client = register(&service)?;
        let code = authorize(&service, &client.client_id).await?;
        let first = service.issue_token(&TokenRequest {
            grant_type: "authorization_code".to_owned(),
            client_id: client.client_id.clone(),
            code: Some(code),
            redirect_uri: Some(
                Url::parse("https://client.example/callback")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
            code_verifier: Some(verifier()),
            refresh_token: None,
            scope: None,
        })?;
        let old_refresh = first.refresh_token.expose_secret().to_owned();
        let second = service.issue_token(&TokenRequest {
            grant_type: "refresh_token".to_owned(),
            client_id: client.client_id.clone(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_refresh.clone()),
            scope: Some("machine:read".to_owned()),
        })?;
        assert_eq!(second.scope.to_space_delimited(), "machine:read");
        let reused = service.issue_token(&TokenRequest {
            grant_type: "refresh_token".to_owned(),
            client_id: client.client_id,
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_refresh),
            scope: None,
        });
        assert!(reused.is_err());
        Ok(())
    }

    #[test]
    fn dynamic_registration_is_rate_limited() -> Result<(), OAuthError> {
        let service = service()?;
        for _ in 0..REGISTRATIONS_PER_WINDOW {
            register(&service)?;
        }
        let result = register(&service);
        assert!(matches!(
            result,
            Err(error) if error.code == crate::OAuthErrorCode::TemporarilyUnavailable
        ));
        Ok(())
    }

    #[test]
    fn dynamic_registration_limit_survives_service_restart() -> Result<(), OAuthError> {
        let directory = tempfile::tempdir().map_err(|_| OAuthError::server())?;
        let database = directory.path().join("state").join("state.db");
        {
            let store = SqliteOAuthStore::open(&database).map_err(map_store_server_error)?;
            let service = service_with_store(Arc::new(store))?;
            for _ in 0..REGISTRATIONS_PER_WINDOW {
                register(&service)?;
            }
        }
        let store = SqliteOAuthStore::open(&database).map_err(map_store_server_error)?;
        let restarted = service_with_store(Arc::new(store))?;
        assert!(matches!(
            register(&restarted),
            Err(error) if error.code == crate::OAuthErrorCode::TemporarilyUnavailable
        ));
        Ok(())
    }

    #[tokio::test]
    async fn wrong_pkce_does_not_consume_authorization_code() -> Result<(), OAuthError> {
        let service = service()?;
        let client = register(&service)?;
        let code = authorize(&service, &client.client_id).await?;
        let mut request = TokenRequest {
            grant_type: "authorization_code".to_owned(),
            client_id: client.client_id,
            code: Some(code),
            redirect_uri: Some(
                Url::parse("https://client.example/callback")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
            code_verifier: Some(
                "wrong-verifier-value-that-is-long-enough-123456789012345".to_owned(),
            ),
            refresh_token: None,
            scope: None,
        };
        assert!(service.issue_token(&request).is_err());
        request.code_verifier = Some(verifier());
        assert!(service.issue_token(&request).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn revoke_ignores_incorrect_token_type_hint() -> Result<(), OAuthError> {
        let service = service()?;
        let client = register(&service)?;
        let code = authorize(&service, &client.client_id).await?;
        let token = service.issue_token(&TokenRequest {
            grant_type: "authorization_code".to_owned(),
            client_id: client.client_id,
            code: Some(code),
            redirect_uri: Some(
                Url::parse("https://client.example/callback")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
            code_verifier: Some(verifier()),
            refresh_token: None,
            scope: None,
        })?;
        let local = ScopeSet::all();
        assert!(
            service
                .authenticate_access(
                    token.access_token.expose_secret(),
                    Scope::MachineRead,
                    &local,
                )
                .is_ok()
        );
        service.revoke(&RevocationRequest {
            token: token.access_token.expose_secret().to_owned(),
            token_type_hint: Some("refresh_token".to_owned()),
        })?;
        assert!(
            service
                .authenticate_access(
                    token.access_token.expose_secret(),
                    Scope::MachineRead,
                    &local,
                )
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn token_scope_is_intersected_with_local_policy() -> Result<(), OAuthError> {
        let service = service()?;
        let client = register(&service)?;
        let code = authorize(&service, &client.client_id).await?;
        let token = service.issue_token(&TokenRequest {
            grant_type: "authorization_code".to_owned(),
            client_id: client.client_id,
            code: Some(code),
            redirect_uri: Some(
                Url::parse("https://client.example/callback")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
            code_verifier: Some(verifier()),
            refresh_token: None,
            scope: None,
        })?;
        let local = ScopeSet::parse("machine:read").unwrap_or_default();
        assert!(
            service
                .authenticate_access(token.access_token.expose_secret(), Scope::FilesRead, &local,)
                .is_err()
        );
        assert!(
            service
                .authenticate_access(
                    token.access_token.expose_secret(),
                    Scope::MachineRead,
                    &local,
                )
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn rejects_non_https_public_issuer_and_non_loopback_http_redirect() {
        let invalid = OAuthServiceConfig {
            issuer: Url::parse("http://mine.example").unwrap_or_else(|_| unreachable!()),
            protected_resource: Url::parse("https://mine.example/mcp")
                .unwrap_or_else(|_| unreachable!()),
            github_client_id: "id".to_owned(),
            github_callback_url: Url::parse("https://mine.example/callback")
                .unwrap_or_else(|_| unreachable!()),
        };
        assert!(invalid.validate().is_err());
        assert!(
            validate_redirect_uri(
                &Url::parse("http://client.example/callback").unwrap_or_else(|_| unreachable!())
            )
            .is_err()
        );
        assert!(
            validate_redirect_uri(
                &Url::parse("http://127.0.0.1:49152/callback").unwrap_or_else(|_| unreachable!())
            )
            .is_ok()
        );
    }
}
