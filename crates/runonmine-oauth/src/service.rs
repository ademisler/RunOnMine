use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use base64::Engine as _;
use chrono::{Duration, Utc};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

use crate::crypto::validate_pkce_challenge;
use crate::diagnostics;
use crate::model::{
    AuthorizationClaim, AuthorizationCodeGrant, ConsentChallenge, PendingAuthorization,
    PendingConsent, RegisteredClient, RegistrationLimits, RegistrationOutcome, TokenGrant,
    TokenPairDraft,
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
const AUTHORIZATION_CLAIM_TTL: Duration = Duration::seconds(30);
const CONSENT_TTL: Duration = Duration::minutes(5);
const AUTHORIZATION_CODE_TTL: Duration = Duration::minutes(5);
const REGISTRATION_WINDOW_SECONDS: i64 = 60;
const REGISTRATIONS_PER_SOURCE_WINDOW: usize = 5;
const REGISTRATIONS_GLOBAL_WINDOW: usize = 20;
const MAX_REGISTERED_CLIENTS: usize = 256;
const UNUSED_CLIENT_TTL: Duration = Duration::days(1);
const ACTIVE_CLIENT_TTL: Duration = Duration::days(90);

#[derive(Clone, Debug)]
pub struct OAuthServiceConfig {
    pub connector_id: String,
    pub issuer: Url,
    pub protected_resource: Url,
    pub github_client_id: String,
    pub github_callback_url: Url,
}

impl OAuthServiceConfig {
    pub fn validate(&self) -> Result<(), OAuthError> {
        if self.connector_id.trim().is_empty()
            || self.connector_id.len() > 128
            || self.connector_id.chars().any(char::is_control)
        {
            return Err(OAuthError::configuration());
        }
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

struct GitHubCallbackPreparation {
    client: RegisteredClient,
    csrf: SecretString,
    consent_id: Uuid,
    client_id_fingerprint: String,
    requested_redirect_origin: String,
    registered_redirect_origins: Vec<String>,
}

pub struct OAuthService {
    config: OAuthServiceConfig,
    store: Arc<dyn OAuthStore>,
    hasher: TokenHasher,
    registration_access_hash: crate::SecretHash,
    github: Arc<dyn GitHubOwnerVerifier>,
}

impl std::fmt::Debug for OAuthService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthService")
            .field("config", &self.config)
            .field("store", &"dyn OAuthStore")
            .field("hasher", &self.hasher)
            .field("registration_access_hash", &"[REDACTED]")
            .field("github", &"dyn GitHubOwnerVerifier")
            .finish()
    }
}

impl OAuthService {
    pub fn new(
        config: OAuthServiceConfig,
        store: Arc<dyn OAuthStore>,
        hasher: TokenHasher,
        registration_access_token: &SecretString,
        github: Arc<dyn GitHubOwnerVerifier>,
    ) -> Result<Self, OAuthError> {
        config.validate()?;
        let registration_access_token = registration_access_token.expose_secret();
        if registration_access_token.len() < 32
            || registration_access_token.len() > 1_024
            || registration_access_token.contains(char::is_whitespace)
        {
            return Err(OAuthError::configuration());
        }
        let registration_access_hash =
            hasher.hash(HashPurpose::RegistrationAccess, registration_access_token);
        Ok(Self {
            config,
            store,
            hasher,
            registration_access_hash,
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
        registration_access_token: &str,
        registration_source: &str,
    ) -> Result<DynamicClientResponse, OAuthError> {
        let supplied_hash = self
            .hasher
            .hash(HashPurpose::RegistrationAccess, registration_access_token);
        if !self
            .registration_access_hash
            .constant_time_eq(&supplied_hash)
        {
            return Err(OAuthError::invalid_client());
        }
        let (client, response) = self.validate_registration(request, registration_source)?;
        let limits = RegistrationLimits {
            now: client.issued_at,
            window_seconds: REGISTRATION_WINDOW_SECONDS,
            per_source_limit: REGISTRATIONS_PER_SOURCE_WINDOW,
            global_limit: REGISTRATIONS_GLOBAL_WINDOW,
            max_clients: MAX_REGISTERED_CLIENTS,
        };
        match self
            .store
            .register_client_limited(&client, &limits)
            .map_err(|error| self.store_server_error("register_client", &error))?
        {
            RegistrationOutcome::Registered => Ok(response),
            RegistrationOutcome::RateLimited | RegistrationOutcome::CapacityReached => {
                Err(OAuthError::temporarily_unavailable())
            }
        }
    }

    fn validate_registration(
        &self,
        request: DynamicClientRequest,
        registration_source: &str,
    ) -> Result<(RegisteredClient, DynamicClientResponse), OAuthError> {
        if registration_source.is_empty()
            || registration_source.len() > 256
            || registration_source.chars().any(char::is_control)
        {
            return Err(OAuthError::invalid_request());
        }
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
            .unwrap_or_else(ScopeSet::dynamic_registration_default);
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
            || client_name.chars().any(unsafe_display_character)
        {
            return Err(OAuthError::invalid_request());
        }
        let client_id_secret = generate_secret()?;
        let connector_key = connector_namespace_key(&self.config.connector_id);
        let client_id = format!("rom_{connector_key}_{}", client_id_secret.expose_secret());
        let issued_at = Utc::now();
        let registration_source_hash = self
            .hasher
            .hash(HashPurpose::RegistrationSource, registration_source)
            .storage_key();
        let client = RegisteredClient {
            connector_id: self.config.connector_id.clone(),
            client_id: client_id.clone(),
            client_name: client_name.clone(),
            redirect_uris: request.redirect_uris.clone(),
            scopes: scopes.clone(),
            issued_at,
            expires_at: issued_at + UNUSED_CLIENT_TTL,
            last_used_at: None,
            registration_source_hash,
        };
        let response = DynamicClientResponse {
            client_id,
            client_id_issued_at: issued_at.timestamp(),
            redirect_uris: request.redirect_uris,
            client_name,
            token_endpoint_auth_method: "none",
            grant_types: vec!["authorization_code", "refresh_token"],
            response_types: vec!["code"],
            scope: scopes.to_space_delimited(),
        };
        Ok((client, response))
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
            .map_err(|error| self.store_server_error("load_authorization_client", &error))?
            .ok_or_else(OAuthError::invalid_client)?;
        if !client.redirect_uris.contains(&request.redirect_uri) {
            return Err(OAuthError::invalid_request());
        }
        let scopes = ScopeSet::parse(&request.scope)?;
        if scopes.is_empty() || !scopes.is_subset(&client.scopes) {
            return Err(OAuthError::invalid_scope());
        }
        let now = Utc::now();
        if !self
            .store
            .touch_client(&request.client_id, now, now + ACTIVE_CLIENT_TTL)
            .map_err(|error| self.store_server_error("touch_authorization_client", &error))?
        {
            return Err(OAuthError::invalid_client());
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
            .map_err(|error| self.store_server_error("store_authorization", &error))?;

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
        let claim = self.claim_github_authorization(&callback)?;
        let prepared = self.prepare_github_callback(&claim)?;
        let identity = match self
            .github
            .verify_code(
                SecretString::from(callback.code),
                &self.config.github_callback_url,
            )
            .await
        {
            Ok(identity) => identity,
            Err(error) => return Err(self.settle_github_verification_error(&claim, error)?),
        };

        let consent = PendingConsent {
            id: prepared.consent_id,
            csrf_hash: self
                .hasher
                .hash(HashPurpose::ConsentCsrf, prepared.csrf.expose_secret()),
            client_id: claim.pending.client_id.clone(),
            redirect_uri: claim.pending.redirect_uri.clone(),
            client_state: claim.pending.client_state.clone(),
            scopes: claim.pending.scopes.clone(),
            code_challenge: claim.pending.code_challenge.clone(),
            subject: format!("github:{}", identity.id),
            expires_at: Utc::now() + CONSENT_TTL,
        };
        self.store
            .complete_authorization_claim(&claim, &consent, Utc::now())
            .map_err(|error| self.store_server_error("complete_authorization_claim", &error))?;

        Ok(ConsentChallenge {
            id: prepared.consent_id,
            csrf: prepared.csrf,
            claimed_client_name: prepared.client.client_name,
            client_id_fingerprint: prepared.client_id_fingerprint,
            registered_at: prepared.client.issued_at,
            requested_redirect_origin: prepared.requested_redirect_origin,
            registered_redirect_origins: prepared.registered_redirect_origins,
            scopes: claim.pending.scopes,
        })
    }

    fn claim_github_authorization(
        &self,
        callback: &GitHubCallback,
    ) -> Result<AuthorizationClaim, OAuthError> {
        if callback.state.len() > 1_024 || callback.code.is_empty() || callback.code.len() > 2_048 {
            return Err(OAuthError::invalid_request());
        }
        let now = Utc::now();
        self.store
            .claim_authorization(
                &self.hasher.hash(HashPurpose::GitHubState, &callback.state),
                &self.hasher.hash(HashPurpose::GitHubCode, &callback.code),
                Uuid::new_v4(),
                now,
                now + AUTHORIZATION_CLAIM_TTL,
            )
            .map_err(|error| match error {
                StoreError::NotFound | StoreError::InvalidGrant => OAuthError::access_denied(),
                unexpected => self.store_server_error("claim_authorization", &unexpected),
            })
    }

    fn prepare_github_callback(
        &self,
        claim: &AuthorizationClaim,
    ) -> Result<GitHubCallbackPreparation, OAuthError> {
        let client = match self.store.client(&claim.pending.client_id) {
            Ok(Some(client)) => client,
            Ok(None) => {
                self.consume_callback_claim(claim, "consume_missing_callback_client")?;
                return Err(OAuthError::invalid_client());
            }
            Err(error) => {
                self.release_callback_claim(claim, "release_callback_client_claim")?;
                return Err(self.store_server_error("load_callback_client", &error));
            }
        };
        let prepared = (|| {
            Ok(GitHubCallbackPreparation {
                client_id_fingerprint: client_id_fingerprint(&client.client_id),
                requested_redirect_origin: redirect_origin(&claim.pending.redirect_uri)?,
                registered_redirect_origins: registered_redirect_origins(&client.redirect_uris)?,
                csrf: generate_secret()?,
                consent_id: Uuid::new_v4(),
                client,
            })
        })();
        match prepared {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                self.release_callback_claim(claim, "release_callback_preparation_claim")?;
                Err(error)
            }
        }
    }

    fn settle_github_verification_error(
        &self,
        claim: &AuthorizationClaim,
        error: OAuthError,
    ) -> Result<OAuthError, OAuthError> {
        if error.code == crate::OAuthErrorCode::TemporarilyUnavailable {
            self.release_callback_claim(claim, "release_transient_github_claim")?;
        } else {
            self.consume_callback_claim(claim, "consume_terminal_github_claim")?;
        }
        Ok(error)
    }

    fn release_callback_claim(
        &self,
        claim: &AuthorizationClaim,
        operation: &'static str,
    ) -> Result<(), OAuthError> {
        self.store
            .release_authorization_claim(claim, Utc::now())
            .map_err(|error| self.store_server_error(operation, &error))
    }

    fn consume_callback_claim(
        &self,
        claim: &AuthorizationClaim,
        operation: &'static str,
    ) -> Result<(), OAuthError> {
        self.store
            .consume_authorization_claim(claim, Utc::now())
            .map_err(|error| self.store_server_error(operation, &error))
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
                unexpected => self.store_server_error("take_consent", &unexpected),
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
            .map_err(|error| self.store_server_error("store_authorization_code", &error))?;
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
        .map_err(|error| self.store_grant_error("issue_token", error))?;
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
            .map_err(|error| self.store_server_error("revoke_access_token", &error))?;
        self.store
            .revoke_token(&self.hasher.hash(HashPurpose::RefreshToken, &request.token))
            .map_err(|error| self.store_server_error("revoke_refresh_token", &error))
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
            .map_err(|error| self.store_server_error("authenticate_access_token", &error))?
            .ok_or_else(OAuthError::invalid_grant)?;
        grant.scopes = grant.scopes.constrained_by(local_policy);
        Ok(grant)
    }

    fn store_server_error(&self, operation: &'static str, error: &StoreError) -> OAuthError {
        map_store_server_error_for(&self.config.connector_id, operation, error)
    }

    fn store_grant_error(&self, operation: &'static str, error: StoreError) -> OAuthError {
        map_store_grant_error_for(&self.config.connector_id, operation, error)
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

fn unsafe_display_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn connector_namespace_key(connector_id: &str) -> String {
    let digest = Sha256::digest(connector_id.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..8])
}

fn client_id_fingerprint(client_id: &str) -> String {
    let digest = Sha256::digest(client_id.as_bytes());
    let compact = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..12]);
    format!("sha256:{compact}")
}

fn registered_redirect_origins(redirect_uris: &[Url]) -> Result<Vec<String>, OAuthError> {
    redirect_uris
        .iter()
        .map(redirect_origin)
        .collect::<Result<BTreeSet<_>, _>>()
        .map(BTreeSet::into_iter)
        .map(Iterator::collect)
}

fn redirect_origin(url: &Url) -> Result<String, OAuthError> {
    let origin = url.origin().ascii_serialization();
    if origin == "null" {
        return Err(OAuthError::invalid_request());
    }
    Ok(origin)
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

fn map_store_server_error_for(
    connector_id: &str,
    operation: &'static str,
    error: &StoreError,
) -> OAuthError {
    diagnostics::log_store_error(connector_id, operation, error);
    OAuthError::server()
}

fn map_store_grant_error_for(
    connector_id: &str,
    operation: &'static str,
    error: StoreError,
) -> OAuthError {
    match error {
        StoreError::InvalidGrant | StoreError::NotFound | StoreError::RefreshReuse => {
            OAuthError::invalid_grant()
        }
        unexpected => map_store_server_error_for(connector_id, operation, &unexpected),
    }
}

#[cfg(test)]
fn map_store_server_error(error: &StoreError) -> OAuthError {
    map_store_server_error_for("test-connector", "test_store_operation", error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GitHubIdentity, SqliteOAuthStore};
    use async_trait::async_trait;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const TEST_REGISTRATION_TOKEN: &str =
        "test-registration-access-token-with-more-than-thirty-two-bytes";

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

    #[derive(Debug)]
    struct SequenceVerifier {
        responses: Mutex<VecDeque<Result<GitHubIdentity, OAuthError>>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl SequenceVerifier {
        fn new(responses: impl IntoIterator<Item = Result<GitHubIdentity, OAuthError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl GitHubOwnerVerifier for SequenceVerifier {
        async fn verify_code(
            &self,
            _code: SecretString,
            _callback_url: &Url,
        ) -> Result<GitHubIdentity, OAuthError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.responses
                .lock()
                .map_err(|_| OAuthError::server())?
                .pop_front()
                .unwrap_or_else(|| Err(OAuthError::server()))
        }
    }

    fn owner_identity() -> GitHubIdentity {
        GitHubIdentity {
            id: 42,
            login: "owner".to_owned(),
        }
    }

    fn service_with_store_and_verifier(
        store: Arc<dyn OAuthStore>,
        github: Arc<dyn GitHubOwnerVerifier>,
    ) -> Result<OAuthService, OAuthError> {
        let config = OAuthServiceConfig {
            connector_id: "test-connector".to_owned(),
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
            &SecretString::from(TEST_REGISTRATION_TOKEN.to_owned()),
            github,
        )
    }

    fn service_with_store(store: Arc<dyn OAuthStore>) -> Result<OAuthService, OAuthError> {
        service_with_store_and_verifier(store, Arc::new(Owner))
    }

    fn service() -> Result<OAuthService, OAuthError> {
        let store =
            SqliteOAuthStore::in_memory().map_err(|error| map_store_server_error(&error))?;
        service_with_store(Arc::new(store))
    }

    fn verifier() -> String {
        "a".repeat(64)
    }

    fn challenge(verifier: &str) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    }

    fn registration_request() -> Result<DynamicClientRequest, OAuthError> {
        Ok(DynamicClientRequest {
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

    fn register_from_source(
        service: &OAuthService,
        source: &str,
    ) -> Result<DynamicClientResponse, OAuthError> {
        service.register_client(registration_request()?, TEST_REGISTRATION_TOKEN, source)
    }

    fn register(service: &OAuthService) -> Result<DynamicClientResponse, OAuthError> {
        register_from_source(service, "test-source")
    }

    fn begin_test_authorization(
        service: &OAuthService,
        client_id: &str,
    ) -> Result<GitHubAuthorization, OAuthError> {
        service.begin_authorization(AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: client_id.to_owned(),
            redirect_uri: Url::parse("https://client.example/callback")
                .map_err(|_| OAuthError::invalid_request())?,
            scope: "machine:read files:read".to_owned(),
            state: "client-csrf-state-retry-123456789".to_owned(),
            code_challenge: challenge(&verifier()),
            code_challenge_method: "S256".to_owned(),
            resource: Some(
                Url::parse("https://mine.example/mcp")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
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

    #[test]
    fn client_name_rejects_invisible_and_bidirectional_control_characters() -> Result<(), OAuthError>
    {
        let service = service()?;
        for unsafe_name in [
            "Trusted client\nFingerprint: trusted",
            "Trusted client\u{202e}moc.live",
            "Trusted\u{200b}client",
            "Trusted\u{2066}client\u{2069}",
        ] {
            let mut request = registration_request()?;
            request.client_name = Some(unsafe_name.to_owned());
            assert!(matches!(
                service.register_client(request, TEST_REGISTRATION_TOKEN, "unsafe-name-source"),
                Err(error) if error.code == crate::OAuthErrorCode::InvalidRequest
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn consent_challenge_identifies_unverified_client_beyond_claimed_name()
    -> Result<(), OAuthError> {
        let service = service()?;
        let mut request = registration_request()?;
        request.client_name = Some("RunOnMine Official Client".to_owned());
        request.redirect_uris = vec![
            Url::parse("https://client.example/callback")
                .map_err(|_| OAuthError::invalid_request())?,
            Url::parse("https://client.example/other?source=registration")
                .map_err(|_| OAuthError::invalid_request())?,
            Url::parse("http://127.0.0.1:8787/oauth/callback")
                .map_err(|_| OAuthError::invalid_request())?,
        ];
        let client =
            service.register_client(request, TEST_REGISTRATION_TOKEN, "consent-identity-source")?;
        let stored = service
            .store
            .client(&client.client_id)
            .map_err(|error| map_store_server_error(&error))?
            .ok_or_else(OAuthError::server)?;
        let start = service.begin_authorization(AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: client.client_id.clone(),
            redirect_uri: Url::parse("https://client.example/callback")
                .map_err(|_| OAuthError::invalid_request())?,
            scope: "machine:read".to_owned(),
            state: "client-csrf-state-identity-123456789".to_owned(),
            code_challenge: challenge(&verifier()),
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
        assert_eq!(consent.claimed_client_name, "RunOnMine Official Client");
        assert_eq!(
            consent.client_id_fingerprint,
            client_id_fingerprint(&client.client_id)
        );
        assert!(consent.client_id_fingerprint.starts_with("sha256:"));
        assert!(!consent.client_id_fingerprint.contains(&client.client_id));
        assert_eq!(consent.registered_at, stored.issued_at);
        assert_eq!(consent.requested_redirect_origin, "https://client.example");
        assert_eq!(
            consent.registered_redirect_origins,
            vec![
                "http://127.0.0.1:8787".to_owned(),
                "https://client.example".to_owned(),
            ]
        );
        Ok(())
    }

    #[test]
    fn missing_dynamic_registration_scope_gets_machine_read_only() -> Result<(), OAuthError> {
        let service = service()?;
        let mut request = registration_request()?;
        request.scope = None;
        let response =
            service.register_client(request, TEST_REGISTRATION_TOKEN, "missing-scope-source")?;
        assert_eq!(response.scope, "machine:read");
        let stored = service
            .store
            .client(&response.client_id)
            .map_err(|error| map_store_server_error(&error))?
            .ok_or_else(OAuthError::server)?;
        assert_eq!(stored.scopes.to_space_delimited(), "machine:read");
        Ok(())
    }

    #[test]
    fn missing_scope_client_cannot_request_unregistered_file_scope() -> Result<(), OAuthError> {
        let service = service()?;
        let mut request = registration_request()?;
        request.scope = None;
        let client = service.register_client(
            request,
            TEST_REGISTRATION_TOKEN,
            "missing-scope-auth-source",
        )?;
        let result = service.begin_authorization(AuthorizationRequest {
            response_type: "code".to_owned(),
            client_id: client.client_id,
            redirect_uri: Url::parse("https://client.example/callback")
                .map_err(|_| OAuthError::invalid_request())?,
            scope: "files:read".to_owned(),
            state: "client-csrf-state-123456789".to_owned(),
            code_challenge: challenge(&verifier()),
            code_challenge_method: "S256".to_owned(),
            resource: Some(
                Url::parse("https://mine.example/mcp")
                    .map_err(|_| OAuthError::invalid_request())?,
            ),
        });
        assert!(matches!(
            result,
            Err(error) if error.code == crate::OAuthErrorCode::InvalidScope
        ));
        Ok(())
    }

    #[tokio::test]
    async fn transient_provider_failure_releases_bound_claim_for_same_code_retry()
    -> Result<(), OAuthError> {
        let store = Arc::new(
            SqliteOAuthStore::in_memory().map_err(|error| map_store_server_error(&error))?,
        );
        let verifier = Arc::new(SequenceVerifier::new([
            Err(OAuthError::temporarily_unavailable()),
            Ok(owner_identity()),
        ]));
        let service = service_with_store_and_verifier(store, verifier.clone())?;
        let client = register(&service)?;
        let start = begin_test_authorization(&service, &client.client_id)?;
        let state = start.provider_state.expose_secret().to_owned();

        let first = service
            .complete_github_callback(GitHubCallback {
                code: "retry-code".to_owned(),
                state: state.clone(),
            })
            .await;
        assert!(matches!(
            first,
            Err(error) if error.code == crate::OAuthErrorCode::TemporarilyUnavailable
        ));

        let consent = service
            .complete_github_callback(GitHubCallback {
                code: "retry-code".to_owned(),
                state: state.clone(),
            })
            .await?;
        assert_eq!(
            consent.scopes.to_space_delimited(),
            "machine:read files:read"
        );
        assert_eq!(verifier.call_count(), 2);

        let replay = service
            .complete_github_callback(GitHubCallback {
                code: "retry-code".to_owned(),
                state,
            })
            .await;
        assert!(matches!(
            replay,
            Err(error) if error.code == crate::OAuthErrorCode::AccessDenied
        ));
        assert_eq!(verifier.call_count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn transient_retry_is_bound_to_the_original_provider_code() -> Result<(), OAuthError> {
        let store = Arc::new(
            SqliteOAuthStore::in_memory().map_err(|error| map_store_server_error(&error))?,
        );
        let verifier = Arc::new(SequenceVerifier::new([
            Err(OAuthError::temporarily_unavailable()),
            Ok(owner_identity()),
        ]));
        let service = service_with_store_and_verifier(store, verifier.clone())?;
        let client = register(&service)?;
        let start = begin_test_authorization(&service, &client.client_id)?;
        let state = start.provider_state.expose_secret().to_owned();

        let first = service
            .complete_github_callback(GitHubCallback {
                code: "bound-code".to_owned(),
                state: state.clone(),
            })
            .await;
        assert!(matches!(
            first,
            Err(error) if error.code == crate::OAuthErrorCode::TemporarilyUnavailable
        ));

        let wrong_code = service
            .complete_github_callback(GitHubCallback {
                code: "different-code".to_owned(),
                state: state.clone(),
            })
            .await;
        assert!(matches!(
            wrong_code,
            Err(error) if error.code == crate::OAuthErrorCode::AccessDenied
        ));
        assert_eq!(verifier.call_count(), 1);

        service
            .complete_github_callback(GitHubCallback {
                code: "bound-code".to_owned(),
                state,
            })
            .await?;
        assert_eq!(verifier.call_count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn terminal_provider_failure_consumes_state_and_blocks_replay() -> Result<(), OAuthError>
    {
        let store = Arc::new(
            SqliteOAuthStore::in_memory().map_err(|error| map_store_server_error(&error))?,
        );
        let verifier = Arc::new(SequenceVerifier::new([
            Err(OAuthError::access_denied()),
            Ok(owner_identity()),
        ]));
        let service = service_with_store_and_verifier(store, verifier.clone())?;
        let client = register(&service)?;
        let start = begin_test_authorization(&service, &client.client_id)?;
        let state = start.provider_state.expose_secret().to_owned();

        for _ in 0..2 {
            let denied = service
                .complete_github_callback(GitHubCallback {
                    code: "terminal-code".to_owned(),
                    state: state.clone(),
                })
                .await;
            assert!(matches!(
                denied,
                Err(error) if error.code == crate::OAuthErrorCode::AccessDenied
            ));
        }
        assert_eq!(verifier.call_count(), 1);
        Ok(())
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
        let grant = service.authenticate_access(
            first.access_token.expose_secret(),
            Scope::MachineRead,
            &ScopeSet::all(),
        )?;
        assert_eq!(grant.subject, "github:42");
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
    fn dynamic_registration_requires_initial_access_token() -> Result<(), OAuthError> {
        let service = service()?;
        let result = service.register_client(registration_request()?, "wrong-token", "source");
        assert!(matches!(
            result,
            Err(error) if error.code == crate::OAuthErrorCode::InvalidClient
        ));
        Ok(())
    }

    #[test]
    fn invalid_registration_does_not_consume_source_capacity() -> Result<(), OAuthError> {
        let service = service()?;
        for _ in 0..(REGISTRATIONS_PER_SOURCE_WINDOW * 3) {
            let mut invalid = registration_request()?;
            invalid.redirect_uris.clear();
            assert!(
                service
                    .register_client(invalid, TEST_REGISTRATION_TOKEN, "same-source")
                    .is_err()
            );
        }
        for _ in 0..REGISTRATIONS_PER_SOURCE_WINDOW {
            register_from_source(&service, "same-source")?;
        }
        assert!(matches!(
            register_from_source(&service, "same-source"),
            Err(error) if error.code == crate::OAuthErrorCode::TemporarilyUnavailable
        ));
        Ok(())
    }

    #[test]
    fn registration_limits_are_partitioned_but_globally_bounded() -> Result<(), OAuthError> {
        let service = service()?;
        for source_index in 0..4 {
            let source = format!("source-{source_index}");
            for _ in 0..REGISTRATIONS_PER_SOURCE_WINDOW {
                register_from_source(&service, &source)?;
            }
        }
        assert_eq!(
            REGISTRATIONS_PER_SOURCE_WINDOW * 4,
            REGISTRATIONS_GLOBAL_WINDOW
        );
        assert!(matches!(
            register_from_source(&service, "new-source"),
            Err(error) if error.code == crate::OAuthErrorCode::TemporarilyUnavailable
        ));
        Ok(())
    }

    #[test]
    fn dynamic_registration_is_rate_limited() -> Result<(), OAuthError> {
        let service = service()?;
        for _ in 0..REGISTRATIONS_PER_SOURCE_WINDOW {
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
            let store = SqliteOAuthStore::open_scoped(&database, "test-connector")
                .map_err(|error| map_store_server_error(&error))?;
            let service = service_with_store(Arc::new(store))?;
            for _ in 0..REGISTRATIONS_PER_SOURCE_WINDOW {
                register(&service)?;
            }
        }
        let store = SqliteOAuthStore::open_scoped(&database, "test-connector")
            .map_err(|error| map_store_server_error(&error))?;
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
    fn internal_store_failure_keeps_the_public_oauth_error_generic() {
        let error = map_store_server_error_for(
            "connector-a",
            "load_client",
            &StoreError::Corrupt("sensitive internal detail"),
        );
        assert_eq!(error.code, crate::OAuthErrorCode::ServerError);
        assert_eq!(error.description(), "The authorization service failed.");
        assert!(!error.to_string().contains("sensitive internal detail"));
    }

    #[test]
    fn rejects_non_https_public_issuer_and_non_loopback_http_redirect() {
        let invalid = OAuthServiceConfig {
            connector_id: "test-connector".to_owned(),
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
