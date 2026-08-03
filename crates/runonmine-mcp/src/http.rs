//! Loopback MCP HTTP transport, connector authentication, and session binding.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::{AUTHORIZATION, HOST, WWW_AUTHENTICATE};
use axum::http::uri::Authority;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router, routing::get};
use base64::Engine;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use runonmine_core::secrets::{
    SecretStore, default_secret_store, recover_pending_config_secret_transaction,
};
use runonmine_core::{
    AppConfig, AppPaths, ConnectorConfig, ConnectorKind, PolicyEngine, PolicyMode,
};
use runonmine_oauth::{
    GitHubApiOwnerVerifier, GitHubIdentity, GitHubIdentityObservationError, GitHubIdentityObserver,
    OAuthErrorCode, OAuthService, OAuthServiceConfig, ObservedGitHubOwnerVerifier, ScopeSet,
    SqliteOAuthStore, TokenHasher, oauth_router,
};
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex as AsyncMutex;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;

use super::{
    IdleSessionManager, REQUEST_ACCESS, REQUEST_RUNTIME, RequestAccess, RequestPrincipal,
    RunOnMineServer, Runtime, TOOL_CAPABILITIES,
    diagnostics::{self, DiagnosticCategory},
    managed_connectors::{
        ConnectorRuntimePhase, ConnectorRuntimeRegistry, ConnectorRuntimeStatus,
        ConnectorStartupFailure, ConnectorStartupStage, start_external_connectors,
    },
    oauth_scope_for_capability, required_secret,
};

const MCP_BODY_LIMIT: usize = 2 * 1_024 * 1_024;
const MCP_CONCURRENCY_LIMIT: usize = 64;

#[derive(serde::Serialize)]
struct ConnectorHealthResponse {
    status: &'static str,
    connectors: Vec<ConnectorRuntimeStatus>,
}

#[derive(Clone)]
struct LocalHttpConnector {
    runtime: Runtime,
    secret_name: String,
    secrets: Arc<dyn SecretStore>,
}

impl std::fmt::Debug for LocalHttpConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalHttpConnector")
            .field("connector_id", &self.runtime.0.connector_id)
            .field("secret_name", &self.secret_name)
            .field("secrets", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug)]
struct QuickHttpConnector {
    runtime: Runtime,
    paths: AppPaths,
}

#[derive(Clone)]
struct OAuthHttpConnector {
    runtime: Runtime,
    service: Arc<OAuthService>,
    public_host: String,
    resource_metadata: Url,
}

impl std::fmt::Debug for OAuthHttpConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OAuthHttpConnector")
            .field("connector_id", &self.runtime.0.connector_id)
            .field("public_host", &self.public_host)
            .field("resource_metadata", &self.resource_metadata)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct OAuthOwnerLoginObserver {
    config_path: PathBuf,
    connector_id: String,
    expected_owner_id: u64,
}

impl GitHubIdentityObserver for OAuthOwnerLoginObserver {
    fn observe(&self, identity: &GitHubIdentity) -> Result<(), GitHubIdentityObservationError> {
        if identity.id != self.expected_owner_id {
            tracing::error!(
                connector_id = %self.connector_id,
                expected_owner_id = self.expected_owner_id,
                observed_owner_id = identity.id,
                "refused OAuth owner display-login reconciliation after numeric identity mismatch"
            );
            return Err(GitHubIdentityObservationError::new());
        }
        let result = AppConfig::update(&self.config_path, |config| {
            config.reconcile_oauth_owner_display_login(
                &self.connector_id,
                self.expected_owner_id,
                identity.id,
                &identity.login,
            )
        });
        match result {
            Ok(true) => {
                tracing::info!(
                    connector_id = %self.connector_id,
                    owner_id = identity.id,
                    "updated OAuth owner display login after verified GitHub rename"
                );
                Ok(())
            }
            Ok(false) => Ok(()),
            Err(_) => {
                diagnostics::log_internal(
                    diagnostics::current_request_id(),
                    &self.connector_id,
                    DiagnosticCategory::ConnectorConfig,
                    "reconcile_oauth_owner_display_login",
                    None,
                    None,
                );
                Err(GitHubIdentityObservationError::new())
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionBinding {
    access: RequestAccess,
    last_seen: Instant,
}

#[derive(Clone, Debug)]
struct HttpConnectorState {
    local: Option<LocalHttpConnector>,
    quick: Option<QuickHttpConnector>,
    oauth: Option<OAuthHttpConnector>,
    agent_port: u16,
    session_idle_ttl: Duration,
    sessions: Arc<AsyncMutex<HashMap<String, SessionBinding>>>,
}

#[derive(Debug)]
struct HttpConnectorBuild {
    state: HttpConnectorState,
    degraded: Vec<ConnectorStartupFailure>,
}

pub async fn serve_loopback() -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    super::reconcile_browser_orphans(&paths).await?;
    let reconciled = super::connector_removal::reconcile_pending_connector_removals(&paths)?;
    if reconciled > 0 {
        tracing::info!(reconciled, "completed pending connector removals");
    }
    let startup_secrets = default_secret_store(&paths)?;
    recover_pending_config_secret_transaction(&paths.config_file(), startup_secrets.as_ref())?;
    let config = AppConfig::load(&paths.config_file()).context("run `runonmine setup` first")?;
    super::reconcile_orphan_connector_artifacts(&paths, &config)?;
    let HttpConnectorBuild { state, degraded } = build_http_connector_state(&paths, &config);
    let connector_runtime = ConnectorRuntimeRegistry::from_failures(&degraded);
    let connector_state = Arc::new(state);
    let mut allowed_hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
        format!("localhost:{}", config.port),
        format!("127.0.0.1:{}", config.port),
        format!("[::1]:{}", config.port),
    ];
    let mut allowed_origins = Vec::new();
    if let Some(oauth) = &connector_state.oauth {
        allowed_hosts.push(oauth.public_host.clone());
        allowed_hosts.push(format!("{}:443", oauth.public_host));
        allowed_origins.push(format!("https://{}", oauth.public_host));
    }
    let session_manager = Arc::new(IdleSessionManager::new(connector_state.session_idle_ttl));
    let session_sweeper = spawn_session_sweeper(
        Arc::downgrade(&session_manager),
        Arc::downgrade(&connector_state),
        connector_state.session_idle_ttl,
    );
    let service = StreamableHttpService::new(
        || {
            REQUEST_RUNTIME
                .try_with(|runtime| RunOnMineServer::new(runtime.clone()))
                .map_err(|_| std::io::Error::other("MCP request connector context is missing"))?
                .map_err(|_| std::io::Error::other("MCP session initialization failed"))
        },
        session_manager,
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(allowed_hosts)
            .with_allowed_origins(allowed_origins),
    );
    let mcp_router = Router::new()
        .route_service("/mcp", service.clone())
        .route_service("/{secret}/mcp", service)
        .layer(DefaultBodyLimit::max(MCP_BODY_LIMIT))
        .layer(RequestBodyLimitLayer::new(MCP_BODY_LIMIT))
        .layer(ConcurrencyLimitLayer::new(MCP_CONCURRENCY_LIMIT))
        .layer(from_fn_with_state(
            Arc::clone(&connector_state),
            http_connector_auth,
        ));
    let health_runtime = connector_runtime.clone();
    let health_port = config.port;
    let mut router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route(
            "/healthz/connectors",
            get(move |request: Request| {
                let runtime = health_runtime.clone();
                async move { connector_health_response(&runtime, &request, health_port) }
            }),
        )
        .merge(mcp_router);
    if let Some(oauth) = &connector_state.oauth {
        let oauth_routes = oauth_router(Arc::clone(&oauth.service)).layer(from_fn_with_state(
            oauth.public_host.clone(),
            public_oauth_host_guard,
        ));
        router = router.merge(oauth_routes);
    }
    let address = format!("{}:{}", config.bind_host, config.port);
    let listener = tokio::net::TcpListener::bind(&address).await?;
    let runtime_marker = runonmine_platform::agent_status::AgentRuntimeMarker::publish()
        .context("failed to publish the running agent version handshake")?;
    tracing::debug!(
        instance_id = %runtime_marker.status().instance_id,
        "published running agent version handshake"
    );
    let managed_connectors =
        start_external_connectors(&paths, &config, degraded, connector_runtime).await?;
    managed_connectors.log_startup_summary();
    tracing::info!(%address, "RunOnMine agent listening on loopback");
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    session_sweeper.abort();
    let _ignored = session_sweeper.await;
    managed_connectors.stop().await;
    drop(runtime_marker);
    result.map_err(Into::into)
}

fn connector_health_response(
    runtime: &ConnectorRuntimeRegistry,
    request: &Request,
    agent_port: u16,
) -> Response {
    if !is_direct_loopback_health_request(request, agent_port) {
        return StatusCode::NOT_FOUND.into_response();
    }
    connector_health_payload(runtime).into_response()
}

fn connector_health_payload(runtime: &ConnectorRuntimeRegistry) -> Json<ConnectorHealthResponse> {
    let connectors = runtime.snapshot();
    let status = if connectors.iter().any(|connector| {
        matches!(
            connector.phase,
            ConnectorRuntimePhase::Degraded | ConnectorRuntimePhase::Backoff
        )
    }) {
        "degraded"
    } else if connectors
        .iter()
        .any(|connector| connector.phase == ConnectorRuntimePhase::Starting)
    {
        "starting"
    } else {
        "ok"
    };
    Json(ConnectorHealthResponse { status, connectors })
}

fn is_direct_loopback_health_request(request: &Request, agent_port: u16) -> bool {
    if [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "cf-connecting-ip",
        "cf-ray",
    ]
    .iter()
    .any(|header| request.headers().contains_key(*header))
    {
        return false;
    }
    let Ok(authority) = request_authority(request) else {
        return false;
    };
    let host = authority.host();
    let host = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    is_loopback_host(host) && authority.port_u16() == Some(agent_port)
}

fn spawn_session_sweeper(
    manager: std::sync::Weak<IdleSessionManager>,
    state: std::sync::Weak<HttpConnectorState>,
    idle_ttl: Duration,
) -> tokio::task::JoinHandle<()> {
    let half_ttl = idle_ttl / 2;
    let interval = half_ttl.clamp(Duration::from_secs(5), Duration::from_mins(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let (Some(manager), Some(state)) = (manager.upgrade(), state.upgrade()) else {
                return;
            };
            let closed = manager.close_expired().await;
            let mut bindings = state.sessions.lock().await;
            let before = bindings.len();
            bindings.retain(|_, binding| binding.last_seen.elapsed() < idle_ttl);
            let removed_bindings = before.saturating_sub(bindings.len());
            if closed > 0 || removed_bindings > 0 {
                tracing::debug!(
                    closed,
                    removed_bindings,
                    "expired MCP sessions were cleaned up"
                );
            }
        }
    })
}

fn build_http_connector_state(paths: &AppPaths, config: &AppConfig) -> HttpConnectorBuild {
    match default_secret_store(paths) {
        Ok(secrets) => {
            let secrets: Arc<dyn SecretStore> = Arc::from(secrets);
            build_http_connector_state_with_store(paths, config, &secrets)
        }
        Err(_) => HttpConnectorBuild {
            state: empty_http_connector_state(config),
            degraded: config
                .connectors
                .iter()
                .filter(|connector| connector.enabled)
                .filter(|connector| {
                    matches!(
                        connector.kind,
                        ConnectorKind::LocalHttp
                            | ConnectorKind::CloudflareQuick
                            | ConnectorKind::CloudflareOauth
                    )
                })
                .map(|connector| {
                    ConnectorStartupFailure::new(
                        &connector.id,
                        connector.kind,
                        ConnectorStartupStage::Authentication,
                    )
                })
                .collect(),
        },
    }
}

fn build_http_connector_state_with_store(
    paths: &AppPaths,
    config: &AppConfig,
    secrets: &Arc<dyn SecretStore>,
) -> HttpConnectorBuild {
    let mut state = empty_http_connector_state(config);
    let mut degraded = Vec::new();
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        let prepared = match connector.kind {
            ConnectorKind::LocalHttp => {
                build_local_http_connector(paths, connector, Arc::clone(secrets))
                    .map(|value| state.local = Some(value))
            }
            ConnectorKind::CloudflareQuick => {
                build_quick_http_connector(paths, connector, secrets.as_ref())
                    .map(|value| state.quick = Some(value))
            }
            ConnectorKind::CloudflareOauth => {
                build_oauth_connector(paths, connector, secrets.as_ref())
                    .map(|value| state.oauth = Some(value))
            }
            ConnectorKind::LocalStdio | ConnectorKind::OpenAiTunnel => Ok(()),
        };
        if prepared.is_err() {
            degraded.push(ConnectorStartupFailure::new(
                &connector.id,
                connector.kind,
                ConnectorStartupStage::Authentication,
            ));
        }
    }
    HttpConnectorBuild { state, degraded }
}

fn empty_http_connector_state(config: &AppConfig) -> HttpConnectorState {
    HttpConnectorState {
        local: None,
        quick: None,
        oauth: None,
        agent_port: config.port,
        session_idle_ttl: Duration::from_secs(
            config.limits.session_idle_minutes.saturating_mul(60),
        ),
        sessions: Arc::new(AsyncMutex::new(HashMap::new())),
    }
}

fn build_local_http_connector(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    secrets: Arc<dyn SecretStore>,
) -> Result<LocalHttpConnector> {
    let secret_name = format!("connector.{}.local_http_token", connector.id);
    let token = required_secret(secrets.as_ref(), &secret_name)?;
    validate_local_http_token(token.expose_secret())?;
    Ok(LocalHttpConnector {
        runtime: Runtime::load_from_paths(paths, &connector.id)?,
        secret_name,
        secrets,
    })
}

fn build_quick_http_connector(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    secrets: &dyn SecretStore,
) -> Result<QuickHttpConnector> {
    let path_secret = required_secret(secrets, &format!("connector.{}.path_secret", connector.id))?;
    validate_quick_path_secret(path_secret.expose_secret())?;
    Ok(QuickHttpConnector {
        runtime: Runtime::load_from_paths(paths, &connector.id)?,
        paths: paths.clone(),
    })
}

fn build_oauth_connector(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    secrets: &dyn SecretStore,
) -> Result<OAuthHttpConnector> {
    let public_base = connector
        .public_base_url
        .clone()
        .context("OAuth connector public base URL is missing")?;
    let public_host = public_base
        .host_str()
        .context("OAuth connector public hostname is missing")?
        .to_ascii_lowercase();
    let owner = connector
        .oauth_owner
        .as_ref()
        .context("OAuth connector owner is missing")?;
    let client_id = required_secret(
        secrets,
        &format!("connector.{}.github_client_id", connector.id),
    )?;
    let client_secret = required_secret(
        secrets,
        &format!("connector.{}.github_client_secret", connector.id),
    )?;
    let hash_key = required_secret(
        secrets,
        &format!("connector.{}.oauth_hash_key", connector.id),
    )?;
    let registration_access_token = required_secret(
        secrets,
        &format!("connector.{}.oauth_registration_token", connector.id),
    )?;
    validate_256_bit_url_secret(
        registration_access_token.expose_secret(),
        "OAuth registration access token",
    )?;
    let decoded_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(hash_key.expose_secret())
        .context("OAuth hash key is invalid")?;
    let hash_key: [u8; 32] = decoded_key
        .try_into()
        .map_err(|_| anyhow::anyhow!("OAuth hash key has an invalid length"))?;
    let protected_resource = public_base
        .join("mcp")
        .context("OAuth protected resource URL is invalid")?;
    let github_callback_url = public_base
        .join("oauth/github/callback")
        .context("OAuth GitHub callback URL is invalid")?;
    let verifier = GitHubApiOwnerVerifier::new(
        client_id.expose_secret().to_owned(),
        client_secret,
        owner.github_id,
    )?;
    let verifier = ObservedGitHubOwnerVerifier::new(
        Arc::new(verifier),
        Arc::new(OAuthOwnerLoginObserver {
            config_path: paths.config_file(),
            connector_id: connector.id.clone(),
            expected_owner_id: owner.github_id,
        }),
    );
    let service = OAuthService::new(
        OAuthServiceConfig {
            connector_id: connector.id.clone(),
            issuer: public_base.clone(),
            protected_resource,
            github_client_id: client_id.expose_secret().to_owned(),
            github_callback_url,
        },
        Arc::new(SqliteOAuthStore::open_scoped(
            &paths.state_db(),
            &connector.id,
        )?),
        TokenHasher::new(hash_key)?,
        &registration_access_token,
        Arc::new(verifier),
    )?;
    let resource_metadata = public_base
        .join(".well-known/oauth-protected-resource")
        .context("OAuth protected resource metadata URL is invalid")?;
    Ok(OAuthHttpConnector {
        runtime: Runtime::load_from_paths(paths, &connector.id)?,
        service: Arc::new(service),
        public_host,
        resource_metadata,
    })
}

fn validate_local_http_token(value: &str) -> Result<()> {
    validate_256_bit_url_secret(value, "Local HTTP bearer token")
}

fn validate_quick_path_secret(value: &str) -> Result<()> {
    validate_256_bit_url_secret(value, "Quick Tunnel path secret")
}

fn validate_256_bit_url_secret(value: &str, label: &str) -> Result<()> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{label} is invalid"))?;
    if decoded.len() != 32 {
        bail!("{label} must contain 256 bits");
    }
    Ok(())
}

async fn http_connector_auth(
    State(state): State<Arc<HttpConnectorState>>,
    request: Request,
    next: Next,
) -> Response {
    diagnostics::scope_request(http_connector_auth_inner(state, request, next)).await
}

async fn http_connector_auth_inner(
    state: Arc<HttpConnectorState>,
    mut request: Request,
    next: Next,
) -> Response {
    let (runtime, access) = match select_http_connector(&state, &request) {
        Ok(selected) => selected,
        Err(response) => return response,
    };
    let request_session = match session_id(request.headers()) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if let Some(session_id) = &request_session {
        let mut sessions = state.sessions.lock().await;
        if !authorize_session_binding(
            &mut sessions,
            session_id,
            &access,
            state.session_idle_ttl,
            Instant::now(),
        ) {
            return StatusCode::NOT_FOUND.into_response();
        }
    }
    request.extensions_mut().insert(access.clone());
    let method = request.method().clone();
    let response = REQUEST_RUNTIME
        .scope(
            runtime,
            REQUEST_ACCESS.scope(access.clone(), next.run(request)),
        )
        .await;
    if let Some(response_session) = response_session_id(response.headers()) {
        let mut sessions = state.sessions.lock().await;
        bind_session(
            &mut sessions,
            response_session,
            access.clone(),
            Instant::now(),
        );
    }
    if method == Method::DELETE
        && let Some(session_id) = request_session
    {
        let mut sessions = state.sessions.lock().await;
        remove_session_binding(&mut sessions, &session_id);
    }
    response
}

#[allow(clippy::result_large_err)]
fn select_http_connector(
    state: &HttpConnectorState,
    request: &Request,
) -> Result<(Runtime, RequestAccess), Response> {
    let path = request.uri().path();
    if path != "/mcp" {
        return select_quick_connector(state, path);
    }
    let authority = request_authority(request)?;
    if let Some(oauth) = &state.oauth
        && matches_public_https_authority(&authority, &oauth.public_host)
    {
        return select_oauth_connector(oauth, request);
    }
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if is_loopback_host(&host)
        && authority
            .port_u16()
            .is_none_or(|port| port == state.agent_port)
        && let Some(local) = &state.local
    {
        return select_local_connector(local, request);
    }
    Err(StatusCode::NOT_FOUND.into_response())
}

#[allow(clippy::result_large_err)]
fn select_quick_connector(
    state: &HttpConnectorState,
    path: &str,
) -> Result<(Runtime, RequestAccess), Response> {
    let Some(supplied) = path
        .strip_prefix('/')
        .and_then(|value| value.strip_suffix("/mcp"))
        .filter(|value| !value.is_empty() && !value.contains('/'))
    else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let Some(quick) = &state.quick else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let Some(expected_secret) = quick_path_secret(quick) else {
        return Err(StatusCode::NOT_FOUND.into_response());
    };
    let expected = expected_secret.expose_secret().as_bytes();
    let matches =
        supplied.len() == expected.len() && bool::from(supplied.as_bytes().ct_eq(expected));
    if !matches {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((
        quick.runtime.clone(),
        RequestAccess {
            connector_id: quick.runtime.0.connector_id.clone(),
            principal: RequestPrincipal::QuickTunnel,
        },
    ))
}

fn quick_path_secret(quick: &QuickHttpConnector) -> Option<secrecy::SecretString> {
    let secret_key = format!("connector.{}.path_secret", quick.runtime.0.connector_id);
    let Ok(store) = default_secret_store(&quick.paths) else {
        diagnostics::log_internal(
            diagnostics::current_request_id(),
            &quick.runtime.0.connector_id,
            DiagnosticCategory::Storage,
            "open_quick_secret_store",
            None,
            None,
        );
        return None;
    };
    let Ok(secret) = store.get(&secret_key) else {
        diagnostics::log_internal(
            diagnostics::current_request_id(),
            &quick.runtime.0.connector_id,
            DiagnosticCategory::Storage,
            "read_quick_path_secret",
            None,
            None,
        );
        return None;
    };
    secret
}

#[allow(clippy::result_large_err)]
fn select_oauth_connector(
    oauth: &OAuthHttpConnector,
    request: &Request,
) -> Result<(Runtime, RequestAccess), Response> {
    let raw_token = bearer_token(request, &oauth.resource_metadata)?;
    let connector = oauth.runtime.connector().map_err(|_| {
        diagnostics::log_internal(
            diagnostics::current_request_id(),
            &oauth.runtime.0.connector_id,
            DiagnosticCategory::ConnectorConfig,
            "load_oauth_connector_policy",
            None,
            None,
        );
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    })?;
    let policy_scopes = oauth_policy_scopes(&connector);
    let grant = oauth
        .service
        .authenticate_access_token(raw_token, &policy_scopes)
        .map_err(|error| {
            if matches!(
                error.code,
                OAuthErrorCode::ServerError | OAuthErrorCode::TemporarilyUnavailable
            ) {
                diagnostics::log_internal(
                    diagnostics::current_request_id(),
                    &oauth.runtime.0.connector_id,
                    DiagnosticCategory::Authorization,
                    "authenticate_oauth_access_token",
                    None,
                    None,
                );
            }
            unauthorized(&oauth.resource_metadata)
        })?;
    Ok((
        oauth.runtime.clone(),
        RequestAccess {
            connector_id: oauth.runtime.0.connector_id.clone(),
            principal: RequestPrincipal::OAuth {
                client_id: grant.client_id,
                subject: grant.subject,
                scopes: grant.scopes,
            },
        },
    ))
}

#[allow(clippy::result_large_err)]
fn select_local_connector(
    local: &LocalHttpConnector,
    request: &Request,
) -> Result<(Runtime, RequestAccess), Response> {
    let supplied = local_bearer_token(request)?;
    let Some(current_token) = current_local_http_token(local) else {
        return Err(local_unauthorized());
    };
    let expected = current_token.expose_secret().as_bytes();
    let matches =
        supplied.len() == expected.len() && bool::from(supplied.as_bytes().ct_eq(expected));
    if !matches {
        return Err(local_unauthorized());
    }
    Ok((
        local.runtime.clone(),
        RequestAccess {
            connector_id: local.runtime.0.connector_id.clone(),
            principal: RequestPrincipal::LocalHttp,
        },
    ))
}

fn current_local_http_token(local: &LocalHttpConnector) -> Option<secrecy::SecretString> {
    let Ok(Some(token)) = local.secrets.get(&local.secret_name) else {
        diagnostics::log_internal(
            diagnostics::current_request_id(),
            &local.runtime.0.connector_id,
            DiagnosticCategory::Storage,
            "read_local_http_token",
            None,
            None,
        );
        return None;
    };
    if validate_local_http_token(token.expose_secret()).is_err() {
        diagnostics::log_internal(
            diagnostics::current_request_id(),
            &local.runtime.0.connector_id,
            DiagnosticCategory::Authorization,
            "validate_local_http_token",
            None,
            None,
        );
        return None;
    }
    Some(token)
}

#[allow(clippy::result_large_err)]
fn request_authority(request: &Request) -> Result<Authority, Response> {
    let value = request
        .headers()
        .get(HOST)
        .ok_or_else(|| StatusCode::BAD_REQUEST.into_response())?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    Authority::from_str(value).map_err(|_| StatusCode::BAD_REQUEST.into_response())
}

fn matches_public_https_authority(authority: &Authority, expected_host: &str) -> bool {
    authority.host().eq_ignore_ascii_case(expected_host)
        && authority.port_u16().is_none_or(|port| port == 443)
}

fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[allow(clippy::result_large_err)]
fn local_bearer_token(request: &Request) -> Result<&str, Response> {
    parse_bearer_token(request).map_err(|()| local_unauthorized())
}

fn local_unauthorized() -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

#[allow(clippy::result_large_err)]
fn bearer_token<'a>(request: &'a Request, resource_metadata: &Url) -> Result<&'a str, Response> {
    parse_bearer_token(request).map_err(|()| unauthorized(resource_metadata))
}

fn parse_bearer_token(request: &Request) -> Result<&str, ()> {
    let value = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(())?
        .to_str()
        .map_err(|_| ())?;
    let token = value.strip_prefix("Bearer ").ok_or(())?;
    if token.is_empty() || token.contains(char::is_whitespace) {
        return Err(());
    }
    Ok(token)
}

fn unauthorized(resource_metadata: &Url) -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    let value = format!("Bearer resource_metadata=\"{resource_metadata}\"");
    if let Ok(value) = HeaderValue::from_str(&value) {
        response.headers_mut().insert(WWW_AUTHENTICATE, value);
    }
    response
}

fn oauth_policy_scopes(connector: &ConnectorConfig) -> ScopeSet {
    TOOL_CAPABILITIES
        .iter()
        .filter(|(tool_name, capability)| {
            PolicyEngine
                .evaluate(connector, tool_name, *capability)
                .mode
                != PolicyMode::Deny
        })
        .map(|(_, capability)| oauth_scope_for_capability(*capability))
        .collect()
}

fn valid_session_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == 45 || byte == 95)
}

fn prune_session_bindings(
    sessions: &mut HashMap<String, SessionBinding>,
    idle_ttl: Duration,
    now: Instant,
) {
    sessions.retain(|_, binding| now.saturating_duration_since(binding.last_seen) < idle_ttl);
}

fn authorize_session_binding(
    sessions: &mut HashMap<String, SessionBinding>,
    session_id: &str,
    access: &RequestAccess,
    idle_ttl: Duration,
    now: Instant,
) -> bool {
    prune_session_bindings(sessions, idle_ttl, now);
    let Some(binding) = sessions.get_mut(session_id) else {
        return false;
    };
    if binding.access != *access {
        return false;
    }
    binding.last_seen = now;
    true
}

fn bind_session(
    sessions: &mut HashMap<String, SessionBinding>,
    session_id: String,
    access: RequestAccess,
    now: Instant,
) {
    if valid_session_id(&session_id) {
        sessions.insert(
            session_id,
            SessionBinding {
                access,
                last_seen: now,
            },
        );
    }
}

fn remove_session_binding(
    sessions: &mut HashMap<String, SessionBinding>,
    session_id: &str,
) -> bool {
    sessions.remove(session_id).is_some()
}

#[allow(clippy::result_large_err)]
fn session_id(headers: &axum::http::HeaderMap) -> Result<Option<String>, Response> {
    headers
        .get("mcp-session-id")
        .map(|value| {
            let value = value
                .to_str()
                .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
            if !valid_session_id(value) {
                return Err(StatusCode::BAD_REQUEST.into_response());
            }
            Ok(value.to_owned())
        })
        .transpose()
}

fn response_session_id(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| valid_session_id(value))
        .map(str::to_owned)
}

pub(crate) fn exercise_fuzz_session_state(data: &[u8]) {
    let split = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    if let Ok(value) = std::str::from_utf8(&data[..split]) {
        let _accepted = valid_session_id(value);
    }

    let now = Instant::now();
    let ttl = Duration::from_millis(8);
    let local = RequestAccess {
        connector_id: "local-http".to_owned(),
        principal: RequestPrincipal::LocalHttp,
    };
    let quick = RequestAccess {
        connector_id: "quick-tunnel".to_owned(),
        principal: RequestPrincipal::QuickTunnel,
    };
    let mut sessions = HashMap::new();
    for (index, operation) in data[split..].iter().copied().enumerate() {
        let session_id = format!("session_{operation:02x}");
        let tick = Duration::from_millis(u64::try_from(index).unwrap_or(u64::MAX));
        let logical_now = now.checked_add(tick).unwrap_or(now);
        match operation % 6 {
            0 => bind_session(&mut sessions, session_id, local.clone(), logical_now),
            1 => {
                let _accepted =
                    authorize_session_binding(&mut sessions, &session_id, &local, ttl, logical_now);
            }
            2 => {
                let _accepted =
                    authorize_session_binding(&mut sessions, &session_id, &quick, ttl, logical_now);
            }
            3 => {
                let _removed = remove_session_binding(&mut sessions, &session_id);
            }
            4 => prune_session_bindings(&mut sessions, ttl, logical_now),
            _ => bind_session(
                &mut sessions,
                format!("invalid session {operation}"),
                quick.clone(),
                logical_now,
            ),
        }
        debug_assert!(sessions.keys().all(|id| valid_session_id(id)));
    }
}

async fn public_oauth_host_guard(
    State(expected_host): State<String>,
    request: Request,
    next: Next,
) -> Response {
    let allowed = request_authority(&request)
        .is_ok_and(|authority| matches_public_https_authority(&authority, &expected_host));
    if !allowed {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

async fn shutdown_signal() {
    let _result = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::*;
    use axum::body::Body;
    use runonmine_core::secrets::SecretStore;
    use runonmine_core::{
        Capability, CloudflareNamedSettings, CloudflareQuickSettings, OAuthOwnerSettings,
        PolicyPreset,
    };
    use runonmine_oauth::Scope;
    use secrecy::SecretString;

    #[derive(Default)]
    struct TestSecretStore {
        values: Mutex<BTreeMap<String, String>>,
    }

    impl SecretStore for TestSecretStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            Ok(self
                .values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret store lock failed"))?
                .get(name)
                .cloned()
                .map(SecretString::from))
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret store lock failed"))?
                .insert(name.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret store lock failed"))?
                .remove(name);
            Ok(())
        }
    }

    fn oauth_owner_test_config(paths: &AppPaths) -> Result<AppConfig> {
        let credentials = paths
            .config_file()
            .parent()
            .context("test config path has no parent")?
            .join("oauth-tunnel-credentials.json");
        std::fs::write(&credentials, b"{}")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&credentials, std::fs::Permissions::from_mode(0o600))?;
        }
        let mut config = AppConfig::default();
        config.connectors.push(ConnectorConfig {
            id: "oauth-owner-test".to_owned(),
            name: "OAuth owner test".to_owned(),
            kind: ConnectorKind::CloudflareOauth,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
            policy_rules: Vec::new(),
            public_base_url: Some(Url::parse("https://mcp.example.com/")?),
            cloudflare_quick: None,
            cloudflare_named: Some(CloudflareNamedSettings {
                tunnel_id: "01234567-89ab-cdef-0123-456789abcdef".to_owned(),
                credentials_file: credentials.canonicalize()?,
                hostname: "mcp.example.com".to_owned(),
                cloudflared_path: None,
                metrics_port: 47_824,
            }),
            oauth_owner: Some(OAuthOwnerSettings {
                github_login: "old-owner".to_owned(),
                github_id: 42,
            }),
            openai_tunnel: None,
        });
        Ok(config)
    }

    #[test]
    fn verified_owner_rename_updates_only_display_login_atomically() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        oauth_owner_test_config(&paths)?.save(&paths.config_file())?;
        let observer = OAuthOwnerLoginObserver {
            config_path: paths.config_file(),
            connector_id: "oauth-owner-test".to_owned(),
            expected_owner_id: 42,
        };

        observer
            .observe(&GitHubIdentity {
                id: 42,
                login: "renamed-owner".to_owned(),
            })
            .map_err(|_| anyhow::anyhow!("verified owner rename was rejected"))?;
        let config = AppConfig::load(&paths.config_file())?;
        let owner = config
            .connector("oauth-owner-test")
            .and_then(|connector| connector.oauth_owner.as_ref())
            .context("updated OAuth owner is missing")?;
        assert_eq!(owner.github_id, 42);
        assert_eq!(owner.github_login, "renamed-owner");
        Ok(())
    }

    #[test]
    fn owner_observer_rejects_numeric_id_mismatch_without_mutating_login() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        oauth_owner_test_config(&paths)?.save(&paths.config_file())?;
        let observer = OAuthOwnerLoginObserver {
            config_path: paths.config_file(),
            connector_id: "oauth-owner-test".to_owned(),
            expected_owner_id: 42,
        };

        assert!(
            observer
                .observe(&GitHubIdentity {
                    id: 7,
                    login: "old-owner".to_owned(),
                })
                .is_err()
        );
        let config = AppConfig::load(&paths.config_file())?;
        let owner = config
            .connector("oauth-owner-test")
            .and_then(|connector| connector.oauth_owner.as_ref())
            .context("OAuth owner is missing")?;
        assert_eq!(owner.github_id, 42);
        assert_eq!(owner.github_login, "old-owner");
        Ok(())
    }

    #[test]
    fn local_http_auth_reads_rotated_token_without_rebuilding_state() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let mut config = AppConfig {
            port: 47_821,
            ..AppConfig::default()
        };
        let local = config
            .connectors
            .iter_mut()
            .find(|connector| connector.kind == ConnectorKind::LocalHttp)
            .context("default local HTTP connector is missing")?;
        local.id = "rotating-local".to_owned();
        local.enabled = true;
        config.validate()?;
        config.save(&paths.config_file())?;

        let store = Arc::new(TestSecretStore::default());
        let old_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([21_u8; 32]);
        let new_token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([22_u8; 32]);
        let secret_name = "connector.rotating-local.local_http_token";
        store.set(secret_name, &SecretString::from(old_token.clone()))?;
        let shared: Arc<dyn SecretStore> = store.clone();
        let state = build_http_connector_state_with_store(&paths, &config, &shared).state;

        let request = |token: &str| {
            Request::builder()
                .uri("http://127.0.0.1:47821/mcp")
                .header(HOST, "127.0.0.1:47821")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())
        };
        assert!(select_http_connector(&state, &request(&old_token)?).is_ok());
        store.set(secret_name, &SecretString::from(new_token.clone()))?;
        assert!(select_http_connector(&state, &request(&old_token)?).is_err());
        assert!(select_http_connector(&state, &request(&new_token)?).is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn quick_auth_failure_does_not_disable_healthy_local_http() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let mut config = AppConfig::default();
        let local = config
            .connectors
            .iter_mut()
            .find(|connector| connector.kind == ConnectorKind::LocalHttp)
            .context("default local HTTP connector is missing")?;
        local.id = "healthy-local".to_owned();
        local.enabled = true;

        let mut quick = ConnectorConfig::local_default();
        quick.id = "missing-quick-secret".to_owned();
        quick.name = "Missing Quick secret".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.cloudflare_quick = Some(CloudflareQuickSettings::default());
        config.connectors.push(quick);
        config.validate()?;
        config.save(&paths.config_file())?;

        let store = Arc::new(TestSecretStore::default());
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11_u8; 32]);
        store.set(
            "connector.healthy-local.local_http_token",
            &SecretString::from(token),
        )?;

        let shared: Arc<dyn SecretStore> = store.clone();
        let build = build_http_connector_state_with_store(&paths, &config, &shared);
        assert!(build.state.local.is_some());
        assert!(build.state.quick.is_none());
        assert!(build.state.oauth.is_none());
        assert_eq!(build.degraded.len(), 1);
        assert_eq!(build.degraded[0].connector_id, "missing-quick-secret");
        assert_eq!(build.degraded[0].kind, ConnectorKind::CloudflareQuick);
        assert_eq!(
            build.degraded[0].stage,
            ConnectorStartupStage::Authentication
        );
        assert_eq!(
            build.degraded[0].message,
            "connector authentication could not be prepared"
        );

        let runtime = ConnectorRuntimeRegistry::from_failures(&build.degraded);
        let managed =
            start_external_connectors(&paths, &config, build.degraded, runtime.clone()).await?;
        assert_eq!(managed.running_count(), 0);
        assert_eq!(managed.degraded_failures().len(), 1);
        assert_eq!(runtime.snapshot()[0].phase, ConnectorRuntimePhase::Degraded);
        assert_eq!(
            managed.degraded_failures()[0].connector_id,
            "missing-quick-secret"
        );
        managed.stop().await;
        Ok(())
    }

    #[test]
    fn connector_health_response_prioritizes_degraded_then_starting() {
        let runtime = ConnectorRuntimeRegistry::default();
        runtime.set_ready("ready", ConnectorKind::CloudflareQuick);
        runtime.set_starting(
            "starting",
            ConnectorKind::OpenAiTunnel,
            ConnectorStartupStage::Preparation,
        );
        let response = connector_health_payload(&runtime);
        assert_eq!(response.0.status, "starting");
        assert_eq!(response.0.connectors.len(), 2);
        runtime.set_backoff(
            "backoff",
            ConnectorKind::OpenAiTunnel,
            ConnectorStartupStage::Readiness,
        );
        assert_eq!(connector_health_payload(&runtime).0.status, "degraded");
        runtime.set_degraded(ConnectorStartupFailure::new(
            "failed",
            ConnectorKind::CloudflareOauth,
            ConnectorStartupStage::Process,
        ));
        let response = connector_health_payload(&runtime);
        assert_eq!(response.0.status, "degraded");
        assert_eq!(response.0.connectors.len(), 4);
    }

    #[test]
    fn bearer_parser_requires_exact_bearer_syntax() -> Result<()> {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer secret-token")
            .body(axum::body::Body::empty())?;
        assert_eq!(parse_bearer_token(&request), Ok("secret-token"));

        let malformed = Request::builder()
            .header(AUTHORIZATION, "bearer secret-token")
            .body(axum::body::Body::empty())?;
        assert!(parse_bearer_token(&malformed).is_err());
        Ok(())
    }

    #[test]
    fn local_http_token_requires_256_bits() {
        let valid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7_u8; 32]);
        assert!(validate_local_http_token(&valid).is_ok());
        assert!(validate_local_http_token("too-short").is_err());
    }

    #[test]
    fn bearer_parser_rejects_empty_or_whitespace_tokens() -> Result<()> {
        for value in [
            "Bearer ",
            "Bearer two tokens",
            "Bearer token\tmore",
            "Basic token",
        ] {
            let request = Request::builder()
                .header(AUTHORIZATION, value)
                .body(Body::empty())?;
            assert!(parse_bearer_token(&request).is_err(), "accepted {value:?}");
        }
        Ok(())
    }

    #[test]
    fn connector_health_details_require_a_direct_loopback_host() -> Result<()> {
        let runtime = ConnectorRuntimeRegistry::default();
        runtime.set_ready("ready", ConnectorKind::CloudflareQuick);
        for host in ["127.0.0.1:47821", "localhost:47821", "[::1]:47821"] {
            let request = Request::builder().header(HOST, host).body(Body::empty())?;
            assert_eq!(
                connector_health_response(&runtime, &request, 47_821).status(),
                StatusCode::OK
            );
        }
        for host in ["mcp.example.com", "127.0.0.1:47822", "localhost"] {
            let request = Request::builder().header(HOST, host).body(Body::empty())?;
            assert_eq!(
                connector_health_response(&runtime, &request, 47_821).status(),
                StatusCode::NOT_FOUND
            );
        }
        let proxied = Request::builder()
            .header(HOST, "127.0.0.1:47821")
            .header("cf-connecting-ip", "203.0.113.1")
            .body(Body::empty())?;
        assert_eq!(
            connector_health_response(&runtime, &proxied, 47_821).status(),
            StatusCode::NOT_FOUND
        );
        Ok(())
    }

    #[test]
    fn session_binding_state_machine_is_access_bound_expiring_and_deletable() {
        let started = Instant::now();
        let ttl = Duration::from_secs(10);
        let local = RequestAccess {
            connector_id: "local-http".to_owned(),
            principal: RequestPrincipal::LocalHttp,
        };
        let quick = RequestAccess {
            connector_id: "quick-tunnel".to_owned(),
            principal: RequestPrincipal::QuickTunnel,
        };
        let mut sessions = HashMap::new();

        bind_session(
            &mut sessions,
            "safe_ID-123".to_owned(),
            local.clone(),
            started,
        );
        bind_session(
            &mut sessions,
            "unsafe session".to_owned(),
            quick.clone(),
            started,
        );
        assert_eq!(sessions.len(), 1);
        assert!(authorize_session_binding(
            &mut sessions,
            "safe_ID-123",
            &local,
            ttl,
            started + Duration::from_secs(1),
        ));
        assert!(!authorize_session_binding(
            &mut sessions,
            "safe_ID-123",
            &quick,
            ttl,
            started + Duration::from_secs(2),
        ));
        assert!(!authorize_session_binding(
            &mut sessions,
            "safe_ID-123",
            &local,
            ttl,
            started + Duration::from_secs(11),
        ));
        assert!(sessions.is_empty());

        bind_session(&mut sessions, "delete_me".to_owned(), local, started);
        assert!(remove_session_binding(&mut sessions, "delete_me"));
        assert!(!remove_session_binding(&mut sessions, "delete_me"));
    }

    #[test]
    fn request_authority_requires_a_valid_host_header() -> Result<()> {
        let missing = Request::builder().body(Body::empty())?;
        assert!(request_authority(&missing).is_err());

        let malformed = Request::builder()
            .header(HOST, "bad host value")
            .body(Body::empty())?;
        assert!(request_authority(&malformed).is_err());

        let ipv6 = Request::builder()
            .header(HOST, "[::1]:47821")
            .body(Body::empty())?;
        let authority =
            request_authority(&ipv6).map_err(|_| anyhow::anyhow!("valid host rejected"))?;
        assert_eq!(authority.host(), "[::1]");
        assert_eq!(authority.port_u16(), Some(47_821));
        Ok(())
    }

    #[test]
    fn loopback_host_matching_is_strict() {
        for value in ["localhost", "LOCALHOST", "127.0.0.1", "::1"] {
            assert!(is_loopback_host(value), "rejected {value}");
        }
        for value in ["localhost.example", "0.0.0.0", "192.168.1.1", "example.com"] {
            assert!(!is_loopback_host(value), "accepted {value}");
        }
    }

    #[test]
    fn public_oauth_authority_requires_https_default_port() -> Result<()> {
        for value in ["mcp.example.com", "MCP.EXAMPLE.COM:443"] {
            let authority = Authority::from_str(value)?;
            assert!(matches_public_https_authority(
                &authority,
                "mcp.example.com"
            ));
        }
        for value in [
            "mcp.example.com:80",
            "mcp.example.com:444",
            "other.example.com",
        ] {
            let authority = Authority::from_str(value)?;
            assert!(!matches_public_https_authority(
                &authority,
                "mcp.example.com"
            ));
        }
        Ok(())
    }

    #[test]
    fn session_id_accepts_only_bounded_safe_identifiers() -> Result<()> {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("mcp-session-id", HeaderValue::from_static("safe_ID-123"));
        assert_eq!(
            session_id(&headers).ok().flatten().as_deref(),
            Some("safe_ID-123")
        );

        for value in ["", "has space", "slash/value", "semi;colon"] {
            let Ok(value) = HeaderValue::from_str(value) else {
                continue;
            };
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("mcp-session-id", value);
            assert!(session_id(&headers).is_err());
        }

        let mut oversized = axum::http::HeaderMap::new();
        let oversized_value = HeaderValue::from_str(&"a".repeat(129))?;
        oversized.insert("mcp-session-id", oversized_value);
        assert!(session_id(&oversized).is_err());
        Ok(())
    }

    #[test]
    fn oauth_capabilities_map_to_expected_scopes() {
        let cases = [
            (Capability::SystemRead, Scope::MachineRead),
            (Capability::FilesRead, Scope::FilesRead),
            (Capability::FilesWrite, Scope::FilesWrite),
            (Capability::ShellExec, Scope::ShellExec),
            (Capability::PlatformNative, Scope::PlatformNative),
            (Capability::BrowserRead, Scope::BrowserRead),
            (Capability::BrowserAct, Scope::BrowserAct),
            (Capability::DesktopControl, Scope::DesktopControl),
            (Capability::AdminExec, Scope::AdminExec),
        ];
        for (capability, expected) in cases {
            assert_eq!(oauth_scope_for_capability(capability), expected);
        }
        assert_ne!(
            oauth_scope_for_capability(Capability::ShellExec),
            oauth_scope_for_capability(Capability::PlatformNative)
        );
    }
}
