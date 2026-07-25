//! Policy-aware MCP server and local transports.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::{AUTHORIZATION, HOST, WWW_AUTHENTICATE};
use axum::http::uri::Authority;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::{IntoResponse, Response};
use axum::{Router, routing::get};
use base64::Engine;
use chrono::Utc;
use futures::Stream;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams,
};
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService,
    session::{
        RestoreOutcome, ServerSseMessage, SessionId, SessionManager,
        local::{LocalSessionManager, LocalSessionManagerError},
    },
};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{ClientJsonRpcMessage, ServerJsonRpcMessage},
    tool, tool_handler, tool_router,
};
use runonmine_browser::{BrowserProfile, BrowserSession, chromium_available};
use runonmine_connectors::cloudflare::{
    NamedTunnelConfig, QuickTunnelConfig, parse_quick_tunnel_url,
};
use runonmine_connectors::openai::{OpenAiMcpTarget, OpenAiTunnelProfile};
use runonmine_connectors::{
    BinaryDiscovery, BinaryKind, ProcessEvent, ProcessSupervisor, RestartPolicy, SecretValue,
    SupervisorHandle, run_once,
};
use runonmine_core::filesystem::ScopedFilesystem;
use runonmine_core::process::{ProcessRequest, execute_shell};
use runonmine_core::secrets::{SecretStore, default_secret_store};
use runonmine_core::{
    AppConfig, AppPaths, ApprovalRequest, ApprovalStatus, AuditEvent, AuditOutcome,
    BrowserProfileMode, Capability, ConnectorConfig, ConnectorKind, PolicyContext, PolicyEngine,
    PolicyMode, PrincipalContext, StateStore,
};
use runonmine_oauth::{
    GitHubApiOwnerVerifier, OAuthService, OAuthServiceConfig, Scope, ScopeSet, SqliteOAuthStore,
    TokenHasher, oauth_router,
};
use runonmine_platform::desktop::{self, ScreenshotTarget};
use runonmine_platform::helper::{
    HelperClient, HelperRequest, HelperResult, MAX_TIMEOUT as MAX_ADMIN_TIMEOUT,
};
use runonmine_platform::native::{self, DbusCall};
use secrecy::ExposeSecret;
use serde::Serialize;
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex as AsyncMutex;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;

pub const SERVER_NAME: &str = "runonmine";
const MCP_BODY_LIMIT: usize = 2 * 1_024 * 1_024;
const MCP_CONCURRENCY_LIMIT: usize = 64;
const MAX_COMMAND_BYTES: usize = 256 * 1_024;
const MAX_SCRIPT_BYTES: usize = 256 * 1_024;
const MAX_TEXT_INPUT_BYTES: usize = 256 * 1_024;
const MAX_URL_BYTES: usize = 16 * 1_024;
const MAX_SELECTOR_BYTES: usize = 8 * 1_024;
const MAX_ARGUMENT_ITEMS: usize = 256;
const MAX_ARGUMENT_BYTES: usize = 256 * 1_024;

tokio::task_local! {
    static REQUEST_RUNTIME: Runtime;
    static REQUEST_ACCESS: RequestAccess;
}

#[derive(Debug)]
struct RuntimeInner {
    config_path: PathBuf,
    connector_id: String,
    store: StateStore,
    filesystem: ScopedFilesystem,
    approval_timeout: Duration,
    process_timeout: Duration,
    max_process_timeout: Duration,
    max_output_bytes: usize,
    calls_per_minute: usize,
    calls: Mutex<HashMap<String, VecDeque<Instant>>>,
    max_sessions: usize,
    active_sessions: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
struct Runtime(Arc<RuntimeInner>);

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequestPrincipal {
    LocalHttp,
    QuickTunnel,
    OAuth {
        client_id: String,
        subject: String,
        scopes: ScopeSet,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestAccess {
    connector_id: String,
    principal: RequestPrincipal,
}

#[derive(Clone)]
struct LocalHttpConnector {
    runtime: Runtime,
    token: Arc<secrecy::SecretString>,
}

impl std::fmt::Debug for LocalHttpConnector {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalHttpConnector")
            .field("connector_id", &self.runtime.0.connector_id)
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

impl RequestAccess {
    fn rate_limit_key(&self) -> String {
        match &self.principal {
            RequestPrincipal::LocalHttp => "local_http".to_owned(),
            RequestPrincipal::QuickTunnel => "quick_tunnel".to_owned(),
            RequestPrincipal::OAuth { client_id, .. } => format!("oauth:{client_id}"),
        }
    }
}

impl Runtime {
    fn load(connector_id: &str) -> Result<Self> {
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        let config =
            AppConfig::load(&paths.config_file()).context("run `runonmine setup` first")?;
        let connector = config
            .connector(connector_id)
            .with_context(|| format!("connector {connector_id} was not found"))?;
        if !connector.enabled {
            bail!("connector is disabled");
        }
        let filesystem = ScopedFilesystem::new(&config.allowed_roots)?;
        let store = StateStore::open(&paths.state_db())?;
        if !store.verify_audit_chain()? {
            bail!("audit chain verification failed; run `runonmine doctor`");
        }
        store.prune_audit()?;
        Ok(Self(Arc::new(RuntimeInner {
            config_path: paths.config_file(),
            connector_id: connector_id.to_owned(),
            store,
            filesystem,
            approval_timeout: Duration::from_secs(config.limits.approval_timeout_seconds),
            process_timeout: Duration::from_secs(config.limits.default_process_timeout_seconds),
            max_process_timeout: Duration::from_secs(config.limits.max_process_timeout_seconds),
            max_output_bytes: config.limits.max_output_bytes,
            calls_per_minute: usize::try_from(config.limits.calls_per_minute).unwrap_or(usize::MAX),
            calls: Mutex::new(HashMap::new()),
            max_sessions: config.limits.max_sessions,
            active_sessions: Arc::new(AtomicUsize::new(0)),
        })))
    }

    fn connector(&self) -> Result<ConnectorConfig> {
        let config = AppConfig::load(&self.0.config_path)?;
        let connector = config
            .connector(&self.0.connector_id)
            .context("connector is no longer configured")?;
        if !connector.enabled {
            bail!("connector is disabled");
        }
        Ok(connector.clone())
    }

    fn acquire_session(&self) -> Result<SessionPermit> {
        let counter = &self.0.active_sessions;
        let mut current = counter.load(Ordering::Acquire);
        loop {
            if current >= self.0.max_sessions {
                bail!("connector session limit reached");
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(SessionPermit {
                        counter: Arc::clone(counter),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn check_rate_limit(&self, principal: &str) -> Result<()> {
        let mut calls = self
            .0
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("rate limit lock failed"))?;
        let now = Instant::now();
        let cutoff = now.checked_sub(Duration::from_mins(1)).unwrap_or(now);
        for entries in calls.values_mut() {
            while entries.front().is_some_and(|instant| *instant < cutoff) {
                entries.pop_front();
            }
        }
        calls.retain(|_, entries| !entries.is_empty());
        let entries = calls.entry(principal.to_owned()).or_default();
        if entries.len() >= self.0.calls_per_minute {
            bail!("principal rate limit reached");
        }
        entries.push_back(now);
        Ok(())
    }
}

#[derive(Debug)]
struct SessionPermit {
    counter: Arc<AtomicUsize>,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// `rmcp` leaves expiry policy to the embedding application. This wrapper
/// records every protocol operation and closes a worker before reporting an
/// idle session as missing.
#[derive(Debug)]
struct IdleSessionManager {
    inner: LocalSessionManager,
    last_seen: tokio::sync::RwLock<HashMap<SessionId, Instant>>,
    idle_ttl: Duration,
}

impl IdleSessionManager {
    fn new(idle_ttl: Duration) -> Self {
        Self {
            inner: LocalSessionManager::default(),
            last_seen: tokio::sync::RwLock::new(HashMap::new()),
            idle_ttl,
        }
    }

    async fn touch(&self, id: &SessionId) -> Result<(), LocalSessionManagerError> {
        let expired = self
            .last_seen
            .read()
            .await
            .get(id)
            .is_some_and(|last_seen| last_seen.elapsed() >= self.idle_ttl);
        if expired {
            self.last_seen.write().await.remove(id);
            self.inner.close_session(id).await?;
            return Err(LocalSessionManagerError::SessionNotFound(id.clone()));
        }
        self.last_seen
            .write()
            .await
            .insert(id.clone(), Instant::now());
        Ok(())
    }

    async fn close_expired(&self) -> usize {
        let expired = {
            let mut last_seen = self.last_seen.write().await;
            let expired = last_seen
                .iter()
                .filter(|(_, seen)| seen.elapsed() >= self.idle_ttl)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>();
            for id in &expired {
                last_seen.remove(id);
            }
            expired
        };
        let mut closed = 0_usize;
        for id in expired {
            if self.inner.close_session(&id).await.is_ok() {
                closed += 1;
            }
        }
        closed
    }
}

impl SessionManager for IdleSessionManager {
    type Error = LocalSessionManagerError;
    type Transport = <LocalSessionManager as SessionManager>::Transport;

    async fn create_session(&self) -> Result<(SessionId, Self::Transport), Self::Error> {
        let (id, transport) = self.inner.create_session().await?;
        self.last_seen
            .write()
            .await
            .insert(id.clone(), Instant::now());
        Ok((id, transport))
    }

    async fn initialize_session(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<ServerJsonRpcMessage, Self::Error> {
        self.touch(id).await?;
        self.inner.initialize_session(id, message).await
    }

    async fn has_session(&self, id: &SessionId) -> Result<bool, Self::Error> {
        if self.touch(id).await.is_err() {
            return Ok(false);
        }
        self.inner.has_session(id).await
    }

    async fn close_session(&self, id: &SessionId) -> Result<(), Self::Error> {
        self.last_seen.write().await.remove(id);
        self.inner.close_session(id).await
    }

    async fn create_stream(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.touch(id).await?;
        self.inner.create_stream(id, message).await
    }

    async fn accept_message(
        &self,
        id: &SessionId,
        message: ClientJsonRpcMessage,
    ) -> Result<(), Self::Error> {
        self.touch(id).await?;
        self.inner.accept_message(id, message).await
    }

    async fn create_standalone_stream(
        &self,
        id: &SessionId,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.touch(id).await?;
        self.inner.create_standalone_stream(id).await
    }

    async fn resume(
        &self,
        id: &SessionId,
        last_event_id: String,
    ) -> Result<impl Stream<Item = ServerSseMessage> + Send + Sync + 'static, Self::Error> {
        self.touch(id).await?;
        self.inner.resume(id, last_event_id).await
    }

    async fn restore_session(
        &self,
        id: SessionId,
    ) -> Result<RestoreOutcome<Self::Transport>, Self::Error> {
        let outcome = self.inner.restore_session(id.clone()).await?;
        if !matches!(outcome, RestoreOutcome::NotSupported) {
            self.last_seen.write().await.insert(id, Instant::now());
        }
        Ok(outcome)
    }
}

#[derive(Clone)]
pub struct RunOnMineServer {
    runtime: Runtime,
    browser: Arc<BrowserSession>,
    admin: Option<HelperClient>,
    tool_router: ToolRouter<Self>,
    _session_permit: Arc<SessionPermit>,
}

impl std::fmt::Debug for RunOnMineServer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RunOnMineServer")
            .field("connector_id", &self.runtime.0.connector_id)
            .finish_non_exhaustive()
    }
}

impl RunOnMineServer {
    fn new(runtime: Runtime) -> Result<Self> {
        let connector = runtime.connector()?;
        let permit = Arc::new(runtime.acquire_session()?);
        let paths = AppPaths::discover()?;
        let app_config = AppConfig::load(&paths.config_file())?;
        let remote_connector = matches!(
            connector.kind,
            ConnectorKind::CloudflareQuick
                | ConnectorKind::CloudflareOauth
                | ConnectorKind::OpenAiTunnel
        );
        let browser_profile = match app_config.browser.external_cdp_url.clone() {
            Some(_) if remote_connector => {
                bail!("external CDP attachment is unavailable to remote connectors")
            }
            Some(endpoint) => BrowserProfile::external(endpoint)?,
            None => {
                let base = paths
                    .browser_profiles()
                    .join(&app_config.browser.profile_name)
                    .join(&connector.id);
                match app_config.browser.profile_mode {
                    BrowserProfileMode::Ephemeral => BrowserProfile::isolated_ephemeral(
                        base.join(uuid::Uuid::new_v4().to_string()),
                    ),
                    BrowserProfileMode::Persistent => BrowserProfile::isolated_persistent(base),
                }
            }
        };
        let browser_available =
            matches!(browser_profile, BrowserProfile::ExternalCdp { .. }) || chromium_available();
        let browser = Arc::new(BrowserSession::new(
            browser_profile,
            browser_should_be_headless(),
            app_config.browser.allow_private_network && !remote_connector,
            runtime.0.max_output_bytes,
        ));
        let engine = PolicyEngine;
        let mut tool_router = Self::tool_router();
        for (tool_name, capability) in TOOL_CAPABILITIES {
            if engine.evaluate(&connector, tool_name, *capability).mode == PolicyMode::Deny {
                tool_router.disable_route(*tool_name);
            }
        }
        if runtime.0.filesystem.roots().is_empty() {
            for tool_name in FILE_TOOLS {
                tool_router.disable_route(*tool_name);
            }
        }
        if !browser_available {
            for tool_name in BROWSER_TOOLS {
                tool_router.disable_route(*tool_name);
            }
        }
        if !desktop::capture_available() {
            for tool_name in DESKTOP_CAPTURE_TOOLS {
                tool_router.disable_route(*tool_name);
            }
        }
        if !desktop::focus_available() {
            tool_router.disable_route("desktop_focus_window");
        }
        if !desktop::input_available() {
            for tool_name in DESKTOP_INPUT_TOOLS {
                tool_router.disable_route(*tool_name);
            }
        }
        if !native::applescript_available() {
            tool_router.disable_route("macos_applescript");
        }
        if !native::powershell_available() {
            tool_router.disable_route("windows_powershell");
        }
        if !native::dbus_available() {
            tool_router.disable_route("linux_dbus_call");
        }
        Ok(Self {
            runtime,
            browser,
            admin: HelperClient::for_current_user().ok(),
            tool_router,
            _session_permit: permit,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn authorize<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
    ) -> Result<(), McpError> {
        let rate_limit_key = REQUEST_ACCESS
            .try_with(RequestAccess::rate_limit_key)
            .unwrap_or_else(|_| "stdio".to_owned());
        if self.runtime.check_rate_limit(&rate_limit_key).is_err() {
            self.audit(
                tool_name,
                capability,
                AuditOutcome::Denied,
                arguments,
                "rate limit reached",
            );
            return Err(McpError::invalid_request(
                "Connector rate limit reached",
                None,
            ));
        }
        let connector = self.runtime.connector().map_err(|_| {
            McpError::invalid_request("Connector configuration is unavailable", None)
        })?;
        let argument_hash = argument_hash(arguments).map_err(|error| {
            tracing::error!(%error, "failed to serialize tool arguments for authorization");
            McpError::internal_error("Tool arguments could not be safely authorized", None)
        })?;
        let access = REQUEST_ACCESS.try_with(Clone::clone).ok();
        let principal = match access.as_ref().map(|item| &item.principal) {
            Some(RequestPrincipal::OAuth {
                client_id, subject, ..
            }) => PrincipalContext::OAuth { client_id, subject },
            _ => PrincipalContext::Local,
        };
        let resource = policy_resource(tool_name, arguments).map_err(|error| {
            tracing::error!(%error, "failed to derive policy resource");
            McpError::internal_error("Tool resource could not be safely authorized", None)
        })?;
        let policy_context = PolicyContext {
            principal,
            resource: resource.as_context(),
        };
        let mode = PolicyEngine
            .evaluate_context(&connector, tool_name, capability, &policy_context)
            .mode;
        let grant_allows = self
            .runtime
            .0
            .store
            .grant_allows_async(
                connector.id.clone(),
                tool_name.to_owned(),
                argument_hash.clone(),
            )
            .await
            .unwrap_or(false);
        if mode == PolicyMode::Allow || grant_allows {
            self.audit_authorization_required(
                tool_name,
                capability,
                AuditOutcome::Allowed,
                &argument_hash,
                summary,
            )
            .await?;
            return Ok(());
        }
        if mode == PolicyMode::Deny {
            self.audit_authorization_required(
                tool_name,
                capability,
                AuditOutcome::Denied,
                &argument_hash,
                summary,
            )
            .await?;
            return Err(McpError::invalid_request(
                "Tool is denied by local policy",
                None,
            ));
        }

        let chrono_timeout = chrono::Duration::from_std(self.runtime.0.approval_timeout)
            .map_err(|_| McpError::internal_error("Invalid local approval timeout", None))?;
        let approval = ApprovalRequest::new(
            &connector.id,
            tool_name,
            approval_preview(tool_name, arguments),
            &argument_hash,
            Utc::now() + chrono_timeout,
        );
        self.runtime
            .0
            .store
            .insert_approval_async(approval.clone())
            .await
            .map_err(|_| {
                McpError::internal_error("Could not create a local approval request", None)
            })?;
        if let Err(error) = self
            .audit_authorization_required(
                tool_name,
                capability,
                AuditOutcome::PendingApproval,
                &argument_hash,
                summary,
            )
            .await
        {
            let _ignored = self
                .runtime
                .0
                .store
                .resolve_approval_async(approval.id, runonmine_core::ApprovalDecision::Deny)
                .await;
            return Err(error);
        }
        let deadline = Instant::now() + self.runtime.0.approval_timeout;
        loop {
            if Instant::now() >= deadline {
                self.audit_authorization_required(
                    tool_name,
                    capability,
                    AuditOutcome::Denied,
                    &argument_hash,
                    "local approval timed out",
                )
                .await?;
                return Err(McpError::invalid_request("Local approval timed out", None));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            let status = self
                .runtime
                .0
                .store
                .approval_status_async(approval.id)
                .await
                .map_err(|_| McpError::internal_error("Could not read local approval", None))?
                .map_or(ApprovalStatus::Expired, |request| request.status);
            match status {
                ApprovalStatus::Approved => {
                    self.audit_authorization_required(
                        tool_name,
                        capability,
                        AuditOutcome::Allowed,
                        &argument_hash,
                        summary,
                    )
                    .await?;
                    return Ok(());
                }
                ApprovalStatus::Denied => {
                    self.audit_authorization_required(
                        tool_name,
                        capability,
                        AuditOutcome::Denied,
                        &argument_hash,
                        "denied by the machine owner",
                    )
                    .await?;
                    return Err(McpError::invalid_request(
                        "Denied by the machine owner",
                        None,
                    ));
                }
                ApprovalStatus::Expired => {
                    self.audit_authorization_required(
                        tool_name,
                        capability,
                        AuditOutcome::Denied,
                        &argument_hash,
                        "local approval expired",
                    )
                    .await?;
                    return Err(McpError::invalid_request("Local approval timed out", None));
                }
                ApprovalStatus::Pending => {}
            }
        }
    }

    async fn audit_authorization_required(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) -> Result<(), McpError> {
        let event = AuditEvent::new(
            &self.runtime.0.connector_id,
            tool_name,
            capability_name(capability),
            outcome,
            argument_hash,
            summary,
        );
        match self.runtime.0.store.append_audit_async(event).await {
            Ok(_) => Ok(()),
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

    fn audit<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        arguments: &T,
        summary: &str,
    ) {
        match argument_hash(arguments) {
            Ok(hash) => self.audit_with_hash(tool_name, capability, outcome, &hash, summary),
            Err(error) => tracing::error!(
                %error,
                tool_name,
                "failed to serialize tool arguments for audit"
            ),
        }
    }

    fn audit_with_hash(
        &self,
        tool_name: &str,
        capability: Capability,
        outcome: AuditOutcome,
        argument_hash: &str,
        summary: &str,
    ) {
        let event = AuditEvent::new(
            &self.runtime.0.connector_id,
            tool_name,
            capability_name(capability),
            outcome,
            argument_hash,
            summary,
        );
        let store = self.runtime.0.store.clone();
        tokio::spawn(async move {
            if let Err(error) = store.append_audit_async(event).await {
                tracing::error!(%error, "failed to append audit event");
            }
        });
    }

    fn success<T: Serialize>(value: &T) -> Result<CallToolResult, McpError> {
        let text = serde_json::to_string(value)
            .map_err(|_| McpError::internal_error("Could not encode tool output", None))?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    fn tool_failed(
        &self,
        tool_name: &str,
        capability: Capability,
        arguments: &impl Serialize,
    ) -> McpError {
        self.audit(
            tool_name,
            capability,
            AuditOutcome::Failed,
            arguments,
            "tool failed",
        );
        McpError::internal_error("Tool failed; inspect the local RunOnMine logs", None)
    }

    fn request_access(context: &RequestContext<RoleServer>) -> Option<&RequestAccess> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<RequestAccess>())
    }

    fn request_allows_tool(&self, tool_name: &str, context: &RequestContext<RoleServer>) -> bool {
        let Some((_, capability)) = TOOL_CAPABILITIES
            .iter()
            .find(|(name, _)| *name == tool_name)
        else {
            return false;
        };
        let local_allows = self.runtime.connector().is_ok_and(|connector| {
            PolicyEngine
                .evaluate(&connector, tool_name, *capability)
                .mode
                != PolicyMode::Deny
        });
        if !local_allows {
            return false;
        }
        let Some(access) = Self::request_access(context) else {
            // Stdio has no HTTP request parts and is governed solely by local policy.
            return true;
        };
        if access.connector_id != self.runtime.0.connector_id {
            return false;
        }
        let RequestPrincipal::OAuth { scopes, .. } = &access.principal else {
            return true;
        };
        scopes.contains(oauth_scope_for_capability(*capability))
    }

    async fn admin_allowlisted_programs(&self) -> Option<usize> {
        let client = self.admin.as_ref()?;
        let response = tokio::time::timeout(
            Duration::from_secs(2),
            client.request(&HelperRequest::health()),
        )
        .await
        .ok()?
        .ok()?;
        match response.result {
            HelperResult::Healthy {
                allowlisted_programs,
            } => Some(allowlisted_programs),
            _ => None,
        }
    }

    async fn admin_available(&self) -> bool {
        self.admin_allowlisted_programs()
            .await
            .is_some_and(|count| count > 0)
    }
}

mod authorization;
use authorization::policy_resource;

mod arguments;
use arguments::{
    AdminExecArgs, DbusCallArgs, DesktopClickArgs, DesktopKeyArgs, DesktopListArgs,
    DesktopScreenshotArgs, DesktopTypeArgs, DesktopWindowArgs, EmptyArgs, EvaluateArgs, KeyArgs,
    ListArgs, MoveArgs, PatchArgs, PathArgs, PlatformScriptArgs, ReadArgs, ReadOutput,
    ScreenshotArgs, SearchArgs, SelectorArgs, ShellArgs, TypeArgs, UrlArgs, WriteArgs,
};

#[tool_router]
impl RunOnMineServer {
    #[tool(
        description = "Return non-secret operating system and RunOnMine capability information",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn machine_info(
        &self,
        Parameters(arguments): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "machine_info",
            Capability::SystemRead,
            "read machine information",
            &arguments,
        )
        .await?;
        let connector = self.runtime.connector().map_err(|_| {
            McpError::internal_error("Connector configuration is unavailable", None)
        })?;
        let remote_connector = matches!(
            connector.kind,
            ConnectorKind::CloudflareQuick
                | ConnectorKind::CloudflareOauth
                | ConnectorKind::OpenAiTunnel
        );
        let hostname = if remote_connector {
            None
        } else {
            hostname::get()
                .ok()
                .map(|value| value.to_string_lossy().into_owned())
        };
        let allowed_roots = (!remote_connector).then(|| self.runtime.0.filesystem.roots());
        let admin_allowlisted_programs = self.admin_allowlisted_programs().await.unwrap_or(0);
        Self::success(&json!({
            "hostname": hostname,
            "os": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "allowed_roots": allowed_roots,
            "allowed_root_count": self.runtime.0.filesystem.roots().len(),
            "admin_helper": admin_allowlisted_programs > 0,
            "admin_allowlisted_programs": admin_allowlisted_programs,
            "desktop_capture": desktop::capture_available(),
            "desktop_input": desktop::input_available(),
        }))
    }

    #[tool(
        description = "List a directory within the machine owner's selected roots",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn fs_list(
        &self,
        Parameters(arguments): Parameters<ListArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_list",
            Capability::FilesRead,
            "list a selected directory",
            &arguments,
        )
        .await?;
        let filesystem = self.runtime.0.filesystem.clone();
        let task_arguments = arguments.clone();
        let result = tokio::task::spawn_blocking(move || {
            filesystem.list_limited(
                &task_arguments.path,
                task_arguments.offset.min(1_000_000),
                task_arguments.limit.clamp(1, 1_000),
            )
        })
        .await;
        match result {
            Ok(Ok(entries)) => Self::success(&entries),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_list", Capability::FilesRead, &arguments))
            }
        }
    }

    #[tool(
        description = "Read a UTF-8 file within the machine owner's selected roots",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn fs_read(
        &self,
        Parameters(arguments): Parameters<ReadArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_read",
            Capability::FilesRead,
            "read a selected file",
            &arguments,
        )
        .await?;
        let limit = arguments
            .max_bytes
            .clamp(1, self.runtime.0.max_output_bytes);
        let filesystem = self.runtime.0.filesystem.clone();
        let path = arguments.path.clone();
        let result = tokio::task::spawn_blocking(move || filesystem.read_text(&path, limit)).await;
        match result {
            Ok(Ok((content, truncated))) => Self::success(&ReadOutput { content, truncated }),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_read", Capability::FilesRead, &arguments))
            }
        }
    }

    #[tool(
        description = "Search file and directory names within a selected root",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn fs_search(
        &self,
        Parameters(arguments): Parameters<SearchArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_search",
            Capability::FilesRead,
            "search a selected root",
            &arguments,
        )
        .await?;
        let filesystem = self.runtime.0.filesystem.clone();
        let task_arguments = arguments.clone();
        let result = tokio::task::spawn_blocking(move || {
            filesystem.search_names_bounded(
                &task_arguments.root,
                &task_arguments.query,
                task_arguments.limit.clamp(1, 1_000),
                task_arguments.max_depth.clamp(1, 64),
                task_arguments.max_nodes.clamp(1, 1_000_000),
                Duration::from_secs(5),
            )
        })
        .await;
        match result {
            Ok(Ok(matches)) => Self::success(&matches),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_search", Capability::FilesRead, &arguments))
            }
        }
    }

    #[tool(
        description = "Atomically create or replace a file within a selected root",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn fs_write(
        &self,
        Parameters(arguments): Parameters<WriteArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_write",
            Capability::FilesWrite,
            "write a selected file",
            &arguments,
        )
        .await?;
        if arguments.content.len() > self.runtime.0.max_output_bytes {
            return Err(McpError::invalid_params(
                "File content exceeds the configured size limit",
                None,
            ));
        }
        let filesystem = self.runtime.0.filesystem.clone();
        let task_arguments = arguments.clone();
        let result = tokio::task::spawn_blocking(move || {
            filesystem.write_atomic(&task_arguments.path, task_arguments.content.as_bytes())
        })
        .await;
        match result {
            Ok(Ok(path)) => Self::success(&json!({"path": path, "bytes": arguments.content.len()})),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_write", Capability::FilesWrite, &arguments))
            }
        }
    }

    #[tool(
        description = "Replace an exact text occurrence in a file within a selected root",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn fs_patch(
        &self,
        Parameters(arguments): Parameters<PatchArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_patch",
            Capability::FilesWrite,
            "patch a selected file",
            &arguments,
        )
        .await?;
        if arguments.old_text.is_empty()
            || arguments.expected_replacements == 0
            || arguments.expected_replacements > 10_000
            || arguments.old_text.len() > self.runtime.0.max_output_bytes
            || arguments.new_text.len() > self.runtime.0.max_output_bytes
        {
            return Err(McpError::invalid_params(
                "Patch parameters are missing or exceed configured limits",
                None,
            ));
        }
        let filesystem = self.runtime.0.filesystem.clone();
        let maximum = self.runtime.0.max_output_bytes;
        let task_arguments = arguments.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<usize> {
            let (content, truncated) = filesystem.read_text(&task_arguments.path, maximum)?;
            if truncated {
                bail!("file exceeds the patch limit");
            }
            let count = content.matches(&task_arguments.old_text).count();
            if count != task_arguments.expected_replacements {
                bail!("patch match count differs from the expected count");
            }
            let updated = content.replacen(
                &task_arguments.old_text,
                &task_arguments.new_text,
                task_arguments.expected_replacements,
            );
            if updated.len() > maximum {
                bail!("patched file exceeds the configured size limit");
            }
            filesystem.write_atomic(&task_arguments.path, updated.as_bytes())?;
            Ok(count)
        })
        .await;
        match result {
            Ok(Ok(replacements)) => Self::success(&json!({"replacements": replacements})),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_patch", Capability::FilesWrite, &arguments))
            }
        }
    }

    #[tool(
        description = "Move or rename a path within the machine owner's selected roots",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn fs_move(
        &self,
        Parameters(arguments): Parameters<MoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_move",
            Capability::FilesWrite,
            "move a selected path",
            &arguments,
        )
        .await?;
        let filesystem = self.runtime.0.filesystem.clone();
        let task_arguments = arguments.clone();
        let result = tokio::task::spawn_blocking(move || {
            filesystem.move_path(&task_arguments.from, &task_arguments.to)
        })
        .await;
        match result {
            Ok(Ok(())) => Self::success(&json!({"moved": true})),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_move", Capability::FilesWrite, &arguments))
            }
        }
    }

    #[tool(
        description = "Move a path within a selected root to the operating system trash",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn fs_delete(
        &self,
        Parameters(arguments): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_delete",
            Capability::FilesWrite,
            "move a selected path to trash",
            &arguments,
        )
        .await?;
        let filesystem = self.runtime.0.filesystem.clone();
        let path = arguments.path.clone();
        let result = tokio::task::spawn_blocking(move || filesystem.move_to_trash(&path)).await;
        match result {
            Ok(Ok(())) => Self::success(&json!({"trashed": true})),
            Ok(Err(_)) | Err(_) => {
                Err(self.tool_failed("fs_delete", Capability::FilesWrite, &arguments))
            }
        }
    }

    #[tool(
        description = "Run a command with the signed-in user's full account permissions; this is not a sandbox",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn shell_exec(
        &self,
        Parameters(arguments): Parameters<ShellArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.command, "Shell command", MAX_COMMAND_BYTES)?;
        validate_optional_path(arguments.cwd.as_deref(), "Shell working directory")?;
        self.authorize(
            "shell_exec",
            Capability::ShellExec,
            "run a user shell command (content withheld)",
            &arguments,
        )
        .await?;
        let requested = arguments
            .timeout_seconds
            .map_or(self.runtime.0.process_timeout, Duration::from_secs)
            .min(self.runtime.0.max_process_timeout);
        let request = ProcessRequest {
            command: arguments.command.clone(),
            cwd: arguments.cwd.clone(),
            timeout: requested,
            max_output_bytes: self.runtime.0.max_output_bytes,
        };
        match execute_shell(&request).await {
            Ok(output) => {
                let outcome = if output.timed_out {
                    AuditOutcome::TimedOut
                } else if output.exit_code == Some(0) {
                    AuditOutcome::Succeeded
                } else {
                    AuditOutcome::Failed
                };
                self.audit(
                    "shell_exec",
                    Capability::ShellExec,
                    outcome,
                    &arguments,
                    "user shell command completed (content withheld)",
                );
                Self::success(&output)
            }
            Err(_) => Err(self.tool_failed("shell_exec", Capability::ShellExec, &arguments)),
        }
    }

    #[tool(
        description = "Run one explicitly installed root/SYSTEM-owned executable through the optional local privileged helper",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn admin_exec(
        &self,
        Parameters(arguments): Parameters<AdminExecArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_path(&arguments.program, "Privileged program")?;
        validate_string_arguments(&arguments.args, "Privileged arguments")?;
        self.authorize(
            "admin_exec",
            Capability::AdminExec,
            "run an allowlisted privileged program (arguments withheld)",
            &arguments,
        )
        .await?;
        let client = self
            .admin
            .as_ref()
            .ok_or_else(|| McpError::invalid_request("Privileged helper is unavailable", None))?;
        let timeout = arguments
            .timeout_seconds
            .map_or(self.runtime.0.process_timeout, Duration::from_secs)
            .min(MAX_ADMIN_TIMEOUT);
        let request =
            HelperRequest::execute(arguments.program.clone(), arguments.args.clone(), timeout)
                .map_err(|_| McpError::invalid_params("Invalid admin execution request", None))?;
        let response =
            tokio::time::timeout(timeout + Duration::from_secs(5), client.request(&request))
                .await
                .map_err(|_| McpError::internal_error("Privileged helper timed out", None))?
                .map_err(|_| self.tool_failed("admin_exec", Capability::AdminExec, &arguments))?;
        match response.result {
            HelperResult::Completed {
                exit_code,
                stdout_base64,
                stderr_base64,
                output_truncated,
                timed_out,
            } => {
                let stdout = base64::engine::general_purpose::STANDARD
                    .decode(stdout_base64)
                    .map_err(|_| McpError::internal_error("Invalid helper response", None))?;
                let stderr = base64::engine::general_purpose::STANDARD
                    .decode(stderr_base64)
                    .map_err(|_| McpError::internal_error("Invalid helper response", None))?;
                Self::success(&json!({
                    "exit_code": exit_code,
                    "stdout": String::from_utf8_lossy(&stdout),
                    "stderr": String::from_utf8_lossy(&stderr),
                    "truncated": output_truncated,
                    "timed_out": timed_out,
                }))
            }
            HelperResult::Rejected { .. } => Err(McpError::invalid_request(
                "Privileged request was rejected locally",
                None,
            )),
            HelperResult::Failed { .. } | HelperResult::Healthy { .. } => {
                Err(self.tool_failed("admin_exec", Capability::AdminExec, &arguments))
            }
        }
    }

    #[tool(
        description = "List visible desktop windows when this interactive session supports capture",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn desktop_list_windows(
        &self,
        Parameters(arguments): Parameters<DesktopListArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "desktop_list_windows",
            Capability::DesktopControl,
            "list desktop windows",
            &arguments,
        )
        .await?;
        let limit = arguments.limit.clamp(1, 1_000);
        match tokio::task::spawn_blocking(move || desktop::list_windows(limit)).await {
            Ok(Ok(windows)) => Self::success(&windows),
            _ => Err(self.tool_failed(
                "desktop_list_windows",
                Capability::DesktopControl,
                &arguments,
            )),
        }
    }

    #[tool(
        description = "Bring a visible desktop window to the foreground",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn desktop_focus_window(
        &self,
        Parameters(arguments): Parameters<DesktopWindowArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "desktop_focus_window",
            Capability::DesktopControl,
            "focus a desktop window",
            &arguments,
        )
        .await?;
        let window_id = arguments.window_id;
        match tokio::task::spawn_blocking(move || desktop::focus_window(window_id)).await {
            Ok(Ok(())) => Self::success(&json!({"focused": true})),
            _ => Err(self.tool_failed(
                "desktop_focus_window",
                Capability::DesktopControl,
                &arguments,
            )),
        }
    }

    #[tool(
        description = "Capture a monitor or desktop window as a bounded, quality-reduced JPEG",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn desktop_screenshot(
        &self,
        Parameters(arguments): Parameters<DesktopScreenshotArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "desktop_screenshot",
            Capability::DesktopControl,
            "capture a desktop screenshot",
            &arguments,
        )
        .await?;
        let target = ScreenshotTarget {
            monitor_id: arguments.monitor_id,
            window_id: arguments.window_id,
            quality: arguments.quality,
            max_dimension: arguments.max_dimension,
        };
        match tokio::task::spawn_blocking(move || desktop::screenshot(target)).await {
            Ok(Ok(image)) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(image.jpeg);
                Ok(CallToolResult::success(vec![
                    ContentBlock::image(encoded, "image/jpeg"),
                    ContentBlock::text(
                        json!({"width": image.width, "height": image.height}).to_string(),
                    ),
                ]))
            }
            _ => {
                Err(self.tool_failed("desktop_screenshot", Capability::DesktopControl, &arguments))
            }
        }
    }

    #[tool(
        description = "Move the pointer and click in the interactive desktop session",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn desktop_click(
        &self,
        Parameters(arguments): Parameters<DesktopClickArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "desktop_click",
            Capability::DesktopControl,
            "click the desktop",
            &arguments,
        )
        .await?;
        let (x, y, button) = (arguments.x, arguments.y, arguments.button.clone());
        match tokio::task::spawn_blocking(move || desktop::click(x, y, &button)).await {
            Ok(Ok(())) => Self::success(&json!({"clicked": true})),
            _ => Err(self.tool_failed("desktop_click", Capability::DesktopControl, &arguments)),
        }
    }

    #[tool(
        description = "Type text into the currently focused desktop control",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn desktop_type(
        &self,
        Parameters(arguments): Parameters<DesktopTypeArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_text(&arguments.text, "Desktop text", MAX_TEXT_INPUT_BYTES)?;
        self.authorize(
            "desktop_type",
            Capability::DesktopControl,
            "type desktop text (content withheld)",
            &arguments,
        )
        .await?;
        let text = arguments.text.clone();
        match tokio::task::spawn_blocking(move || desktop::type_text(&text)).await {
            Ok(Ok(())) => Self::success(&json!({"typed": true})),
            _ => Err(self.tool_failed("desktop_type", Capability::DesktopControl, &arguments)),
        }
    }

    #[tool(
        description = "Press a named key or chord such as enter, escape or ctrl+c in the desktop session",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn desktop_key(
        &self,
        Parameters(arguments): Parameters<DesktopKeyArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.key, "Desktop key", 64)?;
        self.authorize(
            "desktop_key",
            Capability::DesktopControl,
            "press a desktop key",
            &arguments,
        )
        .await?;
        let key = arguments.key.clone();
        match tokio::task::spawn_blocking(move || desktop::key_chord(&key)).await {
            Ok(Ok(())) => Self::success(&json!({"pressed": true})),
            _ => Err(self.tool_failed("desktop_key", Capability::DesktopControl, &arguments)),
        }
    }

    #[tool(
        description = "Run AppleScript through /usr/bin/osascript on macOS with bounded output and process-tree timeout",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn macos_applescript(
        &self,
        Parameters(arguments): Parameters<PlatformScriptArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.script, "AppleScript", MAX_SCRIPT_BYTES)?;
        self.authorize(
            "macos_applescript",
            Capability::PlatformNative,
            "run AppleScript (content withheld)",
            &arguments,
        )
        .await?;
        let timeout = arguments
            .timeout_seconds
            .map_or(self.runtime.0.process_timeout, Duration::from_secs)
            .min(self.runtime.0.max_process_timeout);
        match native::run_applescript(&arguments.script, timeout, self.runtime.0.max_output_bytes)
            .await
        {
            Ok(output) => Self::success(&output),
            Err(_) => {
                Err(self.tool_failed("macos_applescript", Capability::PlatformNative, &arguments))
            }
        }
    }

    #[tool(
        description = "Run non-interactive PowerShell without loading user profiles on Windows",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn windows_powershell(
        &self,
        Parameters(arguments): Parameters<PlatformScriptArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.script, "PowerShell script", MAX_SCRIPT_BYTES)?;
        self.authorize(
            "windows_powershell",
            Capability::PlatformNative,
            "run PowerShell (content withheld)",
            &arguments,
        )
        .await?;
        let timeout = arguments
            .timeout_seconds
            .map_or(self.runtime.0.process_timeout, Duration::from_secs)
            .min(self.runtime.0.max_process_timeout);
        match native::run_powershell(&arguments.script, timeout, self.runtime.0.max_output_bytes)
            .await
        {
            Ok(output) => Self::success(&output),
            Err(_) => {
                Err(self.tool_failed("windows_powershell", Capability::PlatformNative, &arguments))
            }
        }
    }

    #[tool(
        description = "Invoke one structured method on the current Linux user's D-Bus session",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn linux_dbus_call(
        &self,
        Parameters(arguments): Parameters<DbusCallArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_dbus_arguments(&arguments)?;
        self.authorize(
            "linux_dbus_call",
            Capability::PlatformNative,
            "invoke a D-Bus method",
            &arguments,
        )
        .await?;
        let timeout = arguments
            .timeout_seconds
            .map_or(self.runtime.0.process_timeout, Duration::from_secs)
            .min(self.runtime.0.max_process_timeout);
        let call = DbusCall {
            destination: &arguments.destination,
            object_path: &arguments.object_path,
            interface: &arguments.interface,
            method: &arguments.method,
            signature: &arguments.signature,
            arguments: &arguments.arguments,
        };
        match native::run_dbus_call(&call, timeout, self.runtime.0.max_output_bytes).await {
            Ok(output) => Self::success(&output),
            Err(_) => {
                Err(self.tool_failed("linux_dbus_call", Capability::PlatformNative, &arguments))
            }
        }
    }

    #[tool(
        description = "Open a URL in this connector session's isolated Chromium page",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn browser_open(
        &self,
        Parameters(arguments): Parameters<UrlArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.url, "Browser URL", MAX_URL_BYTES)?;
        self.authorize(
            "browser_open",
            Capability::BrowserAct,
            "open a browser page",
            &arguments,
        )
        .await?;
        match self.browser.open(&arguments.url).await {
            Ok(url) => Self::success(&json!({"url": url})),
            Err(_) => Err(self.tool_failed("browser_open", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Navigate the current isolated Chromium page to a URL",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn browser_navigate(
        &self,
        Parameters(arguments): Parameters<UrlArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.url, "Browser URL", MAX_URL_BYTES)?;
        self.authorize(
            "browser_navigate",
            Capability::BrowserAct,
            "navigate a browser page",
            &arguments,
        )
        .await?;
        match self.browser.navigate(&arguments.url).await {
            Ok(url) => Self::success(&json!({"url": url})),
            Err(_) => Err(self.tool_failed("browser_navigate", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Return the current browser page URL",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn browser_get_url(
        &self,
        Parameters(arguments): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "browser_get_url",
            Capability::BrowserRead,
            "read the browser URL",
            &arguments,
        )
        .await?;
        match self.browser.current_url().await {
            Ok(url) => Self::success(&json!({"url": url})),
            Err(_) => Err(self.tool_failed("browser_get_url", Capability::BrowserRead, &arguments)),
        }
    }

    #[tool(
        description = "Return visible text from the current browser page",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn browser_get_text(
        &self,
        Parameters(arguments): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "browser_get_text",
            Capability::BrowserRead,
            "read browser page text",
            &arguments,
        )
        .await?;
        match self.browser.text().await {
            Ok(text) => Self::success(&json!({
                "text": text.content,
                "truncated": text.truncated,
            })),
            Err(_) => {
                Err(self.tool_failed("browser_get_text", Capability::BrowserRead, &arguments))
            }
        }
    }

    #[tool(
        description = "Return the current browser page HTML snapshot",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn browser_snapshot(
        &self,
        Parameters(arguments): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "browser_snapshot",
            Capability::BrowserRead,
            "read a browser snapshot",
            &arguments,
        )
        .await?;
        match self.browser.snapshot().await {
            Ok(html) => Self::success(&json!({
                "html": html.content,
                "truncated": html.truncated,
            })),
            Err(_) => {
                Err(self.tool_failed("browser_snapshot", Capability::BrowserRead, &arguments))
            }
        }
    }

    #[tool(
        description = "Click the first element matching a CSS selector",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn browser_click(
        &self,
        Parameters(arguments): Parameters<SelectorArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.selector, "Browser selector", MAX_SELECTOR_BYTES)?;
        self.authorize(
            "browser_click",
            Capability::BrowserAct,
            "click a browser element",
            &arguments,
        )
        .await?;
        match self.browser.click(&arguments.selector).await {
            Ok(()) => Self::success(&json!({"clicked": true})),
            Err(_) => Err(self.tool_failed("browser_click", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Type text into the first element matching a CSS selector",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn browser_type(
        &self,
        Parameters(arguments): Parameters<TypeArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.selector, "Browser selector", MAX_SELECTOR_BYTES)?;
        validate_text(&arguments.text, "Browser text", MAX_TEXT_INPUT_BYTES)?;
        self.authorize(
            "browser_type",
            Capability::BrowserAct,
            "type into a browser element (text withheld)",
            &arguments,
        )
        .await?;
        match self
            .browser
            .type_text(&arguments.selector, &arguments.text)
            .await
        {
            Ok(()) => Self::success(&json!({"typed": true})),
            Err(_) => Err(self.tool_failed("browser_type", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Press a keyboard key in the focused browser element",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn browser_press(
        &self,
        Parameters(arguments): Parameters<KeyArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(&arguments.key, "Browser key", 64)?;
        self.authorize(
            "browser_press",
            Capability::BrowserAct,
            "press a browser key",
            &arguments,
        )
        .await?;
        match self.browser.press(&arguments.key).await {
            Ok(()) => Self::success(&json!({"pressed": true})),
            Err(_) => Err(self.tool_failed("browser_press", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Capture the current browser page as a quality-reduced JPEG without unsafe byte truncation",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = true
        )
    )]
    async fn browser_screenshot(
        &self,
        Parameters(arguments): Parameters<ScreenshotArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "browser_screenshot",
            Capability::BrowserRead,
            "capture a browser screenshot",
            &arguments,
        )
        .await?;
        match self
            .browser
            .screenshot_jpeg(arguments.quality, arguments.full_page)
            .await
        {
            Ok(bytes) => {
                let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
                Ok(CallToolResult::success(vec![ContentBlock::image(
                    encoded,
                    "image/jpeg",
                )]))
            }
            Err(_) => {
                Err(self.tool_failed("browser_screenshot", Capability::BrowserRead, &arguments))
            }
        }
    }

    #[tool(
        description = "Evaluate JavaScript in the current page; this can perform arbitrary page actions",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn browser_evaluate(
        &self,
        Parameters(arguments): Parameters<EvaluateArgs>,
    ) -> Result<CallToolResult, McpError> {
        validate_nonempty_text(
            &arguments.expression,
            "Browser JavaScript",
            MAX_SCRIPT_BYTES,
        )?;
        self.authorize(
            "browser_evaluate",
            Capability::BrowserAct,
            "evaluate browser JavaScript (content withheld)",
            &arguments,
        )
        .await?;
        match self.browser.evaluate(&arguments.expression).await {
            Ok(value) => Self::success(&value),
            Err(_) => Err(self.tool_failed("browser_evaluate", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Close this connector session's browser page and owned isolated Chromium process",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn browser_close(
        &self,
        Parameters(arguments): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "browser_close",
            Capability::BrowserAct,
            "close the browser session",
            &arguments,
        )
        .await?;
        match self.browser.close().await {
            Ok(()) => Self::success(&json!({"closed": true})),
            Err(_) => Err(self.tool_failed("browser_close", Capability::BrowserAct, &arguments)),
        }
    }

    #[tool(
        description = "Return non-secret information about this connector session's browser profile",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn browser_profile_info(
        &self,
        Parameters(arguments): Parameters<EmptyArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "browser_profile_info",
            Capability::BrowserRead,
            "read browser profile information",
            &arguments,
        )
        .await?;
        match self.browser.info().await {
            Ok(info) => Self::success(&info),
            Err(_) => {
                Err(self.tool_failed("browser_profile_info", Capability::BrowserRead, &arguments))
            }
        }
    }
}

#[tool_handler(
    router = self.tool_router,
    name = "runonmine",
    instructions = "RunOnMine exposes only tools allowed by the machine owner's local policy. Ask-mode tools require approval on the machine."
)]
impl ServerHandler for RunOnMineServer {
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if !self.request_allows_tool(&request.name, &context)
            || (request.name == "admin_exec" && !self.admin_available().await)
        {
            return Err(McpError::invalid_params("tool not found", None));
        }
        let call = ToolCallContext::new(self, request, context);
        self.tool_router.call(call).await
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let admin_available = self.admin_available().await;
        let tools = self
            .tool_router
            .list_all()
            .into_iter()
            .filter(|tool| {
                self.request_allows_tool(tool.name.as_ref(), &context)
                    && (tool.name != "admin_exec" || admin_available)
            })
            .collect();
        Ok(ListToolsResult {
            tools,
            meta: None,
            next_cursor: None,
        })
    }
}

const FILE_TOOLS: &[&str] = &[
    "fs_list",
    "fs_read",
    "fs_search",
    "fs_write",
    "fs_patch",
    "fs_move",
    "fs_delete",
];

const BROWSER_TOOLS: &[&str] = &[
    "browser_open",
    "browser_navigate",
    "browser_get_url",
    "browser_get_text",
    "browser_snapshot",
    "browser_click",
    "browser_type",
    "browser_press",
    "browser_screenshot",
    "browser_evaluate",
    "browser_close",
    "browser_profile_info",
];

const DESKTOP_CAPTURE_TOOLS: &[&str] = &["desktop_list_windows", "desktop_screenshot"];

const DESKTOP_INPUT_TOOLS: &[&str] = &["desktop_click", "desktop_type", "desktop_key"];

const TOOL_CAPABILITIES: &[(&str, Capability)] = &[
    ("machine_info", Capability::SystemRead),
    ("fs_list", Capability::FilesRead),
    ("fs_read", Capability::FilesRead),
    ("fs_search", Capability::FilesRead),
    ("fs_write", Capability::FilesWrite),
    ("fs_patch", Capability::FilesWrite),
    ("fs_move", Capability::FilesWrite),
    ("fs_delete", Capability::FilesWrite),
    ("shell_exec", Capability::ShellExec),
    ("admin_exec", Capability::AdminExec),
    ("desktop_list_windows", Capability::DesktopControl),
    ("desktop_focus_window", Capability::DesktopControl),
    ("desktop_screenshot", Capability::DesktopControl),
    ("desktop_click", Capability::DesktopControl),
    ("desktop_type", Capability::DesktopControl),
    ("desktop_key", Capability::DesktopControl),
    ("macos_applescript", Capability::PlatformNative),
    ("windows_powershell", Capability::PlatformNative),
    ("linux_dbus_call", Capability::PlatformNative),
    ("browser_open", Capability::BrowserAct),
    ("browser_navigate", Capability::BrowserAct),
    ("browser_get_url", Capability::BrowserRead),
    ("browser_get_text", Capability::BrowserRead),
    ("browser_snapshot", Capability::BrowserRead),
    ("browser_click", Capability::BrowserAct),
    ("browser_type", Capability::BrowserAct),
    ("browser_press", Capability::BrowserAct),
    ("browser_screenshot", Capability::BrowserRead),
    ("browser_evaluate", Capability::BrowserAct),
    ("browser_close", Capability::BrowserAct),
    ("browser_profile_info", Capability::BrowserRead),
];

#[derive(Debug, Default)]
struct ManagedConnectors {
    handles: Vec<SupervisorHandle>,
    observers: Vec<tokio::task::JoinHandle<()>>,
}

impl ManagedConnectors {
    async fn stop(mut self) {
        for observer in self.observers.drain(..) {
            observer.abort();
            let _ignored = observer.await;
        }
        for handle in self.handles.drain(..) {
            let _ignored = handle.stop().await;
        }
    }
}

pub async fn serve_stdio(connector_id: &str) -> Result<()> {
    let server = RunOnMineServer::new(Runtime::load(connector_id)?)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

pub async fn serve_loopback() -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config = AppConfig::load(&paths.config_file()).context("run `runonmine setup` first")?;
    let connector_state = Arc::new(build_http_connector_state(&paths, &config)?);
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
    let mut router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
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
    let managed_connectors = start_external_connectors(&paths, &config).await?;
    tracing::info!(%address, "RunOnMine agent listening on loopback");
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await;
    session_sweeper.abort();
    let _ignored = session_sweeper.await;
    managed_connectors.stop().await;
    result.map_err(Into::into)
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

#[allow(clippy::too_many_lines)]
async fn start_external_connectors(
    paths: &AppPaths,
    config: &AppConfig,
) -> Result<ManagedConnectors> {
    let discovery = BinaryDiscovery::new(vec![paths.data_dir.join("bin")]);
    let supervisor = ProcessSupervisor;
    let secrets = default_secret_store(paths)?;
    let origin = Url::parse(&format!("http://127.0.0.1:{}", config.port))?;
    let mut managed = ManagedConnectors::default();
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        match connector.kind {
            ConnectorKind::CloudflareQuick => {
                let settings = connector
                    .cloudflare_quick
                    .as_ref()
                    .context("Cloudflare Quick settings are missing")?;
                let binary = discovery
                    .discover(
                        BinaryKind::Cloudflared,
                        settings.cloudflared_path.as_deref(),
                    )?
                    .context("cloudflared is not installed; run the connector setup again")?;
                let tunnel = QuickTunnelConfig::builder(origin.clone())
                    .metrics_address(format!("127.0.0.1:{}", settings.metrics_port).parse()?)
                    .build()?;
                let mut handle = supervisor.start(
                    tunnel.command(&binary)?,
                    tunnel.health_check()?,
                    RestartPolicy::default(),
                )?;
                if let Some(events) = handle.take_initial_events() {
                    managed.observers.push(spawn_quick_url_observer(
                        events,
                        paths.config_file(),
                        connector.id.clone(),
                    ));
                }
                managed.handles.push(handle);
            }
            ConnectorKind::CloudflareOauth => {
                let settings = connector
                    .cloudflare_named
                    .as_ref()
                    .context("Cloudflare Named Tunnel settings are missing")?;
                let binary = discovery
                    .discover(
                        BinaryKind::Cloudflared,
                        settings.cloudflared_path.as_deref(),
                    )?
                    .context("cloudflared is not installed; run the connector setup again")?;
                let connector_dir = paths.data_dir.join("connectors").join(&connector.id);
                ensure_private_directory(&connector_dir)?;
                let tunnel = NamedTunnelConfig::builder(
                    &settings.tunnel_id,
                    settings.credentials_file.clone(),
                    &settings.hostname,
                    origin.join("mcp")?,
                    connector_dir.join("cloudflared.yml"),
                )
                .metrics_address(format!("127.0.0.1:{}", settings.metrics_port).parse()?)
                .build()?;
                tunnel.write_config()?;
                managed.handles.push(supervisor.start(
                    tunnel.command(&binary)?,
                    tunnel.health_check()?,
                    RestartPolicy::default(),
                )?);
            }
            ConnectorKind::OpenAiTunnel => {
                let settings = connector
                    .openai_tunnel
                    .as_ref()
                    .context("OpenAI tunnel settings are missing")?;
                let binary = discovery
                    .discover(
                        BinaryKind::OpenAiTunnelClient,
                        settings.tunnel_client_path.as_deref(),
                    )?
                    .context("tunnel-client is not installed; run the connector setup again")?;
                let connector_dir = paths.data_dir.join("connectors").join(&connector.id);
                let profile_directory = connector_dir.join("openai-profiles");
                let health_directory = paths.state_dir.join("connectors").join(&connector.id);
                ensure_private_directory(&profile_directory)?;
                ensure_private_directory(&health_directory)?;
                let target =
                    OpenAiMcpTarget::runonmine_stdio(runonmine_cli_executable()?, &connector.id)?;
                let profile =
                    OpenAiTunnelProfile::builder(&settings.profile, &settings.tunnel_id, target)
                        .profile_directory(profile_directory.clone())
                        .health_address(format!("127.0.0.1:{}", settings.health_port).parse()?)
                        .health_url_file(health_directory.join("tunnel-health.url"))
                        .build()?;
                let profile_file = profile_directory.join(format!("{}.yaml", profile.profile()));
                if !profile_file.exists() {
                    let initialized = run_once(
                        profile.init_command(&binary)?,
                        Duration::from_secs(30),
                        128 * 1_024,
                    )
                    .await?;
                    if !initialized.success {
                        bail!("tunnel-client profile initialization failed");
                    }
                    restrict_private_file(&profile_file)?;
                }
                let runtime_key = required_secret(
                    secrets.as_ref(),
                    &format!("connector.{}.runtime_api_key", connector.id),
                )?;
                let doctor = run_once(
                    profile.doctor_command(
                        &binary,
                        SecretValue::new(runtime_key.expose_secret().to_owned())?,
                    )?,
                    Duration::from_secs(30),
                    256 * 1_024,
                )
                .await?;
                if !doctor.success {
                    bail!("tunnel-client doctor failed; run `runonmine doctor` for guidance");
                }
                managed.handles.push(supervisor.start(
                    profile.run_command(
                        &binary,
                        SecretValue::new(runtime_key.expose_secret().to_owned())?,
                    )?,
                    profile.readiness_check()?,
                    RestartPolicy::default(),
                )?);
            }
            ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => {}
        }
    }
    Ok(managed)
}

fn spawn_quick_url_observer(
    mut events: tokio::sync::broadcast::Receiver<ProcessEvent>,
    config_path: PathBuf,
    connector_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(event) = events.recv().await {
            let (ProcessEvent::StandardOutput { line } | ProcessEvent::StandardError { line }) =
                event
            else {
                continue;
            };
            let Some(url) = parse_quick_tunnel_url(&line) else {
                continue;
            };
            if let Err(error) = persist_quick_public_url(&config_path, &connector_id, url) {
                tracing::error!(%error, "failed to persist Quick Tunnel public URL");
            } else {
                tracing::info!(connector_id = %connector_id, "Cloudflare Quick Tunnel is ready");
            }
        }
    })
}

fn persist_quick_public_url(
    config_path: &std::path::Path,
    connector_id: &str,
    url: Url,
) -> Result<()> {
    let mut config = AppConfig::load(config_path)?;
    let connector = config
        .connector_mut(connector_id)
        .context("Quick Tunnel connector was removed")?;
    if connector.kind != ConnectorKind::CloudflareQuick {
        bail!("connector is no longer a Quick Tunnel");
    }
    connector.public_base_url = Some(url);
    config.save(config_path)
}

fn ensure_private_directory(path: &std::path::Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked connector directory");
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_private_file(path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("connector profile was not created")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("connector profile must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn runonmine_cli_executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?.canonicalize()?;
    let expected = if current
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name == "runonmine")
    {
        current
    } else {
        let filename = if cfg!(windows) {
            "runonmine.exe"
        } else {
            "runonmine"
        };
        current
            .parent()
            .context("agent executable has no parent directory")?
            .join(filename)
    };
    if !expected.is_file() {
        bail!("runonmine CLI is not installed next to the agent executable");
    }
    Ok(expected)
}

fn build_http_connector_state(paths: &AppPaths, config: &AppConfig) -> Result<HttpConnectorState> {
    let secrets = default_secret_store(paths)?;
    let mut local = None;
    let mut quick = None;
    let mut oauth = None;
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        match connector.kind {
            ConnectorKind::LocalHttp => {
                let secret_name = format!("connector.{}.local_http_token", connector.id);
                if let Some(token) = secrets.get(&secret_name)? {
                    validate_local_http_token(token.expose_secret())?;
                    local = Some(LocalHttpConnector {
                        runtime: Runtime::load(&connector.id)?,
                        token: Arc::new(token),
                    });
                } else {
                    tracing::warn!(
                        connector_id = %connector.id,
                        "local HTTP connector is enabled without a bearer token and will remain unavailable"
                    );
                }
            }
            ConnectorKind::CloudflareQuick => {
                let path_secret = required_secret(
                    secrets.as_ref(),
                    &format!("connector.{}.path_secret", connector.id),
                )?;
                validate_quick_path_secret(path_secret.expose_secret())?;
                quick = Some(QuickHttpConnector {
                    runtime: Runtime::load(&connector.id)?,
                    paths: paths.clone(),
                });
            }
            ConnectorKind::CloudflareOauth => {
                oauth = Some(build_oauth_connector(paths, connector, secrets.as_ref())?);
            }
            ConnectorKind::LocalStdio | ConnectorKind::OpenAiTunnel => {}
        }
    }
    Ok(HttpConnectorState {
        local,
        quick,
        oauth,
        agent_port: config.port,
        session_idle_ttl: Duration::from_secs(
            config.limits.session_idle_minutes.saturating_mul(60),
        ),
        sessions: Arc::new(AsyncMutex::new(HashMap::new())),
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
        &owner.github_login,
        owner.github_id,
    )?;
    let service = OAuthService::new(
        OAuthServiceConfig {
            issuer: public_base.clone(),
            protected_resource,
            github_client_id: client_id.expose_secret().to_owned(),
            github_callback_url,
        },
        Arc::new(SqliteOAuthStore::open(&paths.state_db())?),
        TokenHasher::new(hash_key)?,
        Arc::new(verifier),
    )?;
    let resource_metadata = public_base
        .join(".well-known/oauth-protected-resource")
        .context("OAuth protected resource metadata URL is invalid")?;
    Ok(OAuthHttpConnector {
        runtime: Runtime::load(&connector.id)?,
        service: Arc::new(service),
        public_host,
        resource_metadata,
    })
}

fn required_secret(store: &dyn SecretStore, name: &str) -> Result<secrecy::SecretString> {
    store
        .get(name)?
        .with_context(|| format!("required credential {name} is missing"))
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
        sessions.retain(|_, binding| binding.last_seen.elapsed() < state.session_idle_ttl);
        let Some(binding) = sessions.get_mut(session_id) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        if binding.access != access {
            return StatusCode::NOT_FOUND.into_response();
        }
        binding.last_seen = Instant::now();
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
        state.sessions.lock().await.insert(
            response_session,
            SessionBinding {
                access: access.clone(),
                last_seen: Instant::now(),
            },
        );
    }
    if method == Method::DELETE
        && let Some(session_id) = request_session
    {
        state.sessions.lock().await.remove(&session_id);
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
        let expected_secret = default_secret_store(&quick.paths)
            .and_then(|store| {
                store.get(&format!(
                    "connector.{}.path_secret",
                    quick.runtime.0.connector_id
                ))
            })
            .ok()
            .flatten();
        let Some(expected_secret) = expected_secret else {
            return Err(StatusCode::NOT_FOUND.into_response());
        };
        let expected = expected_secret.expose_secret().as_bytes();
        let matches =
            supplied.len() == expected.len() && bool::from(supplied.as_bytes().ct_eq(expected));
        if !matches {
            return Err(StatusCode::NOT_FOUND.into_response());
        }
        return Ok((
            quick.runtime.clone(),
            RequestAccess {
                connector_id: quick.runtime.0.connector_id.clone(),
                principal: RequestPrincipal::QuickTunnel,
            },
        ));
    }

    let authority = request_authority(request)?;
    let host = authority
        .host()
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if let Some(oauth) = &state.oauth
        && host == oauth.public_host
    {
        let raw_token = bearer_token(request, &oauth.resource_metadata)?;
        let connector = oauth
            .runtime
            .connector()
            .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
        let policy_scopes = oauth_policy_scopes(&connector);
        let grant = oauth
            .service
            .authenticate_access_token(raw_token, &policy_scopes)
            .map_err(|_| unauthorized(&oauth.resource_metadata))?;
        return Ok((
            oauth.runtime.clone(),
            RequestAccess {
                connector_id: oauth.runtime.0.connector_id.clone(),
                principal: RequestPrincipal::OAuth {
                    client_id: grant.client_id,
                    subject: grant.subject,
                    scopes: grant.scopes,
                },
            },
        ));
    }
    if is_loopback_host(&host)
        && authority
            .port_u16()
            .is_none_or(|port| port == state.agent_port)
        && let Some(local) = &state.local
    {
        let supplied = local_bearer_token(request)?;
        let expected = local.token.expose_secret().as_bytes();
        let matches =
            supplied.len() == expected.len() && bool::from(supplied.as_bytes().ct_eq(expected));
        if !matches {
            return Err(local_unauthorized());
        }
        return Ok((
            local.runtime.clone(),
            RequestAccess {
                connector_id: local.runtime.0.connector_id.clone(),
                principal: RequestPrincipal::LocalHttp,
            },
        ));
    }
    Err(StatusCode::NOT_FOUND.into_response())
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

const fn oauth_scope_for_capability(capability: Capability) -> Scope {
    match capability {
        Capability::SystemRead => Scope::MachineRead,
        Capability::FilesRead => Scope::FilesRead,
        Capability::FilesWrite => Scope::FilesWrite,
        Capability::ShellExec | Capability::PlatformNative => Scope::ShellExec,
        Capability::BrowserRead => Scope::BrowserRead,
        Capability::BrowserAct => Scope::BrowserAct,
        Capability::DesktopControl => Scope::DesktopControl,
        Capability::AdminExec => Scope::AdminExec,
    }
}

#[allow(clippy::result_large_err)]
fn session_id(headers: &axum::http::HeaderMap) -> Result<Option<String>, Response> {
    headers
        .get("mcp-session-id")
        .map(|value| {
            let value = value
                .to_str()
                .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
            if value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
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
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .map(str::to_owned)
}

async fn public_oauth_host_guard(
    State(expected_host): State<String>,
    request: Request,
    next: Next,
) -> Response {
    let allowed = request_authority(&request)
        .is_ok_and(|authority| authority.host().eq_ignore_ascii_case(&expected_host));
    if !allowed {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(request).await
}

async fn shutdown_signal() {
    let _result = tokio::signal::ctrl_c().await;
}

#[allow(clippy::too_many_lines)]
mod validation;
use validation::{
    approval_preview, argument_hash, browser_should_be_headless, capability_name,
    capability_requires_reliable_audit, validate_dbus_arguments, validate_nonempty_text,
    validate_optional_path, validate_path, validate_string_arguments, validate_text,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_hash_does_not_expose_arguments() -> Result<()> {
        let hash = argument_hash(&json!({"token": "secret-value"}))?;
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("secret-value"));
        Ok(())
    }

    #[test]
    fn approval_preview_shows_target_and_redacts_common_secrets() {
        let preview = approval_preview(
            "shell_exec",
            &json!({
                "command": "curl -H 'Authorization: Bearer top-secret' 'https://example.com?token=abc123'",
                "cwd": "/tmp/project",
                "timeout_seconds": 30
            }),
        );
        assert!(preview.contains("curl"));
        assert!(preview.contains("/tmp/project"));
        assert!(preview.contains("[REDACTED]"));
        assert!(!preview.contains("top-secret"));
        assert!(!preview.contains("abc123"));
    }

    #[test]
    fn dangerous_capabilities_require_reliable_audit() {
        assert!(capability_requires_reliable_audit(Capability::ShellExec));
        assert!(capability_requires_reliable_audit(Capability::FilesWrite));
        assert!(!capability_requires_reliable_audit(Capability::FilesRead));
    }

    #[test]
    fn disabled_tools_are_not_listed() {
        let mut router = RunOnMineServer::tool_router();
        assert!(
            router
                .list_all()
                .iter()
                .any(|tool| tool.name == "fs_delete")
        );
        assert!(router.disable_route("fs_delete"));
        assert!(
            router
                .list_all()
                .iter()
                .all(|tool| tool.name != "fs_delete")
        );
    }

    #[tokio::test]
    async fn idle_sessions_expire() -> Result<()> {
        let idle_ttl = Duration::from_secs(30);
        let manager = IdleSessionManager::new(idle_ttl);
        let (id, _transport) = manager.create_session().await?;
        assert!(manager.has_session(&id).await?);

        let expired_at = Instant::now()
            .checked_sub(idle_ttl + Duration::from_millis(1))
            .context("test clock cannot represent an expired session")?;
        manager
            .last_seen
            .write()
            .await
            .insert(id.clone(), expired_at);

        assert!(!manager.has_session(&id).await?);
        Ok(())
    }
    #[test]
    fn argument_hash_fails_closed_on_serialization_error() {
        struct Broken;

        impl Serialize for Broken {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::Error as _;
                Err(S::Error::custom("broken"))
            }
        }

        assert!(argument_hash(&Broken).is_err());
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
    fn dbus_validation_accepts_an_empty_signature_for_no_arguments() {
        let arguments = DbusCallArgs {
            destination: "org.example.Service".to_owned(),
            object_path: "/org/example/Service".to_owned(),
            interface: "org.example.Service".to_owned(),
            method: "Ping".to_owned(),
            signature: String::new(),
            arguments: Vec::new(),
            timeout_seconds: None,
        };
        assert!(validate_dbus_arguments(&arguments).is_ok());
    }

    #[test]
    fn input_validators_reject_oversized_values() {
        assert!(validate_nonempty_text("", "value", 10).is_err());
        assert!(validate_text(&"x".repeat(11), "value", 10).is_err());
        assert!(
            validate_string_arguments(&vec!["x".to_owned(); MAX_ARGUMENT_ITEMS + 1], "args")
                .is_err()
        );
    }
}
