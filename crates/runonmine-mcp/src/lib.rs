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
    AppConfig, AppPaths, ApprovalRequest, ApprovalStatus, AuditEvent, AuditOutcome, Capability,
    ConnectorConfig, ConnectorKind, PolicyEngine, PolicyMode, StateStore,
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
use schemars::JsonSchema;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::json;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex as AsyncMutex;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;
use url::Url;

pub const SERVER_NAME: &str = "runonmine";
const MCP_BODY_LIMIT: usize = 2 * 1_024 * 1_024;
const MCP_CONCURRENCY_LIMIT: usize = 64;

tokio::task_local! {
    static REQUEST_RUNTIME: Runtime;
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
    calls: Mutex<VecDeque<Instant>>,
    max_sessions: usize,
    active_sessions: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
struct Runtime(Arc<RuntimeInner>);

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequestPrincipal {
    Local,
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
    local: Option<Runtime>,
    quick: Option<QuickHttpConnector>,
    oauth: Option<OAuthHttpConnector>,
    agent_port: u16,
    session_idle_ttl: Duration,
    sessions: Arc<AsyncMutex<HashMap<String, SessionBinding>>>,
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
            calls: Mutex::new(VecDeque::new()),
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

    fn check_rate_limit(&self) -> Result<()> {
        let mut calls = self
            .0
            .calls
            .lock()
            .map_err(|_| anyhow::anyhow!("rate limit lock failed"))?;
        let now = Instant::now();
        let cutoff = now.checked_sub(Duration::from_mins(1)).unwrap_or(now);
        while calls.front().is_some_and(|instant| *instant < cutoff) {
            calls.pop_front();
        }
        if calls.len() >= self.0.calls_per_minute {
            bail!("connector rate limit reached");
        }
        calls.push_back(Instant::now());
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
        let browser_profile = match app_config.browser.external_cdp_url.clone() {
            Some(endpoint) => BrowserProfile::external(endpoint)?,
            None => BrowserProfile::Isolated {
                directory: paths
                    .browser_profiles()
                    .join(&app_config.browser.profile_name)
                    .join(&connector.id)
                    .join(uuid::Uuid::new_v4().to_string()),
            },
        };
        let browser_available =
            matches!(browser_profile, BrowserProfile::ExternalCdp { .. }) || chromium_available();
        let browser = Arc::new(BrowserSession::new(
            browser_profile,
            browser_should_be_headless(),
            app_config.browser.allow_private_network,
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
        if self.runtime.check_rate_limit().is_err() {
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
        let argument_hash = argument_hash(arguments);
        let mode = PolicyEngine
            .evaluate(&connector, tool_name, capability)
            .mode;
        if mode == PolicyMode::Allow
            || self
                .runtime
                .0
                .store
                .temporary_grant_allows(&connector.id, tool_name, &argument_hash)
                .unwrap_or(false)
        {
            self.audit_authorization_required(
                tool_name,
                capability,
                AuditOutcome::Allowed,
                &argument_hash,
                summary,
            )?;
            return Ok(());
        }
        if mode == PolicyMode::Deny {
            self.audit_with_hash(
                tool_name,
                capability,
                AuditOutcome::Denied,
                &argument_hash,
                summary,
            );
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
            .insert_approval(&approval)
            .map_err(|_| {
                McpError::internal_error("Could not create a local approval request", None)
            })?;
        if let Err(error) = self.audit_authorization_required(
            tool_name,
            capability,
            AuditOutcome::PendingApproval,
            &argument_hash,
            summary,
        ) {
            let _ignored = self
                .runtime
                .0
                .store
                .resolve_approval(approval.id, runonmine_core::ApprovalDecision::Deny);
            return Err(error);
        }
        let deadline = Instant::now() + self.runtime.0.approval_timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(McpError::invalid_request("Local approval timed out", None));
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            let status = self
                .runtime
                .0
                .store
                .approval_status(approval.id)
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
                    )?;
                    return Ok(());
                }
                ApprovalStatus::Denied => {
                    return Err(McpError::invalid_request(
                        "Denied by the machine owner",
                        None,
                    ));
                }
                ApprovalStatus::Expired => {
                    return Err(McpError::invalid_request("Local approval timed out", None));
                }
                ApprovalStatus::Pending => {}
            }
        }
    }

    fn audit_authorization_required(
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
        match self.runtime.0.store.append_audit(&event) {
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
        self.audit_with_hash(
            tool_name,
            capability,
            outcome,
            &argument_hash(arguments),
            summary,
        );
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
        if let Err(error) = self.runtime.0.store.append_audit(&event) {
            tracing::error!(%error, "failed to append audit event");
        }
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

#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
struct EmptyArgs {}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct PathArgs {
    path: PathBuf,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct ReadArgs {
    path: PathBuf,
    #[serde(default = "default_read_limit")]
    max_bytes: usize,
}

fn default_read_limit() -> usize {
    256 * 1_024
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct SearchArgs {
    root: PathBuf,
    query: String,
    #[serde(default = "default_search_limit")]
    limit: usize,
}

fn default_search_limit() -> usize {
    100
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct WriteArgs {
    path: PathBuf,
    content: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct PatchArgs {
    path: PathBuf,
    old_text: String,
    new_text: String,
    #[serde(default = "one")]
    expected_replacements: usize,
}

const fn one() -> usize {
    1
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct MoveArgs {
    from: PathBuf,
    to: PathBuf,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct ShellArgs {
    command: String,
    cwd: Option<PathBuf>,
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct AdminExecArgs {
    program: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DesktopListArgs {
    #[serde(default = "default_window_limit")]
    limit: usize,
}

const fn default_window_limit() -> usize {
    100
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DesktopWindowArgs {
    window_id: u32,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DesktopScreenshotArgs {
    monitor_id: Option<u32>,
    window_id: Option<u32>,
    #[serde(default = "default_image_quality")]
    quality: u8,
    #[serde(default = "default_desktop_image_dimension")]
    max_dimension: u32,
}

const fn default_desktop_image_dimension() -> u32 {
    2_048
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DesktopClickArgs {
    x: i32,
    y: i32,
    #[serde(default = "default_mouse_button")]
    button: String,
}

fn default_mouse_button() -> String {
    "left".to_owned()
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DesktopTypeArgs {
    text: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DesktopKeyArgs {
    key: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct PlatformScriptArgs {
    script: String,
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct DbusCallArgs {
    destination: String,
    object_path: String,
    interface: String,
    method: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    arguments: Vec<String>,
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct UrlArgs {
    url: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct SelectorArgs {
    selector: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct TypeArgs {
    selector: String,
    text: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct KeyArgs {
    key: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct ScreenshotArgs {
    #[serde(default = "default_image_quality")]
    quality: u8,
    #[serde(default)]
    full_page: bool,
}

const fn default_image_quality() -> u8 {
    70
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
struct EvaluateArgs {
    expression: String,
}

#[derive(Debug, Serialize)]
struct ReadOutput {
    content: String,
    truncated: bool,
}

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
        let hostname = hostname::get().ok().map_or_else(
            || "unknown".to_owned(),
            |value| value.to_string_lossy().into_owned(),
        );
        let admin_allowlisted_programs = self.admin_allowlisted_programs().await.unwrap_or(0);
        Self::success(&json!({
            "hostname": hostname,
            "os": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "allowed_roots": self.runtime.0.filesystem.roots(),
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
        Parameters(arguments): Parameters<PathArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.authorize(
            "fs_list",
            Capability::FilesRead,
            "list a selected directory",
            &arguments,
        )
        .await?;
        match self.runtime.0.filesystem.list(&arguments.path) {
            Ok(entries) => Self::success(&entries),
            Err(_) => Err(self.tool_failed("fs_list", Capability::FilesRead, &arguments)),
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
        match self.runtime.0.filesystem.read_text(&arguments.path, limit) {
            Ok((content, truncated)) => Self::success(&ReadOutput { content, truncated }),
            Err(_) => Err(self.tool_failed("fs_read", Capability::FilesRead, &arguments)),
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
        let limit = arguments.limit.clamp(1, 1_000);
        match self
            .runtime
            .0
            .filesystem
            .search_names(&arguments.root, &arguments.query, limit)
        {
            Ok(matches) => Self::success(&matches),
            Err(_) => Err(self.tool_failed("fs_search", Capability::FilesRead, &arguments)),
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
        match self
            .runtime
            .0
            .filesystem
            .write_atomic(&arguments.path, arguments.content.as_bytes())
        {
            Ok(path) => Self::success(&json!({"path": path, "bytes": arguments.content.len()})),
            Err(_) => Err(self.tool_failed("fs_write", Capability::FilesWrite, &arguments)),
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
        if arguments.old_text.is_empty() || arguments.expected_replacements == 0 {
            return Err(McpError::invalid_params(
                "Patch match and replacement count are required",
                None,
            ));
        }
        let result = (|| -> Result<usize> {
            let (content, truncated) = self
                .runtime
                .0
                .filesystem
                .read_text(&arguments.path, self.runtime.0.max_output_bytes)?;
            if truncated {
                bail!("file exceeds the patch limit");
            }
            let count = content.matches(&arguments.old_text).count();
            if count != arguments.expected_replacements {
                bail!("patch match count differs from the expected count");
            }
            let updated = content.replacen(
                &arguments.old_text,
                &arguments.new_text,
                arguments.expected_replacements,
            );
            self.runtime
                .0
                .filesystem
                .write_atomic(&arguments.path, updated.as_bytes())?;
            Ok(count)
        })();
        match result {
            Ok(replacements) => Self::success(&json!({"replacements": replacements})),
            Err(_) => Err(self.tool_failed("fs_patch", Capability::FilesWrite, &arguments)),
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
        match self
            .runtime
            .0
            .filesystem
            .move_path(&arguments.from, &arguments.to)
        {
            Ok(()) => Self::success(&json!({"moved": true})),
            Err(_) => Err(self.tool_failed("fs_move", Capability::FilesWrite, &arguments)),
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
        match self.runtime.0.filesystem.move_to_trash(&arguments.path) {
            Ok(()) => Self::success(&json!({"trashed": true})),
            Err(_) => Err(self.tool_failed("fs_delete", Capability::FilesWrite, &arguments)),
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
            Ok(mut text) => {
                text.truncate(self.runtime.0.max_output_bytes);
                Self::success(&json!({"text": text}))
            }
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
            Ok(mut html) => {
                html.truncate(self.runtime.0.max_output_bytes);
                Self::success(&json!({"html": html}))
            }
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
    version = "0.1.0-beta.1",
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
    let service = StreamableHttpService::new(
        || {
            REQUEST_RUNTIME
                .try_with(|runtime| RunOnMineServer::new(runtime.clone()))
                .map_err(|_| std::io::Error::other("MCP request connector context is missing"))?
                .map_err(|_| std::io::Error::other("MCP session initialization failed"))
        },
        Arc::new(IdleSessionManager::new(connector_state.session_idle_ttl)),
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
    managed_connectors.stop().await;
    result.map_err(Into::into)
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
            ConnectorKind::LocalHttp => local = Some(Runtime::load(&connector.id)?),
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

fn validate_quick_path_secret(value: &str) -> Result<()> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .context("Quick Tunnel path secret is invalid")?;
    if decoded.len() != 32 {
        bail!("Quick Tunnel path secret must contain 256 bits");
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
    let response = REQUEST_RUNTIME.scope(runtime, next.run(request)).await;
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
                principal: RequestPrincipal::Local,
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
        return Ok((
            local.clone(),
            RequestAccess {
                connector_id: local.0.connector_id.clone(),
                principal: RequestPrincipal::Local,
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
fn bearer_token<'a>(request: &'a Request, resource_metadata: &Url) -> Result<&'a str, Response> {
    let Some(value) = request.headers().get(AUTHORIZATION) else {
        return Err(unauthorized(resource_metadata));
    };
    let value = value
        .to_str()
        .map_err(|_| unauthorized(resource_metadata))?;
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(unauthorized(resource_metadata));
    };
    if token.is_empty() || token.contains(char::is_whitespace) {
        return Err(unauthorized(resource_metadata));
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
fn approval_preview(tool_name: &str, arguments: &impl Serialize) -> String {
    let value = serde_json::to_value(arguments).unwrap_or(serde_json::Value::Null);
    let string = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    };
    let path = |name: &str| string(name);
    let preview = match tool_name {
        "fs_list" | "fs_read" | "fs_delete" => format!("Path: {}", path("path")),
        "fs_search" => format!(
            "Root: {}\nQuery: {}",
            path("root"),
            redact_preview_text(string("query"))
        ),
        "fs_write" => format!(
            "Path: {}\nNew content: {} bytes\nPreview: {}",
            path("path"),
            string("content").len(),
            redact_preview_text(string("content"))
        ),
        "fs_patch" => format!(
            "Path: {}\nExpected replacements: {}\nReplace: {}\nWith: {}",
            path("path"),
            value
                .get("expected_replacements")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1),
            redact_preview_text(string("old_text")),
            redact_preview_text(string("new_text"))
        ),
        "fs_move" => format!("From: {}\nTo: {}", path("from"), path("to")),
        "shell_exec" => format!(
            "Command: {}\nWorking directory: {}",
            redact_preview_text(string("command")),
            value
                .get("cwd")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("current directory")
        ),
        "admin_exec" => format!(
            "Privileged program: {}\nArguments: {}",
            path("program"),
            redact_preview_text(
                &value
                    .get("args")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(serde_json::Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default()
            )
        ),
        "desktop_focus_window" => format!("Window ID: {}", value["window_id"]),
        "desktop_screenshot" => format!(
            "Capture screenshot\nMonitor: {}\nWindow: {}",
            value.get("monitor_id").unwrap_or(&serde_json::Value::Null),
            value.get("window_id").unwrap_or(&serde_json::Value::Null)
        ),
        "desktop_click" => format!(
            "Click at ({}, {}) with {} button",
            value["x"],
            value["y"],
            string("button")
        ),
        "desktop_type" => format!(
            "Type {} characters\nText: {}",
            string("text").chars().count(),
            redact_preview_text(string("text"))
        ),
        "desktop_key" | "browser_press" => format!("Key: {}", string("key")),
        "macos_applescript" | "windows_powershell" => format!(
            "Script ({} characters):\n{}",
            string("script").chars().count(),
            redact_preview_text(string("script"))
        ),
        "linux_dbus_call" => format!(
            "D-Bus: {} {}.{} on {}",
            string("destination"),
            string("interface"),
            string("method"),
            string("object_path")
        ),
        "browser_open" | "browser_navigate" => format!("URL: {}", string("url")),
        "browser_click" => format!("Selector: {}", string("selector")),
        "browser_type" => format!(
            "Selector: {}\nType {} characters\nText: {}",
            string("selector"),
            string("text").chars().count(),
            redact_preview_text(string("text"))
        ),
        "browser_evaluate" => format!(
            "JavaScript ({} characters):\n{}",
            string("expression").chars().count(),
            redact_preview_text(string("expression"))
        ),
        _ => tool_name.replace('_', " "),
    };
    truncate_preview(&preview, 1_500)
}

fn redact_preview_text(input: &str) -> String {
    let mut output = truncate_preview(input, 1_024);
    for marker in [
        "authorization:",
        "bearer ",
        "token=",
        "access_token=",
        "refresh_token=",
        "password=",
        "passwd=",
        "secret=",
        "client_secret=",
        "api_key=",
        "apikey=",
    ] {
        let mut search_from = 0;
        loop {
            let lower = output.to_ascii_lowercase();
            let Some(relative_start) = lower[search_from..].find(marker) else {
                break;
            };
            let start = search_from + relative_start;
            let value_start = start + marker.len();
            let value_end = output[value_start..]
                .find(|character: char| character.is_whitespace() || matches!(character, '&' | ';'))
                .map_or(output.len(), |offset| value_start + offset);
            if value_start >= value_end {
                search_from = value_start;
                continue;
            }
            if &output[value_start..value_end] != "[REDACTED]" {
                output.replace_range(value_start..value_end, "[REDACTED]");
            }
            search_from = value_start + "[REDACTED]".len();
        }
    }
    output
}

fn truncate_preview(value: &str, maximum_chars: usize) -> String {
    let mut output = value.chars().take(maximum_chars).collect::<String>();
    if value.chars().count() > maximum_chars {
        output.push('…');
    }
    output
}

const fn capability_requires_reliable_audit(capability: Capability) -> bool {
    matches!(
        capability,
        Capability::FilesWrite
            | Capability::ShellExec
            | Capability::BrowserAct
            | Capability::DesktopControl
            | Capability::PlatformNative
            | Capability::AdminExec
    )
}

fn argument_hash(value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    blake3::hash(&bytes).to_hex().to_string()
}

const fn capability_name(capability: Capability) -> &'static str {
    match capability {
        Capability::SystemRead => "system_read",
        Capability::FilesRead => "files_read",
        Capability::FilesWrite => "files_write",
        Capability::ShellExec => "shell_exec",
        Capability::BrowserRead => "browser_read",
        Capability::BrowserAct => "browser_act",
        Capability::DesktopControl => "desktop_control",
        Capability::PlatformNative => "platform_native",
        Capability::AdminExec => "admin_exec",
    }
}

fn browser_should_be_headless() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_hash_does_not_expose_arguments() {
        let hash = argument_hash(&json!({"token": "secret-value"}));
        assert_eq!(hash.len(), 64);
        assert!(!hash.contains("secret-value"));
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
}
