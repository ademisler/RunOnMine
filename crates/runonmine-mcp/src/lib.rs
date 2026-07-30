//! Policy-aware MCP server and local transports.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ListToolsResult, PaginatedRequestParams,
};
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, tool, tool_handler, tool_router,
};
use runonmine_browser::{BrowserProfile, BrowserSession, chromium_available};
use runonmine_core::filesystem::ScopedFilesystem;
use runonmine_core::process::{ProcessRequest, execute_shell};
use runonmine_core::secrets::SecretStore;
use runonmine_core::{
    AppConfig, AppPaths, ApprovalPrincipal, AuditOutcome, BrowserProfileMode, Capability,
    ConnectorConfig, ConnectorKind, PolicyContext, PolicyEngine, PolicyMode, PrincipalContext,
    StateStore,
};
use runonmine_oauth::{Scope, ScopeSet};
use runonmine_platform::desktop::{self, ScreenshotTarget};
use runonmine_platform::helper::{
    HelperClient, HelperRequest, HelperResult, MAX_TIMEOUT as MAX_ADMIN_TIMEOUT,
};
use runonmine_platform::native::{self, DbusCall};
use serde::Serialize;
use serde_json::{Value, json};
use url::Url;

mod approval_flow;
mod audit;
mod http;
mod managed_connectors;
mod rate_limit;
mod session;
use approval_flow::ApprovalFlow;
use audit::AuditRecorder;
pub use http::serve_loopback;
use rate_limit::PrincipalRateLimiter;
use session::{IdleSessionManager, SessionPermit};

pub const SERVER_NAME: &str = "runonmine";
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
    audit: AuditRecorder,
    approvals: ApprovalFlow,
    filesystem: ScopedFilesystem,
    process_timeout: Duration,
    max_process_timeout: Duration,
    max_output_bytes: usize,
    rate_limiter: PrincipalRateLimiter,
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

impl RequestAccess {
    fn rate_limit_key(&self) -> String {
        match &self.principal {
            RequestPrincipal::LocalHttp => "local_http".to_owned(),
            RequestPrincipal::QuickTunnel => "quick_tunnel".to_owned(),
            RequestPrincipal::OAuth { client_id, .. } => format!("oauth:{client_id}"),
        }
    }

    fn approval_principal(&self) -> ApprovalPrincipal {
        match &self.principal {
            RequestPrincipal::LocalHttp => ApprovalPrincipal::LocalHttp,
            RequestPrincipal::QuickTunnel => ApprovalPrincipal::QuickTunnel,
            RequestPrincipal::OAuth {
                client_id, subject, ..
            } => ApprovalPrincipal::OAuth {
                client_id: client_id.clone(),
                subject: subject.clone(),
            },
        }
    }
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
        let audit = AuditRecorder::new(connector_id, store.clone());
        let approvals = ApprovalFlow::new(
            connector_id,
            store.clone(),
            audit.clone(),
            Duration::from_secs(config.limits.approval_timeout_seconds),
        );
        Ok(Self(Arc::new(RuntimeInner {
            config_path: paths.config_file(),
            connector_id: connector_id.to_owned(),
            audit,
            approvals,
            store,
            filesystem,
            process_timeout: Duration::from_secs(config.limits.default_process_timeout_seconds),
            max_process_timeout: Duration::from_secs(config.limits.max_process_timeout_seconds),
            max_output_bytes: config.limits.max_output_bytes,
            rate_limiter: PrincipalRateLimiter::new(
                usize::try_from(config.limits.calls_per_minute).unwrap_or(usize::MAX),
            ),
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
        SessionPermit::acquire(&self.0.active_sessions, self.0.max_sessions)
    }

    fn check_rate_limit(&self, principal: &str) -> Result<()> {
        self.0.rate_limiter.check(principal)
    }

    fn audit(&self) -> &AuditRecorder {
        &self.0.audit
    }

    fn approvals(&self) -> &ApprovalFlow {
        &self.0.approvals
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

#[derive(Debug)]
struct BrowserAuthorization {
    arguments: Value,
    current_url: Url,
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

    async fn authorize<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
    ) -> Result<(), McpError> {
        let resources = policy_resources(tool_name, arguments, &self.runtime.0.filesystem)
            .map_err(|error| {
                tracing::error!(%error, "failed to derive policy resources");
                McpError::internal_error("Tool resources could not be safely authorized", None)
            })?;
        let argument_hash = argument_hash(arguments).map_err(|error| {
            tracing::error!(%error, "failed to serialize tool arguments for authorization");
            McpError::internal_error("Tool arguments could not be safely authorized", None)
        })?;
        self.authorize_resolved(
            tool_name,
            capability,
            summary,
            arguments,
            resources,
            argument_hash,
        )
        .await
    }

    async fn authorize_with_resources<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
        resources: OwnedPolicyResources,
    ) -> Result<(), McpError> {
        let argument_hash = resources.authorization_hash(arguments).map_err(|error| {
            tracing::error!(%error, "failed to serialize resource-bound authorization identity");
            McpError::internal_error("Tool arguments could not be safely authorized", None)
        })?;
        self.authorize_resolved(
            tool_name,
            capability,
            summary,
            arguments,
            resources,
            argument_hash,
        )
        .await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn authorize_resolved<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
        resources: OwnedPolicyResources,
        argument_hash: String,
    ) -> Result<(), McpError> {
        let rate_limit_key = REQUEST_ACCESS
            .try_with(RequestAccess::rate_limit_key)
            .unwrap_or_else(|_| "stdio".to_owned());
        if self.runtime.check_rate_limit(&rate_limit_key).is_err() {
            self.runtime.audit().record(
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
        let access = REQUEST_ACCESS.try_with(Clone::clone).ok();
        let approval_principal = access.as_ref().map_or(
            ApprovalPrincipal::LocalStdio,
            RequestAccess::approval_principal,
        );
        let principal = match access.as_ref().map(|item| &item.principal) {
            Some(RequestPrincipal::OAuth {
                client_id, subject, ..
            }) => PrincipalContext::OAuth { client_id, subject },
            _ => PrincipalContext::Local,
        };
        let modes = resources
            .contexts()
            .map(|resource| {
                PolicyEngine
                    .evaluate_context(
                        &connector,
                        tool_name,
                        capability,
                        &PolicyContext {
                            principal: principal.clone(),
                            resource,
                        },
                    )
                    .mode
            })
            .collect::<Vec<_>>();
        let grant_allows = self
            .runtime
            .0
            .store
            .grant_allows_async(
                connector.id.clone(),
                approval_principal.clone(),
                tool_name.to_owned(),
                argument_hash.clone(),
            )
            .await
            .unwrap_or(false);
        match pre_approval_decision(modes, grant_allows) {
            PreApprovalDecision::Allow => {
                self.runtime
                    .audit()
                    .record_required(
                        tool_name,
                        capability,
                        AuditOutcome::Allowed,
                        &argument_hash,
                        summary,
                    )
                    .await?;
                return Ok(());
            }
            PreApprovalDecision::Deny => {
                self.runtime
                    .audit()
                    .record_required(
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
            PreApprovalDecision::Ask => {}
        }

        self.runtime
            .approvals()
            .request(
                &approval_principal,
                tool_name,
                capability,
                summary,
                &argument_hash,
                arguments,
            )
            .await
    }

    async fn authorize_current_browser<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
    ) -> Result<BrowserAuthorization, McpError> {
        const MAX_ORIGIN_CHECKS: usize = 3;
        for _ in 0..MAX_ORIGIN_CHECKS {
            let current_url = self.browser.policy_url().await.map_err(|error| {
                tracing::error!(%error, tool_name, "failed to read current browser policy URL");
                self.tool_failed(tool_name, capability, arguments)
            })?;
            let authorization_arguments =
                browser_authorization_arguments(arguments, &current_url).map_err(|error| {
                    tracing::error!(%error, tool_name, "failed to bind browser origin to arguments");
                    McpError::internal_error(
                        "Browser operation could not be safely authorized",
                        None,
                    )
                })?;
            self.authorize_with_resources(
                tool_name,
                capability,
                summary,
                &authorization_arguments,
                OwnedPolicyResources::browser(current_url.clone()),
            )
            .await?;
            let confirmed_url = self.browser.policy_url().await.map_err(|error| {
                tracing::error!(%error, tool_name, "failed to confirm current browser policy URL");
                self.tool_failed(tool_name, capability, &authorization_arguments)
            })?;
            if same_browser_policy_origin(&current_url, &confirmed_url) {
                return Ok(BrowserAuthorization {
                    arguments: authorization_arguments,
                    current_url: confirmed_url,
                });
            }
            tracing::warn!(
                tool_name,
                previous_origin = %authorization::browser_policy_origin(&current_url),
                current_origin = %authorization::browser_policy_origin(&confirmed_url),
                "browser origin changed during authorization; evaluating the new origin"
            );
        }
        self.runtime.audit().record(
            tool_name,
            capability,
            AuditOutcome::Denied,
            arguments,
            "browser origin changed repeatedly during authorization",
        );
        Err(McpError::invalid_request(
            "Browser page changed during authorization; retry the operation",
            None,
        ))
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
        self.runtime.audit().record(
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
use authorization::{
    OwnedPolicyResources, PreApprovalDecision, browser_authorization_arguments, policy_resources,
    pre_approval_decision, same_browser_policy_origin,
};

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
                self.runtime.audit().record(
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
        let authorization = self
            .authorize_current_browser(
                "browser_get_url",
                Capability::BrowserRead,
                "read the browser URL",
                &arguments,
            )
            .await?;
        Self::success(&json!({"url": authorization.current_url.as_str()}))
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
        let authorization = self
            .authorize_current_browser(
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
            Err(_) => Err(self.tool_failed(
                "browser_get_text",
                Capability::BrowserRead,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
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
            Err(_) => Err(self.tool_failed(
                "browser_snapshot",
                Capability::BrowserRead,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
                "browser_click",
                Capability::BrowserAct,
                "click a browser element",
                &arguments,
            )
            .await?;
        match self.browser.click(&arguments.selector).await {
            Ok(()) => Self::success(&json!({"clicked": true})),
            Err(_) => Err(self.tool_failed(
                "browser_click",
                Capability::BrowserAct,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
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
            Err(_) => Err(self.tool_failed(
                "browser_type",
                Capability::BrowserAct,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
                "browser_press",
                Capability::BrowserAct,
                "press a browser key",
                &arguments,
            )
            .await?;
        match self.browser.press(&arguments.key).await {
            Ok(()) => Self::success(&json!({"pressed": true})),
            Err(_) => Err(self.tool_failed(
                "browser_press",
                Capability::BrowserAct,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
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
            Err(_) => Err(self.tool_failed(
                "browser_screenshot",
                Capability::BrowserRead,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
                "browser_evaluate",
                Capability::BrowserAct,
                "evaluate browser JavaScript (content withheld)",
                &arguments,
            )
            .await?;
        match self.browser.evaluate(&arguments.expression).await {
            Ok(value) => Self::success(&value),
            Err(_) => Err(self.tool_failed(
                "browser_evaluate",
                Capability::BrowserAct,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
                "browser_close",
                Capability::BrowserAct,
                "close the browser session",
                &arguments,
            )
            .await?;
        match self.browser.close().await {
            Ok(()) => Self::success(&json!({"closed": true})),
            Err(_) => Err(self.tool_failed(
                "browser_close",
                Capability::BrowserAct,
                &authorization.arguments,
            )),
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
        let authorization = self
            .authorize_current_browser(
                "browser_profile_info",
                Capability::BrowserRead,
                "read browser profile information",
                &arguments,
            )
            .await?;
        match self.browser.info().await {
            Ok(info) => Self::success(&info),
            Err(_) => Err(self.tool_failed(
                "browser_profile_info",
                Capability::BrowserRead,
                &authorization.arguments,
            )),
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

pub async fn serve_stdio(connector_id: &str) -> Result<()> {
    let server = RunOnMineServer::new(Runtime::load(connector_id)?)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

fn required_secret(store: &dyn SecretStore, name: &str) -> Result<secrecy::SecretString> {
    store
        .get(name)?
        .with_context(|| format!("required credential {name} is missing"))
}

#[allow(clippy::too_many_lines)]
mod validation;
#[cfg(test)]
use validation::approval_preview;
use validation::{
    argument_hash, browser_should_be_headless, validate_dbus_arguments, validate_nonempty_text,
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
    fn every_current_page_browser_handler_uses_origin_authorization() -> Result<()> {
        let source = include_str!("lib.rs");
        for tool in [
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
        ] {
            let start = source
                .find(&format!("async fn {tool}("))
                .ok_or_else(|| anyhow::anyhow!("missing handler {tool}"))?;
            let remainder = &source[start..];
            let end = remainder.find("\n    #[tool(").unwrap_or(remainder.len());
            assert!(
                remainder[..end].contains("authorize_current_browser"),
                "{tool} does not bind the current browser origin"
            );
        }
        Ok(())
    }

    #[test]
    fn browser_approval_preview_includes_current_origin() {
        let preview = approval_preview(
            "browser_click",
            &json!({
                "selector": "#submit",
                "current_origin": "https://example.com"
            }),
        );
        assert!(preview.contains("Origin: https://example.com"));
        assert!(preview.contains("Selector: #submit"));
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
