use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, bail};
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer};
use runonmine_browser::{BrowserProfile, BrowserSession, browser_executable_available};
use runonmine_core::{
    AppConfig, AppPaths, ApprovalPrincipal, AuditOutcome, BrowserProfileMode, Capability,
    ConnectorKind, PolicyContext, PolicyEngine, PolicyMode, PrincipalContext,
};
use runonmine_platform::desktop;
use runonmine_platform::helper::{HelperAvailability, HelperClient};
use runonmine_platform::native;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use super::authorization::{
    OwnedPolicyResources, PreApprovalDecision, browser_authorization_arguments, policy_resources,
    pre_approval_decision, same_browser_policy_origin,
};
use super::runtime::{
    RequestAccess, RequestPrincipal, Runtime, diagnostic_category, oauth_scopes_allow_capability,
};
use super::{
    BROWSER_TOOLS, DESKTOP_CAPTURE_TOOLS, DESKTOP_INPUT_TOOLS, FILE_TOOLS, REQUEST_ACCESS,
    RunOnMineServer, TOOL_CAPABILITIES, argument_hash, authorization, browser_should_be_headless,
    diagnostics,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum HostnameState {
    Available { hostname: String },
    Disabled,
    Unavailable,
    PermissionDenied,
}

impl HostnameState {
    pub(super) fn detect(disabled: bool) -> Self {
        if disabled {
            return Self::Disabled;
        }
        match hostname::get() {
            Ok(hostname) => Self::Available {
                hostname: hostname.to_string_lossy().into_owned(),
            },
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                Self::PermissionDenied
            }
            Err(_) => Self::Unavailable,
        }
    }

    pub(super) fn value(&self) -> Option<&str> {
        match self {
            Self::Available { hostname } => Some(hostname),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(super) struct BrowserAuthorization {
    pub(super) arguments: Value,
    pub(super) current_url: Url,
}

struct ResolvedAuthorization<'a, T> {
    tool_name: &'a str,
    capability: Capability,
    summary: &'a str,
    arguments: &'a T,
    resources: OwnedPolicyResources,
    argument_hash: String,
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
    pub(super) fn new(runtime: Runtime) -> Result<Self> {
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
        let browser_available = matches!(browser_profile, BrowserProfile::ExternalCdp { .. })
            || browser_executable_available(app_config.browser.executable_path.as_deref());
        let browser = Arc::new(BrowserSession::with_executable_and_operation_timeout(
            browser_profile,
            browser_should_be_headless(),
            app_config.browser.allow_private_network && !remote_connector,
            runtime.0.max_output_bytes,
            app_config.browser.executable_path.clone(),
            Duration::from_secs(app_config.browser.operation_timeout_seconds),
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
            admin: HelperClient::for_current_user()
                .map_err(|error| HelperAvailability::from_error(&error)),
            tool_router,
            _session_permit: permit,
        })
    }

    pub(super) async fn authorize<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
    ) -> Result<(), McpError> {
        let resources = policy_resources(tool_name, arguments, &self.runtime.0.filesystem)
            .map_err(|_| {
                diagnostics::internal_error(
                    &self.runtime.0.connector_id,
                    diagnostics::DiagnosticCategory::Authorization,
                    "derive_policy_resources",
                    Some(tool_name),
                    None,
                    "Tool resources could not be safely authorized",
                )
            })?;
        let argument_hash = argument_hash(arguments).map_err(|_| {
            diagnostics::internal_error(
                &self.runtime.0.connector_id,
                diagnostics::DiagnosticCategory::Authorization,
                "serialize_authorization_arguments",
                Some(tool_name),
                None,
                "Tool arguments could not be safely authorized",
            )
        })?;
        self.authorize_resolved(ResolvedAuthorization {
            tool_name,
            capability,
            summary,
            arguments,
            resources,
            argument_hash,
        })
        .await
    }

    pub(super) async fn authorize_with_resources<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
        resources: OwnedPolicyResources,
    ) -> Result<(), McpError> {
        let argument_hash = resources.authorization_hash(arguments).map_err(|_| {
            diagnostics::internal_error(
                &self.runtime.0.connector_id,
                diagnostics::DiagnosticCategory::Authorization,
                "serialize_resource_authorization",
                Some(tool_name),
                None,
                "Tool arguments could not be safely authorized",
            )
        })?;
        self.authorize_resolved(ResolvedAuthorization {
            tool_name,
            capability,
            summary,
            arguments,
            resources,
            argument_hash,
        })
        .await
    }

    fn enforce_rate_limit<T: Serialize>(
        &self,
        request: &ResolvedAuthorization<'_, T>,
    ) -> Result<(), McpError> {
        let rate_limit_key = REQUEST_ACCESS
            .try_with(RequestAccess::rate_limit_key)
            .unwrap_or_else(|_| "stdio".to_owned());
        if self.runtime.check_rate_limit(&rate_limit_key).is_ok() {
            return Ok(());
        }
        self.runtime.audit().record(
            request.tool_name,
            request.capability,
            AuditOutcome::Denied,
            request.arguments,
            "rate limit reached",
        );
        Err(McpError::invalid_request(
            "Connector rate limit reached",
            None,
        ))
    }

    fn authorization_connector(
        &self,
        tool_name: &str,
    ) -> Result<runonmine_core::ConnectorConfig, McpError> {
        self.runtime.connector().map_err(|_| {
            diagnostics::log_internal(
                diagnostics::current_request_id(),
                &self.runtime.0.connector_id,
                diagnostics::DiagnosticCategory::ConnectorConfig,
                "load_connector_for_authorization",
                Some(tool_name),
                None,
            );
            McpError::invalid_request("Connector configuration is unavailable", None)
        })
    }

    fn authorization_modes<T>(
        connector: &runonmine_core::ConnectorConfig,
        access: Option<&RequestAccess>,
        request: &ResolvedAuthorization<'_, T>,
    ) -> Vec<PolicyMode> {
        let principal = match access.map(|item| &item.principal) {
            Some(RequestPrincipal::OAuth {
                client_id, subject, ..
            }) => PrincipalContext::OAuth { client_id, subject },
            _ => PrincipalContext::Local,
        };
        request
            .resources
            .contexts()
            .map(|resource| {
                PolicyEngine
                    .evaluate_context(
                        connector,
                        request.tool_name,
                        request.capability,
                        &PolicyContext {
                            principal: principal.clone(),
                            resource,
                        },
                    )
                    .mode
            })
            .collect()
    }

    async fn exact_grant_allows<T>(
        &self,
        connector_id: String,
        approval_principal: ApprovalPrincipal,
        request: &ResolvedAuthorization<'_, T>,
    ) -> bool {
        if let Ok(value) = self
            .runtime
            .0
            .store
            .grant_allows_async(
                connector_id,
                approval_principal,
                request.tool_name.to_owned(),
                request.argument_hash.clone(),
            )
            .await
        {
            value
        } else {
            diagnostics::log_internal(
                diagnostics::current_request_id(),
                &self.runtime.0.connector_id,
                diagnostics::DiagnosticCategory::Storage,
                "read_authorization_grant",
                Some(request.tool_name),
                None,
            );
            false
        }
    }

    async fn record_policy_decision<T>(
        &self,
        request: &ResolvedAuthorization<'_, T>,
        outcome: AuditOutcome,
    ) -> Result<(), McpError> {
        self.runtime
            .audit()
            .record_required(
                request.tool_name,
                request.capability,
                outcome,
                &request.argument_hash,
                request.summary,
            )
            .await
    }

    async fn authorize_resolved<T: Serialize>(
        &self,
        request: ResolvedAuthorization<'_, T>,
    ) -> Result<(), McpError> {
        self.enforce_rate_limit(&request)?;
        let connector = self.authorization_connector(request.tool_name)?;
        let access = REQUEST_ACCESS.try_with(Clone::clone).ok();
        let approval_principal = access.as_ref().map_or(
            ApprovalPrincipal::LocalStdio,
            RequestAccess::approval_principal,
        );
        let modes = Self::authorization_modes(&connector, access.as_ref(), &request);
        let grant_allows = self
            .exact_grant_allows(connector.id, approval_principal.clone(), &request)
            .await;

        match pre_approval_decision(modes, grant_allows) {
            PreApprovalDecision::Allow => {
                self.record_policy_decision(&request, AuditOutcome::Allowed)
                    .await
            }
            PreApprovalDecision::Deny => {
                self.record_policy_decision(&request, AuditOutcome::Denied)
                    .await?;
                Err(McpError::invalid_request(
                    "Tool is denied by local policy",
                    None,
                ))
            }
            PreApprovalDecision::Ask => {
                self.runtime
                    .approvals()
                    .request(
                        &approval_principal,
                        request.tool_name,
                        request.capability,
                        request.summary,
                        &request.argument_hash,
                        request.arguments,
                    )
                    .await
            }
        }
    }

    pub(super) async fn authorize_current_browser<T: Serialize>(
        &self,
        tool_name: &str,
        capability: Capability,
        summary: &str,
        arguments: &T,
    ) -> Result<BrowserAuthorization, McpError> {
        const MAX_ORIGIN_CHECKS: usize = 3;
        for _ in 0..MAX_ORIGIN_CHECKS {
            let current_url = self
                .browser
                .policy_url()
                .await
                .map_err(|_| self.tool_failed(tool_name, capability, arguments))?;
            let authorization_arguments = browser_authorization_arguments(arguments, &current_url)
                .map_err(|_| {
                    diagnostics::internal_error(
                        &self.runtime.0.connector_id,
                        diagnostics::DiagnosticCategory::Authorization,
                        "bind_browser_origin",
                        Some(tool_name),
                        None,
                        "Browser operation could not be safely authorized",
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
            let confirmed_url =
                self.browser.policy_url().await.map_err(|_| {
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

    pub(super) fn success<T: Serialize>(&self, value: &T) -> Result<CallToolResult, McpError> {
        let text = serde_json::to_string(value).map_err(|_| {
            diagnostics::internal_error(
                &self.runtime.0.connector_id,
                diagnostics::DiagnosticCategory::OutputEncoding,
                "serialize_tool_output",
                None,
                None,
                "Could not encode tool output",
            )
        })?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    pub(super) fn tool_failed(
        &self,
        tool_name: &str,
        capability: Capability,
        arguments: &impl Serialize,
    ) -> McpError {
        let audit_id = self.runtime.audit().record_with_reference(
            tool_name,
            capability,
            AuditOutcome::Failed,
            arguments,
            "tool failed",
        );
        diagnostics::tool_error(
            &self.runtime.0.connector_id,
            diagnostic_category(capability),
            "execute_tool",
            tool_name,
            audit_id,
        )
    }

    pub(super) fn request_access(context: &RequestContext<RoleServer>) -> Option<&RequestAccess> {
        context
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<RequestAccess>())
    }

    pub(super) fn request_allows_tool(
        &self,
        tool_name: &str,
        context: &RequestContext<RoleServer>,
    ) -> bool {
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
        oauth_scopes_allow_capability(scopes, *capability)
    }

    pub(super) async fn admin_helper_state(&self) -> HelperAvailability {
        match &self.admin {
            Ok(client) => tokio::time::timeout(Duration::from_secs(2), client.availability())
                .await
                .unwrap_or(HelperAvailability::Unavailable),
            Err(state) => state.clone(),
        }
    }

    pub(super) async fn admin_available(&self) -> bool {
        self.admin_helper_state()
            .await
            .allowlisted_programs()
            .is_some_and(|count| count > 0)
    }
}
