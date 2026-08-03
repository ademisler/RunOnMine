//! Policy-aware MCP server and local transports.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::tool::ToolCallContext;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
    PaginatedRequestParams,
};
use rmcp::service::RequestContext;
use rmcp::transport::stdio;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt, tool, tool_handler, tool_router,
};
use runonmine_browser::{BrowserSession, reap_orphaned_browser_sessions};
use runonmine_core::process::{ProcessRequest, execute_shell};
use runonmine_core::secrets::{
    SecretStore, default_secret_store, recover_pending_config_secret_transaction,
};
use runonmine_core::{AppConfig, AppPaths, AuditOutcome, Capability, ConnectorKind};
use runonmine_platform::desktop::{self, ScreenshotTarget};
use runonmine_platform::helper::{
    HelperAvailability, HelperClient, HelperRequest, HelperResult, MAX_TIMEOUT as MAX_ADMIN_TIMEOUT,
};
use runonmine_platform::native::{self, DbusCall};
use serde_json::json;

mod approval_flow;
mod audit;
mod connector_removal;
mod diagnostics;
#[doc(hidden)]
pub mod fuzzing;
mod http;
mod managed_connectors;
mod rate_limit;
mod session;
pub use http::serve_loopback;
use session::{IdleSessionManager, SessionPermit};

#[path = "mcp/runtime.rs"]
mod runtime;
#[path = "mcp/server.rs"]
mod server;

#[cfg(test)]
use runonmine_oauth::ScopeSet;
use runtime::{RequestAccess, RequestPrincipal, Runtime, oauth_scope_for_capability};
#[cfg(test)]
use runtime::{load_enabled_connector, oauth_scopes_allow_capability};
use server::HostnameState;

pub const SERVER_NAME: &str = "runonmine";
pub use connector_removal::{
    ensure_connector_id_available, reconcile_pending_connector_removals,
    remove_connector_recoverably,
};
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

#[derive(Clone)]
pub struct RunOnMineServer {
    runtime: Runtime,
    browser: Arc<BrowserSession>,
    admin: Result<HelperClient, HelperAvailability>,
    tool_router: ToolRouter<Self>,
    _session_permit: Arc<SessionPermit>,
}

mod authorization;
use authorization::{OwnedPolicyResources, canonical_shell_working_directory};

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
            diagnostics::internal_error(
                &self.runtime.0.connector_id,
                diagnostics::DiagnosticCategory::ConnectorConfig,
                "load_connector_for_machine_info",
                Some("machine_info"),
                None,
                "Connector configuration is unavailable",
            )
        })?;
        let remote_connector = matches!(
            connector.kind,
            ConnectorKind::CloudflareQuick
                | ConnectorKind::CloudflareOauth
                | ConnectorKind::OpenAiTunnel
        );
        let hostname_state = HostnameState::detect(remote_connector);
        let hostname = hostname_state.value();
        let allowed_roots = (!remote_connector).then(|| self.runtime.0.filesystem.roots());
        let admin_helper_state = self.admin_helper_state().await;
        let admin_allowlisted_programs = admin_helper_state.allowlisted_programs().unwrap_or(0);
        self.success(&json!({
            "hostname": hostname,
            "hostname_state": hostname_state,
            "os": std::env::consts::OS,
            "architecture": std::env::consts::ARCH,
            "allowed_roots": allowed_roots,
            "allowed_root_count": self.runtime.0.filesystem.roots().len(),
            "admin_helper": admin_allowlisted_programs > 0,
            "admin_helper_state": admin_helper_state,
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
            Ok(Ok(entries)) => self.success(&entries),
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
            Ok(Ok((content, truncated))) => self.success(&ReadOutput { content, truncated }),
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
            Ok(Ok(matches)) => self.success(&matches),
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
            Ok(Ok(path)) => self.success(&json!({"path": path, "bytes": arguments.content.len()})),
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
            Ok(Ok(replacements)) => self.success(&json!({"replacements": replacements})),
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
            Ok(Ok(())) => self.success(&json!({"moved": true})),
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
            Ok(Ok(())) => self.success(&json!({"trashed": true})),
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
        let mut arguments = arguments;
        validate_nonempty_text(&arguments.command, "Shell command", MAX_COMMAND_BYTES)?;
        validate_optional_path(arguments.cwd.as_deref(), "Shell working directory")?;
        let canonical_cwd =
            canonical_shell_working_directory(arguments.cwd.as_deref()).map_err(|error| {
                let _ignored = error;
                tracing::warn!("rejected invalid shell working directory");
                McpError::invalid_params("Shell working directory is unavailable", None)
            })?;
        arguments.cwd = Some(canonical_cwd.clone());
        self.authorize_with_resources(
            "shell_exec",
            Capability::ShellExec,
            "run a user shell command (content withheld)",
            &arguments,
            OwnedPolicyResources::shell(arguments.command.clone(), canonical_cwd),
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
                self.success(&output)
            }
            Err(_) => Err(self.tool_failed("shell_exec", Capability::ShellExec, &arguments)),
        }
    }

    #[tool(
        description = "Run one root/SYSTEM-owned, SHA-256-pinned executable only when its complete argument vector matches an installed privileged command profile",
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
            .map_err(|_| McpError::invalid_request("Privileged helper is unavailable", None))?;
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
                .map_err(|_| {
                    diagnostics::internal_error(
                        &self.runtime.0.connector_id,
                        diagnostics::DiagnosticCategory::PrivilegedHelper,
                        "helper_request_timeout",
                        Some("admin_exec"),
                        None,
                        "Privileged helper timed out",
                    )
                })?
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
                    .map_err(|_| {
                        diagnostics::internal_error(
                            &self.runtime.0.connector_id,
                            diagnostics::DiagnosticCategory::PrivilegedHelper,
                            "decode_helper_stdout",
                            Some("admin_exec"),
                            None,
                            "Invalid helper response",
                        )
                    })?;
                let stderr = base64::engine::general_purpose::STANDARD
                    .decode(stderr_base64)
                    .map_err(|_| {
                        diagnostics::internal_error(
                            &self.runtime.0.connector_id,
                            diagnostics::DiagnosticCategory::PrivilegedHelper,
                            "decode_helper_stderr",
                            Some("admin_exec"),
                            None,
                            "Invalid helper response",
                        )
                    })?;
                self.success(&json!({
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
            Ok(Ok(windows)) => self.success(&windows),
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
            Ok(Ok(())) => self.success(&json!({"focused": true})),
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
            Ok(Ok(())) => self.success(&json!({"clicked": true})),
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
            Ok(Ok(())) => self.success(&json!({"typed": true})),
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
            Ok(Ok(())) => self.success(&json!({"pressed": true})),
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
            Ok(output) => self.success(&output),
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
            Ok(output) => self.success(&output),
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
            Ok(output) => self.success(&output),
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
            Ok(url) => self.success(&json!({"url": url})),
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
            Ok(url) => self.success(&json!({"url": url})),
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
        self.success(&json!({"url": authorization.current_url.as_str()}))
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
            Ok(text) => self.success(&json!({
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
            Ok(html) => self.success(&json!({
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
            Ok(()) => self.success(&json!({"clicked": true})),
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
            Ok(()) => self.success(&json!({"typed": true})),
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
            Ok(()) => self.success(&json!({"pressed": true})),
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
            Ok(value) => self.success(&value),
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
            Ok(()) => self.success(&json!({"closed": true})),
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
            Ok(info) => self.success(&info),
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
    ) -> Result<CallToolResponse, McpError> {
        diagnostics::scope_request(async {
            if !self.request_allows_tool(&request.name, &context)
                || (request.name == "admin_exec" && !self.admin_available().await)
            {
                return Err(McpError::invalid_params("tool not found", None));
            }
            let call = ToolCallContext::new(self, request, context);
            self.tool_router.call(call).await
        })
        .await
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
        Ok(ListToolsResult::with_all_items(tools))
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

pub(crate) async fn reconcile_browser_orphans(paths: &AppPaths) -> Result<()> {
    let profiles = paths.browser_profiles();
    let report = tokio::task::spawn_blocking(move || reap_orphaned_browser_sessions(&profiles))
        .await
        .context("browser orphan inventory task failed")??;
    if report.changed() || report.has_warnings() {
        tracing::info!(
            leases_examined = report.leases_examined,
            processes_reaped = report.processes_reaped,
            stale_leases_removed = report.stale_leases_removed,
            ephemeral_profiles_removed = report.ephemeral_profiles_removed,
            live_owners_deferred = report.live_owners_deferred,
            live_profiles_deferred = report.live_profiles_deferred,
            unsafe_entries = report.unsafe_entries,
            failed_reaps = report.failed_reaps,
            "reconciled browser ownership leases and ephemeral profiles"
        );
    }
    Ok(())
}

fn reconcile_orphan_connector_artifacts(paths: &AppPaths, config: &AppConfig) -> Result<()> {
    let configured_ids = config
        .connectors
        .iter()
        .map(|connector| connector.id.clone())
        .collect::<BTreeSet<_>>();
    let report = runonmine_core::reconcile_connector_artifacts(paths, &configured_ids)?;
    if report.quarantined_directories > 0
        || report.removed_runtime_records > 0
        || report.unsafe_entries > 0
    {
        tracing::warn!(
            quarantined_directories = report.quarantined_directories,
            removed_runtime_records = report.removed_runtime_records,
            unsafe_entries = report.unsafe_entries,
            "reconciled orphan connector artifacts"
        );
    }
    Ok(())
}

pub async fn serve_stdio(connector_id: &str) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    reconcile_browser_orphans(&paths).await?;
    let reconciled = connector_removal::reconcile_pending_connector_removals(&paths)?;
    if reconciled > 0 {
        tracing::info!(reconciled, "completed pending connector removals");
    }
    let startup_secrets = default_secret_store(&paths)?;
    recover_pending_config_secret_transaction(&paths.config_file(), startup_secrets.as_ref())?;
    let config = AppConfig::load(&paths.config_file()).context("run `runonmine setup` first")?;
    reconcile_orphan_connector_artifacts(&paths, &config)?;
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

mod validation;
#[cfg(test)]
use validation::approval_preview;
use validation::{
    argument_hash, browser_should_be_headless, validate_dbus_arguments, validate_nonempty_text,
    validate_optional_path, validate_path, validate_string_arguments, validate_text,
};

#[cfg(test)]
#[path = "mcp/tests.rs"]
mod tests;
