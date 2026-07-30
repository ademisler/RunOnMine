use anyhow::{Context, Result};
use rmcp::ErrorData as McpError;
use runonmine_core::Capability;
use serde::Serialize;

use crate::arguments::DbusCallArgs;
use crate::{MAX_ARGUMENT_BYTES, MAX_ARGUMENT_ITEMS};

struct PreviewValue(serde_json::Value);

impl PreviewValue {
    fn string(&self, name: &str) -> &str {
        self.0
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }

    fn value(&self, name: &str) -> &serde_json::Value {
        self.0.get(name).unwrap_or(&serde_json::Value::Null)
    }

    fn joined_strings(&self, name: &str) -> String {
        self.0
            .get(name)
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default()
    }
}

fn filesystem_preview(tool_name: &str, value: &PreviewValue) -> Option<String> {
    match tool_name {
        "fs_list" | "fs_read" | "fs_delete" => Some(format!("Path: {}", value.string("path"))),
        "fs_search" => Some(format!(
            "Root: {}
Query: {}",
            value.string("root"),
            redact_preview_text(value.string("query"))
        )),
        "fs_write" => Some(format!(
            "Path: {}
New content: {} bytes
Preview: {}",
            value.string("path"),
            value.string("content").len(),
            redact_preview_text(value.string("content"))
        )),
        "fs_patch" => Some(format!(
            "Path: {}
Expected replacements: {}
Replace: {}
With: {}",
            value.string("path"),
            value
                .0
                .get("expected_replacements")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1),
            redact_preview_text(value.string("old_text")),
            redact_preview_text(value.string("new_text"))
        )),
        "fs_move" => Some(format!(
            "From: {}
To: {}",
            value.string("from"),
            value.string("to")
        )),
        _ => None,
    }
}

fn process_preview(tool_name: &str, value: &PreviewValue) -> Option<String> {
    match tool_name {
        "shell_exec" => Some(format!(
            "Command: {}
Working directory: {}",
            redact_preview_text(value.string("command")),
            value
                .0
                .get("cwd")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("current directory")
        )),
        "admin_exec" => Some(format!(
            "Privileged program: {}
Arguments: {}",
            value.string("program"),
            redact_preview_text(&value.joined_strings("args"))
        )),
        _ => None,
    }
}

fn desktop_preview(tool_name: &str, value: &PreviewValue) -> Option<String> {
    match tool_name {
        "desktop_focus_window" => Some(format!("Window ID: {}", value.value("window_id"))),
        "desktop_screenshot" => Some(format!(
            "Capture screenshot
Monitor: {}
Window: {}",
            value.value("monitor_id"),
            value.value("window_id")
        )),
        "desktop_click" => Some(format!(
            "Click at ({}, {}) with {} button",
            value.value("x"),
            value.value("y"),
            value.string("button")
        )),
        "desktop_type" => Some(format!(
            "Type {} characters
Text: {}",
            value.string("text").chars().count(),
            redact_preview_text(value.string("text"))
        )),
        "desktop_key" => Some(format!("Key: {}", value.string("key"))),
        _ => None,
    }
}

fn platform_preview(tool_name: &str, value: &PreviewValue) -> Option<String> {
    match tool_name {
        "macos_applescript" | "windows_powershell" => Some(format!(
            "Script ({} characters):
{}",
            value.string("script").chars().count(),
            redact_preview_text(value.string("script"))
        )),
        "linux_dbus_call" => Some(format!(
            "D-Bus: {} {}.{} on {}",
            value.string("destination"),
            value.string("interface"),
            value.string("method"),
            value.string("object_path")
        )),
        _ => None,
    }
}

fn browser_preview(tool_name: &str, value: &PreviewValue) -> Option<String> {
    match tool_name {
        "browser_open" | "browser_navigate" => Some(format!("URL: {}", value.string("url"))),
        "browser_get_url"
        | "browser_get_text"
        | "browser_snapshot"
        | "browser_screenshot"
        | "browser_close"
        | "browser_profile_info" => Some(format!("Origin: {}", value.string("current_origin"))),
        "browser_click" => Some(format!(
            "Origin: {}
Selector: {}",
            value.string("current_origin"),
            value.string("selector")
        )),
        "browser_type" => Some(format!(
            "Origin: {}
Selector: {}
Type {} characters
Text: {}",
            value.string("current_origin"),
            value.string("selector"),
            value.string("text").chars().count(),
            redact_preview_text(value.string("text"))
        )),
        "browser_press" => Some(format!(
            "Origin: {}
Key: {}",
            value.string("current_origin"),
            value.string("key")
        )),
        "browser_evaluate" => Some(format!(
            "Origin: {}
JavaScript ({} characters):
{}",
            value.string("current_origin"),
            value.string("expression").chars().count(),
            redact_preview_text(value.string("expression"))
        )),
        _ => None,
    }
}

pub(super) fn approval_preview(tool_name: &str, arguments: &impl Serialize) -> String {
    let value = PreviewValue(serde_json::to_value(arguments).unwrap_or(serde_json::Value::Null));
    let preview = filesystem_preview(tool_name, &value)
        .or_else(|| process_preview(tool_name, &value))
        .or_else(|| desktop_preview(tool_name, &value))
        .or_else(|| platform_preview(tool_name, &value))
        .or_else(|| browser_preview(tool_name, &value))
        .unwrap_or_else(|| tool_name.replace('_', " "));
    truncate_preview(&preview, 1_500)
}

pub(super) fn redact_preview_text(input: &str) -> String {
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

pub(super) fn truncate_preview(value: &str, maximum_chars: usize) -> String {
    let mut output = value.chars().take(maximum_chars).collect::<String>();
    if value.chars().count() > maximum_chars {
        output.push('…');
    }
    output
}

pub(super) const fn capability_requires_reliable_audit(capability: Capability) -> bool {
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

pub(super) fn argument_hash(value: &impl Serialize) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("tool argument serialization failed")?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

pub(super) fn validate_text(value: &str, label: &str, maximum: usize) -> Result<(), McpError> {
    if value.len() > maximum {
        return Err(McpError::invalid_params(
            format!("{label} exceeds the configured size limit"),
            None,
        ));
    }
    Ok(())
}

pub(super) fn validate_nonempty_text(
    value: &str,
    label: &str,
    maximum: usize,
) -> Result<(), McpError> {
    if value.trim().is_empty() {
        return Err(McpError::invalid_params(
            format!("{label} must not be empty"),
            None,
        ));
    }
    validate_text(value, label, maximum)
}

pub(super) fn validate_path(path: &std::path::Path, label: &str) -> Result<(), McpError> {
    if path.as_os_str().is_empty() || path.as_os_str().len() > 32 * 1_024 {
        return Err(McpError::invalid_params(
            format!("{label} is empty or exceeds the size limit"),
            None,
        ));
    }
    Ok(())
}

pub(super) fn validate_optional_path(
    path: Option<&std::path::Path>,
    label: &str,
) -> Result<(), McpError> {
    if let Some(path) = path {
        validate_path(path, label)?;
    }
    Ok(())
}

pub(super) fn validate_string_arguments(values: &[String], label: &str) -> Result<(), McpError> {
    if values.len() > MAX_ARGUMENT_ITEMS
        || values
            .iter()
            .try_fold(0_usize, |total, value| total.checked_add(value.len()))
            .is_none_or(|total| total > MAX_ARGUMENT_BYTES)
    {
        return Err(McpError::invalid_params(
            format!("{label} exceed the configured limits"),
            None,
        ));
    }
    Ok(())
}

pub(super) fn validate_dbus_arguments(arguments: &DbusCallArgs) -> Result<(), McpError> {
    for (label, value, maximum) in [
        (
            "D-Bus destination",
            arguments.destination.as_str(),
            512_usize,
        ),
        ("D-Bus object path", arguments.object_path.as_str(), 4_096),
        ("D-Bus interface", arguments.interface.as_str(), 512),
        ("D-Bus method", arguments.method.as_str(), 512),
    ] {
        validate_nonempty_text(value, label, maximum)?;
    }
    validate_text(&arguments.signature, "D-Bus signature", 1_024)?;
    validate_string_arguments(&arguments.arguments, "D-Bus arguments")
}

pub(super) const fn capability_name(capability: Capability) -> &'static str {
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

pub(super) fn browser_should_be_headless() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_none() && std::env::var_os("WAYLAND_DISPLAY").is_none()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
