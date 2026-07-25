use anyhow::{Context, Result};
use rmcp::ErrorData as McpError;
use runonmine_core::Capability;
use serde::Serialize;

use crate::arguments::DbusCallArgs;
use crate::{MAX_ARGUMENT_BYTES, MAX_ARGUMENT_ITEMS};

pub(super) fn approval_preview(tool_name: &str, arguments: &impl Serialize) -> String {
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
