use runonmine_core::ConnectorConfig;
use serde::Serialize;

#[test]
fn remote_machine_info_disables_hostname_collection() {
    assert_eq!(HostnameState::detect(true), HostnameState::Disabled);
}

#[test]
fn shell_scope_does_not_authorize_platform_native_tools() {
    let shell_only = ScopeSet::parse("shell:exec").unwrap_or_default();
    assert!(oauth_scopes_allow_capability(
        &shell_only,
        Capability::ShellExec
    ));
    assert!(!oauth_scopes_allow_capability(
        &shell_only,
        Capability::PlatformNative
    ));

    let platform_only = ScopeSet::parse("platform:exec").unwrap_or_default();
    assert!(oauth_scopes_allow_capability(
        &platform_only,
        Capability::PlatformNative
    ));
    assert!(!oauth_scopes_allow_capability(
        &platform_only,
        Capability::ShellExec
    ));
}

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
    let authorization_header = format!("{} {}", "Bearer", "top-secret");
    let command = format!(
        "curl -H 'Authorization: {authorization_header}' 'https://example.com?token=abc123'"
    );
    let preview = approval_preview(
        "shell_exec",
        &json!({
            "command": command,
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
    let source = include_str!("../lib.rs");
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
        validate_string_arguments(&vec!["x".to_owned(); MAX_ARGUMENT_ITEMS + 1], "args").is_err()
    );
}
#[test]
fn runtime_connector_gate_rejects_disable_and_removal_without_restart() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let config_path = directory.path().join("config.toml");
    let mut connector = ConnectorConfig::local_default();
    connector.id = "live-connector".to_owned();
    connector.name = "Live connector".to_owned();
    let mut config = AppConfig {
        connectors: vec![connector],
        ..AppConfig::default()
    };
    config.save(&config_path)?;
    assert!(load_enabled_connector(&config_path, "live-connector").is_ok());

    config.connectors[0].enabled = false;
    config.save(&config_path)?;
    assert!(load_enabled_connector(&config_path, "live-connector").is_err());

    config.connectors.clear();
    config.save(&config_path)?;
    assert!(load_enabled_connector(&config_path, "live-connector").is_err());
    Ok(())
}
