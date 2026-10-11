use std::collections::BTreeSet;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

#[cfg(target_os = "linux")]
use super::LinuxSystemService;

use super::{
    AppConfig, AppPaths, BinaryKind, BinaryProbe, ConnectorConfig, ConnectorKind, DoctorArgs,
    ExposeSecret, InstalledBinary, OpenAiMcpTarget, OpenAiTunnelProfile, OpenAiTunnelSettings,
    Path, QuickTunnelRuntimeStore, ReleaseProvider, Result, SecretString, SecretValue, StateStore,
    UserService, bail, current, default_secret_store, load_connector_binary,
    local_http_secret_name, resolve_browser_executable, run_once,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticStatus {
    Pass,
    Warn,
    Fail,
    Repaired,
    Skipped,
}

#[derive(Clone, Debug, Serialize)]
struct DoctorCheck {
    id: String,
    severity: DiagnosticSeverity,
    status: DiagnosticStatus,
    evidence: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    remediation: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    overall_status: &'static str,
    repaired: bool,
    checks: Vec<DoctorCheck>,
}

impl DoctorCheck {
    fn new(
        id: impl Into<String>,
        severity: DiagnosticSeverity,
        status: DiagnosticStatus,
        evidence: Value,
        remediation: Option<&str>,
    ) -> Self {
        Self {
            id: id.into(),
            severity,
            status,
            evidence,
            remediation: remediation.map(str::to_owned),
        }
    }
}

pub(crate) async fn doctor(arguments: &DoctorArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    let mut checks = vec![DoctorCheck::new(
        "platform.identity",
        DiagnosticSeverity::Info,
        DiagnosticStatus::Pass,
        json!({
            "os": current().os,
            "architecture": current().architecture,
        }),
        None,
    )];

    let config = if let Ok(config) = AppConfig::load(&paths.config_file()) {
        checks.push(DoctorCheck::new(
            "config.validation",
            DiagnosticSeverity::Info,
            DiagnosticStatus::Pass,
            json!({"bind_host": config.bind_host, "port": config.port}),
            None,
        ));
        config
    } else {
        checks.push(DoctorCheck::new(
            "config.validation",
            DiagnosticSeverity::Error,
            DiagnosticStatus::Fail,
            json!({"state": "missing_or_invalid"}),
            Some("Run `runonmine setup` or restore a valid owner-only config file."),
        ));
        return finish_report(*arguments, checks, false);
    };

    collect_browser_check(&config, &mut checks);
    collect_state_checks(&paths, &mut checks);
    collect_agent_check(config.port, &mut checks).await;
    let repaired_artifacts =
        collect_artifact_checks(&paths, &config, arguments.repair, &mut checks)?;
    let repaired_secrets =
        collect_secret_inventory_checks(&paths, &config, arguments.repair, &mut checks)?;
    collect_connector_checks(&paths, &config, &mut checks).await?;
    collect_service_checks(&mut checks);
    finish_report(*arguments, checks, repaired_artifacts || repaired_secrets)
}

fn collect_browser_check(config: &AppConfig, checks: &mut Vec<DoctorCheck>) {
    if config.browser.external_cdp_url.is_some() {
        checks.push(DoctorCheck::new(
            "browser.executable",
            DiagnosticSeverity::Info,
            DiagnosticStatus::Skipped,
            json!({"reason": "external_cdp_configured"}),
            None,
        ));
        return;
    }
    match resolve_browser_executable(config.browser.executable_path.as_deref()) {
        Ok(identity) => checks.push(DoctorCheck::new(
            "browser.executable",
            DiagnosticSeverity::Info,
            DiagnosticStatus::Pass,
            json!({
                "product": identity.product,
                "source": identity.source,
                "binary": identity.path.file_name().and_then(|name| name.to_str()),
            }),
            None,
        )),
        Err(_) => checks.push(DoctorCheck::new(
            "browser.executable",
            DiagnosticSeverity::Error,
            DiagnosticStatus::Fail,
            json!({"state": "unavailable"}),
            Some("Install Chrome/Chromium/Edge or select one with `browser executable set`."),
        )),
    }
}

fn collect_state_checks(paths: &AppPaths, checks: &mut Vec<DoctorCheck>) {
    match StateStore::open(&paths.state_db()) {
        Ok(state) => match state.verify_audit_chain() {
            Ok(true) => checks.push(DoctorCheck::new(
                "state.audit_chain",
                DiagnosticSeverity::Info,
                DiagnosticStatus::Pass,
                json!({"state": "valid"}),
                None,
            )),
            Ok(false) | Err(_) => checks.push(DoctorCheck::new(
                "state.audit_chain",
                DiagnosticSeverity::Error,
                DiagnosticStatus::Fail,
                json!({"state": "invalid_or_unavailable"}),
                Some("Stop the agent and restore state from a trusted backup before continuing."),
            )),
        },
        Err(_) => checks.push(DoctorCheck::new(
            "state.database",
            DiagnosticSeverity::Error,
            DiagnosticStatus::Fail,
            json!({"state": "missing_or_unavailable"}),
            Some("Run setup or restore the owner-only state database."),
        )),
    }
}

async fn collect_agent_check(port: u16, checks: &mut Vec<DoctorCheck>) {
    let reachable = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    checks.push(DoctorCheck::new(
        "agent.loopback_listener",
        if reachable {
            DiagnosticSeverity::Info
        } else {
            DiagnosticSeverity::Warning
        },
        if reachable {
            DiagnosticStatus::Pass
        } else {
            DiagnosticStatus::Warn
        },
        json!({"reachable": reachable, "port": port}),
        (!reachable).then_some("Start the RunOnMine user service or run `runonmine agent run`."),
    ));
}

fn configured_ids(config: &AppConfig) -> BTreeSet<String> {
    config
        .connectors
        .iter()
        .map(|connector| connector.id.clone())
        .collect()
}

fn collect_artifact_checks(
    paths: &AppPaths,
    config: &AppConfig,
    repair: bool,
    checks: &mut Vec<DoctorCheck>,
) -> Result<bool> {
    let configured = configured_ids(config);
    if repair {
        let report = runonmine_core::reconcile_connector_artifacts(paths, &configured)?;
        let repaired = report.quarantined_directories > 0 || report.removed_runtime_records > 0;
        checks.push(DoctorCheck::new(
            "inventory.connector_artifacts",
            if report.unsafe_entries > 0 {
                DiagnosticSeverity::Error
            } else {
                DiagnosticSeverity::Info
            },
            if report.unsafe_entries > 0 {
                DiagnosticStatus::Fail
            } else if repaired {
                DiagnosticStatus::Repaired
            } else {
                DiagnosticStatus::Pass
            },
            json!({
                "quarantined_directories": report.quarantined_directories,
                "removed_runtime_records": report.removed_runtime_records,
                "unsafe_entries": report.unsafe_entries,
            }),
            (report.unsafe_entries > 0).then_some(
                "Inspect invalid or symlinked connector entries manually; automatic repair is intentionally fail-closed.",
            ),
        ));
        return Ok(repaired);
    }
    let inventory = runonmine_core::inventory_connector_artifacts(paths, &configured)?;
    checks.push(DoctorCheck::new(
        "inventory.connector_artifacts",
        if inventory.unsafe_entries > 0 {
            DiagnosticSeverity::Error
        } else if inventory.orphans.is_empty() {
            DiagnosticSeverity::Info
        } else {
            DiagnosticSeverity::Warning
        },
        if inventory.unsafe_entries > 0 {
            DiagnosticStatus::Fail
        } else if inventory.orphans.is_empty() {
            DiagnosticStatus::Pass
        } else {
            DiagnosticStatus::Warn
        },
        json!({
            "orphan_count": inventory.orphans.len(),
            "unsafe_entries": inventory.unsafe_entries,
            "orphans": inventory.orphans,
        }),
        (!inventory.orphans.is_empty())
            .then_some("Run `runonmine doctor --repair` to quarantine config-less directories and clear orphan runtime state."),
    ));
    Ok(false)
}

fn collect_secret_inventory_checks(
    paths: &AppPaths,
    config: &AppConfig,
    repair: bool,
    checks: &mut Vec<DoctorCheck>,
) -> Result<bool> {
    let secrets = default_secret_store(paths)?;
    let inventory = secrets.inventory()?;
    let configured = configured_ids(config);
    let mut orphan_names = Vec::new();
    let mut orphan_connector_ids = BTreeSet::new();
    let mut stale_index_entries = Vec::new();
    let mut malformed_connector_names = 0_usize;
    for name in &inventory.names {
        if secrets.get(name)?.is_none() {
            stale_index_entries.push(name.clone());
            continue;
        }
        let Some(rest) = name.strip_prefix("connector.") else {
            continue;
        };
        let Some((connector_id, _suffix)) = rest.split_once('.') else {
            malformed_connector_names = malformed_connector_names.saturating_add(1);
            continue;
        };
        if runonmine_core::validate_connector_id(connector_id).is_err() {
            malformed_connector_names = malformed_connector_names.saturating_add(1);
            continue;
        }
        if !configured.contains(connector_id) {
            orphan_names.push(name.clone());
            orphan_connector_ids.insert(connector_id.to_owned());
        }
    }
    let repair_count = if repair {
        let candidates = orphan_names
            .iter()
            .chain(stale_index_entries.iter())
            .cloned()
            .collect::<BTreeSet<_>>();
        for name in &candidates {
            secrets.delete(name)?;
        }
        candidates.len()
    } else {
        0
    };
    let has_problem = !orphan_names.is_empty()
        || !stale_index_entries.is_empty()
        || malformed_connector_names > 0;
    checks.push(DoctorCheck::new(
        "inventory.connector_secrets",
        if malformed_connector_names > 0 {
            DiagnosticSeverity::Error
        } else if has_problem || !inventory.complete {
            DiagnosticSeverity::Warning
        } else {
            DiagnosticSeverity::Info
        },
        if malformed_connector_names > 0 {
            DiagnosticStatus::Fail
        } else if repair_count > 0 {
            DiagnosticStatus::Repaired
        } else if has_problem || !inventory.complete {
            DiagnosticStatus::Warn
        } else {
            DiagnosticStatus::Pass
        },
        json!({
            "coverage": if inventory.complete { "complete" } else { "partial" },
            "source": inventory.source,
            "indexed_names": inventory.names.len(),
            "orphan_count": orphan_names.len(),
            "orphan_connector_ids": orphan_connector_ids,
            "stale_index_entries": stale_index_entries.len(),
            "malformed_connector_names": malformed_connector_names,
            "repaired_entries": repair_count,
        }),
        if malformed_connector_names > 0 {
            Some("Inspect malformed connector credential names manually; automatic deletion is refused.")
        } else if has_problem && !repair {
            Some("Run `runonmine doctor --repair` to delete indexed credentials with no configured connector owner.")
        } else if !inventory.complete {
            Some("Platform keyrings cannot enumerate historical unmanaged entries; rotate or remove legacy credentials explicitly if suspected.")
        } else {
            None
        },
    ));
    Ok(repair_count > 0)
}

async fn collect_connector_checks(
    paths: &AppPaths,
    config: &AppConfig,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let secrets = default_secret_store(paths)?;
    let quick_runtime = QuickTunnelRuntimeStore::new(paths);
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        match connector.kind {
            ConnectorKind::LocalStdio => collect_local_stdio_check(connector, checks),
            ConnectorKind::LocalHttp => {
                collect_local_http_check(connector, secrets.as_ref(), checks)?;
            }
            ConnectorKind::CloudflareQuick => {
                collect_quick_connector_checks(
                    paths,
                    connector,
                    secrets.as_ref(),
                    &quick_runtime,
                    checks,
                )
                .await?;
            }
            ConnectorKind::CloudflareOauth => {
                collect_oauth_connector_checks(paths, connector, secrets.as_ref(), checks).await?;
            }
            ConnectorKind::OpenAiTunnel => {
                collect_openai_connector_checks(paths, connector, secrets.as_ref(), checks).await?;
            }
        }
    }
    Ok(())
}

fn collect_local_stdio_check(connector: &ConnectorConfig, checks: &mut Vec<DoctorCheck>) {
    checks.push(DoctorCheck::new(
        format!("connector.{}.local_stdio", connector.id),
        DiagnosticSeverity::Info,
        DiagnosticStatus::Pass,
        json!({"connector_id": connector.id, "kind": connector.kind}),
        None,
    ));
}

fn collect_local_http_check(
    connector: &ConnectorConfig,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    credential_check(
        checks,
        &connector.id,
        "local_http_token",
        secrets
            .get(&local_http_secret_name(&connector.id))?
            .is_some(),
    );
    Ok(())
}

async fn collect_quick_connector_checks(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    quick_runtime: &QuickTunnelRuntimeStore,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let Some(settings) = &connector.cloudflare_quick else {
        connector_failure(checks, &connector.id, "settings", "cloudflare_quick");
        return Ok(());
    };
    binary_check(
        paths,
        checks,
        &connector.id,
        BinaryKind::Cloudflared,
        ReleaseProvider::Cloudflared,
        settings.cloudflared_path.as_deref(),
    )
    .await?;
    credential_check(
        checks,
        &connector.id,
        "path_secret",
        secrets
            .get(&format!("connector.{}.path_secret", connector.id))?
            .is_some(),
    );
    checks.push(match quick_runtime.get(&connector.id) {
        Ok(record) => DoctorCheck::new(
            format!("connector.{}.quick_runtime", connector.id),
            DiagnosticSeverity::Info,
            DiagnosticStatus::Pass,
            json!({"public_url_discovered": record.and_then(|item| item.public_url).is_some()}),
            None,
        ),
        Err(_) => DoctorCheck::new(
            format!("connector.{}.quick_runtime", connector.id),
            DiagnosticSeverity::Error,
            DiagnosticStatus::Fail,
            json!({"state": "corrupt_or_unavailable"}),
            Some("Stop the connector and run doctor repair before restarting it."),
        ),
    });
    Ok(())
}

async fn collect_oauth_connector_checks(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let Some(settings) = &connector.cloudflare_named else {
        connector_failure(checks, &connector.id, "settings", "cloudflare_oauth");
        return Ok(());
    };
    binary_check(
        paths,
        checks,
        &connector.id,
        BinaryKind::Cloudflared,
        ReleaseProvider::Cloudflared,
        settings.cloudflared_path.as_deref(),
    )
    .await?;
    for suffix in [
        "github_client_id",
        "github_client_secret",
        "oauth_hash_key",
        "oauth_registration_token",
    ] {
        credential_check(
            checks,
            &connector.id,
            suffix,
            secrets
                .get(&format!("connector.{}.{suffix}", connector.id))?
                .is_some(),
        );
    }
    let owner_valid = connector
        .oauth_owner
        .as_ref()
        .is_some_and(|owner| owner.github_id > 0);
    checks.push(DoctorCheck::new(
        format!("connector.{}.oauth_owner", connector.id),
        if owner_valid {
            DiagnosticSeverity::Info
        } else {
            DiagnosticSeverity::Error
        },
        if owner_valid {
            DiagnosticStatus::Pass
        } else {
            DiagnosticStatus::Fail
        },
        json!({"immutable_numeric_id_configured": owner_valid}),
        (!owner_valid).then_some("Re-run OAuth connector setup with the verified GitHub owner."),
    ));
    Ok(())
}

async fn collect_openai_connector_checks(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let Some(settings) = &connector.openai_tunnel else {
        connector_failure(checks, &connector.id, "settings", "openai_tunnel");
        return Ok(());
    };
    let binary = binary_check(
        paths,
        checks,
        &connector.id,
        BinaryKind::OpenAiTunnelClient,
        ReleaseProvider::OpenAiTunnelClient,
        settings.tunnel_client_path.as_deref(),
    )
    .await?;
    let runtime_key = secrets.get(&format!("connector.{}.runtime_api_key", connector.id))?;
    credential_check(
        checks,
        &connector.id,
        "runtime_api_key",
        runtime_key.is_some(),
    );
    if let (Some(binary), Some(runtime_key)) = (binary, runtime_key) {
        collect_openai_doctor_check(paths, connector, settings, &binary, &runtime_key, checks)
            .await?;
    }
    Ok(())
}

async fn binary_check(
    paths: &AppPaths,
    checks: &mut Vec<DoctorCheck>,
    connector_id: &str,
    kind: BinaryKind,
    provider: ReleaseProvider,
    configured_path: Option<&Path>,
) -> Result<Option<InstalledBinary>> {
    let loaded = load_connector_binary(paths, kind, provider, configured_path)?;
    let Some(binary) = loaded else {
        checks.push(DoctorCheck::new(
            format!("connector.{connector_id}.binary"),
            DiagnosticSeverity::Error,
            DiagnosticStatus::Fail,
            json!({"state": "missing", "kind": format!("{kind:?}")}),
            Some("Install, update, or explicitly pin the required connector binary."),
        ));
        return Ok(None);
    };
    if let Ok(probe) = BinaryProbe::run_compatible(&binary, Duration::from_secs(10)).await {
        checks.push(DoctorCheck::new(
            format!("connector.{connector_id}.binary"),
            DiagnosticSeverity::Info,
            DiagnosticStatus::Pass,
            json!({"kind": format!("{kind:?}"), "version": probe.version}),
            None,
        ));
    } else {
        checks.push(DoctorCheck::new(
            format!("connector.{connector_id}.binary"),
            DiagnosticSeverity::Error,
            DiagnosticStatus::Fail,
            json!({"state": "probe_failed", "kind": format!("{kind:?}")}),
            Some("Update or re-pin the connector binary and retry."),
        ));
        return Ok(None);
    }
    Ok(Some(binary))
}

fn credential_check(
    checks: &mut Vec<DoctorCheck>,
    connector_id: &str,
    credential: &str,
    configured: bool,
) {
    checks.push(DoctorCheck::new(
        format!("connector.{connector_id}.credential.{credential}"),
        if configured {
            DiagnosticSeverity::Info
        } else {
            DiagnosticSeverity::Error
        },
        if configured {
            DiagnosticStatus::Pass
        } else {
            DiagnosticStatus::Fail
        },
        json!({"configured": configured}),
        (!configured).then_some("Rotate or recreate this connector credential locally."),
    ));
}

fn connector_failure(
    checks: &mut Vec<DoctorCheck>,
    connector_id: &str,
    component: &str,
    kind: &str,
) {
    checks.push(DoctorCheck::new(
        format!("connector.{connector_id}.{component}"),
        DiagnosticSeverity::Error,
        DiagnosticStatus::Fail,
        json!({"state": "missing_or_invalid", "kind": kind}),
        Some("Recreate the connector configuration."),
    ));
}

async fn collect_openai_doctor_check(
    paths: &AppPaths,
    connector: &ConnectorConfig,
    settings: &OpenAiTunnelSettings,
    binary: &InstalledBinary,
    runtime_key: &SecretString,
    checks: &mut Vec<DoctorCheck>,
) -> Result<()> {
    let profile_directory = paths
        .data_dir
        .join("connectors")
        .join(&connector.id)
        .join("openai-profiles");
    let health_directory = paths.state_dir.join("connectors").join(&connector.id);
    let profile = OpenAiTunnelProfile::builder(
        &settings.profile,
        &settings.tunnel_id,
        OpenAiMcpTarget::runonmine_stdio(std::env::current_exe()?.canonicalize()?, &connector.id)?,
    )
    .profile_directory(profile_directory)
    .health_address(format!("127.0.0.1:{}", settings.health_port).parse()?)
    .health_url_file(health_directory.join("tunnel-health.url"))
    .build();
    let status = match profile {
        Ok(profile) => run_once(
            profile.doctor_command(
                binary,
                SecretValue::new(runtime_key.expose_secret().to_owned())?,
            )?,
            Duration::from_secs(30),
            256 * 1_024,
        )
        .await
        .is_ok_and(|report| report.success),
        Err(_) => false,
    };
    checks.push(DoctorCheck::new(
        format!("connector.{}.openai_doctor", connector.id),
        if status {
            DiagnosticSeverity::Info
        } else {
            DiagnosticSeverity::Error
        },
        if status {
            DiagnosticStatus::Pass
        } else {
            DiagnosticStatus::Fail
        },
        json!({"passed": status}),
        (!status).then_some("Verify the tunnel profile, permissions, and runtime API key."),
    ));
    Ok(())
}

fn collect_service_checks(checks: &mut Vec<DoctorCheck>) {
    match UserService::discover().and_then(|service| service.status()) {
        Ok(status) => checks.push(service_check("service.user", &status)),
        Err(_) => checks.push(service_failure("service.user")),
    }
    #[cfg(target_os = "linux")]
    match LinuxSystemService::discover().and_then(|service| service.status()) {
        Ok(status) => checks.push(service_check("service.system", &status)),
        Err(_) => checks.push(service_failure("service.system")),
    }
}

fn service_check(id: &str, status: &runonmine_platform::ServiceStatus) -> DoctorCheck {
    let healthy = !status.installed || status.running;
    DoctorCheck::new(
        id,
        if healthy {
            DiagnosticSeverity::Info
        } else {
            DiagnosticSeverity::Warning
        },
        if healthy {
            DiagnosticStatus::Pass
        } else {
            DiagnosticStatus::Warn
        },
        json!({"installed": status.installed, "running": status.running}),
        (!healthy)
            .then_some("Start the installed service or uninstall it if it is no longer needed."),
    )
}

fn service_failure(id: &str) -> DoctorCheck {
    DoctorCheck::new(
        id,
        DiagnosticSeverity::Warning,
        DiagnosticStatus::Warn,
        json!({"state": "unavailable"}),
        Some("Inspect the platform service manager locally."),
    )
}

fn finish_report(arguments: DoctorArgs, checks: Vec<DoctorCheck>, repaired: bool) -> Result<()> {
    let has_failures = checks.iter().any(|check| {
        check.severity == DiagnosticSeverity::Error && check.status == DiagnosticStatus::Fail
    });
    let has_warnings = checks.iter().any(|check| {
        check.status == DiagnosticStatus::Warn || check.status == DiagnosticStatus::Repaired
    });
    let report = DoctorReport {
        overall_status: if has_failures {
            "unhealthy"
        } else if has_warnings {
            "degraded"
        } else {
            "healthy"
        },
        repaired,
        checks,
    };
    if arguments.json {
        super::print_json_output("doctor", &report)?;
    } else {
        println!("RunOnMine doctor: {}", report.overall_status);
        for check in &report.checks {
            println!(
                "[{:?}] {}: {:?} {}",
                check.severity, check.id, check.status, check.evidence
            );
            if let Some(remediation) = &check.remediation {
                println!("  remediation: {remediation}");
            }
        }
    }
    if has_failures {
        bail!("doctor found failing checks")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_report_has_stable_fields_and_failure_semantics() -> Result<()> {
        let checks = vec![
            DoctorCheck::new(
                "test.pass",
                DiagnosticSeverity::Info,
                DiagnosticStatus::Pass,
                json!({"value": true}),
                None,
            ),
            DoctorCheck::new(
                "test.fail",
                DiagnosticSeverity::Error,
                DiagnosticStatus::Fail,
                json!({"state": "failed"}),
                Some("repair it"),
            ),
        ];
        let report = DoctorReport {
            overall_status: "unhealthy",
            repaired: false,
            checks,
        };
        let value = serde_json::to_value(report)?;
        assert_eq!(value["checks"][1]["id"], "test.fail");
        assert_eq!(value["checks"][1]["severity"], "error");
        assert_eq!(value["checks"][1]["status"], "fail");
        Ok(())
    }
}
