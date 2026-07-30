use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;

use chrono::{DateTime, Utc};
use runonmine_browser::{BrowserExecutableState, browser_executable_state};
use runonmine_core::{
    AppConfig, AppPaths, AuditOutcome, BrowserProfileMode, ConnectorConfig, ConnectorKind,
    PolicyPreset, QuickTunnelRuntimeStore, StateStore,
};
#[cfg(target_os = "linux")]
use runonmine_platform::LinuxSystemService;
use runonmine_platform::{PlatformInfo, ServiceStatus, UserService, current};
use serde::Serialize;

const AUDIT_SAMPLE_LIMIT: usize = 200;

#[derive(Debug, Serialize)]
pub(super) struct SupportSummary {
    schema_version: u32,
    generated_at: DateTime<Utc>,
    application_version: &'static str,
    platform: PlatformInfo,
    config: ConfigReport,
    user_service: ServiceReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_service: Option<ServiceReport>,
    state: StateReport,
    included_log_files: usize,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum ConfigReport {
    Missing,
    PermissionDenied,
    Corrupt,
    Unavailable,
    Valid {
        schema_version: u32,
        loopback_only: bool,
        port: u16,
        default_preset: PolicyPreset,
        allowed_root_count: usize,
        connectors: Vec<ConnectorSummary>,
        browser: BrowserSummary,
        limits: LimitsSummary,
    },
}

#[derive(Debug, Serialize)]
pub(super) struct ConnectorSummary {
    index: usize,
    kind: ConnectorKind,
    enabled: bool,
    policy_preset: PolicyPreset,
    pack_override_count: usize,
    tool_override_count: usize,
    policy_rule_count: usize,
    features: ConnectorFeatures,
}

#[derive(Debug, Serialize)]
pub(super) struct ConnectorFeatures {
    public_endpoint: PublicEndpointStatus,
    external_binary_override_configured: bool,
    immutable_owner_bound: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum PublicEndpointStatus {
    NotConfigured,
    Configured,
    RuntimeUnavailable,
}

#[derive(Debug, Serialize)]
pub(super) struct BrowserSummary {
    profile_mode: BrowserProfileMode,
    executable_selection: &'static str,
    executable_state: BrowserExecutableState,
    executable_product: Option<String>,
    executable_available: bool,
    external_cdp_configured: bool,
    private_network_allowed: bool,
    operation_timeout_seconds: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct LimitsSummary {
    approval_timeout_seconds: u64,
    session_idle_minutes: u64,
    max_sessions: usize,
    calls_per_minute: u32,
    default_process_timeout_seconds: u64,
    max_process_timeout_seconds: u64,
    max_output_bytes: usize,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ServiceReport {
    Available,
    Missing,
    Disabled,
    PermissionDenied,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum AuditChainState {
    Valid,
    Corrupt,
    Unavailable,
    PermissionDenied,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum StateReport {
    Missing,
    PermissionDenied,
    Corrupt,
    Unavailable,
    Available {
        audit_chain: AuditChainState,
        sampled_records: usize,
        outcomes: BTreeMap<String, usize>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum AuditReport {
    Missing,
    PermissionDenied,
    Corrupt,
    Unavailable,
    Available {
        audit_chain: AuditChainState,
        records: Vec<AuditSample>,
    },
}

#[derive(Debug, Serialize)]
pub(super) struct AuditSample {
    timestamp: DateTime<Utc>,
    tool_name: String,
    capability: String,
    outcome: AuditOutcome,
    duration_ms: Option<u64>,
    output_bytes: Option<u64>,
}
pub(super) fn config_report(paths: &AppPaths) -> (ConfigReport, Option<AppConfig>) {
    let path = paths.config_file();
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return (ConfigReport::Missing, None);
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            return (ConfigReport::PermissionDenied, None);
        }
        Err(_) => return (ConfigReport::Unavailable, None),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return (ConfigReport::Corrupt, None);
    }
    let config = match AppConfig::load(&path) {
        Ok(config) => config,
        Err(error) => {
            let report = match error_io_kind(&error) {
                Some(ErrorKind::PermissionDenied) => ConfigReport::PermissionDenied,
                Some(_) => ConfigReport::Unavailable,
                None => ConfigReport::Corrupt,
            };
            return (report, None);
        }
    };
    let report = ConfigReport::Valid {
        schema_version: config.version,
        loopback_only: config.bind_host == "127.0.0.1",
        port: config.port,
        default_preset: config.default_preset,
        allowed_root_count: config.allowed_roots.len(),
        connectors: {
            let quick_runtime = QuickTunnelRuntimeStore::new(paths);
            config
                .connectors
                .iter()
                .enumerate()
                .map(|(index, connector)| connector_summary(index, connector, &quick_runtime))
                .collect()
        },
        browser: {
            let executable_state = if config.browser.external_cdp_url.is_some() {
                BrowserExecutableState::Disabled
            } else {
                browser_executable_state(config.browser.executable_path.as_deref())
            };
            BrowserSummary {
                profile_mode: config.browser.profile_mode,
                executable_selection: if config.browser.external_cdp_url.is_some() {
                    "disabled"
                } else if config.browser.executable_path.is_some() {
                    "explicit"
                } else {
                    "automatic"
                },
                executable_product: executable_state
                    .executable()
                    .map(|identity| identity.product.to_string()),
                executable_available: executable_state.is_available(),
                executable_state,
                external_cdp_configured: config.browser.external_cdp_url.is_some(),
                private_network_allowed: config.browser.allow_private_network,
                operation_timeout_seconds: config.browser.operation_timeout_seconds,
            }
        },
        limits: LimitsSummary {
            approval_timeout_seconds: config.limits.approval_timeout_seconds,
            session_idle_minutes: config.limits.session_idle_minutes,
            max_sessions: config.limits.max_sessions,
            calls_per_minute: config.limits.calls_per_minute,
            default_process_timeout_seconds: config.limits.default_process_timeout_seconds,
            max_process_timeout_seconds: config.limits.max_process_timeout_seconds,
            max_output_bytes: config.limits.max_output_bytes,
        },
    };
    (report, Some(config))
}

fn connector_summary(
    index: usize,
    connector: &ConnectorConfig,
    quick_runtime: &QuickTunnelRuntimeStore,
) -> ConnectorSummary {
    let external_binary_override_configured = connector
        .cloudflare_quick
        .as_ref()
        .and_then(|settings| settings.cloudflared_path.as_ref())
        .or_else(|| {
            connector
                .cloudflare_named
                .as_ref()
                .and_then(|settings| settings.cloudflared_path.as_ref())
        })
        .or_else(|| {
            connector
                .openai_tunnel
                .as_ref()
                .and_then(|settings| settings.tunnel_client_path.as_ref())
        })
        .is_some();
    let public_endpoint = if connector.kind == ConnectorKind::CloudflareQuick {
        match quick_runtime.get(&connector.id) {
            Ok(Some(record)) if record.public_url.is_some() => PublicEndpointStatus::Configured,
            Ok(_) => PublicEndpointStatus::NotConfigured,
            Err(_) => PublicEndpointStatus::RuntimeUnavailable,
        }
    } else if connector.public_base_url.is_some() {
        PublicEndpointStatus::Configured
    } else {
        PublicEndpointStatus::NotConfigured
    };
    ConnectorSummary {
        index,
        kind: connector.kind,
        enabled: connector.enabled,
        policy_preset: connector.policy_preset,
        pack_override_count: connector.pack_overrides.len(),
        tool_override_count: connector.tool_overrides.len(),
        policy_rule_count: connector.policy_rules.len(),
        features: ConnectorFeatures {
            public_endpoint,
            external_binary_override_configured,
            immutable_owner_bound: connector
                .oauth_owner
                .as_ref()
                .is_some_and(|owner| owner.github_id > 0),
        },
    }
}

fn user_service_report() -> ServiceReport {
    match UserService::discover() {
        Ok(service) => service_status_report(service.status()),
        Err(error) => service_error_report(&error),
    }
}

#[cfg(target_os = "linux")]
fn system_service_report() -> ServiceReport {
    match LinuxSystemService::discover() {
        Ok(service) => service_status_report(service.status()),
        Err(error) => service_error_report(&error),
    }
}

fn service_status_report(status: anyhow::Result<ServiceStatus>) -> ServiceReport {
    match status {
        Ok(status) if !status.installed => ServiceReport::Missing,
        Ok(status) if !status.running => ServiceReport::Disabled,
        Ok(_) => ServiceReport::Available,
        Err(error) => service_error_report(&error),
    }
}

fn service_error_report(error: &anyhow::Error) -> ServiceReport {
    if error_io_kind(error) == Some(ErrorKind::PermissionDenied) {
        ServiceReport::PermissionDenied
    } else {
        ServiceReport::Unavailable
    }
}

pub(super) fn audit_report(paths: &AppPaths) -> AuditReport {
    let path = paths.state_db();
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return AuditReport::Missing,
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            return AuditReport::PermissionDenied;
        }
        Err(_) => return AuditReport::Unavailable,
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return AuditReport::Corrupt;
    }
    let store = match StateStore::open(&path) {
        Ok(store) => store,
        Err(error) => return audit_error_report(&error),
    };
    let audit_chain = match store.verify_audit_chain() {
        Ok(true) => AuditChainState::Valid,
        Err(error) if error_io_kind(&error) == Some(ErrorKind::PermissionDenied) => {
            AuditChainState::PermissionDenied
        }
        Err(error) if error_io_kind(&error).is_some() => AuditChainState::Unavailable,
        Ok(false) | Err(_) => AuditChainState::Corrupt,
    };
    let records = match store.audit_tail(AUDIT_SAMPLE_LIMIT) {
        Ok(records) => records,
        Err(error) => return audit_error_report(&error),
    };
    AuditReport::Available {
        audit_chain,
        records: records
            .into_iter()
            .map(|record| AuditSample {
                timestamp: record.event.timestamp,
                tool_name: sanitize_identifier(&record.event.tool_name),
                capability: sanitize_identifier(&record.event.capability),
                outcome: record.event.outcome,
                duration_ms: record.event.duration_ms,
                output_bytes: record.event.output_bytes,
            })
            .collect(),
    }
}

pub(super) fn state_report(audit: &AuditReport) -> StateReport {
    match audit {
        AuditReport::Missing => StateReport::Missing,
        AuditReport::PermissionDenied => StateReport::PermissionDenied,
        AuditReport::Corrupt => StateReport::Corrupt,
        AuditReport::Unavailable => StateReport::Unavailable,
        AuditReport::Available {
            audit_chain,
            records,
        } => {
            let mut outcomes = BTreeMap::new();
            for record in records {
                let key = format!("{:?}", record.outcome).to_ascii_lowercase();
                *outcomes.entry(key).or_insert(0) += 1;
            }
            StateReport::Available {
                audit_chain: *audit_chain,
                sampled_records: records.len(),
                outcomes,
            }
        }
    }
}

fn audit_error_report(error: &anyhow::Error) -> AuditReport {
    match error_io_kind(error) {
        Some(ErrorKind::PermissionDenied) => AuditReport::PermissionDenied,
        Some(_) => AuditReport::Unavailable,
        None => AuditReport::Corrupt,
    }
}

fn error_io_kind(error: &anyhow::Error) -> Option<ErrorKind> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind)
    })
}

fn sanitize_identifier(value: &str) -> String {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return "[REDACTED_IDENTIFIER]".to_owned();
    }
    value.to_owned()
}

pub(super) fn build_support_summary(
    schema_version: u32,
    generated_at: DateTime<Utc>,
    config: ConfigReport,
    state: StateReport,
    included_log_files: usize,
) -> SupportSummary {
    SupportSummary {
        schema_version,
        generated_at,
        application_version: env!("CARGO_PKG_VERSION"),
        platform: current(),
        config,
        user_service: user_service_report(),
        system_service: {
            #[cfg(target_os = "linux")]
            {
                Some(system_service_report())
            }
            #[cfg(not(target_os = "linux"))]
            {
                None
            }
        },
        state,
        included_log_files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_config_distinguishes_missing_and_corrupt() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        assert!(matches!(config_report(&paths).0, ConfigReport::Missing));

        fs::create_dir_all(&paths.config_dir)?;
        fs::write(paths.config_file(), b"not valid toml")?;
        assert!(matches!(config_report(&paths).0, ConfigReport::Corrupt));
        Ok(())
    }

    #[test]
    fn support_audit_distinguishes_missing_and_corrupt() -> anyhow::Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        assert!(matches!(audit_report(&paths), AuditReport::Missing));

        fs::create_dir_all(&paths.state_dir)?;
        fs::write(paths.state_db(), b"not a sqlite database")?;
        assert!(matches!(audit_report(&paths), AuditReport::Corrupt));
        Ok(())
    }

    #[test]
    fn service_status_distinguishes_missing_disabled_and_available() {
        let missing = service_status_report(Ok(ServiceStatus {
            installed: false,
            running: false,
            detail: String::new(),
        }));
        let disabled = service_status_report(Ok(ServiceStatus {
            installed: true,
            running: false,
            detail: String::new(),
        }));
        let available = service_status_report(Ok(ServiceStatus {
            installed: true,
            running: true,
            detail: String::new(),
        }));
        assert!(matches!(missing, ServiceReport::Missing));
        assert!(matches!(disabled, ServiceReport::Disabled));
        assert!(matches!(available, ServiceReport::Available));
    }
}
