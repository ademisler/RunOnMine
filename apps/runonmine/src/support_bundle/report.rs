use std::collections::BTreeMap;
use std::fs;

use chrono::{DateTime, Utc};
use runonmine_browser::resolve_browser_executable;
use runonmine_core::{
    AppConfig, AppPaths, AuditOutcome, BrowserProfileMode, ConnectorConfig, ConnectorKind,
    PolicyPreset, QuickTunnelRuntimeStore, StateStore,
};
#[cfg(target_os = "linux")]
use runonmine_platform::LinuxSystemService;
use runonmine_platform::{PlatformInfo, UserService, current};
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
    Invalid,
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
    Available { installed: bool, running: bool },
    Unavailable,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum StateReport {
    Missing,
    Unavailable,
    Available {
        audit_chain_valid: Option<bool>,
        sampled_records: usize,
        outcomes: BTreeMap<String, usize>,
    },
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(super) enum AuditReport {
    Missing,
    Unavailable,
    Available {
        audit_chain_valid: Option<bool>,
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
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return (ConfigReport::Missing, None);
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return (ConfigReport::Invalid, None);
    }
    let Ok(config) = AppConfig::load(&path) else {
        return (ConfigReport::Invalid, None);
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
            let executable =
                resolve_browser_executable(config.browser.executable_path.as_deref()).ok();
            BrowserSummary {
                profile_mode: config.browser.profile_mode,
                executable_selection: if config.browser.executable_path.is_some() {
                    "explicit"
                } else {
                    "automatic"
                },
                executable_product: executable
                    .as_ref()
                    .map(|identity| identity.product.to_string()),
                executable_available: executable.is_some(),
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
    UserService::discover()
        .and_then(|service| service.status())
        .map_or(ServiceReport::Unavailable, |status| {
            ServiceReport::Available {
                installed: status.installed,
                running: status.running,
            }
        })
}

#[cfg(target_os = "linux")]
fn system_service_report() -> ServiceReport {
    LinuxSystemService::discover()
        .and_then(|service| service.status())
        .map_or(ServiceReport::Unavailable, |status| {
            ServiceReport::Available {
                installed: status.installed,
                running: status.running,
            }
        })
}

pub(super) fn audit_report(paths: &AppPaths) -> AuditReport {
    let path = paths.state_db();
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return AuditReport::Missing;
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return AuditReport::Unavailable;
    }
    let Ok(store) = StateStore::open(&path) else {
        return AuditReport::Unavailable;
    };
    let audit_chain_valid = store.verify_audit_chain().ok();
    let Ok(records) = store.audit_tail(AUDIT_SAMPLE_LIMIT) else {
        return AuditReport::Unavailable;
    };
    AuditReport::Available {
        audit_chain_valid,
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
        AuditReport::Unavailable => StateReport::Unavailable,
        AuditReport::Available {
            audit_chain_valid,
            records,
        } => {
            let mut outcomes = BTreeMap::new();
            for record in records {
                let key = format!("{:?}", record.outcome).to_ascii_lowercase();
                *outcomes.entry(key).or_insert(0) += 1;
            }
            StateReport::Available {
                audit_chain_valid: *audit_chain_valid,
                sampled_records: records.len(),
                outcomes,
            }
        }
    }
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
