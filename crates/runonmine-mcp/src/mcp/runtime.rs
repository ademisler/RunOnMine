use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use runonmine_core::filesystem::ScopedFilesystem;
use runonmine_core::{
    AppConfig, AppPaths, ApprovalPrincipal, Capability, ConnectorConfig, StateStore,
};
use runonmine_oauth::{Scope, ScopeSet};

use super::approval_flow::ApprovalFlow;
use super::audit::AuditRecorder;
use super::diagnostics;
use super::rate_limit::PrincipalRateLimiter;
use super::session::SessionPermit;

#[derive(Debug)]
pub(super) struct RuntimeInner {
    pub(super) config_path: PathBuf,
    pub(super) connector_id: String,
    pub(super) store: StateStore,
    pub(super) audit: AuditRecorder,
    pub(super) approvals: ApprovalFlow,
    pub(super) filesystem: ScopedFilesystem,
    pub(super) process_timeout: Duration,
    pub(super) max_process_timeout: Duration,
    pub(super) max_output_bytes: usize,
    pub(super) rate_limiter: PrincipalRateLimiter,
    pub(super) max_sessions: usize,
    pub(super) active_sessions: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
pub(super) struct Runtime(pub(super) Arc<RuntimeInner>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RequestPrincipal {
    LocalHttp,
    QuickTunnel,
    OAuth {
        client_id: String,
        subject: String,
        scopes: ScopeSet,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct RequestAccess {
    pub(super) connector_id: String,
    pub(super) principal: RequestPrincipal,
}

impl RequestAccess {
    pub(super) fn rate_limit_key(&self) -> String {
        match &self.principal {
            RequestPrincipal::LocalHttp => "local_http".to_owned(),
            RequestPrincipal::QuickTunnel => "quick_tunnel".to_owned(),
            RequestPrincipal::OAuth { client_id, .. } => format!("oauth:{client_id}"),
        }
    }

    pub(super) fn approval_principal(&self) -> ApprovalPrincipal {
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

pub(super) const fn diagnostic_category(capability: Capability) -> diagnostics::DiagnosticCategory {
    use diagnostics::DiagnosticCategory;

    match capability {
        Capability::SystemRead => DiagnosticCategory::RuntimeTask,
        Capability::FilesRead | Capability::FilesWrite => DiagnosticCategory::Filesystem,
        Capability::ShellExec => DiagnosticCategory::Process,
        Capability::PlatformNative => DiagnosticCategory::PlatformNative,
        Capability::BrowserRead | Capability::BrowserAct => DiagnosticCategory::Browser,
        Capability::DesktopControl => DiagnosticCategory::Desktop,
        Capability::AdminExec => DiagnosticCategory::PrivilegedHelper,
    }
}

pub(super) const fn oauth_scope_for_capability(capability: Capability) -> Scope {
    match capability {
        Capability::SystemRead => Scope::MachineRead,
        Capability::FilesRead => Scope::FilesRead,
        Capability::FilesWrite => Scope::FilesWrite,
        Capability::ShellExec => Scope::ShellExec,
        Capability::PlatformNative => Scope::PlatformNative,
        Capability::BrowserRead => Scope::BrowserRead,
        Capability::BrowserAct => Scope::BrowserAct,
        Capability::DesktopControl => Scope::DesktopControl,
        Capability::AdminExec => Scope::AdminExec,
    }
}

pub(super) fn oauth_scopes_allow_capability(scopes: &ScopeSet, capability: Capability) -> bool {
    scopes.contains(oauth_scope_for_capability(capability))
}

impl Runtime {
    pub(super) fn load(connector_id: &str) -> Result<Self> {
        let paths = AppPaths::discover()?;
        Self::load_from_paths(&paths, connector_id)
    }

    pub(super) fn load_from_paths(paths: &AppPaths, connector_id: &str) -> Result<Self> {
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

    pub(super) fn connector(&self) -> Result<ConnectorConfig> {
        load_enabled_connector(&self.0.config_path, &self.0.connector_id)
    }

    pub(super) fn acquire_session(&self) -> Result<SessionPermit> {
        SessionPermit::acquire(&self.0.active_sessions, self.0.max_sessions)
    }

    pub(super) fn check_rate_limit(&self, principal: &str) -> Result<()> {
        self.0.rate_limiter.check(principal)
    }

    pub(super) fn audit(&self) -> &AuditRecorder {
        &self.0.audit
    }

    pub(super) fn approvals(&self) -> &ApprovalFlow {
        &self.0.approvals
    }
}

pub(super) fn load_enabled_connector(
    config_path: &std::path::Path,
    connector_id: &str,
) -> Result<ConnectorConfig> {
    let config = AppConfig::load(config_path)?;
    let connector = config
        .connector(connector_id)
        .context("connector is no longer configured")?;
    if !connector.enabled {
        bail!("connector is disabled");
    }
    Ok(connector.clone())
}
