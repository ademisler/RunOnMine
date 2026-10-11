use std::collections::{HashMap, HashSet};
use std::time::Instant;

use runonmine_core::{
    AppConfig, AppPaths, ApprovalRequest, AuditRecord, AuditVerificationReport, ConnectorKind,
    PersistentGrant, StateStore,
};
use runonmine_oauth::{OAuthSession, RegisteredClient};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::connector_wizard::ConnectorWizardState;
use crate::desktop_acceptance::DesktopAcceptance;
use crate::desktop_instance::DesktopInstance;
use crate::desktop_lifecycle_acceptance::DesktopLifecycleAcceptance;
use crate::desktop_process::BackgroundCliTask;
use crate::desktop_shell::DesktopShell;
use crate::desktop_snapshot::{BackgroundDesktopSnapshot, ConnectorLifecycle};
use crate::policy_editor::PolicyEditorState;
use crate::theme::Icon as UiIcon;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Tab {
    #[default]
    Overview,
    Approvals,
    Connections,
    Permissions,
    OAuth,
    Audit,
    Diagnostics,
}

impl Tab {
    pub(crate) const ALL: [(Self, UiIcon, &'static str); 7] = [
        (Self::Overview, UiIcon::Home, "Overview"),
        (Self::Approvals, UiIcon::Clipboard, "Approvals"),
        (Self::Connections, UiIcon::Link, "Connections"),
        (Self::Permissions, UiIcon::Shield, "Permissions"),
        (Self::OAuth, UiIcon::Key, "OAuth"),
        (Self::Audit, UiIcon::FileText, "Audit log"),
        (Self::Diagnostics, UiIcon::Wrench, "Diagnostics"),
    ];

    pub(super) const fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Approvals => "Approvals",
            Self::Connections => "Connections",
            Self::Permissions => "Permissions",
            Self::OAuth => "OAuth access",
            Self::Audit => "Audit log",
            Self::Diagnostics => "Diagnostics",
        }
    }

    pub(crate) const fn acceptance_name(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Approvals => "approvals",
            Self::Connections => "connections",
            Self::Permissions => "permissions",
            Self::OAuth => "oauth",
            Self::Audit => "audit",
            Self::Diagnostics => "diagnostics",
        }
    }

    pub(super) const fn subtitle(self) -> &'static str {
        match self {
            Self::Overview => "Your machine access posture at a glance.",
            Self::Approvals => "Review actions that require your local confirmation.",
            Self::Connections => "Manage the secure paths AI clients use to reach this machine.",
            Self::Permissions => "Control roots, presets, identities, tools, and resources.",
            Self::OAuth => "Review registered clients and active authorization sessions.",
            Self::Audit => "Inspect recent tool activity and verify log integrity.",
            Self::Diagnostics => "Check installation health, services, and connector status.",
        }
    }
}

pub(super) struct RunOnMineDesktop {
    pub(super) paths: Option<AppPaths>,
    pub(super) store: Option<StateStore>,
    pub(super) config: Option<AppConfig>,
    pub(super) pending: Vec<ApprovalRequest>,
    pub(super) persistent_grants: Vec<PersistentGrant>,
    pub(super) audit: Vec<AuditRecord>,
    pub(super) oauth_clients: Vec<RegisteredClient>,
    pub(super) oauth_sessions: Vec<OAuthSession>,
    pub(super) quick_runtime_urls: HashMap<String, Url>,
    pub(super) connector_lifecycle: HashMap<String, ConnectorLifecycle>,
    pub(super) known: HashSet<Uuid>,
    pub(super) last_refresh: Instant,
    pub(super) snapshot_rx: Option<BackgroundDesktopSnapshot>,
    pub(super) audit_limit: usize,
    pub(super) audit_verification: Option<AuditVerificationReport>,
    pub(super) status: String,
    pub(super) error: Option<String>,
    pub(super) audit_valid: Option<bool>,
    pub(super) agent_reachable: bool,
    pub(super) selected_tab: Tab,
    pub(super) root_input: String,
    pub(super) diagnostics: String,
    pub(super) diagnostic_rx: Option<BackgroundCliTask>,
    pub(super) pending_client_delete: Option<(String, String)>,
    pub(super) pending_connector_delete: Option<String>,
    pub(super) pending_credential_update: Option<(String, ConnectorKind)>,
    pub(super) credential_client_id: String,
    pub(super) credential_secret: Zeroizing<String>,
    pub(super) policy_editor: PolicyEditorState,
    pub(super) connector_wizard: ConnectorWizardState,
    pub(super) connector_rx: Option<BackgroundCliTask>,
    pub(super) instance: DesktopInstance,
    pub(super) shell: DesktopShell,
    pub(super) exit_requested: bool,
    pub(super) acceptance: Option<DesktopAcceptance>,
    pub(super) lifecycle_acceptance: Option<DesktopLifecycleAcceptance>,
}
