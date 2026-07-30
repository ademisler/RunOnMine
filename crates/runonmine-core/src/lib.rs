//! Shared security, configuration, persistence, and execution primitives.

pub mod approval;
mod approval_notifications;
mod atomic;
pub mod audit;
mod audit_mac;
pub mod config;
pub mod connector_id;
pub mod connector_removal;
pub mod filesystem;
pub mod paths;
pub mod policy;
pub mod process;
pub mod quick_tunnel_runtime;
pub mod secrets;
pub mod storage;

pub use approval::{
    ApprovalDecision, ApprovalPrincipal, ApprovalRequest, ApprovalStatus, ApprovalTimeoutResult,
    PersistentGrant,
};
pub use approval_notifications::{
    ApprovalNotificationMetrics, ApprovalNotificationSubscription, ApprovalNotifications,
};
pub use audit::{AuditEvent, AuditOutcome};
pub use config::{
    AppConfig, BrowserProfileMode, CloudflareNamedSettings, CloudflareQuickSettings,
    ConnectorConfig, ConnectorKind, OAuthOwnerSettings, OpenAiTunnelSettings,
};
pub use connector_id::{
    CONNECTOR_ID_MAX_LEN, CONNECTOR_ID_MIN_LEN, connector_id_is_valid, validate_connector_id,
};
pub use connector_removal::{
    ConnectorRemovalJournal, ConnectorRemovalLock, ConnectorRemovalPhase, ConnectorRemovalRecord,
    connector_secret_suffixes, remove_connector_authorization,
    remove_connector_configuration_and_secrets, remove_connector_directories,
};
pub use paths::AppPaths;
pub use policy::{
    Capability, DecisionSource, PolicyContext, PolicyDecision, PolicyEngine, PolicyMode,
    PolicyPreset, PolicyRule, PrincipalContext, PrincipalMatcher, ResourceContext, ResourceMatcher,
};
pub use quick_tunnel_runtime::{
    QuickTunnelGeneration, QuickTunnelRuntimeRecord, QuickTunnelRuntimeStore,
    validate_quick_tunnel_url,
};
pub use storage::{AuditRecord, ConnectorAuthorizationCleanup, StateStore, StateStoreMetrics};

/// Product identifier used for OS integration and MCP metadata.
pub const PRODUCT_NAME: &str = "RunOnMine";
/// Default loopback port. The legacy `MacMCP` service uses 45799 and is never touched.
pub const DEFAULT_PORT: u16 = 47_821;
/// Current configuration schema version.
pub const CONFIG_VERSION: u32 = 1;
