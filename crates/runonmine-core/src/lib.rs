//! Shared security, configuration, persistence, and execution primitives.

pub mod approval;
mod atomic;
pub mod audit;
pub mod config;
pub mod filesystem;
pub mod paths;
pub mod policy;
pub mod process;
pub mod secrets;
pub mod storage;

pub use approval::{ApprovalDecision, ApprovalRequest, ApprovalStatus, PersistentGrant};
pub use audit::{AuditEvent, AuditOutcome};
pub use config::{
    AppConfig, BrowserProfileMode, CloudflareNamedSettings, CloudflareQuickSettings,
    ConnectorConfig, ConnectorKind, OAuthOwnerSettings, OpenAiTunnelSettings,
};
pub use paths::AppPaths;
pub use policy::{Capability, PolicyDecision, PolicyEngine, PolicyMode, PolicyPreset};
pub use storage::{AuditRecord, StateStore};

/// Product identifier used for OS integration and MCP metadata.
pub const PRODUCT_NAME: &str = "RunOnMine";
/// Default loopback port. The legacy `MacMCP` service uses 45799 and is never touched.
pub const DEFAULT_PORT: u16 = 47_821;
/// Current configuration schema version.
pub const CONFIG_VERSION: u32 = 1;
