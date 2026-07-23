use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::{ConnectorConfig, ConnectorKind};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    SystemRead,
    FilesRead,
    FilesWrite,
    ShellExec,
    BrowserRead,
    BrowserAct,
    DesktopControl,
    PlatformNative,
    AdminExec,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    #[default]
    Deny,
    Ask,
    Allow,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPreset {
    #[default]
    Safe,
    Developer,
    Full,
    Custom,
}

impl PolicyPreset {
    pub fn modes(self) -> BTreeMap<Capability, PolicyMode> {
        use Capability::{
            AdminExec, BrowserAct, BrowserRead, DesktopControl, FilesRead, FilesWrite,
            PlatformNative, ShellExec, SystemRead,
        };
        use PolicyMode::{Allow, Ask, Deny};

        match self {
            Self::Safe => BTreeMap::from([
                (SystemRead, Allow),
                (FilesRead, Allow),
                (FilesWrite, Ask),
                (ShellExec, Ask),
                (BrowserRead, Allow),
                (BrowserAct, Ask),
                (DesktopControl, Ask),
                (PlatformNative, Ask),
                (AdminExec, Deny),
            ]),
            Self::Developer => BTreeMap::from([
                (SystemRead, Allow),
                (FilesRead, Allow),
                (FilesWrite, Allow),
                (ShellExec, Allow),
                (BrowserRead, Allow),
                (BrowserAct, Ask),
                (DesktopControl, Ask),
                (PlatformNative, Ask),
                (AdminExec, Deny),
            ]),
            Self::Full => Capability::ALL
                .into_iter()
                .map(|capability| (capability, Allow))
                .collect(),
            Self::Custom => BTreeMap::new(),
        }
    }
}

impl Capability {
    pub const ALL: [Self; 9] = [
        Self::SystemRead,
        Self::FilesRead,
        Self::FilesWrite,
        Self::ShellExec,
        Self::BrowserRead,
        Self::BrowserAct,
        Self::DesktopControl,
        Self::PlatformNative,
        Self::AdminExec,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub mode: PolicyMode,
    pub source: DecisionSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionSource {
    ToolOverride,
    PackOverride,
    Preset,
    DefaultDeny,
    RemoteSafetyCeiling,
}

#[derive(Clone, Debug, Default)]
pub struct PolicyEngine;

impl PolicyEngine {
    pub fn evaluate(
        &self,
        connector: &ConnectorConfig,
        tool_name: &str,
        capability: Capability,
    ) -> PolicyDecision {
        let decision = if let Some(mode) = connector.tool_overrides.get(tool_name) {
            PolicyDecision {
                mode: *mode,
                source: DecisionSource::ToolOverride,
            }
        } else if let Some(mode) = connector.pack_overrides.get(&capability) {
            PolicyDecision {
                mode: *mode,
                source: DecisionSource::PackOverride,
            }
        } else if let Some(mode) = connector.policy_preset.modes().get(&capability) {
            PolicyDecision {
                mode: *mode,
                source: DecisionSource::Preset,
            }
        } else {
            PolicyDecision {
                mode: PolicyMode::Deny,
                source: DecisionSource::DefaultDeny,
            }
        };
        apply_remote_safety_ceiling(connector, capability, decision)
    }
}

fn apply_remote_safety_ceiling(
    connector: &ConnectorConfig,
    capability: Capability,
    decision: PolicyDecision,
) -> PolicyDecision {
    if !matches!(
        connector.kind,
        ConnectorKind::CloudflareQuick
            | ConnectorKind::CloudflareOauth
            | ConnectorKind::OpenAiTunnel
    ) {
        return decision;
    }
    let capped_mode = match capability {
        Capability::AdminExec => PolicyMode::Deny,
        Capability::FilesWrite
        | Capability::ShellExec
        | Capability::BrowserAct
        | Capability::DesktopControl
        | Capability::PlatformNative
            if decision.mode == PolicyMode::Allow =>
        {
            PolicyMode::Ask
        }
        _ => return decision,
    };
    if capped_mode == decision.mode {
        return decision;
    }
    PolicyDecision {
        mode: capped_mode,
        source: DecisionSource::RemoteSafetyCeiling,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ConnectorConfig, ConnectorKind};

    #[test]
    fn precedence_is_tool_then_pack_then_preset() {
        let engine = PolicyEngine;
        let mut connector = ConnectorConfig::local_default();
        connector.policy_preset = PolicyPreset::Safe;
        assert_eq!(
            engine
                .evaluate(&connector, "shell_exec", Capability::ShellExec)
                .mode,
            PolicyMode::Ask
        );
        connector
            .pack_overrides
            .insert(Capability::ShellExec, PolicyMode::Allow);
        assert_eq!(
            engine
                .evaluate(&connector, "shell_exec", Capability::ShellExec)
                .mode,
            PolicyMode::Allow
        );
        connector
            .tool_overrides
            .insert("shell_exec".to_owned(), PolicyMode::Deny);
        let decision = engine.evaluate(&connector, "shell_exec", Capability::ShellExec);
        assert_eq!(decision.mode, PolicyMode::Deny);
        assert_eq!(decision.source, DecisionSource::ToolOverride);
    }

    #[test]
    fn remote_connectors_cannot_auto_allow_dangerous_capabilities() {
        let mut connector = ConnectorConfig::local_default();
        connector.kind = ConnectorKind::CloudflareQuick;
        connector.cloudflare_quick = Some(crate::config::CloudflareQuickSettings::default());
        connector.policy_preset = PolicyPreset::Full;
        let shell = PolicyEngine.evaluate(&connector, "shell_exec", Capability::ShellExec);
        assert_eq!(shell.mode, PolicyMode::Ask);
        assert_eq!(shell.source, DecisionSource::RemoteSafetyCeiling);
        let admin = PolicyEngine.evaluate(&connector, "admin_exec", Capability::AdminExec);
        assert_eq!(admin.mode, PolicyMode::Deny);
        assert_eq!(admin.source, DecisionSource::RemoteSafetyCeiling);
    }

    #[test]
    fn remote_safety_ceiling_preserves_explicit_denials() {
        let mut connector = ConnectorConfig::local_default();
        connector.kind = ConnectorKind::OpenAiTunnel;
        connector.openai_tunnel = Some(crate::config::OpenAiTunnelSettings {
            tunnel_id: "tunnel_0123456789abcdef0123456789abcdef".to_owned(),
            profile: "test".to_owned(),
            tunnel_client_path: None,
            health_port: 47_823,
        });
        connector
            .tool_overrides
            .insert("shell_exec".to_owned(), PolicyMode::Deny);
        let decision = PolicyEngine.evaluate(&connector, "shell_exec", Capability::ShellExec);
        assert_eq!(decision.mode, PolicyMode::Deny);
        assert_eq!(decision.source, DecisionSource::ToolOverride);
    }

    #[test]
    fn safe_preset_denies_admin() {
        assert_eq!(
            PolicyPreset::Safe.modes().get(&Capability::AdminExec),
            Some(&PolicyMode::Deny)
        );
    }
}
