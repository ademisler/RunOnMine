use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::ConnectorConfig;

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
        if let Some(mode) = connector.tool_overrides.get(tool_name) {
            return PolicyDecision {
                mode: *mode,
                source: DecisionSource::ToolOverride,
            };
        }
        if let Some(mode) = connector.pack_overrides.get(&capability) {
            return PolicyDecision {
                mode: *mode,
                source: DecisionSource::PackOverride,
            };
        }
        if let Some(mode) = connector.policy_preset.modes().get(&capability) {
            return PolicyDecision {
                mode: *mode,
                source: DecisionSource::Preset,
            };
        }
        PolicyDecision {
            mode: PolicyMode::Deny,
            source: DecisionSource::DefaultDeny,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConnectorConfig;

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
    fn safe_preset_denies_admin() {
        assert_eq!(
            PolicyPreset::Safe.modes().get(&Capability::AdminExec),
            Some(&PolicyMode::Deny)
        );
    }
}
