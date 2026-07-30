use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use url::Url;

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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PrincipalMatcher {
    #[default]
    Any,
    Local,
    OAuthClient {
        client_id: String,
    },
    OAuthSubject {
        subject: String,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceMatcher {
    #[default]
    Any,
    FilesystemPrefix {
        path: PathBuf,
    },
    BrowserOrigin {
        origin: Url,
    },
    Executable {
        path: PathBuf,
    },
    CommandPrefix {
        prefix: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub mode: PolicyMode,
    #[serde(default)]
    pub principal: PrincipalMatcher,
    #[serde(default)]
    pub resource: ResourceMatcher,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub capability: Option<Capability>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalContext<'a> {
    Local,
    OAuth {
        client_id: &'a str,
        subject: &'a str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceContext<'a> {
    None,
    Filesystem(&'a Path),
    Browser(&'a Url),
    Executable(&'a Path),
    Command(&'a str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyContext<'a> {
    pub principal: PrincipalContext<'a>,
    pub resource: ResourceContext<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub mode: PolicyMode,
    pub source: DecisionSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionSource {
    ResourceRule,
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
        self.evaluate_context(
            connector,
            tool_name,
            capability,
            &PolicyContext {
                principal: PrincipalContext::Local,
                resource: ResourceContext::None,
            },
        )
    }

    pub fn evaluate_context(
        &self,
        connector: &ConnectorConfig,
        tool_name: &str,
        capability: Capability,
        context: &PolicyContext<'_>,
    ) -> PolicyDecision {
        let decision =
            matching_rule(connector, tool_name, capability, context).unwrap_or_else(|| {
                if let Some(mode) = connector.tool_overrides.get(tool_name) {
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
                }
            });
        apply_remote_safety_ceiling(connector, capability, decision)
    }
}

fn matching_rule(
    connector: &ConnectorConfig,
    tool_name: &str,
    capability: Capability,
    context: &PolicyContext<'_>,
) -> Option<PolicyDecision> {
    connector
        .policy_rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            rule.tool.as_deref().is_none_or(|tool| tool == tool_name)
                && rule.capability.is_none_or(|item| item == capability)
                && principal_matches(&rule.principal, &context.principal)
                && resource_matches(&rule.resource, &context.resource)
        })
        .max_by_key(|(index, rule)| (rule_specificity(rule), mode_priority(rule.mode), *index))
        .map(|(_, rule)| PolicyDecision {
            mode: rule.mode,
            source: DecisionSource::ResourceRule,
        })
}

fn rule_specificity(rule: &PolicyRule) -> u8 {
    u8::from(!matches!(rule.principal, PrincipalMatcher::Any))
        + u8::from(!matches!(rule.resource, ResourceMatcher::Any))
        + u8::from(rule.tool.is_some())
        + u8::from(rule.capability.is_some())
}

const fn mode_priority(mode: PolicyMode) -> u8 {
    match mode {
        PolicyMode::Deny => 3,
        PolicyMode::Ask => 2,
        PolicyMode::Allow => 1,
    }
}

fn principal_matches(matcher: &PrincipalMatcher, principal: &PrincipalContext<'_>) -> bool {
    match (matcher, principal) {
        (PrincipalMatcher::Any, _) | (PrincipalMatcher::Local, PrincipalContext::Local) => true,
        (
            PrincipalMatcher::OAuthClient { client_id },
            PrincipalContext::OAuth {
                client_id: actual, ..
            },
        ) => client_id == actual,
        (
            PrincipalMatcher::OAuthSubject { subject },
            PrincipalContext::OAuth {
                subject: actual, ..
            },
        ) => subject == actual,
        _ => false,
    }
}

fn resource_matches(matcher: &ResourceMatcher, resource: &ResourceContext<'_>) -> bool {
    match (matcher, resource) {
        (ResourceMatcher::Any, _) => true,
        (ResourceMatcher::FilesystemPrefix { path }, ResourceContext::Filesystem(actual)) => {
            actual == path || actual.starts_with(path)
        }
        (ResourceMatcher::BrowserOrigin { origin }, ResourceContext::Browser(actual)) => {
            same_origin(origin, actual)
        }
        (ResourceMatcher::Executable { path }, ResourceContext::Executable(actual)) => {
            path == actual
        }
        (ResourceMatcher::CommandPrefix { prefix }, ResourceContext::Command(actual)) => {
            command_prefix_matches(prefix, actual)
        }
        _ => false,
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn command_prefix_matches(prefix: &str, actual: &str) -> bool {
    if prefix.is_empty()
        || contains_shell_control_syntax(prefix)
        || contains_shell_control_syntax(actual)
    {
        return false;
    }
    if prefix.chars().last().is_some_and(char::is_whitespace) {
        return actual.starts_with(prefix);
    }
    actual == prefix
        || actual
            .strip_prefix(prefix)
            .and_then(|remainder| remainder.chars().next())
            .is_some_and(char::is_whitespace)
}

fn contains_shell_control_syntax(command: &str) -> bool {
    command
        .chars()
        .any(|character| matches!(character, ';' | '|' | '&' | '<' | '>' | '`' | '\n' | '\r'))
        || command.contains("$(")
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
    use proptest::prelude::*;

    fn policy_mode_strategy() -> impl Strategy<Value = PolicyMode> {
        prop_oneof![
            Just(PolicyMode::Deny),
            Just(PolicyMode::Ask),
            Just(PolicyMode::Allow),
        ]
    }

    fn policy_preset_strategy() -> impl Strategy<Value = PolicyPreset> {
        prop::sample::select(vec![
            PolicyPreset::Safe,
            PolicyPreset::Developer,
            PolicyPreset::Full,
            PolicyPreset::Custom,
        ])
    }

    fn capability_strategy() -> impl Strategy<Value = Capability> {
        prop::sample::select(Capability::ALL.to_vec())
    }

    fn remote_connector_kind_strategy() -> impl Strategy<Value = ConnectorKind> {
        prop::sample::select(vec![
            ConnectorKind::CloudflareQuick,
            ConnectorKind::CloudflareOauth,
            ConnectorKind::OpenAiTunnel,
        ])
    }

    fn dangerous_remote_capability_strategy() -> impl Strategy<Value = Capability> {
        prop::sample::select(vec![
            Capability::FilesWrite,
            Capability::ShellExec,
            Capability::BrowserAct,
            Capability::DesktopControl,
            Capability::PlatformNative,
            Capability::AdminExec,
        ])
    }

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
    fn principal_and_resource_rules_are_enforced() {
        let mut connector = ConnectorConfig::local_default();
        connector.policy_rules.push(PolicyRule {
            mode: PolicyMode::Allow,
            principal: PrincipalMatcher::OAuthClient {
                client_id: "trusted".to_owned(),
            },
            resource: ResourceMatcher::FilesystemPrefix {
                path: PathBuf::from("/safe"),
            },
            tool: Some("fs_read".to_owned()),
            capability: None,
        });
        let safe = Path::new("/safe/report.txt");
        let context = PolicyContext {
            principal: PrincipalContext::OAuth {
                client_id: "trusted",
                subject: "owner",
            },
            resource: ResourceContext::Filesystem(safe),
        };
        let decision =
            PolicyEngine.evaluate_context(&connector, "fs_read", Capability::FilesRead, &context);
        assert_eq!(decision.mode, PolicyMode::Allow);
        assert_eq!(decision.source, DecisionSource::ResourceRule);
        let other = PolicyContext {
            principal: PrincipalContext::OAuth {
                client_id: "other",
                subject: "owner",
            },
            resource: ResourceContext::Filesystem(safe),
        };
        assert_eq!(
            PolicyEngine
                .evaluate_context(&connector, "fs_read", Capability::FilesRead, &other)
                .source,
            DecisionSource::Preset
        );
    }

    #[test]
    fn explicit_resource_deny_wins_at_equal_specificity() {
        let mut connector = ConnectorConfig::local_default();
        for mode in [PolicyMode::Allow, PolicyMode::Deny] {
            connector.policy_rules.push(PolicyRule {
                mode,
                principal: PrincipalMatcher::Any,
                resource: ResourceMatcher::CommandPrefix {
                    prefix: "rm ".to_owned(),
                },
                tool: None,
                capability: Some(Capability::ShellExec),
            });
        }
        let context = PolicyContext {
            principal: PrincipalContext::Local,
            resource: ResourceContext::Command("rm -rf tmp"),
        };
        assert_eq!(
            PolicyEngine
                .evaluate_context(&connector, "shell_exec", Capability::ShellExec, &context)
                .mode,
            PolicyMode::Deny
        );
    }

    #[test]
    fn command_prefix_requires_a_token_boundary() {
        assert!(command_prefix_matches("cargo test", "cargo test"));
        assert!(command_prefix_matches(
            "cargo test",
            "cargo test --workspace"
        ));
        assert!(!command_prefix_matches("cargo test", "cargo testing"));
        assert!(command_prefix_matches("rm ", "rm -rf tmp"));
        assert!(!command_prefix_matches("", "anything"));
    }

    #[test]
    fn command_prefix_rejects_shell_composition_and_substitution() {
        for command in [
            "cargo test && rm -rf tmp",
            "cargo test || printf failed",
            "cargo test; rm -rf tmp",
            "cargo test | tee output",
            "cargo test > output",
            "cargo test < input",
            "cargo test `printf injected`",
            "cargo test $(printf injected)",
            "cargo test\nprintf injected",
            "cargo test\rprintf injected",
        ] {
            assert!(
                !command_prefix_matches("cargo test", command),
                "accepted unsafe shell command {command:?}"
            );
        }
        assert!(!command_prefix_matches(
            "cargo test &&",
            "cargo test && true"
        ));
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
    }

    #[test]
    fn safe_preset_denies_admin() {
        assert_eq!(
            PolicyPreset::Safe.modes().get(&Capability::AdminExec),
            Some(&PolicyMode::Deny)
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn tool_override_always_precedes_pack_and_preset(
            capability in capability_strategy(),
            preset in policy_preset_strategy(),
            pack_mode in policy_mode_strategy(),
            tool_mode in policy_mode_strategy(),
        ) {
            let mut connector = ConnectorConfig::local_default();
            connector.policy_preset = preset;
            connector.pack_overrides.insert(capability, pack_mode);
            connector
                .tool_overrides
                .insert("property_tool".to_owned(), tool_mode);

            let decision = PolicyEngine.evaluate(&connector, "property_tool", capability);
            prop_assert_eq!(decision.mode, tool_mode);
            prop_assert_eq!(decision.source, DecisionSource::ToolOverride);
        }

        #[test]
        fn pack_override_always_precedes_preset_when_tool_override_is_absent(
            capability in capability_strategy(),
            preset in policy_preset_strategy(),
            pack_mode in policy_mode_strategy(),
        ) {
            let mut connector = ConnectorConfig::local_default();
            connector.policy_preset = preset;
            connector.pack_overrides.insert(capability, pack_mode);
            connector
                .tool_overrides
                .insert("different_tool".to_owned(), PolicyMode::Deny);

            let decision = PolicyEngine.evaluate(&connector, "property_tool", capability);
            prop_assert_eq!(decision.mode, pack_mode);
            prop_assert_eq!(decision.source, DecisionSource::PackOverride);
        }

        #[test]
        fn equal_specificity_deny_wins_regardless_of_rule_order(
            command in "[a-z][a-z0-9_-]{0,11}",
            argument in "[a-z0-9][a-z0-9_-]{0,15}",
            deny_first in any::<bool>(),
        ) {
            let mut connector = ConnectorConfig::local_default();
            let modes = if deny_first {
                [PolicyMode::Deny, PolicyMode::Allow]
            } else {
                [PolicyMode::Allow, PolicyMode::Deny]
            };
            for mode in modes {
                connector.policy_rules.push(PolicyRule {
                    mode,
                    principal: PrincipalMatcher::Any,
                    resource: ResourceMatcher::CommandPrefix {
                        prefix: command.clone(),
                    },
                    tool: Some("shell_exec".to_owned()),
                    capability: Some(Capability::ShellExec),
                });
            }
            let actual = format!("{command} {argument}");
            let context = PolicyContext {
                principal: PrincipalContext::Local,
                resource: ResourceContext::Command(&actual),
            };

            let decision = PolicyEngine.evaluate_context(
                &connector,
                "shell_exec",
                Capability::ShellExec,
                &context,
            );
            prop_assert_eq!(decision.mode, PolicyMode::Deny);
            prop_assert_eq!(decision.source, DecisionSource::ResourceRule);
        }

        #[test]
        fn remote_safety_ceiling_never_auto_allows_dangerous_capabilities(
            kind in remote_connector_kind_strategy(),
            capability in dangerous_remote_capability_strategy(),
            requested_mode in policy_mode_strategy(),
        ) {
            let mut connector = ConnectorConfig::local_default();
            connector.kind = kind;
            connector
                .tool_overrides
                .insert("property_tool".to_owned(), requested_mode);

            let decision = PolicyEngine.evaluate(&connector, "property_tool", capability);
            prop_assert_ne!(decision.mode, PolicyMode::Allow);
            if capability == Capability::AdminExec {
                prop_assert_eq!(decision.mode, PolicyMode::Deny);
            }
        }
    }
}
