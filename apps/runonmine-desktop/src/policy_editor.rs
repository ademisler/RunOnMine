use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use eframe::egui;
use runonmine_core::{
    AppConfig, Capability, PolicyMode, PolicyRule, PrincipalMatcher, ResourceMatcher,
};
use url::Url;

use crate::theme;
use crate::theme::{Icon, StatusTone};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PrincipalKind {
    #[default]
    Any,
    Local,
    OAuthClient,
    OAuthSubject,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ResourceKind {
    #[default]
    Any,
    FilesystemPrefix,
    BrowserOrigin,
    Executable,
    CommandPrefix,
}

#[derive(Debug, Default)]
pub(crate) struct PolicyEditorState {
    connector_id: String,
    mode: PolicyMode,
    principal_kind: PrincipalKind,
    principal_value: String,
    resource_kind: ResourceKind,
    resource_value: String,
    tool: String,
    capability: Option<Capability>,
}

#[derive(Debug)]
pub(crate) enum PolicyEditorAction {
    Add {
        connector_id: String,
        rule: PolicyRule,
    },
    Remove {
        connector_id: String,
        index: usize,
    },
}

impl PolicyEditorState {
    #[allow(clippy::too_many_lines)] // Policy form extraction remains tracked in P2-02.
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        config: &AppConfig,
    ) -> Result<Option<PolicyEditorAction>> {
        if self.connector_id.is_empty() {
            self.connector_id = config
                .connectors
                .first()
                .map(|connector| connector.id.clone())
                .unwrap_or_default();
        }
        if config.connectors.is_empty() {
            theme::empty_state(
                ui,
                Icon::Link,
                "No connector available",
                "Create a connector before adding advanced policy rules.",
            );
            return Ok(None);
        }

        let mut action = None;
        let mut add_rule = false;
        theme::card(ui, |ui| {
            theme::section_header(
                ui,
                "Advanced policy rules",
                "Target a specific identity, tool, capability, or resource. More specific rules win; deny wins ties.",
            );

            ui.label(
                egui::RichText::new("Connector")
                    .size(12.0)
                    .color(theme::MUTED),
            );
            let selected_name = config
                .connector(&self.connector_id)
                .map_or("Select connector", |connector| connector.name.as_str());
            egui::ComboBox::from_id_salt("policy-rule-connector")
                .selected_text(selected_name)
                .width(ui.available_width())
                .show_ui(ui, |ui| {
                    for connector in &config.connectors {
                        ui.selectable_value(
                            &mut self.connector_id,
                            connector.id.clone(),
                            &connector.name,
                        );
                    }
                });
            ui.add_space(14.0);

            egui::Grid::new("policy-rule-builder")
                .num_columns(2)
                .spacing([18.0, 12.0])
                .min_col_width(180.0)
                .show(ui, |ui| {
                    field_label(ui, "Decision");
                    egui::ComboBox::from_id_salt("policy-rule-mode")
                        .selected_text(format!("{:?}", self.mode))
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.mode, PolicyMode::Deny, "Deny");
                            ui.selectable_value(&mut self.mode, PolicyMode::Ask, "Ask locally");
                            ui.selectable_value(&mut self.mode, PolicyMode::Allow, "Allow");
                        });
                    ui.end_row();

                    field_label(ui, "Identity");
                    egui::ComboBox::from_id_salt("policy-rule-principal")
                        .selected_text(format!("{:?}", self.principal_kind))
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.principal_kind,
                                PrincipalKind::Any,
                                "Any identity",
                            );
                            ui.selectable_value(
                                &mut self.principal_kind,
                                PrincipalKind::Local,
                                "Local only",
                            );
                            ui.selectable_value(
                                &mut self.principal_kind,
                                PrincipalKind::OAuthClient,
                                "OAuth client ID",
                            );
                            ui.selectable_value(
                                &mut self.principal_kind,
                                PrincipalKind::OAuthSubject,
                                "OAuth subject",
                            );
                        });
                    ui.end_row();

                    if matches!(
                        self.principal_kind,
                        PrincipalKind::OAuthClient | PrincipalKind::OAuthSubject
                    ) {
                        field_label(ui, "Identity value");
                        ui.add_sized(
                            [360.0, 34.0],
                            egui::TextEdit::singleline(&mut self.principal_value)
                                .hint_text("Exact client ID or subject"),
                        );
                        ui.end_row();
                    }

                    field_label(ui, "Resource");
                    egui::ComboBox::from_id_salt("policy-rule-resource")
                        .selected_text(format!("{:?}", self.resource_kind))
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.resource_kind,
                                ResourceKind::Any,
                                "Any resource",
                            );
                            ui.selectable_value(
                                &mut self.resource_kind,
                                ResourceKind::FilesystemPrefix,
                                "Filesystem prefix",
                            );
                            ui.selectable_value(
                                &mut self.resource_kind,
                                ResourceKind::BrowserOrigin,
                                "Browser origin",
                            );
                            ui.selectable_value(
                                &mut self.resource_kind,
                                ResourceKind::Executable,
                                "Executable path",
                            );
                            ui.selectable_value(
                                &mut self.resource_kind,
                                ResourceKind::CommandPrefix,
                                "Command prefix",
                            );
                        });
                    ui.end_row();

                    if self.resource_kind != ResourceKind::Any {
                        field_label(ui, "Resource value");
                        ui.add_sized(
                            [360.0, 34.0],
                            egui::TextEdit::singleline(&mut self.resource_value)
                                .hint_text(resource_hint(self.resource_kind)),
                        );
                        ui.end_row();
                    }

                    field_label(ui, "Tool (optional)");
                    ui.add_sized(
                        [360.0, 34.0],
                        egui::TextEdit::singleline(&mut self.tool).hint_text("e.g. fs_read"),
                    );
                    ui.end_row();

                    field_label(ui, "Capability (optional)");
                    egui::ComboBox::from_id_salt("policy-rule-capability")
                        .selected_text(self.capability.map_or_else(
                            || "Any capability".to_owned(),
                            |item| format!("{item:?}"),
                        ))
                        .width(220.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.capability, None, "Any capability");
                            for capability in Capability::ALL {
                                ui.selectable_value(
                                    &mut self.capability,
                                    Some(capability),
                                    format!("{capability:?}"),
                                );
                            }
                        });
                    ui.end_row();
                });

            ui.add_space(14.0);
            if ui
                .add(theme::primary_button("Add validated rule"))
                .clicked()
            {
                add_rule = true;
            }
        });
        if add_rule {
            action = Some(PolicyEditorAction::Add {
                connector_id: self.connector_id.clone(),
                rule: self.build_rule()?,
            });
        }

        ui.add_space(16.0);
        theme::section_header(
            ui,
            "Configured rules",
            "Rules are evaluated before connector overrides and presets.",
        );
        let Some(connector) = config.connector(&self.connector_id) else {
            return Ok(action);
        };
        if connector.policy_rules.is_empty() {
            theme::empty_state(
                ui,
                Icon::Shield,
                "No advanced rules",
                "This connector currently relies on its preset and overrides.",
            );
        }
        for (index, rule) in connector.policy_rules.iter().enumerate() {
            theme::subtle_card(ui, |ui| {
                ui.horizontal(|ui| {
                    theme::status_badge(
                        ui,
                        &format!("{:?}", rule.mode),
                        match rule.mode {
                            PolicyMode::Allow => StatusTone::Success,
                            PolicyMode::Ask => StatusTone::Warning,
                            PolicyMode::Deny => StatusTone::Danger,
                        },
                    );
                    ui.label(
                        egui::RichText::new(describe_rule(rule))
                            .size(12.0)
                            .color(theme::TEXT),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(theme::danger_button("Remove")).clicked() {
                            action = Some(PolicyEditorAction::Remove {
                                connector_id: connector.id.clone(),
                                index,
                            });
                        }
                    });
                });
            });
            ui.add_space(7.0);
        }
        Ok(action)
    }

    fn build_rule(&self) -> Result<PolicyRule> {
        let principal = match self.principal_kind {
            PrincipalKind::Any => PrincipalMatcher::Any,
            PrincipalKind::Local => PrincipalMatcher::Local,
            PrincipalKind::OAuthClient => PrincipalMatcher::OAuthClient {
                client_id: required(&self.principal_value, "OAuth client ID")?,
            },
            PrincipalKind::OAuthSubject => PrincipalMatcher::OAuthSubject {
                subject: required(&self.principal_value, "OAuth subject")?,
            },
        };
        let resource = match self.resource_kind {
            ResourceKind::Any => ResourceMatcher::Any,
            ResourceKind::FilesystemPrefix => ResourceMatcher::FilesystemPrefix {
                path: absolute_path(&self.resource_value, "filesystem prefix")?,
            },
            ResourceKind::BrowserOrigin => {
                let origin = Url::parse(&required(&self.resource_value, "browser origin")?)
                    .context("Browser origin is not a valid URL")?;
                ResourceMatcher::BrowserOrigin { origin }
            }
            ResourceKind::Executable => ResourceMatcher::Executable {
                path: absolute_path(&self.resource_value, "executable path")?,
            },
            ResourceKind::CommandPrefix => ResourceMatcher::CommandPrefix {
                prefix: required(&self.resource_value, "command prefix")?,
            },
        };
        Ok(PolicyRule {
            mode: self.mode,
            principal,
            resource,
            tool: (!self.tool.trim().is_empty()).then(|| self.tool.trim().to_owned()),
            capability: self.capability,
        })
    }
}

fn field_label(ui: &mut egui::Ui, label: &str) {
    ui.label(egui::RichText::new(label).size(12.0).color(theme::MUTED));
}

const fn resource_hint(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Any => "",
        ResourceKind::FilesystemPrefix => "/absolute/path",
        ResourceKind::BrowserOrigin => "https://example.com/",
        ResourceKind::Executable => "/absolute/path/to/executable",
        ResourceKind::CommandPrefix => "cargo test",
    }
}

fn required(value: &str, label: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        bail!("{label} is required");
    }
    Ok(value.to_owned())
}

fn absolute_path(value: &str, label: &str) -> Result<PathBuf> {
    let path = PathBuf::from(required(value, label)?);
    if !path.is_absolute() {
        bail!("{label} must be an absolute path");
    }
    Ok(path)
}

fn describe_rule(rule: &PolicyRule) -> String {
    let principal = match &rule.principal {
        PrincipalMatcher::Any => "any identity".to_owned(),
        PrincipalMatcher::Local => "local identity".to_owned(),
        PrincipalMatcher::OAuthClient { client_id } => format!("OAuth client {client_id}"),
        PrincipalMatcher::OAuthSubject { subject } => format!("OAuth subject {subject}"),
    };
    let resource = match &rule.resource {
        ResourceMatcher::Any => "any resource".to_owned(),
        ResourceMatcher::FilesystemPrefix { path } => format!("files under {}", path.display()),
        ResourceMatcher::BrowserOrigin { origin } => format!("origin {origin}"),
        ResourceMatcher::Executable { path } => format!("executable {}", path.display()),
        ResourceMatcher::CommandPrefix { prefix } => format!("command prefix {prefix:?}"),
    };
    let tool = rule.tool.as_deref().unwrap_or("any tool");
    let capability = rule
        .capability
        .map_or_else(|| "any capability".to_owned(), |item| format!("{item:?}"));
    format!("{principal} · {resource} · {tool} · {capability}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_scoped_oauth_filesystem_rule() -> Result<()> {
        let editor = PolicyEditorState {
            connector_id: "connector".to_owned(),
            mode: PolicyMode::Allow,
            principal_kind: PrincipalKind::OAuthClient,
            principal_value: "trusted-client".to_owned(),
            resource_kind: ResourceKind::FilesystemPrefix,
            resource_value: "/safe/project".to_owned(),
            tool: "fs_read".to_owned(),
            capability: Some(Capability::FilesRead),
        };
        let rule = editor.build_rule()?;
        assert_eq!(rule.mode, PolicyMode::Allow);
        assert_eq!(
            rule.principal,
            PrincipalMatcher::OAuthClient {
                client_id: "trusted-client".to_owned()
            }
        );
        assert_eq!(
            rule.resource,
            ResourceMatcher::FilesystemPrefix {
                path: PathBuf::from("/safe/project")
            }
        );
        assert_eq!(rule.tool.as_deref(), Some("fs_read"));
        assert_eq!(rule.capability, Some(Capability::FilesRead));
        Ok(())
    }

    #[test]
    fn rejects_relative_paths_and_missing_identity_values() {
        let relative = PolicyEditorState {
            resource_kind: ResourceKind::FilesystemPrefix,
            resource_value: "relative/path".to_owned(),
            ..PolicyEditorState::default()
        };
        assert!(relative.build_rule().is_err());

        let missing_client = PolicyEditorState {
            principal_kind: PrincipalKind::OAuthClient,
            ..PolicyEditorState::default()
        };
        assert!(missing_client.build_rule().is_err());
    }

    #[test]
    fn generated_rule_passes_full_config_validation() -> Result<()> {
        let editor = PolicyEditorState {
            mode: PolicyMode::Ask,
            principal_kind: PrincipalKind::Local,
            resource_kind: ResourceKind::CommandPrefix,
            resource_value: "cargo test".to_owned(),
            capability: Some(Capability::ShellExec),
            ..PolicyEditorState::default()
        };
        let mut config = AppConfig::default();
        config.connectors[0].policy_rules.push(editor.build_rule()?);
        config.validate()
    }
}
