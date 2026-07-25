use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use eframe::egui;
use runonmine_core::{
    AppConfig, Capability, PolicyMode, PolicyRule, PrincipalMatcher, ResourceMatcher,
};
use url::Url;

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
    #[allow(clippy::too_many_lines)]
    pub(crate) fn show(
        &mut self,
        ui: &mut egui::Ui,
        config: &AppConfig,
    ) -> Result<Option<PolicyEditorAction>> {
        ui.heading("Advanced policy rules");
        ui.label("Restrict a connector by identity, exact tool or capability, and a concrete resource. More specific rules win; deny wins ties.");
        if self.connector_id.is_empty() {
            self.connector_id = config
                .connectors
                .first()
                .map(|connector| connector.id.clone())
                .unwrap_or_default();
        }
        if config.connectors.is_empty() {
            ui.label("Create a connector before adding policy rules.");
            return Ok(None);
        }

        let selected_name = config
            .connector(&self.connector_id)
            .map_or("Select connector", |connector| connector.name.as_str());
        egui::ComboBox::from_id_salt("policy-rule-connector")
            .selected_text(selected_name)
            .show_ui(ui, |ui| {
                for connector in &config.connectors {
                    ui.selectable_value(
                        &mut self.connector_id,
                        connector.id.clone(),
                        &connector.name,
                    );
                }
            });

        ui.separator();
        egui::Grid::new("policy-rule-builder")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Decision");
                egui::ComboBox::from_id_salt("policy-rule-mode")
                    .selected_text(format!("{:?}", self.mode))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.mode, PolicyMode::Deny, "Deny");
                        ui.selectable_value(&mut self.mode, PolicyMode::Ask, "Ask locally");
                        ui.selectable_value(&mut self.mode, PolicyMode::Allow, "Allow");
                    });
                ui.end_row();

                ui.label("Identity");
                egui::ComboBox::from_id_salt("policy-rule-principal")
                    .selected_text(format!("{:?}", self.principal_kind))
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
                    ui.label("Identity value");
                    ui.text_edit_singleline(&mut self.principal_value);
                    ui.end_row();
                }

                ui.label("Resource");
                egui::ComboBox::from_id_salt("policy-rule-resource")
                    .selected_text(format!("{:?}", self.resource_kind))
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
                    ui.label("Resource value");
                    ui.text_edit_singleline(&mut self.resource_value);
                    ui.end_row();
                }

                ui.label("Tool (optional)");
                ui.text_edit_singleline(&mut self.tool);
                ui.end_row();

                ui.label("Capability (optional)");
                egui::ComboBox::from_id_salt("policy-rule-capability")
                    .selected_text(
                        self.capability
                            .map_or_else(|| "Any".to_owned(), |item| format!("{item:?}")),
                    )
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

        let mut action = None;
        if ui.button("Add validated rule").clicked() {
            action = Some(PolicyEditorAction::Add {
                connector_id: self.connector_id.clone(),
                rule: self.build_rule()?,
            });
        }

        ui.separator();
        ui.heading("Configured rules");
        let Some(connector) = config.connector(&self.connector_id) else {
            return Ok(action);
        };
        if connector.policy_rules.is_empty() {
            ui.label("No advanced rules for this connector.");
        }
        for (index, rule) in connector.policy_rules.iter().enumerate() {
            ui.group(|ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(format!("{:?}", rule.mode));
                    ui.label(describe_rule(rule));
                    if ui.button("Remove").clicked() {
                        action = Some(PolicyEditorAction::Remove {
                            connector_id: connector.id.clone(),
                            index,
                        });
                    }
                });
            });
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
