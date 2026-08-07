use super::super::{
    ConnectorConfig, ConnectorKind, RunOnMineDesktop, StatusTone, Zeroize, egui, rotation_label,
    theme,
};

#[derive(Debug, Default)]
struct ConnectorUiActions {
    toggle: Option<(String, bool)>,
    rotate_quick: Option<String>,
    remove: Option<String>,
    update_credentials: Option<(String, ConnectorKind)>,
}

impl RunOnMineDesktop {
    fn connector_lifecycle_display(
        &self,
        connector: &ConnectorConfig,
    ) -> (String, StatusTone, Option<String>) {
        if !connector.enabled {
            return ("Disabled".to_owned(), StatusTone::Neutral, None);
        }
        if connector.kind == ConnectorKind::LocalStdio {
            return (
                "On demand".to_owned(),
                StatusTone::Info,
                Some("Starts for each local stdio client session.".to_owned()),
            );
        }
        if let Some(runtime) = self.connector_lifecycle.get(&connector.id) {
            let (label, tone) = match runtime.phase.as_str() {
                "ready" => ("Ready".to_owned(), StatusTone::Success),
                "starting" => ("Starting".to_owned(), StatusTone::Info),
                "backoff" => ("Backoff".to_owned(), StatusTone::Warning),
                "stopped" => ("Stopped".to_owned(), StatusTone::Neutral),
                "degraded" if runtime.stage.as_deref() == Some("authentication") => {
                    ("Stale credentials".to_owned(), StatusTone::Warning)
                }
                "degraded" if runtime.stage.as_deref() == Some("process") => {
                    ("Failed".to_owned(), StatusTone::Danger)
                }
                "degraded" => ("Degraded".to_owned(), StatusTone::Danger),
                other => (other.replace('_', " "), StatusTone::Warning),
            };
            let detail = runtime.message.clone().or_else(|| {
                runtime
                    .stage
                    .as_ref()
                    .map(|stage| format!("Lifecycle stage: {stage}"))
            });
            return (label, tone, detail);
        }
        if connector.kind == ConnectorKind::LocalHttp && self.agent_reachable {
            return ("Ready".to_owned(), StatusTone::Success, None);
        }
        if self.agent_reachable {
            (
                "Configured".to_owned(),
                StatusTone::Neutral,
                Some("No active managed runtime was reported for this connector.".to_owned()),
            )
        } else {
            (
                "Agent offline".to_owned(),
                StatusTone::Warning,
                Some("Start the RunOnMine agent to observe runtime health.".to_owned()),
            )
        }
    }

    pub(super) fn show_connections(&mut self, ui: &mut egui::Ui) {
        self.show_connections_intro(ui);
        ui.add_space(16.0);

        let connectors = self
            .config
            .as_ref()
            .map(|config| config.connectors.clone())
            .unwrap_or_default();
        let mut actions = ConnectorUiActions::default();
        for connector in connectors {
            self.show_connector_card(ui, &connector, &mut actions);
            ui.add_space(10.0);
        }
        self.apply_connector_actions(actions);
        self.show_credential_update_window(ui);
    }

    fn show_connections_intro(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Secure connector endpoints")
                            .size(17.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Secrets stay masked and are stored in the operating-system credential store.",
                        )
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            self.connector_rx.is_none(),
                            theme::primary_button("Add connector"),
                        )
                        .clicked()
                    {
                        self.connector_wizard.open = true;
                    }
                });
            });
        });
    }

    fn show_connector_card(
        &mut self,
        ui: &mut egui::Ui,
        connector: &ConnectorConfig,
        actions: &mut ConnectorUiActions,
    ) {
        let confirming_delete = self.pending_connector_delete.as_deref() == Some(&connector.id);
        let public_url = if connector.kind == ConnectorKind::CloudflareQuick {
            self.quick_runtime_urls
                .get(&connector.id)
                .map(ToString::to_string)
        } else {
            connector.public_base_url.as_ref().map(ToString::to_string)
        };
        let (lifecycle_label, lifecycle_tone, lifecycle_detail) =
            self.connector_lifecycle_display(connector);
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                Self::show_connector_summary(
                    ui,
                    connector,
                    public_url.as_deref(),
                    &lifecycle_label,
                    lifecycle_tone,
                    lifecycle_detail.as_deref(),
                );
                self.show_connector_actions(ui, connector, confirming_delete, actions);
            });
            if confirming_delete {
                Self::show_connector_delete_warning(ui);
            }
        });
    }

    fn show_connector_summary(
        ui: &mut egui::Ui,
        connector: &ConnectorConfig,
        public_url: Option<&str>,
        lifecycle_label: &str,
        lifecycle_tone: StatusTone,
        lifecycle_detail: Option<&str>,
    ) {
        ui.vertical(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(&connector.name)
                        .size(17.0)
                        .strong()
                        .color(theme::TEXT),
                );
                theme::status_badge(
                    ui,
                    if connector.enabled {
                        "Enabled"
                    } else {
                        "Disabled"
                    },
                    if connector.enabled {
                        StatusTone::Success
                    } else {
                        StatusTone::Neutral
                    },
                );
                theme::status_badge(ui, lifecycle_label, lifecycle_tone);
                theme::status_badge(ui, &format!("{:?}", connector.kind), StatusTone::Info);
                theme::status_badge(
                    ui,
                    &format!("{:?}", connector.policy_preset),
                    StatusTone::Neutral,
                );
            });
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new(format!("ID  {}", connector.id))
                    .size(10.0)
                    .monospace()
                    .color(theme::MUTED),
            );
            if let Some(url) = public_url {
                ui.label(
                    egui::RichText::new(format!("Public endpoint  {url}"))
                        .size(12.0)
                        .color(theme::INFO),
                );
            }
            if let Some(detail) = lifecycle_detail {
                ui.label(egui::RichText::new(detail).size(11.0).color(theme::MUTED));
            }
        });
    }

    fn show_connector_actions(
        &mut self,
        ui: &mut egui::Ui,
        connector: &ConnectorConfig,
        confirming_delete: bool,
        actions: &mut ConnectorUiActions,
    ) {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if confirming_delete {
                if ui.add(theme::danger_button("Confirm removal")).clicked() {
                    actions.remove = Some(connector.id.clone());
                }
                if ui.button("Cancel").clicked() {
                    self.pending_connector_delete = None;
                }
                return;
            }
            if !matches!(
                connector.kind,
                ConnectorKind::LocalStdio | ConnectorKind::LocalHttp
            ) && ui.add(theme::danger_button("Remove…")).clicked()
            {
                self.pending_connector_delete = Some(connector.id.clone());
            }
            if let Some(label) = rotation_label(connector.kind)
                && ui
                    .add_enabled(self.connector_rx.is_none(), egui::Button::new(label))
                    .clicked()
            {
                match connector.kind {
                    ConnectorKind::CloudflareQuick => {
                        actions.rotate_quick = Some(connector.id.clone());
                    }
                    ConnectorKind::CloudflareOauth | ConnectorKind::OpenAiTunnel => {
                        actions.update_credentials = Some((connector.id.clone(), connector.kind));
                    }
                    ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => {}
                }
            }
            if ui
                .add_enabled(
                    self.connector_rx.is_none(),
                    egui::Button::new(if connector.enabled {
                        "Disable"
                    } else {
                        "Enable"
                    }),
                )
                .clicked()
            {
                actions.toggle = Some((connector.id.clone(), !connector.enabled));
            }
        });
    }

    fn show_connector_delete_warning(ui: &mut egui::Ui) {
        ui.add_space(12.0);
        egui::Frame::new()
            .fill(theme::DANGER_SOFT)
            .stroke(egui::Stroke::new(1.0, theme::DANGER))
            .corner_radius(egui::CornerRadius::same(9))
            .inner_margin(egui::Margin::same(10))
            .show(ui, |ui| {
                ui.label(
                    egui::RichText::new(
                        "This removes local credentials, persistent grants, and connector state. Live transports close after the agent restarts.",
                    )
                    .size(12.0)
                    .color(theme::DANGER),
                );
            });
    }

    fn apply_connector_actions(&mut self, actions: ConnectorUiActions) {
        if let Some((id, enable)) = actions.toggle {
            let result = self.toggle_connector(&id, enable);
            self.apply_result(result);
        }
        if let Some(id) = actions.rotate_quick {
            let result = self.rotate_quick_connector(&id);
            self.apply_result(result);
        }
        if let Some((id, kind)) = actions.update_credentials {
            self.pending_credential_update = Some((id, kind));
            self.credential_client_id.clear();
            self.credential_secret.zeroize();
        }
        if let Some(id) = actions.remove {
            self.pending_connector_delete = None;
            let result = self.remove_connector(&id);
            self.apply_result(result);
        }
    }

    fn show_credential_update_window(&mut self, ui: &mut egui::Ui) {
        let Some((connector_id, kind)) = self.pending_credential_update.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new("Update connector credentials")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .show(ui.ctx(), |ui| {
                theme::section_header(
                    ui,
                    "Replace stored credentials",
                    "The new secret is written directly to the credential store and never displayed again.",
                );
                if kind == ConnectorKind::CloudflareOauth {
                    ui.label(
                        egui::RichText::new("GitHub client ID")
                            .size(12.0)
                            .color(theme::MUTED),
                    );
                    ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut self.credential_client_id),
                    );
                    ui.add_space(10.0);
                }
                let secret_label = if kind == ConnectorKind::CloudflareOauth {
                    "GitHub client secret"
                } else {
                    "Runtime API key"
                };
                ui.label(
                    egui::RichText::new(secret_label)
                        .size(12.0)
                        .color(theme::MUTED),
                );
                ui.add_sized(
                    [ui.available_width(), 36.0],
                    egui::TextEdit::singleline(&mut *self.credential_secret).password(true),
                );
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(theme::primary_button("Save and revoke old sessions"))
                        .clicked()
                    {
                        let result = self.update_connector_credentials(&connector_id, kind);
                        self.apply_result(result);
                    }
                    if ui.button("Cancel").clicked() {
                        self.clear_credential_update();
                    }
                });
            });
        if !open {
            self.clear_credential_update();
        }
    }

    fn clear_credential_update(&mut self) {
        self.pending_credential_update = None;
        self.credential_client_id.clear();
        self.credential_secret.zeroize();
    }
}
