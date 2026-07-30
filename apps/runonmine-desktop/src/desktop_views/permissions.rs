use super::super::{PolicyPreset, RunOnMineDesktop, egui, theme};

impl RunOnMineDesktop {
    #[allow(clippy::too_many_lines)] // Screen-section extraction remains tracked in P2-02.
    pub(super) fn show_permissions(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            theme::section_header(
                ui,
                "Filesystem roots",
                "File tools cannot leave these explicitly selected directories.",
            );
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 170.0, 36.0],
                    egui::TextEdit::singleline(&mut self.root_input)
                        .hint_text("/absolute/path/to/project"),
                );
                if ui.add(theme::primary_button("Add directory")).clicked() {
                    let result = self.add_root();
                    self.apply_result(result);
                }
            });
            ui.add_space(12.0);
            let roots = self
                .config
                .as_ref()
                .map(|config| config.allowed_roots.clone())
                .unwrap_or_default();
            let mut remove = None;
            if roots.is_empty() {
                ui.label(
                    egui::RichText::new("No roots selected. File tools remain unavailable.")
                        .color(theme::MUTED),
                );
            }
            for root in roots {
                theme::subtle_card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(root.display().to_string())
                                .monospace()
                                .color(theme::TEXT),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(theme::danger_button("Remove")).clicked() {
                                remove = Some(root.clone());
                            }
                        });
                    });
                });
                ui.add_space(7.0);
            }
            if let Some(root) = remove {
                let result = self.remove_root(&root);
                self.apply_result(result);
            }
        });

        ui.add_space(18.0);
        theme::card(ui, |ui| {
            theme::section_header(
                ui,
                "Connector policy presets",
                "Choose a baseline, then narrow it with advanced rules below.",
            );
            let connectors = self
                .config
                .as_ref()
                .map(|config| config.connectors.clone())
                .unwrap_or_default();
            let mut preset_change = None;
            for connector in connectors {
                theme::subtle_card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(&connector.name)
                                    .strong()
                                    .color(theme::TEXT),
                            );
                            ui.label(
                                egui::RichText::new(format!("{:?}", connector.kind))
                                    .size(11.0)
                                    .color(theme::MUTED),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let mut selected = connector.policy_preset;
                            egui::ComboBox::from_id_salt(format!("preset-{}", connector.id))
                                .selected_text(format!("{selected:?}"))
                                .width(150.0)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut selected, PolicyPreset::Safe, "Safe");
                                    ui.selectable_value(
                                        &mut selected,
                                        PolicyPreset::Developer,
                                        "Developer",
                                    );
                                    ui.selectable_value(&mut selected, PolicyPreset::Full, "Full");
                                });
                            if selected != connector.policy_preset {
                                preset_change = Some((connector.id.clone(), selected));
                            }
                        });
                    });
                });
                ui.add_space(7.0);
            }
            if let Some((id, preset)) = preset_change {
                let result = self.set_preset(&id, preset);
                self.apply_result(result);
            }
            ui.add_space(8.0);
            ui.label(
                    egui::RichText::new(
                        "Changing a preset clears connector-specific overrides. Remote safety ceilings still apply.",
                    )
                    .size(11.0)
                    .color(theme::MUTED),
                );
        });

        ui.add_space(18.0);
        if let Some(config) = self.config.clone() {
            match self.policy_editor.show(ui, &config) {
                Ok(Some(action)) => {
                    let result = self.apply_policy_action(action);
                    self.apply_result(result);
                }
                Ok(None) => {}
                Err(error) => self.error = Some(error.to_string()),
            }
        }
    }
}
