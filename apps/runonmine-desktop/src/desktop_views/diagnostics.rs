use super::super::{RunOnMineDesktop, egui, theme};

impl RunOnMineDesktop {
    pub(super) fn show_diagnostics(&mut self, ui: &mut egui::Ui) {
        let running = self.diagnostic_rx.is_some();
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("System health check")
                            .size(17.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Validate services, binaries, credentials, and audit integrity.",
                        )
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh state").clicked() {
                        let result = self.start_refresh();
                        self.apply_result(result);
                    }
                    if ui
                        .add_enabled(
                            !running,
                            theme::primary_button(if running {
                                "Checking…"
                            } else {
                                "Run full doctor"
                            }),
                        )
                        .clicked()
                    {
                        let result = self.start_doctor();
                        self.apply_result(result);
                    }
                });
            });
        });
        ui.add_space(16.0);
        theme::card(ui, |ui| {
            theme::section_header(
                ui,
                "Diagnostic output",
                "Sensitive credentials are never printed here.",
            );
            egui::Frame::new()
                .fill(egui::Color32::from_rgb(9, 12, 15))
                .stroke(egui::Stroke::new(1.0, theme::BORDER))
                .corner_radius(egui::CornerRadius::same(9))
                .inner_margin(egui::Margin::same(14))
                .show(ui, |ui| {
                    ui.set_min_height(260.0);
                    if self.diagnostics.trim().is_empty() {
                        ui.label(
                            egui::RichText::new("Run the doctor to inspect this installation.")
                                .color(theme::MUTED),
                        );
                    } else {
                        ui.monospace(&self.diagnostics);
                    }
                });
        });
    }
}
