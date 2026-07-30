use super::super::*;

impl RunOnMineDesktop {
    pub(super) fn show_audit(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("Audit integrity")
                                .size(17.0)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new(
                                "Records are linked through a tamper-evident hash chain.",
                            )
                            .size(12.0)
                            .color(theme::MUTED),
                        );
                        if let Some(report) = self.audit_verification {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} verification · {} new record(s) checked · checkpoint #{} · tail #{}",
                                    if report.full { "Full" } else { "Incremental" },
                                    report.records_verified,
                                    report.checkpoint_sequence,
                                    report.tail_sequence,
                                ))
                                .size(10.5)
                                .monospace()
                                .color(theme::MUTED),
                            );
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        theme::status_badge(
                            ui,
                            match self.audit_valid {
                                Some(true) => "Verified",
                                Some(false) => "Failed",
                                None => "Unknown",
                            },
                            match self.audit_valid {
                                Some(true) => StatusTone::Success,
                                Some(false) => StatusTone::Danger,
                                None => StatusTone::Warning,
                            },
                        );
                    });
                });
        });
        ui.add_space(18.0);

        if self.audit.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::FileText,
                "No audit events",
                "Tool decisions will be recorded here.",
            );
            return;
        }
        for record in self.audit.iter().rev() {
            theme::subtle_card(ui, |ui| {
                ui.horizontal(|ui| {
                    theme::status_badge(
                        ui,
                        &format!("{:?}", record.event.outcome),
                        StatusTone::Neutral,
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "#{}  {}",
                                record.sequence, record.event.tool_name
                            ))
                            .strong()
                            .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new(&record.event.summary)
                                .size(12.0)
                                .color(theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(record.event.timestamp.to_rfc3339())
                                .size(10.0)
                                .color(theme::MUTED),
                        );
                    });
                });
                ui.label(
                    egui::RichText::new(format!("Connector {}", record.event.connector_id))
                        .size(10.0)
                        .monospace()
                        .color(theme::MUTED),
                );
            });
            ui.add_space(7.0);
        }
        if self.audit.len() >= self.audit_limit && self.audit_limit < 10_000 {
            ui.add_space(10.0);
            if ui.button("Load older audit records").clicked() {
                self.audit_limit = self.audit_limit.saturating_mul(2).min(10_000);
                let result = self.start_refresh();
                self.apply_result(result);
            }
        }
    }
}
