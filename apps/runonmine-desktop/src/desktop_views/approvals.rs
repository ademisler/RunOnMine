use runonmine_core::{ApprovalRequest, PersistentGrant};

use super::super::{ApprovalDecision, RunOnMineDesktop, StatusTone, UiIcon, egui, theme};

impl RunOnMineDesktop {
    pub(super) fn show_approvals(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "Waiting for review",
            "Approvals can only be resolved from this machine or the local CLI.",
        );
        self.show_pending_approvals(ui);

        ui.add_space(22.0);
        theme::section_header(
            ui,
            "Persistent exact-action grants",
            "These grants match one connector, requester principal, tool, and argument hash only.",
        );
        self.show_persistent_grants(ui);
    }

    fn show_pending_approvals(&mut self, ui: &mut egui::Ui) {
        if self.pending.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Check,
                "Nothing needs approval",
                "New sensitive actions will appear here with their exact target.",
            );
            return;
        }
        let mut action = None;
        for request in self.pending.clone() {
            if let Some(decision) = pending_request_card(ui, &request) {
                action = Some((request.id, decision));
            }
            ui.add_space(10.0);
        }
        if let Some((id, decision)) = action {
            let result = self.resolve(id, decision);
            self.apply_result(result);
        }
    }

    fn show_persistent_grants(&mut self, ui: &mut egui::Ui) {
        if self.persistent_grants.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Shield,
                "No persistent grants",
                "Approving an exact action permanently will add it here.",
            );
            return;
        }
        let mut revoke = None;
        for grant in self.persistent_grants.clone() {
            if persistent_grant_card(ui, &grant) {
                revoke = Some(grant);
            }
            ui.add_space(8.0);
        }
        if let Some(grant) = revoke {
            let result = self.revoke_grant(&grant);
            self.apply_result(result);
        }
    }
}

fn pending_request_card(ui: &mut egui::Ui, request: &ApprovalRequest) -> Option<ApprovalDecision> {
    let mut decision = None;
    theme::card(ui, |ui| {
        ui.horizontal(|ui| {
            theme::status_badge(ui, "Review required", StatusTone::Warning);
            ui.label(
                egui::RichText::new(&request.tool_name)
                    .size(16.0)
                    .strong()
                    .color(theme::TEXT),
            );
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(format!("Expires {}", request.expires_at.to_rfc3339()))
                        .size(11.0)
                        .color(theme::MUTED),
                );
            });
        });
        ui.add_space(10.0);
        theme::subtle_card(ui, |ui| {
            ui.label(
                egui::RichText::new(&request.argument_summary)
                    .monospace()
                    .color(theme::TEXT),
            );
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(format!("Connector: {}", request.connector_id))
                    .size(11.0)
                    .color(theme::MUTED),
            );
            ui.label(
                egui::RichText::new(format!("Requester: {}", request.principal.display_label()))
                    .size(11.0)
                    .color(theme::MUTED),
            );
            ui.label(
                egui::RichText::new(format!(
                    "Principal fingerprint: {}",
                    request.principal_fingerprint
                ))
                .size(10.0)
                .monospace()
                .color(theme::MUTED),
            );
        });
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(
                "Review the complete effective action above before approving. Secret redaction only hides credential values; it does not make an unfamiliar command, path, URL, selector, or requester safe.",
            )
            .size(11.0)
            .color(theme::WARNING),
        );
        ui.add_space(10.0);
        ui.horizontal_wrapped(|ui| {
            if ui.add(theme::primary_button("Allow once")).clicked() {
                decision = Some(ApprovalDecision::Once);
            }
            if ui.button("Allow for 10 minutes").clicked() {
                decision = Some(ApprovalDecision::ForTenMinutes);
            }
            if ui.button("Always allow exact action").clicked() {
                decision = Some(ApprovalDecision::Always);
            }
            if ui.add(theme::danger_button("Deny")).clicked() {
                decision = Some(ApprovalDecision::Deny);
            }
        });
    });
    decision
}

fn persistent_grant_card(ui: &mut egui::Ui, grant: &PersistentGrant) -> bool {
    let mut revoke = false;
    theme::subtle_card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new(format!("{} · {}", grant.connector_id, grant.tool_name))
                        .strong()
                        .color(theme::TEXT),
                );
                ui.label(
                    egui::RichText::new(&grant.argument_summary)
                        .size(12.0)
                        .color(theme::MUTED),
                );
                ui.label(
                    egui::RichText::new(format!("Requester {}", grant.principal.display_label()))
                        .size(11.0)
                        .color(theme::MUTED),
                );
                ui.label(
                    egui::RichText::new(format!("Principal {}", grant.principal_fingerprint))
                        .size(10.0)
                        .monospace()
                        .color(theme::MUTED),
                );
                ui.label(
                    egui::RichText::new(format!("Hash {}", grant.argument_hash))
                        .size(10.0)
                        .monospace()
                        .color(theme::MUTED),
                );
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                revoke = ui.add(theme::danger_button("Revoke")).clicked();
            });
        });
    });
    revoke
}
