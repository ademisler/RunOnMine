use super::super::*;

impl RunOnMineDesktop {
    pub(super) fn show_oauth(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "Registered clients",
            "Clients can be revoked without deleting their registration.",
        );
        let clients = self.oauth_clients.clone();
        let mut client_action = None;
        let mut request_delete = None;
        let mut cancel_delete = false;
        if clients.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Key,
                "No OAuth clients",
                "A client will appear after completing dynamic registration.",
            );
        }
        for client in clients {
            let confirming =
                self.pending_client_delete
                    .as_ref()
                    .is_some_and(|(connector_id, client_id)| {
                        connector_id == &client.connector_id && client_id == &client.client_id
                    });
            theme::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(&client.client_name)
                                .size(16.0)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "Connector {} · ID {}",
                                client.connector_id, client.client_id
                            ))
                            .size(11.0)
                            .monospace()
                            .color(theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if confirming {
                            if ui.add(theme::danger_button("Confirm delete")).clicked() {
                                client_action = Some((
                                    client.connector_id.clone(),
                                    client.client_id.clone(),
                                    true,
                                ));
                            }
                            if ui.button("Cancel").clicked() {
                                cancel_delete = true;
                            }
                        } else {
                            if ui.add(theme::danger_button("Delete…")).clicked() {
                                request_delete =
                                    Some((client.connector_id.clone(), client.client_id.clone()));
                            }
                            if ui.button("Revoke tokens").clicked() {
                                client_action = Some((
                                    client.connector_id.clone(),
                                    client.client_id.clone(),
                                    false,
                                ));
                            }
                        }
                    });
                });
                ui.add_space(10.0);
                ui.horizontal_wrapped(|ui| {
                    theme::status_badge(ui, &client.scopes.to_space_delimited(), StatusTone::Info);
                    ui.label(
                        egui::RichText::new(format!("Issued {}", client.issued_at.to_rfc3339()))
                            .size(11.0)
                            .color(theme::MUTED),
                    );
                });
                if confirming {
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("Deleting this client also removes tokens and pending authorization state.").color(theme::DANGER));
                }
            });
            ui.add_space(10.0);
        }
        if cancel_delete {
            self.pending_client_delete = None;
        }
        if let Some(client) = request_delete {
            self.pending_client_delete = Some(client);
        }
        if let Some((connector_id, client_id, delete)) = client_action {
            self.pending_client_delete = None;
            let result = if delete {
                self.delete_oauth_client(&connector_id, &client_id)
            } else {
                self.revoke_oauth_client(&connector_id, &client_id)
            };
            self.apply_result(result);
        }

        ui.add_space(22.0);
        theme::section_header(
            ui,
            "Authorization sessions",
            "Refresh-token families can be revoked independently.",
        );
        let sessions = self.oauth_sessions.clone();
        let mut revoke = None;
        if sessions.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Activity,
                "No sessions",
                "Active authorization sessions will appear here.",
            );
        }
        for session in sessions {
            theme::subtle_card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(&session.client_id)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "{} · {}",
                                session.connector_id, session.family_id
                            ))
                            .size(11.0)
                            .monospace()
                            .color(theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if session.active && ui.add(theme::danger_button("Revoke")).clicked() {
                            revoke = Some((session.connector_id.clone(), session.family_id));
                        }
                        theme::status_badge(
                            ui,
                            if session.active { "Active" } else { "Revoked" },
                            if session.active {
                                StatusTone::Success
                            } else {
                                StatusTone::Neutral
                            },
                        );
                    });
                });
                ui.label(
                    egui::RichText::new(format!("Expires {}", session.expires_at.to_rfc3339()))
                        .size(11.0)
                        .color(theme::MUTED),
                );
            });
            ui.add_space(8.0);
        }
        if let Some((connector_id, family_id)) = revoke {
            let result = self.revoke_oauth_session(&connector_id, family_id);
            self.apply_result(result);
        }
    }
}
