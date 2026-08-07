use runonmine_oauth::{OAuthSession, RegisteredClient};

use super::super::{RunOnMineDesktop, StatusTone, UiIcon, egui, theme};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientCardAction {
    ConfirmDelete,
    RequestDelete,
    CancelDelete,
    RevokeTokens,
}

impl RunOnMineDesktop {
    pub(super) fn show_oauth(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "Registered clients",
            "Clients can be revoked without deleting their registration.",
        );
        self.show_oauth_clients(ui);

        ui.add_space(22.0);
        theme::section_header(
            ui,
            "Authorization sessions",
            "Refresh-token families can be revoked independently.",
        );
        self.show_oauth_sessions(ui);
    }

    fn show_oauth_clients(&mut self, ui: &mut egui::Ui) {
        let clients = self.oauth_clients.clone();
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
            if let Some(action) = oauth_client_card(ui, &client, confirming) {
                self.apply_oauth_client_action(&client, action);
            }
            ui.add_space(10.0);
        }
    }

    fn apply_oauth_client_action(&mut self, client: &RegisteredClient, action: ClientCardAction) {
        match action {
            ClientCardAction::CancelDelete => self.pending_client_delete = None,
            ClientCardAction::RequestDelete => {
                self.pending_client_delete =
                    Some((client.connector_id.clone(), client.client_id.clone()));
            }
            ClientCardAction::ConfirmDelete | ClientCardAction::RevokeTokens => {
                self.pending_client_delete = None;
                let result = if action == ClientCardAction::ConfirmDelete {
                    self.delete_oauth_client(&client.connector_id, &client.client_id)
                } else {
                    self.revoke_oauth_client(&client.connector_id, &client.client_id)
                };
                self.apply_result(result);
            }
        }
    }

    fn show_oauth_sessions(&mut self, ui: &mut egui::Ui) {
        let sessions = self.oauth_sessions.clone();
        if sessions.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Activity,
                "No sessions",
                "Active authorization sessions will appear here.",
            );
        }
        for session in sessions {
            if oauth_session_card(ui, &session) {
                let result = self.revoke_oauth_session(&session.connector_id, session.family_id);
                self.apply_result(result);
            }
            ui.add_space(8.0);
        }
    }
}

fn oauth_client_card(
    ui: &mut egui::Ui,
    client: &RegisteredClient,
    confirming: bool,
) -> Option<ClientCardAction> {
    let mut action = None;
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
                        action = Some(ClientCardAction::ConfirmDelete);
                    }
                    if ui.button("Cancel").clicked() {
                        action = Some(ClientCardAction::CancelDelete);
                    }
                } else {
                    if ui.add(theme::danger_button("Delete…")).clicked() {
                        action = Some(ClientCardAction::RequestDelete);
                    }
                    if ui.button("Revoke tokens").clicked() {
                        action = Some(ClientCardAction::RevokeTokens);
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
            ui.label(
                egui::RichText::new(
                    "Deleting this client also removes tokens and pending authorization state.",
                )
                .color(theme::DANGER),
            );
        }
    });
    action
}

fn oauth_session_card(ui: &mut egui::Ui, session: &OAuthSession) -> bool {
    let mut revoke = false;
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
                    revoke = true;
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
    revoke
}
