use eframe::egui;
use runonmine_core::ConnectorKind;

use crate::theme;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum WizardKind {
    #[default]
    Quick,
    CloudflareOAuth,
    OpenAi,
}

#[derive(Debug, Default)]
pub(crate) struct ConnectorWizardState {
    pub(crate) open: bool,
    pub(crate) kind: WizardKind,
    pub(crate) hostname: String,
    pub(crate) tunnel_id: String,
    pub(crate) credentials_file: String,
    pub(crate) github_client_id: String,
    pub(crate) github_client_secret: String,
    pub(crate) github_owner: String,
    pub(crate) github_owner_id: String,
    pub(crate) owner_full_access: bool,
    pub(crate) openai_profile: String,
    pub(crate) openai_api_key: String,
}

#[derive(Debug)]
pub(crate) struct ConnectorCommand {
    pub(crate) arguments: Vec<String>,
    pub(crate) stdin_secret: Option<String>,
}

impl ConnectorWizardState {
    pub(crate) fn show(
        &mut self,
        context: &egui::Context,
        running: bool,
    ) -> Option<ConnectorCommand> {
        if !self.open {
            return None;
        }
        let mut command = None;
        let mut open = self.open;
        egui::Window::new("Add secure connector")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(620.0)
            .show(context, |ui| self.show_window(ui, running, &mut command));
        self.open = open && self.open;
        command
    }

    fn show_window(
        &mut self,
        ui: &mut egui::Ui,
        running: bool,
        command: &mut Option<ConnectorCommand>,
    ) {
        theme::section_header(
            ui,
            "Connect this machine",
            "Choose a transport. Sensitive values go to the local CLI over stdin and are never placed in process arguments.",
        );
        self.show_kind_choices(ui);
        ui.add_space(16.0);
        theme::card(ui, |ui| self.show_connector_form(ui));
        ui.add_space(14.0);
        self.show_actions(ui, running, command);
    }

    fn show_kind_choices(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            connector_choice(
                ui,
                &mut self.kind,
                WizardKind::Quick,
                "Quick tunnel",
                "Temporary testing",
            );
            connector_choice(
                ui,
                &mut self.kind,
                WizardKind::CloudflareOAuth,
                "Cloudflare OAuth",
                "Recommended remote",
            );
            connector_choice(
                ui,
                &mut self.kind,
                WizardKind::OpenAi,
                "OpenAI tunnel",
                "Official client",
            );
        });
    }

    fn show_connector_form(&mut self, ui: &mut egui::Ui) {
        match self.kind {
            WizardKind::Quick => {
                theme::section_header(
                    ui,
                    "Cloudflare Quick Tunnel",
                    "Creates a temporary public URL with a random 256-bit secret path.",
                );
                ui.label(
                    egui::RichText::new(
                        "Use this for short tests only. It does not provide a durable user identity layer.",
                    )
                    .size(12.0)
                    .color(theme::WARNING),
                );
            }
            WizardKind::CloudflareOAuth => self.show_cloudflare_oauth_fields(ui),
            WizardKind::OpenAi => self.show_openai_fields(ui),
        }
    }

    fn show_cloudflare_oauth_fields(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "Cloudflare Named Tunnel + OAuth",
            "GitHub verifies the configured machine owner while RunOnMine owns the OAuth flow.",
        );
        field(
            ui,
            "Public hostname",
            &mut self.hostname,
            false,
            "mcp.example.com",
        );
        field(
            ui,
            "Cloudflare tunnel UUID",
            &mut self.tunnel_id,
            false,
            "00000000-0000-0000-0000-000000000000",
        );
        field(
            ui,
            "Credentials JSON path",
            &mut self.credentials_file,
            false,
            "/absolute/path/credentials.json",
        );
        field(
            ui,
            "GitHub OAuth client ID",
            &mut self.github_client_id,
            false,
            "Client ID",
        );
        field(
            ui,
            "GitHub OAuth client secret",
            &mut self.github_client_secret,
            true,
            "Stored securely",
        );
        field(
            ui,
            "GitHub owner display login",
            &mut self.github_owner,
            false,
            "username",
        );
        field(
            ui,
            "GitHub owner numeric ID",
            &mut self.github_owner_id,
            false,
            "123456",
        );
        ui.add_space(8.0);
        ui.checkbox(
            &mut self.owner_full_access,
            "Owner workstation full access (dangerous)",
        );
        if self.owner_full_access {
            ui.label(
                egui::RichText::new(
                    "This authenticated Named Tunnel may use Full policy, including root shell, browser actions, desktop control, and platform automation. Use only on a machine you own.",
                )
                .size(12.0)
                .color(theme::WARNING),
            );
        }
    }

    fn show_openai_fields(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "OpenAI Secure MCP Tunnel",
            "Initializes the official tunnel client against the local stdio connector.",
        );
        field(
            ui,
            "OpenAI tunnel ID",
            &mut self.tunnel_id,
            false,
            "Tunnel ID",
        );
        field(
            ui,
            "Profile name",
            &mut self.openai_profile,
            false,
            "runonmine",
        );
        field(
            ui,
            "Runtime API key",
            &mut self.openai_api_key,
            true,
            "Stored securely",
        );
    }

    fn show_actions(
        &mut self,
        ui: &mut egui::Ui,
        running: bool,
        command: &mut Option<ConnectorCommand>,
    ) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !running,
                    theme::primary_button(if running {
                        "Creating connector…"
                    } else {
                        "Create connector"
                    }),
                )
                .clicked()
            {
                *command = Some(self.command());
            }
            if ui.button("Cancel").clicked() {
                self.open = false;
            }
        });
    }

    pub(crate) fn clear_secrets(&mut self) {
        self.github_client_secret.clear();
        self.openai_api_key.clear();
    }

    fn command(&self) -> ConnectorCommand {
        match self.kind {
            WizardKind::Quick => ConnectorCommand {
                arguments: vec!["connect".into(), "cloudflare".into(), "quick".into()],
                stdin_secret: None,
            },
            WizardKind::CloudflareOAuth => {
                let mut arguments = vec![
                    "connect".into(),
                    "cloudflare".into(),
                    "oauth".into(),
                    "--hostname".into(),
                    self.hostname.trim().into(),
                    "--tunnel-id".into(),
                    self.tunnel_id.trim().into(),
                    "--credentials-file".into(),
                    self.credentials_file.trim().into(),
                    "--github-client-id".into(),
                    self.github_client_id.trim().into(),
                    "--github-owner".into(),
                    self.github_owner.trim().into(),
                    "--github-owner-id".into(),
                    self.github_owner_id.trim().into(),
                ];
                if self.owner_full_access {
                    arguments.push("--owner-full-access".into());
                }
                arguments.push("--client-secret-stdin".into());
                ConnectorCommand {
                    arguments,
                    stdin_secret: Some(self.github_client_secret.clone()),
                }
            }
            WizardKind::OpenAi => ConnectorCommand {
                arguments: vec![
                    "connect".into(),
                    "openai".into(),
                    "--tunnel-id".into(),
                    self.tunnel_id.trim().into(),
                    "--profile".into(),
                    if self.openai_profile.trim().is_empty() {
                        "runonmine".into()
                    } else {
                        self.openai_profile.trim().into()
                    },
                    "--api-key-stdin".into(),
                ],
                stdin_secret: Some(self.openai_api_key.clone()),
            },
        }
    }
}

pub(crate) fn rotation_label(kind: ConnectorKind) -> Option<&'static str> {
    match kind {
        ConnectorKind::CloudflareQuick => Some("Rotate secret URL"),
        ConnectorKind::CloudflareOauth => Some("Update GitHub credentials"),
        ConnectorKind::OpenAiTunnel => Some("Update runtime API key"),
        ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => None,
    }
}

fn connector_choice(
    ui: &mut egui::Ui,
    selected: &mut WizardKind,
    value: WizardKind,
    title: &str,
    subtitle: &str,
) {
    let active = *selected == value;
    let response = egui::Frame::new()
        .fill(if active {
            theme::ACCENT_SOFT
        } else {
            theme::SURFACE
        })
        .stroke(egui::Stroke::new(
            1.0,
            if active { theme::ACCENT } else { theme::BORDER },
        ))
        .corner_radius(egui::CornerRadius::same(10))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_min_width(160.0);
            ui.label(egui::RichText::new(title).strong().color(if active {
                theme::ACCENT
            } else {
                theme::TEXT
            }));
            ui.label(egui::RichText::new(subtitle).size(11.0).color(theme::MUTED));
        })
        .response
        .interact(egui::Sense::click());
    if response.clicked() {
        *selected = value;
    }
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, secret: bool, hint: &str) {
    ui.label(egui::RichText::new(label).size(12.0).color(theme::MUTED));
    let edit = egui::TextEdit::singleline(value)
        .desired_width(ui.available_width())
        .password(secret)
        .hint_text(hint);
    ui.add_sized([ui.available_width(), 36.0], edit);
    ui.add_space(9.0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_secret_is_stdin_only() {
        let wizard = ConnectorWizardState {
            kind: WizardKind::CloudflareOAuth,
            hostname: "mcp.example.com".to_owned(),
            tunnel_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            credentials_file: "/tmp/credentials.json".to_owned(),
            github_client_id: "client-id".to_owned(),
            github_client_secret: "super-secret".to_owned(),
            github_owner: "owner".to_owned(),
            github_owner_id: "42".to_owned(),
            ..ConnectorWizardState::default()
        };
        let command = wizard.command();
        assert_eq!(command.stdin_secret.as_deref(), Some("super-secret"));
        assert!(
            !command
                .arguments
                .iter()
                .any(|value| value == "super-secret")
        );
        assert!(
            command
                .arguments
                .iter()
                .any(|value| value == "--client-secret-stdin")
        );
    }

    #[test]
    fn openai_secret_is_stdin_only_and_profile_defaults() {
        let wizard = ConnectorWizardState {
            kind: WizardKind::OpenAi,
            tunnel_id: "tunnel".to_owned(),
            openai_api_key: "runtime-secret".to_owned(),
            ..ConnectorWizardState::default()
        };
        let command = wizard.command();
        assert_eq!(command.stdin_secret.as_deref(), Some("runtime-secret"));
        assert!(
            !command
                .arguments
                .iter()
                .any(|value| value == "runtime-secret")
        );
        let profile_index = command
            .arguments
            .iter()
            .position(|value| value == "--profile");
        assert_eq!(
            profile_index
                .and_then(|index| command.arguments.get(index + 1))
                .map(String::as_str),
            Some("runonmine")
        );
    }

    #[test]
    fn rotation_actions_match_remote_connector_types() {
        assert_eq!(
            rotation_label(ConnectorKind::CloudflareQuick),
            Some("Rotate secret URL")
        );
        assert_eq!(
            rotation_label(ConnectorKind::CloudflareOauth),
            Some("Update GitHub credentials")
        );
        assert_eq!(
            rotation_label(ConnectorKind::OpenAiTunnel),
            Some("Update runtime API key")
        );
        assert_eq!(rotation_label(ConnectorKind::LocalStdio), None);
        assert_eq!(rotation_label(ConnectorKind::LocalHttp), None);
    }

    #[test]
    fn clear_secrets_removes_sensitive_fields_only() {
        let mut wizard = ConnectorWizardState {
            hostname: "mcp.example.com".to_owned(),
            github_client_secret: "github-secret".to_owned(),
            openai_api_key: "openai-secret".to_owned(),
            ..ConnectorWizardState::default()
        };
        wizard.clear_secrets();
        assert!(wizard.github_client_secret.is_empty());
        assert!(wizard.openai_api_key.is_empty());
        assert_eq!(wizard.hostname, "mcp.example.com");
    }
}
