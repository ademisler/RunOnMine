use eframe::egui;
use runonmine_core::ConnectorKind;

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
            .resizable(true)
            .show(context, |ui| {
                ui.label("Secrets are sent to the local RunOnMine CLI over standard input and stored in the operating-system credential store. They are never placed in process arguments.");
                ui.horizontal_wrapped(|ui| {
                    ui.selectable_value(&mut self.kind, WizardKind::Quick, "Cloudflare Quick");
                    ui.selectable_value(&mut self.kind, WizardKind::CloudflareOAuth, "Cloudflare OAuth");
                    ui.selectable_value(&mut self.kind, WizardKind::OpenAi, "OpenAI Secure Tunnel");
                });
                ui.separator();
                match self.kind {
                    WizardKind::Quick => {
                        ui.label("Creates a temporary Cloudflare tunnel with a random 256-bit secret path. Recommended only for testing.");
                    }
                    WizardKind::CloudflareOAuth => {
                        field(ui, "Public hostname", &mut self.hostname, false);
                        field(ui, "Cloudflare tunnel UUID", &mut self.tunnel_id, false);
                        field(ui, "Credentials JSON path", &mut self.credentials_file, false);
                        field(ui, "GitHub OAuth client ID", &mut self.github_client_id, false);
                        field(ui, "GitHub OAuth client secret", &mut self.github_client_secret, true);
                        field(ui, "GitHub owner login", &mut self.github_owner, false);
                        field(ui, "GitHub owner numeric ID", &mut self.github_owner_id, false);
                    }
                    WizardKind::OpenAi => {
                        field(ui, "OpenAI tunnel ID", &mut self.tunnel_id, false);
                        field(ui, "Profile name", &mut self.openai_profile, false);
                        field(ui, "Runtime API key", &mut self.openai_api_key, true);
                    }
                }
                ui.add_space(8.0);
                if ui.add_enabled(!running, egui::Button::new(if running { "Working…" } else { "Create connector" })).clicked() {
                    command = Some(self.command());
                }
            });
        self.open = open;
        command
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
            WizardKind::CloudflareOAuth => ConnectorCommand {
                arguments: vec![
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
                    "--client-secret-stdin".into(),
                ],
                stdin_secret: Some(self.github_client_secret.clone()),
            },
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

fn field(ui: &mut egui::Ui, label: &str, value: &mut String, secret: bool) {
    ui.horizontal(|ui| {
        ui.label(label);
        let edit = egui::TextEdit::singleline(value)
            .desired_width(420.0)
            .password(secret);
        ui.add(edit);
    });
}
