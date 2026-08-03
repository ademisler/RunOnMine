#[path = "desktop_model.rs"]
pub(crate) mod model;
#[path = "desktop_views.rs"]
mod views;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use anyhow::{Context, Result, bail};
use eframe::egui;
use runonmine_core::secrets::{default_secret_store, recover_pending_config_secret_transaction};
use runonmine_core::{
    AppConfig, AppPaths, ApprovalDecision, ConnectorConfig, ConnectorKind, PersistentGrant,
    PolicyPreset, StateStore,
};
use secrecy::SecretString;

use crate::connector_wizard::{ConnectorCommand, ConnectorWizardState, rotation_label};
use crate::credential_update::replace_connector_secrets_transactionally;
use crate::desktop_process::{BackgroundCliTask, run_cli};
use crate::desktop_snapshot::{BackgroundDesktopSnapshot, DesktopSnapshot};
use crate::layout;
use crate::policy_editor::{PolicyEditorAction, PolicyEditorState};
use crate::theme::{self, Icon as UiIcon, StatusTone};
use runonmine_oauth::SqliteOAuthStore;
use runonmine_platform::UserService;
use uuid::Uuid;

#[cfg(target_os = "windows")]
const fn native_renderer() -> eframe::Renderer {
    eframe::Renderer::Wgpu
}

#[cfg(not(target_os = "windows"))]
const fn native_renderer() -> eframe::Renderer {
    eframe::Renderer::Glow
}

pub fn run() -> Result<()> {
    let instance = match crate::desktop_instance::DesktopInstance::acquire()? {
        crate::desktop_instance::DesktopInstanceOutcome::Primary(instance) => instance,
        crate::desktop_instance::DesktopInstanceOutcome::Secondary => return Ok(()),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size(layout::DEFAULT_VIEWPORT)
            .with_min_inner_size(layout::MINIMUM_VIEWPORT)
            .with_icon(crate::desktop_icon::egui_icon()),
        renderer: native_renderer(),
        ..Default::default()
    };
    eframe::run_native(
        "RunOnMine",
        options,
        Box::new(move |context| {
            theme::apply(&context.egui_ctx);
            Ok(Box::new(RunOnMineDesktop::new(instance)?))
        }),
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))
}

use model::{RunOnMineDesktop, Tab};

impl RunOnMineDesktop {
    fn new(instance: crate::desktop_instance::DesktopInstance) -> Result<Self> {
        let now = Instant::now();
        let mut app = Self {
            paths: None,
            store: None,
            config: None,
            pending: Vec::new(),
            persistent_grants: Vec::new(),
            audit: Vec::new(),
            oauth_clients: Vec::new(),
            oauth_sessions: Vec::new(),
            quick_runtime_urls: HashMap::new(),
            connector_lifecycle: HashMap::new(),
            known: HashSet::new(),
            last_refresh: now.checked_sub(Duration::from_secs(10)).unwrap_or(now),
            snapshot_rx: None,
            audit_limit: 100,
            audit_verification: None,
            status: "Starting".to_owned(),
            error: None,
            audit_valid: None,
            agent_reachable: false,
            selected_tab: Tab::Overview,
            root_input: String::new(),
            diagnostics: String::new(),
            diagnostic_rx: None,
            pending_client_delete: None,
            pending_connector_delete: None,
            pending_credential_update: None,
            credential_client_id: String::new(),
            credential_secret: Zeroizing::new(String::new()),
            policy_editor: PolicyEditorState::default(),
            connector_wizard: ConnectorWizardState::default(),
            connector_rx: None,
            instance,
            shell: crate::desktop_shell::DesktopShell::new(),
            exit_requested: false,
            acceptance: crate::desktop_acceptance::DesktopAcceptance::from_environment()?,
        };
        if let Err(error) = app.initialize() {
            app.error = Some(error.to_string());
            "Setup required".clone_into(&mut app.status);
        }
        Ok(app)
    }

    fn initialize(&mut self) -> Result<()> {
        let paths = AppPaths::discover()?;
        paths.ensure()?;
        self.paths = Some(paths.clone());
        let secrets = default_secret_store(&paths)?;
        recover_pending_config_secret_transaction(&paths.config_file(), secrets.as_ref())?;
        let config = AppConfig::load_or_create(&paths.config_file())?;
        let store = StateStore::open(&paths.state_db())?;
        self.config = Some(config);
        self.store = Some(store);
        self.start_refresh()?;
        Ok(())
    }

    fn start_refresh(&mut self) -> Result<()> {
        if self.snapshot_rx.is_some() {
            return Ok(());
        }
        let paths = self
            .paths
            .as_ref()
            .context("RunOnMine paths are unavailable")?
            .clone();
        self.snapshot_rx = Some(BackgroundDesktopSnapshot::spawn(paths, self.audit_limit));
        self.last_refresh = Instant::now();
        Ok(())
    }

    fn poll_refresh(&mut self) {
        let result = self
            .snapshot_rx
            .as_mut()
            .and_then(BackgroundDesktopSnapshot::try_take);
        let Some(result) = result else {
            return;
        };
        self.snapshot_rx = None;
        match result {
            Ok(snapshot) => {
                self.apply_snapshot(snapshot);
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn apply_snapshot(&mut self, snapshot: DesktopSnapshot) {
        self.pending = snapshot.pending;
        self.persistent_grants = snapshot.persistent_grants;
        self.audit = snapshot.audit;
        self.audit_valid = Some(snapshot.audit_verification.valid);
        self.audit_verification = Some(snapshot.audit_verification);
        self.oauth_clients = snapshot.oauth_clients;
        self.oauth_sessions = snapshot.oauth_sessions;
        self.quick_runtime_urls = snapshot.quick_runtime_urls;
        self.connector_lifecycle = snapshot.connector_lifecycle;
        self.agent_reachable = snapshot.agent_reachable;
        for request in &self.pending {
            self.known.insert(request.id);
        }
        self.status = if !self.pending.is_empty() {
            format!("{} approval(s) waiting", self.pending.len())
        } else if self.agent_reachable {
            "Agent ready".to_owned()
        } else {
            "Agent stopped".to_owned()
        };
        self.config = Some(snapshot.config);
        self.shell
            .set_status(&self.status, !self.pending.is_empty());
    }

    fn resolve(&mut self, id: Uuid, decision: ApprovalDecision) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .context("RunOnMine is not initialized")?;
        store
            .approval_status(id)?
            .context("Approval no longer exists")?;
        if !store.resolve_approval(id, decision)? {
            bail!("Approval expired or was already resolved");
        }
        self.start_refresh()
    }

    fn emergency_lock(&mut self) -> Result<()> {
        let arguments = vec!["lock".to_owned()];
        let output = run_cli_capture(&arguments)?;
        self.diagnostics = output;
        self.start_refresh()?;
        "Locked — restart explicitly to restore access".clone_into(&mut self.status);
        self.shell.set_status("locked", true);
        Ok(())
    }

    fn update_config<T>(&mut self, update: impl FnOnce(&mut AppConfig) -> Result<T>) -> Result<T> {
        let config_path = self
            .paths
            .as_ref()
            .context("RunOnMine paths are unavailable")?
            .config_file();
        let output = AppConfig::update(&config_path, update)?;
        self.start_refresh()?;
        Ok(output)
    }

    fn reconcile_user_service_roots(&self) -> Result<()> {
        let config = self
            .config
            .as_ref()
            .context("RunOnMine configuration is unavailable")?;
        let _reconciled =
            UserService::discover()?.reconcile_allowed_roots(&config.allowed_roots)?;
        Ok(())
    }

    fn add_root(&mut self) -> Result<()> {
        let value = self.root_input.trim();
        if value.is_empty() {
            bail!("Enter a directory path first");
        }
        let root = PathBuf::from(value)
            .canonicalize()
            .context("Selected root does not exist")?;
        if !root.is_dir() {
            bail!("Selected root is not a directory");
        }
        self.root_input.clear();
        self.update_config(move |config| {
            if !config.allowed_roots.contains(&root) {
                config.allowed_roots.push(root);
                config.allowed_roots.sort();
            }
            Ok(())
        })?;
        self.reconcile_user_service_roots()
    }

    fn remove_root(&mut self, root: &Path) -> Result<()> {
        let root = root.to_path_buf();
        self.update_config(move |config| {
            config.allowed_roots.retain(|candidate| candidate != &root);
            Ok(())
        })?;
        self.reconcile_user_service_roots()
    }

    fn set_preset(&mut self, connector_id: &str, preset: PolicyPreset) -> Result<()> {
        self.update_config(|config| {
            let connector = config
                .connector_mut(connector_id)
                .context("Connector no longer exists")?;
            connector.policy_preset = preset;
            connector.pack_overrides.clear();
            connector.tool_overrides.clear();
            Ok(())
        })
    }

    fn toggle_connector(&mut self, connector_id: &str, enable: bool) -> Result<()> {
        let verb = if enable { "enable" } else { "disable" };
        self.diagnostics = run_cli_capture(&[
            "connect".to_owned(),
            verb.to_owned(),
            connector_id.to_owned(),
        ])?;
        self.start_refresh()
    }

    fn revoke_grant(&mut self, grant: &PersistentGrant) -> Result<()> {
        let store = self
            .store
            .as_ref()
            .context("RunOnMine state is unavailable")?;
        if !store.delete_persistent_grant(
            &grant.connector_id,
            &grant.principal_fingerprint,
            &grant.tool_name,
            &grant.argument_hash,
        )? {
            bail!("Persistent grant no longer exists");
        }
        self.start_refresh()
    }

    fn revoke_oauth_client(&mut self, connector_id: &str, client_id: &str) -> Result<()> {
        let paths = self
            .paths
            .as_ref()
            .context("RunOnMine paths are unavailable")?;
        let oauth = SqliteOAuthStore::open(&paths.state_db())?;
        let revoked = oauth.revoke_client_tokens_for(connector_id, client_id)?;
        self.diagnostics =
            format!("Revoked {revoked} active token(s) for {connector_id}/{client_id}.");
        self.start_refresh()
    }

    fn delete_oauth_client(&mut self, connector_id: &str, client_id: &str) -> Result<()> {
        let paths = self
            .paths
            .as_ref()
            .context("RunOnMine paths are unavailable")?;
        if !SqliteOAuthStore::open(&paths.state_db())?.delete_client_for(connector_id, client_id)? {
            bail!("OAuth client no longer exists in this connector");
        }
        self.start_refresh()
    }

    fn revoke_oauth_session(&mut self, connector_id: &str, family_id: Uuid) -> Result<()> {
        let paths = self
            .paths
            .as_ref()
            .context("RunOnMine paths are unavailable")?;
        let revoked = SqliteOAuthStore::open(&paths.state_db())?
            .revoke_session_for(connector_id, family_id)?;
        self.diagnostics =
            format!("Revoked {revoked} active token(s) in {connector_id}/{family_id}.");
        self.start_refresh()
    }

    fn apply_policy_action(&mut self, action: PolicyEditorAction) -> Result<()> {
        self.update_config(move |config| {
            match action {
                PolicyEditorAction::Add { connector_id, rule } => {
                    config
                        .connector_mut(&connector_id)
                        .context("Connector no longer exists")?
                        .policy_rules
                        .push(rule);
                }
                PolicyEditorAction::Remove {
                    connector_id,
                    index,
                } => {
                    let rules = &mut config
                        .connector_mut(&connector_id)
                        .context("Connector no longer exists")?
                        .policy_rules;
                    if index >= rules.len() {
                        bail!("Policy rule no longer exists");
                    }
                    rules.remove(index);
                }
            }
            Ok(())
        })
    }

    fn start_connector_command(&mut self, command: ConnectorCommand) -> Result<()> {
        if self.connector_rx.is_some() {
            bail!("Another connector operation is already running");
        }
        let cli = sibling_cli()?;
        self.connector_rx = Some(BackgroundCliTask::spawn(
            cli,
            command.arguments,
            command.stdin_secret,
        ));
        "Connector operation is running…".clone_into(&mut self.diagnostics);
        Ok(())
    }

    fn poll_connector_command(&mut self) {
        let result = self
            .connector_rx
            .as_mut()
            .and_then(BackgroundCliTask::try_take);
        if let Some(result) = result {
            self.connector_rx = None;
            self.connector_wizard.clear_secrets();
            match result {
                Ok(output) => {
                    self.diagnostics = output;
                    self.connector_wizard.open = false;
                    if let Err(error) = self.start_refresh() {
                        self.error = Some(error.to_string());
                    } else {
                        self.error = None;
                    }
                }
                Err(error) => self.error = Some(error),
            }
        }
    }

    fn rotate_quick_connector(&mut self, connector_id: &str) -> Result<()> {
        self.start_connector_command(ConnectorCommand {
            arguments: vec![
                "connect".to_owned(),
                "cloudflare".to_owned(),
                "quick".to_owned(),
                "--rotate".to_owned(),
                connector_id.to_owned(),
            ],
            stdin_secret: None,
        })
    }

    fn remove_connector(&mut self, connector_id: &str) -> Result<()> {
        self.start_connector_command(ConnectorCommand {
            arguments: vec![
                "connect".to_owned(),
                "remove".to_owned(),
                connector_id.to_owned(),
                "--confirm".to_owned(),
                "REMOVE".to_owned(),
            ],
            stdin_secret: None,
        })
    }

    fn update_connector_credentials(
        &mut self,
        connector_id: &str,
        kind: ConnectorKind,
    ) -> Result<()> {
        let paths = self
            .paths
            .as_ref()
            .context("RunOnMine paths are unavailable")?;
        let secrets = default_secret_store(paths)?;
        match kind {
            ConnectorKind::CloudflareOauth => {
                let client_id = self.credential_client_id.trim();
                let secret = self.credential_secret.trim();
                if client_id.is_empty() || secret.is_empty() {
                    bail!("GitHub client ID and client secret are required");
                }
                let revoked = replace_connector_secrets_transactionally(
                    &paths.config_file(),
                    secrets.as_ref(),
                    connector_id,
                    kind,
                    &[
                        (
                            format!("connector.{connector_id}.github_client_id"),
                            SecretString::from(client_id.to_owned()),
                        ),
                        (
                            format!("connector.{connector_id}.github_client_secret"),
                            SecretString::from(secret.to_owned()),
                        ),
                    ],
                    || {
                        Ok(
                            SqliteOAuthStore::open_scoped(&paths.state_db(), connector_id)?
                                .emergency_revoke_all()?,
                        )
                    },
                )?;
                self.diagnostics = format!(
                    "Updated GitHub credentials and revoked {revoked} OAuth token(s). Restart the agent to apply the new credentials."
                );
            }
            ConnectorKind::OpenAiTunnel => {
                let secret = self.credential_secret.trim();
                if secret.is_empty() {
                    bail!("OpenAI runtime API key is required");
                }
                replace_connector_secrets_transactionally(
                    &paths.config_file(),
                    secrets.as_ref(),
                    connector_id,
                    kind,
                    &[(
                        format!("connector.{connector_id}.runtime_api_key"),
                        SecretString::from(secret.to_owned()),
                    )],
                    || Ok(()),
                )?;
                "Updated the OpenAI runtime API key. Restart the agent to reconnect."
                    .clone_into(&mut self.diagnostics);
            }
            _ => bail!("This connector does not support credential updates"),
        }
        self.credential_client_id.clear();
        self.credential_secret.zeroize();
        self.pending_credential_update = None;
        self.start_refresh()
    }

    fn start_doctor(&mut self) -> Result<()> {
        if self.diagnostic_rx.is_some() {
            return Ok(());
        }
        let cli = sibling_cli()?;
        self.diagnostic_rx = Some(BackgroundCliTask::spawn(
            cli,
            vec!["doctor".to_owned()],
            None,
        ));
        "Doctor is running…".clone_into(&mut self.diagnostics);
        Ok(())
    }

    fn poll_doctor(&mut self) {
        let result = self
            .diagnostic_rx
            .as_mut()
            .and_then(BackgroundCliTask::try_take);
        if let Some(result) = result {
            self.diagnostics = result.unwrap_or_else(|error| error);
            self.diagnostic_rx = None;
        }
    }

    fn process_shell(&mut self, context: &egui::Context) {
        while let Some(command) = self
            .shell
            .try_command()
            .or_else(|| self.instance.try_command())
        {
            match command {
                crate::desktop_shell::DesktopCommand::Show => show_window(context),
                crate::desktop_shell::DesktopCommand::Lock => {
                    if let Err(error) = self.emergency_lock() {
                        self.error = Some(error.to_string());
                    }
                    show_window(context);
                }
                crate::desktop_shell::DesktopCommand::Quit => {
                    self.exit_requested = true;
                    context.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    fn process_close_request(&mut self, context: &egui::Context) {
        let close_requested = context.input(|input| input.viewport().close_requested());
        if close_requested
            && !self.exit_requested
            && self.acceptance.is_none()
            && self.shell.is_available()
        {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            context.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    fn process_acceptance(&mut self, context: &egui::Context) {
        let next_tab = self
            .acceptance
            .as_ref()
            .and_then(crate::desktop_acceptance::DesktopAcceptance::next_tab);
        if let Some(tab) = next_tab {
            self.selected_tab = tab;
            context.request_repaint();
            return;
        }
        let Some(acceptance) = self.acceptance.as_mut() else {
            return;
        };
        if !acceptance.ready_to_report() {
            return;
        }
        match acceptance.write_report(self.shell.is_available()) {
            Ok(()) => {
                self.exit_requested = true;
                context.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn apply_result(&mut self, result: Result<()>) {
        match result {
            Ok(()) => self.error = None,
            Err(error) => self.error = Some(error.to_string()),
        }
    }
}

impl eframe::App for RunOnMineDesktop {
    fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.process_shell(context);
        self.process_close_request(context);
        self.process_acceptance(context);
        self.poll_doctor();
        self.poll_connector_command();
        self.poll_refresh();
        if self.last_refresh.elapsed() >= Duration::from_secs(2) && self.snapshot_rx.is_none() {
            let result = self.start_refresh();
            self.apply_result(result);
        }
        let interval = if self.acceptance.is_some() { 50 } else { 500 };
        context.request_repaint_after(Duration::from_millis(interval));
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.render_ui(ui, frame);
        if let Some(acceptance) = self.acceptance.as_mut() {
            acceptance.record_render(self.selected_tab, ui.max_rect().size());
        }
    }
}

fn overview_check(ui: &mut egui::Ui, label: &str, value: &str, tone: StatusTone) {
    ui.horizontal(|ui| {
        let icon = match tone {
            StatusTone::Success => UiIcon::Check,
            StatusTone::Warning | StatusTone::Danger => UiIcon::AlertTriangle,
            StatusTone::Info | StatusTone::Purple | StatusTone::Neutral => UiIcon::Activity,
        };
        let (_, color) = theme::tone_colors(tone);
        theme::icon(ui, icon, 15.0, color);
        ui.label(egui::RichText::new(label).size(11.5).color(theme::TEXT));
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(value).size(11.0).strong().color(color));
        });
    });
    ui.add_space(5.0);
}

fn activity_row(
    ui: &mut egui::Ui,
    icon: UiIcon,
    title: &str,
    subtitle: &str,
    time: &str,
    tone: StatusTone,
) {
    ui.horizontal(|ui| {
        let (_, color) = theme::tone_colors(tone);
        theme::icon(ui, icon, 17.0, color);
        ui.add_space(3.0);
        ui.vertical(|ui| {
            ui.label(
                egui::RichText::new(title)
                    .size(11.5)
                    .strong()
                    .color(theme::TEXT),
            );
            ui.label(egui::RichText::new(subtitle).size(10.0).color(theme::MUTED));
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(egui::RichText::new(time).size(10.0).color(theme::MUTED));
        });
    });
    ui.add_space(7.0);
    ui.separator();
    ui.add_space(4.0);
}

fn show_window(context: &egui::Context) {
    context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
    context.send_viewport_cmd(egui::ViewportCommand::Focus);
}

fn sibling_cli() -> Result<PathBuf> {
    let current = std::env::current_exe().context("Could not locate RunOnMine Desktop")?;
    let directory = current
        .parent()
        .context("RunOnMine Desktop has no installation directory")?;
    let cli = if cfg!(windows) {
        directory.join("runonmine.exe")
    } else {
        directory.join("runonmine")
    };
    let metadata = cli
        .symlink_metadata()
        .context("RunOnMine CLI is not installed beside the desktop application")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("RunOnMine CLI must be a regular, non-symlink sibling executable");
    }
    Ok(cli)
}

fn run_cli_capture(arguments: &[String]) -> Result<String> {
    run_cli(&sibling_cli()?, arguments, None)
}

#[cfg(test)]
mod renderer_tests {
    use super::*;

    #[test]
    fn native_renderer_matches_platform_contract() {
        #[cfg(target_os = "windows")]
        assert_eq!(native_renderer(), eframe::Renderer::Wgpu);

        #[cfg(not(target_os = "windows"))]
        assert_eq!(native_renderer(), eframe::Renderer::Glow);
    }
}
