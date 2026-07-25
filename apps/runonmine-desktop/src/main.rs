#[cfg(feature = "desktop-ui")]
mod connector_wizard;
#[cfg(feature = "desktop-ui")]
mod policy_editor;

#[cfg(feature = "desktop-ui")]
mod desktop {
    use std::collections::HashSet;
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::mpsc::{self, Receiver};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail};
    use eframe::egui;
    use runonmine_core::secrets::default_secret_store;
    use runonmine_core::{
        AppConfig, AppPaths, ApprovalDecision, ApprovalRequest, AuditRecord, ConnectorKind,
        PersistentGrant, PolicyPreset, StateStore,
    };
    use secrecy::SecretString;

    use crate::connector_wizard::{ConnectorCommand, ConnectorWizardState, rotation_label};
    use crate::policy_editor::{PolicyEditorAction, PolicyEditorState};
    use runonmine_oauth::{OAuthSession, RegisteredClient, SqliteOAuthStore};
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
    use uuid::Uuid;

    pub fn run() -> Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([980.0, 700.0])
                .with_min_inner_size([760.0, 520.0]),
            ..Default::default()
        };
        eframe::run_native(
            "RunOnMine",
            options,
            Box::new(|_context| Ok(Box::new(RunOnMineDesktop::new()))),
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum Tab {
        #[default]
        Overview,
        Approvals,
        Connections,
        Permissions,
        OAuth,
        Audit,
        Diagnostics,
    }

    struct RunOnMineDesktop {
        paths: Option<AppPaths>,
        store: Option<StateStore>,
        config: Option<AppConfig>,
        pending: Vec<ApprovalRequest>,
        persistent_grants: Vec<PersistentGrant>,
        audit: Vec<AuditRecord>,
        oauth_clients: Vec<RegisteredClient>,
        oauth_sessions: Vec<OAuthSession>,
        known: HashSet<Uuid>,
        last_refresh: Instant,
        status: String,
        error: Option<String>,
        audit_valid: Option<bool>,
        agent_reachable: bool,
        selected_tab: Tab,
        root_input: String,
        diagnostics: String,
        diagnostic_rx: Option<Receiver<std::result::Result<String, String>>>,
        pending_client_delete: Option<String>,
        pending_connector_delete: Option<String>,
        pending_credential_update: Option<(String, ConnectorKind)>,
        credential_client_id: String,
        credential_secret: String,
        policy_editor: PolicyEditorState,
        connector_wizard: ConnectorWizardState,
        connector_rx: Option<Receiver<std::result::Result<String, String>>>,
        tray: Option<TrayIcon>,
        open_menu_id: Option<MenuId>,
        lock_menu_id: Option<MenuId>,
        quit_menu_id: Option<MenuId>,
    }

    impl RunOnMineDesktop {
        fn new() -> Self {
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
                known: HashSet::new(),
                last_refresh: now.checked_sub(Duration::from_secs(10)).unwrap_or(now),
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
                credential_secret: String::new(),
                policy_editor: PolicyEditorState::default(),
                connector_wizard: ConnectorWizardState::default(),
                connector_rx: None,
                tray: None,
                open_menu_id: None,
                lock_menu_id: None,
                quit_menu_id: None,
            };
            if let Err(error) = app.initialize() {
                app.error = Some(error.to_string());
                "Setup required".clone_into(&mut app.status);
            }
            app
        }

        fn initialize(&mut self) -> Result<()> {
            let paths = AppPaths::discover()?;
            paths.ensure()?;
            let config =
                AppConfig::load(&paths.config_file()).context("Run `runonmine setup` first")?;
            let store = StateStore::open(&paths.state_db())?;
            self.paths = Some(paths);
            self.config = Some(config);
            self.store = Some(store);
            self.create_tray();
            self.refresh()?;
            Ok(())
        }

        fn create_tray(&mut self) {
            let menu = Menu::new();
            let open = MenuItem::new("Open RunOnMine", true, None);
            let lock = MenuItem::new("Lock RunOnMine", true, None);
            let quit = MenuItem::new("Quit", true, None);
            if menu.append(&open).is_err()
                || menu.append(&lock).is_err()
                || menu.append(&quit).is_err()
            {
                return;
            }
            let Ok(icon) = app_icon() else {
                return;
            };
            let Ok(tray) = TrayIconBuilder::new()
                .with_menu(Box::new(menu))
                .with_tooltip("RunOnMine")
                .with_icon(icon)
                .build()
            else {
                return;
            };
            self.open_menu_id = Some(open.id().clone());
            self.lock_menu_id = Some(lock.id().clone());
            self.quit_menu_id = Some(quit.id().clone());
            self.tray = Some(tray);
        }

        fn refresh(&mut self) -> Result<()> {
            let paths = self
                .paths
                .as_ref()
                .context("RunOnMine paths are unavailable")?;
            let config = AppConfig::load(&paths.config_file())?;
            let store = self
                .store
                .as_ref()
                .context("RunOnMine state is unavailable")?;
            self.pending = store.pending_approvals()?;
            self.persistent_grants = store.persistent_grants(None)?;
            self.audit = store.audit_tail(100)?;
            self.audit_valid = Some(store.verify_audit_chain()?);
            for request in &self.pending {
                self.known.insert(request.id);
            }
            let address = std::net::SocketAddr::from(([127, 0, 0, 1], config.port));
            self.agent_reachable =
                std::net::TcpStream::connect_timeout(&address, Duration::from_millis(120)).is_ok();
            let oauth = SqliteOAuthStore::open(&paths.state_db())?;
            self.oauth_clients = oauth.registered_clients()?;
            self.oauth_sessions = oauth.sessions(None)?;
            self.status = if !self.pending.is_empty() {
                format!("{} approval(s) waiting", self.pending.len())
            } else if self.agent_reachable {
                "Agent ready".to_owned()
            } else {
                "Agent stopped".to_owned()
            };
            self.config = Some(config);
            if let Some(tray) = &self.tray {
                let _result = tray.set_tooltip(Some(&format!("RunOnMine — {}", self.status)));
            }
            self.last_refresh = Instant::now();
            Ok(())
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
            self.refresh()
        }

        fn emergency_lock(&mut self) -> Result<()> {
            #[cfg(target_os = "linux")]
            let arguments = vec!["lock".to_owned(), "--system".to_owned()];
            #[cfg(not(target_os = "linux"))]
            let arguments = vec!["lock".to_owned()];
            let output = run_cli_capture(&arguments)?;
            self.diagnostics = output;
            self.refresh()?;
            "Locked — restart explicitly to restore access".clone_into(&mut self.status);
            if let Some(tray) = &self.tray {
                let _result = tray.set_tooltip(Some("RunOnMine — locked"));
            }
            Ok(())
        }

        fn save_config(&mut self, config: AppConfig) -> Result<()> {
            let paths = self
                .paths
                .as_ref()
                .context("RunOnMine paths are unavailable")?;
            config.validate()?;
            config.save(&paths.config_file())?;
            self.config = Some(config);
            self.refresh()
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
            let mut config = self
                .config
                .clone()
                .context("Configuration is unavailable")?;
            if !config.allowed_roots.contains(&root) {
                config.allowed_roots.push(root);
                config.allowed_roots.sort();
            }
            self.root_input.clear();
            self.save_config(config)
        }

        fn remove_root(&mut self, root: &PathBuf) -> Result<()> {
            let mut config = self
                .config
                .clone()
                .context("Configuration is unavailable")?;
            config.allowed_roots.retain(|candidate| candidate != root);
            self.save_config(config)
        }

        fn set_preset(&mut self, connector_id: &str, preset: PolicyPreset) -> Result<()> {
            let mut config = self
                .config
                .clone()
                .context("Configuration is unavailable")?;
            let connector = config
                .connector_mut(connector_id)
                .context("Connector no longer exists")?;
            connector.policy_preset = preset;
            connector.pack_overrides.clear();
            connector.tool_overrides.clear();
            self.save_config(config)
        }

        fn toggle_connector(&mut self, connector_id: &str, enable: bool) -> Result<()> {
            let verb = if enable { "enable" } else { "disable" };
            self.diagnostics = run_cli_capture(&[
                "connect".to_owned(),
                verb.to_owned(),
                connector_id.to_owned(),
            ])?;
            self.refresh()
        }

        fn revoke_grant(&mut self, grant: &PersistentGrant) -> Result<()> {
            let store = self
                .store
                .as_ref()
                .context("RunOnMine state is unavailable")?;
            if !store.delete_persistent_grant(
                &grant.connector_id,
                &grant.tool_name,
                &grant.argument_hash,
            )? {
                bail!("Persistent grant no longer exists");
            }
            self.refresh()
        }

        fn revoke_oauth_client(&mut self, client_id: &str) -> Result<()> {
            let paths = self
                .paths
                .as_ref()
                .context("RunOnMine paths are unavailable")?;
            let oauth = SqliteOAuthStore::open(&paths.state_db())?;
            let revoked = oauth.revoke_client_tokens(client_id)?;
            self.diagnostics = format!("Revoked {revoked} active token(s) for {client_id}.");
            self.refresh()
        }

        fn delete_oauth_client(&mut self, client_id: &str) -> Result<()> {
            let paths = self
                .paths
                .as_ref()
                .context("RunOnMine paths are unavailable")?;
            if !SqliteOAuthStore::open(&paths.state_db())?.delete_client(client_id)? {
                bail!("OAuth client no longer exists");
            }
            self.refresh()
        }

        fn revoke_oauth_session(&mut self, family_id: Uuid) -> Result<()> {
            let paths = self
                .paths
                .as_ref()
                .context("RunOnMine paths are unavailable")?;
            let revoked = SqliteOAuthStore::open(&paths.state_db())?.revoke_session(family_id)?;
            self.diagnostics = format!("Revoked {revoked} active token(s) in {family_id}.");
            self.refresh()
        }

        fn apply_policy_action(&mut self, action: PolicyEditorAction) -> Result<()> {
            let mut config = self
                .config
                .clone()
                .context("Configuration is unavailable")?;
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
            self.save_config(config)
        }

        fn start_connector_command(&mut self, command: ConnectorCommand) -> Result<()> {
            if self.connector_rx.is_some() {
                bail!("Another connector operation is already running");
            }
            let cli = sibling_cli()?;
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result =
                    run_cli_with_input(&cli, &command.arguments, command.stdin_secret.as_deref())
                        .map_err(|error| error.to_string());
                let _ignored = sender.send(result);
            });
            self.connector_rx = Some(receiver);
            "Connector operation is running…".clone_into(&mut self.diagnostics);
            Ok(())
        }

        fn poll_connector_command(&mut self) {
            let result = self
                .connector_rx
                .as_ref()
                .and_then(|receiver| receiver.try_recv().ok());
            if let Some(result) = result {
                self.connector_rx = None;
                self.connector_wizard.clear_secrets();
                match result {
                    Ok(output) => {
                        self.diagnostics = output;
                        self.connector_wizard.open = false;
                        if let Err(error) = self.refresh() {
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
                    secrets.set(
                        &format!("connector.{connector_id}.github_client_id"),
                        &SecretString::from(client_id.to_owned()),
                    )?;
                    secrets.set(
                        &format!("connector.{connector_id}.github_client_secret"),
                        &SecretString::from(secret.to_owned()),
                    )?;
                    let revoked =
                        SqliteOAuthStore::open(&paths.state_db())?.emergency_revoke_all()?;
                    self.diagnostics = format!(
                        "Updated GitHub credentials and revoked {revoked} OAuth token(s). Restart the agent to apply the new credentials."
                    );
                }
                ConnectorKind::OpenAiTunnel => {
                    let secret = self.credential_secret.trim();
                    if secret.is_empty() {
                        bail!("OpenAI runtime API key is required");
                    }
                    secrets.set(
                        &format!("connector.{connector_id}.runtime_api_key"),
                        &SecretString::from(secret.to_owned()),
                    )?;
                    "Updated the OpenAI runtime API key. Restart the agent to reconnect."
                        .clone_into(&mut self.diagnostics);
                }
                _ => bail!("This connector does not support credential updates"),
            }
            self.credential_client_id.clear();
            self.credential_secret.clear();
            self.pending_credential_update = None;
            self.refresh()
        }

        fn start_doctor(&mut self) -> Result<()> {
            if self.diagnostic_rx.is_some() {
                return Ok(());
            }
            let cli = sibling_cli()?;
            let (sender, receiver) = mpsc::channel();
            std::thread::spawn(move || {
                let result = std::process::Command::new(cli)
                    .arg("doctor")
                    .output()
                    .map_err(|error| error.to_string())
                    .and_then(|output| {
                        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                        if !output.stderr.is_empty() {
                            text.push_str(&String::from_utf8_lossy(&output.stderr));
                        }
                        if output.status.success() {
                            Ok(text)
                        } else {
                            Err(text)
                        }
                    });
                let _ignored = sender.send(result);
            });
            self.diagnostic_rx = Some(receiver);
            "Doctor is running…".clone_into(&mut self.diagnostics);
            Ok(())
        }

        fn poll_doctor(&mut self) {
            let result = self
                .diagnostic_rx
                .as_ref()
                .and_then(|receiver| receiver.try_recv().ok());
            if let Some(result) = result {
                self.diagnostics = result.unwrap_or_else(|error| error);
                self.diagnostic_rx = None;
            }
        }

        fn process_menu(&mut self, context: &egui::Context) {
            while let Ok(event) = MenuEvent::receiver().try_recv() {
                if self.open_menu_id.as_ref() == Some(&event.id) {
                    context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    context.send_viewport_cmd(egui::ViewportCommand::Focus);
                } else if self.lock_menu_id.as_ref() == Some(&event.id) {
                    if let Err(error) = self.emergency_lock() {
                        self.error = Some(error.to_string());
                    }
                    context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    context.send_viewport_cmd(egui::ViewportCommand::Focus);
                } else if self.quit_menu_id.as_ref() == Some(&event.id) {
                    context.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        fn show_tabs(&mut self, ui: &mut egui::Ui) {
            ui.horizontal_wrapped(|ui| {
                for (tab, label) in [
                    (Tab::Overview, "Overview"),
                    (Tab::Approvals, "Approvals"),
                    (Tab::Connections, "Connections"),
                    (Tab::Permissions, "Permissions"),
                    (Tab::OAuth, "OAuth"),
                    (Tab::Audit, "Audit"),
                    (Tab::Diagnostics, "Diagnostics"),
                ] {
                    ui.selectable_value(&mut self.selected_tab, tab, label);
                }
            });
        }

        fn show_overview(&mut self, ui: &mut egui::Ui) {
            let Some(config) = &self.config else {
                ui.label("Configuration is unavailable.");
                return;
            };
            ui.heading("Security overview");
            egui::Grid::new("overview-grid")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.label("Agent");
                    ui.label(if self.agent_reachable {
                        "Reachable"
                    } else {
                        "Stopped"
                    });
                    ui.end_row();
                    ui.label("Audit chain");
                    ui.label(match self.audit_valid {
                        Some(true) => "Valid",
                        Some(false) => "FAILED",
                        None => "Unknown",
                    });
                    ui.end_row();
                    ui.label("Enabled connectors");
                    ui.label(
                        config
                            .connectors
                            .iter()
                            .filter(|item| item.enabled)
                            .count()
                            .to_string(),
                    );
                    ui.end_row();
                    ui.label("Allowed roots");
                    ui.label(config.allowed_roots.len().to_string());
                    ui.end_row();
                    ui.label("Pending approvals");
                    ui.label(self.pending.len().to_string());
                    ui.end_row();
                    ui.label("Persistent exact grants");
                    ui.label(self.persistent_grants.len().to_string());
                    ui.end_row();
                    ui.label("OAuth clients");
                    ui.label(self.oauth_clients.len().to_string());
                    ui.end_row();
                });
            ui.add_space(16.0);
            ui.label("RunOnMine only exposes capabilities permitted by local connector policy. Remote connectors cannot use administrator execution, external CDP, or private-network browser access.");
        }

        fn show_approvals(&mut self, ui: &mut egui::Ui) {
            ui.heading("Local approvals");
            ui.label("Only this application or the local CLI can approve AI tool calls.");
            ui.add_space(8.0);
            if self.pending.is_empty() {
                ui.group(|ui| {
                    ui.label("No tool calls are waiting for approval.");
                });
            }
            let pending = self.pending.clone();
            let mut action = None;
            for request in pending {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.strong(&request.tool_name);
                        ui.label(format!("Connector: {}", request.connector_id));
                    });
                    ui.label(&request.argument_summary);
                    ui.small(format!("Expires: {}", request.expires_at.to_rfc3339()));
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Allow once").clicked() {
                            action = Some((request.id, ApprovalDecision::Once));
                        }
                        if ui.button("Allow exact action for 10 minutes").clicked() {
                            action = Some((request.id, ApprovalDecision::ForTenMinutes));
                        }
                        if ui.button("Always allow this exact action").clicked() {
                            action = Some((request.id, ApprovalDecision::Always));
                        }
                        if ui.button("Deny").clicked() {
                            action = Some((request.id, ApprovalDecision::Deny));
                        }
                    });
                });
                ui.add_space(8.0);
            }
            if let Some((id, decision)) = action {
                let result = self.resolve(id, decision);
                self.apply_result(result);
            }

            ui.separator();
            ui.heading("Persistent exact-action grants");
            let grants = self.persistent_grants.clone();
            if grants.is_empty() {
                ui.label("No persistent grants.");
            }
            let mut revoke = None;
            for grant in grants {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.strong(format!("{} · {}", grant.connector_id, grant.tool_name));
                        if ui.button("Revoke").clicked() {
                            revoke = Some(grant.clone());
                        }
                    });
                    ui.label(grant.argument_summary.clone());
                    ui.small(format!("Hash: {}", grant.argument_hash));
                });
            }
            if let Some(grant) = revoke {
                let result = self.revoke_grant(&grant);
                self.apply_result(result);
            }
        }

        #[allow(clippy::too_many_lines)]
        fn show_connections(&mut self, ui: &mut egui::Ui) {
            ui.horizontal(|ui| {
                ui.heading("Connections");
                if ui
                    .add_enabled(
                        self.connector_rx.is_none(),
                        egui::Button::new("Add connector…"),
                    )
                    .clicked()
                {
                    self.connector_wizard.open = true;
                }
            });
            ui.label("Connector secrets remain masked and are stored in the operating-system credential store.");
            let connectors = self
                .config
                .as_ref()
                .map(|config| config.connectors.clone())
                .unwrap_or_default();
            let mut toggle = None;
            let mut rotate_quick = None;
            let mut remove = None;
            let mut update_credentials = None;
            for connector in connectors {
                let confirming_delete =
                    self.pending_connector_delete.as_deref() == Some(&connector.id);
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(&connector.name);
                        ui.label(format!("{:?}", connector.kind));
                        ui.label(if connector.enabled { "Enabled" } else { "Disabled" });
                        if ui
                            .add_enabled(
                                self.connector_rx.is_none(),
                                egui::Button::new(if connector.enabled { "Disable" } else { "Enable" }),
                            )
                            .clicked()
                        {
                            toggle = Some((connector.id.clone(), !connector.enabled));
                        }
                        if let Some(label) = rotation_label(connector.kind)
                            && ui.add_enabled(self.connector_rx.is_none(), egui::Button::new(label)).clicked()
                        {
                            match connector.kind {
                                ConnectorKind::CloudflareQuick => rotate_quick = Some(connector.id.clone()),
                                ConnectorKind::CloudflareOauth | ConnectorKind::OpenAiTunnel => {
                                    update_credentials = Some((connector.id.clone(), connector.kind));
                                }
                                _ => {}
                            }
                        }
                        if confirming_delete {
                            if ui.button("Confirm permanent removal").clicked() {
                                remove = Some(connector.id.clone());
                            }
                            if ui.button("Cancel").clicked() {
                                self.pending_connector_delete = None;
                            }
                        } else if !matches!(connector.kind, ConnectorKind::LocalStdio | ConnectorKind::LocalHttp)
                            && ui.button("Remove…").clicked()
                        {
                            self.pending_connector_delete = Some(connector.id.clone());
                        }
                    });
                    ui.small(format!("ID: {}", connector.id));
                    ui.label(format!("Policy: {:?}", connector.policy_preset));
                    if let Some(url) = connector.public_base_url {
                        ui.label(format!("Public URL: {url}"));
                    }
                    if confirming_delete {
                        ui.colored_label(
                            egui::Color32::from_rgb(190, 45, 45),
                            "This removes local credentials, persistent grants, and connector state. Live transports close after agent restart.",
                        );
                    }
                });
                ui.add_space(6.0);
            }
            if let Some((id, enable)) = toggle {
                let result = self.toggle_connector(&id, enable);
                self.apply_result(result);
            }
            if let Some(id) = rotate_quick {
                let result = self.rotate_quick_connector(&id);
                self.apply_result(result);
            }
            if let Some((id, kind)) = update_credentials {
                self.pending_credential_update = Some((id, kind));
                self.credential_client_id.clear();
                self.credential_secret.clear();
            }
            if let Some(id) = remove {
                self.pending_connector_delete = None;
                let result = self.remove_connector(&id);
                self.apply_result(result);
            }

            if let Some((connector_id, kind)) = self.pending_credential_update.clone() {
                let mut open = true;
                egui::Window::new("Update connector credentials")
                    .open(&mut open)
                    .collapsible(false)
                    .show(ui.ctx(), |ui| {
                        ui.label("The new secret is written directly to the operating-system credential store and is never displayed after saving.");
                        if kind == ConnectorKind::CloudflareOauth {
                            ui.horizontal(|ui| {
                                ui.label("GitHub client ID");
                                ui.text_edit_singleline(&mut self.credential_client_id);
                            });
                        }
                        ui.horizontal(|ui| {
                            ui.label(if kind == ConnectorKind::CloudflareOauth { "GitHub client secret" } else { "Runtime API key" });
                            ui.add(egui::TextEdit::singleline(&mut self.credential_secret).password(true));
                        });
                        if ui.button("Save and revoke old sessions").clicked() {
                            let result = self.update_connector_credentials(&connector_id, kind);
                            self.apply_result(result);
                        }
                    });
                if !open {
                    self.pending_credential_update = None;
                    self.credential_client_id.clear();
                    self.credential_secret.clear();
                }
            }
        }

        fn show_permissions(&mut self, ui: &mut egui::Ui) {
            ui.heading("Filesystem roots");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.root_input);
                if ui.button("Add existing directory").clicked() {
                    let result = self.add_root();
                    self.apply_result(result);
                }
            });
            let roots = self
                .config
                .as_ref()
                .map(|config| config.allowed_roots.clone())
                .unwrap_or_default();
            let mut remove = None;
            for root in roots {
                ui.horizontal(|ui| {
                    ui.monospace(root.display().to_string());
                    if ui.button("Remove").clicked() {
                        remove = Some(root.clone());
                    }
                });
            }
            if let Some(root) = remove {
                let result = self.remove_root(&root);
                self.apply_result(result);
            }

            ui.separator();
            ui.heading("Connector policy presets");
            let connectors = self
                .config
                .as_ref()
                .map(|config| config.connectors.clone())
                .unwrap_or_default();
            let mut preset_change = None;
            for connector in connectors {
                ui.horizontal(|ui| {
                    ui.label(&connector.name);
                    let mut selected = connector.policy_preset;
                    egui::ComboBox::from_id_salt(format!("preset-{}", connector.id))
                        .selected_text(format!("{selected:?}"))
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
            }
            if let Some((id, preset)) = preset_change {
                let result = self.set_preset(&id, preset);
                self.apply_result(result);
            }
            ui.label("Changing a preset clears connector-specific overrides. Remote safety ceilings still apply.");
            ui.separator();
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

        fn show_oauth(&mut self, ui: &mut egui::Ui) {
            ui.heading("OAuth clients");
            let clients = self.oauth_clients.clone();
            let mut client_action = None;
            let mut request_delete = None;
            let mut cancel_delete = false;
            for client in clients {
                let confirming = self.pending_client_delete.as_deref() == Some(&client.client_id);
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(&client.client_name);
                        if ui.button("Revoke tokens").clicked() {
                            client_action = Some((client.client_id.clone(), false));
                        }
                        if confirming {
                            if ui.button("Confirm permanent delete").clicked() {
                                client_action = Some((client.client_id.clone(), true));
                            }
                            if ui.button("Cancel").clicked() {
                                cancel_delete = true;
                            }
                        } else if ui.button("Delete client…").clicked() {
                            request_delete = Some(client.client_id.clone());
                        }
                    });
                    ui.small(format!("ID: {}", client.client_id));
                    ui.label(format!("Scopes: {}", client.scopes.to_space_delimited()));
                    ui.label(format!("Issued: {}", client.issued_at.to_rfc3339()));
                    if confirming {
                        ui.colored_label(
                            egui::Color32::from_rgb(190, 45, 45),
                            "Deleting this client also removes its tokens and pending authorization state.",
                        );
                    }
                });
            }
            if cancel_delete {
                self.pending_client_delete = None;
            }
            if let Some(client_id) = request_delete {
                self.pending_client_delete = Some(client_id);
            }
            if let Some((client, delete)) = client_action {
                self.pending_client_delete = None;
                let result = if delete {
                    self.delete_oauth_client(&client)
                } else {
                    self.revoke_oauth_client(&client)
                };
                self.apply_result(result);
            }

            ui.separator();
            ui.heading("OAuth sessions");
            let sessions = self.oauth_sessions.clone();
            let mut revoke = None;
            for session in sessions {
                ui.horizontal(|ui| {
                    ui.label(format!(
                        "{} · {} · active={} · expires {}",
                        session.client_id,
                        session.family_id,
                        session.active,
                        session.expires_at.to_rfc3339()
                    ));
                    if session.active && ui.button("Revoke").clicked() {
                        revoke = Some(session.family_id);
                    }
                });
            }
            if let Some(family) = revoke {
                let result = self.revoke_oauth_session(family);
                self.apply_result(result);
            }
        }

        fn show_audit(&mut self, ui: &mut egui::Ui) {
            ui.heading("Recent audit events");
            ui.label(match self.audit_valid {
                Some(true) => "Hash chain: valid",
                Some(false) => "Hash chain: FAILED — dangerous actions should be blocked",
                None => "Hash chain: unknown",
            });
            for record in self.audit.iter().rev() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.strong(format!("#{} {}", record.sequence, record.event.tool_name));
                        ui.label(format!("{:?}", record.event.outcome));
                        ui.label(record.event.timestamp.to_rfc3339());
                    });
                    ui.label(&record.event.summary);
                    ui.small(format!("Connector: {}", record.event.connector_id));
                });
            }
        }

        fn show_diagnostics(&mut self, ui: &mut egui::Ui) {
            ui.heading("Diagnostics");
            let running = self.diagnostic_rx.is_some();
            if ui
                .add_enabled(!running, egui::Button::new("Run full doctor"))
                .clicked()
            {
                let result = self.start_doctor();
                self.apply_result(result);
            }
            if ui.button("Refresh state").clicked() {
                let result = self.refresh();
                self.apply_result(result);
            }
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                ui.monospace(&self.diagnostics);
            });
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
            self.process_menu(context);
            self.poll_doctor();
            self.poll_connector_command();
            if self.last_refresh.elapsed() >= Duration::from_secs(2) {
                let result = self.refresh();
                self.apply_result(result);
            }
            context.request_repaint_after(Duration::from_millis(500));
        }

        fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
            if let Some(command) = self
                .connector_wizard
                .show(ui.ctx(), self.connector_rx.is_some())
            {
                let result = self.start_connector_command(command);
                self.apply_result(result);
            }
            egui::Frame::central_panel(ui.style()).show(ui, |ui| {
                let mut lock_requested = false;
                ui.horizontal(|ui| {
                    ui.heading("RunOnMine");
                    ui.separator();
                    ui.label(&self.status);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.button("Lock all access").clicked() {
                            lock_requested = true;
                        }
                    });
                });
                if lock_requested {
                    let result = self.emergency_lock();
                    self.apply_result(result);
                }
                self.show_tabs(ui);
                ui.separator();
                if let Some(error) = &self.error {
                    ui.colored_label(egui::Color32::from_rgb(190, 45, 45), error);
                    ui.separator();
                }
                egui::ScrollArea::vertical().show(ui, |ui| match self.selected_tab {
                    Tab::Overview => self.show_overview(ui),
                    Tab::Approvals => self.show_approvals(ui),
                    Tab::Connections => self.show_connections(ui),
                    Tab::Permissions => self.show_permissions(ui),
                    Tab::OAuth => self.show_oauth(ui),
                    Tab::Audit => self.show_audit(ui),
                    Tab::Diagnostics => self.show_diagnostics(ui),
                });
            });
        }
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
        if !cli.is_file() {
            bail!("RunOnMine CLI is not installed beside the desktop application");
        }
        Ok(cli)
    }

    fn run_cli_capture(arguments: &[String]) -> Result<String> {
        let output = std::process::Command::new(sibling_cli()?)
            .args(arguments)
            .output()?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.stderr.is_empty() {
            text.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        if !output.status.success() {
            bail!("{text}");
        }
        Ok(text)
    }

    fn run_cli_with_input(
        cli: &PathBuf,
        arguments: &[String],
        secret: Option<&str>,
    ) -> Result<String> {
        let mut command = std::process::Command::new(cli);
        command
            .args(arguments)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if secret.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn()?;
        if let Some(secret) = secret {
            let mut stdin = child
                .stdin
                .take()
                .context("Failed to open connector command input")?;
            stdin.write_all(secret.as_bytes())?;
            stdin.write_all(b"\n")?;
        }
        let output = child.wait_with_output()?;
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.stderr.is_empty() {
            text.push_str(&String::from_utf8_lossy(&output.stderr));
        }
        if !output.status.success() {
            bail!("{text}");
        }
        Ok(text)
    }

    fn app_icon() -> Result<Icon> {
        const SIZE: usize = 32;
        let mut rgba = vec![0_u8; SIZE * SIZE * 4];
        for y in 0..SIZE {
            for x in 0..SIZE {
                let offset = (y * SIZE + x) * 4;
                let inside = (4..28).contains(&x) && (4..28).contains(&y);
                rgba[offset] = if inside { 38 } else { 0 };
                rgba[offset + 1] = if inside { 155 } else { 0 };
                rgba[offset + 2] = if inside { 111 } else { 0 };
                rgba[offset + 3] = if inside { 255 } else { 0 };
            }
        }
        let size = u32::try_from(SIZE).context("tray icon size is invalid")?;
        Icon::from_rgba(rgba, size, size).map_err(|error| anyhow::anyhow!(error.to_string()))
    }
}

#[cfg(feature = "desktop-ui")]
fn main() -> anyhow::Result<()> {
    desktop::run()
}

#[cfg(not(feature = "desktop-ui"))]
fn main() {
    eprintln!("runonmine-desktop was built without the desktop-ui feature");
}
