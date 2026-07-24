#[cfg(feature = "desktop-ui")]
mod desktop {
    use std::collections::HashSet;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result};
    use eframe::egui;
    use runonmine_core::{
        AppConfig, AppPaths, ApprovalDecision, ApprovalRequest, PolicyMode, StateStore,
    };
    use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
    use uuid::Uuid;

    pub fn run() -> Result<()> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([760.0, 560.0])
                .with_min_inner_size([600.0, 420.0]),
            ..Default::default()
        };
        eframe::run_native(
            "RunOnMine",
            options,
            Box::new(|_context| Ok(Box::new(RunOnMineDesktop::new()))),
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))
    }

    struct RunOnMineDesktop {
        paths: Option<AppPaths>,
        store: Option<StateStore>,
        pending: Vec<ApprovalRequest>,
        known: HashSet<Uuid>,
        last_refresh: Instant,
        status: String,
        error: Option<String>,
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
                pending: Vec::new(),
                known: HashSet::new(),
                last_refresh: now.checked_sub(Duration::from_secs(10)).unwrap_or(now),
                status: "Starting".to_owned(),
                error: None,
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
            let _config =
                AppConfig::load(&paths.config_file()).context("Run `runonmine setup` first")?;
            let store = StateStore::open(&paths.state_db())?;
            self.paths = Some(paths);
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
            if let Some(store) = &self.store {
                self.pending = store.pending_approvals()?;
                for request in &self.pending {
                    self.known.insert(request.id);
                }
                self.status = if self.pending.is_empty() {
                    "Agent ready".to_owned()
                } else {
                    format!("{} approval(s) waiting", self.pending.len())
                };
                if let Some(tray) = &self.tray {
                    let _result = tray.set_tooltip(Some(&format!("RunOnMine — {}", self.status)));
                }
            }
            self.last_refresh = Instant::now();
            Ok(())
        }

        fn resolve(&mut self, id: Uuid, decision: ApprovalDecision) -> Result<()> {
            let store = self
                .store
                .as_ref()
                .context("RunOnMine is not initialized")?;
            let request = store
                .approval_status(id)?
                .context("Approval no longer exists")?;
            if !store.resolve_approval(id, decision)? {
                anyhow::bail!("Approval expired or was already resolved");
            }
            if decision == ApprovalDecision::Always {
                let paths = self
                    .paths
                    .as_ref()
                    .context("RunOnMine paths are unavailable")?;
                let mut config = AppConfig::load(&paths.config_file())?;
                let connector = config
                    .connector_mut(&request.connector_id)
                    .context("Connector no longer exists")?;
                connector
                    .tool_overrides
                    .insert(request.tool_name, PolicyMode::Allow);
                config.save(&paths.config_file())?;
            }
            self.refresh()
        }

        fn emergency_lock(&mut self) -> Result<()> {
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
                anyhow::bail!("RunOnMine CLI is not installed beside the desktop application");
            }
            let status = std::process::Command::new(cli).arg("lock").status()?;
            if !status.success() {
                anyhow::bail!("RunOnMine could not be locked");
            }
            self.refresh()?;
            "Locked — restart explicitly to restore access".clone_into(&mut self.status);
            if let Some(tray) = &self.tray {
                let _result = tray.set_tooltip(Some("RunOnMine — locked"));
            }
            Ok(())
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
    }

    impl eframe::App for RunOnMineDesktop {
        fn logic(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
            self.process_menu(context);
            if self.last_refresh.elapsed() >= Duration::from_secs(1)
                && let Err(error) = self.refresh()
            {
                self.error = Some(error.to_string());
            }
            context.request_repaint_after(Duration::from_millis(500));
        }

        fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
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
                    match self.emergency_lock() {
                        Ok(()) => self.error = None,
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
                ui.separator();
                ui.add_space(8.0);
                ui.heading("Local approvals");
                ui.label(
                    "Only this local application or the RunOnMine CLI can approve AI tool calls.",
                );
                ui.add_space(10.0);

                if let Some(error) = &self.error {
                    ui.colored_label(egui::Color32::from_rgb(190, 45, 45), error);
                    ui.add_space(10.0);
                }
                if self.pending.is_empty() {
                    ui.group(|ui| {
                        ui.label("No tool calls are waiting for approval.");
                    });
                    return;
                }

                let mut action = None;
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for request in &self.pending {
                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.strong(&request.tool_name);
                                ui.label(format!("Connector: {}", request.connector_id));
                            });
                            ui.label(&request.argument_summary);
                            ui.small(format!("Expires: {}", request.expires_at.to_rfc3339()));
                            ui.horizontal(|ui| {
                                if ui.button("Allow once").clicked() {
                                    action = Some((request.id, ApprovalDecision::Once));
                                }
                                if ui
                                    .button("Allow this exact action for 10 minutes")
                                    .clicked()
                                {
                                    action = Some((request.id, ApprovalDecision::ForTenMinutes));
                                }
                                if ui.button("Always allow this tool (unsafe)").clicked() {
                                    action = Some((request.id, ApprovalDecision::Always));
                                }
                                if ui.button("Deny").clicked() {
                                    action = Some((request.id, ApprovalDecision::Deny));
                                }
                            });
                        });
                        ui.add_space(8.0);
                    }
                });
                if let Some((id, decision)) = action {
                    match self.resolve(id, decision) {
                        Ok(()) => self.error = None,
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
            });
        }
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
