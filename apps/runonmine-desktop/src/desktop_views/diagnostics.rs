use super::super::{RunOnMineDesktop, StatusTone, UiIcon, egui, theme};

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
        self.show_desktop_integration(ui);
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

    fn show_desktop_integration(&self, ui: &mut egui::Ui) {
        let shell_available = self.shell.is_available();
        let shell_status = if shell_available {
            "System tray active"
        } else {
            "Window-only fallback"
        };
        let close_behavior = if shell_available {
            "Closing the window hides RunOnMine while the security controls remain available from the system tray."
        } else {
            "This session has no supported native tray, so closing the window exits the control center."
        };
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                theme::icon(ui, UiIcon::Monitor, 19.0, theme::TEXT);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Desktop integration")
                            .size(17.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.label(
                        egui::RichText::new(format!(
                            "{} · {}",
                            desktop_platform_label(),
                            desktop_session_label()
                        ))
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    theme::status_badge(
                        ui,
                        shell_status,
                        if shell_available {
                            StatusTone::Success
                        } else {
                            StatusTone::Warning
                        },
                    );
                });
            });
            ui.add_space(12.0);
            theme::subtle_card(ui, |ui| {
                ui.label(
                    egui::RichText::new(close_behavior)
                        .size(12.0)
                        .color(theme::TEXT),
                );
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        egui::RichText::new("Native actions")
                            .strong()
                            .color(theme::MUTED),
                    );
                    for action in ["Open", "Lock", "Quit"] {
                        theme::status_badge(ui, action, StatusTone::Info);
                    }
                });
            });
        });
    }
}

fn desktop_platform_label() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "linux" => "Linux",
        "windows" => "Windows",
        _ => "Desktop",
    }
}

fn desktop_session_label() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some() {
            return "Wayland session";
        }
        if std::env::var_os("DISPLAY").is_some() {
            return "X11 session";
        }
        "headless session"
    }
    #[cfg(target_os = "macos")]
    {
        "native app session"
    }
    #[cfg(target_os = "windows")]
    {
        "native app session"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "desktop session"
    }
}
