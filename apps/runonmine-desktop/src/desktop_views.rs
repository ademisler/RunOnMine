use super::*;

#[path = "desktop_views/approvals.rs"]
mod approvals;
#[path = "desktop_views/audit.rs"]
mod audit;
#[path = "desktop_views/connections.rs"]
mod connections;
#[path = "desktop_views/diagnostics.rs"]
mod diagnostics;
#[path = "desktop_views/oauth.rs"]
mod oauth;
#[path = "desktop_views/overview.rs"]
mod overview;
#[path = "desktop_views/permissions.rs"]
mod permissions;

impl RunOnMineDesktop {
    fn render_sidebar(&mut self, ui: &mut egui::Ui, sidebar_rect: egui::Rect) -> bool {
        let sidebar_inner = sidebar_rect.shrink2(egui::vec2(17.0, 18.0));
        let mut sidebar = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(sidebar_inner)
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        sidebar.set_width(sidebar_inner.width());
        sidebar.set_height(sidebar_inner.height());

        sidebar.horizontal(|ui| {
            egui::Frame::new()
                .fill(theme::ACCENT)
                .corner_radius(egui::CornerRadius::same(9))
                .inner_margin(egui::Margin::symmetric(10, 7))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("R")
                            .size(19.0)
                            .strong()
                            .color(egui::Color32::from_rgb(4, 32, 23)),
                    );
                });
            ui.add_space(3.0);
            ui.vertical(|ui| {
                ui.label(
                    egui::RichText::new("RunOnMine")
                        .size(17.0)
                        .strong()
                        .color(theme::TEXT),
                );
                ui.label(
                    egui::RichText::new("Security control center")
                        .size(10.5)
                        .color(theme::MUTED),
                );
            });
        });
        sidebar.add_space(20.0);

        let setup_required = self
            .config
            .as_ref()
            .is_none_or(|config| config.allowed_roots.is_empty());
        let setup_response = egui::Frame::new()
            .fill(theme::SURFACE_ALT)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .corner_radius(egui::CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(12, 11))
            .show(&mut sidebar, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    theme::icon_box(
                        ui,
                        if setup_required {
                            UiIcon::AlertTriangle
                        } else {
                            UiIcon::Shield
                        },
                        if setup_required {
                            StatusTone::Warning
                        } else {
                            StatusTone::Success
                        },
                    );
                    ui.add_space(3.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(if setup_required {
                                "Setup required"
                            } else if self.agent_reachable {
                                "System ready"
                            } else {
                                "Agent offline"
                            })
                            .size(12.5)
                            .strong()
                            .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new(if setup_required {
                                "Complete initial configuration"
                            } else {
                                &self.status
                            })
                            .size(10.5)
                            .color(theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        theme::icon(ui, UiIcon::ChevronRight, 13.0, theme::MUTED);
                    });
                });
            })
            .response
            .interact(egui::Sense::click());
        if setup_response.clicked() {
            self.selected_tab = if setup_required {
                Tab::Permissions
            } else {
                Tab::Overview
            };
        }
        let navigation_top = sidebar.cursor().top() + 18.0;
        let footer_height = 76.0;
        let footer_rect = egui::Rect::from_min_max(
            egui::pos2(sidebar_inner.left(), sidebar_inner.bottom() - footer_height),
            sidebar_inner.max,
        );
        let navigation_rect = egui::Rect::from_min_max(
            egui::pos2(sidebar_inner.left(), navigation_top),
            egui::pos2(sidebar_inner.right(), footer_rect.top() - 8.0),
        );
        if navigation_rect.height() > 1.0 {
            let mut navigation = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(navigation_rect)
                    .layout(egui::Layout::top_down(egui::Align::Min)),
            );
            navigation.set_clip_rect(navigation_rect);
            navigation.set_width(navigation_rect.width());
            egui::ScrollArea::vertical()
                .id_salt("sidebar-navigation")
                .auto_shrink([false, false])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                .show(&mut navigation, |ui| {
                    ui.set_width(ui.available_width());
                    for (tab, icon, label) in Tab::ALL {
                        let badge = (tab == Tab::Approvals).then_some(self.pending.len());
                        if theme::nav_item(ui, icon, label, self.selected_tab == tab, badge)
                            .clicked()
                        {
                            self.selected_tab = tab;
                        }
                        ui.add_space(4.0);
                    }
                });
        }

        let mut lock_requested = false;
        let mut footer = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(footer_rect)
                .layout(egui::Layout::bottom_up(egui::Align::Min)),
        );
        footer.set_clip_rect(footer_rect);
        footer.set_width(footer_rect.width());
        let lock = egui::Frame::new()
            .fill(theme::DANGER_SOFT)
            .stroke(egui::Stroke::new(1.0, theme::DANGER.gamma_multiply(0.55)))
            .corner_radius(egui::CornerRadius::same(7))
            .inner_margin(egui::Margin::symmetric(12, 10))
            .show(&mut footer, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal_centered(|ui| {
                    theme::icon(ui, UiIcon::Lock, 16.0, theme::DANGER);
                    ui.label(
                        egui::RichText::new("Lock all access")
                            .size(12.5)
                            .strong()
                            .color(theme::DANGER),
                    );
                });
            })
            .response
            .interact(egui::Sense::click());
        if lock.clicked() {
            lock_requested = true;
        }
        footer.add_space(9.0);
        footer.label(
            egui::RichText::new(format!("v{}", env!("CARGO_PKG_VERSION")))
                .size(10.5)
                .color(theme::MUTED),
        );

        lock_requested
    }

    fn render_content(&mut self, ui: &mut egui::Ui, content_rect: egui::Rect) {
        let content_inner = content_rect.shrink2(egui::vec2(26.0, 20.0));
        let mut content = ui.new_child(
            egui::UiBuilder::new()
                .max_rect(content_inner)
                .layout(egui::Layout::top_down(egui::Align::Min)),
        );
        content.set_width(content_inner.width());
        content.set_height(content_inner.height());

        if let Some(error) = self.error.clone() {
            egui::Frame::new()
                .fill(theme::DANGER_SOFT)
                .stroke(egui::Stroke::new(1.0, theme::DANGER.gamma_multiply(0.65)))
                .corner_radius(egui::CornerRadius::same(8))
                .inner_margin(egui::Margin::symmetric(14, 11))
                .show(&mut content, |ui| {
                    ui.set_width(ui.available_width());
                    ui.horizontal(|ui| {
                        theme::icon(ui, UiIcon::AlertTriangle, 20.0, theme::DANGER);
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new("RunOnMine needs attention")
                                    .size(12.5)
                                    .strong()
                                    .color(theme::DANGER),
                            );
                            ui.label(egui::RichText::new(error).size(11.5).color(theme::MUTED));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui
                                .add(theme::danger_button("Manage allowed roots"))
                                .clicked()
                            {
                                self.selected_tab = Tab::Permissions;
                            }
                        });
                    });
                });
            content.add_space(16.0);
        }

        content.horizontal(|ui| {
            ui.vertical(|ui| {
                theme::page_header(ui, self.selected_tab.title(), self.selected_tab.subtitle());
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                if theme::toolbar_button(ui, UiIcon::FileText, "Open audit", 104.0).clicked() {
                    self.selected_tab = Tab::Audit;
                }
                ui.add_space(7.0);
                if theme::toolbar_button(ui, UiIcon::Refresh, "Refresh", 92.0).clicked() {
                    let result = self.start_refresh();
                    self.apply_result(result);
                }
            });
        });
        content.add_space(20.0);

        // The sticky header and scrolling page body use independent clipping
        // regions so custom-painted cards can never draw under the header.
        let body_rect = content.available_rect_before_wrap();
        if body_rect.height() > 1.0 {
            let mut body = ui.new_child(
                egui::UiBuilder::new()
                    .max_rect(body_rect)
                    .layout(egui::Layout::top_down(egui::Align::Min)),
            );
            body.set_clip_rect(body_rect);
            body.set_width(body_rect.width());
            body.set_height(body_rect.height());

            egui::ScrollArea::vertical()
                .id_salt("main-content-scroll")
                .auto_shrink([false, false])
                .max_height(body_rect.height())
                .show(&mut body, |ui| {
                    ui.set_clip_rect(ui.clip_rect().intersect(body_rect));
                    ui.set_width(ui.available_width());
                    match self.selected_tab {
                        Tab::Overview => self.show_overview(ui),
                        Tab::Approvals => self.show_approvals(ui),
                        Tab::Connections => self.show_connections(ui),
                        Tab::Permissions => self.show_permissions(ui),
                        Tab::OAuth => self.show_oauth(ui),
                        Tab::Audit => self.show_audit(ui),
                        Tab::Diagnostics => self.show_diagnostics(ui),
                    }
                    ui.add_space(20.0);
                });
        }
    }

    pub(super) fn render_ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(command) = self
            .connector_wizard
            .show(ui.ctx(), self.connector_rx.is_some())
        {
            let result = self.start_connector_command(command);
            self.apply_result(result);
        }

        let full_rect = ui.available_rect_before_wrap();
        ui.allocate_rect(full_rect, egui::Sense::hover());
        let sidebar_width = layout::sidebar_width(full_rect.width());
        let sidebar_rect = egui::Rect::from_min_max(
            full_rect.min,
            egui::pos2(full_rect.left() + sidebar_width, full_rect.bottom()),
        );
        let content_rect = egui::Rect::from_min_max(
            egui::pos2(sidebar_rect.right(), full_rect.top()),
            full_rect.max,
        );
        ui.painter().rect_filled(sidebar_rect, 0.0, theme::SIDEBAR);
        ui.painter().rect_filled(content_rect, 0.0, theme::BG);
        ui.painter().line_segment(
            [sidebar_rect.right_top(), sidebar_rect.right_bottom()],
            egui::Stroke::new(1.0, theme::BORDER),
        );

        let lock_requested = self.render_sidebar(ui, sidebar_rect);
        self.render_content(ui, content_rect);

        if lock_requested {
            let result = self.emergency_lock();
            self.apply_result(result);
        }
    }
}
