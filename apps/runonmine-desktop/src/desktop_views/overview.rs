use super::super::{
    RunOnMineDesktop, StatusTone, Tab, UiIcon, activity_row, egui, layout, overview_check, theme,
};

impl RunOnMineDesktop {
    #[allow(clippy::too_many_lines)] // Screen-section extraction remains tracked in P2-02.
    pub(super) fn show_overview(&mut self, ui: &mut egui::Ui) {
        let enabled_connectors = self
            .config
            .as_ref()
            .map(|config| config.connectors.iter().filter(|item| item.enabled).count())
            .unwrap_or_default();
        let allowed_roots = self
            .config
            .as_ref()
            .map(|config| config.allowed_roots.len())
            .unwrap_or_default();
        let audit_integrity = matches!(self.audit_valid, Some(true));

        let metrics = [
            (
                UiIcon::Monitor,
                "Agent status",
                if self.agent_reachable {
                    "Online".to_owned()
                } else {
                    "Offline".to_owned()
                },
                if self.agent_reachable {
                    "Service is reachable"
                } else {
                    "No active agent"
                },
                "View diagnostics",
                if self.agent_reachable {
                    StatusTone::Success
                } else {
                    StatusTone::Neutral
                },
                Tab::Diagnostics,
            ),
            (
                UiIcon::Link,
                "Active connectors",
                enabled_connectors.to_string(),
                if enabled_connectors == 1 {
                    "Connector enabled"
                } else {
                    "Connectors enabled"
                },
                "View connections",
                StatusTone::Info,
                Tab::Connections,
            ),
            (
                UiIcon::Folder,
                "Allowed roots",
                allowed_roots.to_string(),
                if allowed_roots == 1 {
                    "Path configured"
                } else {
                    "Paths configured"
                },
                "Manage allowed roots",
                if allowed_roots > 0 {
                    StatusTone::Success
                } else {
                    StatusTone::Warning
                },
                Tab::Permissions,
            ),
            (
                UiIcon::Clipboard,
                "Pending approvals",
                self.pending.len().to_string(),
                if self.pending.is_empty() {
                    "Nothing awaiting review"
                } else {
                    "Awaiting local review"
                },
                "View approvals",
                if self.pending.is_empty() {
                    StatusTone::Success
                } else {
                    StatusTone::Warning
                },
                Tab::Approvals,
            ),
            (
                UiIcon::Key,
                "OAuth clients",
                self.oauth_clients.len().to_string(),
                if self.oauth_clients.len() == 1 {
                    "Registered client"
                } else {
                    "Registered clients"
                },
                "Manage OAuth",
                StatusTone::Purple,
                Tab::OAuth,
            ),
            (
                UiIcon::Shield,
                "Audit integrity",
                if audit_integrity {
                    "100%".to_owned()
                } else {
                    "Check".to_owned()
                },
                if audit_integrity {
                    "Hash chain verified"
                } else {
                    "Integrity needs review"
                },
                "View audit log",
                if audit_integrity {
                    StatusTone::Success
                } else {
                    StatusTone::Danger
                },
                Tab::Audit,
            ),
        ];

        let mut navigate_to = None;
        let metric_columns = layout::metric_columns(ui.available_width());
        for row in metrics.chunks(metric_columns) {
            ui.columns(row.len(), |columns| {
                for (column, metric) in columns.iter_mut().zip(row.iter()) {
                    let response = theme::metric_card(
                        column, metric.0, metric.1, &metric.2, metric.3, metric.4, metric.5,
                    );
                    if response.clicked() {
                        navigate_to = Some(metric.6);
                    }
                }
            });
            ui.add_space(10.0);
        }
        if let Some(tab) = navigate_to {
            self.selected_tab = tab;
        }

        let mut score = 0_u32;
        if audit_integrity {
            score += 30;
        }
        if allowed_roots > 0 {
            score += 25;
        }
        if enabled_connectors > 0 {
            score += 20;
        }
        if self.agent_reachable {
            score += 15;
        }
        if self.pending.is_empty() {
            score += 10;
        }
        let score_label = if score >= 80 {
            "Good"
        } else if score >= 50 {
            "Needs attention"
        } else {
            "Setup required"
        };

        ui.columns(2, |columns| {
            theme::card(&mut columns[0], |ui| {
                ui.set_min_height(275.0);
                ui.horizontal(|ui| {
                    theme::icon(ui, UiIcon::Shield, 19.0, theme::TEXT);
                    ui.label(
                        egui::RichText::new("Security posture")
                            .size(16.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                });
                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    theme::ring_gauge(ui, score, score_label);
                    ui.add_space(16.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(if score >= 80 {
                                "Your posture is good"
                            } else {
                                "A few items need attention"
                            })
                            .size(14.0)
                            .strong()
                            .color(if score >= 80 {
                                theme::ACCENT
                            } else {
                                theme::WARNING
                            }),
                        );
                        ui.label(
                            egui::RichText::new(
                                "Review the controls below to improve machine access safety.",
                            )
                            .size(11.5)
                            .color(theme::MUTED),
                        );
                        ui.add_space(12.0);
                        overview_check(
                            ui,
                            "Audit log integrity",
                            if audit_integrity {
                                "Good"
                            } else {
                                "Action required"
                            },
                            if audit_integrity {
                                StatusTone::Success
                            } else {
                                StatusTone::Danger
                            },
                        );
                        overview_check(
                            ui,
                            "Allowed roots configured",
                            if allowed_roots > 0 {
                                "Good"
                            } else {
                                "Action required"
                            },
                            if allowed_roots > 0 {
                                StatusTone::Success
                            } else {
                                StatusTone::Warning
                            },
                        );
                        overview_check(
                            ui,
                            "Active connectors",
                            if enabled_connectors > 0 {
                                "Ready"
                            } else {
                                "None"
                            },
                            if enabled_connectors > 0 {
                                StatusTone::Info
                            } else {
                                StatusTone::Neutral
                            },
                        );
                        overview_check(
                            ui,
                            "Agent service",
                            if self.agent_reachable {
                                "Online"
                            } else {
                                "Offline"
                            },
                            if self.agent_reachable {
                                StatusTone::Success
                            } else {
                                StatusTone::Neutral
                            },
                        );
                    });
                });
            });

            theme::card(&mut columns[1], |ui| {
                ui.set_min_height(275.0);
                ui.horizontal(|ui| {
                    theme::icon(ui, UiIcon::Activity, 19.0, theme::TEXT);
                    ui.label(
                        egui::RichText::new("Recent activity")
                            .size(16.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.link("View full audit log").clicked() {
                            self.selected_tab = Tab::Audit;
                        }
                    });
                });
                ui.add_space(12.0);
                if self.audit.is_empty() {
                    activity_row(
                        ui,
                        UiIcon::Server,
                        "Control center initialized",
                        "System",
                        "Current session",
                        StatusTone::Info,
                    );
                    activity_row(
                        ui,
                        if allowed_roots > 0 {
                            UiIcon::Check
                        } else {
                            UiIcon::AlertTriangle
                        },
                        if allowed_roots > 0 {
                            "Allowed roots configured"
                        } else {
                            "No allowed roots configured"
                        },
                        "Security",
                        "Current state",
                        if allowed_roots > 0 {
                            StatusTone::Success
                        } else {
                            StatusTone::Warning
                        },
                    );
                    activity_row(
                        ui,
                        if audit_integrity {
                            UiIcon::Check
                        } else {
                            UiIcon::AlertTriangle
                        },
                        if audit_integrity {
                            "Audit chain verified"
                        } else {
                            "Audit chain unavailable"
                        },
                        "Audit",
                        "Current state",
                        if audit_integrity {
                            StatusTone::Success
                        } else {
                            StatusTone::Danger
                        },
                    );
                } else {
                    for record in self.audit.iter().rev().take(5) {
                        activity_row(
                            ui,
                            UiIcon::Activity,
                            &record.event.tool_name,
                            &record.event.summary,
                            &record.event.timestamp.format("%H:%M").to_string(),
                            StatusTone::Info,
                        );
                    }
                }
            });
        });

        ui.add_space(10.0);
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                theme::icon(ui, UiIcon::Clipboard, 19.0, theme::TEXT);
                ui.label(
                    egui::RichText::new("Recent approvals")
                        .size(16.0)
                        .strong()
                        .color(theme::TEXT),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.link("View all approvals").clicked() {
                        self.selected_tab = Tab::Approvals;
                    }
                });
            });
            ui.add_space(10.0);
            if self.pending.is_empty() {
                ui.horizontal_centered(|ui| {
                    theme::icon(ui, UiIcon::Clipboard, 34.0, theme::MUTED);
                    ui.add_space(10.0);
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new("No pending approvals")
                                .size(14.0)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new("You are all caught up.")
                                .size(12.0)
                                .color(theme::MUTED),
                        );
                    });
                });
            } else {
                for request in self.pending.iter().take(3) {
                    ui.horizontal(|ui| {
                        theme::icon_box(ui, UiIcon::AlertTriangle, StatusTone::Warning);
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(&request.tool_name)
                                    .strong()
                                    .color(theme::TEXT),
                            );
                            ui.label(
                                egui::RichText::new(&request.argument_summary)
                                    .size(11.5)
                                    .color(theme::MUTED),
                            );
                        });
                    });
                }
            }
        });
    }
}
