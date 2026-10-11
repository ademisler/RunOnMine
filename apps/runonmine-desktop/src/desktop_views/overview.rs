use super::super::{
    RunOnMineDesktop, StatusTone, Tab, UiIcon, activity_row, egui, layout, overview_check, theme,
};

#[derive(Clone, Copy, Debug)]
struct OverviewState {
    enabled_connectors: usize,
    allowed_roots: usize,
    audit_integrity: bool,
}

struct OverviewMetric {
    icon: UiIcon,
    title: &'static str,
    value: String,
    detail: &'static str,
    action: &'static str,
    tone: StatusTone,
    tab: Tab,
}

impl RunOnMineDesktop {
    pub(super) fn show_overview(&mut self, ui: &mut egui::Ui) {
        let state = self.overview_state();
        self.show_onboarding(ui, state);
        self.show_metric_cards(ui, state);

        let (score, score_label) = self.security_score(state);
        self.show_posture_and_activity(ui, state, score, score_label);
        ui.add_space(10.0);
        self.show_recent_approvals(ui);
    }

    fn overview_state(&self) -> OverviewState {
        OverviewState {
            enabled_connectors: self
                .config
                .as_ref()
                .map(|config| config.connectors.iter().filter(|item| item.enabled).count())
                .unwrap_or_default(),
            allowed_roots: self
                .config
                .as_ref()
                .map(|config| config.allowed_roots.len())
                .unwrap_or_default(),
            audit_integrity: matches!(self.audit_valid, Some(true)),
        }
    }

    fn show_onboarding(&mut self, ui: &mut egui::Ui, state: OverviewState) {
        if state.allowed_roots > 0 && state.enabled_connectors > 0 {
            return;
        }
        let mut onboarding_target = None;
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                theme::icon(ui, UiIcon::Shield, 20.0, theme::ACCENT);
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Secure first run")
                            .size(16.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Start in Safe mode: select only the project roots AI may see, then review or add a connector. Writes and execution still require local review.",
                        )
                        .size(11.5)
                        .color(theme::MUTED),
                    );
                });
            });
            ui.add_space(12.0);
            ui.horizontal_wrapped(|ui| {
                if ui.add(theme::primary_button("1. Select roots")).clicked() {
                    onboarding_target = Some(Tab::Permissions);
                }
                let connector_action = if state.enabled_connectors == 0 {
                    "2. Add connector"
                } else {
                    "2. Review connector"
                };
                if ui.add(theme::primary_button(connector_action)).clicked() {
                    onboarding_target = Some(Tab::Connections);
                }
                ui.label(
                    egui::RichText::new(
                        "3. Review exact actions in Approvals · Emergency Lock is always available in the sidebar and menu bar.",
                    )
                    .size(11.0)
                    .color(theme::MUTED),
                );
            });
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Administrator access is not installed by setup. The privileged helper is a separate, explicit advanced installation.",
                )
                .size(10.5)
                .color(theme::WARNING),
            );
        });
        if let Some(tab) = onboarding_target {
            self.selected_tab = tab;
        }
        ui.add_space(10.0);
    }

    fn show_metric_cards(&mut self, ui: &mut egui::Ui, state: OverviewState) {
        let metrics = self.overview_metrics(state);
        let mut navigate_to = None;
        let metric_columns = layout::metric_columns(ui.available_width());
        for row in metrics.chunks(metric_columns) {
            ui.columns(row.len(), |columns| {
                for (column, metric) in columns.iter_mut().zip(row.iter()) {
                    let response = theme::metric_card(
                        column,
                        metric.icon,
                        metric.title,
                        &metric.value,
                        metric.detail,
                        metric.action,
                        metric.tone,
                    );
                    if response.clicked() {
                        navigate_to = Some(metric.tab);
                    }
                }
            });
            ui.add_space(10.0);
        }
        if let Some(tab) = navigate_to {
            self.selected_tab = tab;
        }
    }

    fn overview_metrics(&self, state: OverviewState) -> [OverviewMetric; 6] {
        [
            self.agent_metric(),
            Self::connector_metric(state.enabled_connectors),
            Self::roots_metric(state.allowed_roots),
            self.approvals_metric(),
            self.oauth_metric(),
            Self::audit_metric(state.audit_integrity),
        ]
    }

    fn agent_metric(&self) -> OverviewMetric {
        OverviewMetric {
            icon: UiIcon::Monitor,
            title: "Agent status",
            value: if self.agent_reachable {
                "Online"
            } else {
                "Offline"
            }
            .to_owned(),
            detail: if self.agent_reachable {
                "Service is reachable"
            } else {
                "No active agent"
            },
            action: "View diagnostics",
            tone: if self.agent_reachable {
                StatusTone::Success
            } else {
                StatusTone::Neutral
            },
            tab: Tab::Diagnostics,
        }
    }

    fn connector_metric(enabled_connectors: usize) -> OverviewMetric {
        OverviewMetric {
            icon: UiIcon::Link,
            title: "Active connectors",
            value: enabled_connectors.to_string(),
            detail: if enabled_connectors == 1 {
                "Connector enabled"
            } else {
                "Connectors enabled"
            },
            action: "View connections",
            tone: StatusTone::Info,
            tab: Tab::Connections,
        }
    }

    fn roots_metric(allowed_roots: usize) -> OverviewMetric {
        OverviewMetric {
            icon: UiIcon::Folder,
            title: "Allowed roots",
            value: allowed_roots.to_string(),
            detail: if allowed_roots == 1 {
                "Path configured"
            } else {
                "Paths configured"
            },
            action: "Manage allowed roots",
            tone: if allowed_roots > 0 {
                StatusTone::Success
            } else {
                StatusTone::Warning
            },
            tab: Tab::Permissions,
        }
    }

    fn approvals_metric(&self) -> OverviewMetric {
        OverviewMetric {
            icon: UiIcon::Clipboard,
            title: "Pending approvals",
            value: self.pending.len().to_string(),
            detail: if self.pending.is_empty() {
                "Nothing awaiting review"
            } else {
                "Awaiting local review"
            },
            action: "View approvals",
            tone: if self.pending.is_empty() {
                StatusTone::Success
            } else {
                StatusTone::Warning
            },
            tab: Tab::Approvals,
        }
    }

    fn oauth_metric(&self) -> OverviewMetric {
        OverviewMetric {
            icon: UiIcon::Key,
            title: "OAuth clients",
            value: self.oauth_clients.len().to_string(),
            detail: if self.oauth_clients.len() == 1 {
                "Registered client"
            } else {
                "Registered clients"
            },
            action: "Manage OAuth",
            tone: StatusTone::Purple,
            tab: Tab::OAuth,
        }
    }

    fn audit_metric(audit_integrity: bool) -> OverviewMetric {
        OverviewMetric {
            icon: UiIcon::Shield,
            title: "Audit integrity",
            value: if audit_integrity { "100%" } else { "Check" }.to_owned(),
            detail: if audit_integrity {
                "Hash chain verified"
            } else {
                "Integrity needs review"
            },
            action: "View audit log",
            tone: if audit_integrity {
                StatusTone::Success
            } else {
                StatusTone::Danger
            },
            tab: Tab::Audit,
        }
    }

    fn security_score(&self, state: OverviewState) -> (u32, &'static str) {
        let mut score = 0_u32;
        if state.audit_integrity {
            score += 30;
        }
        if state.allowed_roots > 0 {
            score += 25;
        }
        if state.enabled_connectors > 0 {
            score += 20;
        }
        if self.agent_reachable {
            score += 15;
        }
        if self.pending.is_empty() {
            score += 10;
        }
        let label = if score >= 80 {
            "Good"
        } else if score >= 50 {
            "Needs attention"
        } else {
            "Setup required"
        };
        (score, label)
    }

    fn show_posture_and_activity(
        &mut self,
        ui: &mut egui::Ui,
        state: OverviewState,
        score: u32,
        score_label: &str,
    ) {
        ui.columns(2, |columns| {
            self.show_security_posture(&mut columns[0], state, score, score_label);
            self.show_recent_activity(&mut columns[1], state);
        });
    }

    fn show_security_posture(
        &self,
        ui: &mut egui::Ui,
        state: OverviewState,
        score: u32,
        score_label: &str,
    ) {
        theme::card(ui, |ui| {
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
                    self.show_security_checks(ui, state);
                });
            });
        });
    }

    fn show_security_checks(&self, ui: &mut egui::Ui, state: OverviewState) {
        overview_check(
            ui,
            "Audit log integrity",
            if state.audit_integrity {
                "Good"
            } else {
                "Action required"
            },
            if state.audit_integrity {
                StatusTone::Success
            } else {
                StatusTone::Danger
            },
        );
        overview_check(
            ui,
            "Allowed roots configured",
            if state.allowed_roots > 0 {
                "Good"
            } else {
                "Action required"
            },
            if state.allowed_roots > 0 {
                StatusTone::Success
            } else {
                StatusTone::Warning
            },
        );
        overview_check(
            ui,
            "Active connectors",
            if state.enabled_connectors > 0 {
                "Ready"
            } else {
                "None"
            },
            if state.enabled_connectors > 0 {
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
    }

    fn show_recent_activity(&mut self, ui: &mut egui::Ui, state: OverviewState) {
        theme::card(ui, |ui| {
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
                    if state.allowed_roots > 0 {
                        UiIcon::Check
                    } else {
                        UiIcon::AlertTriangle
                    },
                    if state.allowed_roots > 0 {
                        "Allowed roots configured"
                    } else {
                        "No allowed roots configured"
                    },
                    "Security",
                    "Current state",
                    if state.allowed_roots > 0 {
                        StatusTone::Success
                    } else {
                        StatusTone::Warning
                    },
                );
                activity_row(
                    ui,
                    if state.audit_integrity {
                        UiIcon::Check
                    } else {
                        UiIcon::AlertTriangle
                    },
                    if state.audit_integrity {
                        "Audit chain verified"
                    } else {
                        "Audit chain unavailable"
                    },
                    "Audit",
                    "Current state",
                    if state.audit_integrity {
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
    }

    fn show_recent_approvals(&mut self, ui: &mut egui::Ui) {
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
