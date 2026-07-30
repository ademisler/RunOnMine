use super::*;

impl RunOnMineDesktop {
    fn show_overview(&mut self, ui: &mut egui::Ui) {
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

    #[allow(clippy::too_many_lines)]
    fn show_approvals(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "Waiting for review",
            "Approvals can only be resolved from this machine or the local CLI.",
        );
        let mut action = None;
        if self.pending.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Check,
                "Nothing needs approval",
                "New sensitive actions will appear here with their exact target.",
            );
        } else {
            for request in self.pending.clone() {
                theme::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        theme::status_badge(ui, "Review required", StatusTone::Warning);
                        ui.label(
                            egui::RichText::new(&request.tool_name)
                                .size(16.0)
                                .strong()
                                .color(theme::TEXT),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "Expires {}",
                                    request.expires_at.to_rfc3339()
                                ))
                                .size(11.0)
                                .color(theme::MUTED),
                            );
                        });
                    });
                    ui.add_space(10.0);
                    theme::subtle_card(ui, |ui| {
                        ui.label(
                            egui::RichText::new(&request.argument_summary)
                                .monospace()
                                .color(theme::TEXT),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!("Connector: {}", request.connector_id))
                                .size(11.0)
                                .color(theme::MUTED),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "Requester: {}",
                                request.principal.display_label()
                            ))
                            .size(11.0)
                            .color(theme::MUTED),
                        );
                        ui.label(
                            egui::RichText::new(format!(
                                "Principal fingerprint: {}",
                                request.principal_fingerprint
                            ))
                            .size(10.0)
                            .monospace()
                            .color(theme::MUTED),
                        );
                    });
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(
                            "Review the complete effective action above before approving. Secret redaction only hides credential values; it does not make an unfamiliar command, path, URL, selector, or requester safe.",
                        )
                        .size(11.0)
                        .color(theme::WARNING),
                    );
                    ui.add_space(10.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(theme::primary_button("Allow once")).clicked() {
                            action = Some((request.id, ApprovalDecision::Once));
                        }
                        if ui.button("Allow for 10 minutes").clicked() {
                            action = Some((request.id, ApprovalDecision::ForTenMinutes));
                        }
                        if ui.button("Always allow exact action").clicked() {
                            action = Some((request.id, ApprovalDecision::Always));
                        }
                        if ui.add(theme::danger_button("Deny")).clicked() {
                            action = Some((request.id, ApprovalDecision::Deny));
                        }
                    });
                });
                ui.add_space(10.0);
            }
        }
        if let Some((id, decision)) = action {
            let result = self.resolve(id, decision);
            self.apply_result(result);
        }

        ui.add_space(22.0);
        theme::section_header(
            ui,
            "Persistent exact-action grants",
            "These grants match one connector, requester principal, tool, and argument hash only.",
        );
        let mut revoke = None;
        if self.persistent_grants.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Shield,
                "No persistent grants",
                "Approving an exact action permanently will add it here.",
            );
        } else {
            for grant in self.persistent_grants.clone() {
                theme::subtle_card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(format!(
                                    "{} · {}",
                                    grant.connector_id, grant.tool_name
                                ))
                                .strong()
                                .color(theme::TEXT),
                            );
                            ui.label(
                                egui::RichText::new(&grant.argument_summary)
                                    .size(12.0)
                                    .color(theme::MUTED),
                            );
                            ui.label(
                                egui::RichText::new(format!(
                                    "Requester {}",
                                    grant.principal.display_label()
                                ))
                                .size(11.0)
                                .color(theme::MUTED),
                            );
                            ui.label(
                                egui::RichText::new(format!(
                                    "Principal {}",
                                    grant.principal_fingerprint
                                ))
                                .size(10.0)
                                .monospace()
                                .color(theme::MUTED),
                            );
                            ui.label(
                                egui::RichText::new(format!("Hash {}", grant.argument_hash))
                                    .size(10.0)
                                    .monospace()
                                    .color(theme::MUTED),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(theme::danger_button("Revoke")).clicked() {
                                revoke = Some(grant.clone());
                            }
                        });
                    });
                });
                ui.add_space(8.0);
            }
        }
        if let Some(grant) = revoke {
            let result = self.revoke_grant(&grant);
            self.apply_result(result);
        }
    }

    fn connector_lifecycle_display(
        &self,
        connector: &ConnectorConfig,
    ) -> (String, StatusTone, Option<String>) {
        if !connector.enabled {
            return ("Disabled".to_owned(), StatusTone::Neutral, None);
        }
        if connector.kind == ConnectorKind::LocalStdio {
            return (
                "On demand".to_owned(),
                StatusTone::Info,
                Some("Starts for each local stdio client session.".to_owned()),
            );
        }
        if let Some(runtime) = self.connector_lifecycle.get(&connector.id) {
            let (label, tone) = match runtime.phase.as_str() {
                "ready" => ("Ready".to_owned(), StatusTone::Success),
                "starting" => ("Starting".to_owned(), StatusTone::Info),
                "backoff" => ("Backoff".to_owned(), StatusTone::Warning),
                "stopped" => ("Stopped".to_owned(), StatusTone::Neutral),
                "degraded" if runtime.stage.as_deref() == Some("authentication") => {
                    ("Stale credentials".to_owned(), StatusTone::Warning)
                }
                "degraded" if runtime.stage.as_deref() == Some("process") => {
                    ("Failed".to_owned(), StatusTone::Danger)
                }
                "degraded" => ("Degraded".to_owned(), StatusTone::Danger),
                other => (other.replace('_', " "), StatusTone::Warning),
            };
            let detail = runtime.message.clone().or_else(|| {
                runtime
                    .stage
                    .as_ref()
                    .map(|stage| format!("Lifecycle stage: {stage}"))
            });
            return (label, tone, detail);
        }
        if connector.kind == ConnectorKind::LocalHttp && self.agent_reachable {
            return ("Ready".to_owned(), StatusTone::Success, None);
        }
        if self.agent_reachable {
            (
                "Configured".to_owned(),
                StatusTone::Neutral,
                Some("No active managed runtime was reported for this connector.".to_owned()),
            )
        } else {
            (
                "Agent offline".to_owned(),
                StatusTone::Warning,
                Some("Start the RunOnMine agent to observe runtime health.".to_owned()),
            )
        }
    }

    #[allow(clippy::too_many_lines)]
    fn show_connections(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Secure connector endpoints")
                            .size(17.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Secrets stay masked and are stored in the operating-system credential store.",
                        )
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .add_enabled(
                            self.connector_rx.is_none(),
                            theme::primary_button("Add connector"),
                        )
                        .clicked()
                    {
                        self.connector_wizard.open = true;
                    }
                });
            });
        });
        ui.add_space(16.0);

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
            let confirming_delete = self.pending_connector_delete.as_deref() == Some(&connector.id);
            let public_url = if connector.kind == ConnectorKind::CloudflareQuick {
                self.quick_runtime_urls.get(&connector.id).cloned()
            } else {
                connector.public_base_url.clone()
            };
            let (lifecycle_label, lifecycle_tone, lifecycle_detail) =
                self.connector_lifecycle_display(&connector);
            theme::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                egui::RichText::new(&connector.name)
                                    .size(17.0)
                                    .strong()
                                    .color(theme::TEXT),
                            );
                            theme::status_badge(
                                ui,
                                if connector.enabled {
                                    "Enabled"
                                } else {
                                    "Disabled"
                                },
                                if connector.enabled {
                                    StatusTone::Success
                                } else {
                                    StatusTone::Neutral
                                },
                            );
                            theme::status_badge(ui, &lifecycle_label, lifecycle_tone);
                            theme::status_badge(
                                ui,
                                &format!("{:?}", connector.kind),
                                StatusTone::Info,
                            );
                            theme::status_badge(
                                ui,
                                &format!("{:?}", connector.policy_preset),
                                StatusTone::Neutral,
                            );
                        });
                        ui.add_space(6.0);
                        ui.label(
                            egui::RichText::new(format!("ID  {}", connector.id))
                                .size(10.0)
                                .monospace()
                                .color(theme::MUTED),
                        );
                        if let Some(url) = &public_url {
                            ui.label(
                                egui::RichText::new(format!("Public endpoint  {url}"))
                                    .size(12.0)
                                    .color(theme::INFO),
                            );
                        }
                        if let Some(detail) = &lifecycle_detail {
                            ui.label(egui::RichText::new(detail).size(11.0).color(theme::MUTED));
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if confirming_delete {
                            if ui.add(theme::danger_button("Confirm removal")).clicked() {
                                remove = Some(connector.id.clone());
                            }
                            if ui.button("Cancel").clicked() {
                                self.pending_connector_delete = None;
                            }
                        } else {
                            if !matches!(
                                connector.kind,
                                ConnectorKind::LocalStdio | ConnectorKind::LocalHttp
                            ) && ui.add(theme::danger_button("Remove…")).clicked()
                            {
                                self.pending_connector_delete = Some(connector.id.clone());
                            }
                            if let Some(label) = rotation_label(connector.kind)
                                && ui
                                    .add_enabled(
                                        self.connector_rx.is_none(),
                                        egui::Button::new(label),
                                    )
                                    .clicked()
                            {
                                match connector.kind {
                                    ConnectorKind::CloudflareQuick => {
                                        rotate_quick = Some(connector.id.clone());
                                    }
                                    ConnectorKind::CloudflareOauth
                                    | ConnectorKind::OpenAiTunnel => {
                                        update_credentials =
                                            Some((connector.id.clone(), connector.kind));
                                    }
                                    ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => {}
                                }
                            }
                            if ui
                                .add_enabled(
                                    self.connector_rx.is_none(),
                                    egui::Button::new(if connector.enabled {
                                        "Disable"
                                    } else {
                                        "Enable"
                                    }),
                                )
                                .clicked()
                            {
                                toggle = Some((connector.id.clone(), !connector.enabled));
                            }
                        }
                    });
                });
                if confirming_delete {
                    ui.add_space(12.0);
                    egui::Frame::new()
                        .fill(theme::DANGER_SOFT)
                        .stroke(egui::Stroke::new(1.0, theme::DANGER))
                        .corner_radius(egui::CornerRadius::same(9))
                        .inner_margin(egui::Margin::same(10))
                        .show(ui, |ui| {
                            ui.label(
                                egui::RichText::new(
                                    "This removes local credentials, persistent grants, and connector state. Live transports close after the agent restarts.",
                                )
                                .size(12.0)
                                .color(theme::DANGER),
                            );
                        });
                }
            });
            ui.add_space(10.0);
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
            self.credential_secret.zeroize();
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
                .resizable(false)
                .default_width(520.0)
                .show(ui.ctx(), |ui| {
                    theme::section_header(
                        ui,
                        "Replace stored credentials",
                        "The new secret is written directly to the credential store and never displayed again.",
                    );
                    if kind == ConnectorKind::CloudflareOauth {
                        ui.label(egui::RichText::new("GitHub client ID").size(12.0).color(theme::MUTED));
                        ui.add_sized(
                            [ui.available_width(), 36.0],
                            egui::TextEdit::singleline(&mut self.credential_client_id),
                        );
                        ui.add_space(10.0);
                    }
                    ui.label(
                        egui::RichText::new(if kind == ConnectorKind::CloudflareOauth {
                            "GitHub client secret"
                        } else {
                            "Runtime API key"
                        })
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                    ui.add_sized(
                        [ui.available_width(), 36.0],
                        egui::TextEdit::singleline(&mut *self.credential_secret).password(true),
                    );
                    ui.add_space(14.0);
                    ui.horizontal(|ui| {
                        if ui.add(theme::primary_button("Save and revoke old sessions")).clicked() {
                            let result = self.update_connector_credentials(&connector_id, kind);
                            self.apply_result(result);
                        }
                        if ui.button("Cancel").clicked() {
                            self.pending_credential_update = None;
                            self.credential_client_id.clear();
                            self.credential_secret.zeroize();
                        }
                    });
                });
            if !open {
                self.pending_credential_update = None;
                self.credential_client_id.clear();
                self.credential_secret.zeroize();
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn show_permissions(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            theme::section_header(
                ui,
                "Filesystem roots",
                "File tools cannot leave these explicitly selected directories.",
            );
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 170.0, 36.0],
                    egui::TextEdit::singleline(&mut self.root_input)
                        .hint_text("/absolute/path/to/project"),
                );
                if ui.add(theme::primary_button("Add directory")).clicked() {
                    let result = self.add_root();
                    self.apply_result(result);
                }
            });
            ui.add_space(12.0);
            let roots = self
                .config
                .as_ref()
                .map(|config| config.allowed_roots.clone())
                .unwrap_or_default();
            let mut remove = None;
            if roots.is_empty() {
                ui.label(
                    egui::RichText::new("No roots selected. File tools remain unavailable.")
                        .color(theme::MUTED),
                );
            }
            for root in roots {
                theme::subtle_card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new(root.display().to_string())
                                .monospace()
                                .color(theme::TEXT),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.add(theme::danger_button("Remove")).clicked() {
                                remove = Some(root.clone());
                            }
                        });
                    });
                });
                ui.add_space(7.0);
            }
            if let Some(root) = remove {
                let result = self.remove_root(&root);
                self.apply_result(result);
            }
        });

        ui.add_space(18.0);
        theme::card(ui, |ui| {
            theme::section_header(
                ui,
                "Connector policy presets",
                "Choose a baseline, then narrow it with advanced rules below.",
            );
            let connectors = self
                .config
                .as_ref()
                .map(|config| config.connectors.clone())
                .unwrap_or_default();
            let mut preset_change = None;
            for connector in connectors {
                theme::subtle_card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(
                                egui::RichText::new(&connector.name)
                                    .strong()
                                    .color(theme::TEXT),
                            );
                            ui.label(
                                egui::RichText::new(format!("{:?}", connector.kind))
                                    .size(11.0)
                                    .color(theme::MUTED),
                            );
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let mut selected = connector.policy_preset;
                            egui::ComboBox::from_id_salt(format!("preset-{}", connector.id))
                                .selected_text(format!("{selected:?}"))
                                .width(150.0)
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
                    });
                });
                ui.add_space(7.0);
            }
            if let Some((id, preset)) = preset_change {
                let result = self.set_preset(&id, preset);
                self.apply_result(result);
            }
            ui.add_space(8.0);
            ui.label(
                egui::RichText::new(
                    "Changing a preset clears connector-specific overrides. Remote safety ceilings still apply.",
                )
                .size(11.0)
                .color(theme::MUTED),
            );
        });

        ui.add_space(18.0);
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

    #[allow(clippy::too_many_lines)]
    fn show_oauth(&mut self, ui: &mut egui::Ui) {
        theme::section_header(
            ui,
            "Registered clients",
            "Clients can be revoked without deleting their registration.",
        );
        let clients = self.oauth_clients.clone();
        let mut client_action = None;
        let mut request_delete = None;
        let mut cancel_delete = false;
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
                                client_action = Some((
                                    client.connector_id.clone(),
                                    client.client_id.clone(),
                                    true,
                                ));
                            }
                            if ui.button("Cancel").clicked() {
                                cancel_delete = true;
                            }
                        } else {
                            if ui.add(theme::danger_button("Delete…")).clicked() {
                                request_delete =
                                    Some((client.connector_id.clone(), client.client_id.clone()));
                            }
                            if ui.button("Revoke tokens").clicked() {
                                client_action = Some((
                                    client.connector_id.clone(),
                                    client.client_id.clone(),
                                    false,
                                ));
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
                    ui.label(egui::RichText::new("Deleting this client also removes tokens and pending authorization state.").color(theme::DANGER));
                }
            });
            ui.add_space(10.0);
        }
        if cancel_delete {
            self.pending_client_delete = None;
        }
        if let Some(client) = request_delete {
            self.pending_client_delete = Some(client);
        }
        if let Some((connector_id, client_id, delete)) = client_action {
            self.pending_client_delete = None;
            let result = if delete {
                self.delete_oauth_client(&connector_id, &client_id)
            } else {
                self.revoke_oauth_client(&connector_id, &client_id)
            };
            self.apply_result(result);
        }

        ui.add_space(22.0);
        theme::section_header(
            ui,
            "Authorization sessions",
            "Refresh-token families can be revoked independently.",
        );
        let sessions = self.oauth_sessions.clone();
        let mut revoke = None;
        if sessions.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::Activity,
                "No sessions",
                "Active authorization sessions will appear here.",
            );
        }
        for session in sessions {
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
                            revoke = Some((session.connector_id.clone(), session.family_id));
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
            ui.add_space(8.0);
        }
        if let Some((connector_id, family_id)) = revoke {
            let result = self.revoke_oauth_session(&connector_id, family_id);
            self.apply_result(result);
        }
    }

    fn show_audit(&mut self, ui: &mut egui::Ui) {
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        egui::RichText::new("Audit integrity")
                            .size(17.0)
                            .strong()
                            .color(theme::TEXT),
                    );
                    ui.label(
                        egui::RichText::new(
                            "Records are linked through a tamper-evident hash chain.",
                        )
                        .size(12.0)
                        .color(theme::MUTED),
                    );
                    if let Some(report) = self.audit_verification {
                        ui.label(
                            egui::RichText::new(format!(
                                "{} verification · {} new record(s) checked · checkpoint #{} · tail #{}",
                                if report.full { "Full" } else { "Incremental" },
                                report.records_verified,
                                report.checkpoint_sequence,
                                report.tail_sequence,
                            ))
                            .size(10.5)
                            .monospace()
                            .color(theme::MUTED),
                        );
                    }
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    theme::status_badge(
                        ui,
                        match self.audit_valid {
                            Some(true) => "Verified",
                            Some(false) => "Failed",
                            None => "Unknown",
                        },
                        match self.audit_valid {
                            Some(true) => StatusTone::Success,
                            Some(false) => StatusTone::Danger,
                            None => StatusTone::Warning,
                        },
                    );
                });
            });
        });
        ui.add_space(18.0);

        if self.audit.is_empty() {
            theme::empty_state(
                ui,
                UiIcon::FileText,
                "No audit events",
                "Tool decisions will be recorded here.",
            );
            return;
        }
        for record in self.audit.iter().rev() {
            theme::subtle_card(ui, |ui| {
                ui.horizontal(|ui| {
                    theme::status_badge(
                        ui,
                        &format!("{:?}", record.event.outcome),
                        StatusTone::Neutral,
                    );
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(format!(
                                "#{}  {}",
                                record.sequence, record.event.tool_name
                            ))
                            .strong()
                            .color(theme::TEXT),
                        );
                        ui.label(
                            egui::RichText::new(&record.event.summary)
                                .size(12.0)
                                .color(theme::MUTED),
                        );
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            egui::RichText::new(record.event.timestamp.to_rfc3339())
                                .size(10.0)
                                .color(theme::MUTED),
                        );
                    });
                });
                ui.label(
                    egui::RichText::new(format!("Connector {}", record.event.connector_id))
                        .size(10.0)
                        .monospace()
                        .color(theme::MUTED),
                );
            });
            ui.add_space(7.0);
        }
        if self.audit.len() >= self.audit_limit && self.audit_limit < 10_000 {
            ui.add_space(10.0);
            if ui.button("Load older audit records").clicked() {
                self.audit_limit = self.audit_limit.saturating_mul(2).min(10_000);
                let result = self.start_refresh();
                self.apply_result(result);
            }
        }
    }

    fn show_diagnostics(&mut self, ui: &mut egui::Ui) {
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

        if lock_requested {
            let result = self.emergency_lock();
            self.apply_result(result);
        }
    }
}
