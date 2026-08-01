use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use eframe::egui;
use serde::Serialize;

use crate::desktop_shell::DESKTOP_ACTIONS;
use crate::layout;

use crate::desktop_app::model::Tab;

const REPORT_ENV: &str = "RUNONMINE_DESKTOP_ACCEPTANCE_REPORT";

#[derive(Debug)]
pub(crate) struct DesktopAcceptance {
    output: PathBuf,
    rendered: Vec<RenderedView>,
    report_written: bool,
    completed_at: Option<Instant>,
}

#[derive(Clone, Debug, Serialize)]
struct RenderedView {
    name: &'static str,
    width: f32,
    height: f32,
}

#[derive(Debug, Serialize)]
struct DesktopAcceptanceReport {
    schema_version: u32,
    package_version: &'static str,
    platform: &'static str,
    architecture: &'static str,
    rendered_views: Vec<RenderedView>,
    native_shell_available: bool,
    close_to_tray: bool,
    native_shell_actions: [&'static str; 3],
    default_viewport: [f32; 2],
    minimum_viewport: [f32; 2],
    application_icon: bool,
}

impl DesktopAcceptance {
    pub(crate) fn from_environment() -> Result<Option<Self>> {
        let Some(value) = std::env::var_os(REPORT_ENV) else {
            return Ok(None);
        };
        let requested = PathBuf::from(value);
        if !requested.is_absolute() {
            bail!("{REPORT_ENV} must be an absolute path");
        }
        if requested.exists() {
            bail!("{REPORT_ENV} must not already exist");
        }
        let parent = requested
            .parent()
            .context("desktop acceptance report has no parent directory")?;
        let parent = parent.canonicalize().with_context(|| {
            format!(
                "desktop acceptance report parent is unavailable: {}",
                parent.display()
            )
        })?;
        let name = requested
            .file_name()
            .context("desktop acceptance report has no file name")?;
        Ok(Some(Self {
            output: parent.join(name),
            rendered: Vec::with_capacity(Tab::ALL.len()),
            report_written: false,
            completed_at: None,
        }))
    }

    pub(crate) fn next_tab(&self) -> Option<Tab> {
        Tab::ALL.get(self.rendered.len()).map(|(tab, _, _)| *tab)
    }

    pub(crate) fn record_render(&mut self, tab: Tab, size: egui::Vec2) {
        let Some((expected, _, _)) = Tab::ALL.get(self.rendered.len()) else {
            return;
        };
        if tab != *expected || size.x <= 0.0 || size.y <= 0.0 {
            return;
        }
        self.rendered.push(RenderedView {
            name: tab.acceptance_name(),
            width: size.x,
            height: size.y,
        });
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.rendered.len() == Tab::ALL.len()
    }

    pub(crate) fn ready_to_report(&mut self) -> bool {
        if !self.is_complete() {
            self.completed_at = None;
            return false;
        }
        let completed_at = self.completed_at.get_or_insert_with(Instant::now);
        completed_at.elapsed() >= Duration::from_millis(2_500)
    }

    pub(crate) fn write_report(&mut self, native_shell_available: bool) -> Result<()> {
        if self.report_written {
            return Ok(());
        }
        if !self.is_complete() {
            bail!("desktop acceptance report cannot be written before every view renders");
        }
        write_new_json(
            &self.output,
            &DesktopAcceptanceReport {
                schema_version: 1,
                package_version: env!("CARGO_PKG_VERSION"),
                platform: std::env::consts::OS,
                architecture: std::env::consts::ARCH,
                rendered_views: self.rendered.clone(),
                native_shell_available,
                close_to_tray: native_shell_available,
                native_shell_actions: DESKTOP_ACTIONS,
                default_viewport: layout::DEFAULT_VIEWPORT,
                minimum_viewport: layout::MINIMUM_VIEWPORT,
                application_icon: true,
            },
        )?;
        self.report_written = true;
        Ok(())
    }
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| {
            format!(
                "could not create desktop acceptance report: {}",
                path.display()
            )
        })?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_requires_all_views_and_contains_no_machine_identity() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let output = temp.path().join("desktop-report.json");
        let mut acceptance = DesktopAcceptance {
            output: output.clone(),
            rendered: Vec::new(),
            report_written: false,
            completed_at: None,
        };
        assert!(acceptance.write_report(true).is_err());
        for (tab, _, _) in Tab::ALL {
            acceptance.record_render(tab, egui::vec2(1040.0, 680.0));
        }
        acceptance.write_report(true)?;
        let report: serde_json::Value = serde_json::from_slice(&std::fs::read(output)?)?;
        assert_eq!(report["rendered_views"].as_array().map(Vec::len), Some(7));
        assert_eq!(
            report["native_shell_actions"],
            serde_json::json!(["show", "lock", "quit"])
        );
        assert!(report.get("home").is_none());
        assert!(report.get("username").is_none());
        Ok(())
    }
}
