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
const SCREENSHOT_ENV: &str = "RUNONMINE_DESKTOP_ACCEPTANCE_SCREENSHOT";
const SCREENSHOT_MARKER: &str = "runonmine-acceptance-overview";

#[derive(Debug)]
pub(crate) struct DesktopAcceptance {
    output: PathBuf,
    rendered: Vec<RenderedView>,
    report_written: bool,
    completed_at: Option<Instant>,
    screenshot_output: Option<PathBuf>,
    screenshot_requested: bool,
    screenshot_written: bool,
    screenshot_ready_at: Option<Instant>,
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
        let screenshot_output = optional_new_absolute_path(SCREENSHOT_ENV)?;
        Ok(Some(Self {
            output: parent.join(name),
            rendered: Vec::with_capacity(Tab::ALL.len()),
            report_written: false,
            completed_at: None,
            screenshot_output,
            screenshot_requested: false,
            screenshot_written: false,
            screenshot_ready_at: None,
        }))
    }

    pub(crate) fn process_screenshot(&mut self, context: &egui::Context) -> Result<bool> {
        let screenshot = context.input(|input| {
            input.events.iter().find_map(|event| {
                let egui::Event::Screenshot {
                    user_data, image, ..
                } = event
                else {
                    return None;
                };
                let marker = user_data
                    .data
                    .as_ref()
                    .and_then(|value| value.downcast_ref::<&'static str>());
                (marker.copied() == Some(SCREENSHOT_MARKER)).then(|| image.clone())
            })
        });
        if let Some(image) = screenshot {
            let output = self
                .screenshot_output
                .as_ref()
                .context("desktop acceptance screenshot output is unavailable")?;
            write_new_png(output, &image)?;
            self.screenshot_written = true;
        }
        if self.screenshot_output.is_none() || self.screenshot_written {
            return Ok(false);
        }
        if self.rendered.is_empty() {
            self.screenshot_ready_at = None;
            return Ok(false);
        }
        let ready_at = self.screenshot_ready_at.get_or_insert_with(Instant::now);
        if ready_at.elapsed() < Duration::from_secs(1) {
            context.request_repaint_after(Duration::from_millis(50));
            return Ok(true);
        }
        if !self.screenshot_requested {
            context.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::new(
                SCREENSHOT_MARKER,
            )));
            self.screenshot_requested = true;
        }
        context.request_repaint();
        Ok(true)
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

fn optional_new_absolute_path(variable: &str) -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(None);
    };
    let requested = PathBuf::from(value);
    if !requested.is_absolute() {
        bail!("{variable} must be an absolute path");
    }
    if requested.exists() {
        bail!("{variable} must not already exist");
    }
    let parent = requested
        .parent()
        .context("desktop acceptance screenshot has no parent directory")?
        .canonicalize()
        .with_context(|| {
            format!(
                "desktop acceptance screenshot parent is unavailable: {}",
                requested.display()
            )
        })?;
    let name = requested
        .file_name()
        .context("desktop acceptance screenshot has no file name")?;
    Ok(Some(parent.join(name)))
}

fn write_new_png(path: &Path, image: &egui::ColorImage) -> Result<()> {
    use image::ImageEncoder as _;

    let width = u32::try_from(image.size[0]).context("screenshot width is too large")?;
    let height = u32::try_from(image.size[1]).context("screenshot height is too large")?;
    let mut rgba = Vec::with_capacity(image.pixels.len().saturating_mul(4));
    for pixel in &image.pixels {
        rgba.extend_from_slice(&pixel.to_array());
    }
    let mut encoded = Vec::new();
    image::codecs::png::PngEncoder::new(&mut encoded).write_image(
        &rgba,
        width,
        height,
        image::ExtendedColorType::Rgba8,
    )?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create desktop screenshot: {}", path.display()))?;
    file.write_all(&encoded)?;
    file.sync_all()?;
    Ok(())
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
            screenshot_output: None,
            screenshot_requested: false,
            screenshot_written: false,
            screenshot_ready_at: None,
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
