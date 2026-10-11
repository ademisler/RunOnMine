use std::fs::OpenOptions;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use eframe::egui;
use serde::Serialize;

const REPORT_ENV: &str = "RUNONMINE_DESKTOP_LIFECYCLE_REPORT";
const READY_ENV: &str = "RUNONMINE_DESKTOP_LIFECYCLE_READY";
const START_DELAY: Duration = Duration::from_secs(1);
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleState {
    Waiting,
    CloseRequested,
    Hidden,
    Restored,
    Reported,
}

pub(crate) struct DesktopLifecycleAcceptance {
    report: PathBuf,
    ready: PathBuf,
    started_at: Instant,
    state: LifecycleState,
}

#[derive(Serialize)]
struct DesktopLifecycleReport {
    schema_version: u32,
    platform: &'static str,
    architecture: &'static str,
    native_shell_available: bool,
    close_request_intercepted: bool,
    restored_by_second_instance: bool,
    single_instance_transport: &'static str,
}

impl DesktopLifecycleAcceptance {
    pub(crate) fn from_environment() -> Result<Option<Self>> {
        let Some(report) = optional_new_absolute_path(REPORT_ENV)? else {
            if std::env::var_os(READY_ENV).is_some() {
                bail!("{READY_ENV} requires {REPORT_ENV}");
            }
            return Ok(None);
        };
        let ready = optional_new_absolute_path(READY_ENV)?
            .context("desktop lifecycle acceptance requires a ready output path")?;
        if report == ready {
            bail!("desktop lifecycle report and ready paths must be different");
        }
        Ok(Some(Self {
            report,
            ready,
            started_at: Instant::now(),
            state: LifecycleState::Waiting,
        }))
    }

    pub(crate) fn process(
        &mut self,
        context: &egui::Context,
        native_shell_available: bool,
    ) -> Result<bool> {
        if self.started_at.elapsed() >= TIMEOUT && self.state != LifecycleState::Reported {
            bail!("desktop lifecycle acceptance timed out");
        }
        match self.state {
            LifecycleState::Waiting if self.started_at.elapsed() >= START_DELAY => {
                if !native_shell_available {
                    bail!("desktop lifecycle acceptance requires the native menu-bar shell");
                }
                context.send_viewport_cmd(egui::ViewportCommand::Close);
                self.state = LifecycleState::CloseRequested;
                context.request_repaint();
            }
            LifecycleState::Restored => {
                write_new_json(
                    &self.report,
                    &DesktopLifecycleReport {
                        schema_version: 1,
                        platform: std::env::consts::OS,
                        architecture: std::env::consts::ARCH,
                        native_shell_available,
                        close_request_intercepted: true,
                        restored_by_second_instance: true,
                        single_instance_transport: if cfg!(windows) {
                            "named-pipe"
                        } else {
                            "owner-private-unix-socket"
                        },
                    },
                )?;
                self.state = LifecycleState::Reported;
                return Ok(true);
            }
            LifecycleState::Waiting
            | LifecycleState::CloseRequested
            | LifecycleState::Hidden
            | LifecycleState::Reported => {}
        }
        context.request_repaint_after(Duration::from_millis(50));
        Ok(false)
    }

    pub(crate) fn mark_close_intercepted(&mut self) -> Result<()> {
        if self.state != LifecycleState::CloseRequested {
            bail!("desktop close was intercepted in an unexpected lifecycle state");
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.ready)
            .with_context(|| {
                format!(
                    "could not create desktop lifecycle ready marker: {}",
                    self.ready.display()
                )
            })?;
        file.write_all(b"hidden\n")?;
        file.sync_all()?;
        self.state = LifecycleState::Hidden;
        Ok(())
    }

    pub(crate) fn mark_restored_by_instance(&mut self) -> Result<()> {
        if self.state != LifecycleState::Hidden {
            bail!("desktop instance restore arrived before close-to-menu-bar completed");
        }
        self.state = LifecycleState::Restored;
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
        .context("desktop lifecycle acceptance output has no parent directory")?
        .canonicalize()
        .with_context(|| {
            format!(
                "desktop lifecycle acceptance parent is unavailable: {}",
                requested.display()
            )
        })?;
    let name = requested
        .file_name()
        .context("desktop lifecycle acceptance output has no file name")?;
    Ok(Some(parent.join(name)))
}

fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("could not create lifecycle report: {}", path.display()))?;
    file.write_all(&encoded)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_and_instance_restore_require_ordered_state() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let mut acceptance = DesktopLifecycleAcceptance {
            report: temporary.path().join("report.json"),
            ready: temporary.path().join("ready"),
            started_at: Instant::now(),
            state: LifecycleState::CloseRequested,
        };
        acceptance.mark_close_intercepted()?;
        assert_eq!(acceptance.state, LifecycleState::Hidden);
        assert_eq!(std::fs::read_to_string(&acceptance.ready)?, "hidden\n");
        acceptance.mark_restored_by_instance()?;
        assert_eq!(acceptance.state, LifecycleState::Restored);
        Ok(())
    }

    #[test]
    fn restore_before_hidden_is_rejected() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let mut acceptance = DesktopLifecycleAcceptance {
            report: temporary.path().join("report.json"),
            ready: temporary.path().join("ready"),
            started_at: Instant::now(),
            state: LifecycleState::Waiting,
        };
        assert!(acceptance.mark_restored_by_instance().is_err());
        Ok(())
    }
}
