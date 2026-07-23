use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;

/// Platform-native locations for non-secret configuration, state, logs, and browser data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    pub data_dir: PathBuf,
    pub log_dir: PathBuf,
}

impl AppPaths {
    /// Resolve paths using the operating system's standard per-user locations.
    pub fn discover() -> Result<Self> {
        let dirs = ProjectDirs::from("dev", "RunOnMine", "RunOnMine")
            .context("the operating system did not provide a user data directory")?;
        Ok(Self {
            config_dir: dirs.config_dir().to_path_buf(),
            state_dir: dirs
                .state_dir()
                .unwrap_or_else(|| dirs.data_local_dir())
                .to_path_buf(),
            data_dir: dirs.data_local_dir().to_path_buf(),
            log_dir: dirs.data_local_dir().join("logs"),
        })
    }

    /// Build deterministic paths for tests and portable development runs.
    pub fn under(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref();
        Self {
            config_dir: root.join("config"),
            state_dir: root.join("state"),
            data_dir: root.join("data"),
            log_dir: root.join("logs"),
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    pub fn state_db(&self) -> PathBuf {
        self.state_dir.join("state.db")
    }

    pub fn browser_profiles(&self) -> PathBuf {
        self.data_dir.join("browser").join("profiles")
    }

    /// Create directories without following a pre-existing symlink.
    pub fn ensure(&self) -> Result<()> {
        for dir in [
            &self.config_dir,
            &self.state_dir,
            &self.data_dir,
            &self.log_dir,
        ] {
            if dir
                .symlink_metadata()
                .is_ok_and(|meta| meta.file_type().is_symlink())
            {
                bail!(
                    "refusing to use symlinked RunOnMine directory: {}",
                    dir.display()
                );
            }
            fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
            restrict_directory(dir)?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed to restrict {}", path.display()))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}
