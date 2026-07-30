use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use uuid::Uuid;

pub const AGENT_STATUS_PROTOCOL_VERSION: u16 = 1;
pub const AGENT_PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const AGENT_STATUS_ENV: &str = "RUNONMINE_AGENT_STATUS_FILE";
const AGENT_STATUS_FILE: &str = "agent-runtime.json";
const MAX_AGENT_STATUS_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeStatus {
    pub protocol_version: u16,
    pub package_version: String,
    pub process_id: u32,
    pub executable: PathBuf,
    pub instance_id: Uuid,
    pub started_unix_ms: u64,
}

impl AgentRuntimeStatus {
    pub fn current() -> Result<Self> {
        let executable = std::env::current_exe()
            .context("failed to locate the running agent executable")?
            .canonicalize()
            .context("failed to resolve the running agent executable")?;
        Ok(Self {
            protocol_version: AGENT_STATUS_PROTOCOL_VERSION,
            package_version: AGENT_PACKAGE_VERSION.to_owned(),
            process_id: std::process::id(),
            executable,
            instance_id: Uuid::new_v4(),
            started_unix_ms: unix_milliseconds(SystemTime::now())?,
        })
    }

    fn validate_restart(
        &self,
        expected_executable: &Path,
        not_before_unix_ms: u64,
        previous_instance_id: Option<Uuid>,
    ) -> Result<()> {
        if self.protocol_version != AGENT_STATUS_PROTOCOL_VERSION {
            bail!("running agent protocol version does not match the installer");
        }
        if self.package_version != AGENT_PACKAGE_VERSION {
            bail!("running agent package version does not match the installer");
        }
        if self.process_id == 0 || self.started_unix_ms < not_before_unix_ms {
            bail!("agent runtime marker is stale");
        }
        if previous_instance_id == Some(self.instance_id) {
            bail!("agent service did not publish a new runtime instance");
        }
        let expected = canonical_regular_executable(expected_executable)
            .context("failed to validate the installed agent executable")?;
        let actual = canonical_regular_executable(&self.executable)
            .context("failed to validate the running agent executable identity")?;
        if actual != expected {
            bail!("running agent executable does not match the installed executable");
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct AgentRestartExpectation {
    path: PathBuf,
    expected_executable: PathBuf,
    previous_instance_id: Option<Uuid>,
    not_before_unix_ms: u64,
}

impl AgentRestartExpectation {
    pub fn begin(path: PathBuf, expected_executable: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("agent runtime status path must be absolute");
        }
        let expected_executable = canonical_regular_executable(expected_executable)?;
        let previous_instance_id = read_agent_runtime_status(&path)
            .ok()
            .map(|status| status.instance_id);
        clear_agent_runtime_status(&path)?;
        Ok(Self {
            path,
            expected_executable,
            previous_instance_id,
            not_before_unix_ms: unix_milliseconds(SystemTime::now())?,
        })
    }

    pub fn wait_blocking(&self, timeout: Duration) -> Result<AgentRuntimeStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            let error = match read_agent_runtime_status(&self.path).and_then(|status| {
                status.validate_restart(
                    &self.expected_executable,
                    self.not_before_unix_ms,
                    self.previous_instance_id,
                )?;
                Ok(status)
            }) {
                Ok(status) => return Ok(status),
                Err(error) => error,
            };
            if Instant::now() >= deadline {
                bail!("agent did not publish a fresh matching runtime handshake: {error}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub async fn wait(&self, timeout: Duration) -> Result<AgentRuntimeStatus> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let error = match read_agent_runtime_status(&self.path).and_then(|status| {
                status.validate_restart(
                    &self.expected_executable,
                    self.not_before_unix_ms,
                    self.previous_instance_id,
                )?;
                Ok(status)
            }) {
                Ok(status) => return Ok(status),
                Err(error) => error,
            };
            if tokio::time::Instant::now() >= deadline {
                bail!("agent did not publish a fresh matching runtime handshake: {error}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

#[derive(Debug)]
pub struct AgentRuntimeMarker {
    path: PathBuf,
    status: AgentRuntimeStatus,
}

impl AgentRuntimeMarker {
    pub fn publish() -> Result<Self> {
        Self::publish_to(agent_status_path()?)
    }

    fn publish_to(path: PathBuf) -> Result<Self> {
        let status = AgentRuntimeStatus::current()?;
        write_agent_runtime_status_to(&path, &status)?;
        Ok(Self { path, status })
    }

    pub fn status(&self) -> &AgentRuntimeStatus {
        &self.status
    }
}

impl Drop for AgentRuntimeMarker {
    fn drop(&mut self) {
        let _ignored = clear_agent_runtime_status_for_instance(&self.path, self.status.instance_id);
    }
}

pub fn agent_status_path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(AGENT_STATUS_ENV) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            bail!("agent runtime status path must be absolute");
        }
        return Ok(path);
    }
    let dirs = ProjectDirs::from("dev", "RunOnMine", "RunOnMine")
        .context("the operating system did not provide an agent state directory")?;
    Ok(dirs
        .state_dir()
        .unwrap_or_else(|| dirs.data_local_dir())
        .join(AGENT_STATUS_FILE))
}

pub fn clear_agent_runtime_status(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("agent runtime status path is not a regular file")
        }
        Ok(_) => fs::remove_file(path).context("failed to remove stale agent runtime status"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect agent runtime status"),
    }
}

fn clear_agent_runtime_status_for_instance(path: &Path, instance_id: Uuid) -> Result<()> {
    match read_agent_runtime_status(path) {
        Ok(status) if status.instance_id == instance_id => clear_agent_runtime_status(path),
        Ok(_) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(())
        }
        Err(_) if !path.exists() => Ok(()),
        Err(error) => Err(error).context("failed to inspect agent runtime status during cleanup"),
    }
}

pub fn read_agent_runtime_status(path: &Path) -> Result<AgentRuntimeStatus> {
    let metadata = path
        .symlink_metadata()
        .context("agent runtime status is unavailable")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_AGENT_STATUS_BYTES
    {
        bail!("agent runtime status is not a safe bounded regular file");
    }
    let bytes = fs::read(path).context("failed to read agent runtime status")?;
    serde_json::from_slice(&bytes).context("agent runtime status is invalid")
}

pub fn unix_milliseconds(value: SystemTime) -> Result<u64> {
    u64::try_from(value.duration_since(UNIX_EPOCH)?.as_millis())
        .context("agent runtime timestamp exceeds the supported range")
}

fn canonical_regular_executable(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("agent executable identity must be an absolute path");
    }
    let metadata = path
        .symlink_metadata()
        .context("agent executable identity is unavailable")?;
    if metadata.file_type().is_symlink() {
        let canonical = path
            .canonicalize()
            .context("failed to resolve the agent executable identity")?;
        if !canonical.is_file() {
            bail!("agent executable identity is not a regular file");
        }
        return Ok(canonical);
    }
    if !metadata.is_file() {
        bail!("agent executable identity is not a regular file");
    }
    path.canonicalize()
        .context("failed to resolve the agent executable identity")
}

fn write_agent_runtime_status_to(path: &Path, status: &AgentRuntimeStatus) -> Result<()> {
    let parent = path
        .parent()
        .context("agent runtime status path has no parent directory")?;
    if parent
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("agent runtime status parent must not be a symbolic link");
    }
    fs::create_dir_all(parent)?;
    let parent_metadata = parent.symlink_metadata()?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("agent runtime status parent must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to replace a symlinked agent runtime status");
    }
    let mut temporary = NamedTempFile::new_in(parent)?;
    serde_json::to_writer(temporary.as_file_mut(), status)?;
    temporary.as_file_mut().write_all(b"\n")?;
    restrict_owner_file(temporary.path())?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("failed to publish agent runtime status")?;
    restrict_owner_file(path)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn restrict_owner_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .context("failed to restrict agent runtime status")
}

#[cfg(windows)]
fn restrict_owner_file(path: &Path) -> Result<()> {
    use std::process::Command;

    let identity = Command::new("whoami.exe")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .context("failed to resolve the current Windows user SID")?;
    if !identity.status.success() {
        bail!("failed to resolve the current Windows user SID");
    }
    let output = String::from_utf8_lossy(&identity.stdout);
    let sid = output
        .split([',', '"', '\r', '\n'])
        .map(str::trim)
        .find(|field| field.starts_with("S-1-"))
        .context("the current Windows user SID was not returned")?;
    let grant = format!("*{sid}:F");
    let restricted = Command::new("icacls.exe")
        .args([
            path.to_string_lossy().as_ref(),
            "/inheritance:r",
            "/grant:r",
            &grant,
        ])
        .output()
        .context("failed to restrict agent runtime status ACL")?;
    if !restricted.status.success() {
        bail!("failed to restrict agent runtime status ACL");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn restrict_owner_file(_path: &Path) -> Result<()> {
    bail!("private agent runtime status files are unsupported on this operating system")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_for(executable: &Path, started_unix_ms: u64) -> Result<AgentRuntimeStatus> {
        Ok(AgentRuntimeStatus {
            protocol_version: AGENT_STATUS_PROTOCOL_VERSION,
            package_version: AGENT_PACKAGE_VERSION.to_owned(),
            process_id: 42,
            executable: executable.canonicalize()?,
            instance_id: Uuid::new_v4(),
            started_unix_ms,
        })
    }

    #[test]
    fn runtime_status_rejects_stale_version_instance_time_and_executable() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let expected = directory.path().join("expected-agent");
        let other = directory.path().join("other-agent");
        fs::write(&expected, b"expected")?;
        fs::write(&other, b"other")?;
        let now = unix_milliseconds(SystemTime::now())?;
        let valid = status_for(&expected, now)?;
        valid.validate_restart(&expected, now, None)?;

        let stale = AgentRuntimeStatus {
            started_unix_ms: now.saturating_sub(1),
            ..valid.clone()
        };
        assert!(stale.validate_restart(&expected, now, None).is_err());
        let wrong_version = AgentRuntimeStatus {
            package_version: "stale-version".to_owned(),
            ..valid.clone()
        };
        assert!(
            wrong_version
                .validate_restart(&expected, now, None)
                .is_err()
        );
        let wrong_executable = AgentRuntimeStatus {
            executable: other.canonicalize()?,
            ..valid.clone()
        };
        assert!(
            wrong_executable
                .validate_restart(&expected, now, None)
                .is_err()
        );
        assert!(
            valid
                .validate_restart(&expected, now, Some(valid.instance_id))
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn wait_requires_a_fresh_matching_marker() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let expected = directory.path().join("agent");
        fs::write(&expected, b"agent")?;
        let status_path = directory.path().join("runtime.json");
        let now = unix_milliseconds(SystemTime::now())?;
        let stale = status_for(&expected, now.saturating_sub(1))?;
        write_agent_runtime_status_to(&status_path, &stale)?;
        let expectation = AgentRestartExpectation {
            path: status_path.clone(),
            expected_executable: expected.canonicalize()?,
            previous_instance_id: Some(stale.instance_id),
            not_before_unix_ms: now,
        };
        let publisher_path = status_path;
        let fresh = status_for(&expected, now)?;
        let expected_instance = fresh.instance_id;
        let publisher = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            write_agent_runtime_status_to(&publisher_path, &fresh)
        });
        let status = expectation.wait(Duration::from_secs(1)).await?;
        publisher.await??;
        assert_eq!(status.instance_id, expected_instance);
        Ok(())
    }

    #[test]
    fn marker_cleanup_does_not_delete_a_newer_instance() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("runtime.json");
        let marker = AgentRuntimeMarker::publish_to(path.clone())?;
        let replacement = AgentRuntimeStatus {
            instance_id: Uuid::new_v4(),
            ..marker.status().clone()
        };
        write_agent_runtime_status_to(&path, &replacement)?;
        drop(marker);
        assert_eq!(read_agent_runtime_status(&path)?, replacement);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn marker_is_private_and_symlink_replacement_is_rejected() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let path = directory.path().join("runtime.json");
        let executable = std::env::current_exe()?.canonicalize()?;
        let status = status_for(&executable, unix_milliseconds(SystemTime::now())?)?;
        write_agent_runtime_status_to(&path, &status)?;
        assert_eq!(path.metadata()?.permissions().mode() & 0o777, 0o600);
        fs::remove_file(&path)?;
        let outside = directory.path().join("outside");
        fs::write(&outside, b"outside")?;
        symlink(&outside, &path)?;
        assert!(write_agent_runtime_status_to(&path, &status).is_err());
        assert_eq!(fs::read(outside)?, b"outside");
        Ok(())
    }
}
