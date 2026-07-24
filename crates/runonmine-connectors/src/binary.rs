use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use command_group::AsyncCommandGroup;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

const PROBE_OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryKind {
    Cloudflared,
    OpenAiTunnelClient,
}

impl BinaryKind {
    pub fn executable_name(self) -> &'static str {
        match (self, cfg!(windows)) {
            (Self::Cloudflared, true) => "cloudflared.exe",
            (Self::Cloudflared, false) => "cloudflared",
            (Self::OpenAiTunnelClient, true) => "tunnel-client.exe",
            (Self::OpenAiTunnelClient, false) => "tunnel-client",
        }
    }

    fn version_arguments(self) -> &'static [&'static str] {
        match self {
            Self::Cloudflared | Self::OpenAiTunnelClient => &["--version"],
        }
    }
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstalledBinary {
    pub kind: BinaryKind,
    pub path: PathBuf,
}

impl fmt::Debug for InstalledBinary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstalledBinary")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .finish()
    }
}

impl InstalledBinary {
    pub fn from_verified_path(kind: BinaryKind, path: &Path) -> Result<Self> {
        let path = validate_executable(path)?;
        Ok(Self { kind, path })
    }
}

#[derive(Clone, Debug, Default)]
pub struct BinaryDiscovery {
    managed_directories: Vec<PathBuf>,
}

impl BinaryDiscovery {
    pub fn new(managed_directories: Vec<PathBuf>) -> Self {
        Self {
            managed_directories,
        }
    }

    pub fn discover_managed(&self, kind: BinaryKind) -> Result<Option<InstalledBinary>> {
        for directory in &self.managed_directories {
            let candidate = directory.join(kind.executable_name());
            if candidate.exists() {
                return InstalledBinary::from_verified_path(kind, &candidate).map(Some);
            }
        }
        Ok(None)
    }

    /// Discovers a binary in strict priority order: explicit path, `RunOnMine`'s
    /// managed directories, then the current process `PATH`.
    pub fn discover(
        &self,
        kind: BinaryKind,
        explicit_path: Option<&Path>,
    ) -> Result<Option<InstalledBinary>> {
        if let Some(path) = explicit_path {
            return InstalledBinary::from_verified_path(kind, path).map(Some);
        }

        for directory in &self.managed_directories {
            let candidate = directory.join(kind.executable_name());
            if candidate.exists() {
                return InstalledBinary::from_verified_path(kind, &candidate).map(Some);
            }
        }

        let Some(path_value) = std::env::var_os("PATH") else {
            return Ok(None);
        };
        for directory in std::env::split_paths(&path_value) {
            let candidate = directory.join(kind.executable_name());
            if candidate.exists() {
                return InstalledBinary::from_verified_path(kind, &candidate).map(Some);
            }
        }
        Ok(None)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BinaryProbe {
    pub kind: BinaryKind,
    pub version: String,
    pub raw_output: String,
}

impl BinaryProbe {
    pub async fn run(binary: &InstalledBinary, timeout: Duration) -> Result<Self> {
        let capture = run_limited(
            &binary.path,
            binary
                .kind
                .version_arguments()
                .iter()
                .map(OsString::from)
                .collect(),
            &[],
            timeout,
        )
        .await
        .context("binary version probe failed")?;
        if !capture.success {
            bail!("binary version probe returned a non-zero exit status");
        }
        let raw_output = combine_output(&capture.stdout, &capture.stderr);
        let version = extract_version(&raw_output)
            .context("binary version output did not contain a recognizable version")?;
        Ok(Self {
            kind: binary.kind,
            version,
            raw_output,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub binary: BinaryKind,
    pub healthy: bool,
    pub exit_code: Option<i32>,
    pub summary: String,
}

impl DoctorReport {
    pub async fn cloudflared(binary: &InstalledBinary, timeout: Duration) -> Result<Self> {
        if binary.kind != BinaryKind::Cloudflared {
            bail!("cloudflared doctor requires a cloudflared binary");
        }
        // This is an offline executable/configuration sanity check. Tunnel
        // connectivity is checked by the supervisor's readiness endpoint.
        let capture = run_limited(
            &binary.path,
            vec!["tunnel".into(), "--help".into()],
            &[],
            timeout,
        )
        .await?;
        Ok(Self {
            binary: binary.kind,
            healthy: capture.success,
            exit_code: capture.exit_code,
            summary: combine_output(&capture.stdout, &capture.stderr),
        })
    }
}

struct Capture {
    success: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

async fn run_limited(
    executable: &Path,
    arguments: Vec<OsString>,
    environment: &[(OsString, OsString)],
    timeout: Duration,
) -> Result<Capture> {
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .group_spawn()
        .context("failed to start binary probe")?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .context("failed to capture probe stdout")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .context("failed to capture probe stderr")?;

    let stdout_task = tokio::spawn(read_capped(stdout, PROBE_OUTPUT_LIMIT));
    let stderr_task = tokio::spawn(read_capped(stderr, PROBE_OUTPUT_LIMIT));
    let deadline = tokio::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if tokio::time::Instant::now() >= deadline {
            let _ignored = child.start_kill();
            loop {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => tokio::time::sleep(Duration::from_millis(25)).await,
                }
            }
            bail!("binary probe timed out");
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    };
    let stdout = stdout_task.await.context("probe stdout task failed")??;
    let stderr = stderr_task.await.context("probe stderr task failed")??;
    Ok(Capture {
        success: status.success(),
        exit_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

async fn read_capped<R>(reader: R, limit: usize) -> std::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut output = Vec::new();
    reader
        .take(u64::try_from(limit).unwrap_or(u64::MAX))
        .read_to_end(&mut output)
        .await?;
    Ok(output)
}

fn validate_executable(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("binary does not exist: {}", path.display()))?;
    let metadata = std::fs::metadata(&canonical)
        .with_context(|| format!("binary does not exist: {}", path.display()))?;
    if !metadata.is_file() {
        bail!("binary path is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            bail!("binary path is not executable");
        }
    }
    Ok(canonical)
}

fn combine_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim(), stderr.trim()) {
        ("", "") => String::new(),
        (stdout, "") => stdout.to_owned(),
        ("", stderr) => stderr.to_owned(),
        (stdout, stderr) => format!("{stdout}\n{stderr}"),
    }
}

fn extract_version(output: &str) -> Option<String> {
    output.split_whitespace().find_map(|part| {
        let candidate = part
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '.')
            .trim_start_matches('v');
        let mut pieces = candidate.split('.');
        let major = pieces.next()?;
        let minor = pieces.next()?;
        if major.chars().all(|character| character.is_ascii_digit())
            && minor.chars().all(|character| character.is_ascii_digit())
        {
            Some(candidate.to_owned())
        } else {
            None
        }
    })
}

pub(crate) fn validate_profile(profile: &str) -> Result<()> {
    if profile.is_empty()
        || profile.len() > 64
        || !profile
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("profile must contain 1-64 ASCII letters, digits, dashes, or underscores");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parser_accepts_semver_and_date_versions() {
        assert_eq!(
            extract_version("cloudflared version 2026.7.2 (built 2026-07-15)"),
            Some("2026.7.2".to_owned())
        );
        assert_eq!(
            extract_version("tunnel-client v0.0.10"),
            Some("0.0.10".to_owned())
        );
    }

    #[test]
    fn profile_validation_rejects_option_injection() {
        assert!(validate_profile("local-stdio").is_ok());
        assert!(validate_profile("--help value").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn executable_symlink_is_resolved_to_a_pinned_target() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target");
        std::fs::write(&target, b"not executed")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
        let link = directory.path().join("link");
        symlink(&target, &link)?;
        let installed = InstalledBinary::from_verified_path(BinaryKind::Cloudflared, &link)?;
        assert_eq!(installed.path, target.canonicalize()?);
        Ok(())
    }
}
