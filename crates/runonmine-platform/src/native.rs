//! Bounded adapters for the platform-native MCP tools.

use std::io;
use std::path::Path;
#[cfg(any(target_os = "linux", windows))]
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use command_group::AsyncCommandGroup as _;
use serde::Serialize;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::process::Command;

const MAX_SCRIPT_BYTES: usize = 256 * 1024;
#[cfg(target_os = "linux")]
const MAX_ARGUMENTS: usize = 64;

#[derive(Clone, Debug, Serialize)]
pub struct NativeCommandOutput {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
}

#[must_use]
pub fn applescript_available() -> bool {
    cfg!(target_os = "macos") && Path::new("/usr/bin/osascript").is_file()
}

#[must_use]
pub fn powershell_available() -> bool {
    #[cfg(windows)]
    {
        powershell_path().is_ok_and(|path| path.is_file())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[must_use]
pub fn dbus_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() && busctl_path().is_some()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub async fn run_applescript(
    script: &str,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<NativeCommandOutput> {
    #[cfg(target_os = "macos")]
    {
        validate_script(script)?;
        run_bounded(
            Path::new("/usr/bin/osascript"),
            &["-".to_owned()],
            script.as_bytes(),
            timeout,
            max_output_bytes,
            &[],
        )
        .await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (script, timeout, max_output_bytes);
        bail!("AppleScript is only available on macOS")
    }
}

#[allow(clippy::unused_async)]
pub async fn run_powershell(
    script: &str,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<NativeCommandOutput> {
    #[cfg(windows)]
    {
        validate_script(script)?;
        let program = powershell_path()?;
        let system_root = program
            .ancestors()
            .nth(4)
            .context("PowerShell path is invalid")?
            .as_os_str()
            .to_owned();
        run_bounded(
            &program,
            &[
                "-NoLogo".to_owned(),
                "-NoProfile".to_owned(),
                "-NonInteractive".to_owned(),
                "-ExecutionPolicy".to_owned(),
                "Bypass".to_owned(),
                "-Command".to_owned(),
                "-".to_owned(),
            ],
            script.as_bytes(),
            timeout,
            max_output_bytes,
            &[("SystemRoot", system_root)],
        )
        .await
    }
    #[cfg(not(windows))]
    {
        let _ = (script, timeout, max_output_bytes);
        bail!("PowerShell is only available on Windows")
    }
}

#[derive(Clone, Debug)]
pub struct DbusCall<'a> {
    pub destination: &'a str,
    pub object_path: &'a str,
    pub interface: &'a str,
    pub method: &'a str,
    pub signature: &'a str,
    pub arguments: &'a [String],
}

#[allow(clippy::unused_async)]
pub async fn run_dbus_call(
    call: &DbusCall<'_>,
    timeout: Duration,
    max_output_bytes: usize,
) -> Result<NativeCommandOutput> {
    #[cfg(target_os = "linux")]
    {
        validate_dbus_call(call)?;
        let program = busctl_path().context("busctl is not installed")?;
        let mut arguments = vec![
            "--user".to_owned(),
            "--no-pager".to_owned(),
            "call".to_owned(),
            call.destination.to_owned(),
            call.object_path.to_owned(),
            call.interface.to_owned(),
            call.method.to_owned(),
        ];
        if !call.signature.is_empty() {
            arguments.push(call.signature.to_owned());
            arguments.extend(call.arguments.iter().cloned());
        }
        let mut environment = Vec::new();
        if let Some(value) = std::env::var_os("DBUS_SESSION_BUS_ADDRESS") {
            environment.push(("DBUS_SESSION_BUS_ADDRESS", value));
        }
        if let Some(value) = std::env::var_os("XDG_RUNTIME_DIR") {
            environment.push(("XDG_RUNTIME_DIR", value));
        }
        run_bounded(
            &program,
            &arguments,
            &[],
            timeout,
            max_output_bytes,
            &environment,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (call, timeout, max_output_bytes);
        bail!("D-Bus calls are only available on Linux")
    }
}

fn validate_script(script: &str) -> Result<()> {
    if script.is_empty() || script.len() > MAX_SCRIPT_BYTES || script.contains('\0') {
        bail!("platform script is outside the supported size limit");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_dbus_call(call: &DbusCall<'_>) -> Result<()> {
    if !valid_bus_name(call.destination)
        || !valid_object_path(call.object_path)
        || !valid_dotted_name(call.interface)
        || !valid_member(call.method)
        || call.signature.len() > 128
        || !call
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'(' | b')' | b'{' | b'}'))
        || call.arguments.len() > MAX_ARGUMENTS
        || call
            .arguments
            .iter()
            .any(|argument| argument.len() > 8 * 1024 || argument.contains('\0'))
        || (call.signature.is_empty() && !call.arguments.is_empty())
    {
        bail!("D-Bus call arguments are invalid");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn valid_bus_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.contains('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

#[cfg(target_os = "linux")]
fn valid_object_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.starts_with('/')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/'))
}

#[cfg(target_os = "linux")]
fn valid_dotted_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value.contains('.')
        && value.split('.').all(|part| valid_identifier(part, false))
}

#[cfg(target_os = "linux")]
fn valid_member(value: &str) -> bool {
    valid_identifier(value, false)
}

#[cfg(target_os = "linux")]
fn valid_identifier(value: &str, allow_hyphen: bool) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'_' || (allow_hyphen && byte == b'-')
        })
}

#[cfg(windows)]
fn powershell_path() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .context("SystemRoot is unavailable")?;
    Ok(root.join("System32/WindowsPowerShell/v1.0/powershell.exe"))
}

#[cfg(target_os = "linux")]
fn busctl_path() -> Option<PathBuf> {
    ["/usr/bin/busctl", "/bin/busctl"]
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
}

async fn run_bounded(
    program: &Path,
    arguments: &[String],
    input: &[u8],
    timeout: Duration,
    max_output_bytes: usize,
    environment: &[(&str, std::ffi::OsString)],
) -> Result<NativeCommandOutput> {
    if !program.is_absolute() || !program.is_file() {
        bail!("platform executable is unavailable");
    }
    let metadata = std::fs::symlink_metadata(program)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("platform executable must be a regular, non-symlink file");
    }
    let timeout = timeout.clamp(Duration::from_secs(1), Duration::from_mins(5));
    let max_output_bytes = max_output_bytes.clamp(1_024, 8 * 1024 * 1024);
    let mut command = Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.group_spawn()?;
    let mut stdin = child
        .inner()
        .stdin
        .take()
        .context("platform stdin missing")?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .context("platform stdout missing")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .context("platform stderr missing")?;
    let input = input.to_vec();
    let stdin_task = tokio::spawn(async move {
        stdin.write_all(&input).await?;
        stdin.shutdown().await
    });
    let capture_limit = u64::try_from(max_output_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let stdout_task = tokio::spawn(read_limited(stdout, capture_limit));
    let stderr_task = tokio::spawn(read_limited(stderr, capture_limit));
    let (status, timed_out) = if let Ok(status) = tokio::time::timeout(timeout, child.wait()).await
    {
        (Some(status?), false)
    } else {
        let _ignored = child.kill().await;
        (child.wait().await.ok(), true)
    };
    match stdin_task.await.context("platform stdin task failed")? {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {}
        Err(error) => return Err(error).context("failed to write platform stdin"),
    }
    let mut stdout = stdout_task.await.context("platform stdout task failed")??;
    let mut stderr = stderr_task.await.context("platform stderr task failed")??;
    let truncated = stdout.len() > max_output_bytes || stderr.len() > max_output_bytes;
    stdout.truncate(max_output_bytes);
    stderr.truncate(max_output_bytes);
    Ok(NativeCommandOutput {
        exit_code: status.and_then(|status| status.code()),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated,
        timed_out,
    })
}

async fn read_limited<R>(reader: R, limit: u64) -> io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader.take(limit).read_to_end(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_limits_reject_empty_and_nul() {
        assert!(validate_script("").is_err());
        assert!(validate_script("hello\0world").is_err());
        assert!(validate_script("return 1").is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dbus_identifiers_are_strict() {
        assert!(valid_bus_name("org.freedesktop.DBus"));
        assert!(!valid_bus_name("org/freedesktop/DBus"));
        assert!(valid_object_path("/org/freedesktop/DBus"));
        assert!(!valid_object_path("org/freedesktop/DBus"));
        assert!(valid_dotted_name("org.freedesktop.DBus"));
        assert!(valid_member("ListNames"));
        assert!(!valid_member("List.Names"));
    }
}
