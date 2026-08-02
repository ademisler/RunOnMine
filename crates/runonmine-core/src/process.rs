use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use command_group::AsyncCommandGroup;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessRequest {
    pub command: String,
    pub cwd: Option<PathBuf>,
    pub timeout: Duration,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessResult {
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub timed_out: bool,
    pub duration_ms: u64,
}

pub async fn execute_shell(request: &ProcessRequest) -> Result<ProcessResult> {
    if request.command.trim().is_empty() {
        bail!("command must not be empty");
    }
    if request.max_output_bytes < 1_024 {
        bail!("max output must be at least 1024 bytes");
    }
    let (program, args) = shell_command(&request.command);
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_safe_environment(&mut command);
    if let Some(cwd) = &request.cwd {
        command.current_dir(cwd);
    }
    let started = Instant::now();
    let mut child = command.group_spawn().context("failed to start shell")?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .context("failed to capture stdout")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .context("failed to capture stderr")?;
    let output_budget = Arc::new(SharedOutputBudget::new(request.max_output_bytes));
    let stdout_task = tokio::spawn(read_with_shared_budget(stdout, Arc::clone(&output_budget)));
    let stderr_task = tokio::spawn(read_with_shared_budget(stderr, Arc::clone(&output_budget)));

    let (status, timed_out) =
        if let Ok(result) = tokio::time::timeout(request.timeout, child.wait()).await {
            (Some(result?), false)
        } else {
            let _result = child.kill().await;
            let status = child.wait().await.ok();
            (status, true)
        };

    let stdout = stdout_task.await.context("stdout task failed")??;
    let stderr = stderr_task.await.context("stderr task failed")??;
    let truncated = output_budget.truncated();

    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status
            .as_ref()
            .and_then(std::process::ExitStatus::signal)
            .map(|value| value.to_string())
    };
    #[cfg(not(unix))]
    let signal = None;

    Ok(ProcessResult {
        exit_code: status.and_then(|value| value.code()),
        signal,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated,
        timed_out,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

#[derive(Debug)]
struct SharedOutputBudget {
    remaining: AtomicUsize,
    truncated: AtomicBool,
}

impl SharedOutputBudget {
    const fn new(maximum: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(maximum),
            truncated: AtomicBool::new(false),
        }
    }

    fn reserve(&self, requested: usize) -> usize {
        let mut remaining = self.remaining.load(Ordering::Acquire);
        loop {
            if remaining == 0 {
                self.truncated.store(true, Ordering::Release);
                return 0;
            }
            let accepted = requested.min(remaining);
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - accepted,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    if accepted < requested {
                        self.truncated.store(true, Ordering::Release);
                    }
                    return accepted;
                }
                Err(actual) => remaining = actual,
            }
        }
    }

    fn truncated(&self) -> bool {
        self.truncated.load(Ordering::Acquire)
    }
}

async fn read_with_shared_budget<R>(
    mut reader: R,
    budget: Arc<SharedOutputBudget>,
) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        let accepted = budget.reserve(count);
        output.extend_from_slice(&buffer[..accepted]);
    }
    Ok(output)
}

fn configure_safe_environment(command: &mut Command) {
    #[cfg(windows)]
    command.env("PATH", r"C:\Windows\System32;C:\Windows");
    #[cfg(target_os = "macos")]
    command.env(
        "PATH",
        "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    );
    #[cfg(all(unix, not(target_os = "macos")))]
    command.env("PATH", "/usr/local/bin:/usr/bin:/bin");

    command.env("LANG", "C.UTF-8");
    command.env("LC_ALL", "C.UTF-8");
    for name in [
        "HOME",
        "USERPROFILE",
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn shell_command(command: &str) -> (&'static str, Vec<&str>) {
    #[cfg(windows)]
    {
        (
            "powershell.exe",
            vec!["-NoLogo", "-NonInteractive", "-Command", command],
        )
    }
    #[cfg(target_os = "macos")]
    {
        ("/bin/zsh", vec!["-c", command])
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        ("/bin/sh", vec!["-c", command])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_output() -> Result<()> {
        #[cfg(windows)]
        let command = "[Console]::Out.Write('hello')";
        #[cfg(not(windows))]
        let command = "printf hello";
        let result = execute_shell(&ProcessRequest {
            command: command.to_owned(),
            cwd: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1_024,
        })
        .await?;
        assert_eq!(result.stdout, "hello");
        assert_eq!(result.exit_code, Some(0));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stdout_and_stderr_share_one_output_budget() -> Result<()> {
        let result = execute_shell(&ProcessRequest {
            command: "printf '%0800d' 0; printf '%0800d' 0 >&2".to_owned(),
            cwd: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1_024,
        })
        .await?;
        assert!(result.truncated);
        assert!(result.stdout.len() + result.stderr.len() <= 1_024);
        Ok(())
    }

    #[tokio::test]
    async fn output_below_the_combined_budget_is_not_truncated() -> Result<()> {
        #[cfg(windows)]
        let command = "Write-Output 'out'; [Console]::Error.Write('err')";
        #[cfg(not(windows))]
        let command = "printf out; printf err >&2";
        let result = execute_shell(&ProcessRequest {
            command: command.to_owned(),
            cwd: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1_024,
        })
        .await?;
        assert_eq!(result.stdout.trim(), "out");
        assert_eq!(result.stderr, "err");
        assert!(!result.truncated);
        Ok(())
    }

    #[tokio::test]
    async fn does_not_inherit_unapproved_environment_variables() -> Result<()> {
        let allowed = [
            "HOME",
            "USERPROFILE",
            "SystemRoot",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "PATH",
            "LANG",
            "LC_ALL",
        ];
        let (variable_name, _) = std::env::vars_os()
            .filter_map(|(name, value)| Some((name.into_string().ok()?, value)))
            .map(|(name, value)| (name, value.to_string_lossy().into_owned()))
            .find(|(name, value)| {
                !value.is_empty()
                    && !allowed.contains(&name.as_str())
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
            .context("test process has no non-allowlisted environment variable")?;
        #[cfg(windows)]
        let command =
            format!("if ($env:{variable_name}) {{ $env:{variable_name} }} else {{ 'missing' }}");
        #[cfg(not(windows))]
        let command = format!(r#"printf %s "${{{variable_name}-missing}}""#);
        let result = execute_shell(&ProcessRequest {
            command,
            cwd: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1_024,
        })
        .await?;
        assert_eq!(result.stdout.trim(), "missing");
        Ok(())
    }

    #[tokio::test]
    async fn times_out() -> Result<()> {
        let result = execute_shell(&ProcessRequest {
            command: "sleep 5".to_owned(),
            cwd: None,
            timeout: Duration::from_millis(100),
            max_output_bytes: 1_024,
        })
        .await?;
        assert!(result.timed_out);
        Ok(())
    }
}
