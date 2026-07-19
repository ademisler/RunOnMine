use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use command_group::AsyncCommandGroup;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let cap = request.max_output_bytes.saturating_add(1) as u64;
    let stdout_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stdout
            .take(cap)
            .read_to_end(&mut output)
            .await
            .map(|_| output)
    });
    let stderr_task = tokio::spawn(async move {
        let mut output = Vec::new();
        stderr
            .take(cap)
            .read_to_end(&mut output)
            .await
            .map(|_| output)
    });

    let (status, timed_out) =
        if let Ok(result) = tokio::time::timeout(request.timeout, child.wait()).await {
            (Some(result?), false)
        } else {
            let _result = child.kill().await;
            let status = child.wait().await.ok();
            (status, true)
        };

    let mut stdout = stdout_task.await.context("stdout task failed")??;
    let mut stderr = stderr_task.await.context("stderr task failed")??;
    let truncated =
        stdout.len() > request.max_output_bytes || stderr.len() > request.max_output_bytes;
    stdout.truncate(request.max_output_bytes);
    stderr.truncate(request.max_output_bytes);

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
        let result = execute_shell(&ProcessRequest {
            command: "printf hello".to_owned(),
            cwd: None,
            timeout: Duration::from_secs(5),
            max_output_bytes: 1_024,
        })
        .await?;
        assert_eq!(result.stdout, "hello");
        assert_eq!(result.exit_code, Some(0));
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
