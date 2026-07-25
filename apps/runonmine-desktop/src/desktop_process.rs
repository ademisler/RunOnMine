use std::io::{Read, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use command_group::{CommandGroup as _, GroupChild};

const MAX_COMMAND_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_SECRET_INPUT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_DURATION: Duration = Duration::from_mins(5);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct BackgroundCliTask {
    result: Receiver<std::result::Result<String, String>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BackgroundCliTask {
    pub(crate) fn spawn(cli: PathBuf, arguments: Vec<String>, secret: Option<String>) -> Self {
        let (sender, result) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let thread = std::thread::spawn(move || {
            let outcome = run_cli_cancellable(&cli, &arguments, secret.as_deref(), &worker_cancel)
                .map_err(|error| error.to_string());
            let _ignored = sender.send(outcome);
        });
        Self {
            result,
            cancel,
            thread: Some(thread),
        }
    }

    pub(crate) fn try_take(&mut self) -> Option<std::result::Result<String, String>> {
        match self.result.try_recv() {
            Ok(result) => {
                self.join();
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.join();
                Some(Err("background CLI task stopped unexpectedly".to_owned()))
            }
        }
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ignored = thread.join();
        }
    }
}

impl Drop for BackgroundCliTask {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        self.join();
    }
}

pub(crate) fn run_cli(cli: &Path, arguments: &[String], secret: Option<&str>) -> Result<String> {
    run_cli_cancellable(cli, arguments, secret, &AtomicBool::new(false))
}

fn run_cli_cancellable(
    cli: &Path,
    arguments: &[String],
    secret: Option<&str>,
    cancel: &AtomicBool,
) -> Result<String> {
    if secret.is_some_and(|value| value.len() > MAX_SECRET_INPUT_BYTES) {
        bail!("connector secret input exceeds the size limit");
    }
    let mut command = Command::new(cli);
    command
        .args(arguments)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if secret.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.group_spawn()?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .context("failed to capture CLI output")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .context("failed to capture CLI errors")?;
    let stdout_reader = std::thread::spawn(move || read_bounded(stdout));
    let stderr_reader = std::thread::spawn(move || read_bounded(stderr));
    if let Some(secret) = secret {
        let mut stdin = child
            .inner()
            .stdin
            .take()
            .context("failed to open connector command input")?;
        stdin.write_all(secret.as_bytes())?;
        stdin.write_all(b"\n")?;
    }

    let started = Instant::now();
    let termination = loop {
        if cancel.load(Ordering::Acquire) {
            terminate_child(&mut child)?;
            break Termination::Canceled;
        }
        if started.elapsed() >= MAX_COMMAND_DURATION {
            terminate_child(&mut child)?;
            break Termination::TimedOut;
        }
        if let Some(status) = child.try_wait()? {
            break Termination::Exited(status);
        }
        std::thread::sleep(PROCESS_POLL_INTERVAL);
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| anyhow::anyhow!("CLI output reader panicked"))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("CLI error reader panicked"))??;
    let mut output = String::from_utf8_lossy(&stdout.bytes).into_owned();
    if !stderr.bytes.is_empty() {
        if !output.is_empty() && !output.ends_with('\n') {
            output.push('\n');
        }
        output.push_str(&String::from_utf8_lossy(&stderr.bytes));
    }
    if stdout.truncated || stderr.truncated {
        output.push_str("\n[output truncated by RunOnMine Desktop]");
    }
    let output = sanitize_output(&output, secret);
    match termination {
        Termination::Exited(status) if status.success() => Ok(output),
        Termination::Exited(_) => bail!("{output}"),
        Termination::Canceled => bail!("desktop CLI operation was canceled"),
        Termination::TimedOut => bail!("desktop CLI operation timed out\n{output}"),
    }
}

fn terminate_child(child: &mut GroupChild) -> Result<()> {
    match child.kill() {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {}
        Err(error) => return Err(error.into()),
    }
    let _status = child.wait()?;
    Ok(())
}

enum Termination {
    Exited(ExitStatus),
    Canceled,
    TimedOut,
}

struct BoundedBytes {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded(mut reader: impl Read) -> Result<BoundedBytes> {
    let mut bytes = Vec::with_capacity(MAX_COMMAND_OUTPUT_BYTES.min(8 * 1024));
    let mut truncated = false;
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_COMMAND_OUTPUT_BYTES.saturating_sub(bytes.len());
        let retained = read.min(remaining);
        bytes.extend_from_slice(&buffer[..retained]);
        truncated |= retained < read;
    }
    Ok(BoundedBytes { bytes, truncated })
}

fn sanitize_output<'a>(input: &str, secrets: impl IntoIterator<Item = &'a str>) -> String {
    let mut output = input.to_owned();
    for secret in secrets {
        if !secret.is_empty() {
            output = output.replace(secret, "[REDACTED]");
        }
    }
    output
        .lines()
        .map(redact_sensitive_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_sensitive_line(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let sensitive = [
        "authorization",
        "client_secret",
        "api_key",
        "apikey",
        "password",
        "refresh_token",
        "access_token",
    ]
    .iter()
    .any(|marker| lower.contains(marker));
    if !sensitive {
        return line.to_owned();
    }
    let separator = line.find('=').or_else(|| line.find(':'));
    separator.map_or_else(
        || "[REDACTED SENSITIVE OUTPUT]".to_owned(),
        |index| format!("{}=[REDACTED]", line[..index].trim_end()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_redaction_covers_explicit_and_labeled_secrets() {
        let output = sanitize_output(
            "normal\napi_key=visible\nAuthorization: Bearer token\nexact-value",
            ["exact-value"],
        );
        assert!(output.contains("normal"));
        assert!(!output.contains("visible"));
        assert!(!output.contains("Bearer token"));
        assert!(!output.contains("exact-value"));
    }

    #[test]
    fn bounded_reader_drains_but_retains_only_the_limit() -> Result<()> {
        let input = vec![b'x'; MAX_COMMAND_OUTPUT_BYTES + 512];
        let result = read_bounded(input.as_slice())?;
        assert_eq!(result.bytes.len(), MAX_COMMAND_OUTPUT_BYTES);
        assert!(result.truncated);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn background_task_is_canceled_and_joined_on_drop() -> Result<()> {
        let executable = ["/bin/sleep", "/usr/bin/sleep"]
            .into_iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .context("sleep executable is unavailable")?;
        let task = BackgroundCliTask::spawn(executable, vec!["30".to_owned()], None);
        std::thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        drop(task);
        assert!(started.elapsed() < Duration::from_secs(3));
        Ok(())
    }
}
