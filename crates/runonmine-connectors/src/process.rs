use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use command_group::{AsyncCommandGroup, AsyncGroupChild};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use zeroize::Zeroize;

use crate::output::SharedOutputBudget;

const MAX_SECRET_BYTES: usize = 16 * 1024;
const MAX_PROCESS_VALUE_BYTES: usize = 64 * 1024;
const REDACTED: &[u8] = b"[REDACTED]";
const ONE_SHOT_READ_BYTES: usize = 4 * 1024;

/// A secret kept in memory only for launching a child process.
///
/// The type intentionally does not implement `Clone`, `Display`, `Serialize`, or
/// any method returning `&str` publicly. This makes accidental logging harder.
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() {
            bail!("secret values must not be empty");
        }
        if value.len() > MAX_SECRET_BYTES {
            bail!("secret values exceed the permitted size");
        }
        if value
            .chars()
            .any(|character| matches!(character, '\0' | '\r' | '\n'))
        {
            bail!("secret values must not contain NUL or newline bytes");
        }
        Ok(Self(value))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

impl Drop for SecretValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub enum CommandArg {
    Public(String),
    Secret(SecretValue),
}

impl CommandArg {
    pub fn public(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_process_value(&value, "argument")?;
        Ok(Self::Public(value))
    }

    pub fn secret(value: SecretValue) -> Self {
        Self::Secret(value)
    }

    pub(crate) fn expose(&self) -> &str {
        match self {
            Self::Public(value) => value,
            Self::Secret(value) => value.expose(),
        }
    }
}

impl fmt::Debug for CommandArg {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public(value) => formatter.debug_tuple("Public").field(value).finish(),
            Self::Secret(_) => formatter.write_str("Secret([REDACTED])"),
        }
    }
}

pub enum EnvironmentValue {
    Public(String),
    Secret(SecretValue),
}

impl EnvironmentValue {
    pub fn public(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_process_value(&value, "environment value")?;
        Ok(Self::Public(value))
    }

    pub fn secret(value: SecretValue) -> Self {
        Self::Secret(value)
    }

    fn expose(&self) -> &str {
        match self {
            Self::Public(value) => value,
            Self::Secret(value) => value.expose(),
        }
    }
}

impl fmt::Debug for EnvironmentValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Public(value) => formatter.debug_tuple("Public").field(value).finish(),
            Self::Secret(_) => formatter.write_str("Secret([REDACTED])"),
        }
    }
}

pub struct CommandSpec {
    pub label: String,
    pub executable: PathBuf,
    pub args: Vec<CommandArg>,
    pub environment: BTreeMap<String, EnvironmentValue>,
    pub current_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OneShotOutput {
    pub success: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub output_truncated: bool,
    pub timed_out: bool,
}

/// Runs a connector command once with process-tree timeout and redacted,
/// bounded output. This is intended for init and doctor commands, not
/// long-lived tunnels.
pub async fn run_once(
    command: CommandSpec,
    timeout: Duration,
    maximum_output_bytes: usize,
) -> Result<OneShotOutput> {
    if timeout.is_zero() || maximum_output_bytes == 0 || maximum_output_bytes > 1024 * 1024 {
        bail!("invalid one-shot connector process limits");
    }
    let redactor = Arc::new(command.redactor());
    let mut child = command.spawn_grouped()?;
    let stdout = child
        .inner()
        .stdout
        .take()
        .context("connector process stdout is unavailable")?;
    let stderr = child
        .inner()
        .stderr
        .take()
        .context("connector process stderr is unavailable")?;
    let output_budget = Arc::new(SharedOutputBudget::new(maximum_output_bytes));
    let stdout_task = tokio::spawn(read_redacted_capped(
        stdout,
        Arc::clone(&redactor),
        Arc::clone(&output_budget),
    ));
    let stderr_task = tokio::spawn(read_redacted_capped(
        stderr,
        redactor,
        Arc::clone(&output_budget),
    ));
    let (status, timed_out) = if let Ok(status) = tokio::time::timeout(timeout, child.wait()).await
    {
        (Some(status?), false)
    } else {
        let _ignored = child.start_kill();
        (child.wait().await.ok(), true)
    };
    let stdout = stdout_task.await.context("stdout reader stopped")??;
    let stderr = stderr_task.await.context("stderr reader stopped")??;
    Ok(OneShotOutput {
        success: status
            .as_ref()
            .is_some_and(std::process::ExitStatus::success)
            && !timed_out,
        exit_code: status.and_then(|value| value.code()),
        stdout,
        stderr,
        output_truncated: output_budget.truncated(),
        timed_out,
    })
}

impl CommandSpec {
    pub fn new(label: impl Into<String>, executable: PathBuf) -> Result<Self> {
        let label = label.into();
        if label.trim().is_empty() {
            bail!("command label must not be empty");
        }
        if !executable.is_absolute() {
            bail!("managed child executable must use an absolute path");
        }
        Ok(Self {
            label,
            executable,
            args: Vec::new(),
            environment: BTreeMap::new(),
            current_dir: None,
        })
    }

    pub fn arg(mut self, value: impl Into<String>) -> Result<Self> {
        self.args.push(CommandArg::public(value)?);
        Ok(self)
    }

    pub fn secret_arg(mut self, value: SecretValue) -> Self {
        self.args.push(CommandArg::secret(value));
        self
    }

    pub fn env(mut self, name: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        let name = name.into();
        validate_environment_name(&name)?;
        self.environment
            .insert(name, EnvironmentValue::public(value)?);
        Ok(self)
    }

    pub fn secret_env(mut self, name: impl Into<String>, value: SecretValue) -> Result<Self> {
        let name = name.into();
        validate_environment_name(&name)?;
        self.environment
            .insert(name, EnvironmentValue::secret(value));
        Ok(self)
    }

    pub fn current_dir(mut self, path: PathBuf) -> Result<Self> {
        if !path.is_absolute() {
            bail!("managed child working directory must use an absolute path");
        }
        self.current_dir = Some(path);
        Ok(self)
    }

    pub fn redacted_command_line(&self) -> Vec<String> {
        let mut values = vec![self.executable.to_string_lossy().into_owned()];
        values.extend(self.args.iter().map(|argument| match argument {
            CommandArg::Public(value) => value.clone(),
            CommandArg::Secret(_) => "[REDACTED]".to_owned(),
        }));
        values
    }

    pub(crate) fn spawn_grouped(&self) -> Result<AsyncGroupChild> {
        let mut command = Command::new(&self.executable);
        command
            .args(self.args.iter().map(CommandArg::expose))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (name, value) in &self.environment {
            command.env(name, value.expose());
        }
        if let Some(path) = &self.current_dir {
            command.current_dir(path);
        }
        Ok(command.group_spawn()?)
    }

    pub(crate) fn redactor(&self) -> Redactor {
        let mut secrets = Vec::new();
        for argument in &self.args {
            if let CommandArg::Secret(value) = argument {
                secrets.push(value.expose().to_owned());
            }
        }
        for value in self.environment.values() {
            if let EnvironmentValue::Secret(value) = value {
                secrets.push(value.expose().to_owned());
            }
        }
        secrets.sort_by_key(|value| std::cmp::Reverse(value.len()));
        secrets.dedup();
        Redactor { secrets }
    }
}

impl fmt::Debug for CommandSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let environment = self
            .environment
            .iter()
            .map(|(name, value)| {
                let value = match value {
                    EnvironmentValue::Public(value) => value.clone(),
                    EnvironmentValue::Secret(_) => "[REDACTED]".to_owned(),
                };
                (name, value)
            })
            .collect::<BTreeMap<_, _>>();
        formatter
            .debug_struct("CommandSpec")
            .field("label", &self.label)
            .field("command", &self.redacted_command_line())
            .field("environment", &environment)
            .field("current_dir", &self.current_dir)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    #[cfg(test)]
    pub(crate) fn redact(&self, input: &str) -> String {
        self.secrets
            .iter()
            .fold(input.to_owned(), |output, secret| {
                output.replace(secret, "[REDACTED]")
            })
    }

    pub(crate) fn overlap_len(&self) -> usize {
        self.secrets
            .iter()
            .map(String::len)
            .max()
            .unwrap_or(1)
            .saturating_sub(1)
    }

    /// Redacts a raw prefix while using the remaining bytes as look-ahead.
    /// The returned consumed count can exceed `safe_prefix` when a secret
    /// crosses the boundary, ensuring that no partial secret is emitted.
    pub(crate) fn redact_prefix(&self, input: &[u8], safe_prefix: usize) -> (String, usize) {
        let safe_prefix = safe_prefix.min(input.len());
        let mut output = Vec::with_capacity(safe_prefix);
        let mut cursor = 0;
        while cursor < safe_prefix {
            let matched = self
                .secrets
                .iter()
                .map(String::as_bytes)
                .find(|secret| input[cursor..].starts_with(secret));
            if let Some(secret) = matched {
                output.extend_from_slice(REDACTED);
                cursor = cursor.saturating_add(secret.len());
            } else {
                output.push(input[cursor]);
                cursor += 1;
            }
        }
        (String::from_utf8_lossy(&output).into_owned(), cursor)
    }
}

impl fmt::Debug for Redactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Redactor")
            .field("secret_count", &self.secrets.len())
            .finish()
    }
}

fn validate_process_value(value: &str, label: &str) -> Result<()> {
    if value.len() > MAX_PROCESS_VALUE_BYTES {
        bail!("{label} exceeds the permitted size");
    }
    if value.contains('\0') {
        bail!("{label} must not contain NUL bytes");
    }
    Ok(())
}

fn validate_environment_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.contains('=')
        || name.contains('\0')
        || !name
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
    {
        bail!("invalid environment variable name");
    }
    Ok(())
}

async fn read_redacted_capped<R>(
    mut reader: R,
    redactor: Arc<Redactor>,
    budget: Arc<SharedOutputBudget>,
) -> std::io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let overlap = redactor.overlap_len();
    let mut pending = Vec::with_capacity(ONE_SHOT_READ_BYTES + overlap);
    let mut output = Vec::new();
    let mut buffer = [0_u8; ONE_SHOT_READ_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            if !pending.is_empty() {
                let pending_len = pending.len();
                let (text, consumed) = redactor.redact_prefix(&pending, pending_len);
                append_shared(&mut output, text.as_bytes(), &budget);
                pending.drain(..consumed);
            }
            break;
        }
        pending.extend_from_slice(&buffer[..read]);
        while pending.len() > ONE_SHOT_READ_BYTES.saturating_add(overlap) {
            let (text, consumed) = redactor.redact_prefix(&pending, ONE_SHOT_READ_BYTES);
            append_shared(&mut output, text.as_bytes(), &budget);
            pending.drain(..consumed);
        }
    }
    Ok(String::from_utf8_lossy(&output).into_owned())
}

fn append_shared(output: &mut Vec<u8>, value: &[u8], budget: &SharedOutputBudget) {
    let accepted = budget.reserve(value.len());
    output.extend_from_slice(&value[..accepted]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_and_command_line_redact_secrets() -> Result<()> {
        let spec = CommandSpec::new("test", PathBuf::from("/bin/test"))?
            .arg("--token")?
            .secret_arg(SecretValue::new("top-secret-token")?)
            .secret_env("API_KEY", SecretValue::new("environment-secret")?)?;
        let debug = format!("{spec:?}");
        assert!(!debug.contains("top-secret-token"));
        assert!(!debug.contains("environment-secret"));
        assert_eq!(
            spec.redacted_command_line(),
            vec!["/bin/test", "--token", "[REDACTED]"]
        );
        Ok(())
    }

    #[test]
    fn output_redactor_handles_overlapping_values() -> Result<()> {
        let spec = CommandSpec::new("test", PathBuf::from("/bin/test"))?
            .secret_arg(SecretValue::new("abc")?)
            .secret_arg(SecretValue::new("abcdef")?);
        assert_eq!(
            spec.redactor().redact("value=abcdef value=abc"),
            "value=[REDACTED] value=[REDACTED]"
        );
        Ok(())
    }

    #[test]
    fn streaming_redactor_hides_secrets_across_chunk_boundaries() -> Result<()> {
        let spec = CommandSpec::new("test", PathBuf::from("/bin/test"))?
            .secret_arg(SecretValue::new("cross-boundary-secret")?);
        let redactor = spec.redactor();
        let input = b"prefix cross-boundary-secret suffix";
        let safe_prefix = b"prefix cross-bound".len();
        let (first, consumed) = redactor.redact_prefix(input, safe_prefix);
        let (second, _) = redactor.redact_prefix(&input[consumed..], input.len() - consumed);
        let output = format!("{first}{second}");
        assert_eq!(output, "prefix [REDACTED] suffix");
        assert!(!output.contains("cross-boundary-secret"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn one_shot_stdout_and_stderr_share_one_budget() -> Result<()> {
        let command = CommandSpec::new("combined output", PathBuf::from("/bin/sh"))?
            .arg("-c")?
            .arg("printf '%0800d' 0; printf '%0800d' 0 >&2")?;
        let output = run_once(command, Duration::from_secs(5), 1_024).await?;
        assert!(output.output_truncated);
        assert!(output.stdout.len() + output.stderr.len() <= 1_024);
        Ok(())
    }

    #[test]
    fn secret_values_reject_process_injection_and_excessive_size() {
        assert!(SecretValue::new("line\nbreak").is_err());
        assert!(SecretValue::new("\0").is_err());
        assert!(SecretValue::new("x".repeat(MAX_SECRET_BYTES + 1)).is_err());
    }
}
