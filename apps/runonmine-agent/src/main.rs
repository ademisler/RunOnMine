use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::MakeWriter;

const SERVICE_STDERR_LOG_ENV: &str = "RUNONMINE_SERVICE_STDERR_LOG";
const SERVICE_STDERR_LOG_LIMIT_BYTES: u64 = 5 * 1_024 * 1_024;

#[derive(Clone, Debug)]
struct ServiceStderrWriter {
    path: Option<PathBuf>,
}

impl ServiceStderrWriter {
    fn discover() -> Result<Self> {
        let Some(raw_path) = std::env::var_os(SERVICE_STDERR_LOG_ENV) else {
            return Ok(Self { path: None });
        };
        let paths = runonmine_core::AppPaths::discover()?;
        paths.ensure()?;
        let expected = paths.log_dir.join("agent.stderr.log");
        let configured = PathBuf::from(raw_path);
        if configured != expected {
            bail!("service stderr log path does not match the RunOnMine log directory");
        }
        ensure_bounded_log_file(&configured)?;
        Ok(Self {
            path: Some(configured),
        })
    }
}

struct ServiceStderrGuard {
    stderr: io::Stderr,
    path: Option<PathBuf>,
}

impl Write for ServiceStderrGuard {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if let Some(path) = &self.path {
            truncate_log_before_write(path, buffer.len() as u64).map_err(io::Error::other)?;
        }
        self.stderr.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stderr.flush()
    }
}

impl<'writer> MakeWriter<'writer> for ServiceStderrWriter {
    type Writer = ServiceStderrGuard;

    fn make_writer(&'writer self) -> Self::Writer {
        ServiceStderrGuard {
            stderr: io::stderr(),
            path: self.path.clone(),
        }
    }
}

fn ensure_bounded_log_file(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)?;
            file.sync_all()?;
            fs::symlink_metadata(path)?
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("service stderr log must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn truncate_log_before_write(path: &Path, incoming_bytes: u64) -> Result<()> {
    ensure_bounded_log_file(path)?;
    let length = fs::metadata(path)?.len();
    if length.saturating_add(incoming_bytes) <= SERVICE_STDERR_LOG_LIMIT_BYTES {
        return Ok(());
    }
    let file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)?;
    file.sync_all()
        .context("failed to truncate the bounded service log")
}

#[derive(Debug, Parser)]
#[command(name = "runonmine-agent", version, about = "RunOnMine MCP agent")]
struct Cli {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Run the loopback Streamable HTTP agent.
    Run,
    /// Run an MCP connector over standard input/output.
    Stdio {
        #[arg(long)]
        connector: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let service_stderr = ServiceStderrWriter::discover()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(service_stderr)
        .with_ansi(false)
        .init();
    match Cli::parse().command {
        AgentCommand::Run => runonmine_mcp::serve_loopback().await,
        AgentCommand::Stdio { connector } => {
            let paths = runonmine_core::AppPaths::discover()?;
            paths.ensure()?;
            let reconciled = runonmine_mcp::reconcile_pending_connector_removals(&paths)?;
            if reconciled > 0 {
                tracing::info!(reconciled, "completed pending connector removals");
            }
            runonmine_mcp::serve_stdio(&connector).await
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[test]
    fn service_stderr_log_is_truncated_before_exceeding_the_bound() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("agent.stderr.log");
        fs::write(
            &path,
            vec![b'x'; usize::try_from(SERVICE_STDERR_LOG_LIMIT_BYTES)?],
        )?;
        truncate_log_before_write(&path, 1)?;
        assert_eq!(fs::metadata(&path)?.len(), 0);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = directory.path().join("target.log");
            fs::write(&target, b"target")?;
            let link = directory.path().join("link.log");
            symlink(&target, &link)?;
            assert!(truncate_log_before_write(&link, 1).is_err());
            assert_eq!(fs::read(&target)?, b"target");
        }
        Ok(())
    }

    #[test]
    fn stdio_requires_and_preserves_connector_identity() -> Result<()> {
        let cli =
            Cli::try_parse_from(["runonmine-agent", "stdio", "--connector", "connector-123"])?;
        let AgentCommand::Stdio { connector } = cli.command else {
            anyhow::bail!("unexpected run command");
        };
        assert_eq!(connector, "connector-123");
        assert!(Cli::try_parse_from(["runonmine-agent", "stdio"]).is_err());
        Ok(())
    }

    #[test]
    fn run_command_parses_without_extra_arguments() -> Result<()> {
        let cli = Cli::try_parse_from(["runonmine-agent", "run"])?;
        assert!(matches!(cli.command, AgentCommand::Run));
        Ok(())
    }
}
