use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
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
