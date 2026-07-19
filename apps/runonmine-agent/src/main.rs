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
        AgentCommand::Stdio { connector } => runonmine_mcp::serve_stdio(&connector).await,
    }
}
