use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use base64::Engine;
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use rand::RngCore;
use runonmine_connectors::openai::{OpenAiMcpTarget, OpenAiTunnelProfile};
use runonmine_connectors::{
    BinaryInstaller, BinaryKind, BinaryProbe, ExternalBinaryTrust, GitHubReleaseResolver,
    InstallReceipt, InstalledBinary, ReleaseChannel, ReleaseProvider, SecretValue,
    VersionedBinaryStore, external_binary_pin_store, is_managed_connector_binary,
    managed_binary_store, resolve_connector_binary, run_once,
};
use runonmine_core::secrets::{SecretTransaction, default_secret_store};
use runonmine_core::{
    AppConfig, AppPaths, ApprovalDecision, BrowserProfileMode, Capability, CloudflareNamedSettings,
    CloudflareQuickSettings, ConnectorConfig, ConnectorKind, ConnectorRemovalJournal,
    ConnectorRemovalLock, OAuthOwnerSettings, OpenAiTunnelSettings, PolicyMode, PolicyPreset,
    QuickTunnelRuntimeStore, StateStore, connector_secret_suffixes,
};
use runonmine_mcp::{reconcile_pending_connector_removals, remove_connector_recoverably};
use runonmine_oauth::SqliteOAuthStore;
use runonmine_platform::{
    LinuxSystemService, UserService, current, helper::ProgramProfileDocument,
};
use secrecy::{ExposeSecret, SecretString};
use tracing_subscriber::EnvFilter;
use url::Url;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "runonmine",
    version,
    about = "Let AI work on the machines you own."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Setup(SetupArgs),
    Ui,
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    Connect {
        #[command(subcommand)]
        command: ConnectCommand,
    },
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    Approvals {
        #[command(subcommand)]
        command: ApprovalCommand,
    },
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    Oauth {
        #[command(subcommand)]
        command: OauthCommand,
    },
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Immediately stop access, revoke live sessions, and invalidate temporary credentials.
    Lock(LockArgs),
    /// Remove the per-user service. User data is retained unless purge is explicit.
    Uninstall(UninstallArgs),
    /// Create a bounded, redacted ZIP for troubleshooting.
    SupportBundle(SupportBundleArgs),
    Doctor,
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// Directories that file tools may access. May be repeated.
    #[arg(long = "root", value_name = "DIRECTORY")]
    roots: Vec<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    Run,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    Stdio {
        #[arg(long)]
        connector: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConnectCommand {
    List,
    Show {
        connector: String,
    },
    Enable {
        connector: String,
    },
    Disable {
        connector: String,
    },
    Remove {
        connector: String,
        #[arg(long)]
        confirm: String,
    },
    LocalHttp {
        #[command(subcommand)]
        command: LocalHttpCommand,
    },
    Cloudflare {
        #[command(subcommand)]
        command: CloudflareCommand,
    },
    Openai(OpenAiConnectArgs),

    /// Download, verify and atomically select the latest managed connector binaries.
    UpdateManagedBinaries,

    /// Pin configured external connector binaries to their current path, digest and ownership metadata.
    PinExternalBinaries,
}

#[derive(Debug, Subcommand)]
enum LocalHttpCommand {
    /// Enable authenticated loopback MCP access without printing its bearer token.
    Enable {
        /// Write credentials once to a new owner-only JSON file. The path must be absolute.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        token_output: Option<PathBuf>,
    },
    /// Disable loopback MCP access and delete its bearer token.
    Disable,
    /// Replace the bearer token for the enabled loopback connector without printing it.
    Rotate {
        /// Write credentials once to a new owner-only JSON file. The path must be absolute.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        token_output: Option<PathBuf>,
    },
    /// Show non-secret local HTTP status and optionally export credentials securely.
    Status {
        /// Write current credentials to a new owner-only JSON file. The path must be absolute.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        token_output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum CloudflareCommand {
    Quick {
        /// Rotate the secret path for an existing Quick Tunnel connector.
        #[arg(long)]
        rotate: Option<String>,
        /// Explicit cloudflared binary. Missing binaries are installed from the verified official release.
        #[arg(long)]
        cloudflared: Option<PathBuf>,
    },
    Oauth(CloudflareOAuthArgs),
}

#[derive(Debug, Args)]
struct CloudflareOAuthArgs {
    #[arg(long)]
    hostname: Option<String>,
    #[arg(long)]
    tunnel_id: Option<String>,
    #[arg(long)]
    credentials_file: Option<PathBuf>,
    #[arg(long)]
    github_client_id: Option<String>,
    #[arg(long)]
    github_owner: Option<String>,
    #[arg(long)]
    github_owner_id: Option<u64>,
    #[arg(long)]
    cloudflared: Option<PathBuf>,
    /// Write the initial OAuth registration credential to a new owner-only JSON file.
    #[arg(long, value_name = "ABSOLUTE_FILE")]
    registration_token_output: Option<PathBuf>,
    /// Read the GitHub OAuth client secret from standard input.
    #[arg(long, hide = true)]
    client_secret_stdin: bool,
}

#[derive(Debug, Args)]
struct OpenAiConnectArgs {
    #[arg(long)]
    tunnel_id: Option<String>,
    #[arg(long, default_value = "runonmine")]
    profile: String,
    #[arg(long)]
    tunnel_client: Option<PathBuf>,
    /// Read the `OpenAI` runtime API key from standard input.
    #[arg(long, hide = true)]
    api_key_stdin: bool,
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    Show {
        #[arg(long)]
        connector: Option<String>,
    },
    Preset {
        preset: PresetArg,
        #[arg(long)]
        connector: Option<String>,
    },
    Set {
        connector: String,
        capability: CapabilityArg,
        mode: ModeArg,
    },
}

#[derive(Debug, Subcommand)]
enum ApprovalCommand {
    List,
    Approve(ApproveArgs),
    Deny {
        id: Uuid,
    },
    Grants {
        #[command(subcommand)]
        command: GrantCommand,
    },
}

#[derive(Debug, Subcommand)]
enum GrantCommand {
    List {
        #[arg(long)]
        connector: Option<String>,
    },
    Revoke {
        connector: String,
        #[arg(long)]
        principal_fingerprint: String,
        tool: String,
        argument_hash: String,
    },
    Clear {
        #[arg(long)]
        connector: Option<String>,
        #[arg(long)]
        confirm: String,
    },
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("decision")
        .required(true)
        .multiple(false)
        .args(["once", "duration", "always"])
))]
struct ApproveArgs {
    id: Uuid,
    #[arg(long)]
    once: bool,
    #[arg(long = "for", value_name = "DURATION", value_parser = parse_approval_duration)]
    duration: Option<ApprovalDuration>,
    #[arg(long)]
    always: bool,
}

#[derive(Clone, Copy, Debug)]
enum ApprovalDuration {
    TenMinutes,
}

fn parse_approval_duration(value: &str) -> Result<ApprovalDuration, String> {
    match value {
        "10m" => Ok(ApprovalDuration::TenMinutes),
        _ => Err("the only supported temporary duration is 10m".to_owned()),
    }
}

#[derive(Debug, Subcommand)]
enum BrowserCommand {
    Profile {
        #[command(subcommand)]
        command: BrowserProfileCommand,
    },
    Attach {
        loopback_cdp_url: Url,
    },
    PrivateNetwork {
        #[arg(value_enum)]
        access: PrivateNetworkAccess,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PrivateNetworkAccess {
    Allow,
    Deny,
}

#[derive(Debug, Subcommand)]
enum BrowserProfileCommand {
    /// Create or select a persistent browser profile.
    Create {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Use a disposable browser profile that is removed when the MCP session ends.
    Ephemeral {
        #[arg(long, default_value = "default")]
        name: String,
    },
    /// Delete a persistent profile that is not currently selected.
    Delete { name: String },
}

#[derive(Debug, Subcommand)]
enum OauthCommand {
    Clients {
        #[command(subcommand)]
        command: OauthClientCommand,
    },
    Sessions {
        #[command(subcommand)]
        command: OauthSessionCommand,
    },
    RegistrationToken {
        #[command(subcommand)]
        command: OauthRegistrationTokenCommand,
    },
    /// Remove expired authorization state and tokens.
    Cleanup,
}

#[derive(Debug, Subcommand)]
enum OauthRegistrationTokenCommand {
    /// Export the current initial access token to a new owner-only JSON file.
    Export {
        connector_id: String,
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        output: PathBuf,
    },
    /// Rotate the initial access token and optionally export it securely.
    Rotate {
        connector_id: String,
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum OauthClientCommand {
    List,
    /// Revoke every active token issued to one client.
    Revoke {
        connector_id: String,
        client_id: String,
    },
    /// Delete one registered client and all of its authorization state.
    Delete {
        connector_id: String,
        client_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum OauthSessionCommand {
    List {
        #[arg(long)]
        connector_id: Option<String>,
        #[arg(long)]
        client_id: Option<String>,
    },
    Revoke {
        connector_id: String,
        family_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Install {
        /// Root/SYSTEM-owned executable to permit with no arguments. May be repeated.
        #[arg(long = "allow-program", value_name = "ABSOLUTE_PATH")]
        allowed_programs: Vec<PathBuf>,
        /// Versioned JSON document with executable-specific invocation profiles.
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        profile_file: Option<PathBuf>,
    },
    Uninstall,
    Status,
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    Install(ServiceInstallArgs),
    Uninstall(ServiceScopeArgs),
    Start(ServiceScopeArgs),
    Stop(ServiceScopeArgs),
    Status(ServiceScopeArgs),
}

#[derive(Debug, Args)]
struct ServiceInstallArgs {
    /// Install a headless systemd service instead of a per-user service (Linux only).
    #[arg(long)]
    system: bool,
    /// Existing non-root account used by the Linux system service.
    #[arg(long, value_name = "ACCOUNT", requires = "system")]
    user: Option<String>,
}

#[derive(Clone, Copy, Debug, Args)]
struct ServiceScopeArgs {
    /// Operate on the headless systemd service (Linux only).
    #[arg(long)]
    system: bool,
}

#[derive(Debug, Args)]
struct LockArgs {
    /// Also stop the Linux system service in addition to the current user's service.
    #[arg(long)]
    system: bool,
}

#[derive(Debug, Args)]
struct UninstallArgs {
    /// Also remove configuration, state, browser profiles, logs, and connector secrets.
    #[arg(long)]
    purge: bool,
    /// Required destructive confirmation when --purge is used; value must be PURGE.
    #[arg(long, value_name = "PURGE", requires = "purge")]
    confirm: Option<String>,
}

#[derive(Debug, Args)]
struct SupportBundleArgs {
    /// Output ZIP. Defaults to a timestamped file in the current directory.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    Tail {
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    Export {
        output: PathBuf,
        #[arg(long, default_value_t = 10_000)]
        limit: usize,
    },
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PresetArg {
    Safe,
    Developer,
    Full,
}

impl From<PresetArg> for PolicyPreset {
    fn from(value: PresetArg) -> Self {
        match value {
            PresetArg::Safe => Self::Safe,
            PresetArg::Developer => Self::Developer,
            PresetArg::Full => Self::Full,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ModeArg {
    Deny,
    Ask,
    Allow,
}

impl From<ModeArg> for PolicyMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Deny => Self::Deny,
            ModeArg::Ask => Self::Ask,
            ModeArg::Allow => Self::Allow,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CapabilityArg {
    SystemRead,
    FilesRead,
    FilesWrite,
    ShellExec,
    BrowserRead,
    BrowserAct,
    DesktopControl,
    PlatformNative,
    AdminExec,
}

impl From<CapabilityArg> for Capability {
    fn from(value: CapabilityArg) -> Self {
        match value {
            CapabilityArg::SystemRead => Self::SystemRead,
            CapabilityArg::FilesRead => Self::FilesRead,
            CapabilityArg::FilesWrite => Self::FilesWrite,
            CapabilityArg::ShellExec => Self::ShellExec,
            CapabilityArg::BrowserRead => Self::BrowserRead,
            CapabilityArg::BrowserAct => Self::BrowserAct,
            CapabilityArg::DesktopControl => Self::DesktopControl,
            CapabilityArg::PlatformNative => Self::PlatformNative,
            CapabilityArg::AdminExec => Self::AdminExec,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    dispatch(cli.command).await
}

async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Setup(args) => setup(&args.roots),
        Command::Ui => spawn_sibling("runonmine-desktop", &[]),
        Command::Agent {
            command: AgentCommand::Run,
        } => runonmine_mcp::serve_loopback().await,
        Command::Mcp {
            command: McpCommand::Stdio { connector },
        } => runonmine_mcp::serve_stdio(&connector).await,
        Command::Connect { command } => connect(command).await,
        Command::Policy { command } => policy(command),
        Command::Approvals { command } => approvals(command),
        Command::Browser { command } => browser(command),
        Command::Oauth { command } => oauth(command),
        Command::Admin { command } => admin(command),
        Command::Service { command } => service(command),
        Command::Lock(args) => emergency_lock(&args),
        Command::Uninstall(args) => uninstall(&args),
        Command::SupportBundle(args) => create_support_bundle(args.output.as_deref()),
        Command::Doctor => doctor().await,
        Command::Audit { command } => audit(command),
    }
}

mod commands;
mod support_bundle;
use commands::{
    admin, approvals, audit, browser, connect, doctor, emergency_lock, oauth, policy, service,
    setup, spawn_sibling, uninstall,
};
use support_bundle::create_support_bundle;
