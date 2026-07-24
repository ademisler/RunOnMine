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
    BinaryInstaller, BinaryKind, BinaryProbe, GitHubReleaseResolver, InstallReceipt,
    InstalledBinary, ReleaseChannel, ReleaseProvider, SecretValue, run_once,
};
use runonmine_core::secrets::default_secret_store;
use runonmine_core::{
    AppConfig, AppPaths, ApprovalDecision, BrowserProfileMode, Capability, CloudflareNamedSettings,
    CloudflareQuickSettings, ConnectorConfig, ConnectorKind, OAuthOwnerSettings,
    OpenAiTunnelSettings, PolicyMode, PolicyPreset, StateStore,
};
use runonmine_oauth::SqliteOAuthStore;
use runonmine_platform::{LinuxSystemService, UserService, current};
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
}

#[derive(Debug, Subcommand)]
enum LocalHttpCommand {
    /// Enable authenticated loopback MCP access and print a new bearer token once.
    Enable,
    /// Disable loopback MCP access and delete its bearer token.
    Disable,
    /// Replace the bearer token for the enabled loopback connector.
    Rotate,
    /// Show local HTTP status. The token is hidden unless explicitly requested.
    Status {
        #[arg(long)]
        show_token: bool,
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
}

#[derive(Debug, Args)]
struct OpenAiConnectArgs {
    #[arg(long)]
    tunnel_id: Option<String>,
    #[arg(long, default_value = "runonmine")]
    profile: String,
    #[arg(long)]
    tunnel_client: Option<PathBuf>,
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
    /// Remove expired authorization state and tokens.
    Cleanup,
}

#[derive(Debug, Subcommand)]
enum OauthClientCommand {
    List,
    /// Revoke every active token issued to one client.
    Revoke {
        client_id: String,
    },
    /// Delete one registered client and all of its authorization state.
    Delete {
        client_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum OauthSessionCommand {
    List {
        #[arg(long)]
        client_id: Option<String>,
    },
    Revoke {
        family_id: Uuid,
    },
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Install {
        /// Root/SYSTEM-owned executable to permit through `admin_exec`. May be repeated.
        #[arg(long = "allow-program", value_name = "ABSOLUTE_PATH")]
        allowed_programs: Vec<PathBuf>,
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
        Command::Doctor => doctor().await,
        Command::Audit { command } => audit(command),
    }
}

fn setup(roots: &[PathBuf]) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load_or_create(&paths.config_file())?;
    for root in roots {
        let canonical = std::fs::canonicalize(root)
            .with_context(|| format!("allowed root does not exist: {}", root.display()))?;
        if !canonical.is_dir() {
            bail!("allowed root is not a directory: {}", canonical.display());
        }
        if !config.allowed_roots.contains(&canonical) {
            config.allowed_roots.push(canonical);
        }
    }
    config.allowed_roots.sort();
    config.save(&paths.config_file())?;
    let _state = StateStore::open(&paths.state_db())?;
    println!("RunOnMine is initialized.");
    println!("Config: {}", paths.config_file().display());
    println!("Allowed roots: {}", config.allowed_roots.len());
    if config.allowed_roots.is_empty() {
        println!("File tools remain unavailable until at least one --root is added.");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
async fn connect(command: ConnectCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load_or_create(&paths.config_file())?;
    let secrets = default_secret_store(&paths)?;
    match command {
        ConnectCommand::List => {
            if config.connectors.is_empty() {
                println!("No connectors are configured.");
            }
            for connector in &config.connectors {
                println!(
                    "{}  {:?}  enabled={}  preset={:?}  {}",
                    connector.id,
                    connector.kind,
                    connector.enabled,
                    connector.policy_preset,
                    connector.name,
                );
            }
        }
        ConnectCommand::Show { connector } => {
            let connector = config
                .connector(&connector)
                .context("connector was not found")?;
            println!("{}", serde_json::to_string_pretty(connector)?);
        }
        ConnectCommand::Enable { connector } => {
            let item = config
                .connector(&connector)
                .context("connector was not found")?;
            ensure_connector_credentials(item, secrets.as_ref())?;
            config
                .connector_mut(&connector)
                .context("connector was not found")?
                .enabled = true;
            config.save(&paths.config_file())?;
            println!(
                "Enabled connector {connector}. Restart the agent to apply transport changes."
            );
        }
        ConnectCommand::Disable { connector } => {
            config
                .connector_mut(&connector)
                .context("connector was not found")?
                .enabled = false;
            config.save(&paths.config_file())?;
            println!(
                "Disabled connector {connector}. Restart the agent to close live transport sessions."
            );
        }
        ConnectCommand::Remove { connector, confirm } => {
            if confirm != "REMOVE" {
                bail!("connector removal requires --confirm REMOVE");
            }
            let index = config
                .connectors
                .iter()
                .position(|item| item.id == connector)
                .context("connector was not found")?;
            let removed = config.connectors.remove(index);
            let secret_names = connector_secret_suffixes(removed.kind)
                .iter()
                .map(|suffix| format!("connector.{}.{suffix}", removed.id))
                .collect::<Vec<_>>();
            save_config_after_secret_deletion(
                &config,
                &paths.config_file(),
                secrets.as_ref(),
                &secret_names,
            )?;
            StateStore::open(&paths.state_db())?.clear_persistent_grants(Some(&removed.id))?;
            if removed.kind == ConnectorKind::CloudflareOauth {
                SqliteOAuthStore::open(&paths.state_db())?.emergency_revoke_all()?;
            }
            remove_connector_directories(&paths, &removed.id)?;
            println!(
                "Removed connector {} and its local credentials/state.",
                removed.id
            );
            println!("Restart the agent to close any live transport process.");
        }
        ConnectCommand::LocalHttp { command } => {
            let connector_index = config
                .connectors
                .iter()
                .position(|connector| connector.kind == ConnectorKind::LocalHttp);
            let connector_index = if let Some(index) = connector_index {
                index
            } else {
                let mut connector = ConnectorConfig::local_http_default();
                connector.policy_preset = config.default_preset;
                config.connectors.push(connector);
                config.connectors.len() - 1
            };
            let connector_id = config.connectors[connector_index].id.clone();
            let secret_name = local_http_secret_name(&connector_id);
            match command {
                LocalHttpCommand::Enable => {
                    config.connectors[connector_index].enabled = true;
                    config.connectors[connector_index].policy_preset = config.default_preset;
                    let token = generate_path_secret();
                    commit_connector(
                        &config,
                        &paths,
                        secrets.as_ref(),
                        &[(secret_name, SecretString::from(token.clone()))],
                    )?;
                    print_local_http_credentials(config.port, &connector_id, &token);
                }
                LocalHttpCommand::Disable => {
                    config.connectors[connector_index].enabled = false;
                    save_config_after_secret_deletion(
                        &config,
                        &paths.config_file(),
                        secrets.as_ref(),
                        std::slice::from_ref(&secret_name),
                    )?;
                    println!(
                        "Local HTTP connector {connector_id} is disabled and its token was deleted."
                    );
                }
                LocalHttpCommand::Rotate => {
                    if !config.connectors[connector_index].enabled {
                        bail!("local HTTP is disabled; enable it before rotating its token");
                    }
                    let token = generate_path_secret();
                    secrets.set(&secret_name, &SecretString::from(token.clone()))?;
                    print_local_http_credentials(config.port, &connector_id, &token);
                }
                LocalHttpCommand::Status { show_token } => {
                    let enabled = config.connectors[connector_index].enabled;
                    println!("Connector: {connector_id}");
                    println!("Enabled: {enabled}");
                    println!("Endpoint: http://127.0.0.1:{}/mcp", config.port);
                    let token = secrets.get(&secret_name)?;
                    println!("Token configured: {}", token.is_some());
                    if show_token {
                        let token = token.context("local HTTP token is not configured")?;
                        println!("Bearer token: {}", token.expose_secret());
                    }
                }
            }
        }
        ConnectCommand::Cloudflare {
            command:
                CloudflareCommand::Quick {
                    rotate,
                    cloudflared,
                },
        } => {
            if let Some(id) = rotate {
                let connector = config.connector(&id).context("connector was not found")?;
                if connector.kind != ConnectorKind::CloudflareQuick {
                    bail!("secret rotation is only valid for a Cloudflare Quick Tunnel connector");
                }
                let path_secret = generate_path_secret();
                secrets.set(
                    &format!("connector.{id}.path_secret"),
                    &SecretString::from(path_secret),
                )?;
                println!("Rotated the temporary connector secret. The previous URL is invalid.");
                return Ok(());
            }
            let binary = ensure_binary(
                &paths,
                BinaryKind::Cloudflared,
                ReleaseProvider::Cloudflared,
                cloudflared.as_deref(),
            )
            .await?;
            let id = Uuid::new_v4().to_string();
            let path_secret = generate_path_secret();
            config.connectors.push(ConnectorConfig {
                id: id.clone(),
                name: "Cloudflare Quick Tunnel".to_owned(),
                kind: ConnectorKind::CloudflareQuick,
                enabled: true,
                policy_preset: config.default_preset,
                pack_overrides: BTreeMap::default(),
                tool_overrides: BTreeMap::default(),
                public_base_url: None,
                cloudflare_quick: Some(CloudflareQuickSettings {
                    cloudflared_path: Some(binary.path),
                    ..CloudflareQuickSettings::default()
                }),
                cloudflare_named: None,
                oauth_owner: None,
                openai_tunnel: None,
            });
            commit_connector(
                &config,
                &paths,
                secrets.as_ref(),
                &[(
                    format!("connector.{id}.path_secret"),
                    SecretString::from(path_secret),
                )],
            )?;
            println!("Created temporary Cloudflare connector {id}.");
            println!("The secret URL path is stored in the operating system credential store.");
        }
        ConnectCommand::Cloudflare {
            command: CloudflareCommand::Oauth(args),
        } => {
            let binary = ensure_binary(
                &paths,
                BinaryKind::Cloudflared,
                ReleaseProvider::Cloudflared,
                args.cloudflared.as_deref(),
            )
            .await?;
            let hostname = value_or_prompt(args.hostname, "Public Cloudflare hostname: ")?
                .to_ascii_lowercase();
            let callback_url = format!("https://{hostname}/oauth/github/callback");
            let tunnel_id = value_or_prompt(args.tunnel_id, "Cloudflare tunnel UUID: ")?;
            let credentials_file = args
                .credentials_file
                .map_or_else(
                    || prompt_required("Cloudflare credentials JSON path: ").map(PathBuf::from),
                    Ok,
                )?
                .canonicalize()
                .context("Cloudflare credentials file does not exist")?;
            let client_id = value_or_prompt(args.github_client_id, "GitHub OAuth client ID: ")?;
            let client_secret = rpassword::prompt_password("GitHub OAuth client secret: ")?;
            if client_secret.trim().is_empty() {
                bail!("GitHub OAuth client secret must not be empty");
            }
            let owner_login = value_or_prompt(args.github_owner, "Machine owner's GitHub login: ")?;
            let owner_id = args.github_owner_id.map_or_else(
                || {
                    prompt_required("Machine owner's immutable GitHub numeric ID: ")?
                        .parse::<u64>()
                        .context("GitHub owner ID must be a positive integer")
                },
                Ok,
            )?;
            if owner_id == 0 {
                bail!("GitHub owner ID must be greater than zero");
            }
            let id = Uuid::new_v4().to_string();
            let public_base_url = Url::parse(&format!("https://{hostname}/"))
                .context("public Cloudflare hostname is invalid")?;
            config.connectors.push(ConnectorConfig {
                id: id.clone(),
                name: "Cloudflare Named Tunnel with OAuth".to_owned(),
                kind: ConnectorKind::CloudflareOauth,
                enabled: true,
                policy_preset: config.default_preset,
                pack_overrides: BTreeMap::default(),
                tool_overrides: BTreeMap::default(),
                public_base_url: Some(public_base_url),
                cloudflare_quick: None,
                cloudflare_named: Some(CloudflareNamedSettings {
                    tunnel_id,
                    credentials_file,
                    hostname,
                    cloudflared_path: Some(binary.path),
                    metrics_port: 47_824,
                }),
                oauth_owner: Some(OAuthOwnerSettings {
                    github_login: owner_login,
                    github_id: Some(owner_id),
                }),
                openai_tunnel: None,
            });
            commit_connector(
                &config,
                &paths,
                secrets.as_ref(),
                &[
                    (
                        format!("connector.{id}.github_client_id"),
                        SecretString::from(client_id),
                    ),
                    (
                        format!("connector.{id}.github_client_secret"),
                        SecretString::from(client_secret),
                    ),
                    (
                        format!("connector.{id}.oauth_hash_key"),
                        SecretString::from(generate_path_secret()),
                    ),
                ],
            )?;
            println!("Created OAuth connector {id}.");
            println!("Register {callback_url} in the GitHub OAuth app.");
        }
        ConnectCommand::Openai(args) => {
            validate_profile_name(&args.profile)?;
            let binary = ensure_binary(
                &paths,
                BinaryKind::OpenAiTunnelClient,
                ReleaseProvider::OpenAiTunnelClient,
                args.tunnel_client.as_deref(),
            )
            .await?;
            let tunnel_id = value_or_prompt(args.tunnel_id, "OpenAI tunnel ID: ")?;
            let api_key = rpassword::prompt_password("OpenAI runtime API key: ")?;
            if api_key.trim().is_empty() {
                bail!("runtime API key must not be empty");
            }
            let id = Uuid::new_v4().to_string();
            let profile_directory = paths
                .data_dir
                .join("connectors")
                .join(&id)
                .join("openai-profiles");
            ensure_private_directory(&profile_directory)?;
            let health_directory = paths.state_dir.join("connectors").join(&id);
            ensure_private_directory(&health_directory)?;
            let profile = OpenAiTunnelProfile::builder(
                &args.profile,
                &tunnel_id,
                OpenAiMcpTarget::runonmine_stdio(std::env::current_exe()?.canonicalize()?, &id)?,
            )
            .profile_directory(profile_directory.clone())
            .health_address("127.0.0.1:47823".parse()?)
            .health_url_file(health_directory.join("tunnel-health.url"))
            .build()?;
            let initialized = run_once(
                profile.init_command(&binary)?,
                std::time::Duration::from_secs(30),
                128 * 1_024,
            )
            .await?;
            if !initialized.success {
                bail!("tunnel-client profile initialization failed");
            }
            restrict_private_file(&profile_directory.join(format!("{}.yaml", args.profile)))?;
            let doctor = run_once(
                profile.doctor_command(&binary, SecretValue::new(api_key.clone())?)?,
                std::time::Duration::from_secs(30),
                256 * 1_024,
            )
            .await?;
            if !doctor.success {
                bail!("tunnel-client doctor failed; verify tunnel permissions and the runtime key");
            }
            config.connectors.push(ConnectorConfig {
                id: id.clone(),
                name: "OpenAI Secure MCP Tunnel".to_owned(),
                kind: ConnectorKind::OpenAiTunnel,
                enabled: true,
                policy_preset: config.default_preset,
                pack_overrides: BTreeMap::default(),
                tool_overrides: BTreeMap::default(),
                public_base_url: None,
                cloudflare_quick: None,
                cloudflare_named: None,
                oauth_owner: None,
                openai_tunnel: Some(OpenAiTunnelSettings {
                    tunnel_id,
                    profile: args.profile,
                    tunnel_client_path: Some(binary.path),
                    health_port: 47_823,
                }),
            });
            commit_connector(
                &config,
                &paths,
                secrets.as_ref(),
                &[(
                    format!("connector.{id}.runtime_api_key"),
                    SecretString::from(api_key),
                )],
            )?;
            println!("Created OpenAI Secure MCP Tunnel connector {id}.");
        }
    }
    Ok(())
}

fn save_config_after_secret_deletion(
    config: &AppConfig,
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    names: &[String],
) -> Result<()> {
    let backups = names
        .iter()
        .map(|name| Ok((name.clone(), secrets.get(name)?)))
        .collect::<Result<Vec<_>>>()?;
    for name in names {
        if let Err(error) = secrets.delete(name) {
            restore_secret_backups(secrets, &backups)?;
            return Err(error).context("failed to delete connector credential");
        }
    }
    if let Err(error) = config.save(config_path) {
        restore_secret_backups(secrets, &backups)?;
        return Err(error).context("failed to save configuration after credential deletion");
    }
    Ok(())
}

fn restore_secret_backups(
    secrets: &dyn runonmine_core::secrets::SecretStore,
    backups: &[(String, Option<SecretString>)],
) -> Result<()> {
    for (name, value) in backups {
        match value {
            Some(value) => secrets.set(name, value)?,
            None => secrets.delete(name)?,
        }
    }
    Ok(())
}

fn connector_secret_suffixes(kind: ConnectorKind) -> &'static [&'static str] {
    match kind {
        ConnectorKind::LocalStdio => &[],
        ConnectorKind::LocalHttp => &["local_http_token"],
        ConnectorKind::CloudflareQuick => &["path_secret"],
        ConnectorKind::CloudflareOauth => {
            &["github_client_id", "github_client_secret", "oauth_hash_key"]
        }
        ConnectorKind::OpenAiTunnel => &["runtime_api_key"],
    }
}

fn ensure_connector_credentials(
    connector: &ConnectorConfig,
    secrets: &dyn runonmine_core::secrets::SecretStore,
) -> Result<()> {
    for suffix in connector_secret_suffixes(connector.kind) {
        if secrets
            .get(&format!("connector.{}.{suffix}", connector.id))?
            .is_none()
        {
            bail!("connector credential {suffix} is missing");
        }
    }
    if connector.kind == ConnectorKind::CloudflareOauth
        && connector
            .oauth_owner
            .as_ref()
            .and_then(|owner| owner.github_id)
            .is_none_or(|id| id == 0)
    {
        bail!("OAuth connector must pin the machine owner's immutable GitHub numeric ID");
    }
    Ok(())
}

fn remove_connector_directories(paths: &AppPaths, connector_id: &str) -> Result<()> {
    for directory in [
        paths.data_dir.join("connectors").join(connector_id),
        paths.state_dir.join("connectors").join(connector_id),
    ] {
        remove_real_directory_if_exists(&directory)?;
    }
    let profiles = paths.browser_profiles();
    if profiles.is_dir() {
        for entry in std::fs::read_dir(&profiles)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                remove_real_directory_if_exists(&entry.path().join(connector_id))?;
            }
        }
    }
    Ok(())
}

fn remove_real_directory_if_exists(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "refusing to remove symlinked connector directory: {}",
                path.display()
            );
        }
        Ok(metadata) if metadata.is_dir() => {
            std::fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
        Ok(_) => bail!(
            "connector state path is not a directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn local_http_secret_name(connector_id: &str) -> String {
    format!("connector.{connector_id}.local_http_token")
}

fn print_local_http_credentials(port: u16, connector_id: &str, token: &str) {
    println!("Local HTTP connector {connector_id} is enabled.");
    println!("Endpoint: http://127.0.0.1:{port}/mcp");
    println!("Bearer token: {token}");
    println!("Store this token now; it is kept in the operating system credential store.");
}

fn value_or_prompt(value: Option<String>, prompt: &str) -> Result<String> {
    value.map_or_else(|| prompt_required(prompt), Ok)
}

fn commit_connector(
    config: &AppConfig,
    paths: &AppPaths,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    values: &[(String, SecretString)],
) -> Result<()> {
    config.validate()?;
    let mut stored: Vec<String> = Vec::new();
    for (name, value) in values {
        if let Err(error) = secrets.set(name, value) {
            for stored_name in &stored {
                let _ignored = secrets.delete(stored_name);
            }
            return Err(error);
        }
        stored.push(name.to_owned());
    }
    if let Err(error) = config.save(&paths.config_file()) {
        for name in &stored {
            let _ignored = secrets.delete(name);
        }
        return Err(error);
    }
    Ok(())
}

async fn ensure_binary(
    paths: &AppPaths,
    kind: BinaryKind,
    provider: ReleaseProvider,
    explicit_path: Option<&Path>,
) -> Result<InstalledBinary> {
    let managed_directory = paths.data_dir.join("bin");
    ensure_private_directory(&managed_directory)?;
    if let Some(path) = explicit_path {
        let binary = InstalledBinary::from_verified_path(kind, path)?;
        BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await?;
        return Ok(binary);
    }

    let destination = managed_directory.join(kind.executable_name());
    let receipt_path = managed_receipt_path(&managed_directory, kind);
    if destination.exists() {
        let binary = InstalledBinary::from_verified_path(kind, &destination)?;
        match verify_managed_binary(&binary, provider, &receipt_path) {
            Ok(()) => {
                BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await?;
                return Ok(binary);
            }
            Err(error) => {
                tracing::warn!(%error, path = %destination.display(), "managed connector binary failed integrity verification and will be replaced");
                std::fs::remove_file(&destination)?;
                if receipt_path.exists() {
                    std::fs::remove_file(&receipt_path)?;
                }
            }
        }
    }

    println!("Downloading the latest verified official connector binary...");
    let artifact = GitHubReleaseResolver::production()?
        .resolve(provider, &ReleaseChannel::Latest)
        .await?;
    let receipt = BinaryInstaller::production()?
        .install(&artifact, &destination)
        .await?;
    write_install_receipt(&receipt_path, &receipt)?;
    let binary = InstalledBinary::from_verified_path(kind, &destination)?;
    verify_managed_binary(&binary, provider, &receipt_path)?;
    BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await?;
    Ok(binary)
}

fn managed_receipt_path(directory: &Path, kind: BinaryKind) -> PathBuf {
    directory.join(format!("{}.receipt.json", kind.executable_name()))
}

fn write_install_receipt(path: &Path, receipt: &InstallReceipt) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(receipt)?)?;
    restrict_private_file(path)
}

fn read_install_receipt(path: &Path) -> Result<InstallReceipt> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("managed binary receipt is missing: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1_024 {
        bail!("managed binary receipt is not a small regular file");
    }
    serde_json::from_slice(&std::fs::read(path)?).context("managed binary receipt is invalid")
}

fn verify_managed_binary(
    binary: &InstalledBinary,
    provider: ReleaseProvider,
    receipt_path: &Path,
) -> Result<()> {
    let receipt = read_install_receipt(receipt_path)?;
    if receipt.provider != provider {
        bail!("managed binary receipt provider does not match");
    }
    let expected_path = receipt
        .installed_path
        .canonicalize()
        .context("managed binary receipt path does not exist")?;
    if expected_path != binary.path {
        bail!("managed binary path does not match its receipt");
    }
    if !receipt.sha256.verify_file(&binary.path)? {
        bail!("managed binary SHA-256 does not match its installation receipt");
    }
    Ok(())
}

fn load_connector_binary(
    paths: &AppPaths,
    kind: BinaryKind,
    provider: ReleaseProvider,
    configured_path: Option<&Path>,
) -> Result<Option<InstalledBinary>> {
    let managed_directory = paths.data_dir.join("bin");
    let candidate = configured_path.map_or_else(
        || managed_directory.join(kind.executable_name()),
        Path::to_path_buf,
    );
    if !candidate.exists() {
        return Ok(None);
    }
    let managed = managed_directory
        .canonicalize()
        .unwrap_or(managed_directory.clone());
    let candidate_parent = candidate
        .parent()
        .and_then(|parent| parent.canonicalize().ok());
    let is_managed_candidate = candidate_parent.as_deref() == Some(managed.as_path())
        && candidate.file_name() == Some(std::ffi::OsStr::new(kind.executable_name()));
    if is_managed_candidate
        && std::fs::symlink_metadata(&candidate)?
            .file_type()
            .is_symlink()
    {
        bail!("managed connector binary must not be a symlink");
    }
    let binary = InstalledBinary::from_verified_path(kind, &candidate)?;
    if is_managed_candidate {
        verify_managed_binary(
            &binary,
            provider,
            &managed_receipt_path(&managed_directory, kind),
        )?;
    }
    Ok(Some(binary))
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked private directory");
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_private_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("private file was not created")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("private file must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn generate_path_secret() -> String {
    let mut raw = [0_u8; 32];
    rand::rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

fn policy(command: PolicyCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    let mut config =
        AppConfig::load(&paths.config_file()).context("run `runonmine setup` first")?;
    match command {
        PolicyCommand::Show { connector } => {
            let selected = connector.as_deref().map_or_else(
                || config.connectors.iter().collect(),
                |id| config.connector(id).into_iter().collect::<Vec<_>>(),
            );
            if selected.is_empty() {
                bail!("connector was not found");
            }
            for item in selected {
                println!("{}  {}  {:?}", item.id, item.name, item.policy_preset);
                for capability in Capability::ALL {
                    let mode = item
                        .pack_overrides
                        .get(&capability)
                        .copied()
                        .or_else(|| item.policy_preset.modes().get(&capability).copied())
                        .unwrap_or(PolicyMode::Deny);
                    println!("  {capability:?}: {mode:?}");
                }
                for (tool, mode) in &item.tool_overrides {
                    println!("  tool {tool}: {mode:?}");
                }
            }
        }
        PolicyCommand::Preset { preset, connector } => {
            let id = match connector {
                Some(id) => id,
                None => config
                    .connectors
                    .first()
                    .context("no connectors are configured")?
                    .id
                    .clone(),
            };
            let item = config
                .connector_mut(&id)
                .context("connector was not found")?;
            item.policy_preset = preset.into();
            item.pack_overrides.clear();
            item.tool_overrides.clear();
            let updated_preset = item.policy_preset;
            config.save(&paths.config_file())?;
            println!("Updated connector {id} to {updated_preset:?}.");
        }
        PolicyCommand::Set {
            connector,
            capability,
            mode,
        } => {
            let item = config
                .connector_mut(&connector)
                .context("connector was not found")?;
            item.pack_overrides.insert(capability.into(), mode.into());
            config.save(&paths.config_file())?;
            println!("Updated connector {connector}.");
        }
    }
    Ok(())
}

fn approvals(command: ApprovalCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    let store = StateStore::open(&paths.state_db()).context("run `runonmine setup` first")?;
    match command {
        ApprovalCommand::List => {
            let pending = store.pending_approvals()?;
            if pending.is_empty() {
                println!("No pending approvals.");
            }
            for request in pending {
                println!(
                    "{}  {}  {}  expires {}\n  {}",
                    request.id,
                    request.connector_id,
                    request.tool_name,
                    request.expires_at.to_rfc3339(),
                    request.argument_summary
                );
            }
        }
        ApprovalCommand::Approve(args) => {
            let decision = if args.once {
                ApprovalDecision::Once
            } else if args.duration.is_some() {
                ApprovalDecision::ForTenMinutes
            } else {
                ApprovalDecision::Always
            };
            if !store.resolve_approval(args.id, decision)? {
                bail!("approval is no longer pending or has expired");
            }
            println!(
                "Approved {} ({decision:?}). Temporary and persistent grants apply only to the exact arguments shown.",
                args.id
            );
        }
        ApprovalCommand::Deny { id } => {
            if !store.resolve_approval(id, ApprovalDecision::Deny)? {
                bail!("approval is no longer pending or has expired");
            }
            println!("Denied {id}.");
        }
        ApprovalCommand::Grants {
            command: GrantCommand::List { connector },
        } => {
            let grants = store.persistent_grants(connector.as_deref())?;
            if grants.is_empty() {
                println!("No persistent exact-action grants were found.");
            }
            for grant in grants {
                println!(
                    "{}  {}  {}  created={}
  {}",
                    grant.connector_id,
                    grant.tool_name,
                    grant.argument_hash,
                    grant.created_at.to_rfc3339(),
                    grant.argument_summary,
                );
            }
        }
        ApprovalCommand::Grants {
            command:
                GrantCommand::Revoke {
                    connector,
                    tool,
                    argument_hash,
                },
        } => {
            if !store.delete_persistent_grant(&connector, &tool, &argument_hash)? {
                bail!("persistent grant was not found");
            }
            println!("Revoked the persistent exact-action grant.");
        }
        ApprovalCommand::Grants {
            command: GrantCommand::Clear { connector, confirm },
        } => {
            if confirm != "CLEAR" {
                bail!("clearing persistent grants requires --confirm CLEAR");
            }
            let removed = store.clear_persistent_grants(connector.as_deref())?;
            println!("Removed {removed} persistent exact-action grant(s).");
        }
    }
    Ok(())
}

fn browser(command: BrowserCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut config = AppConfig::load_or_create(&paths.config_file())?;
    match command {
        BrowserCommand::Profile {
            command: BrowserProfileCommand::Create { name },
        } => {
            validate_profile_name(&name)?;
            let directory = paths.browser_profiles().join(&name);
            ensure_private_directory(&directory)?;
            config.browser.profile_name = name;
            config.browser.profile_mode = BrowserProfileMode::Persistent;
            config.browser.external_cdp_url = None;
            config.save(&paths.config_file())?;
            println!(
                "Selected persistent browser profile at {}.",
                directory.display()
            );
        }
        BrowserCommand::Profile {
            command: BrowserProfileCommand::Ephemeral { name },
        } => {
            validate_profile_name(&name)?;
            config.browser.profile_name = name;
            config.browser.profile_mode = BrowserProfileMode::Ephemeral;
            config.browser.external_cdp_url = None;
            config.save(&paths.config_file())?;
            println!("Selected disposable browser profile mode.");
        }
        BrowserCommand::Profile {
            command: BrowserProfileCommand::Delete { name },
        } => {
            validate_profile_name(&name)?;
            if config.browser.profile_mode == BrowserProfileMode::Persistent
                && config.browser.profile_name == name
                && config.browser.external_cdp_url.is_none()
            {
                bail!(
                    "switch to an ephemeral or different profile before deleting the active profile"
                );
            }
            let directory = paths.browser_profiles().join(&name);
            if directory
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                bail!("refusing to delete a symlinked browser profile directory");
            }
            if directory.exists() {
                std::fs::remove_dir_all(&directory)?;
            }
            println!("Deleted browser profile {}.", directory.display());
        }
        BrowserCommand::Attach { loopback_cdp_url } => {
            runonmine_browser_guard(&loopback_cdp_url)?;
            config.browser.external_cdp_url = Some(loopback_cdp_url);
            config.save(&paths.config_file())?;
            println!(
                "Configured expert CDP attachment. RunOnMine will not launch your daily profile."
            );
        }
        BrowserCommand::PrivateNetwork { access } => {
            config.browser.allow_private_network = matches!(access, PrivateNetworkAccess::Allow);
            config.save(&paths.config_file())?;
            if config.browser.allow_private_network {
                println!(
                    "Private-network browser access enabled for local connectors. Remote connectors remain blocked."
                );
            } else {
                println!("Private-network browser access disabled.");
            }
        }
    }
    Ok(())
}

fn oauth(command: OauthCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    let store = SqliteOAuthStore::open(&paths.state_db())?;
    match command {
        OauthCommand::Clients {
            command: OauthClientCommand::List,
        } => {
            let clients = store.registered_clients()?;
            if clients.is_empty() {
                println!("No OAuth clients are registered.");
            }
            for client in clients {
                println!(
                    "{}  {}  issued={}
  scopes: {}
  redirects: {}",
                    client.client_id,
                    client.client_name,
                    client.issued_at.to_rfc3339(),
                    client.scopes.to_space_delimited(),
                    client
                        .redirect_uris
                        .iter()
                        .map(Url::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        OauthCommand::Clients {
            command: OauthClientCommand::Revoke { client_id },
        } => {
            let revoked = store.revoke_client_tokens(&client_id)?;
            println!("Revoked {revoked} active OAuth token(s) for {client_id}.");
        }
        OauthCommand::Clients {
            command: OauthClientCommand::Delete { client_id },
        } => {
            if !store.delete_client(&client_id)? {
                bail!("OAuth client was not found");
            }
            println!("Deleted OAuth client {client_id} and its authorization state.");
        }
        OauthCommand::Sessions {
            command: OauthSessionCommand::List { client_id },
        } => {
            let sessions = store.sessions(client_id.as_deref())?;
            if sessions.is_empty() {
                println!("No OAuth sessions were found.");
            }
            for session in sessions {
                println!(
                    "{}  client={}  active={}  expires={}
  subject: {}
  scopes: {}",
                    session.family_id,
                    session.client_id,
                    session.active,
                    session.expires_at.to_rfc3339(),
                    session.subject,
                    session.scopes.to_space_delimited(),
                );
            }
        }
        OauthCommand::Sessions {
            command: OauthSessionCommand::Revoke { family_id },
        } => {
            let revoked = store.revoke_session(family_id)?;
            println!("Revoked {revoked} active token(s) in session {family_id}.");
        }
        OauthCommand::Cleanup => {
            let removed = store.cleanup_expired(chrono::Utc::now())?;
            println!("Removed {removed} expired OAuth record(s).");
        }
    }
    Ok(())
}

fn admin(command: AdminCommand) -> Result<()> {
    let helper = sibling_executable("runonmine-helper")?;
    match command {
        AdminCommand::Install { allowed_programs } => {
            for path in &allowed_programs {
                if !path.is_absolute() {
                    bail!("admin allowlist entries must be absolute paths");
                }
            }
            install_admin_helper(&helper, &allowed_programs)
        }
        AdminCommand::Uninstall => run_elevated_helper(&helper, &["uninstall".into()]),
        AdminCommand::Status => run_process(ProcessCommand::new(helper).arg("status")),
    }
}

fn service(command: ServiceCommand) -> Result<()> {
    match command {
        ServiceCommand::Install(args) if args.system => {
            let user = args
                .user
                .as_deref()
                .context("--user is required with --system")?;
            LinuxSystemService::discover()?.install(user)?;
        }
        ServiceCommand::Install(_) => UserService::discover()?.install()?,
        ServiceCommand::Uninstall(args) if args.system => {
            LinuxSystemService::discover()?.uninstall()?;
        }
        ServiceCommand::Uninstall(_) => UserService::discover()?.uninstall()?,
        ServiceCommand::Start(args) if args.system => LinuxSystemService::discover()?.start()?,
        ServiceCommand::Start(_) => UserService::discover()?.start()?,
        ServiceCommand::Stop(args) if args.system => LinuxSystemService::discover()?.stop()?,
        ServiceCommand::Stop(_) => UserService::discover()?.stop()?,
        ServiceCommand::Status(args) => {
            let status = if args.system {
                LinuxSystemService::discover()?.status()?
            } else {
                UserService::discover()?.status()?
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
            return Ok(());
        }
    }
    println!("Service operation completed.");
    Ok(())
}

fn emergency_lock(arguments: &LockArgs) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;

    let mut stop_failures = Vec::new();
    match UserService::discover() {
        Ok(service) => match service.status() {
            Ok(status) if status.running => {
                if let Err(error) = service.stop() {
                    stop_failures.push(format!("user service: {error}"));
                }
            }
            Ok(_) => {}
            Err(error) => stop_failures.push(format!("user service status: {error}")),
        },
        Err(error) => stop_failures.push(format!("user service discovery: {error}")),
    }
    #[cfg(target_os = "linux")]
    if arguments.system {
        match LinuxSystemService::discover() {
            Ok(service) => match service.status() {
                Ok(status) if status.running => {
                    if let Err(error) = service.stop() {
                        stop_failures.push(format!("system service: {error}"));
                    }
                }
                Ok(_) => {}
                Err(error) => stop_failures.push(format!("system service status: {error}")),
            },
            Err(error) => stop_failures.push(format!("system service discovery: {error}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    if arguments.system {
        stop_failures.push("system service locking is only supported on Linux".to_owned());
    }

    let store = StateStore::open(&paths.state_db())?;
    let (denied, temporary_grants) = store.emergency_lock()?;
    let oauth = SqliteOAuthStore::open(&paths.state_db())?;
    let revoked_tokens = oauth.emergency_revoke_all()?;

    let config = AppConfig::load(&paths.config_file())?;
    let secrets = default_secret_store(&paths)?;
    let mut rotated_local_http_tokens = 0_usize;
    let mut rotated_quick_tunnels = 0_usize;
    let mut removed_openai_keys = 0_usize;
    for connector in &config.connectors {
        match connector.kind {
            ConnectorKind::LocalHttp => {
                secrets.set(
                    &local_http_secret_name(&connector.id),
                    &SecretString::from(generate_path_secret()),
                )?;
                rotated_local_http_tokens += 1;
            }
            ConnectorKind::CloudflareQuick => {
                secrets.set(
                    &format!("connector.{}.path_secret", connector.id),
                    &SecretString::from(generate_path_secret()),
                )?;
                rotated_quick_tunnels += 1;
            }
            ConnectorKind::OpenAiTunnel => {
                secrets.delete(&format!("connector.{}.runtime_api_key", connector.id))?;
                removed_openai_keys += 1;
            }
            ConnectorKind::LocalStdio | ConnectorKind::CloudflareOauth => {}
        }
    }

    println!("RunOnMine is locked.");
    println!("Denied pending approvals: {denied}");
    println!("Cleared temporary grants: {temporary_grants}");
    println!("Revoked OAuth tokens: {revoked_tokens}");
    println!("Rotated local HTTP tokens: {rotated_local_http_tokens}");
    println!("Rotated Quick Tunnel secrets: {rotated_quick_tunnels}");
    println!("Removed OpenAI runtime keys: {removed_openai_keys}");
    println!("Restart and reconnect explicitly when access should be restored.");
    if !stop_failures.is_empty() {
        bail!(
            "credentials and grants were locked, but service shutdown had errors: {}",
            stop_failures.join("; ")
        );
    }
    Ok(())
}

fn uninstall(arguments: &UninstallArgs) -> Result<()> {
    let user_service = UserService::discover()?;
    if user_service.status()?.installed {
        user_service.uninstall()?;
    }
    if !arguments.purge {
        println!("RunOnMine user service removed. Configuration, state, and secrets were kept.");
        println!("Use --purge --confirm PURGE only when permanent data removal is intended.");
        return Ok(());
    }
    if arguments.confirm.as_deref() != Some("PURGE") {
        bail!("permanent removal requires --purge --confirm PURGE");
    }

    let paths = AppPaths::discover()?;
    let config_path = paths.config_file();
    let config = if config_path.exists() {
        Some(AppConfig::load(&config_path)?)
    } else {
        None
    };
    if config.is_none()
        && [&paths.config_dir, &paths.state_dir, &paths.data_dir]
            .into_iter()
            .any(|directory| directory.exists())
    {
        bail!(
            "configuration is missing; connector credentials cannot be enumerated for a safe purge"
        );
    }
    if let Some(config) = &config {
        match default_secret_store(&paths) {
            Ok(store) => {
                for connector in &config.connectors {
                    for suffix in [
                        "local_http_token",
                        "path_secret",
                        "github_client_id",
                        "github_client_secret",
                        "oauth_hash_key",
                        "runtime_api_key",
                    ] {
                        store.delete(&format!("connector.{}.{suffix}", connector.id))?;
                    }
                }
            }
            Err(error) if paths.state_dir.join("secrets.enc").is_file() => {
                tracing::warn!(%error, "encrypted secret file will be removed with local state");
            }
            Err(error) => return Err(error).context("failed to purge connector credentials"),
        }
    }

    let mut directories = vec![
        paths.config_dir,
        paths.state_dir,
        paths.data_dir,
        paths.log_dir,
    ];
    directories.sort();
    directories.dedup();
    for directory in &directories {
        if directory
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!(
                "refusing to purge symlinked RunOnMine directory: {}",
                directory.display()
            );
        }
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        if directory.exists() {
            std::fs::remove_dir_all(&directory)
                .with_context(|| format!("failed to remove {}", directory.display()))?;
        }
    }
    println!("RunOnMine user data and connector credentials were permanently removed.");
    println!(
        "Privileged helper and Linux system service, if installed, must be removed separately."
    );
    Ok(())
}

#[allow(clippy::if_not_else, clippy::single_match_else, clippy::too_many_lines)]
async fn doctor() -> Result<()> {
    let paths = AppPaths::discover()?;
    println!("RunOnMine doctor");
    println!("Platform: {} {}", current().os, current().architecture);
    let config =
        AppConfig::load(&paths.config_file()).context("configuration is missing or invalid")?;
    println!(
        "Config: valid (loopback {}:{})",
        config.bind_host, config.port
    );
    println!("Legacy MacMCP port 45799: reserved and untouched");
    let mut failures = 0_u32;
    let state = StateStore::open(&paths.state_db())?;
    if !state.verify_audit_chain()? {
        println!("Audit chain: FAILED");
        failures = failures.saturating_add(1);
    } else {
        println!("Audit chain: valid");
    }
    let agent_reachable = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        tokio::net::TcpStream::connect(("127.0.0.1", config.port)),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    println!("Agent loopback listener: {agent_reachable}");
    let secrets = default_secret_store(&paths)?;
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        match connector.kind {
            ConnectorKind::LocalHttp => {
                if secrets
                    .get(&local_http_secret_name(&connector.id))?
                    .is_some()
                {
                    println!("{}: authenticated local HTTP configured", connector.id);
                } else {
                    println!("{}: local HTTP bearer token missing", connector.id);
                    failures = failures.saturating_add(1);
                }
            }
            ConnectorKind::CloudflareQuick => {
                let Some(settings) = &connector.cloudflare_quick else {
                    println!("{}: Cloudflare Quick settings FAILED", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                match load_connector_binary(
                    &paths,
                    BinaryKind::Cloudflared,
                    ReleaseProvider::Cloudflared,
                    settings.cloudflared_path.as_deref(),
                )? {
                    Some(binary) => {
                        match BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await {
                            Ok(probe) => println!(
                                "{}: cloudflared {}, public URL discovered={}",
                                connector.id,
                                probe.version,
                                connector.public_base_url.is_some()
                            ),
                            Err(_) => {
                                println!("{}: cloudflared probe FAILED", connector.id);
                                failures = failures.saturating_add(1);
                            }
                        }
                    }
                    None => {
                        println!("{}: cloudflared missing", connector.id);
                        failures = failures.saturating_add(1);
                    }
                }
                if secrets
                    .get(&format!("connector.{}.path_secret", connector.id))?
                    .is_none()
                {
                    println!("{}: Quick Tunnel path credential missing", connector.id);
                    failures = failures.saturating_add(1);
                }
            }
            ConnectorKind::CloudflareOauth => {
                let Some(settings) = &connector.cloudflare_named else {
                    println!("{}: Cloudflare OAuth settings FAILED", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                match load_connector_binary(
                    &paths,
                    BinaryKind::Cloudflared,
                    ReleaseProvider::Cloudflared,
                    settings.cloudflared_path.as_deref(),
                )? {
                    Some(binary) => {
                        match BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await {
                            Ok(probe) => {
                                println!(
                                    "{}: cloudflared {}, OAuth configured",
                                    connector.id, probe.version
                                );
                            }
                            Err(_) => {
                                println!("{}: cloudflared probe FAILED", connector.id);
                                failures = failures.saturating_add(1);
                            }
                        }
                    }
                    None => {
                        println!("{}: cloudflared missing", connector.id);
                        failures = failures.saturating_add(1);
                    }
                }
                for suffix in ["github_client_id", "github_client_secret", "oauth_hash_key"] {
                    if secrets
                        .get(&format!("connector.{}.{suffix}", connector.id))?
                        .is_none()
                    {
                        println!("{}: OAuth credential {suffix} missing", connector.id);
                        failures = failures.saturating_add(1);
                    }
                }
                if connector
                    .oauth_owner
                    .as_ref()
                    .and_then(|owner| owner.github_id)
                    .is_none_or(|id| id == 0)
                {
                    println!("{}: immutable GitHub owner ID missing", connector.id);
                    failures = failures.saturating_add(1);
                }
            }
            ConnectorKind::OpenAiTunnel => {
                let Some(settings) = &connector.openai_tunnel else {
                    println!("{}: OpenAI settings FAILED", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                let Some(binary) = load_connector_binary(
                    &paths,
                    BinaryKind::OpenAiTunnelClient,
                    ReleaseProvider::OpenAiTunnelClient,
                    settings.tunnel_client_path.as_deref(),
                )?
                else {
                    println!("{}: tunnel-client missing", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                match BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await {
                    Ok(probe) => println!("{}: tunnel-client {}", connector.id, probe.version),
                    Err(_) => {
                        println!("{}: tunnel-client probe FAILED", connector.id);
                        failures = failures.saturating_add(1);
                        continue;
                    }
                }
                let Some(runtime_key) =
                    secrets.get(&format!("connector.{}.runtime_api_key", connector.id))?
                else {
                    println!("{}: OpenAI runtime key missing", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                let profile_directory = paths
                    .data_dir
                    .join("connectors")
                    .join(&connector.id)
                    .join("openai-profiles");
                let health_directory = paths.state_dir.join("connectors").join(&connector.id);
                let profile = OpenAiTunnelProfile::builder(
                    &settings.profile,
                    &settings.tunnel_id,
                    OpenAiMcpTarget::runonmine_stdio(
                        std::env::current_exe()?.canonicalize()?,
                        &connector.id,
                    )?,
                )
                .profile_directory(profile_directory)
                .health_address(format!("127.0.0.1:{}", settings.health_port).parse()?)
                .health_url_file(health_directory.join("tunnel-health.url"))
                .build();
                match profile {
                    Ok(profile) => {
                        let report = run_once(
                            profile.doctor_command(
                                &binary,
                                SecretValue::new(runtime_key.expose_secret().to_owned())?,
                            )?,
                            std::time::Duration::from_secs(30),
                            256 * 1_024,
                        )
                        .await?;
                        if report.success {
                            println!("{}: tunnel-client doctor passed", connector.id);
                        } else {
                            println!("{}: tunnel-client doctor FAILED", connector.id);
                            failures = failures.saturating_add(1);
                        }
                    }
                    Err(_) => {
                        println!("{}: OpenAI profile FAILED", connector.id);
                        failures = failures.saturating_add(1);
                    }
                }
            }
            ConnectorKind::LocalStdio => {}
        }
    }
    let status = UserService::discover()?.status()?;
    println!(
        "User service: installed={}, running={}",
        status.installed, status.running
    );
    #[cfg(target_os = "linux")]
    {
        let status = LinuxSystemService::discover()?.status()?;
        println!(
            "System service: installed={}, running={}",
            status.installed, status.running
        );
    }
    if failures > 0 {
        bail!("doctor found {failures} failing check(s)");
    }
    println!("Doctor result: healthy");
    Ok(())
}

fn audit(command: AuditCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    let state = StateStore::open(&paths.state_db()).context("run `runonmine setup` first")?;
    match command {
        AuditCommand::Tail { limit } => {
            for record in state.audit_tail(limit)? {
                println!(
                    "{}  {}  {}  {:?}  {}",
                    record.sequence,
                    record.event.timestamp.to_rfc3339(),
                    record.event.tool_name,
                    record.event.outcome,
                    record.event.summary
                );
            }
        }
        AuditCommand::Export { output, limit } => {
            atomic_write(
                &output,
                &serde_json::to_vec_pretty(&state.audit_tail(limit)?)?,
            )?;
            println!("Exported audit records to {}.", output.display());
        }
    }
    Ok(())
}

fn prompt_required(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let value = input.trim().to_owned();
    if value.is_empty() {
        bail!("a value is required");
    }
    Ok(value)
}

fn spawn_sibling(name: &str, args: &[&str]) -> Result<()> {
    let executable = sibling_executable(name)?;
    let status = ProcessCommand::new(executable).args(args).status()?;
    if !status.success() {
        bail!("{name} exited unsuccessfully");
    }
    Ok(())
}

fn sibling_executable(name: &str) -> Result<PathBuf> {
    let current = std::env::current_exe()?;
    let directory = current
        .parent()
        .context("RunOnMine executable has no parent directory")?;
    #[cfg(windows)]
    let executable = directory.join(format!("{name}.exe"));
    #[cfg(not(windows))]
    let executable = directory.join(name);
    if !executable.is_file() {
        bail!("{} was not found", executable.display());
    }
    Ok(executable)
}

#[cfg(unix)]
fn install_admin_helper(helper: &Path, allowed_programs: &[PathBuf]) -> Result<()> {
    use std::ffi::OsString;

    let output = ProcessCommand::new("id")
        .arg("-u")
        .output()
        .context("failed to determine the current user id")?;
    if !output.status.success() {
        bail!("failed to determine the current user id");
    }
    let effective_uid = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let owner_uid = if effective_uid == "0" {
        std::env::var("SUDO_UID")
            .context("install as your normal account or provide a sudo caller identity")?
    } else {
        effective_uid
    };
    let mut arguments = vec![
        OsString::from("install"),
        OsString::from("--owner-uid"),
        OsString::from(owner_uid),
    ];
    for program in allowed_programs {
        arguments.push(OsString::from("--allow-program"));
        arguments.push(program.as_os_str().to_owned());
    }
    run_elevated_helper(helper, &arguments)
}

#[cfg(windows)]
fn install_admin_helper(helper: &Path, allowed_programs: &[PathBuf]) -> Result<()> {
    use runonmine_platform::helper::{OwnerIdentity, resolve_install_owner};
    use std::ffi::OsString;

    let OwnerIdentity::WindowsSid { sid } = resolve_install_owner(None, None)? else {
        bail!("failed to determine the Windows owner SID");
    };
    let mut arguments = vec![
        OsString::from("install"),
        OsString::from("--owner-sid"),
        OsString::from(sid),
    ];
    for program in allowed_programs {
        arguments.push(OsString::from("--allow-program"));
        arguments.push(program.as_os_str().to_owned());
    }
    run_elevated_helper(helper, &arguments)
}

#[cfg(unix)]
fn run_elevated_helper(helper: &Path, arguments: &[std::ffi::OsString]) -> Result<()> {
    run_process(
        ProcessCommand::new("sudo")
            .arg("--")
            .arg(helper)
            .args(arguments),
    )
}

#[cfg(windows)]
fn run_elevated_helper(helper: &Path, arguments: &[std::ffi::OsString]) -> Result<()> {
    fn quote_powershell(value: &str) -> String {
        format!("'{}'", value.replace('\'', "''"))
    }

    let argument_list = arguments
        .iter()
        .map(|value| quote_powershell(&value.to_string_lossy()))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "$p=Start-Process -FilePath {} -ArgumentList @({argument_list}) -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
        quote_powershell(&helper.to_string_lossy())
    );
    run_process(ProcessCommand::new("powershell.exe").args([
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &script,
    ]))
}

fn run_process(command: &mut ProcessCommand) -> Result<()> {
    let status = command.status().context("failed to start helper process")?;
    if !status.success() {
        bail!("privileged helper operation failed");
    }
    Ok(())
}

fn validate_profile_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("profile names may only contain letters, numbers, '-' and '_'");
    }
    Ok(())
}

fn runonmine_browser_guard(url: &Url) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        bail!("CDP URL must use HTTP or WebSocket transport");
    }
    let host = url.host_str().unwrap_or_default();
    if !matches!(host, "127.0.0.1" | "::1" | "localhost") {
        bail!("external CDP endpoints must use loopback");
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to replace a symlink: {}", path.display());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("failed to atomically replace export")?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runonmine_core::secrets::SecretStore;

    #[cfg(unix)]
    #[test]
    fn managed_binary_symlink_is_rejected_before_receipt_verification() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let root = tempfile::tempdir()?;
        let paths = AppPaths::under(root.path());
        let managed = paths.data_dir.join("bin");
        std::fs::create_dir_all(&managed)?;
        let target = root.path().join("outside-cloudflared");
        std::fs::write(&target, b"not executed")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))?;
        let candidate = managed.join(BinaryKind::Cloudflared.executable_name());
        symlink(&target, &candidate)?;

        let result = load_connector_binary(
            &paths,
            BinaryKind::Cloudflared,
            ReleaseProvider::Cloudflared,
            Some(&candidate),
        );
        assert!(result.is_err());
        Ok(())
    }

    #[derive(Default)]
    struct MemorySecretStore {
        values: std::sync::Mutex<std::collections::BTreeMap<String, String>>,
    }

    impl runonmine_core::secrets::SecretStore for MemorySecretStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            let values = self
                .values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret store lock failed"))?;
            Ok(values.get(name).cloned().map(SecretString::from))
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret store lock failed"))?
                .insert(name.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("test secret store lock failed"))?
                .remove(name);
            Ok(())
        }
    }

    #[test]
    fn secret_deletion_is_committed_with_config_save() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        let store = MemorySecretStore::default();
        let name = "connector.local.local_http_token".to_owned();
        store.set(&name, &SecretString::from("token".to_owned()))?;
        save_config_after_secret_deletion(
            &AppConfig::default(),
            &config_path,
            &store,
            std::slice::from_ref(&name),
        )?;
        assert!(store.get(&name)?.is_none());
        assert!(config_path.is_file());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn secret_deletion_rolls_back_when_config_save_fails() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let target = directory.path().join("target.toml");
        std::fs::write(&target, "unchanged")?;
        let config_path = directory.path().join("config.toml");
        symlink(&target, &config_path)?;
        let store = MemorySecretStore::default();
        let name = "connector.local.local_http_token".to_owned();
        store.set(&name, &SecretString::from("token".to_owned()))?;
        assert!(
            save_config_after_secret_deletion(
                &AppConfig::default(),
                &config_path,
                &store,
                std::slice::from_ref(&name),
            )
            .is_err()
        );
        assert_eq!(
            store
                .get(&name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("token".to_owned())
        );
        Ok(())
    }

    #[test]
    fn connector_secret_sets_are_complete() {
        assert!(connector_secret_suffixes(ConnectorKind::LocalStdio).is_empty());
        assert_eq!(
            connector_secret_suffixes(ConnectorKind::LocalHttp),
            &["local_http_token"]
        );
        assert!(
            connector_secret_suffixes(ConnectorKind::CloudflareOauth)
                .contains(&"github_client_secret")
        );
    }
}
