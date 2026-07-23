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
    BinaryDiscovery, BinaryInstaller, BinaryKind, BinaryProbe, GitHubReleaseResolver,
    InstalledBinary, ReleaseChannel, ReleaseProvider, SecretValue, run_once,
};
use runonmine_core::secrets::default_secret_store;
use runonmine_core::{
    AppConfig, AppPaths, ApprovalDecision, Capability, CloudflareNamedSettings,
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
    Cloudflare {
        #[command(subcommand)]
        command: CloudflareCommand,
    },
    Openai(OpenAiConnectArgs),
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
    Deny { id: Uuid },
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
    Create {
        #[arg(long, default_value = "default")]
        name: String,
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
    /// Stop the Linux system service instead of the current user's service.
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
                policy_preset: PolicyPreset::Safe,
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
            let id = Uuid::new_v4().to_string();
            let public_base_url = Url::parse(&format!("https://{hostname}/"))
                .context("public Cloudflare hostname is invalid")?;
            config.connectors.push(ConnectorConfig {
                id: id.clone(),
                name: "Cloudflare Named Tunnel with OAuth".to_owned(),
                kind: ConnectorKind::CloudflareOauth,
                enabled: true,
                policy_preset: PolicyPreset::Safe,
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
                    github_id: args.github_owner_id,
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
                policy_preset: PolicyPreset::Safe,
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
    let discovery = BinaryDiscovery::new(vec![managed_directory.clone()]);
    if let Some(binary) = discovery.discover(kind, explicit_path)? {
        BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await?;
        return Ok(binary);
    }
    println!("Downloading the latest verified official connector binary...");
    let artifact = GitHubReleaseResolver::production()?
        .resolve(provider, &ReleaseChannel::Latest)
        .await?;
    let destination = managed_directory.join(kind.executable_name());
    BinaryInstaller::production()?
        .install(&artifact, &destination)
        .await?;
    let binary = InstalledBinary::from_verified_path(kind, &destination)?;
    BinaryProbe::run(&binary, std::time::Duration::from_secs(10)).await?;
    Ok(binary)
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
            let request = store
                .approval_status(args.id)?
                .context("approval was not found")?;
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
            if args.always {
                let mut config = AppConfig::load(&paths.config_file())?;
                let connector = config
                    .connector_mut(&request.connector_id)
                    .context("approval connector is no longer configured")?;
                connector
                    .tool_overrides
                    .insert(request.tool_name.clone(), PolicyMode::Allow);
                config.save(&paths.config_file())?;
            }
            println!(
                "Approved {} ({decision:?}). Ten-minute grants apply only to the exact arguments shown.",
                args.id
            );
        }
        ApprovalCommand::Deny { id } => {
            if !store.resolve_approval(id, ApprovalDecision::Deny)? {
                bail!("approval is no longer pending or has expired");
            }
            println!("Denied {id}.");
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
            std::fs::create_dir_all(&directory)?;
            config.browser.profile_name = name;
            config.browser.external_cdp_url = None;
            config.save(&paths.config_file())?;
            println!(
                "Created isolated browser profile at {}.",
                directory.display()
            );
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
                    "Private-network browser access enabled. Remote connectors can reach local services."
                );
            } else {
                println!("Private-network browser access disabled.");
            }
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

    if arguments.system {
        let service = LinuxSystemService::discover()?;
        if service.status().is_ok_and(|status| status.running) {
            service.stop()?;
        }
    } else {
        let service = UserService::discover()?;
        if service.status().is_ok_and(|status| status.running) {
            service.stop()?;
        }
    }

    let store = StateStore::open(&paths.state_db())?;
    let (denied, temporary_grants) = store.emergency_lock()?;
    let oauth = SqliteOAuthStore::open(&paths.state_db())?;
    let revoked_tokens = oauth.emergency_revoke_all()?;

    let config = AppConfig::load(&paths.config_file())?;
    let secrets = default_secret_store(&paths)?;
    let mut rotated_quick_tunnels = 0_usize;
    let mut removed_openai_keys = 0_usize;
    for connector in &config.connectors {
        match connector.kind {
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
            ConnectorKind::LocalStdio
            | ConnectorKind::LocalHttp
            | ConnectorKind::CloudflareOauth => {}
        }
    }

    println!("RunOnMine is locked.");
    println!("Denied pending approvals: {denied}");
    println!("Cleared temporary grants: {temporary_grants}");
    println!("Revoked OAuth tokens: {revoked_tokens}");
    println!("Rotated Quick Tunnel secrets: {rotated_quick_tunnels}");
    println!("Removed OpenAI runtime keys: {removed_openai_keys}");
    println!("Restart and reconnect explicitly when access should be restored.");
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
    let discovery = BinaryDiscovery::new(vec![paths.data_dir.join("bin")]);
    let secrets = default_secret_store(&paths)?;
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        match connector.kind {
            ConnectorKind::CloudflareQuick => {
                let Some(settings) = &connector.cloudflare_quick else {
                    println!("{}: Cloudflare Quick settings FAILED", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                match discovery.discover(
                    BinaryKind::Cloudflared,
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
                match discovery.discover(
                    BinaryKind::Cloudflared,
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
            }
            ConnectorKind::OpenAiTunnel => {
                let Some(settings) = &connector.openai_tunnel else {
                    println!("{}: OpenAI settings FAILED", connector.id);
                    failures = failures.saturating_add(1);
                    continue;
                };
                let Some(binary) = discovery.discover(
                    BinaryKind::OpenAiTunnelClient,
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
            ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => {}
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
