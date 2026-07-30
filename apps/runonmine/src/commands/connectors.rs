use super::connector_transactions::{
    commit_new_connector, disable_local_http_transactionally, enable_local_http_transactionally,
    ensure_connector_credentials, local_http_secret_name, update_config_with_secrets,
};
#[allow(clippy::wildcard_imports)]
use super::*;
use std::io::Read as _;

pub(crate) fn setup(roots: &[PathBuf]) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let mut canonical_roots = Vec::with_capacity(roots.len());
    for root in roots {
        let canonical = std::fs::canonicalize(root)
            .with_context(|| format!("allowed root does not exist: {}", root.display()))?;
        if !canonical.is_dir() {
            bail!("allowed root is not a directory: {}", canonical.display());
        }
        canonical_roots.push(canonical);
    }
    let allowed_roots = AppConfig::update(&paths.config_file(), move |config| {
        for canonical in canonical_roots {
            if !config.allowed_roots.contains(&canonical) {
                config.allowed_roots.push(canonical);
            }
        }
        config.allowed_roots.sort();
        Ok(config.allowed_roots.clone())
    })?;
    let _state = StateStore::open(&paths.state_db())?;
    let service_reconciled = UserService::discover()?.reconcile_allowed_roots(&allowed_roots)?;
    println!("RunOnMine is initialized.");
    println!("Config: {}", paths.config_file().display());
    println!("Allowed roots: {}", allowed_roots.len());
    if service_reconciled {
        println!("Installed Linux user service sandbox updated for the selected roots.");
    }
    if allowed_roots.is_empty() {
        println!("File tools remain unavailable until at least one --root is added.");
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn connect(command: ConnectCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config_path = paths.config_file();
    let secrets = default_secret_store(&paths)?;
    let reconciled = reconcile_pending_connector_removals(&paths)?;
    if reconciled > 0 {
        println!("Completed {reconciled} pending connector removal(s).");
    }
    let config = AppConfig::load_or_create(&config_path)?;
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
            let _removal_lock = ConnectorRemovalLock::acquire(&paths)?;
            ConnectorRemovalJournal::new(&paths).ensure_id_available(&connector)?;
            AppConfig::update(&config_path, |config| {
                let item = config
                    .connector(&connector)
                    .context("connector was not found")?;
                ensure_connector_credentials(item, secrets.as_ref())?;
                config
                    .connector_mut(&connector)
                    .context("connector was not found")?
                    .enabled = true;
                Ok(())
            })?;
            println!("Enabled connector {connector}.");
            reconcile_running_agent_after_connector_change()?;
        }
        ConnectCommand::Disable { connector } => {
            let _removal_lock = ConnectorRemovalLock::acquire(&paths)?;
            ConnectorRemovalJournal::new(&paths).ensure_id_available(&connector)?;
            AppConfig::update(&config_path, |config| {
                config
                    .connector_mut(&connector)
                    .context("connector was not found")?
                    .enabled = false;
                Ok(())
            })?;
            println!("Disabled connector {connector}.");
            reconcile_running_agent_after_connector_change()?;
        }
        ConnectCommand::Remove { connector, confirm } => {
            if confirm != "REMOVE" {
                bail!("connector removal requires --confirm REMOVE");
            }
            if remove_connector_recoverably(&paths, secrets.as_ref(), &connector)? {
                println!("Removed connector {connector} and reconciled all local state.");
                reconcile_running_agent_after_connector_change()?;
            } else {
                println!("Connector {connector} is already absent and has no pending cleanup.");
            }
        }
        ConnectCommand::LocalHttp { command } => match command {
            LocalHttpCommand::Enable { token_output } => {
                validate_private_output_path(token_output.as_deref())?;
                let token = generate_path_secret();
                let secret = SecretString::from(token.clone());
                let (connector_id, port) = enable_local_http_transactionally(
                    &paths,
                    &config_path,
                    secrets.as_ref(),
                    &secret,
                )?;
                report_local_http_credentials(
                    port,
                    &connector_id,
                    &token,
                    token_output.as_deref(),
                )?;
                reconcile_running_agent_after_connector_change()?;
            }
            LocalHttpCommand::Disable => {
                let connector_id =
                    disable_local_http_transactionally(&paths, &config_path, secrets.as_ref())?;
                println!(
                    "Local HTTP connector {connector_id} is disabled and its token was deleted."
                );
                reconcile_running_agent_after_connector_change()?;
            }
            LocalHttpCommand::Rotate { token_output } => {
                validate_private_output_path(token_output.as_deref())?;
                let token = generate_path_secret();
                let secret = SecretString::from(token.clone());
                let _removal_lock = ConnectorRemovalLock::acquire(&paths)?;
                let (connector_id, port) = update_config_with_secrets(
                    &config_path,
                    secrets.as_ref(),
                    |config, transaction| {
                        let connector = config
                            .connectors
                            .iter()
                            .find(|connector| connector.kind == ConnectorKind::LocalHttp)
                            .context("local HTTP connector is missing")?;
                        if !connector.enabled {
                            bail!("local HTTP is disabled; enable it before rotating its token");
                        }
                        let connector_id = connector.id.clone();
                        transaction.set(&local_http_secret_name(&connector_id), &secret)?;
                        Ok((connector_id, config.port))
                    },
                )?;
                report_local_http_credentials(
                    port,
                    &connector_id,
                    &token,
                    token_output.as_deref(),
                )?;
            }
            LocalHttpCommand::Status { token_output } => {
                validate_private_output_path(token_output.as_deref())?;
                let connector = config
                    .connectors
                    .iter()
                    .find(|connector| connector.kind == ConnectorKind::LocalHttp)
                    .context("local HTTP connector is missing")?;
                let connector_id = connector.id.clone();
                let enabled = connector.enabled;
                let secret_name = local_http_secret_name(&connector_id);
                println!("Connector: {connector_id}");
                println!("Enabled: {enabled}");
                println!("Endpoint: http://127.0.0.1:{}/mcp", config.port);
                let token = secrets.get(&secret_name)?;
                println!("Token configured: {}", token.is_some());
                if let Some(output) = token_output.as_deref() {
                    let token = token.context("local HTTP token is not configured")?;
                    write_local_http_credentials(
                        output,
                        config.port,
                        &connector_id,
                        token.expose_secret(),
                    )?;
                    println!("Credentials written to {}.", output.display());
                } else {
                    println!(
                        "Bearer token is not printed. Use --token-output <absolute-file> to export it securely."
                    );
                }
            }
        },
        ConnectCommand::Cloudflare {
            command:
                CloudflareCommand::Quick {
                    rotate,
                    cloudflared,
                },
        } => {
            if let Some(id) = rotate {
                let path_secret = SecretString::from(generate_path_secret());
                update_config_with_secrets(
                    &config_path,
                    secrets.as_ref(),
                    |config, transaction| {
                        let connector = config.connector(&id).context("connector was not found")?;
                        if connector.kind != ConnectorKind::CloudflareQuick {
                            bail!(
                                "secret rotation is only valid for a Cloudflare Quick Tunnel connector"
                            );
                        }
                        transaction.set(&format!("connector.{id}.path_secret"), &path_secret)
                    },
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
            let connector = ConnectorConfig {
                id: id.clone(),
                name: "Cloudflare Quick Tunnel".to_owned(),
                kind: ConnectorKind::CloudflareQuick,
                enabled: true,
                policy_preset: PolicyPreset::Safe,
                pack_overrides: BTreeMap::default(),
                tool_overrides: BTreeMap::default(),
                policy_rules: Vec::new(),
                public_base_url: None,
                cloudflare_quick: Some(CloudflareQuickSettings {
                    cloudflared_path: Some(binary.path),
                    ..CloudflareQuickSettings::default()
                }),
                cloudflare_named: None,
                oauth_owner: None,
                openai_tunnel: None,
            };
            commit_new_connector(
                connector,
                &paths,
                &config_path,
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
            validate_private_output_path(args.registration_token_output.as_deref())?;
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
            let client_secret =
                read_secret(args.client_secret_stdin, "GitHub OAuth client secret: ")?;
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
            let registration_token = generate_path_secret();
            let public_base_url = Url::parse(&format!("https://{hostname}/"))
                .context("public Cloudflare hostname is invalid")?;
            let connector = ConnectorConfig {
                id: id.clone(),
                name: "Cloudflare Named Tunnel with OAuth".to_owned(),
                kind: ConnectorKind::CloudflareOauth,
                enabled: true,
                policy_preset: PolicyPreset::Safe,
                pack_overrides: BTreeMap::default(),
                tool_overrides: BTreeMap::default(),
                policy_rules: Vec::new(),
                public_base_url: Some(public_base_url),
                cloudflare_quick: None,
                cloudflare_named: Some(CloudflareNamedSettings {
                    tunnel_id,
                    credentials_file,
                    hostname: hostname.clone(),
                    cloudflared_path: Some(binary.path),
                    metrics_port: 47_824,
                }),
                oauth_owner: Some(OAuthOwnerSettings {
                    github_login: owner_login,
                    github_id: owner_id,
                }),
                openai_tunnel: None,
            };
            commit_new_connector(
                connector,
                &paths,
                &config_path,
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
                    (
                        format!("connector.{id}.oauth_registration_token"),
                        SecretString::from(registration_token.clone()),
                    ),
                ],
            )?;
            println!("Created OAuth connector {id}.");
            println!("Register {callback_url} in the GitHub OAuth app.");
            if let Some(output) = args.registration_token_output.as_deref() {
                write_oauth_registration_credentials(
                    output,
                    &id,
                    &format!("https://{hostname}/oauth/register"),
                    &registration_token,
                )
                .with_context(|| {
                    format!(
                        "the registration token remains in the credential store, but secure export to {} failed; retry with `runonmine oauth registration-token export {id} --output <absolute-file>`",
                        output.display()
                    )
                })?;
                println!(
                    "OAuth registration credentials written to {}.",
                    output.display()
                );
            } else {
                println!(
                    "The OAuth registration token was not printed. Export it with `runonmine oauth registration-token export {id} --output <absolute-file>`."
                );
            }
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
            let api_key = read_secret(args.api_key_stdin, "OpenAI runtime API key: ")?;
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
            let connector = ConnectorConfig {
                id: id.clone(),
                name: "OpenAI Secure MCP Tunnel".to_owned(),
                kind: ConnectorKind::OpenAiTunnel,
                enabled: true,
                policy_preset: PolicyPreset::Safe,
                pack_overrides: BTreeMap::default(),
                tool_overrides: BTreeMap::default(),
                policy_rules: Vec::new(),
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
            };
            commit_new_connector(
                connector,
                &paths,
                &config_path,
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

#[derive(serde::Serialize)]
struct LocalHttpCredentialExport<'a> {
    version: u8,
    connector_id: &'a str,
    endpoint: String,
    authorization_scheme: &'static str,
    bearer_token: &'a str,
}

fn reconcile_running_agent_after_connector_change() -> Result<()> {
    let service = runonmine_platform::UserService::discover()?;
    if service.restart_if_running()? {
        println!("Running agent restarted; live sessions and managed transports were reconciled.");
    }
    Ok(())
}

fn report_local_http_credentials(
    port: u16,
    connector_id: &str,
    token: &str,
    token_output: Option<&Path>,
) -> Result<()> {
    println!("Local HTTP connector {connector_id} is enabled.");
    println!("Endpoint: http://127.0.0.1:{port}/mcp");
    println!("Bearer token stored in the operating-system credential store.");
    if let Some(output) = token_output {
        write_local_http_credentials(output, port, connector_id, token).with_context(|| {
            format!(
                "the token was updated and remains in the credential store, but secure export to {} failed; retry with `local-http status --token-output <absolute-file>`",
                output.display()
            )
        })?;
        println!("Credentials written to {}.", output.display());
    } else {
        println!(
            "The token was not printed. Use `local-http status --token-output <absolute-file>` to export it securely."
        );
    }
    Ok(())
}

pub(super) fn validate_private_output_path(path: Option<&Path>) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    if !path.is_absolute() {
        bail!("credential output must be an absolute path");
    }
    let parent = path
        .parent()
        .context("credential output has no parent directory")?;
    if !parent.is_dir() {
        bail!("credential output parent must already exist");
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => bail!(
            "refusing to overwrite existing credential output: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_local_http_credentials(
    path: &Path,
    port: u16,
    connector_id: &str,
    token: &str,
) -> Result<()> {
    write_private_json_new(
        path,
        &LocalHttpCredentialExport {
            version: 1,
            connector_id,
            endpoint: format!("http://127.0.0.1:{port}/mcp"),
            authorization_scheme: "Bearer",
            bearer_token: token,
        },
    )
}

#[derive(serde::Serialize)]
struct OAuthRegistrationCredentialExport<'a> {
    version: u8,
    connector_id: &'a str,
    registration_endpoint: &'a str,
    authorization_scheme: &'static str,
    initial_access_token: &'a str,
}

pub(super) fn write_oauth_registration_credentials(
    path: &Path,
    connector_id: &str,
    registration_endpoint: &str,
    token: &str,
) -> Result<()> {
    write_private_json_new(
        path,
        &OAuthRegistrationCredentialExport {
            version: 1,
            connector_id,
            registration_endpoint,
            authorization_scheme: "Bearer",
            initial_access_token: token,
        },
    )
}

fn write_private_json_new(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    validate_private_output_path(Some(path))?;
    let mut contents = serde_json::to_vec_pretty(value)?;
    contents.push(b'\n');
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).with_context(|| {
        format!(
            "failed to create private credential output {}",
            path.display()
        )
    })?;
    let result = (|| -> Result<()> {
        file.write_all(&contents)?;
        file.sync_all()?;
        runonmine_platform::restrict_current_user_file(path)?;
        #[cfg(unix)]
        {
            let parent = path
                .parent()
                .context("credential output has no parent directory")?;
            std::fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        drop(file);
        let _ignored = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

pub(super) fn read_secret(from_stdin: bool, prompt: &str) -> Result<String> {
    if !from_stdin {
        return rpassword::prompt_password(prompt).map_err(Into::into);
    }
    let mut value = String::new();
    std::io::stdin()
        .take(16 * 1_024)
        .read_to_string(&mut value)
        .context("failed to read secret from standard input")?;
    while value.ends_with(['\n', '\r']) {
        value.pop();
    }
    Ok(value)
}

pub(super) fn value_or_prompt(value: Option<String>, prompt: &str) -> Result<String> {
    value.map_or_else(|| prompt_required(prompt), Ok)
}

pub(super) async fn ensure_binary(
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

pub(super) fn managed_receipt_path(directory: &Path, kind: BinaryKind) -> PathBuf {
    directory.join(format!("{}.receipt.json", kind.executable_name()))
}

pub(super) fn write_install_receipt(path: &Path, receipt: &InstallReceipt) -> Result<()> {
    atomic_write(path, &serde_json::to_vec_pretty(receipt)?)?;
    restrict_private_file(path)
}

pub(super) fn read_install_receipt(path: &Path) -> Result<InstallReceipt> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("managed binary receipt is missing: {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 64 * 1_024 {
        bail!("managed binary receipt is not a small regular file");
    }
    serde_json::from_slice(&std::fs::read(path)?).context("managed binary receipt is invalid")
}

pub(super) fn verify_managed_binary(
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

pub(super) fn load_connector_binary(
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

pub(super) fn ensure_private_directory(path: &Path) -> Result<()> {
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

pub(super) fn restrict_private_file(path: &Path) -> Result<()> {
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

pub(super) fn generate_path_secret() -> String {
    let mut raw = [0_u8; 32];
    rand::rng().fill_bytes(&mut raw);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_http_credentials_use_private_no_overwrite_output() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("local-http.json");
        write_local_http_credentials(&output, 47_821, "local-http", "secret-token")?;
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&output)?)?;
        assert_eq!(value["connector_id"], "local-http");
        assert_eq!(value["endpoint"], "http://127.0.0.1:47821/mcp");
        assert_eq!(value["authorization_scheme"], "Bearer");
        assert_eq!(value["bearer_token"], "secret-token");
        assert!(
            write_local_http_credentials(&output, 47_821, "local-http", "other-token").is_err()
        );
        let after_failed_overwrite: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&output)?)?;
        assert_eq!(value, after_failed_overwrite);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&output)?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn oauth_registration_credentials_use_private_no_overwrite_output() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let output = temporary.path().join("oauth-registration.json");
        write_oauth_registration_credentials(
            &output,
            "connector-id",
            "https://mcp.example.com/oauth/register",
            "registration-token",
        )?;
        let value: serde_json::Value = serde_json::from_slice(&std::fs::read(&output)?)?;
        assert_eq!(value["connector_id"], "connector-id");
        assert_eq!(
            value["registration_endpoint"],
            "https://mcp.example.com/oauth/register"
        );
        assert_eq!(value["authorization_scheme"], "Bearer");
        assert_eq!(value["initial_access_token"], "registration-token");
        assert!(
            write_oauth_registration_credentials(
                &output,
                "connector-id",
                "https://mcp.example.com/oauth/register",
                "other-token",
            )
            .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&output)?.permissions().mode() & 0o777,
                0o600
            );
        }
        Ok(())
    }

    #[test]
    fn local_http_credential_output_requires_absolute_new_path() -> Result<()> {
        assert!(validate_private_output_path(Some(Path::new("relative.json"))).is_err());
        let temporary = tempfile::tempdir()?;
        assert!(
            validate_private_output_path(Some(&temporary.path().join("missing/secret.json")))
                .is_err()
        );
        Ok(())
    }
}
