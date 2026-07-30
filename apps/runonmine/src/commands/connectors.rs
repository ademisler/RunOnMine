use super::connector_transactions::{
    commit_new_connector, disable_local_http_transactionally, enable_local_http_transactionally,
    ensure_connector_credentials, local_http_secret_name, update_config_with_secrets,
};
use super::openai_connector_transaction::{
    OpenAiBinaryStaging, OpenAiConnectorStaging, commit_prepared_openai_connector,
    validate_new_openai_connector,
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
                    "{}  {:?}  enabled={}  preset={:?}  binary_trust={}  {}",
                    connector.id,
                    connector.kind,
                    connector.enabled,
                    connector.policy_preset,
                    connector_binary_trust_label(&paths, connector),
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
        ConnectCommand::UpdateManagedBinaries => {
            let cloudflare_updated = update_managed_cloudflared(&paths, &config_path).await?;
            let openai_updated = update_managed_openai(&paths, &config_path).await?;
            if cloudflare_updated == 0 {
                println!("No managed Cloudflare connector paths required an update.");
            } else {
                println!("Updated {cloudflare_updated} managed Cloudflare connector path(s).");
            }
            if openai_updated == 0 {
                println!("No managed OpenAI tunnel-client paths required an update.");
            } else {
                println!("Updated {openai_updated} managed OpenAI tunnel-client path(s).");
            }
        }
        ConnectCommand::PinExternalBinaries => {
            let pinned = pin_configured_external_binaries(&paths, &config)?;
            if pinned == 0 {
                println!("No unpinned external connector binaries were configured.");
            } else {
                println!("Pinned {pinned} external connector binary path(s).");
            }
        }
        ConnectCommand::Openai(args) => {
            validate_profile_name(&args.profile)?;
            let tunnel_id = value_or_prompt(args.tunnel_id, "OpenAI tunnel ID: ")?;
            let api_key = read_secret(args.api_key_stdin, "OpenAI runtime API key: ")?;
            if api_key.trim().is_empty() {
                bail!("runtime API key must not be empty");
            }
            let id = Uuid::new_v4().to_string();
            let configured_binary_path =
                OpenAiBinaryStaging::configured_path(&paths, args.tunnel_client.as_deref())?;
            let mut connector_candidate = ConnectorConfig {
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
                    tunnel_id: tunnel_id.clone(),
                    profile: args.profile.clone(),
                    tunnel_client_path: Some(configured_binary_path.clone()),
                    health_port: 47_823,
                }),
            };
            validate_new_openai_connector(&paths, &config_path, connector_candidate.clone())?;
            let binary =
                OpenAiBinaryStaging::prepare(&paths, args.tunnel_client.as_deref()).await?;
            let actual_binary_path = binary.configured_binary_path();
            connector_candidate
                .openai_tunnel
                .as_mut()
                .context("OpenAI connector settings disappeared during setup")?
                .tunnel_client_path = Some(actual_binary_path);
            let connector =
                validate_new_openai_connector(&paths, &config_path, connector_candidate)?;
            let staging = OpenAiConnectorStaging::prepare(&paths, &id)?;
            let profile_directory = staging.profile_directory();
            let profile = OpenAiTunnelProfile::builder(
                &args.profile,
                &tunnel_id,
                OpenAiMcpTarget::runonmine_stdio(std::env::current_exe()?.canonicalize()?, &id)?,
            )
            .profile_directory(profile_directory.clone())
            .health_address("127.0.0.1:47823".parse()?)
            .health_url_file(staging.health_directory().join("tunnel-health.url"))
            .build()?;
            let initialized = run_once(
                profile.init_command(binary.binary())?,
                std::time::Duration::from_secs(30),
                128 * 1_024,
            )
            .await?;
            if !initialized.success {
                bail!("tunnel-client profile initialization failed");
            }
            restrict_private_file(&profile_directory.join(format!("{}.yaml", args.profile)))?;
            let doctor = run_once(
                profile.doctor_command(binary.binary(), SecretValue::new(api_key.clone())?)?,
                std::time::Duration::from_secs(30),
                256 * 1_024,
            )
            .await?;
            if !doctor.success {
                bail!("tunnel-client doctor failed; verify tunnel permissions and the runtime key");
            }
            commit_prepared_openai_connector(
                connector,
                &paths,
                &config_path,
                secrets.as_ref(),
                &[(
                    format!("connector.{id}.runtime_api_key"),
                    SecretString::from(api_key),
                )],
                binary,
                staging,
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
    if let Some(path) = explicit_path {
        let binary = InstalledBinary::from_verified_path(kind, path)?;
        BinaryProbe::run_compatible(&binary, std::time::Duration::from_secs(10)).await?;
        return Ok(binary);
    }

    let store = managed_binary_store(&paths.data_dir, kind);
    if let Some(active) = store.resolve_active()? {
        let binary = InstalledBinary::from_verified_path(kind, &active.binary_path)?;
        verify_managed_binary(&binary, provider, &active.receipt_path)?;
        BinaryProbe::run_compatible(&binary, std::time::Duration::from_secs(10)).await?;
        return Ok(binary);
    }

    println!("Downloading the latest verified official connector binary...");
    let prepared = prepare_latest_managed_binary(paths, kind, provider).await?;
    let activation = prepared.store.activate(&prepared.version)?;
    if let Err(error) =
        BinaryProbe::run_compatible(&prepared.binary, std::time::Duration::from_secs(10)).await
    {
        prepared.store.rollback(activation)?;
        return Err(error.context("managed binary probe failed and activation was rolled back"));
    }
    Ok(prepared.binary)
}

#[derive(Debug)]
pub(super) struct PreparedManagedBinary {
    pub(super) store: VersionedBinaryStore,
    pub(super) version: ManagedBinaryVersion,
    pub(super) binary: InstalledBinary,
}

pub(super) async fn prepare_latest_managed_binary(
    paths: &AppPaths,
    kind: BinaryKind,
    provider: ReleaseProvider,
) -> Result<PreparedManagedBinary> {
    let store = managed_binary_store(&paths.data_dir, kind);
    let staging_parent = paths.data_dir.join("managed-binary-staging");
    ensure_private_directory(&staging_parent)?;
    let staging = tempfile::Builder::new()
        .prefix("binary-")
        .tempdir_in(&staging_parent)?;
    let staged_path = staging.path().join(kind.executable_name());
    let artifact =
        SignedReleaseResolver::production()?.resolve(provider, &ReleaseChannel::Latest)?;
    let mut receipt = BinaryInstaller::production()?
        .install(&artifact, &staged_path)
        .await?;
    let staged = InstalledBinary::from_verified_path(kind, &staged_path)?;
    BinaryProbe::run_compatible(&staged, std::time::Duration::from_secs(10)).await?;
    let version_id = store.version_id_for_file(&staged_path)?;
    let target = store.version(&version_id)?;
    receipt.installed_path.clone_from(&target.binary_path);
    let version = store.prepare(&staged_path, &serde_json::to_vec_pretty(&receipt)?)?;
    let binary = InstalledBinary::from_verified_path(kind, &version.binary_path)?;
    verify_managed_binary(&binary, provider, &version.receipt_path)?;
    BinaryProbe::run_compatible(&binary, std::time::Duration::from_secs(10)).await?;
    Ok(PreparedManagedBinary {
        store,
        version,
        binary,
    })
}

#[derive(Debug)]
struct ManagedUpdateState {
    store: VersionedBinaryStore,
    activation: Option<runonmine_connectors::ManagedBinaryActivation>,
}

async fn update_managed_cloudflared(paths: &AppPaths, config_path: &Path) -> Result<usize> {
    let current = AppConfig::load_or_create(config_path)?;
    let mut candidates = 0_usize;
    for connector in &current.connectors {
        let Some((kind, _provider, path)) = connector_binary_path(connector) else {
            continue;
        };
        if kind == BinaryKind::Cloudflared
            && is_managed_connector_binary(&paths.data_dir, kind, path)?
        {
            candidates = candidates.saturating_add(1);
        }
    }
    if candidates == 0 {
        return Ok(0);
    }

    let prepared =
        prepare_latest_managed_binary(paths, BinaryKind::Cloudflared, ReleaseProvider::Cloudflared)
            .await?;
    let target_path = prepared.binary.path.clone();
    let mut state = ManagedUpdateState {
        store: prepared.store,
        activation: None,
    };
    AppConfig::update_with_activation(
        config_path,
        &mut state,
        |config, _state| rewrite_managed_cloudflare_paths(config, paths, &target_path),
        |_updated, state| {
            state.activation = Some(state.store.activate(&prepared.version)?);
            reconcile_running_agent_after_connector_change()
        },
        |state| match state.activation.take() {
            Some(activation) => state.store.rollback(activation),
            None => Ok(()),
        },
    )
}

fn rewrite_managed_cloudflare_paths(
    config: &mut AppConfig,
    paths: &AppPaths,
    target_path: &Path,
) -> Result<usize> {
    let mut updated = 0_usize;
    for connector in &mut config.connectors {
        let configured = match connector.kind {
            ConnectorKind::CloudflareQuick => connector
                .cloudflare_quick
                .as_ref()
                .and_then(|settings| settings.cloudflared_path.as_deref()),
            ConnectorKind::CloudflareOauth => connector
                .cloudflare_named
                .as_ref()
                .and_then(|settings| settings.cloudflared_path.as_deref()),
            ConnectorKind::LocalStdio | ConnectorKind::LocalHttp | ConnectorKind::OpenAiTunnel => {
                None
            }
        };
        let Some(configured) = configured else {
            continue;
        };
        if !is_managed_connector_binary(&paths.data_dir, BinaryKind::Cloudflared, configured)? {
            continue;
        }
        match connector.kind {
            ConnectorKind::CloudflareQuick => {
                connector
                    .cloudflare_quick
                    .as_mut()
                    .context("Cloudflare Quick settings are missing")?
                    .cloudflared_path = Some(target_path.to_path_buf());
            }
            ConnectorKind::CloudflareOauth => {
                connector
                    .cloudflare_named
                    .as_mut()
                    .context("Cloudflare OAuth settings are missing")?
                    .cloudflared_path = Some(target_path.to_path_buf());
            }
            ConnectorKind::LocalStdio | ConnectorKind::LocalHttp | ConnectorKind::OpenAiTunnel => {
                unreachable!("filtered connector kind")
            }
        }
        updated = updated.saturating_add(1);
    }
    Ok(updated)
}

async fn update_managed_openai(paths: &AppPaths, config_path: &Path) -> Result<usize> {
    let current = AppConfig::load_or_create(config_path)?;
    let mut candidates = 0_usize;
    for connector in &current.connectors {
        let Some(settings) = &connector.openai_tunnel else {
            continue;
        };
        let Some(path) = settings.tunnel_client_path.as_deref() else {
            continue;
        };
        if is_managed_connector_binary(&paths.data_dir, BinaryKind::OpenAiTunnelClient, path)? {
            candidates = candidates.saturating_add(1);
        }
    }
    if candidates == 0 {
        return Ok(0);
    }

    let prepared = prepare_latest_managed_binary(
        paths,
        BinaryKind::OpenAiTunnelClient,
        ReleaseProvider::OpenAiTunnelClient,
    )
    .await?;
    let target_path = prepared.binary.path.clone();
    let mut state = ManagedUpdateState {
        store: prepared.store,
        activation: None,
    };
    AppConfig::update_with_activation(
        config_path,
        &mut state,
        |config, _state| rewrite_managed_openai_paths(config, paths, &target_path),
        |_updated, state| {
            state.activation = Some(state.store.activate(&prepared.version)?);
            reconcile_running_agent_after_connector_change()
        },
        |state| match state.activation.take() {
            Some(activation) => state.store.rollback(activation),
            None => Ok(()),
        },
    )
}

fn rewrite_managed_openai_paths(
    config: &mut AppConfig,
    paths: &AppPaths,
    target_path: &Path,
) -> Result<usize> {
    let mut updated = 0_usize;
    for connector in &mut config.connectors {
        let Some(settings) = connector.openai_tunnel.as_mut() else {
            continue;
        };
        let Some(configured) = settings.tunnel_client_path.as_deref() else {
            continue;
        };
        if !is_managed_connector_binary(
            &paths.data_dir,
            BinaryKind::OpenAiTunnelClient,
            configured,
        )? {
            continue;
        }
        settings.tunnel_client_path = Some(target_path.to_path_buf());
        updated = updated.saturating_add(1);
    }
    Ok(updated)
}

#[cfg(test)]
fn existing_managed_binary(
    kind: BinaryKind,
    provider: ReleaseProvider,
    destination: &Path,
    receipt_path: &Path,
) -> Result<Option<InstalledBinary>> {
    let binary_present = safe_regular_file_presence(destination, "managed connector binary")?;
    let receipt_present = safe_regular_file_presence(receipt_path, "managed connector receipt")?;
    match (binary_present, receipt_present) {
        (false, false) => Ok(None),
        (true, true) => {
            let binary = InstalledBinary::from_verified_path(kind, destination)?;
            verify_managed_binary(&binary, provider, receipt_path).with_context(|| {
                format!(
                    "existing managed {} failed integrity verification; it was preserved for explicit repair or rollback",
                    kind.executable_name()
                )
            })?;
            Ok(Some(binary))
        }
        _ => bail!(
            "managed connector installation is incomplete; the existing binary or receipt was preserved for explicit repair"
        ),
    }
}

#[cfg(test)]
fn safe_regular_file_presence(path: &Path, description: &str) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{description} must be a regular non-symlink file")
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {description}")),
    }
}

pub(super) fn managed_receipt_path(directory: &Path, kind: BinaryKind) -> PathBuf {
    directory.join(format!("{}.receipt.json", kind.executable_name()))
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
    let Some(resolved) = resolve_connector_binary(
        &paths.data_dir,
        &paths.state_dir,
        kind,
        provider,
        configured_path,
    )?
    else {
        return Ok(None);
    };
    if resolved.trust == ExternalBinaryTrust::ExternalUnpinned {
        tracing::warn!(
            binary_path = %resolved.binary.path.display(),
            ?kind,
            "connector uses an unpinned external binary; run `runonmine connect pin-external-binaries`"
        );
    }
    Ok(Some(resolved.binary))
}

fn connector_binary_path(
    connector: &ConnectorConfig,
) -> Option<(BinaryKind, ReleaseProvider, &Path)> {
    match connector.kind {
        ConnectorKind::CloudflareQuick => connector
            .cloudflare_quick
            .as_ref()
            .and_then(|settings| settings.cloudflared_path.as_deref())
            .map(|path| (BinaryKind::Cloudflared, ReleaseProvider::Cloudflared, path)),
        ConnectorKind::CloudflareOauth => connector
            .cloudflare_named
            .as_ref()
            .and_then(|settings| settings.cloudflared_path.as_deref())
            .map(|path| (BinaryKind::Cloudflared, ReleaseProvider::Cloudflared, path)),
        ConnectorKind::OpenAiTunnel => connector
            .openai_tunnel
            .as_ref()
            .and_then(|settings| settings.tunnel_client_path.as_deref())
            .map(|path| {
                (
                    BinaryKind::OpenAiTunnelClient,
                    ReleaseProvider::OpenAiTunnelClient,
                    path,
                )
            }),
        ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => None,
    }
}

fn connector_binary_trust_label(paths: &AppPaths, connector: &ConnectorConfig) -> &'static str {
    let Some((kind, provider, path)) = connector_binary_path(connector) else {
        return "not_applicable";
    };
    match resolve_connector_binary(
        &paths.data_dir,
        &paths.state_dir,
        kind,
        provider,
        Some(path),
    ) {
        Ok(Some(resolved)) => match resolved.trust {
            ExternalBinaryTrust::ManagedVersioned => "managed_verified",
            ExternalBinaryTrust::ExternalPinned => "external_pinned",
            ExternalBinaryTrust::ExternalUnpinned => "external_unpinned",
        },
        Ok(None) => "missing",
        Err(_) => "invalid",
    }
}

fn pin_configured_external_binaries(paths: &AppPaths, config: &AppConfig) -> Result<usize> {
    let pins = external_binary_pin_store(&paths.state_dir);
    let mut pinned = 0_usize;
    let mut seen = std::collections::BTreeSet::new();
    for connector in &config.connectors {
        let Some((kind, _provider, path)) = connector_binary_path(connector) else {
            continue;
        };
        let canonical = path.canonicalize().with_context(|| {
            format!("configured connector binary is missing: {}", path.display())
        })?;
        if is_managed_connector_binary(&paths.data_dir, kind, &canonical)? {
            continue;
        }
        if seen.insert((kind.executable_name().to_owned(), canonical.clone())) {
            pins.pin(kind, &canonical)?;
            pinned = pinned.saturating_add(1);
        }
    }
    Ok(pinned)
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
    fn existing_invalid_managed_binary_is_preserved_fail_closed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let destination = temporary
            .path()
            .join(BinaryKind::Cloudflared.executable_name());
        let receipt_path = managed_receipt_path(temporary.path(), BinaryKind::Cloudflared);
        std::fs::write(&destination, b"untrusted managed bytes")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::write(&receipt_path, b"invalid receipt")?;

        assert!(
            existing_managed_binary(
                BinaryKind::Cloudflared,
                ReleaseProvider::Cloudflared,
                &destination,
                &receipt_path,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&destination)?, b"untrusted managed bytes");
        assert_eq!(std::fs::read(&receipt_path)?, b"invalid receipt");
        Ok(())
    }

    #[test]
    fn incomplete_managed_binary_pair_is_preserved_fail_closed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let destination = temporary
            .path()
            .join(BinaryKind::Cloudflared.executable_name());
        let receipt_path = managed_receipt_path(temporary.path(), BinaryKind::Cloudflared);
        std::fs::write(&destination, b"orphan managed bytes")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o700))?;
        }

        assert!(
            existing_managed_binary(
                BinaryKind::Cloudflared,
                ReleaseProvider::Cloudflared,
                &destination,
                &receipt_path,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&destination)?, b"orphan managed bytes");
        assert!(!receipt_path.exists());
        Ok(())
    }

    #[test]
    fn managed_cloudflare_rewrite_preserves_external_paths() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path());
        paths.ensure()?;
        let legacy_directory = paths.data_dir.join("bin");
        ensure_private_directory(&legacy_directory)?;
        let managed = legacy_directory.join(BinaryKind::Cloudflared.executable_name());
        std::fs::write(&managed, b"managed")?;
        let external = temporary.path().join("external-cloudflared");
        std::fs::write(&external, b"external")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o700))?;
        }
        let target = temporary.path().join("new-version");
        let mut quick = ConnectorConfig::local_default();
        quick.id = "quick".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.cloudflare_quick = Some(CloudflareQuickSettings {
            cloudflared_path: Some(managed),
            ..CloudflareQuickSettings::default()
        });
        let mut oauth = ConnectorConfig::local_default();
        oauth.id = "oauth".to_owned();
        oauth.kind = ConnectorKind::CloudflareOauth;
        oauth.cloudflare_named = Some(CloudflareNamedSettings {
            tunnel_id: "00000000-0000-4000-8000-000000000000".to_owned(),
            credentials_file: temporary.path().join("credentials.json"),
            hostname: "mcp.example.com".to_owned(),
            cloudflared_path: Some(external.clone()),
            metrics_port: 47_824,
        });
        let mut config = AppConfig {
            connectors: vec![quick, oauth],
            ..AppConfig::default()
        };
        assert_eq!(
            rewrite_managed_cloudflare_paths(&mut config, &paths, &target)?,
            1
        );
        assert_eq!(
            config.connectors[0]
                .cloudflare_quick
                .as_ref()
                .and_then(|settings| settings.cloudflared_path.as_deref()),
            Some(target.as_path())
        );
        assert_eq!(
            config.connectors[1]
                .cloudflare_named
                .as_ref()
                .and_then(|settings| settings.cloudflared_path.as_deref()),
            Some(external.as_path())
        );
        Ok(())
    }

    #[test]
    fn managed_openai_rewrite_preserves_external_paths() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path());
        paths.ensure()?;
        let legacy_directory = paths.data_dir.join("bin");
        ensure_private_directory(&legacy_directory)?;
        let managed = legacy_directory.join(BinaryKind::OpenAiTunnelClient.executable_name());
        std::fs::write(&managed, b"managed")?;
        let external = temporary.path().join("external-tunnel-client");
        std::fs::write(&external, b"external")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700))?;
            std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o700))?;
        }
        let target = temporary.path().join("new-openai-version");
        let mut managed_connector = ConnectorConfig::local_default();
        managed_connector.id = "managed-openai".to_owned();
        managed_connector.kind = ConnectorKind::OpenAiTunnel;
        managed_connector.openai_tunnel = Some(OpenAiTunnelSettings {
            tunnel_id: "tunnel_0123456789abcdef0123456789abcdef".to_owned(),
            profile: "managed-profile".to_owned(),
            tunnel_client_path: Some(managed),
            health_port: 47_823,
        });
        let mut external_connector = ConnectorConfig::local_default();
        external_connector.id = "external-openai".to_owned();
        external_connector.kind = ConnectorKind::OpenAiTunnel;
        external_connector.openai_tunnel = Some(OpenAiTunnelSettings {
            tunnel_id: "tunnel_1123456789abcdef0123456789abcdef".to_owned(),
            profile: "external-profile".to_owned(),
            tunnel_client_path: Some(external.clone()),
            health_port: 47_825,
        });
        let mut config = AppConfig {
            connectors: vec![managed_connector, external_connector],
            ..AppConfig::default()
        };
        assert_eq!(
            rewrite_managed_openai_paths(&mut config, &paths, &target)?,
            1
        );
        assert_eq!(
            config.connectors[0]
                .openai_tunnel
                .as_ref()
                .and_then(|settings| settings.tunnel_client_path.as_deref()),
            Some(target.as_path())
        );
        assert_eq!(
            config.connectors[1]
                .openai_tunnel
                .as_ref()
                .and_then(|settings| settings.tunnel_client_path.as_deref()),
            Some(external.as_path())
        );
        Ok(())
    }

    #[test]
    fn pin_command_deduplicates_external_binary_paths() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path());
        paths.ensure()?;
        let external = temporary.path().join("external-cloudflared");
        std::fs::write(&external, b"external")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&external, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut first = ConnectorConfig::local_default();
        first.id = "first".to_owned();
        first.kind = ConnectorKind::CloudflareQuick;
        first.cloudflare_quick = Some(CloudflareQuickSettings {
            cloudflared_path: Some(external.clone()),
            ..CloudflareQuickSettings::default()
        });
        let mut second = first.clone();
        second.id = "second".to_owned();
        let config = AppConfig {
            connectors: vec![first, second],
            ..AppConfig::default()
        };
        assert_eq!(pin_configured_external_binaries(&paths, &config)?, 1);
        assert_eq!(
            connector_binary_trust_label(&paths, &config.connectors[0]),
            "external_pinned"
        );
        Ok(())
    }

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
