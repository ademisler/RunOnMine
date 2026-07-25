#[allow(clippy::wildcard_imports)]
use super::*;
use std::io::Read as _;

pub(crate) fn setup(roots: &[PathBuf]) -> Result<()> {
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
pub(crate) async fn connect(command: ConnectCommand) -> Result<()> {
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
                policy_rules: Vec::new(),
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
                policy_rules: Vec::new(),
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
                    github_id: owner_id,
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
            config.connectors.push(ConnectorConfig {
                id: id.clone(),
                name: "OpenAI Secure MCP Tunnel".to_owned(),
                kind: ConnectorKind::OpenAiTunnel,
                enabled: true,
                policy_preset: config.default_preset,
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

pub(super) fn save_config_after_secret_deletion(
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

pub(super) fn restore_secret_backups(
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

pub(super) fn connector_secret_suffixes(kind: ConnectorKind) -> &'static [&'static str] {
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

pub(super) fn ensure_connector_credentials(
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
            .map(|owner| owner.github_id)
            .is_none_or(|id| id == 0)
    {
        bail!("OAuth connector must pin the machine owner's immutable GitHub numeric ID");
    }
    Ok(())
}

pub(super) fn remove_connector_directories(paths: &AppPaths, connector_id: &str) -> Result<()> {
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

pub(super) fn remove_real_directory_if_exists(path: &Path) -> Result<()> {
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

pub(super) fn local_http_secret_name(connector_id: &str) -> String {
    format!("connector.{connector_id}.local_http_token")
}

pub(super) fn print_local_http_credentials(port: u16, connector_id: &str, token: &str) {
    println!("Local HTTP connector {connector_id} is enabled.");
    println!("Endpoint: http://127.0.0.1:{port}/mcp");
    println!("Bearer token: {token}");
    println!("Store this token now; it is kept in the operating system credential store.");
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

pub(super) fn commit_connector(
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
