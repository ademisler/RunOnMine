use super::*;

mod connector_transactions;
mod connectors;
mod openai_connector_transaction;
#[cfg(test)]
use connector_transactions::commit_new_connector;
use connector_transactions::{local_http_secret_name, update_config_with_secrets};
pub(crate) use connectors::{connect, setup};
use connectors::{
    ensure_private_directory, generate_path_secret, load_connector_binary,
    validate_private_output_path, write_oauth_registration_credentials,
};

pub(super) fn policy(command: PolicyCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    let config_path = paths.config_file();
    match command {
        PolicyCommand::Show { connector } => {
            let config = AppConfig::load(&config_path).context("run `runonmine setup` first")?;
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
            let (id, updated_preset) = AppConfig::update(&config_path, move |config| {
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
                Ok((id, item.policy_preset))
            })?;
            println!("Updated connector {id} to {updated_preset:?}.");
        }
        PolicyCommand::Set {
            connector,
            capability,
            mode,
        } => {
            AppConfig::update(&config_path, |config| {
                config
                    .connector_mut(&connector)
                    .context("connector was not found")?
                    .pack_overrides
                    .insert(capability.into(), mode.into());
                Ok(())
            })?;
            println!("Updated connector {connector}.");
        }
    }
    Ok(())
}

pub(super) fn approvals(command: ApprovalCommand) -> Result<()> {
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
                    "{}  {}  {}  expires {}\n  requester={} fingerprint={}\n  {}",
                    request.id,
                    request.connector_id,
                    request.tool_name,
                    request.expires_at.to_rfc3339(),
                    request.principal.display_label(),
                    request.principal_fingerprint,
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
                    "{}  {}  {}  created={}\n  requester={} fingerprint={}\n  {}",
                    grant.connector_id,
                    grant.tool_name,
                    grant.argument_hash,
                    grant.created_at.to_rfc3339(),
                    grant.principal.display_label(),
                    grant.principal_fingerprint,
                    grant.argument_summary,
                );
            }
        }
        ApprovalCommand::Grants {
            command:
                GrantCommand::Revoke {
                    connector,
                    principal_fingerprint,
                    tool,
                    argument_hash,
                },
        } => {
            if !store.delete_persistent_grant(
                &connector,
                &principal_fingerprint,
                &tool,
                &argument_hash,
            )? {
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

pub(super) fn browser(command: BrowserCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    paths.ensure()?;
    let config_path = paths.config_file();
    match command {
        BrowserCommand::Profile {
            command: BrowserProfileCommand::Create { name },
        } => {
            validate_profile_name(&name)?;
            let directory = paths.browser_profiles().join(&name);
            ensure_private_directory(&directory)?;
            AppConfig::update(&config_path, move |config| {
                config.browser.profile_name = name;
                config.browser.profile_mode = BrowserProfileMode::Persistent;
                config.browser.external_cdp_url = None;
                Ok(())
            })?;
            println!(
                "Selected persistent browser profile at {}.",
                directory.display()
            );
        }
        BrowserCommand::Profile {
            command: BrowserProfileCommand::Ephemeral { name },
        } => {
            validate_profile_name(&name)?;
            AppConfig::update(&config_path, move |config| {
                config.browser.profile_name = name;
                config.browser.profile_mode = BrowserProfileMode::Ephemeral;
                config.browser.external_cdp_url = None;
                Ok(())
            })?;
            println!("Selected disposable browser profile mode.");
        }
        BrowserCommand::Profile {
            command: BrowserProfileCommand::Delete { name },
        } => {
            validate_profile_name(&name)?;
            let config = AppConfig::load_or_create(&config_path)?;
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
            AppConfig::update(&config_path, move |config| {
                config.browser.external_cdp_url = Some(loopback_cdp_url);
                Ok(())
            })?;
            println!(
                "Configured expert CDP attachment. RunOnMine will not launch your daily profile."
            );
        }
        BrowserCommand::PrivateNetwork { access } => {
            let allowed = AppConfig::update(&config_path, |config| {
                config.browser.allow_private_network =
                    matches!(access, PrivateNetworkAccess::Allow);
                Ok(config.browser.allow_private_network)
            })?;
            if allowed {
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

pub(super) fn oauth(command: OauthCommand) -> Result<()> {
    let paths = AppPaths::discover()?;
    let store = SqliteOAuthStore::open(&paths.state_db())?;
    match command {
        OauthCommand::Clients { command } => oauth_clients(&store, command),
        OauthCommand::Sessions { command } => oauth_sessions(&store, command),
        OauthCommand::RegistrationToken { command } => oauth_registration_token(&paths, command),
        OauthCommand::Cleanup => {
            let removed = store.cleanup_expired(chrono::Utc::now())?;
            println!("Removed {removed} expired OAuth record(s).");
            Ok(())
        }
    }
}

fn oauth_clients(store: &SqliteOAuthStore, command: OauthClientCommand) -> Result<()> {
    match command {
        OauthClientCommand::List => {
            let clients = store.registered_clients()?;
            if clients.is_empty() {
                println!("No OAuth clients are registered.");
            }
            for client in clients {
                println!(
                    "connector={}  {}  {}  issued={}  expires={}  last_used={}\n  scopes: {}\n  redirects: {}",
                    client.connector_id,
                    client.client_id,
                    client.client_name,
                    client.issued_at.to_rfc3339(),
                    client.expires_at.to_rfc3339(),
                    client
                        .last_used_at
                        .map_or_else(|| "never".to_owned(), |value| value.to_rfc3339()),
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
        OauthClientCommand::Revoke {
            connector_id,
            client_id,
        } => {
            let revoked = store.revoke_client_tokens_for(&connector_id, &client_id)?;
            println!("Revoked {revoked} active OAuth token(s) for {connector_id}/{client_id}.");
        }
        OauthClientCommand::Delete {
            connector_id,
            client_id,
        } => {
            if !store.delete_client_for(&connector_id, &client_id)? {
                bail!("OAuth client was not found in the selected connector");
            }
            println!(
                "Deleted OAuth client {connector_id}/{client_id} and its authorization state."
            );
        }
    }
    Ok(())
}

fn oauth_sessions(store: &SqliteOAuthStore, command: OauthSessionCommand) -> Result<()> {
    match command {
        OauthSessionCommand::List {
            connector_id,
            client_id,
        } => {
            let sessions = store.sessions_for(connector_id.as_deref(), client_id.as_deref())?;
            if sessions.is_empty() {
                println!("No OAuth sessions were found.");
            }
            for session in sessions {
                println!(
                    "{}  connector={}  client={}  active={}  expires={}\n  subject: {}\n  scopes: {}",
                    session.family_id,
                    session.connector_id,
                    session.client_id,
                    session.active,
                    session.expires_at.to_rfc3339(),
                    session.subject,
                    session.scopes.to_space_delimited(),
                );
            }
        }
        OauthSessionCommand::Revoke {
            connector_id,
            family_id,
        } => {
            let revoked = store.revoke_session_for(&connector_id, family_id)?;
            println!("Revoked {revoked} active token(s) in session {connector_id}/{family_id}.");
        }
    }
    Ok(())
}

fn oauth_registration_token(
    paths: &AppPaths,
    command: OauthRegistrationTokenCommand,
) -> Result<()> {
    match command {
        OauthRegistrationTokenCommand::Export {
            connector_id,
            output,
        } => export_oauth_registration_token(paths, &connector_id, &output),
        OauthRegistrationTokenCommand::Rotate {
            connector_id,
            output,
        } => rotate_oauth_registration_token(paths, &connector_id, output.as_deref()),
    }
}

fn export_oauth_registration_token(
    paths: &AppPaths,
    connector_id: &str,
    output: &Path,
) -> Result<()> {
    validate_private_output_path(Some(output))?;
    let config = AppConfig::load(&paths.config_file()).context("run `runonmine setup` first")?;
    let connector = oauth_connector(&config, connector_id)?;
    let endpoint = oauth_registration_endpoint(connector)?;
    let secrets = default_secret_store(paths)?;
    let token = secrets
        .get(&format!(
            "connector.{connector_id}.oauth_registration_token"
        ))?
        .context("OAuth registration token is missing")?;
    write_oauth_registration_credentials(
        output,
        connector_id,
        endpoint.as_str(),
        token.expose_secret(),
    )?;
    println!(
        "OAuth registration credentials written to {}.",
        output.display()
    );
    Ok(())
}

fn rotate_oauth_registration_token(
    paths: &AppPaths,
    connector_id: &str,
    output: Option<&Path>,
) -> Result<()> {
    validate_private_output_path(output)?;
    let token = generate_path_secret();
    let secrets = default_secret_store(paths)?;
    let endpoint = update_config_with_secrets(
        &paths.config_file(),
        secrets.as_ref(),
        |config, transaction| {
            let connector = oauth_connector(config, connector_id)?;
            let endpoint = oauth_registration_endpoint(connector)?;
            transaction.set(
                &format!("connector.{connector_id}.oauth_registration_token"),
                &SecretString::from(token.clone()),
            )?;
            Ok(endpoint)
        },
    )?;
    if let Some(output) = output {
        write_oauth_registration_credentials(output, connector_id, endpoint.as_str(), &token)
            .with_context(|| {
                format!(
                    "the token was rotated and remains in the credential store, but secure export to {} failed; retry with `runonmine oauth registration-token export {connector_id} --output <absolute-file>`",
                    output.display()
                )
            })?;
        println!(
            "OAuth registration credentials written to {}.",
            output.display()
        );
    } else {
        println!("OAuth registration token rotated in the credential store.");
    }
    println!("Restart the agent to invalidate the previous registration token.");
    Ok(())
}

fn oauth_connector<'a>(config: &'a AppConfig, connector_id: &str) -> Result<&'a ConnectorConfig> {
    let connector = config
        .connector(connector_id)
        .context("OAuth connector was not found")?;
    if connector.kind != ConnectorKind::CloudflareOauth {
        bail!("connector is not a Cloudflare OAuth connector");
    }
    Ok(connector)
}

fn oauth_registration_endpoint(connector: &ConnectorConfig) -> Result<Url> {
    connector
        .public_base_url
        .as_ref()
        .context("OAuth connector public base URL is missing")?
        .join("oauth/register")
        .context("OAuth registration endpoint is invalid")
}

pub(super) fn admin(command: AdminCommand) -> Result<()> {
    let helper = sibling_executable("runonmine-helper")?;
    match command {
        AdminCommand::Install {
            allowed_programs,
            profile_file,
        } => {
            validate_admin_install_inputs(&allowed_programs, profile_file.as_deref())?;
            install_admin_helper(&helper, &allowed_programs, profile_file.as_deref())
        }
        AdminCommand::Uninstall => run_elevated_helper(&helper, &["uninstall".into()]),
        AdminCommand::Status => run_process(ProcessCommand::new(helper).arg("status")),
    }
}

fn validate_admin_install_inputs(
    allowed_programs: &[PathBuf],
    profile_file: Option<&Path>,
) -> Result<()> {
    if allowed_programs.is_empty() && profile_file.is_none() {
        bail!("admin install requires --allow-program or --profile-file");
    }
    for path in allowed_programs {
        if !path.is_absolute() {
            bail!("admin allowlist entries must be absolute paths");
        }
    }
    if let Some(path) = profile_file {
        ProgramProfileDocument::load(path).context("admin program profile validation failed")?;
    }
    Ok(())
}

pub(super) fn service(command: ServiceCommand) -> Result<()> {
    match command {
        ServiceCommand::Install(args) if args.system => {
            let user = args
                .user
                .as_deref()
                .context("--user is required with --system")?;
            LinuxSystemService::discover()?.install(user)?;
        }
        ServiceCommand::Install(_) => {
            let paths = AppPaths::discover()?;
            let config = AppConfig::load(&paths.config_file())
                .context("run `runonmine setup` before installing the user service")?;
            UserService::discover()?.install(&config.allowed_roots)?;
        }
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

pub(super) fn emergency_lock(arguments: &LockArgs) -> Result<()> {
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

    let (
        rotated_local_http_tokens,
        rotated_quick_tunnels,
        rotated_oauth_registration_tokens,
        removed_openai_keys,
    ) = rotate_lock_credentials(&paths)?;

    println!("RunOnMine is locked.");
    println!("Denied pending approvals: {denied}");
    println!("Cleared temporary grants: {temporary_grants}");
    println!("Revoked OAuth tokens: {revoked_tokens}");
    println!("Rotated local HTTP tokens: {rotated_local_http_tokens}");
    println!("Rotated Quick Tunnel secrets: {rotated_quick_tunnels}");
    println!("Rotated OAuth registration tokens: {rotated_oauth_registration_tokens}");
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

fn rotate_lock_credentials(paths: &AppPaths) -> Result<(usize, usize, usize, usize)> {
    let config_path = paths.config_file();
    let secrets = default_secret_store(paths)?;
    update_config_with_secrets(&config_path, secrets.as_ref(), |config, transaction| {
        let mut local_http = 0_usize;
        let mut quick_tunnels = 0_usize;
        let mut oauth_registration = 0_usize;
        let mut openai = 0_usize;
        for connector in &config.connectors {
            match connector.kind {
                ConnectorKind::LocalHttp => {
                    transaction.set(
                        &local_http_secret_name(&connector.id),
                        &SecretString::from(generate_path_secret()),
                    )?;
                    local_http += 1;
                }
                ConnectorKind::CloudflareQuick => {
                    transaction.set(
                        &format!("connector.{}.path_secret", connector.id),
                        &SecretString::from(generate_path_secret()),
                    )?;
                    quick_tunnels += 1;
                }
                ConnectorKind::CloudflareOauth => {
                    transaction.set(
                        &format!("connector.{}.oauth_registration_token", connector.id),
                        &SecretString::from(generate_path_secret()),
                    )?;
                    oauth_registration += 1;
                }
                ConnectorKind::OpenAiTunnel => {
                    transaction.delete(&format!("connector.{}.runtime_api_key", connector.id))?;
                    openai += 1;
                }
                ConnectorKind::LocalStdio => {}
            }
        }
        Ok((local_http, quick_tunnels, oauth_registration, openai))
    })
}

pub(super) fn uninstall(arguments: &UninstallArgs) -> Result<()> {
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
    if config.is_some() {
        match default_secret_store(&paths) {
            Ok(store) => {
                update_config_with_secrets(&config_path, store.as_ref(), |config, transaction| {
                    for connector in &config.connectors {
                        for suffix in [
                            "local_http_token",
                            "path_secret",
                            "github_client_id",
                            "github_client_secret",
                            "oauth_hash_key",
                            "oauth_registration_token",
                            "runtime_api_key",
                        ] {
                            transaction.delete(&format!("connector.{}.{suffix}", connector.id))?;
                        }
                    }
                    Ok(())
                })?;
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
pub(super) async fn doctor() -> Result<()> {
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
                for suffix in [
                    "github_client_id",
                    "github_client_secret",
                    "oauth_hash_key",
                    "oauth_registration_token",
                ] {
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
                    .map(|owner| owner.github_id)
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

pub(super) fn audit(command: AuditCommand) -> Result<()> {
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

pub(super) fn prompt_required(prompt: &str) -> Result<String> {
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

pub(super) fn spawn_sibling(name: &str, args: &[&str]) -> Result<()> {
    let executable = sibling_executable(name)?;
    let status = ProcessCommand::new(executable).args(args).status()?;
    if !status.success() {
        bail!("{name} exited unsuccessfully");
    }
    Ok(())
}

pub(super) fn sibling_executable(name: &str) -> Result<PathBuf> {
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
pub(super) fn install_admin_helper(
    helper: &Path,
    allowed_programs: &[PathBuf],
    profile_file: Option<&Path>,
) -> Result<()> {
    use std::ffi::OsString;

    let effective_uid = nix::unistd::geteuid().as_raw();
    let owner_uid = if effective_uid == 0 {
        std::env::var("SUDO_UID")
            .context("install as your normal account or provide a sudo caller identity")?
            .parse::<u32>()
            .context("SUDO_UID is invalid")?
    } else {
        effective_uid
    };
    if owner_uid == 0 {
        bail!("the privileged helper owner must be a non-root user");
    }
    let mut arguments = vec![
        OsString::from("install"),
        OsString::from("--owner-uid"),
        OsString::from(owner_uid.to_string()),
    ];
    for program in allowed_programs {
        arguments.push(OsString::from("--allow-program"));
        arguments.push(program.as_os_str().to_owned());
    }
    if let Some(profile_file) = profile_file {
        arguments.push(OsString::from("--profile-file"));
        arguments.push(profile_file.as_os_str().to_owned());
    }
    run_elevated_helper(helper, &arguments)
}

#[cfg(windows)]
pub(super) fn install_admin_helper(
    helper: &Path,
    allowed_programs: &[PathBuf],
    profile_file: Option<&Path>,
) -> Result<()> {
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
    if let Some(profile_file) = profile_file {
        arguments.push(OsString::from("--profile-file"));
        arguments.push(profile_file.as_os_str().to_owned());
    }
    run_elevated_helper(helper, &arguments)
}

#[cfg(unix)]
pub(super) fn run_elevated_helper(helper: &Path, arguments: &[std::ffi::OsString]) -> Result<()> {
    let sudo = ["/usr/bin/sudo", "/bin/sudo"]
        .into_iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .context("sudo was not found in a trusted system location")?;
    run_process(
        ProcessCommand::new(sudo)
            .arg("--")
            .arg(helper)
            .args(arguments),
    )
}

#[cfg(windows)]
pub(super) fn run_elevated_helper(helper: &Path, arguments: &[std::ffi::OsString]) -> Result<()> {
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

pub(super) fn run_process(command: &mut ProcessCommand) -> Result<()> {
    let status = command.status().context("failed to start helper process")?;
    if !status.success() {
        bail!("privileged helper operation failed");
    }
    Ok(())
}

pub(super) fn validate_profile_name(name: &str) -> Result<()> {
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

pub(super) fn runonmine_browser_guard(url: &Url) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        bail!("CDP URL must use HTTP or WebSocket transport");
    }
    let host = url.host_str().unwrap_or_default();
    if !matches!(host, "127.0.0.1" | "::1" | "localhost") {
        bail!("external CDP endpoints must use loopback");
    }
    Ok(())
}

pub(super) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
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

    #[test]
    fn admin_install_inputs_fail_before_elevation_when_missing_or_relative() {
        assert!(validate_admin_install_inputs(&[], None).is_err());
        assert!(validate_admin_install_inputs(&[PathBuf::from("relative-program")], None).is_err());
        assert!(
            validate_admin_install_inputs(&[], Some(Path::new("relative-profile.json"))).is_err()
        );
    }

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
        fail_set_once: std::sync::Mutex<Option<String>>,
    }

    impl MemorySecretStore {
        fn fail_next_set(&self, name: &str) -> Result<()> {
            *self
                .fail_set_once
                .lock()
                .map_err(|_| anyhow::anyhow!("test failure lock failed"))? = Some(name.to_owned());
            Ok(())
        }
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
            let mut failure = self
                .fail_set_once
                .lock()
                .map_err(|_| anyhow::anyhow!("test failure lock failed"))?;
            if failure.as_deref() == Some(name) {
                *failure = None;
                bail!("injected secret-store failure");
            }
            drop(failure);
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

    fn quick_connector(id: &str) -> ConnectorConfig {
        ConnectorConfig {
            id: id.to_owned(),
            name: "Quick test connector".to_owned(),
            kind: ConnectorKind::CloudflareQuick,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::default(),
            tool_overrides: BTreeMap::default(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: Some(CloudflareQuickSettings::default()),
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: None,
        }
    }

    #[test]
    fn connector_removal_deletes_credentials_and_preserves_unrelated_config() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        let root = directory.path().join("allowed");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        let mut config = AppConfig::default();
        let connector = quick_connector("quick-remove");
        config.allowed_roots.push(root.clone());
        config.connectors.push(connector);
        config.save(&config_path)?;

        let store = MemorySecretStore::default();
        let name = "connector.quick-remove.path_secret".to_owned();
        store.set(&name, &SecretString::from("token".to_owned()))?;
        assert!(remove_connector_recoverably(
            &paths,
            &store,
            "quick-remove"
        )?);

        assert!(store.get(&name)?.is_none());
        let updated = AppConfig::load(&config_path)?;
        assert_eq!(updated.allowed_roots, vec![root]);
        assert!(updated.connector("quick-remove").is_none());
        Ok(())
    }

    #[test]
    fn failed_config_validation_restores_deleted_credential() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        AppConfig::default().save(&config_path)?;
        let store = MemorySecretStore::default();
        let name = "connector.local.local_http_token".to_owned();
        store.set(&name, &SecretString::from("token".to_owned()))?;

        let result: Result<()> =
            update_config_with_secrets(&config_path, &store, |config, transaction| {
                transaction.delete(&name)?;
                config.port = 0;
                Ok(())
            });
        assert!(result.is_err());
        assert_eq!(
            store
                .get(&name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("token".to_owned())
        );
        assert_eq!(
            AppConfig::load(&config_path)?.port,
            AppConfig::default().port
        );
        Ok(())
    }

    #[test]
    fn partial_multi_secret_write_restores_every_previous_value() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        AppConfig::default().save(&config_path)?;
        let store = MemorySecretStore::default();
        let first = "connector.oauth.client_id";
        let second = "connector.oauth.client_secret";
        store.set(first, &SecretString::from("old-client".to_owned()))?;
        store.set(second, &SecretString::from("old-secret".to_owned()))?;
        store.fail_next_set(second)?;

        let result: Result<()> =
            update_config_with_secrets(&config_path, &store, |_config, transaction| {
                transaction.set(first, &SecretString::from("new-client".to_owned()))?;
                transaction.set(second, &SecretString::from("new-secret".to_owned()))?;
                Ok(())
            });
        assert!(result.is_err());
        assert_eq!(
            store
                .get(first)?
                .map(|value| value.expose_secret().to_owned()),
            Some("old-client".to_owned())
        );
        assert_eq!(
            store
                .get(second)?
                .map(|value| value.expose_secret().to_owned()),
            Some("old-secret".to_owned())
        );
        Ok(())
    }

    #[test]
    fn failed_connector_commit_restores_overwritten_credential() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        let mut config = AppConfig::default();
        config.connectors.push(quick_connector("quick-existing"));
        config.save(&config_path)?;

        let store = MemorySecretStore::default();
        let name = "connector.quick-new.path_secret".to_owned();
        store.set(&name, &SecretString::from("previous".to_owned()))?;
        assert!(
            commit_new_connector(
                quick_connector("quick-new"),
                &paths,
                &config_path,
                &store,
                &[(name.clone(), SecretString::from("replacement".to_owned()))],
            )
            .is_err()
        );
        assert_eq!(
            store
                .get(&name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("previous".to_owned())
        );
        assert!(
            AppConfig::load(&config_path)?
                .connector("quick-new")
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn connector_commit_rejects_an_id_with_pending_removal() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        AppConfig::default().save(&config_path)?;
        let connector = quick_connector("pending-id");
        ConnectorRemovalJournal::new(&paths).begin(&connector)?;
        let store = MemorySecretStore::default();
        let secret_name = "connector.pending-id.path_secret".to_owned();
        store.set(&secret_name, &SecretString::from("previous".to_owned()))?;

        assert!(
            commit_new_connector(
                connector,
                &paths,
                &config_path,
                &store,
                &[(
                    secret_name.clone(),
                    SecretString::from("replacement".to_owned()),
                )],
            )
            .is_err()
        );
        assert!(
            AppConfig::load(&config_path)?
                .connector("pending-id")
                .is_none()
        );
        assert_eq!(
            store
                .get(&secret_name)?
                .map(|value| value.expose_secret().to_owned()),
            Some("previous".to_owned())
        );
        Ok(())
    }

    #[test]
    fn connector_commit_uses_latest_preset_without_losing_other_updates() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let config_path = paths.config_file();
        let root = directory.path().join("allowed");
        std::fs::create_dir(&root)?;
        let root = root.canonicalize()?;
        AppConfig::default().save(&config_path)?;
        let candidate = quick_connector("quick-latest");
        AppConfig::update(&config_path, |config| {
            config.default_preset = PolicyPreset::Developer;
            config.allowed_roots.push(root.clone());
            Ok(())
        })?;

        let store = MemorySecretStore::default();
        commit_new_connector(
            candidate,
            &paths,
            &config_path,
            &store,
            &[(
                "connector.quick-latest.path_secret".to_owned(),
                SecretString::from("token".to_owned()),
            )],
        )?;
        let updated = AppConfig::load(&config_path)?;
        assert_eq!(updated.allowed_roots, vec![root]);
        assert_eq!(
            updated
                .connector("quick-latest")
                .context("new connector is missing")?
                .policy_preset,
            PolicyPreset::Developer
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
        let oauth = connector_secret_suffixes(ConnectorKind::CloudflareOauth);
        assert!(oauth.contains(&"github_client_secret"));
        assert!(oauth.contains(&"oauth_hash_key"));
        assert!(oauth.contains(&"oauth_registration_token"));
    }
}
