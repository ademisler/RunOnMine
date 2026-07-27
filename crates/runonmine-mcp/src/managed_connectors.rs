//! External connector process lifecycle and managed connector artifacts.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use runonmine_connectors::cloudflare::{
    NamedTunnelConfig, QuickTunnelConfig, parse_quick_tunnel_url,
};
use runonmine_connectors::openai::{OpenAiMcpTarget, OpenAiTunnelProfile};
use runonmine_connectors::{
    BinaryDiscovery, BinaryKind, ProcessEvent, ProcessSupervisor, RestartPolicy, SecretValue,
    SupervisorHandle, run_once,
};
use runonmine_core::secrets::default_secret_store;
use runonmine_core::{AppConfig, AppPaths, ConnectorKind};
use secrecy::ExposeSecret;
use url::Url;

use super::required_secret;

#[derive(Debug, Default)]
pub(super) struct ManagedConnectors {
    handles: Vec<SupervisorHandle>,
    observers: Vec<tokio::task::JoinHandle<()>>,
}

#[derive(Debug)]
struct PendingQuickObserver {
    events: tokio::sync::broadcast::Receiver<ProcessEvent>,
    connector_id: String,
}

impl ManagedConnectors {
    fn activate_quick_observers(
        &mut self,
        config_path: &std::path::Path,
        pending: Vec<PendingQuickObserver>,
    ) {
        self.observers.extend(pending.into_iter().map(|observer| {
            spawn_quick_url_observer(
                observer.events,
                config_path.to_path_buf(),
                observer.connector_id,
            )
        }));
    }

    pub(super) async fn stop(mut self) {
        for observer in self.observers.drain(..) {
            observer.abort();
            let _ignored = observer.await;
        }
        for handle in self.handles.drain(..) {
            let _ignored = handle.stop().await;
        }
    }
}

pub(super) async fn start_external_connectors(
    paths: &AppPaths,
    config: &AppConfig,
) -> Result<ManagedConnectors> {
    let mut managed = ManagedConnectors::default();
    let mut pending_observers = Vec::new();
    if let Err(error) =
        start_external_connectors_inner(paths, config, &mut managed, &mut pending_observers).await
    {
        managed.stop().await;
        return Err(error);
    }
    managed.activate_quick_observers(&paths.config_file(), pending_observers);
    Ok(managed)
}

#[allow(clippy::too_many_lines)]
async fn start_external_connectors_inner(
    paths: &AppPaths,
    config: &AppConfig,
    managed: &mut ManagedConnectors,
    pending_observers: &mut Vec<PendingQuickObserver>,
) -> Result<()> {
    let discovery = BinaryDiscovery::new(vec![paths.data_dir.join("bin")]);
    let supervisor = ProcessSupervisor;
    let secrets = default_secret_store(paths)?;
    let origin = Url::parse(&format!("http://127.0.0.1:{}", config.port))?;
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.enabled)
    {
        match connector.kind {
            ConnectorKind::CloudflareQuick => {
                let settings = connector
                    .cloudflare_quick
                    .as_ref()
                    .context("Cloudflare Quick settings are missing")?;
                let binary = discovery
                    .discover(
                        BinaryKind::Cloudflared,
                        settings.cloudflared_path.as_deref(),
                    )?
                    .context("cloudflared is not installed; run the connector setup again")?;
                let tunnel = QuickTunnelConfig::builder(origin.clone())
                    .metrics_address(format!("127.0.0.1:{}", settings.metrics_port).parse()?)
                    .build()?;
                let mut handle = supervisor.start(
                    tunnel.command(&binary)?,
                    tunnel.health_check()?,
                    RestartPolicy::default(),
                )?;
                if let Some(events) = handle.take_initial_events() {
                    pending_observers.push(PendingQuickObserver {
                        events,
                        connector_id: connector.id.clone(),
                    });
                }
                managed.handles.push(handle);
            }
            ConnectorKind::CloudflareOauth => {
                let settings = connector
                    .cloudflare_named
                    .as_ref()
                    .context("Cloudflare Named Tunnel settings are missing")?;
                let binary = discovery
                    .discover(
                        BinaryKind::Cloudflared,
                        settings.cloudflared_path.as_deref(),
                    )?
                    .context("cloudflared is not installed; run the connector setup again")?;
                let connector_dir = paths.data_dir.join("connectors").join(&connector.id);
                ensure_private_directory(&connector_dir)?;
                let tunnel = NamedTunnelConfig::builder(
                    &settings.tunnel_id,
                    settings.credentials_file.clone(),
                    &settings.hostname,
                    origin.join("mcp")?,
                    connector_dir.join("cloudflared.yml"),
                )
                .metrics_address(format!("127.0.0.1:{}", settings.metrics_port).parse()?)
                .build()?;
                tunnel.write_config()?;
                managed.handles.push(supervisor.start(
                    tunnel.command(&binary)?,
                    tunnel.health_check()?,
                    RestartPolicy::default(),
                )?);
            }
            ConnectorKind::OpenAiTunnel => {
                let settings = connector
                    .openai_tunnel
                    .as_ref()
                    .context("OpenAI tunnel settings are missing")?;
                let binary = discovery
                    .discover(
                        BinaryKind::OpenAiTunnelClient,
                        settings.tunnel_client_path.as_deref(),
                    )?
                    .context("tunnel-client is not installed; run the connector setup again")?;
                let connector_dir = paths.data_dir.join("connectors").join(&connector.id);
                let profile_directory = connector_dir.join("openai-profiles");
                let health_directory = paths.state_dir.join("connectors").join(&connector.id);
                ensure_private_directory(&profile_directory)?;
                ensure_private_directory(&health_directory)?;
                let target =
                    OpenAiMcpTarget::runonmine_stdio(runonmine_cli_executable()?, &connector.id)?;
                let profile =
                    OpenAiTunnelProfile::builder(&settings.profile, &settings.tunnel_id, target)
                        .profile_directory(profile_directory.clone())
                        .health_address(format!("127.0.0.1:{}", settings.health_port).parse()?)
                        .health_url_file(health_directory.join("tunnel-health.url"))
                        .build()?;
                let profile_file = profile_directory.join(format!("{}.yaml", profile.profile()));
                if !profile_file.exists() {
                    let initialized = run_once(
                        profile.init_command(&binary)?,
                        Duration::from_secs(30),
                        128 * 1_024,
                    )
                    .await?;
                    if !initialized.success {
                        bail!("tunnel-client profile initialization failed");
                    }
                    restrict_private_file(&profile_file)?;
                }
                let runtime_key = required_secret(
                    secrets.as_ref(),
                    &format!("connector.{}.runtime_api_key", connector.id),
                )?;
                let doctor = run_once(
                    profile.doctor_command(
                        &binary,
                        SecretValue::new(runtime_key.expose_secret().to_owned())?,
                    )?,
                    Duration::from_secs(30),
                    256 * 1_024,
                )
                .await?;
                if !doctor.success {
                    bail!("tunnel-client doctor failed; run `runonmine doctor` for guidance");
                }
                managed.handles.push(supervisor.start(
                    profile.run_command(
                        &binary,
                        SecretValue::new(runtime_key.expose_secret().to_owned())?,
                    )?,
                    profile.readiness_check()?,
                    RestartPolicy::default(),
                )?);
            }
            ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => {}
        }
    }
    Ok(())
}

fn spawn_quick_url_observer(
    mut events: tokio::sync::broadcast::Receiver<ProcessEvent>,
    config_path: PathBuf,
    connector_id: String,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let event = match events.recv().await {
                Ok(event) => event,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::warn!(
                        connector_id = %connector_id,
                        skipped,
                        "Quick Tunnel observer skipped buffered process events"
                    );
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
            };
            let (ProcessEvent::StandardOutput { line } | ProcessEvent::StandardError { line }) =
                event
            else {
                continue;
            };
            let Some(url) = parse_quick_tunnel_url(&line) else {
                continue;
            };
            if let Err(error) = persist_quick_public_url(&config_path, &connector_id, url) {
                tracing::error!(%error, "failed to persist Quick Tunnel public URL");
            } else {
                tracing::info!(connector_id = %connector_id, "Cloudflare Quick Tunnel is ready");
            }
        }
    })
}

fn persist_quick_public_url(
    config_path: &std::path::Path,
    connector_id: &str,
    url: Url,
) -> Result<()> {
    AppConfig::update(config_path, |config| {
        let connector = config
            .connector_mut(connector_id)
            .context("Quick Tunnel connector was removed")?;
        if connector.kind != ConnectorKind::CloudflareQuick {
            bail!("connector is no longer a Quick Tunnel");
        }
        connector.public_base_url = Some(url);
        Ok(())
    })
}

fn ensure_private_directory(path: &std::path::Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked connector directory");
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_private_file(path: &std::path::Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("connector profile was not created")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("connector profile must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn runonmine_cli_executable() -> Result<PathBuf> {
    let current = std::env::current_exe()?.canonicalize()?;
    let expected = if current
        .file_stem()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name == "runonmine")
    {
        current
    } else {
        let filename = if cfg!(windows) {
            "runonmine.exe"
        } else {
            "runonmine"
        };
        current
            .parent()
            .context("agent executable has no parent directory")?
            .join(filename)
    };
    if !expected.is_file() {
        bail!("runonmine CLI is not installed next to the agent executable");
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use runonmine_core::{CloudflareQuickSettings, ConnectorConfig};

    #[test]
    fn quick_public_url_is_persisted_only_for_the_expected_connector_kind() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;

        let mut quick = ConnectorConfig::local_default();
        quick.id = "quick-connector".to_owned();
        quick.name = "Quick connector".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.cloudflare_quick = Some(CloudflareQuickSettings::default());

        let config = AppConfig {
            connectors: vec![quick],
            ..AppConfig::default()
        };
        config.save(&paths.config_file())?;

        let public_url = Url::parse("https://example.trycloudflare.com/")?;
        persist_quick_public_url(&paths.config_file(), "quick-connector", public_url.clone())?;
        let updated = AppConfig::load(&paths.config_file())?;
        assert_eq!(
            updated
                .connector("quick-connector")
                .and_then(|connector| connector.public_base_url.as_ref()),
            Some(&public_url)
        );

        assert!(
            persist_quick_public_url(&paths.config_file(), "missing", public_url.clone()).is_err()
        );

        let mut changed = updated;
        let connector = changed
            .connector_mut("quick-connector")
            .context("test connector is missing")?;
        connector.kind = ConnectorKind::LocalHttp;
        connector.cloudflare_quick = None;
        connector.public_base_url = None;
        changed.save(&paths.config_file())?;
        assert!(
            persist_quick_public_url(&paths.config_file(), "quick-connector", public_url).is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn quick_url_side_effects_wait_for_successful_activation() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;

        let mut quick = ConnectorConfig::local_default();
        quick.id = "quick-connector".to_owned();
        quick.name = "Quick connector".to_owned();
        quick.kind = ConnectorKind::CloudflareQuick;
        quick.cloudflare_quick = Some(CloudflareQuickSettings::default());
        let config = AppConfig {
            connectors: vec![quick],
            ..AppConfig::default()
        };
        config.save(&paths.config_file())?;

        let (sender, _) = tokio::sync::broadcast::channel(4);
        let receiver = sender.subscribe();
        for index in 0..12 {
            sender.send(ProcessEvent::StandardOutput {
                line: format!("buffered-noise-{index}"),
            })?;
        }
        sender.send(ProcessEvent::StandardOutput {
            line: "https://deferred-observer.trycloudflare.com".to_owned(),
        })?;
        let pending = vec![PendingQuickObserver {
            events: receiver,
            connector_id: "quick-connector".to_owned(),
        }];

        let before = AppConfig::load(&paths.config_file())?;
        assert!(
            before
                .connector("quick-connector")
                .and_then(|connector| connector.public_base_url.as_ref())
                .is_none()
        );

        let mut managed = ManagedConnectors::default();
        managed.activate_quick_observers(&paths.config_file(), pending);
        let persisted = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let current = AppConfig::load(&paths.config_file())?;
                if let Some(url) = current
                    .connector("quick-connector")
                    .and_then(|connector| connector.public_base_url.clone())
                {
                    return Ok::<Url, anyhow::Error>(url);
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("Quick URL observer did not persist the deferred event")??;
        assert_eq!(
            persisted,
            Url::parse("https://deferred-observer.trycloudflare.com")?
        );
        managed.stop().await;
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn connector_artifacts_are_private_and_symlinks_are_rejected() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = tempfile::tempdir()?;
        let private_dir = temporary.path().join("private");
        ensure_private_directory(&private_dir)?;
        assert_eq!(
            std::fs::metadata(&private_dir)?.permissions().mode() & 0o777,
            0o700
        );

        let profile = private_dir.join("profile.yml");
        std::fs::write(&profile, b"profile")?;
        restrict_private_file(&profile)?;
        assert_eq!(
            std::fs::metadata(&profile)?.permissions().mode() & 0o777,
            0o600
        );

        let directory_target = temporary.path().join("directory-target");
        std::fs::create_dir(&directory_target)?;
        let directory_link = temporary.path().join("directory-link");
        symlink(&directory_target, &directory_link)?;
        assert!(ensure_private_directory(&directory_link).is_err());

        let file_target = temporary.path().join("file-target");
        std::fs::write(&file_target, b"target")?;
        let file_link = temporary.path().join("file-link");
        symlink(&file_target, &file_link)?;
        assert!(restrict_private_file(&file_link).is_err());
        Ok(())
    }
}
