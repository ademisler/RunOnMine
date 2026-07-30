//! Connector configuration and credential coordination.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn update_config_with_secrets<T>(
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    update: impl FnOnce(&mut AppConfig, &mut SecretTransaction<'_>) -> Result<T>,
) -> Result<T> {
    let mut transaction = SecretTransaction::new(secrets);
    AppConfig::update_with_rollback(
        config_path,
        &mut transaction,
        |config, transaction| update(config, transaction),
        SecretTransaction::rollback,
    )
}

pub(super) fn commit_new_connector(
    mut connector: ConnectorConfig,
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    values: &[(String, SecretString)],
) -> Result<()> {
    let connector_id = connector.id.clone();
    update_config_with_secrets(config_path, secrets, move |config, transaction| {
        if config.connector(&connector_id).is_some() {
            bail!("connector id already exists");
        }
        for (name, value) in values {
            transaction.set(name, value)?;
        }
        connector.policy_preset = config.default_preset;
        config.connectors.push(connector);
        Ok(())
    })
}

pub(super) fn remove_connector_transactionally(
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    connector_id: &str,
) -> Result<ConnectorConfig> {
    update_config_with_secrets(config_path, secrets, |config, transaction| {
        let index = config
            .connectors
            .iter()
            .position(|connector| connector.id == connector_id)
            .context("connector was not found")?;
        let removed = config.connectors[index].clone();
        for suffix in connector_secret_suffixes(removed.kind) {
            transaction.delete(&format!("connector.{}.{suffix}", removed.id))?;
        }
        config.connectors.remove(index);
        Ok(removed)
    })
}

fn local_http_connector_index(config: &mut AppConfig) -> usize {
    if let Some(index) = config
        .connectors
        .iter()
        .position(|connector| connector.kind == ConnectorKind::LocalHttp)
    {
        return index;
    }
    let mut connector = ConnectorConfig::local_http_default();
    connector.policy_preset = config.default_preset;
    config.connectors.push(connector);
    config.connectors.len() - 1
}

pub(super) fn enable_local_http_transactionally(
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    token: &SecretString,
) -> Result<(String, u16)> {
    update_config_with_secrets(config_path, secrets, |config, transaction| {
        let index = local_http_connector_index(config);
        let connector_id = config.connectors[index].id.clone();
        let port = config.port;
        config.connectors[index].enabled = true;
        config.connectors[index].policy_preset = config.default_preset;
        transaction.set(&local_http_secret_name(&connector_id), token)?;
        Ok((connector_id, port))
    })
}

pub(super) fn disable_local_http_transactionally(
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
) -> Result<String> {
    update_config_with_secrets(config_path, secrets, |config, transaction| {
        let index = local_http_connector_index(config);
        let connector_id = config.connectors[index].id.clone();
        config.connectors[index].enabled = false;
        transaction.delete(&local_http_secret_name(&connector_id))?;
        Ok(connector_id)
    })
}

pub(super) fn connector_secret_suffixes(kind: ConnectorKind) -> &'static [&'static str] {
    match kind {
        ConnectorKind::LocalStdio => &[],
        ConnectorKind::LocalHttp => &["local_http_token"],
        ConnectorKind::CloudflareQuick => &["path_secret"],
        ConnectorKind::CloudflareOauth => &[
            "github_client_id",
            "github_client_secret",
            "oauth_hash_key",
            "oauth_registration_token",
        ],
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

pub(super) fn local_http_secret_name(connector_id: &str) -> String {
    format!("connector.{connector_id}.local_http_token")
}
