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
    paths: &AppPaths,
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    values: &[(String, SecretString)],
) -> Result<()> {
    let connector_id = connector.id.clone();
    let _removal_lock = ConnectorRemovalLock::acquire(paths)?;
    ConnectorRemovalJournal::new(paths).ensure_id_available(&connector_id)?;
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
    paths: &AppPaths,
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
    token: &SecretString,
) -> Result<(String, u16)> {
    let _removal_lock = ConnectorRemovalLock::acquire(paths)?;
    let journal = ConnectorRemovalJournal::new(paths);
    update_config_with_secrets(config_path, secrets, |config, transaction| {
        let index = local_http_connector_index(config);
        let connector_id = config.connectors[index].id.clone();
        journal.ensure_id_available(&connector_id)?;
        let port = config.port;
        config.connectors[index].enabled = true;
        config.connectors[index].policy_preset = config.default_preset;
        transaction.set(&local_http_secret_name(&connector_id), token)?;
        Ok((connector_id, port))
    })
}

pub(super) fn disable_local_http_transactionally(
    paths: &AppPaths,
    config_path: &Path,
    secrets: &dyn runonmine_core::secrets::SecretStore,
) -> Result<String> {
    let _removal_lock = ConnectorRemovalLock::acquire(paths)?;
    let journal = ConnectorRemovalJournal::new(paths);
    update_config_with_secrets(config_path, secrets, |config, transaction| {
        let index = local_http_connector_index(config);
        journal.ensure_id_available(&config.connectors[index].id)?;
        let connector_id = config.connectors[index].id.clone();
        config.connectors[index].enabled = false;
        transaction.delete(&local_http_secret_name(&connector_id))?;
        Ok(connector_id)
    })
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
