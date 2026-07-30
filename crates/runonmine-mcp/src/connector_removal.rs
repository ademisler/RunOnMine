//! Recoverable connector removal shared by the CLI and agent startup.

use anyhow::{Context, Result};
use runonmine_core::secrets::SecretStore;
use runonmine_core::{
    AppConfig, AppPaths, ConnectorRemovalJournal, ConnectorRemovalLock, ConnectorRemovalPhase,
    ConnectorRemovalRecord, remove_connector_authorization,
    remove_connector_configuration_and_secrets, remove_connector_directories,
};
use runonmine_oauth::SqliteOAuthStore;

pub fn remove_connector_recoverably(
    paths: &AppPaths,
    secrets: &dyn SecretStore,
    connector_id: &str,
) -> Result<bool> {
    let _lock = ConnectorRemovalLock::acquire(paths)?;
    let journal = ConnectorRemovalJournal::new(paths);
    let record = if let Some(record) = journal.get(connector_id)? {
        record
    } else {
        let config = AppConfig::load(&paths.config_file())?;
        let Some(connector) = config.connector(connector_id) else {
            return Ok(false);
        };
        journal.begin(connector)?
    };
    reconcile_connector_removal(paths, secrets, &journal, record)?;
    Ok(true)
}

pub fn reconcile_pending_connector_removals(paths: &AppPaths) -> Result<usize> {
    let _lock = ConnectorRemovalLock::acquire(paths)?;
    let journal = ConnectorRemovalJournal::new(paths);
    let pending = journal.pending()?;
    if pending.is_empty() {
        return Ok(0);
    }
    let secrets = runonmine_core::secrets::default_secret_store(paths)?;
    reconcile_pending_locked(paths, secrets.as_ref(), &journal, pending)
}

#[cfg(test)]
fn reconcile_pending_connector_removals_with_store(
    paths: &AppPaths,
    secrets: &dyn SecretStore,
) -> Result<usize> {
    let _lock = ConnectorRemovalLock::acquire(paths)?;
    let journal = ConnectorRemovalJournal::new(paths);
    let pending = journal.pending()?;
    reconcile_pending_locked(paths, secrets, &journal, pending)
}

fn reconcile_pending_locked(
    paths: &AppPaths,
    secrets: &dyn SecretStore,
    journal: &ConnectorRemovalJournal,
    pending: Vec<ConnectorRemovalRecord>,
) -> Result<usize> {
    let mut completed = 0_usize;
    let mut failures = Vec::new();
    for record in pending {
        let connector_id = record.connector_id.clone();
        match reconcile_connector_removal(paths, secrets, journal, record) {
            Ok(()) => completed = completed.saturating_add(1),
            Err(error) => failures.push(format!("{connector_id}: {error:#}")),
        }
    }
    if failures.is_empty() {
        Ok(completed)
    } else {
        anyhow::bail!(
            "connector-removal startup reconciliation failed: {}",
            failures.join("; ")
        )
    }
}

pub fn ensure_connector_id_available(paths: &AppPaths, connector_id: &str) -> Result<()> {
    let _lock = ConnectorRemovalLock::acquire(paths)?;
    ConnectorRemovalJournal::new(paths).ensure_id_available(connector_id)
}

pub fn reconcile_connector_removal(
    paths: &AppPaths,
    secrets: &dyn SecretStore,
    journal: &ConnectorRemovalJournal,
    mut record: ConnectorRemovalRecord,
) -> Result<()> {
    if record.phase < ConnectorRemovalPhase::ConfigurationRemoved {
        remove_connector_configuration_and_secrets(paths, secrets, &record)?;
        record = journal.advance(&record, ConnectorRemovalPhase::ConfigurationRemoved)?;
    }
    if record.phase < ConnectorRemovalPhase::AuthorizationRemoved {
        remove_connector_authorization(paths, &record.connector_id)?;
        record = journal.advance(&record, ConnectorRemovalPhase::AuthorizationRemoved)?;
    }
    if record.phase < ConnectorRemovalPhase::OAuthRemoved {
        if record.requires_oauth_cleanup() {
            SqliteOAuthStore::open_scoped(&paths.state_db(), &record.connector_id)?
                .remove_connector_data()
                .context("failed to remove connector OAuth state")?;
        }
        record = journal.advance(&record, ConnectorRemovalPhase::OAuthRemoved)?;
    }
    if record.phase < ConnectorRemovalPhase::DirectoriesRemoved {
        remove_connector_directories(paths, &record.connector_id)?;
        runonmine_core::QuickTunnelRuntimeStore::new(paths)
            .clear_connector(&record.connector_id)?;
        record = journal.advance(&record, ConnectorRemovalPhase::DirectoriesRemoved)?;
    }
    journal.complete(&record)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Mutex;

    use anyhow::anyhow;
    use runonmine_core::secrets::SecretStore;
    use runonmine_core::{ConnectorConfig, ConnectorKind, PolicyPreset};
    use secrecy::SecretString;

    use super::*;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<BTreeMap<String, SecretString>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            Ok(self
                .values
                .lock()
                .map_err(|_| anyhow!("secret mutex was poisoned"))?
                .get(name)
                .cloned())
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow!("secret mutex was poisoned"))?
                .insert(name.to_owned(), value.clone());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow!("secret mutex was poisoned"))?
                .remove(name);
            Ok(())
        }
    }

    fn connector(id: &str) -> ConnectorConfig {
        ConnectorConfig {
            id: id.to_owned(),
            name: "Removal test".to_owned(),
            kind: ConnectorKind::CloudflareQuick,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: Some(runonmine_core::CloudflareQuickSettings::default()),
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: None,
        }
    }

    #[test]
    fn repeated_remove_is_successful_after_journal_completion() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let connector = connector("remove-once");
        let mut config = AppConfig::default();
        config.connectors.push(connector.clone());
        config.save(&paths.config_file())?;
        let secrets = MemorySecretStore::default();
        secrets.set(
            &format!("connector.{}.path_secret", connector.id),
            &SecretString::from("secret".to_owned()),
        )?;

        assert!(remove_connector_recoverably(
            &paths,
            &secrets,
            &connector.id
        )?);
        assert!(!remove_connector_recoverably(
            &paths,
            &secrets,
            &connector.id
        )?);
        assert!(ConnectorRemovalJournal::new(&paths).pending()?.is_empty());
        Ok(())
    }
    #[test]
    fn startup_reconciliation_resumes_after_directory_failure() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let connector = connector("resume-startup");
        let mut config = AppConfig::default();
        config.connectors.push(connector.clone());
        config.save(&paths.config_file())?;
        let secrets = MemorySecretStore::default();
        secrets.set(
            &format!("connector.{}.path_secret", connector.id),
            &SecretString::from("secret".to_owned()),
        )?;

        let journal = ConnectorRemovalJournal::new(&paths);
        let mut record = journal.begin(&connector)?;
        remove_connector_configuration_and_secrets(&paths, &secrets, &record)?;
        record = journal.advance(&record, ConnectorRemovalPhase::ConfigurationRemoved)?;
        remove_connector_authorization(&paths, &record.connector_id)?;
        record = journal.advance(&record, ConnectorRemovalPhase::AuthorizationRemoved)?;
        journal.advance(&record, ConnectorRemovalPhase::OAuthRemoved)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let connector_directory = paths.data_dir.join("connectors").join(&connector.id);
            fs::create_dir_all(connector_directory.parent().context("missing parent")?)?;
            let outside = directory.path().join("outside");
            fs::create_dir(&outside)?;
            symlink(&outside, &connector_directory)?;
            assert!(reconcile_pending_connector_removals_with_store(&paths, &secrets).is_err());
            assert_eq!(
                journal.get(&connector.id)?.map(|item| item.phase),
                Some(ConnectorRemovalPhase::OAuthRemoved)
            );
            fs::remove_file(&connector_directory)?;
            assert_eq!(
                reconcile_pending_connector_removals_with_store(&paths, &secrets)?,
                1
            );
            assert!(outside.is_dir());
        }
        Ok(())
    }

    #[test]
    fn pending_removal_rejects_same_id_with_changed_configuration() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let connector = connector("reused-removal-id");
        let journal = ConnectorRemovalJournal::new(&paths);
        journal.begin(&connector)?;
        let mut changed = connector;
        changed.name = "Changed identity".to_owned();
        let mut config = AppConfig::default();
        config.connectors.push(changed);
        config.save(&paths.config_file())?;
        let secrets = MemorySecretStore::default();
        assert!(reconcile_pending_connector_removals_with_store(&paths, &secrets).is_err());
        assert!(journal.get("reused-removal-id")?.is_some());
        Ok(())
    }
}
