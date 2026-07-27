use std::path::Path;

use anyhow::{Context as _, Result, bail};
use runonmine_core::secrets::{SecretStore, SecretTransaction};
use runonmine_core::{AppConfig, ConnectorKind};
use secrecy::SecretString;

pub(crate) fn replace_connector_secrets_transactionally<T>(
    config_path: &Path,
    store: &dyn SecretStore,
    connector_id: &str,
    expected_kind: ConnectorKind,
    updates: &[(String, SecretString)],
    after_write: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let mut transaction = SecretTransaction::new(store);
    AppConfig::update_with_rollback(
        config_path,
        &mut transaction,
        |config, transaction| {
            let connector = config
                .connector(connector_id)
                .context("connector no longer exists")?;
            if connector.kind != expected_kind {
                bail!("connector kind changed before credential update");
            }
            for (name, value) in updates {
                transaction.set(name, value)?;
            }
            after_write()
        },
        SecretTransaction::rollback,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use anyhow::{Result, bail};
    use runonmine_core::secrets::SecretStore;
    use secrecy::{ExposeSecret as _, SecretString};

    use super::*;

    #[derive(Default)]
    struct FailingStore {
        values: Mutex<BTreeMap<String, String>>,
        fail_on: Mutex<Option<String>>,
    }

    impl SecretStore for FailingStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            Ok(self
                .values
                .lock()
                .map_err(|_| anyhow::anyhow!("lock failed"))?
                .get(name)
                .cloned()
                .map(SecretString::from))
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            if self
                .fail_on
                .lock()
                .map_err(|_| anyhow::anyhow!("lock failed"))?
                .as_deref()
                == Some(name)
            {
                *self
                    .fail_on
                    .lock()
                    .map_err(|_| anyhow::anyhow!("lock failed"))? = None;
                bail!("injected write failure");
            }
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("lock failed"))?
                .insert(name.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("lock failed"))?
                .remove(name);
            Ok(())
        }
    }

    #[test]
    fn failed_multi_secret_update_restores_previous_values() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        let config = AppConfig::default();
        let connector = config
            .connectors
            .first()
            .context("default connector is missing")?;
        let connector_id = connector.id.clone();
        let connector_kind = connector.kind;
        config.save(&config_path)?;
        let store = FailingStore::default();
        store.set("first", &SecretString::from("old-first".to_owned()))?;
        store.set("second", &SecretString::from("old-second".to_owned()))?;
        *store
            .fail_on
            .lock()
            .map_err(|_| anyhow::anyhow!("lock failed"))? = Some("second".to_owned());
        let result = replace_connector_secrets_transactionally(
            &config_path,
            &store,
            &connector_id,
            connector_kind,
            &[
                (
                    "first".to_owned(),
                    SecretString::from("new-first".to_owned()),
                ),
                (
                    "second".to_owned(),
                    SecretString::from("new-second".to_owned()),
                ),
            ],
            || Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(
            store
                .get("first")?
                .map(|value| value.expose_secret().to_owned()),
            Some("old-first".to_owned())
        );
        assert_eq!(
            store
                .get("second")?
                .map(|value| value.expose_secret().to_owned()),
            Some("old-second".to_owned())
        );
        Ok(())
    }

    #[test]
    fn stale_connector_selection_cannot_create_orphan_credentials() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        let config = AppConfig::default();
        let connector = config
            .connectors
            .first()
            .context("default connector is missing")?;
        let connector_id = connector.id.clone();
        let connector_kind = connector.kind;
        config.save(&config_path)?;
        AppConfig::update(&config_path, |config| {
            config
                .connectors
                .retain(|connector| connector.id != connector_id);
            Ok(())
        })?;

        let store = FailingStore::default();
        let credential_name = format!("connector.{connector_id}.test");
        let result = replace_connector_secrets_transactionally(
            &config_path,
            &store,
            &connector_id,
            connector_kind,
            &[(
                credential_name.clone(),
                SecretString::from("new-value".to_owned()),
            )],
            || Ok(()),
        );
        assert!(result.is_err());
        assert!(store.get(&credential_name)?.is_none());
        Ok(())
    }
}
