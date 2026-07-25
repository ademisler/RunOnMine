use anyhow::{Context as _, Result};
use runonmine_core::secrets::SecretStore;
use secrecy::SecretString;

pub(crate) fn replace_secrets_transactionally<T>(
    store: &dyn SecretStore,
    updates: &[(String, SecretString)],
    after_write: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let previous = updates
        .iter()
        .map(|(name, _)| Ok((name.clone(), store.get(name)?)))
        .collect::<Result<Vec<_>>>()?;
    let operation = (|| {
        for (name, value) in updates {
            store.set(name, value)?;
        }
        after_write()
    })();
    match operation {
        Ok(value) => Ok(value),
        Err(error) => {
            rollback(store, &previous).context(format!(
                "credential update failed and rollback was incomplete: {error:#}"
            ))?;
            Err(error)
        }
    }
}

fn rollback(store: &dyn SecretStore, previous: &[(String, Option<SecretString>)]) -> Result<()> {
    for (name, value) in previous.iter().rev() {
        match value {
            Some(value) => store.set(name, value)?,
            None => store.delete(name)?,
        }
    }
    Ok(())
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
        let store = FailingStore::default();
        store.set("first", &SecretString::from("old-first".to_owned()))?;
        store.set("second", &SecretString::from("old-second".to_owned()))?;
        *store
            .fail_on
            .lock()
            .map_err(|_| anyhow::anyhow!("lock failed"))? = Some("second".to_owned());
        let result = replace_secrets_transactionally(
            &store,
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
}
