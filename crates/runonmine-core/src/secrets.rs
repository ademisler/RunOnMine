use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use fs2::FileExt as _;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{AppPaths, atomic};

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretString>>;
    fn set(&self, name: &str, value: &SecretString) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
}

/// Records original secret values before mutation so a coordinating caller
/// can restore them after a handled error without exposing secret contents.
pub struct SecretTransaction<'a> {
    store: &'a dyn SecretStore,
    backups: BTreeMap<String, Option<SecretString>>,
}

impl std::fmt::Debug for SecretTransaction<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretTransaction")
            .field("backup_count", &self.backups.len())
            .finish_non_exhaustive()
    }
}

impl<'a> SecretTransaction<'a> {
    /// Starts an empty transaction against the selected secret store.
    pub fn new(store: &'a dyn SecretStore) -> Self {
        Self {
            store,
            backups: BTreeMap::new(),
        }
    }

    fn remember(&mut self, name: &str) -> Result<()> {
        if !self.backups.contains_key(name) {
            self.backups.insert(name.to_owned(), self.store.get(name)?);
        }
        Ok(())
    }

    /// Stores a value after snapshotting the previous value once.
    pub fn set(&mut self, name: &str, value: &SecretString) -> Result<()> {
        self.remember(name)?;
        self.store.set(name, value)
    }

    /// Deletes a value after snapshotting the previous value once.
    pub fn delete(&mut self, name: &str) -> Result<()> {
        self.remember(name)?;
        self.store.delete(name)
    }

    /// Restores every snapshotted value and clears the rollback journal.
    pub fn rollback(&mut self) -> Result<()> {
        for (name, value) in &self.backups {
            match value {
                Some(value) => self.store.set(name, value)?,
                None => self.store.delete(name)?,
            }
        }
        self.backups.clear();
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct KeyringSecretStore {
    service: String,
}

impl KeyringSecretStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, name: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(&self.service, name).context("failed to open platform credential store")
    }
}

impl SecretStore for KeyringSecretStore {
    fn get(&self, name: &str) -> Result<Option<SecretString>> {
        match self.entry(name)?.get_password() {
            Ok(value) => Ok(Some(SecretString::from(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(error).context("failed to read platform credential"),
        }
    }

    fn set(&self, name: &str, value: &SecretString) -> Result<()> {
        self.entry(name)?
            .set_password(value.expose_secret())
            .context("failed to store platform credential")
    }

    fn delete(&self, name: &str) -> Result<()> {
        match self.entry(name)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(error).context("failed to delete platform credential"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct EncryptedValue {
    nonce: String,
    ciphertext: String,
}

#[derive(Default, Serialize, Deserialize)]
struct EncryptedSecretFile {
    version: u32,
    values: BTreeMap<String, EncryptedValue>,
}

#[derive(Debug)]
struct ProcessFileLock(File);

impl ProcessFileLock {
    fn acquire(path: &Path) -> Result<Self> {
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to use a symlinked encrypted secret store lock");
        }
        let parent = path.parent().context("secret lock path has no parent")?;
        fs::create_dir_all(parent)?;
        restrict_secret_directory(parent)?;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(path)?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;
        restrict_secret_file(path)?;
        file.lock_exclusive()
            .context("failed to lock encrypted secret store")?;
        Ok(Self(file))
    }
}

impl Drop for ProcessFileLock {
    fn drop(&mut self) {
        let _ignored = self.0.unlock();
    }
}

pub struct EncryptedFileSecretStore {
    path: PathBuf,
    service: String,
    key: Zeroizing<[u8; 32]>,
    lock: Mutex<()>,
}

impl std::fmt::Debug for EncryptedFileSecretStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedFileSecretStore")
            .field("path", &self.path)
            .field("service", &self.service)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl EncryptedFileSecretStore {
    pub fn from_environment(path: PathBuf, service: impl Into<String>) -> Result<Self> {
        let raw = std::env::var("RUNONMINE_MASTER_KEY")
            .context("headless secret storage requires RUNONMINE_MASTER_KEY")?;
        let key = decode_master_key(&raw)?;
        Ok(Self {
            path,
            service: service.into(),
            key: Zeroizing::new(key),
            lock: Mutex::new(()),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| anyhow!("encrypted secret store lock is poisoned"))
    }

    fn file_lock_path(&self) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(".lock");
        self.path.with_file_name(name)
    }

    fn process_file_lock(&self) -> Result<ProcessFileLock> {
        ProcessFileLock::acquire(&self.file_lock_path())
    }

    fn load(&self) -> Result<EncryptedSecretFile> {
        if !self.path.exists() {
            return Ok(EncryptedSecretFile {
                version: 1,
                values: BTreeMap::new(),
            });
        }
        if self
            .path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to read a symlinked encrypted secret store");
        }
        let file: EncryptedSecretFile = serde_json::from_slice(&fs::read(&self.path)?)?;
        if file.version != 1 {
            bail!("unsupported encrypted secret store version");
        }
        Ok(file)
    }

    fn save(&self, file: &EncryptedSecretFile) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("secret store path has no parent")?;
        fs::create_dir_all(parent)?;
        if self
            .path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to replace a symlinked encrypted secret store");
        }
        atomic::write(&self.path, &serde_json::to_vec(file)?, 0o600)?;
        restrict_secret_file(&self.path)?;
        Ok(())
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new((&*self.key).into())
    }

    fn aad(&self, name: &str) -> Vec<u8> {
        format!("{}\0{name}", self.service).into_bytes()
    }
}

impl SecretStore for EncryptedFileSecretStore {
    fn get(&self, name: &str) -> Result<Option<SecretString>> {
        let _guard = self.lock()?;
        let _file_guard = self.process_file_lock()?;
        let file = self.load()?;
        let Some(value) = file.values.get(name) else {
            return Ok(None);
        };
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&value.nonce)
            .context("invalid encrypted secret nonce")?;
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&value.ciphertext)
            .context("invalid encrypted secret ciphertext")?;
        if nonce.len() != 24 {
            bail!("invalid encrypted secret nonce length");
        }
        let plaintext = self
            .cipher()
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &self.aad(name),
                },
            )
            .map_err(|_| anyhow!("encrypted secret authentication failed"))?;
        let text = String::from_utf8(plaintext).context("encrypted secret is not valid UTF-8")?;
        Ok(Some(SecretString::from(text)))
    }

    fn set(&self, name: &str, value: &SecretString) -> Result<()> {
        let _guard = self.lock()?;
        let _file_guard = self.process_file_lock()?;
        let mut file = self.load()?;
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher()
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: value.expose_secret().as_bytes(),
                    aad: &self.aad(name),
                },
            )
            .map_err(|_| anyhow!("failed to encrypt secret"))?;
        file.values.insert(
            name.to_owned(),
            EncryptedValue {
                nonce: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(ciphertext),
            },
        );
        self.save(&file)
    }

    fn delete(&self, name: &str) -> Result<()> {
        let _guard = self.lock()?;
        let _file_guard = self.process_file_lock()?;
        let mut file = self.load()?;
        file.values.remove(name);
        self.save(&file)
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn default_secret_store(paths: &AppPaths) -> Result<Box<dyn SecretStore>> {
    #[cfg(debug_assertions)]
    if std::env::var_os("RUNONMINE_TEST_FILE_SECRETS").is_some() {
        return Ok(Box::new(EncryptedFileSecretStore::from_environment(
            paths.state_dir.join("secrets.enc"),
            "dev.runonmine.agent",
        )?));
    }
    #[cfg(target_os = "linux")]
    {
        let desktop_secret_service = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
            || std::env::var_os("XDG_RUNTIME_DIR").is_some();
        if !desktop_secret_service {
            return Ok(Box::new(EncryptedFileSecretStore::from_environment(
                paths.state_dir.join("secrets.enc"),
                "dev.runonmine.agent",
            )?));
        }
    }
    Ok(Box::new(KeyringSecretStore::new("dev.runonmine.agent")))
}

fn decode_master_key(value: &str) -> Result<[u8; 32]> {
    let decoded = if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        hex::decode(value)
            .context("RUNONMINE_MASTER_KEY must be 32 bytes encoded as base64 or hex")?
    } else {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
            .context("RUNONMINE_MASTER_KEY must be 32 bytes encoded as base64 or hex")?
    };
    decoded
        .try_into()
        .map_err(|_| anyhow!("RUNONMINE_MASTER_KEY must decode to exactly 32 bytes"))
}

#[cfg(unix)]
fn restrict_secret_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_secret_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_secret_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_secret_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<BTreeMap<String, String>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            Ok(self
                .values
                .lock()
                .map_err(|_| anyhow!("test secret store lock failed"))?
                .get(name)
                .cloned()
                .map(SecretString::from))
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow!("test secret store lock failed"))?
                .insert(name.to_owned(), value.expose_secret().to_owned());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow!("test secret store lock failed"))?
                .remove(name);
            Ok(())
        }
    }

    #[test]
    fn secret_transaction_restores_the_original_value_after_repeated_mutations() -> Result<()> {
        let store = MemorySecretStore::default();
        store.set("existing", &SecretString::from("original".to_owned()))?;
        let mut transaction = SecretTransaction::new(&store);
        transaction.set("existing", &SecretString::from("first".to_owned()))?;
        transaction.set("existing", &SecretString::from("second".to_owned()))?;
        transaction.set("new", &SecretString::from("temporary".to_owned()))?;
        transaction.delete("existing")?;
        transaction.rollback()?;

        assert_eq!(
            store
                .get("existing")?
                .map(|value| value.expose_secret().to_owned()),
            Some("original".to_owned())
        );
        assert!(store.get("new")?.is_none());
        Ok(())
    }

    #[test]
    fn master_key_decoder_distinguishes_hex_from_base64() -> Result<()> {
        let expected = [0xab_u8; 32];
        let hexadecimal = "ab".repeat(32);
        assert_eq!(decode_master_key(&hexadecimal)?, expected);

        let base64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(expected);
        assert_eq!(decode_master_key(&base64)?, expected);
        Ok(())
    }

    #[test]
    fn encrypted_store_serializes_updates_across_instances() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("secrets.enc");
        let first = std::sync::Arc::new(EncryptedFileSecretStore {
            path: path.clone(),
            service: "test".to_owned(),
            key: Zeroizing::new([9_u8; 32]),
            lock: Mutex::new(()),
        });
        let second = std::sync::Arc::new(EncryptedFileSecretStore {
            path,
            service: "test".to_owned(),
            key: Zeroizing::new([9_u8; 32]),
            lock: Mutex::new(()),
        });
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for (prefix, store) in [("first", first.clone()), ("second", second.clone())] {
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || -> Result<()> {
                barrier.wait();
                for index in 0..25 {
                    store.set(
                        &format!("{prefix}-{index}"),
                        &SecretString::from(format!("secret-{index}")),
                    )?;
                }
                Ok(())
            }));
        }
        barrier.wait();
        for thread in threads {
            thread
                .join()
                .map_err(|_| anyhow!("secret writer thread panicked"))??;
        }
        for prefix in ["first", "second"] {
            for index in 0..25 {
                assert!(first.get(&format!("{prefix}-{index}"))?.is_some());
            }
        }
        Ok(())
    }

    #[test]
    fn encrypted_store_round_trip_does_not_write_plaintext() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("secrets.enc");
        let store = EncryptedFileSecretStore {
            path: path.clone(),
            service: "test".to_owned(),
            key: Zeroizing::new([7_u8; 32]),
            lock: Mutex::new(()),
        };
        store.set("token", &SecretString::from("plain-secret".to_owned()))?;
        assert_eq!(
            store
                .get("token")?
                .map(|value| value.expose_secret().to_owned()),
            Some("plain-secret".to_owned())
        );
        assert!(!String::from_utf8_lossy(&fs::read(path)?).contains("plain-secret"));
        Ok(())
    }
}
