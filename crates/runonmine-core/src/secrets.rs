use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
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
        let mut file = self.load()?;
        file.values.remove(name);
        self.save(&file)
    }
}

pub fn default_secret_store(_paths: &AppPaths) -> Result<Box<dyn SecretStore>> {
    #[cfg(target_os = "linux")]
    {
        let desktop_secret_service = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
            || std::env::var_os("XDG_RUNTIME_DIR").is_some();
        if !desktop_secret_service {
            return Ok(Box::new(EncryptedFileSecretStore::from_environment(
                _paths.state_dir.join("secrets.enc"),
                "dev.runonmine.agent",
            )?));
        }
    }
    Ok(Box::new(KeyringSecretStore::new("dev.runonmine.agent")))
}

fn decode_master_key(value: &str) -> Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(value))
        .or_else(|_| hex::decode(value))
        .context("RUNONMINE_MASTER_KEY must be 32 bytes encoded as base64 or hex")?;
    decoded
        .try_into()
        .map_err(|_| anyhow!("RUNONMINE_MASTER_KEY must decode to exactly 32 bytes"))
}

#[cfg(unix)]
fn restrict_secret_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_secret_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
