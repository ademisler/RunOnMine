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
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{AppPaths, atomic};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecretInventory {
    pub names: Vec<String>,
    pub complete: bool,
    pub source: &'static str,
}

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<SecretString>>;
    fn set(&self, name: &str, value: &SecretString) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;

    fn inventory(&self) -> Result<SecretInventory> {
        Ok(SecretInventory {
            names: Vec::new(),
            complete: false,
            source: "backend_not_enumerable",
        })
    }
}

/// Records original secret values before mutation so a coordinating caller
/// can restore them after a handled error without exposing secret contents.
pub struct SecretTransaction<'a> {
    store: &'a dyn SecretStore,
    backups: BTreeMap<String, Option<SecretString>>,
    durable: Option<DurableSecretTransaction>,
}

impl std::fmt::Debug for SecretTransaction<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretTransaction")
            .field("backup_count", &self.backups.len())
            .field("durable", &self.durable.is_some())
            .finish_non_exhaustive()
    }
}

impl<'a> SecretTransaction<'a> {
    /// Starts an empty transaction against the selected secret store.
    pub fn new(store: &'a dyn SecretStore) -> Self {
        Self {
            store,
            backups: BTreeMap::new(),
            durable: None,
        }
    }

    pub fn begin_durable(
        &mut self,
        config_path: &Path,
        original_config: Option<&[u8]>,
    ) -> Result<()> {
        if self.durable.is_some() || !self.backups.is_empty() {
            bail!("durable secret transaction must begin before mutation");
        }
        self.durable = Some(DurableSecretTransaction::begin(
            config_path,
            original_config,
        )?);
        Ok(())
    }

    fn remember(&mut self, name: &str) -> Result<()> {
        if self.backups.contains_key(name) {
            return Ok(());
        }
        let original = self.store.get(name)?;
        if let Some(durable) = &mut self.durable {
            durable.capture(self.store, name, original.as_ref())?;
        }
        self.backups.insert(name.to_owned(), original);
        Ok(())
    }

    pub fn mark_config_committed(&mut self) -> Result<()> {
        let durable = self
            .durable
            .as_mut()
            .context("durable transaction was not started")?;
        durable.mark_committed()
    }

    pub fn finish_committed(&mut self) -> Result<()> {
        let Some(mut durable) = self.durable.take() else {
            return Ok(());
        };
        durable.finish_committed(self.store)
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
        if let Some(mut durable) = self.durable.take() {
            durable.finish_rolled_back(self.store)?;
        }
        Ok(())
    }
}

const DURABLE_TRANSACTION_VERSION: u16 = 1;
const MAX_DURABLE_JOURNAL_BYTES: u64 = 4 * 1_024 * 1_024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DurableTransactionPhase {
    Prepared,
    ConfigCommitted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableSecretBackup {
    backup_name: String,
    existed: bool,
    captured: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableTransactionJournal {
    version: u16,
    generation: Uuid,
    phase: DurableTransactionPhase,
    original_config: Option<String>,
    original_config_digest: Option<String>,
    backups: BTreeMap<String, DurableSecretBackup>,
}

#[derive(Debug)]
struct DurableSecretTransaction {
    journal_path: PathBuf,
    journal: DurableTransactionJournal,
    _lock: ProcessFileLock,
}

impl DurableSecretTransaction {
    fn begin(config_path: &Path, original_config: Option<&[u8]>) -> Result<Self> {
        let journal_path = durable_transaction_journal_path(config_path)?;
        let lock = ProcessFileLock::acquire(&durable_transaction_lock_path(&journal_path))?;
        if journal_path.exists() {
            bail!("a pending config/secret transaction must be recovered first");
        }
        if original_config.is_some_and(|bytes| bytes.len() as u64 > MAX_DURABLE_JOURNAL_BYTES) {
            bail!("configuration snapshot exceeds the durable transaction limit");
        }
        let encoded =
            original_config.map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes));
        let digest = original_config.map(|bytes| blake3::hash(bytes).to_hex().to_string());
        let journal = DurableTransactionJournal {
            version: DURABLE_TRANSACTION_VERSION,
            generation: Uuid::new_v4(),
            phase: DurableTransactionPhase::Prepared,
            original_config: encoded,
            original_config_digest: digest,
            backups: BTreeMap::new(),
        };
        let transaction = Self {
            journal_path,
            journal,
            _lock: lock,
        };
        transaction.persist()?;
        Ok(transaction)
    }

    fn capture(
        &mut self,
        store: &dyn SecretStore,
        name: &str,
        original: Option<&SecretString>,
    ) -> Result<()> {
        if self.journal.backups.contains_key(name) {
            return Ok(());
        }
        let backup_name = format!(
            "transaction.{}.{}",
            self.journal.generation,
            blake3::hash(name.as_bytes()).to_hex()
        );
        self.journal.backups.insert(
            name.to_owned(),
            DurableSecretBackup {
                backup_name: backup_name.clone(),
                existed: original.is_some(),
                captured: false,
            },
        );
        self.persist()?;
        if let Some(value) = original {
            store.set(&backup_name, value)?;
        }
        self.journal
            .backups
            .get_mut(name)
            .context("durable secret backup disappeared")?
            .captured = true;
        self.persist()
    }

    fn mark_committed(&mut self) -> Result<()> {
        self.journal.phase = DurableTransactionPhase::ConfigCommitted;
        self.persist()
    }

    fn finish_committed(&mut self, store: &dyn SecretStore) -> Result<()> {
        if self.journal.phase != DurableTransactionPhase::ConfigCommitted {
            bail!("durable transaction is not committed");
        }
        self.cleanup(store)
    }

    fn finish_rolled_back(&mut self, store: &dyn SecretStore) -> Result<()> {
        self.cleanup(store)
    }

    fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.journal)?;
        if bytes.len() as u64 > MAX_DURABLE_JOURNAL_BYTES {
            bail!("durable config/secret transaction journal exceeds the size limit");
        }
        atomic::write(&self.journal_path, &bytes, 0o600)?;
        restrict_secret_file(&self.journal_path)
    }

    fn cleanup(&mut self, store: &dyn SecretStore) -> Result<()> {
        for backup in self.journal.backups.values() {
            store.delete(&backup.backup_name)?;
        }
        remove_regular_file_if_present(&self.journal_path)?;
        Ok(())
    }
}

pub fn recover_pending_config_secret_transaction(
    config_path: &Path,
    store: &dyn SecretStore,
) -> Result<bool> {
    let journal_path = durable_transaction_journal_path(config_path)?;
    let _lock = ProcessFileLock::acquire(&durable_transaction_lock_path(&journal_path))?;
    let Some(journal) = load_durable_journal(&journal_path)? else {
        return Ok(false);
    };
    if journal.phase == DurableTransactionPhase::Prepared {
        restore_config_bytes(config_path, &journal)?;
        for (name, backup) in &journal.backups {
            if !backup.captured {
                continue;
            }
            if backup.existed {
                let value = store
                    .get(&backup.backup_name)?
                    .context("durable secret backup is missing")?;
                store.set(name, &value)?;
            } else {
                store.delete(name)?;
            }
        }
    }
    for backup in journal.backups.values() {
        store.delete(&backup.backup_name)?;
    }
    remove_regular_file_if_present(&journal_path)?;
    Ok(true)
}

fn durable_transaction_journal_path(config_path: &Path) -> Result<PathBuf> {
    let file_name = config_path
        .file_name()
        .context("configuration path has no file name")?;
    let mut journal_name = file_name.to_os_string();
    journal_name.push(".secret-transaction.json");
    Ok(config_path.with_file_name(journal_name))
}

fn durable_transaction_lock_path(journal_path: &Path) -> PathBuf {
    let mut name = journal_path.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    journal_path.with_file_name(name)
}

fn load_durable_journal(path: &Path) -> Result<Option<DurableTransactionJournal>> {
    let metadata = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_DURABLE_JOURNAL_BYTES
    {
        bail!("durable config/secret transaction journal is unsafe");
    }
    let journal: DurableTransactionJournal = serde_json::from_slice(&fs::read(path)?)?;
    if journal.version != DURABLE_TRANSACTION_VERSION {
        bail!("unsupported durable config/secret transaction journal version");
    }
    Ok(Some(journal))
}

fn restore_config_bytes(path: &Path, journal: &DurableTransactionJournal) -> Result<()> {
    match (&journal.original_config, &journal.original_config_digest) {
        (Some(encoded), Some(expected_digest)) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .context("durable configuration snapshot is invalid")?;
            if blake3::hash(&bytes).to_hex().as_str() != expected_digest {
                bail!("durable configuration snapshot digest does not match");
            }
            atomic::write(path, &bytes, 0o600)?;
            restrict_secret_file(path)
        }
        (None, None) => remove_regular_file_if_present(path),
        _ => bail!("durable configuration snapshot metadata is inconsistent"),
    }
}

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("refusing to remove an unsafe durable transaction file")
        }
        Ok(_) => {
            fs::remove_file(path)?;
            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        }
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
        let raw = load_master_key_material()?;
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

    fn inventory(&self) -> Result<SecretInventory> {
        let _guard = self.lock()?;
        let _file_guard = self.process_file_lock()?;
        let file = self.load()?;
        Ok(SecretInventory {
            names: file.values.keys().cloned().collect(),
            complete: true,
            source: "encrypted_file",
        })
    }
}

const SECRET_INDEX_VERSION: u16 = 1;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretNameIndex {
    version: u16,
    names: BTreeMap<String, bool>,
}

struct IndexedSecretStore {
    inner: Box<dyn SecretStore>,
    index_path: PathBuf,
    lock: Mutex<()>,
}

impl std::fmt::Debug for IndexedSecretStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IndexedSecretStore")
            .field("index_path", &self.index_path)
            .finish_non_exhaustive()
    }
}

impl IndexedSecretStore {
    fn new(inner: Box<dyn SecretStore>, index_path: PathBuf) -> Self {
        Self {
            inner,
            index_path,
            lock: Mutex::new(()),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| anyhow!("secret inventory lock is poisoned"))
    }

    fn file_lock_path(&self) -> PathBuf {
        let mut name = self
            .index_path
            .file_name()
            .unwrap_or_default()
            .to_os_string();
        name.push(".lock");
        self.index_path.with_file_name(name)
    }

    fn load_index(&self) -> Result<SecretNameIndex> {
        match fs::symlink_metadata(&self.index_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(SecretNameIndex {
                version: SECRET_INDEX_VERSION,
                names: BTreeMap::new(),
            }),
            Err(error) => Err(error.into()),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("secret inventory must be a regular non-symlink file")
            }
            Ok(_) => {
                let index: SecretNameIndex = serde_json::from_slice(&fs::read(&self.index_path)?)?;
                if index.version != SECRET_INDEX_VERSION {
                    bail!("unsupported secret inventory version");
                }
                Ok(index)
            }
        }
    }

    fn save_index(&self, index: &SecretNameIndex) -> Result<()> {
        let parent = self
            .index_path
            .parent()
            .context("secret inventory path has no parent")?;
        fs::create_dir_all(parent)?;
        restrict_secret_directory(parent)?;
        atomic::write(&self.index_path, &serde_json::to_vec(index)?, 0o600)?;
        restrict_secret_file(&self.index_path)
    }

    fn record_name(&self, name: &str, present: bool) -> Result<()> {
        let _guard = self.lock()?;
        let _process_guard = ProcessFileLock::acquire(&self.file_lock_path())?;
        let mut index = self.load_index()?;
        if present {
            index.names.insert(name.to_owned(), true);
        } else {
            index.names.remove(name);
        }
        self.save_index(&index)
    }
}

impl SecretStore for IndexedSecretStore {
    fn get(&self, name: &str) -> Result<Option<SecretString>> {
        self.inner.get(name)
    }

    fn set(&self, name: &str, value: &SecretString) -> Result<()> {
        self.inner.set(name, value)?;
        self.record_name(name, true)
    }

    fn delete(&self, name: &str) -> Result<()> {
        self.inner.delete(name)?;
        self.record_name(name, false)
    }

    fn inventory(&self) -> Result<SecretInventory> {
        let _guard = self.lock()?;
        let _process_guard = ProcessFileLock::acquire(&self.file_lock_path())?;
        let index = self.load_index()?;
        let native = self.inner.inventory()?;
        let mut names = native
            .names
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        names.extend(index.names.into_keys());
        Ok(SecretInventory {
            names: names.into_iter().collect(),
            complete: native.complete,
            source: if native.complete {
                "backend_and_managed_index"
            } else {
                "managed_index_partial"
            },
        })
    }
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn default_secret_store(paths: &AppPaths) -> Result<Box<dyn SecretStore>> {
    #[cfg(debug_assertions)]
    let inner: Box<dyn SecretStore> = if std::env::var_os("RUNONMINE_TEST_FILE_SECRETS").is_some() {
        Box::new(EncryptedFileSecretStore::from_environment(
            paths.state_dir.join("secrets.enc"),
            "dev.runonmine.agent",
        )?)
    } else {
        default_platform_secret_store(paths)?
    };
    #[cfg(not(debug_assertions))]
    let inner = default_platform_secret_store(paths)?;
    Ok(Box::new(IndexedSecretStore::new(
        inner,
        paths.state_dir.join("secret-names.json"),
    )))
}

#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
fn default_platform_secret_store(paths: &AppPaths) -> Result<Box<dyn SecretStore>> {
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

const SYSTEMD_MASTER_KEY_CREDENTIAL: &str = "runonmine-master-key";
const MAX_MASTER_KEY_FILE_BYTES: u64 = 4 * 1_024;

fn load_master_key_material() -> Result<Zeroizing<String>> {
    if let Some(directory) = std::env::var_os("CREDENTIALS_DIRECTORY") {
        return read_master_key_credential(
            &PathBuf::from(directory).join(SYSTEMD_MASTER_KEY_CREDENTIAL),
        );
    }
    let raw = std::env::var("RUNONMINE_MASTER_KEY").context(
        "headless secret storage requires a systemd runonmine-master-key credential or RUNONMINE_MASTER_KEY",
    )?;
    Ok(Zeroizing::new(raw))
}

fn read_master_key_credential(path: &Path) -> Result<Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "failed to inspect master-key credential at {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MASTER_KEY_FILE_BYTES
    {
        bail!("master-key credential must be a bounded regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("master-key credential permissions are too broad");
        }
    }
    let raw = Zeroizing::new(fs::read_to_string(path)?);
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|byte| byte.is_ascii_whitespace()) {
        bail!("master-key credential contains invalid whitespace");
    }
    Ok(Zeroizing::new(trimmed.to_owned()))
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

    fn secret_text(store: &dyn SecretStore, name: &str) -> Result<Option<String>> {
        Ok(store
            .get(name)?
            .map(|value| value.expose_secret().to_owned()))
    }

    fn transaction_backup_count(store: &MemorySecretStore) -> Result<usize> {
        Ok(store
            .values
            .lock()
            .map_err(|_| anyhow!("test secret store lock failed"))?
            .keys()
            .filter(|name| name.starts_with("transaction."))
            .count())
    }

    #[test]
    fn prepared_durable_transaction_recovers_config_and_secrets_after_drop() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        fs::write(&config_path, b"version = 'original'\n")?;
        let store = MemorySecretStore::default();
        store.set(
            "connector.token",
            &SecretString::from("original-secret".to_owned()),
        )?;

        {
            let mut transaction = SecretTransaction::new(&store);
            transaction.begin_durable(&config_path, Some(&fs::read(&config_path)?))?;
            transaction.set(
                "connector.token",
                &SecretString::from("new-secret".to_owned()),
            )?;
            transaction.set(
                "connector.new",
                &SecretString::from("temporary-secret".to_owned()),
            )?;
            fs::write(&config_path, b"version = 'new'\n")?;
        }

        assert_eq!(transaction_backup_count(&store)?, 1);
        assert!(recover_pending_config_secret_transaction(
            &config_path,
            &store
        )?);
        assert_eq!(fs::read(&config_path)?, b"version = 'original'\n");
        assert_eq!(
            secret_text(&store, "connector.token")?,
            Some("original-secret".to_owned())
        );
        assert!(store.get("connector.new")?.is_none());
        assert_eq!(transaction_backup_count(&store)?, 0);
        assert!(!durable_transaction_journal_path(&config_path)?.exists());
        assert!(!recover_pending_config_secret_transaction(
            &config_path,
            &store
        )?);
        Ok(())
    }

    #[test]
    fn committed_durable_transaction_preserves_new_state_and_cleans_after_drop() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        fs::write(&config_path, b"version = 'original'\n")?;
        let store = MemorySecretStore::default();
        store.set(
            "connector.token",
            &SecretString::from("original-secret".to_owned()),
        )?;

        {
            let mut transaction = SecretTransaction::new(&store);
            transaction.begin_durable(&config_path, Some(&fs::read(&config_path)?))?;
            transaction.set(
                "connector.token",
                &SecretString::from("new-secret".to_owned()),
            )?;
            fs::write(&config_path, b"version = 'new'\n")?;
            transaction.mark_config_committed()?;
        }

        assert!(recover_pending_config_secret_transaction(
            &config_path,
            &store
        )?);
        assert_eq!(fs::read(&config_path)?, b"version = 'new'\n");
        assert_eq!(
            secret_text(&store, "connector.token")?,
            Some("new-secret".to_owned())
        );
        assert_eq!(transaction_backup_count(&store)?, 0);
        assert!(!durable_transaction_journal_path(&config_path)?.exists());
        Ok(())
    }

    #[test]
    fn future_durable_journal_fails_closed_without_mutating_state() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        fs::write(&config_path, b"current-config")?;
        let store = MemorySecretStore::default();
        store.set(
            "connector.token",
            &SecretString::from("current-secret".to_owned()),
        )?;
        let journal_path = durable_transaction_journal_path(&config_path)?;
        let journal = DurableTransactionJournal {
            version: DURABLE_TRANSACTION_VERSION + 1,
            generation: Uuid::new_v4(),
            phase: DurableTransactionPhase::Prepared,
            original_config: Some(base64::engine::general_purpose::STANDARD.encode(b"old-config")),
            original_config_digest: Some(blake3::hash(b"old-config").to_hex().to_string()),
            backups: BTreeMap::new(),
        };
        atomic::write(&journal_path, &serde_json::to_vec(&journal)?, 0o600)?;

        assert!(recover_pending_config_secret_transaction(&config_path, &store).is_err());
        assert_eq!(fs::read(&config_path)?, b"current-config");
        assert_eq!(
            secret_text(&store, "connector.token")?,
            Some("current-secret".to_owned())
        );
        assert!(journal_path.exists());
        Ok(())
    }

    #[test]
    fn durable_journal_creation_failure_precedes_secret_mutation() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        fs::write(&config_path, b"original")?;
        let journal_path = durable_transaction_journal_path(&config_path)?;
        fs::create_dir(&journal_path)?;
        let store = MemorySecretStore::default();
        store.set(
            "connector.token",
            &SecretString::from("original-secret".to_owned()),
        )?;
        let mut transaction = SecretTransaction::new(&store);

        assert!(
            transaction
                .begin_durable(&config_path, Some(&fs::read(&config_path)?))
                .is_err()
        );
        assert_eq!(
            secret_text(&store, "connector.token")?,
            Some("original-secret".to_owned())
        );
        assert_eq!(transaction_backup_count(&store)?, 0);
        Ok(())
    }

    #[test]
    fn concurrent_recovery_applies_one_generation_once() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let config_path = directory.path().join("config.toml");
        fs::write(&config_path, b"original")?;
        let store = std::sync::Arc::new(MemorySecretStore::default());
        store.set(
            "connector.token",
            &SecretString::from("original-secret".to_owned()),
        )?;
        {
            let mut transaction = SecretTransaction::new(store.as_ref());
            transaction.begin_durable(&config_path, Some(b"original"))?;
            transaction.set(
                "connector.token",
                &SecretString::from("new-secret".to_owned()),
            )?;
            fs::write(&config_path, b"new")?;
        }
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let path = config_path.clone();
            let store = store.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || -> Result<bool> {
                barrier.wait();
                recover_pending_config_secret_transaction(&path, store.as_ref())
            }));
        }
        barrier.wait();
        let mut outcomes = Vec::new();
        for thread in threads {
            outcomes.push(
                thread
                    .join()
                    .map_err(|_| anyhow!("recovery thread panicked"))??,
            );
        }
        outcomes.sort_unstable();
        assert_eq!(outcomes, vec![false, true]);
        assert_eq!(fs::read(&config_path)?, b"original");
        assert_eq!(
            secret_text(store.as_ref(), "connector.token")?,
            Some("original-secret".to_owned())
        );
        assert_eq!(transaction_backup_count(store.as_ref())?, 0);
        Ok(())
    }

    #[test]
    fn indexed_store_tracks_names_without_secret_values() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let index_path = directory.path().join("secret-names.json");
        let store =
            IndexedSecretStore::new(Box::new(MemorySecretStore::default()), index_path.clone());
        store.set(
            "connector.00000000-0000-4000-8000-000000000123.token",
            &SecretString::from("never-write-this-value".to_owned()),
        )?;
        let inventory = store.inventory()?;
        assert_eq!(inventory.names.len(), 1);
        assert!(!inventory.complete);
        let serialized = String::from_utf8(fs::read(&index_path)?)?;
        assert!(serialized.contains("connector.00000000-0000-4000-8000-000000000123.token"));
        assert!(!serialized.contains("never-write-this-value"));
        store.delete("connector.00000000-0000-4000-8000-000000000123.token")?;
        assert!(store.inventory()?.names.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn master_key_credential_is_bounded_private_and_not_a_symlink() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let credential = directory.path().join(SYSTEMD_MASTER_KEY_CREDENTIAL);
        fs::write(&credential, format!("{}\n", "ab".repeat(32)))?;
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o400))?;
        assert_eq!(
            read_master_key_credential(&credential)?.as_str(),
            "ab".repeat(32)
        );

        fs::set_permissions(&credential, fs::Permissions::from_mode(0o644))?;
        assert!(read_master_key_credential(&credential).is_err());
        fs::set_permissions(&credential, fs::Permissions::from_mode(0o400))?;
        let link = directory.path().join("credential-link");
        symlink(&credential, &link)?;
        assert!(read_master_key_credential(&link).is_err());
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
