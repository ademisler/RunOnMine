//! Durable connector-removal journal and idempotent cleanup primitives.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::{AppConfig, ConnectorConfig, ConnectorKind};
use crate::secrets::{SecretStore, SecretTransaction};
use crate::{AppPaths, StateStore, atomic};

const JOURNAL_VERSION: u32 = 1;
const MAX_RECORD_BYTES: u64 = 64 * 1024;
const REMOVAL_LOCK_FILE: &str = "connector-removals.lock";

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorRemovalPhase {
    IntentRecorded,
    ConfigurationRemoved,
    AuthorizationRemoved,
    OAuthRemoved,
    DirectoriesRemoved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorRemovalRecord {
    pub version: u32,
    pub connector_id: String,
    pub connector_kind: ConnectorKind,
    pub connector_fingerprint: String,
    pub phase: ConnectorRemovalPhase,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ConnectorRemovalRecord {
    fn new(connector: &ConnectorConfig) -> Result<Self> {
        crate::validate_connector_id(&connector.id)?;
        let now = Utc::now();
        Ok(Self {
            version: JOURNAL_VERSION,
            connector_id: connector.id.clone(),
            connector_kind: connector.kind,
            connector_fingerprint: connector_fingerprint(connector)?,
            phase: ConnectorRemovalPhase::IntentRecorded,
            created_at: now,
            updated_at: now,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.version != JOURNAL_VERSION {
            bail!("unsupported connector-removal journal version");
        }
        crate::validate_connector_id(&self.connector_id)?;
        if self.connector_fingerprint.len() != 64
            || !self
                .connector_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("connector-removal journal fingerprint is invalid");
        }
        if self.updated_at < self.created_at {
            bail!("connector-removal journal timestamps are invalid");
        }
        Ok(())
    }

    pub fn requires_oauth_cleanup(&self) -> bool {
        self.connector_kind == ConnectorKind::CloudflareOauth
    }

    pub fn secret_names(&self) -> Vec<String> {
        connector_secret_suffixes(self.connector_kind)
            .iter()
            .map(|suffix| format!("connector.{}.{suffix}", self.connector_id))
            .collect()
    }
}

#[derive(Debug)]
pub struct ConnectorRemovalLock {
    _file: File,
}

impl ConnectorRemovalLock {
    pub fn acquire(paths: &AppPaths) -> Result<Self> {
        paths.ensure()?;
        let path = paths.state_dir.join(REMOVAL_LOCK_FILE);
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to use a symlinked connector-removal lock");
        }
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .context("failed to open connector-removal lock")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.lock_exclusive()
            .context("failed to lock connector-removal journal")?;
        Ok(Self { _file: file })
    }
}

fn connector_fingerprint(connector: &ConnectorConfig) -> Result<String> {
    let bytes = serde_json::to_vec(connector)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Clone, Debug)]
pub struct ConnectorRemovalJournal {
    directory: PathBuf,
}

impl ConnectorRemovalJournal {
    pub fn new(paths: &AppPaths) -> Self {
        Self {
            directory: paths.connector_removals_dir(),
        }
    }

    pub fn begin(&self, connector: &ConnectorConfig) -> Result<ConnectorRemovalRecord> {
        let record = ConnectorRemovalRecord::new(connector)?;
        self.ensure_directory()?;
        let path = self.record_path(&record.connector_id)?;
        match Self::read_path(&path) {
            Ok(existing) => {
                if existing.connector_kind != record.connector_kind
                    || existing.connector_fingerprint != record.connector_fingerprint
                {
                    bail!("connector-removal journal does not match configured connector");
                }
                Ok(existing)
            }
            Err(error) if is_not_found(&error) => {
                self.write(&record)?;
                Ok(record)
            }
            Err(error) => Err(error),
        }
    }

    pub fn get(&self, connector_id: &str) -> Result<Option<ConnectorRemovalRecord>> {
        crate::validate_connector_id(connector_id)?;
        let path = self.record_path(connector_id)?;
        match Self::read_path(&path) {
            Ok(record) => Ok(Some(record)),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub fn pending(&self) -> Result<Vec<ConnectorRemovalRecord>> {
        match fs::symlink_metadata(&self.directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!("connector-removal journal path must be a real directory")
            }
            Ok(_) => {}
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                records.push(Self::read_path(&path)?);
                if records.len() > 256 {
                    bail!("too many pending connector-removal records");
                }
            }
        }
        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.connector_id.cmp(&right.connector_id))
        });
        Ok(records)
    }

    pub fn advance(
        &self,
        record: &ConnectorRemovalRecord,
        phase: ConnectorRemovalPhase,
    ) -> Result<ConnectorRemovalRecord> {
        record.validate()?;
        if phase < record.phase {
            bail!("connector-removal journal cannot move backwards");
        }
        let current = self
            .get(&record.connector_id)?
            .context("connector-removal journal disappeared during cleanup")?;
        if current.connector_kind != record.connector_kind
            || current.connector_fingerprint != record.connector_fingerprint
        {
            bail!("connector-removal journal identity changed during cleanup");
        }
        if current.phase > phase {
            return Ok(current);
        }
        let mut updated = current;
        updated.phase = phase;
        updated.updated_at = Utc::now();
        self.write(&updated)?;
        Ok(updated)
    }

    pub fn complete(&self, record: &ConnectorRemovalRecord) -> Result<()> {
        record.validate()?;
        if record.phase != ConnectorRemovalPhase::DirectoriesRemoved {
            bail!("connector-removal journal cannot complete before all cleanup phases");
        }
        let path = self.record_path(&record.connector_id)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("connector-removal record must be a regular non-symlink file")
            }
            Ok(_) => {
                fs::remove_file(&path)?;
                sync_parent(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    pub fn ensure_id_available(&self, connector_id: &str) -> Result<()> {
        if self.get(connector_id)?.is_some() {
            bail!("connector id is still pending removal; complete cleanup before reusing it");
        }
        Ok(())
    }

    fn write(&self, record: &ConnectorRemovalRecord) -> Result<()> {
        record.validate()?;
        self.ensure_directory()?;
        let path = self.record_path(&record.connector_id)?;
        let bytes = serde_json::to_vec_pretty(record)?;
        atomic::write(&path, &bytes, 0o600)
    }

    fn read_path(path: &Path) -> Result<ConnectorRemovalRecord> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_RECORD_BYTES
        {
            bail!("connector-removal record is not a safe bounded regular file");
        }
        let record: ConnectorRemovalRecord = serde_json::from_slice(&fs::read(path)?)
            .context("connector-removal record is invalid")?;
        record.validate()?;
        let expected = path
            .file_stem()
            .and_then(|name| name.to_str())
            .context("connector-removal record filename is invalid")?;
        if expected != record.connector_id {
            bail!("connector-removal record filename does not match its connector id");
        }
        Ok(record)
    }

    fn ensure_directory(&self) -> Result<()> {
        match fs::symlink_metadata(&self.directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!("connector-removal journal path must be a real directory")
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.directory)?;
            }
            Err(error) => return Err(error.into()),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn record_path(&self, connector_id: &str) -> Result<PathBuf> {
        crate::validate_connector_id(connector_id)?;
        Ok(self.directory.join(format!("{connector_id}.json")))
    }
}

pub fn remove_connector_configuration_and_secrets(
    paths: &AppPaths,
    secrets: &dyn SecretStore,
    record: &ConnectorRemovalRecord,
) -> Result<()> {
    record.validate()?;
    let config_path = paths.config_file();
    let mut transaction = SecretTransaction::new(secrets);
    if config_path.exists() {
        AppConfig::update_with_rollback(
            &config_path,
            &mut transaction,
            |config, transaction| {
                if let Some(index) = config
                    .connectors
                    .iter()
                    .position(|connector| connector.id == record.connector_id)
                {
                    let configured = &config.connectors[index];
                    if configured.kind != record.connector_kind
                        || connector_fingerprint(configured)? != record.connector_fingerprint
                    {
                        bail!("pending removal connector no longer matches configuration");
                    }
                    config.connectors.remove(index);
                }
                for name in record.secret_names() {
                    transaction.delete(&name)?;
                }
                Ok(())
            },
            SecretTransaction::rollback,
        )?;
    } else {
        for name in record.secret_names() {
            if let Err(error) = transaction.delete(&name) {
                return match transaction.rollback() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(error.context(format!(
                        "connector secret rollback also failed: {rollback:#}"
                    ))),
                };
            }
        }
    }
    Ok(())
}

pub fn remove_connector_authorization(paths: &AppPaths, connector_id: &str) -> Result<()> {
    StateStore::open(&paths.state_db())?.clear_connector_authorization(connector_id)?;
    Ok(())
}

pub fn remove_connector_directories(paths: &AppPaths, connector_id: &str) -> Result<()> {
    crate::validate_connector_id(connector_id)?;
    for parent in [
        paths.data_dir.join("connectors"),
        paths.state_dir.join("connectors"),
    ] {
        remove_connector_child(&parent, connector_id)?;
    }
    let profiles = paths.browser_profiles();
    match fs::symlink_metadata(&profiles) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("browser profiles path must be a real directory")
        }
        Ok(_) => {
            for entry in fs::read_dir(&profiles)? {
                let entry = entry?;
                let metadata = fs::symlink_metadata(entry.path())?;
                if metadata.file_type().is_symlink() {
                    bail!("browser profiles directory contains a symlinked entry");
                }
                if metadata.is_dir() {
                    remove_connector_child(&entry.path(), connector_id)?;
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn remove_connector_child(parent: &Path, connector_id: &str) -> Result<()> {
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!(
                "connector artifact parent must be a real directory: {}",
                parent.display()
            )
        }
        Ok(_) => {}
    }
    remove_real_directory_if_exists(&parent.join(connector_id))
}

pub fn connector_secret_suffixes(kind: ConnectorKind) -> &'static [&'static str] {
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

fn remove_real_directory_if_exists(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "refusing to remove symlinked connector directory: {}",
                path.display()
            )
        }
        Ok(metadata) if metadata.is_dir() => {
            fs::remove_dir_all(path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
        }
        Ok(_) => bail!(
            "connector state path is not a directory: {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "parent directory fsync is Unix-only while connector removal keeps one fallible interface"
)]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use secrecy::SecretString;

    use super::*;
    use crate::PolicyPreset;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<BTreeMap<String, SecretString>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get(&self, name: &str) -> Result<Option<SecretString>> {
            Ok(self
                .values
                .lock()
                .map_err(|_| anyhow::anyhow!("secret mutex was poisoned"))?
                .get(name)
                .cloned())
        }

        fn set(&self, name: &str, value: &SecretString) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("secret mutex was poisoned"))?
                .insert(name.to_owned(), value.clone());
            Ok(())
        }

        fn delete(&self, name: &str) -> Result<()> {
            self.values
                .lock()
                .map_err(|_| anyhow::anyhow!("secret mutex was poisoned"))?
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
            cloudflare_quick: Some(crate::CloudflareQuickSettings::default()),
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: None,
        }
    }

    #[test]
    fn journal_is_private_monotonic_and_idempotent() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let connector = connector("remove-me");
        let journal = ConnectorRemovalJournal::new(&paths);
        let first = journal.begin(&connector)?;
        let second = journal.begin(&connector)?;
        assert_eq!(first, second);
        assert_eq!(journal.pending()?, vec![first.clone()]);
        assert!(journal.ensure_id_available(&connector.id).is_err());
        let advanced = journal.advance(&first, ConnectorRemovalPhase::ConfigurationRemoved)?;
        assert_eq!(advanced.phase, ConnectorRemovalPhase::ConfigurationRemoved);
        assert!(
            journal
                .advance(&advanced, ConnectorRemovalPhase::IntentRecorded)
                .is_err()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let path = journal.record_path(&connector.id)?;
            assert_eq!(path.metadata()?.permissions().mode() & 0o777, 0o600);
        }
        let completed = journal.advance(&advanced, ConnectorRemovalPhase::DirectoriesRemoved)?;
        journal.complete(&completed)?;
        journal.complete(&completed)?;
        assert!(journal.pending()?.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn partial_cleanup_can_resume_from_persisted_phase() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let connector = connector("partial-remove");
        let mut config = AppConfig::default();
        config.connectors.push(connector.clone());
        config.save(&paths.config_file())?;
        let secrets = MemorySecretStore::default();
        let secret_name = format!("connector.{}.path_secret", connector.id);
        secrets.set(&secret_name, &SecretString::from("secret".to_owned()))?;
        let journal = ConnectorRemovalJournal::new(&paths);
        let mut record = journal.begin(&connector)?;

        remove_connector_configuration_and_secrets(&paths, &secrets, &record)?;
        record = journal.advance(&record, ConnectorRemovalPhase::ConfigurationRemoved)?;
        remove_connector_authorization(&paths, &record.connector_id)?;
        record = journal.advance(&record, ConnectorRemovalPhase::AuthorizationRemoved)?;
        record = journal.advance(&record, ConnectorRemovalPhase::OAuthRemoved)?;

        let connector_directory = paths.data_dir.join("connectors").join(&connector.id);
        fs::create_dir_all(
            connector_directory
                .parent()
                .context("connector directory has no parent")?,
        )?;
        let outside = directory.path().join("outside");
        fs::create_dir(&outside)?;
        symlink(&outside, &connector_directory)?;
        assert!(remove_connector_directories(&paths, &record.connector_id).is_err());
        assert_eq!(
            journal.get(&record.connector_id)?.map(|item| item.phase),
            Some(ConnectorRemovalPhase::OAuthRemoved)
        );
        assert!(
            AppConfig::load(&paths.config_file())?
                .connector(&connector.id)
                .is_none()
        );
        assert!(secrets.get(&secret_name)?.is_none());

        fs::remove_file(&connector_directory)?;
        fs::create_dir(&connector_directory)?;
        remove_connector_directories(&paths, &record.connector_id)?;
        record = journal.advance(&record, ConnectorRemovalPhase::DirectoriesRemoved)?;
        journal.complete(&record)?;
        assert!(!connector_directory.exists());
        assert!(journal.get(&connector.id)?.is_none());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn removal_lock_is_private_and_symlinks_are_rejected() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let lock = ConnectorRemovalLock::acquire(&paths)?;
        let lock_path = paths.state_dir.join(REMOVAL_LOCK_FILE);
        assert_eq!(lock_path.metadata()?.permissions().mode() & 0o777, 0o600);
        drop(lock);
        fs::remove_file(&lock_path)?;
        let outside = directory.path().join("outside-lock");
        fs::write(&outside, b"outside")?;
        symlink(&outside, &lock_path)?;
        assert!(ConnectorRemovalLock::acquire(&paths).is_err());
        assert_eq!(fs::read(outside)?, b"outside");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn connector_cleanup_rejects_symlinked_artifact_parents() -> Result<()> {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let outside = directory.path().join("outside-artifacts");
        fs::create_dir(&outside)?;
        symlink(&outside, paths.data_dir.join("connectors"))?;
        assert!(remove_connector_directories(&paths, "connector-id").is_err());
        assert!(outside.is_dir());
        Ok(())
    }
}
