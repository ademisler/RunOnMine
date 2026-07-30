//! Immutable managed binary versions with serialized atomic active-manifest switching.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const MANIFEST_VERSION: u16 = 1;
const ACTIVE_MANIFEST: &str = "active.json";
const STORE_LOCK: &str = ".lock";
const VERSIONS_DIRECTORY: &str = "versions";
const BINARY_FILE: &str = "binary";
const RECEIPT_FILE: &str = "receipt.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug)]
pub struct VersionedBinaryStore {
    root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedBinaryVersion {
    pub version_id: String,
    pub binary_path: PathBuf,
    pub receipt_path: PathBuf,
}

#[derive(Debug)]
pub struct ManagedBinaryActivation {
    previous: Option<ActiveManifest>,
    current: ActiveManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveManifest {
    version: u16,
    version_id: String,
    activation_id: Uuid,
}

#[derive(Debug)]
struct StoreLock(File);

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ignored = self.0.unlock();
    }
}

impl VersionedBinaryStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare(
        &self,
        source_binary: &Path,
        receipt_bytes: &[u8],
    ) -> Result<ManagedBinaryVersion> {
        let _lock = self.lock()?;
        self.prepare_locked(source_binary, receipt_bytes)
    }

    pub fn activate(&self, version: &ManagedBinaryVersion) -> Result<ManagedBinaryActivation> {
        let _lock = self.lock()?;
        self.activate_locked(version)
    }

    pub fn activate_version(&self, version_id: &str) -> Result<ManagedBinaryActivation> {
        let _lock = self.lock()?;
        let version = self.version(version_id)?;
        self.activate_locked(&version)
    }

    pub fn rollback(&self, activation: ManagedBinaryActivation) -> Result<()> {
        let _lock = self.lock()?;
        let active = self.read_active_manifest_locked()?;
        if active.as_ref() != Some(&activation.current) {
            bail!("managed binary active version changed before rollback");
        }
        match activation.previous {
            Some(previous) => self.write_active_manifest_locked(&previous),
            None => self.remove_active_manifest_locked(),
        }
    }

    pub fn resolve_active(&self) -> Result<Option<ManagedBinaryVersion>> {
        let _lock = self.lock()?;
        let Some(manifest) = self.read_active_manifest_locked()? else {
            return Ok(None);
        };
        let version = self.version(&manifest.version_id)?;
        Self::verify_version_files(&version)?;
        Ok(Some(version))
    }

    pub fn list_versions(&self) -> Result<Vec<ManagedBinaryVersion>> {
        let _lock = self.lock()?;
        let versions_directory = self.root.join(VERSIONS_DIRECTORY);
        let mut versions = Vec::new();
        for entry in fs::read_dir(&versions_directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("managed binary version name is not UTF-8"))?;
            if name.starts_with(".staging-") {
                continue;
            }
            validate_version_id(&name)?;
            if file_type.is_symlink() || !file_type.is_dir() {
                bail!("managed binary versions directory contains an unsafe entry");
            }
            let version = self.version(&name)?;
            Self::verify_version_files(&version)?;
            versions.push(version);
        }
        versions.sort_by(|left, right| left.version_id.cmp(&right.version_id));
        Ok(versions)
    }

    fn lock(&self) -> Result<StoreLock> {
        self.ensure_layout()?;
        let path = self.root.join(STORE_LOCK);
        reject_symlink_if_present(&path, "managed binary store lock")?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(false).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .context("failed to open managed binary store lock")?;
        restrict_private_file(&path)?;
        file.lock_exclusive()
            .context("failed to lock managed binary store")?;
        Ok(StoreLock(file))
    }

    fn prepare_locked(
        &self,
        source_binary: &Path,
        receipt_bytes: &[u8],
    ) -> Result<ManagedBinaryVersion> {
        let source_metadata = fs::symlink_metadata(source_binary)
            .context("failed to inspect staged managed binary")?;
        if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
            bail!("staged managed binary must be a regular non-symlink file");
        }
        if receipt_bytes.is_empty() || receipt_bytes.len() as u64 > MAX_MANIFEST_BYTES {
            bail!("managed binary receipt is empty or too large");
        }
        let version_id = sha256_file(source_binary)?;
        let final_version = self.version(&version_id)?;
        let final_directory = final_version
            .binary_path
            .parent()
            .context("version path has no parent")?;
        match fs::symlink_metadata(final_directory) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!("managed binary version path is unsafe")
            }
            Ok(_) => {
                Self::verify_version(&final_version, receipt_bytes)?;
                return Ok(final_version);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }

        let versions = self.root.join(VERSIONS_DIRECTORY);
        let staging = versions.join(format!(".staging-{}", Uuid::new_v4()));
        ensure_private_directory(&staging)?;
        let staged_binary = staging.join(BINARY_FILE);
        let staged_receipt = staging.join(RECEIPT_FILE);
        let stage_result = (|| -> Result<()> {
            copy_new_private_file(source_binary, &staged_binary, true)?;
            write_new_private_file(&staged_receipt, receipt_bytes, false)?;
            if sha256_file(&staged_binary)? != version_id {
                bail!("managed binary changed while it was staged");
            }
            fs::rename(&staging, final_directory)
                .context("failed to activate immutable binary version directory")?;
            sync_directory(&versions)
        })();
        if let Err(error) = stage_result {
            let cleanup = remove_owned_directory(&staging);
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(error.context(format!(
                    "managed binary staging cleanup also failed: {cleanup_error:#}"
                ))),
            };
        }
        Self::verify_version(&final_version, receipt_bytes)?;
        Ok(final_version)
    }

    fn activate_locked(&self, version: &ManagedBinaryVersion) -> Result<ManagedBinaryActivation> {
        let expected = self.version(&version.version_id)?;
        if expected != *version {
            bail!("managed binary version does not belong to this store");
        }
        Self::verify_version_files(version)?;
        let previous = self.read_active_manifest_locked()?;
        let current = ActiveManifest {
            version: MANIFEST_VERSION,
            version_id: version.version_id.clone(),
            activation_id: Uuid::new_v4(),
        };
        self.write_active_manifest_locked(&current)?;
        Ok(ManagedBinaryActivation { previous, current })
    }

    fn version(&self, version_id: &str) -> Result<ManagedBinaryVersion> {
        validate_version_id(version_id)?;
        let directory = self.root.join(VERSIONS_DIRECTORY).join(version_id);
        Ok(ManagedBinaryVersion {
            version_id: version_id.to_owned(),
            binary_path: directory.join(BINARY_FILE),
            receipt_path: directory.join(RECEIPT_FILE),
        })
    }

    fn ensure_layout(&self) -> Result<()> {
        ensure_private_directory(&self.root)?;
        ensure_private_directory(&self.root.join(VERSIONS_DIRECTORY))
    }

    fn verify_version(version: &ManagedBinaryVersion, receipt_bytes: &[u8]) -> Result<()> {
        Self::verify_version_files(version)?;
        if fs::read(&version.receipt_path)? != receipt_bytes {
            bail!("existing managed binary version has a different receipt");
        }
        Ok(())
    }

    fn verify_version_files(version: &ManagedBinaryVersion) -> Result<()> {
        validate_version_id(&version.version_id)?;
        let directory = version
            .binary_path
            .parent()
            .context("managed version binary has no parent")?;
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("managed binary version directory is unsafe");
        }
        for path in [&version.binary_path, &version.receipt_path] {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("managed binary version contains an unsafe file");
            }
        }
        if sha256_file(&version.binary_path)? != version.version_id {
            bail!("managed binary version digest does not match its identity");
        }
        let receipt_length = fs::metadata(&version.receipt_path)?.len();
        if receipt_length == 0 || receipt_length > MAX_MANIFEST_BYTES {
            bail!("managed binary version receipt is empty or too large");
        }
        Ok(())
    }

    fn read_active_manifest_locked(&self) -> Result<Option<ActiveManifest>> {
        let path = self.root.join(ACTIVE_MANIFEST);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES
        {
            bail!("managed binary active manifest is unsafe");
        }
        let manifest: ActiveManifest = serde_json::from_slice(&fs::read(path)?)
            .context("managed binary active manifest is invalid")?;
        validate_manifest(&manifest)?;
        Ok(Some(manifest))
    }

    fn write_active_manifest_locked(&self, manifest: &ActiveManifest) -> Result<()> {
        validate_manifest(manifest)?;
        atomic_write_private(
            &self.root.join(ACTIVE_MANIFEST),
            &serde_json::to_vec_pretty(manifest)?,
        )
    }

    fn remove_active_manifest_locked(&self) -> Result<()> {
        let path = self.root.join(ACTIVE_MANIFEST);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("refusing to remove unsafe managed binary active manifest")
            }
            Ok(_) => {
                fs::remove_file(path)?;
                sync_directory(&self.root)
            }
        }
    }
}

fn validate_manifest(manifest: &ActiveManifest) -> Result<()> {
    if manifest.version != MANIFEST_VERSION {
        bail!("unsupported managed binary active-manifest version");
    }
    if manifest.activation_id.is_nil() {
        bail!("managed binary activation identity is invalid");
    }
    validate_version_id(&manifest.version_id)
}

fn validate_version_id(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("managed binary version identity is invalid");
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn reject_symlink_if_present(path: &Path, description: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("{description} must not be a symbolic link")
        }
        Ok(_) | Err(_) => Ok(()),
    }
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    reject_symlink_if_present(path, "managed binary directory")?;
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("managed binary path must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_private_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_private_file(_path: &Path) -> Result<()> {
    Ok(())
}

fn copy_new_private_file(source: &Path, destination: &Path, executable: bool) -> Result<()> {
    let mut input = File::open(source)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if executable { 0o700 } else { 0o600 });
    }
    let mut output = options.open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    Ok(())
}

fn write_new_private_file(path: &Path, bytes: &[u8], executable: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if executable { 0o700 } else { 0o600 });
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("active manifest has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("active manifest parent must be a real directory");
    }
    reject_symlink_if_present(path, "managed binary active manifest")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("failed to atomically replace managed binary active manifest")?;
    sync_directory(parent)
}

fn remove_owned_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("refusing to remove unsafe managed binary staging directory")
        }
        Ok(_) => {
            fs::remove_dir_all(path)?;
            if let Some(parent) = path.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    fn source(directory: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf> {
        let path = directory.join(name);
        fs::write(&path, bytes)?;
        Ok(path)
    }

    #[test]
    fn versions_are_immutable_listed_and_activation_rolls_back() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = VersionedBinaryStore::new(temporary.path().join("store"));
        let first_source = source(temporary.path(), "first", b"first binary")?;
        let second_source = source(temporary.path(), "second", b"second binary")?;
        let first = store.prepare(&first_source, b"first receipt")?;
        let second = store.prepare(&second_source, b"second receipt")?;
        assert_eq!(store.list_versions()?.len(), 2);
        let first_activation = store.activate(&first)?;
        assert_eq!(store.resolve_active()?, Some(first.clone()));
        let second_activation = store.activate_version(&second.version_id)?;
        assert_eq!(store.resolve_active()?, Some(second.clone()));
        store.rollback(second_activation)?;
        assert_eq!(store.resolve_active()?, Some(first.clone()));
        let reactivation = store.activate_version(&first.version_id)?;
        assert!(store.rollback(first_activation).is_err());
        assert_eq!(store.resolve_active()?, Some(first.clone()));
        store.rollback(reactivation)?;
        assert_eq!(store.resolve_active()?, Some(first.clone()));
        assert_eq!(fs::read(first.binary_path)?, b"first binary");
        assert_eq!(fs::read(second.binary_path)?, b"second binary");
        Ok(())
    }

    #[test]
    fn failed_activation_does_not_change_previous_active_version() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = VersionedBinaryStore::new(temporary.path().join("store"));
        let first_source = source(temporary.path(), "first", b"first")?;
        let first = store.prepare(&first_source, b"receipt")?;
        store.activate(&first)?;
        assert!(store.activate_version(&"0".repeat(64)).is_err());
        assert_eq!(store.resolve_active()?, Some(first));
        Ok(())
    }

    #[test]
    fn concurrent_preparation_reuses_one_immutable_version() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = source(temporary.path(), "binary", b"same binary")?;
        let root = temporary.path().join("store");
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let source = source.clone();
            let root = root.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(
                move || -> Result<ManagedBinaryVersion> {
                    barrier.wait();
                    VersionedBinaryStore::new(root).prepare(&source, b"same receipt")
                },
            ));
        }
        barrier.wait();
        let first = threads
            .remove(0)
            .join()
            .map_err(|_| anyhow::anyhow!("thread panicked"))??;
        let second = threads
            .remove(0)
            .join()
            .map_err(|_| anyhow::anyhow!("thread panicked"))??;
        assert_eq!(first, second);
        assert_eq!(VersionedBinaryStore::new(root).list_versions()?.len(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_manifest_version_and_lock_are_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let store = VersionedBinaryStore::new(temporary.path().join("store"));
        let source = source(temporary.path(), "binary", b"binary")?;
        let version = store.prepare(&source, b"receipt")?;
        store.activate(&version)?;
        let outside = temporary.path().join("outside");
        fs::write(&outside, b"outside")?;
        fs::remove_file(&version.binary_path)?;
        symlink(&outside, &version.binary_path)?;
        assert!(store.resolve_active().is_err());
        assert_eq!(fs::read(&outside)?, b"outside");

        fs::remove_file(store.root.join(STORE_LOCK))?;
        symlink(&outside, store.root.join(STORE_LOCK))?;
        assert!(store.list_versions().is_err());
        assert_eq!(fs::read(outside)?, b"outside");
        Ok(())
    }

    #[test]
    fn malformed_active_manifest_fails_closed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let store = VersionedBinaryStore::new(temporary.path().join("store"));
        let source = source(temporary.path(), "binary", b"binary")?;
        let version = store.prepare(&source, b"receipt")?;
        store.activate(&version)?;
        fs::write(store.root.join(ACTIVE_MANIFEST), b"{}")?;
        assert!(store.resolve_active().is_err());
        assert_eq!(fs::read(version.binary_path)?, b"binary");
        Ok(())
    }
}
