//! Optional persistent pins and trust classification for external connector binaries.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{BinaryKind, InstalledBinary};

const DOCUMENT_VERSION: u16 = 1;
const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalBinaryTrust {
    ManagedVersioned,
    ExternalPinned,
    ExternalUnpinned,
}

#[derive(Clone, Debug)]
pub struct ExternalBinaryPinStore {
    path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalBinaryPin {
    pub kind: String,
    pub canonical_path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub modified_nanos: Option<u128>,
    pub unix_uid: Option<u32>,
    pub unix_gid: Option<u32>,
    pub unix_mode: Option<u32>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PinDocument {
    version: u16,
    pins: Vec<ExternalBinaryPin>,
}

impl ExternalBinaryPinStore {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn pin(&self, kind: BinaryKind, path: &Path) -> Result<ExternalBinaryPin> {
        let pin = inspect_pin(kind, path)?;
        let _lock = self.lock()?;
        let mut document = self.read_unlocked()?;
        document.pins.retain(|existing| {
            existing.kind != pin.kind || existing.canonical_path != pin.canonical_path
        });
        document.pins.push(pin.clone());
        document.pins.sort_by(|left, right| {
            left.kind
                .cmp(&right.kind)
                .then_with(|| left.canonical_path.cmp(&right.canonical_path))
        });
        self.write_unlocked(&document)?;
        Ok(pin)
    }

    pub fn remove(&self, kind: BinaryKind, path: &Path) -> Result<bool> {
        let canonical = canonical_external_path(path)?;
        let kind = kind_key(kind);
        let _lock = self.lock()?;
        let mut document = self.read_unlocked()?;
        let before = document.pins.len();
        document
            .pins
            .retain(|pin| pin.kind != kind || pin.canonical_path != canonical);
        if document.pins.len() == before {
            return Ok(false);
        }
        self.write_unlocked(&document)?;
        Ok(true)
    }

    pub fn verify(&self, kind: BinaryKind, path: &Path) -> Result<bool> {
        let current = inspect_pin(kind, path)?;
        let _lock = self.lock()?;
        let document = self.read_unlocked()?;
        let Some(expected) = document
            .pins
            .iter()
            .find(|pin| pin.kind == current.kind && pin.canonical_path == current.canonical_path)
        else {
            return Ok(false);
        };
        if expected != &current {
            bail!("external connector binary no longer matches its installed pin");
        }
        Ok(true)
    }

    pub fn trust(
        &self,
        managed_root: &Path,
        kind: BinaryKind,
        path: &Path,
    ) -> Result<ExternalBinaryTrust> {
        let canonical = canonical_external_path(path)?;
        let managed = managed_root
            .canonicalize()
            .ok()
            .is_some_and(|root| canonical.starts_with(root));
        if managed {
            return Ok(ExternalBinaryTrust::ManagedVersioned);
        }
        if self.verify(kind, &canonical)? {
            Ok(ExternalBinaryTrust::ExternalPinned)
        } else {
            Ok(ExternalBinaryTrust::ExternalUnpinned)
        }
    }

    fn lock(&self) -> Result<PinLock> {
        let parent = self.path.parent().context("pin file has no parent")?;
        ensure_private_directory(parent)?;
        let lock_path = self.path.with_extension("lock");
        reject_symlink_if_present(&lock_path, "external binary pin lock")?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        restrict_file(&lock_path)?;
        file.lock_exclusive()?;
        Ok(PinLock(file))
    }

    fn read_unlocked(&self) -> Result<PinDocument> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PinDocument {
                    version: DOCUMENT_VERSION,
                    pins: Vec::new(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_DOCUMENT_BYTES
        {
            bail!("external binary pin document is unsafe");
        }
        let document: PinDocument = serde_json::from_slice(&fs::read(&self.path)?)?;
        if document.version != DOCUMENT_VERSION {
            bail!("unsupported external binary pin document version");
        }
        for pin in &document.pins {
            validate_pin(pin)?;
        }
        Ok(document)
    }

    fn write_unlocked(&self, document: &PinDocument) -> Result<()> {
        for pin in &document.pins {
            validate_pin(pin)?;
        }
        let bytes = serde_json::to_vec_pretty(document)?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            bail!("external binary pin document exceeds the size limit");
        }
        atomic_write_private(&self.path, &bytes)?;
        restrict_file(&self.path)
    }
}

#[derive(Debug)]
struct PinLock(File);

impl Drop for PinLock {
    fn drop(&mut self) {
        let _ignored = self.0.unlock();
    }
}

pub fn verify_external_binary(
    store: &ExternalBinaryPinStore,
    kind: BinaryKind,
    path: &Path,
) -> Result<(InstalledBinary, ExternalBinaryTrust)> {
    let binary = InstalledBinary::from_verified_path(kind, path)?;
    let trust = if store.verify(kind, &binary.path)? {
        ExternalBinaryTrust::ExternalPinned
    } else {
        ExternalBinaryTrust::ExternalUnpinned
    };
    Ok((binary, trust))
}

fn inspect_pin(kind: BinaryKind, path: &Path) -> Result<ExternalBinaryPin> {
    let canonical_path = canonical_external_path(path)?;
    let metadata = fs::symlink_metadata(&canonical_path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("external connector binary must be a regular non-symlink file");
    }
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos());
    #[cfg(unix)]
    let (owner_user_id, owner_group_id, permissions_mode) = {
        use std::os::unix::fs::MetadataExt as _;
        (
            Some(metadata.uid()),
            Some(metadata.gid()),
            Some(metadata.mode()),
        )
    };
    #[cfg(not(unix))]
    let (owner_user_id, owner_group_id, permissions_mode) = (None, None, None);
    let pin = ExternalBinaryPin {
        kind: kind_key(kind),
        canonical_path,
        sha256: sha256_file(path)?,
        size: metadata.len(),
        modified_nanos,
        unix_uid: owner_user_id,
        unix_gid: owner_group_id,
        unix_mode: permissions_mode,
    };
    validate_pin(&pin)?;
    Ok(pin)
}

fn canonical_external_path(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("external connector binary must be a regular non-symlink file");
    }
    path.canonicalize()
        .context("failed to canonicalize external connector binary")
}

fn validate_pin(pin: &ExternalBinaryPin) -> Result<()> {
    if pin.kind.is_empty()
        || !pin.canonical_path.is_absolute()
        || pin.sha256.len() != 64
        || !pin.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("external connector binary pin is invalid");
    }
    Ok(())
}

fn kind_key(kind: BinaryKind) -> String {
    kind.executable_name().to_owned()
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

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;

    let parent = path.parent().context("pin document has no parent")?;
    ensure_private_directory(parent)?;
    reject_symlink_if_present(path, "external binary pin document")?;
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
        .context("failed to atomically replace external binary pin document")?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    reject_symlink_if_present(path, "external binary pin directory")?;
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn reject_symlink_if_present(path: &Path, description: &str) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing a symlinked {description}");
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_detects_content_and_metadata_changes() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let binary = temporary.path().join("external");
        fs::write(&binary, b"first")?;
        let store = ExternalBinaryPinStore::new(temporary.path().join("pins.json"));
        assert!(!store.verify(BinaryKind::Cloudflared, &binary)?);
        store.pin(BinaryKind::Cloudflared, &binary)?;
        assert!(store.verify(BinaryKind::Cloudflared, &binary)?);
        fs::write(&binary, b"second")?;
        assert!(store.verify(BinaryKind::Cloudflared, &binary).is_err());
        Ok(())
    }

    #[test]
    fn pins_are_kind_specific_and_removable() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let binary = temporary.path().join("external");
        fs::write(&binary, b"binary")?;
        let store = ExternalBinaryPinStore::new(temporary.path().join("pins.json"));
        store.pin(BinaryKind::Cloudflared, &binary)?;
        assert!(store.verify(BinaryKind::Cloudflared, &binary)?);
        assert!(!store.verify(BinaryKind::OpenAiTunnelClient, &binary)?);
        assert!(store.remove(BinaryKind::Cloudflared, &binary)?);
        assert!(!store.verify(BinaryKind::Cloudflared, &binary)?);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_external_binary_is_rejected() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir()?;
        let target = temporary.path().join("target");
        let link = temporary.path().join("link");
        fs::write(&target, b"binary")?;
        symlink(&target, &link)?;
        let store = ExternalBinaryPinStore::new(temporary.path().join("pins.json"));
        assert!(store.pin(BinaryKind::Cloudflared, &link).is_err());
        assert_eq!(fs::read(target)?, b"binary");
        Ok(())
    }
}
