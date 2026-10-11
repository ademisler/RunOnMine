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
        let mismatched = pin_mismatch_fields(expected, &current);
        if !mismatched.is_empty() {
            bail!(
                "external connector binary no longer matches its installed pin (mismatched fields: {})",
                mismatched.join(", ")
            );
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

fn pin_mismatch_fields(
    expected: &ExternalBinaryPin,
    current: &ExternalBinaryPin,
) -> Vec<&'static str> {
    let mut fields = Vec::new();
    if expected.kind != current.kind {
        fields.push("kind");
    }
    if expected.canonical_path != current.canonical_path {
        fields.push("canonical_path");
    }
    if expected.sha256 != current.sha256 {
        fields.push("sha256");
    }
    if expected.size != current.size {
        fields.push("size");
    }
    if expected.modified_nanos != current.modified_nanos {
        fields.push("modified_nanos");
    }
    if !unix_identity_matches(expected.unix_uid, current.unix_uid, LinuxIdentityKind::User) {
        fields.push("unix_uid");
    }
    if !unix_identity_matches(
        expected.unix_gid,
        current.unix_gid,
        LinuxIdentityKind::Group,
    ) {
        fields.push("unix_gid");
    }
    if expected.unix_mode != current.unix_mode {
        fields.push("unix_mode");
    }
    fields
}

#[derive(Clone, Copy, Debug)]
enum LinuxIdentityKind {
    User,
    Group,
}

fn unix_identity_matches(
    expected: Option<u32>,
    current: Option<u32>,
    kind: LinuxIdentityKind,
) -> bool {
    if expected == current {
        return true;
    }
    #[cfg(target_os = "linux")]
    {
        let (Some(expected), Some(current)) = (expected, current) else {
            return false;
        };
        let (map_path, overflow_path) = match kind {
            LinuxIdentityKind::User => ("/proc/self/uid_map", "/proc/sys/kernel/overflowuid"),
            LinuxIdentityKind::Group => ("/proc/self/gid_map", "/proc/sys/kernel/overflowgid"),
        };
        let Ok(map) = fs::read_to_string(map_path) else {
            return false;
        };
        let Ok(overflow) = fs::read_to_string(overflow_path) else {
            return false;
        };
        let Ok(overflow) = overflow.trim().parse::<u32>() else {
            return false;
        };
        identity_matches_with_map(expected, current, &map, overflow)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = kind;
        false
    }
}

#[cfg(target_os = "linux")]
fn identity_matches_with_map(expected: u32, current: u32, map: &str, overflow: u32) -> bool {
    match map_parent_identity(map, expected) {
        Ok(Some(mapped)) => current == mapped,
        Ok(None) => current == overflow,
        Err(()) => false,
    }
}

#[cfg(target_os = "linux")]
fn map_parent_identity(map: &str, parent: u32) -> std::result::Result<Option<u32>, ()> {
    let parent = u64::from(parent);
    for line in map.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_ascii_whitespace();
        let inside = fields.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
        let outside = fields.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
        let length = fields.next().ok_or(())?.parse::<u64>().map_err(|_| ())?;
        if fields.next().is_some() || length == 0 {
            return Err(());
        }
        let end = outside.checked_add(length).ok_or(())?;
        if parent >= outside && parent < end {
            let mapped = inside.checked_add(parent - outside).ok_or(())?;
            return u32::try_from(mapped).map(Some).map_err(|_| ());
        }
    }
    Ok(None)
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
#[expect(
    clippy::unnecessary_wraps,
    reason = "Unix mode hardening is a no-op on Windows while binary pinning keeps one fallible interface"
)]
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

    #[cfg(target_os = "linux")]
    #[test]
    fn namespace_identity_mapping_accepts_only_kernel_mapped_or_overflow_identity() {
        let restricted = "1001 1001 1\n";
        assert!(identity_matches_with_map(1001, 1001, restricted, 65_534));
        assert!(identity_matches_with_map(0, 65_534, restricted, 65_534));
        assert!(!identity_matches_with_map(0, 1001, restricted, 65_534));
        assert!(identity_matches_with_map(0, 0, "0 0 1\n", 65_534));
        assert!(identity_matches_with_map(1000, 0, "0 1000 1\n", 65_534));
        assert!(!identity_matches_with_map(0, 65_534, "invalid\n", 65_534));
        assert!(!identity_matches_with_map(0, 65_534, "0 0 0\n", 65_534));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn pin_comparison_still_rejects_content_and_mode_changes() {
        let expected = ExternalBinaryPin {
            kind: "cloudflared".to_owned(),
            canonical_path: PathBuf::from("/usr/local/bin/cloudflared"),
            sha256: "a".repeat(64),
            size: 10,
            modified_nanos: Some(20),
            unix_uid: Some(0),
            unix_gid: Some(0),
            unix_mode: Some(0o100_755),
        };
        let mut current = expected.clone();
        current.sha256 = "b".repeat(64);
        current.unix_mode = Some(0o100_775);
        let mismatched = pin_mismatch_fields(&expected, &current);
        assert!(mismatched.contains(&"sha256"));
        assert!(mismatched.contains(&"unix_mode"));
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
