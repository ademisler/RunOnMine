//! Unified managed-receipt and external-pin verification for connector binaries.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::provenance::verify_install_provenance;
use crate::{
    BinaryKind, ExternalBinaryPinStore, ExternalBinaryTrust, InstallReceipt, InstalledBinary,
    ReleaseProvider, VersionedBinaryStore,
};

const MAX_RECEIPT_BYTES: u64 = 64 * 1024;
const PIN_DOCUMENT: &str = "external-binary-pins.json";

#[derive(Clone, Debug)]
pub struct ResolvedConnectorBinary {
    pub binary: InstalledBinary,
    pub trust: ExternalBinaryTrust,
}

pub fn external_binary_pin_store(state_dir: &Path) -> ExternalBinaryPinStore {
    ExternalBinaryPinStore::new(state_dir.join(PIN_DOCUMENT))
}

pub fn managed_binary_store(data_dir: &Path, kind: BinaryKind) -> VersionedBinaryStore {
    VersionedBinaryStore::new(
        data_dir
            .join("managed-binaries")
            .join(kind.executable_name()),
    )
}

pub fn resolve_connector_binary(
    data_dir: &Path,
    state_dir: &Path,
    kind: BinaryKind,
    provider: ReleaseProvider,
    configured_path: Option<&Path>,
) -> Result<Option<ResolvedConnectorBinary>> {
    let legacy_directory = data_dir.join("bin");
    let candidate = configured_path.map_or_else(
        || legacy_directory.join(kind.executable_name()),
        Path::to_path_buf,
    );
    let metadata = match fs::symlink_metadata(&candidate) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("connector binary must be a regular non-symlink file");
    }
    let binary = InstalledBinary::from_verified_path(kind, &candidate)?;

    let store = managed_binary_store(data_dir, kind);
    if is_below_existing_root(&binary.path, store.root())? {
        let version = store.version_for_binary_path(&binary.path)?;
        verify_receipt(&binary, provider, &version.receipt_path)?;
        return Ok(Some(ResolvedConnectorBinary {
            binary,
            trust: ExternalBinaryTrust::ManagedVersioned,
        }));
    }

    if is_legacy_managed_binary(&binary.path, &legacy_directory, kind)? {
        verify_receipt(
            &binary,
            provider,
            &legacy_directory.join(format!("{}.receipt.json", kind.executable_name())),
        )?;
        return Ok(Some(ResolvedConnectorBinary {
            binary,
            trust: ExternalBinaryTrust::ManagedVersioned,
        }));
    }

    let pins = external_binary_pin_store(state_dir);
    let trust = if pins.verify(kind, &binary.path)? {
        ExternalBinaryTrust::ExternalPinned
    } else {
        ExternalBinaryTrust::ExternalUnpinned
    };
    Ok(Some(ResolvedConnectorBinary { binary, trust }))
}

pub fn is_managed_connector_binary(data_dir: &Path, kind: BinaryKind, path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("connector binary must be a regular non-symlink file");
    }
    let canonical = path.canonicalize()?;
    let store = managed_binary_store(data_dir, kind);
    if is_below_existing_root(&canonical, store.root())? {
        store.version_for_binary_path(&canonical)?;
        return Ok(true);
    }
    is_legacy_managed_binary(&canonical, &data_dir.join("bin"), kind)
}

fn verify_receipt(
    binary: &InstalledBinary,
    provider: ReleaseProvider,
    receipt_path: &Path,
) -> Result<()> {
    let metadata = fs::symlink_metadata(receipt_path).with_context(|| {
        format!(
            "managed binary receipt is missing: {}",
            receipt_path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_RECEIPT_BYTES
    {
        bail!("managed binary receipt is not a small regular file");
    }
    let receipt: InstallReceipt = serde_json::from_slice(&fs::read(receipt_path)?)
        .context("managed binary receipt is invalid")?;
    if receipt.provider != provider {
        bail!("managed binary receipt provider does not match");
    }
    if let Some(provenance) = &receipt.provenance {
        verify_install_provenance(provenance, provider, &receipt.release_tag, &receipt.sha256)?;
    }
    let expected_path = receipt
        .installed_path
        .canonicalize()
        .context("managed binary receipt path does not exist")?;
    if expected_path != binary.path {
        bail!("managed binary path does not match its receipt");
    }
    if !receipt.sha256.verify_file(&binary.path)? {
        bail!("managed binary SHA-256 does not match its installation receipt");
    }
    Ok(())
}

fn is_below_existing_root(path: &Path, root: &Path) -> Result<bool> {
    match root.canonicalize() {
        Ok(root) => Ok(path.starts_with(root)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn is_legacy_managed_binary(
    path: &Path,
    legacy_directory: &Path,
    kind: BinaryKind,
) -> Result<bool> {
    let directory = match legacy_directory.canonicalize() {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    Ok(path.parent() == Some(directory.as_path())
        && path.file_name() == Some(std::ffi::OsStr::new(kind.executable_name())))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use sha2::{Digest as _, Sha256};

    use super::*;
    use crate::{ManagedBinaryVersion, Sha256Digest};

    fn executable(path: &Path, bytes: &[u8]) -> Result<()> {
        fs::write(path, bytes)?;
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn receipt(path: &Path, provider: ReleaseProvider, binary: &Path, bytes: &[u8]) -> Result<()> {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        fs::write(
            path,
            serde_json::to_vec(&InstallReceipt {
                provider,
                release_tag: "v-test".to_owned(),
                sha256: Sha256Digest::parse(&digest)?,
                installed_path: binary.to_path_buf(),
                provenance: None,
            })?,
        )?;
        Ok(())
    }

    #[test]
    fn versioned_managed_binary_requires_matching_receipt() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let data = temporary.path().join("data");
        let state = temporary.path().join("state");
        fs::create_dir_all(&state)?;
        let store = managed_binary_store(&data, BinaryKind::Cloudflared);
        let source = temporary.path().join("source");
        executable(&source, b"managed")?;
        let version_id = store.version_id_for_file(&source)?;
        let target: ManagedBinaryVersion = store.version(&version_id)?;
        let receipt_bytes = {
            let digest = format!("sha256:{}", hex::encode(Sha256::digest(b"managed")));
            serde_json::to_vec(&InstallReceipt {
                provider: ReleaseProvider::Cloudflared,
                release_tag: "v-test".to_owned(),
                sha256: Sha256Digest::parse(&digest)?,
                installed_path: target.binary_path.clone(),
                provenance: None,
            })?
        };
        let version = store.prepare(&source, &receipt_bytes)?;
        let resolved = resolve_connector_binary(
            &data,
            &state,
            BinaryKind::Cloudflared,
            ReleaseProvider::Cloudflared,
            Some(&version.binary_path),
        )?
        .context("managed binary was not resolved")?;
        assert_eq!(resolved.trust, ExternalBinaryTrust::ManagedVersioned);
        fs::write(&version.binary_path, b"tampered")?;
        assert!(
            resolve_connector_binary(
                &data,
                &state,
                BinaryKind::Cloudflared,
                ReleaseProvider::Cloudflared,
                Some(&version.binary_path),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn external_binary_moves_from_unpinned_to_pinned_and_detects_change() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let data = temporary.path().join("data");
        let state = temporary.path().join("state");
        fs::create_dir_all(&state)?;
        let binary = temporary.path().join("external");
        executable(&binary, b"external")?;
        let unpinned = resolve_connector_binary(
            &data,
            &state,
            BinaryKind::Cloudflared,
            ReleaseProvider::Cloudflared,
            Some(&binary),
        )?
        .context("external binary was not resolved")?;
        assert_eq!(unpinned.trust, ExternalBinaryTrust::ExternalUnpinned);
        external_binary_pin_store(&state).pin(BinaryKind::Cloudflared, &binary)?;
        let pinned = resolve_connector_binary(
            &data,
            &state,
            BinaryKind::Cloudflared,
            ReleaseProvider::Cloudflared,
            Some(&binary),
        )?
        .context("pinned binary was not resolved")?;
        assert_eq!(pinned.trust, ExternalBinaryTrust::ExternalPinned);
        executable(&binary, b"changed")?;
        assert!(
            resolve_connector_binary(
                &data,
                &state,
                BinaryKind::Cloudflared,
                ReleaseProvider::Cloudflared,
                Some(&binary),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn legacy_managed_binary_requires_legacy_receipt() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let data = temporary.path().join("data");
        let state = temporary.path().join("state");
        let legacy = data.join("bin");
        fs::create_dir_all(&legacy)?;
        fs::create_dir_all(&state)?;
        let binary = legacy.join(BinaryKind::Cloudflared.executable_name());
        executable(&binary, b"legacy")?;
        receipt(
            &legacy.join(format!(
                "{}.receipt.json",
                BinaryKind::Cloudflared.executable_name()
            )),
            ReleaseProvider::Cloudflared,
            &binary,
            b"legacy",
        )?;
        let resolved = resolve_connector_binary(
            &data,
            &state,
            BinaryKind::Cloudflared,
            ReleaseProvider::Cloudflared,
            Some(&binary),
        )?
        .context("legacy binary was not resolved")?;
        assert_eq!(resolved.trust, ExternalBinaryTrust::ManagedVersioned);
        Ok(())
    }
}
