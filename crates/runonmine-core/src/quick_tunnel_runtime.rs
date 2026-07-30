//! Ephemeral, generation-bound Cloudflare Quick Tunnel runtime discovery state.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;

use crate::{AppPaths, atomic};

const STATE_VERSION: u16 = 1;
const STATE_DIRECTORY: &str = "quick-tunnel-runtime";
const STATE_LOCK: &str = ".lock";
const MAX_STATE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuickTunnelGeneration {
    connector_id: String,
    generation: Uuid,
}

impl QuickTunnelGeneration {
    pub fn connector_id(&self) -> &str {
        &self.connector_id
    }

    pub fn generation(&self) -> Uuid {
        self.generation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickTunnelRuntimeRecord {
    pub version: u16,
    pub connector_id: String,
    pub generation: Uuid,
    pub public_url: Option<Url>,
    pub started_at: DateTime<Utc>,
    pub observed_at: Option<DateTime<Utc>>,
}

impl QuickTunnelRuntimeRecord {
    fn validate(&self) -> Result<()> {
        if self.version != STATE_VERSION {
            bail!("unsupported Quick Tunnel runtime-state version");
        }
        crate::validate_connector_id(&self.connector_id)?;
        if let Some(url) = &self.public_url {
            validate_quick_tunnel_url(url)?;
            if self.observed_at.is_none() {
                bail!("Quick Tunnel runtime URL has no observation timestamp");
            }
        } else if self.observed_at.is_some() {
            bail!("Quick Tunnel observation timestamp has no URL");
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct QuickTunnelRuntimeStore {
    directory: PathBuf,
}

impl QuickTunnelRuntimeStore {
    pub fn new(paths: &AppPaths) -> Self {
        Self {
            directory: paths.state_dir.join(STATE_DIRECTORY),
        }
    }

    pub fn begin(&self, connector_id: &str) -> Result<QuickTunnelGeneration> {
        crate::validate_connector_id(connector_id)?;
        let _lock = self.lock()?;
        let generation = QuickTunnelGeneration {
            connector_id: connector_id.to_owned(),
            generation: Uuid::new_v4(),
        };
        self.write(&QuickTunnelRuntimeRecord {
            version: STATE_VERSION,
            connector_id: connector_id.to_owned(),
            generation: generation.generation,
            public_url: None,
            started_at: Utc::now(),
            observed_at: None,
        })?;
        Ok(generation)
    }

    pub fn set_url(&self, generation: &QuickTunnelGeneration, url: &Url) -> Result<bool> {
        validate_quick_tunnel_url(url)?;
        let _lock = self.lock()?;
        let Some(mut record) = self.read(&generation.connector_id)? else {
            return Ok(false);
        };
        if record.generation != generation.generation {
            return Ok(false);
        }
        record.public_url = Some(url.to_owned());
        record.observed_at = Some(Utc::now());
        self.write(&record)?;
        Ok(true)
    }

    pub fn clear_url(&self, generation: &QuickTunnelGeneration) -> Result<bool> {
        let _lock = self.lock()?;
        let Some(mut record) = self.read(&generation.connector_id)? else {
            return Ok(false);
        };
        if record.generation != generation.generation {
            return Ok(false);
        }
        record.public_url = None;
        record.observed_at = None;
        self.write(&record)?;
        Ok(true)
    }

    pub fn finish(&self, generation: &QuickTunnelGeneration) -> Result<bool> {
        let _lock = self.lock()?;
        let Some(record) = self.read(&generation.connector_id)? else {
            return Ok(false);
        };
        if record.generation != generation.generation {
            return Ok(false);
        }
        self.remove(&generation.connector_id)?;
        Ok(true)
    }

    pub fn clear_connector(&self, connector_id: &str) -> Result<bool> {
        crate::validate_connector_id(connector_id)?;
        let _lock = self.lock()?;
        let path = self.record_path(connector_id);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("refusing to remove unsafe Quick Tunnel runtime state")
            }
            Ok(_) => {
                fs::remove_file(&path)?;
                sync_directory(&self.directory)?;
                Ok(true)
            }
        }
    }

    pub fn get(&self, connector_id: &str) -> Result<Option<QuickTunnelRuntimeRecord>> {
        crate::validate_connector_id(connector_id)?;
        let _lock = self.lock()?;
        self.read(connector_id)
    }

    fn lock(&self) -> Result<RuntimeLock> {
        ensure_private_directory(&self.directory)?;
        let path = self.directory.join(STATE_LOCK);
        reject_symlink_if_present(&path, "Quick Tunnel runtime lock")?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .context("failed to open Quick Tunnel runtime lock")?;
        restrict_file(&path)?;
        file.lock_exclusive()
            .context("failed to lock Quick Tunnel runtime state")?;
        Ok(RuntimeLock(file))
    }

    fn read(&self, connector_id: &str) -> Result<Option<QuickTunnelRuntimeRecord>> {
        let path = self.record_path(connector_id);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() > MAX_STATE_BYTES
        {
            bail!("Quick Tunnel runtime state is not a safe bounded regular file");
        }
        let bytes = fs::read(&path)?;
        let record: QuickTunnelRuntimeRecord =
            serde_json::from_slice(&bytes).context("Quick Tunnel runtime state is invalid")?;
        record.validate()?;
        if record.connector_id != connector_id {
            bail!("Quick Tunnel runtime-state identity does not match its path");
        }
        Ok(Some(record))
    }

    fn write(&self, record: &QuickTunnelRuntimeRecord) -> Result<()> {
        record.validate()?;
        let bytes = serde_json::to_vec_pretty(record)?;
        if bytes.len() as u64 > MAX_STATE_BYTES {
            bail!("Quick Tunnel runtime state exceeds the size limit");
        }
        let path = self.record_path(&record.connector_id);
        atomic::write(&path, &bytes, 0o600)?;
        restrict_file(&path)
    }

    fn remove(&self, connector_id: &str) -> Result<()> {
        let path = self.record_path(connector_id);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                bail!("refusing to remove unsafe Quick Tunnel runtime state")
            }
            Ok(_) => {
                fs::remove_file(&path)?;
                sync_directory(&self.directory)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn record_path(&self, connector_id: &str) -> PathBuf {
        let digest = Sha256::digest(connector_id.as_bytes());
        self.directory.join(format!("{}.json", hex::encode(digest)))
    }
}

#[derive(Debug)]
struct RuntimeLock(File);

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        let _ignored = self.0.unlock();
    }
}

pub fn validate_quick_tunnel_url(url: &Url) -> Result<()> {
    let host = url.host_str().context("Quick Tunnel URL has no host")?;
    let Some(label) = host.strip_suffix(".trycloudflare.com") else {
        bail!("Quick Tunnel runtime URL must use a trycloudflare.com host");
    };
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || label.is_empty()
        || label.contains('.')
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        bail!("Quick Tunnel runtime URL must be an HTTPS trycloudflare.com origin root");
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    reject_symlink_if_present(path, "Quick Tunnel runtime directory")?;
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Quick Tunnel runtime path must be a real directory");
    }
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
        bail!("refusing to use a symlinked {description}");
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
    use super::*;

    #[test]
    fn generations_prevent_stale_writes_and_clears() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let store = QuickTunnelRuntimeStore::new(&paths);
        let old = store.begin("quick-id")?;
        let new = store.begin("quick-id")?;
        let url = Url::parse("https://example.trycloudflare.com/")?;
        assert!(!store.set_url(&old, &url)?);
        assert!(store.set_url(&new, &url)?);
        assert!(!store.clear_url(&old)?);
        assert_eq!(
            store.get("quick-id")?.and_then(|item| item.public_url),
            Some(url)
        );
        assert!(!store.finish(&old)?);
        assert!(store.finish(&new)?);
        assert!(store.get("quick-id")?.is_none());
        Ok(())
    }

    #[test]
    fn clear_url_retains_generation_for_supervisor_restart() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let store = QuickTunnelRuntimeStore::new(&paths);
        let generation = store.begin("quick-restart")?;
        let first = Url::parse("https://first.trycloudflare.com/")?;
        let second = Url::parse("https://second.trycloudflare.com/")?;
        assert!(store.set_url(&generation, &first)?);
        assert!(store.clear_url(&generation)?);
        let cleared = store
            .get("quick-restart")?
            .context("runtime state missing")?;
        assert!(cleared.public_url.is_none());
        assert!(store.set_url(&generation, &second)?);
        assert_eq!(
            store.get("quick-restart")?.and_then(|item| item.public_url),
            Some(second)
        );
        Ok(())
    }

    #[test]
    fn url_validation_rejects_credentials_paths_and_non_quick_hosts() -> Result<()> {
        for value in [
            "http://example.trycloudflare.com/",
            "https://example.trycloudflare.com/path",
            "https://user@example.trycloudflare.com/",
            "https://trycloudflare.com/",
            "https://example.com/",
        ] {
            assert!(validate_quick_tunnel_url(&Url::parse(value)?).is_err());
        }
        assert!(
            validate_quick_tunnel_url(&Url::parse("https://valid.trycloudflare.com/")?).is_ok()
        );
        Ok(())
    }

    #[test]
    fn stale_cleanup_removes_malformed_runtime_state_without_parsing_it() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let store = QuickTunnelRuntimeStore::new(&paths);
        let generation = store.begin("malformed-quick")?;
        let record_path = store.record_path(generation.connector_id());
        fs::write(&record_path, b"")?;
        assert!(store.get("malformed-quick").is_err());
        assert!(store.clear_connector("malformed-quick")?);
        assert!(!record_path.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn state_is_private_and_symlink_records_are_rejected() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir()?;
        let paths = AppPaths::under(directory.path());
        paths.ensure()?;
        let store = QuickTunnelRuntimeStore::new(&paths);
        let generation = store.begin("private-quick")?;
        let record_path = store.record_path(generation.connector_id());
        assert_eq!(
            store.directory.metadata()?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(record_path.metadata()?.permissions().mode() & 0o777, 0o600);
        fs::remove_file(&record_path)?;
        let outside = directory.path().join("outside");
        fs::write(&outside, b"outside")?;
        symlink(&outside, &record_path)?;
        assert!(store.get("private-quick").is_err());
        assert_eq!(fs::read(outside)?, b"outside");
        Ok(())
    }
}
