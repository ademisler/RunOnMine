use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

const KEY_BYTES: usize = 32;
const RECORD_DOMAIN: &[u8] = b"RunOnMine audit record MAC v1\0";
const TAIL_DOMAIN: &[u8] = b"RunOnMine audit tail MAC v1\0";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub(crate) struct AuditMacKey([u8; KEY_BYTES]);

impl std::fmt::Debug for AuditMacKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuditMacKey")
            .finish_non_exhaustive()
    }
}

impl AuditMacKey {
    pub(crate) fn generate() -> Result<Self> {
        let mut key = [0_u8; KEY_BYTES];
        getrandom::fill(&mut key).context("failed to generate an audit MAC key")?;
        Ok(Self(key))
    }

    pub(crate) fn load_or_create(database: &Path) -> Result<Self> {
        let path = key_path(database);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            restrict_directory(parent)?;
        }
        loop {
            match load_key(&path) {
                Ok(key) => return Ok(key),
                Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    io.kind() == std::io::ErrorKind::NotFound
                }) => {}
                Err(error) => return Err(error),
            }
            let key = Self::generate()?;
            match create_key(&path, &key.0) {
                Ok(()) => return Ok(key),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error).context("failed to create the audit MAC key"),
            }
        }
    }

    pub(crate) fn record_mac(
        &self,
        sequence: u64,
        previous_hash: &str,
        record_hash: &str,
        payload: &[u8],
    ) -> String {
        let mut mac = match HmacSha256::new_from_slice(&self.0) {
            Ok(mac) => mac,
            Err(_) => return String::new(),
        };
        mac.update(RECORD_DOMAIN);
        mac.update(&sequence.to_be_bytes());
        update_length_prefixed(&mut mac, previous_hash.as_bytes());
        update_length_prefixed(&mut mac, record_hash.as_bytes());
        update_length_prefixed(&mut mac, payload);
        hex::encode(mac.finalize().into_bytes())
    }

    pub(crate) fn tail_mac(
        &self,
        sequence: u64,
        record_hash: &str,
        record_mac: &str,
    ) -> String {
        let mut mac = match HmacSha256::new_from_slice(&self.0) {
            Ok(mac) => mac,
            Err(_) => return String::new(),
        };
        mac.update(TAIL_DOMAIN);
        mac.update(&sequence.to_be_bytes());
        update_length_prefixed(&mut mac, record_hash.as_bytes());
        update_length_prefixed(&mut mac, record_mac.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub(crate) fn verifies_record(
        &self,
        expected: &str,
        sequence: u64,
        previous_hash: &str,
        record_hash: &str,
        payload: &[u8],
    ) -> bool {
        constant_time_hex_eq(
            expected,
            &self.record_mac(sequence, previous_hash, record_hash, payload),
        )
    }

    pub(crate) fn verifies_tail(
        &self,
        expected: &str,
        sequence: u64,
        record_hash: &str,
        record_mac: &str,
    ) -> bool {
        constant_time_hex_eq(
            expected,
            &self.tail_mac(sequence, record_hash, record_mac),
        )
    }
}

fn update_length_prefixed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

fn constant_time_hex_eq(left: &str, right: &str) -> bool {
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn key_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_os_string();
    path.push(".audit-key");
    PathBuf::from(path)
}

fn load_key(path: &Path) -> Result<AuditMacKey> {
    let metadata = path.symlink_metadata()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != KEY_BYTES as u64 {
        bail!("audit MAC key is not a safe 256-bit regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("audit MAC key permissions are too broad");
        }
    }
    let mut file = fs::File::open(path)?;
    let mut key = [0_u8; KEY_BYTES];
    file.read_exact(&mut key)?;
    let mut extra = [0_u8; 1];
    if file.read(&mut extra)? != 0 {
        bail!("audit MAC key contains unexpected trailing bytes");
    }
    Ok(AuditMacKey(key))
}

fn create_key(path: &Path, key: &[u8; KEY_BYTES]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(key)?;
    file.sync_all()?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_tail_macs_bind_every_input() -> Result<()> {
        let key = AuditMacKey::generate()?;
        let payload = br#"{"id":"event"}"#;
        let record = key.record_mac(7, "previous", "record", payload);
        assert!(key.verifies_record(&record, 7, "previous", "record", payload));
        assert!(!key.verifies_record(&record, 8, "previous", "record", payload));
        assert!(!key.verifies_record(&record, 7, "changed", "record", payload));
        assert!(!key.verifies_record(&record, 7, "previous", "changed", payload));
        assert!(!key.verifies_record(&record, 7, "previous", "record", b"changed"));
        let tail = key.tail_mac(7, "record", &record);
        assert!(key.verifies_tail(&tail, 7, "record", &record));
        assert!(!key.verifies_tail(&tail, 6, "record", &record));
        Ok(())
    }

    #[test]
    fn key_file_is_private_and_symlinks_are_rejected() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        let first = AuditMacKey::load_or_create(&database)?;
        let second = AuditMacKey::load_or_create(&database)?;
        assert_eq!(first.0, second.0);
        let path = key_path(&database);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt as _, symlink};
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
            fs::remove_file(&path)?;
            symlink("missing", &path)?;
            assert!(AuditMacKey::load_or_create(&database).is_err());
        }
        Ok(())
    }
}
