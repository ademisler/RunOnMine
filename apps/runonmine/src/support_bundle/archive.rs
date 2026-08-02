use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use zip::write::SimpleFileOptions;

use super::BUNDLE_SCHEMA_VERSION;

#[derive(Debug, Serialize)]
struct BundleManifest {
    schema_version: u32,
    generated_at: DateTime<Utc>,
    entries: Vec<ManifestEntry>,
    inputs: Vec<ManifestInput>,
    privacy_note: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct ManifestInput {
    pub(super) name: String,
    pub(super) status: &'static str,
    pub(super) included_entries: usize,
    pub(super) skipped_entries: usize,
    pub(super) truncated_entries: usize,
    pub(super) note: &'static str,
}

#[derive(Debug, Serialize)]
struct ManifestEntry {
    path: String,
    size_bytes: usize,
    sha256: String,
}

#[derive(Debug)]
pub(super) struct BundleEntry {
    pub(super) path: String,
    pub(super) bytes: Vec<u8>,
}
fn reject_unsafe_output(output: &Path) -> Result<()> {
    if output.extension().and_then(|value| value.to_str()) != Some("zip") {
        bail!("support bundle output must use the .zip extension");
    }
    if output.exists() {
        bail!(
            "refusing to overwrite existing support bundle: {}",
            output.display()
        );
    }
    if output
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to replace symlinked support bundle output");
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    if parent
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to write a support bundle through a symlinked directory");
    }
    Ok(())
}

pub(super) fn write_zip_atomically(
    output: &Path,
    generated_at: DateTime<Utc>,
    entries: &[BundleEntry],
    inputs: &[ManifestInput],
) -> Result<()> {
    reject_unsafe_output(output)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)?;
    restrict_private_file(temporary.as_file())?;
    let options = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o600);
    let mut manifest_entries = Vec::with_capacity(entries.len());
    {
        let mut archive = zip::ZipWriter::new(temporary.as_file_mut());
        for entry in entries {
            archive.start_file(&entry.path, options)?;
            archive.write_all(&entry.bytes)?;
            manifest_entries.push(ManifestEntry {
                path: entry.path.clone(),
                size_bytes: entry.bytes.len(),
                sha256: sha256_hex(&entry.bytes),
            });
        }
        let manifest = BundleManifest {
            schema_version: BUNDLE_SCHEMA_VERSION,
            generated_at,
            entries: manifest_entries,
            inputs: inputs.to_vec(),
            privacy_note: "Generated entries only; raw config, state, credentials, and audit arguments are excluded.",
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        archive.start_file("manifest.json", options)?;
        archive.write_all(&manifest_bytes)?;
        archive.finish()?.sync_all()?;
    }
    temporary
        .persist_noclobber(output)
        .map_err(|error| error.error)
        .context("failed to atomically persist support bundle")?;
    restrict_private_path(output)?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(unix)]
fn restrict_private_file(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Unix mode hardening is a no-op on Windows while support bundle creation keeps one fallible interface"
)]
fn restrict_private_file(_file: &File) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn restrict_private_path(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Unix mode hardening is a no-op on Windows while support bundle persistence keeps one fallible interface"
)]
fn restrict_private_path(_path: &Path) -> Result<()> {
    Ok(())
}
