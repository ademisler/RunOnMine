use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use uuid::Uuid;

use crate::{AppPaths, QuickTunnelRuntimeStore, validate_connector_id};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorArtifactKind {
    DataDirectory,
    StateDirectory,
    QuickRuntime,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrphanConnectorArtifact {
    pub connector_id: String,
    pub kind: ConnectorArtifactKind,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ConnectorArtifactInventory {
    pub orphans: Vec<OrphanConnectorArtifact>,
    pub unsafe_entries: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ConnectorArtifactReconciliation {
    pub quarantined_directories: usize,
    pub removed_runtime_records: usize,
    pub unsafe_entries: usize,
}

#[derive(Clone, Debug)]
struct ArtifactPath {
    connector_id: String,
    kind: ConnectorArtifactKind,
    path: PathBuf,
    quarantine_root: PathBuf,
}

pub fn inventory_connector_artifacts(
    paths: &AppPaths,
    configured_ids: &BTreeSet<String>,
) -> Result<ConnectorArtifactInventory> {
    let (inventory, _) = scan_connector_artifacts(paths, configured_ids)?;
    Ok(inventory)
}

pub fn reconcile_connector_artifacts(
    paths: &AppPaths,
    configured_ids: &BTreeSet<String>,
) -> Result<ConnectorArtifactReconciliation> {
    let (inventory, paths_to_quarantine) = scan_connector_artifacts(paths, configured_ids)?;
    let run_id = Uuid::new_v4().to_string();
    let mut report = ConnectorArtifactReconciliation {
        unsafe_entries: inventory.unsafe_entries,
        ..ConnectorArtifactReconciliation::default()
    };
    for artifact in paths_to_quarantine {
        let destination_root = artifact.quarantine_root.join(&run_id);
        ensure_private_directory(&destination_root)?;
        let destination = destination_root.join(&artifact.connector_id);
        if destination.exists() {
            bail!("connector quarantine destination already exists");
        }
        fs::rename(&artifact.path, &destination).with_context(|| {
            format!(
                "failed to quarantine {:?} connector artifact",
                artifact.kind
            )
        })?;
        sync_directory(
            artifact
                .path
                .parent()
                .context("connector artifact path has no parent")?,
        )?;
        sync_directory(&destination_root)?;
        report.quarantined_directories = report.quarantined_directories.saturating_add(1);
    }
    let runtime = QuickTunnelRuntimeStore::new(paths);
    for orphan in inventory
        .orphans
        .iter()
        .filter(|item| item.kind == ConnectorArtifactKind::QuickRuntime)
    {
        if runtime.clear_connector(&orphan.connector_id)? {
            report.removed_runtime_records = report.removed_runtime_records.saturating_add(1);
        }
    }
    Ok(report)
}

fn scan_connector_artifacts(
    paths: &AppPaths,
    configured_ids: &BTreeSet<String>,
) -> Result<(ConnectorArtifactInventory, Vec<ArtifactPath>)> {
    let mut inventory = ConnectorArtifactInventory::default();
    let mut artifact_paths = Vec::new();
    scan_connector_directory(
        &paths.data_dir.join("connectors"),
        &paths.data_dir.join("connector-quarantine"),
        ConnectorArtifactKind::DataDirectory,
        configured_ids,
        &mut inventory,
        &mut artifact_paths,
    )?;
    scan_connector_directory(
        &paths.state_dir.join("connectors"),
        &paths.state_dir.join("connector-quarantine"),
        ConnectorArtifactKind::StateDirectory,
        configured_ids,
        &mut inventory,
        &mut artifact_paths,
    )?;
    let runtime = QuickTunnelRuntimeStore::new(paths).inventory()?;
    inventory.unsafe_entries = inventory
        .unsafe_entries
        .saturating_add(runtime.unsafe_entries);
    for record in runtime.records {
        if !configured_ids.contains(&record.connector_id) {
            inventory.orphans.push(OrphanConnectorArtifact {
                connector_id: record.connector_id,
                kind: ConnectorArtifactKind::QuickRuntime,
            });
        }
    }
    inventory.orphans.sort_by(|left, right| {
        left.connector_id
            .cmp(&right.connector_id)
            .then_with(|| format!("{:?}", left.kind).cmp(&format!("{:?}", right.kind)))
    });
    Ok((inventory, artifact_paths))
}

fn scan_connector_directory(
    directory: &Path,
    quarantine_root: &Path,
    kind: ConnectorArtifactKind,
    configured_ids: &BTreeSet<String>,
    inventory: &mut ConnectorArtifactInventory,
    artifact_paths: &mut Vec<ArtifactPath>,
) -> Result<()> {
    let metadata = match fs::symlink_metadata(directory) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        inventory.unsafe_entries = inventory.unsafe_entries.saturating_add(1);
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let Ok(entry) = entry else {
            inventory.unsafe_entries = inventory.unsafe_entries.saturating_add(1);
            continue;
        };
        let Some(connector_id) = entry.file_name().to_str().map(str::to_owned) else {
            inventory.unsafe_entries = inventory.unsafe_entries.saturating_add(1);
            continue;
        };
        if validate_connector_id(&connector_id).is_err() {
            inventory.unsafe_entries = inventory.unsafe_entries.saturating_add(1);
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            inventory.unsafe_entries = inventory.unsafe_entries.saturating_add(1);
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            inventory.unsafe_entries = inventory.unsafe_entries.saturating_add(1);
            continue;
        }
        if configured_ids.contains(&connector_id) {
            continue;
        }
        inventory.orphans.push(OrphanConnectorArtifact {
            connector_id: connector_id.clone(),
            kind,
        });
        artifact_paths.push(ArtifactPath {
            connector_id,
            kind,
            path,
            quarantine_root: quarantine_root.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked connector quarantine directory");
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg_attr(
    not(unix),
    expect(
        clippy::unnecessary_wraps,
        reason = "directory fsync is Unix-only while the quarantine transaction keeps one fallible interface"
    )
)]
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orphan_directories_are_quarantined_and_runtime_is_removed() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let paths = AppPaths::under(temporary.path().join("runonmine"));
        paths.ensure()?;
        let configured = "00000000-0000-4000-8000-000000000001".to_owned();
        let orphan = "00000000-0000-4000-8000-000000000002".to_owned();
        fs::create_dir_all(paths.data_dir.join("connectors").join(&configured))?;
        fs::create_dir_all(paths.data_dir.join("connectors").join(&orphan))?;
        fs::create_dir_all(paths.state_dir.join("connectors").join(&orphan))?;
        fs::create_dir_all(paths.data_dir.join("connectors").join("bad"))?;
        QuickTunnelRuntimeStore::new(&paths).begin(&orphan)?;
        let configured_ids = BTreeSet::from([configured.clone()]);

        let inventory = inventory_connector_artifacts(&paths, &configured_ids)?;
        assert_eq!(inventory.orphans.len(), 3);
        assert_eq!(inventory.unsafe_entries, 1);

        let report = reconcile_connector_artifacts(&paths, &configured_ids)?;
        assert_eq!(report.quarantined_directories, 2);
        assert_eq!(report.removed_runtime_records, 1);
        assert_eq!(report.unsafe_entries, 1);
        assert!(paths.data_dir.join("connectors").join(configured).is_dir());
        assert!(!paths.data_dir.join("connectors").join(&orphan).exists());
        assert!(!paths.state_dir.join("connectors").join(&orphan).exists());
        assert!(paths.data_dir.join("connectors").join("bad").is_dir());
        assert!(QuickTunnelRuntimeStore::new(&paths).get(&orphan)?.is_none());
        Ok(())
    }
}
