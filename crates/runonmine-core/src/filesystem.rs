use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use walkdir::WalkDir;

use crate::atomic;

#[derive(Clone, Debug)]
pub struct ScopedFilesystem {
    roots: Vec<PathBuf>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: PathBuf,
    pub kind: String,
    pub bytes: Option<u64>,
}

impl ScopedFilesystem {
    pub fn new(roots: &[PathBuf]) -> Result<Self> {
        let mut canonical = Vec::with_capacity(roots.len());
        for root in roots {
            let resolved = fs::canonicalize(root)
                .with_context(|| format!("allowed root does not exist: {}", root.display()))?;
            if !resolved.is_dir() {
                bail!("allowed root is not a directory: {}", resolved.display());
            }
            canonical.push(resolved);
        }
        canonical.sort();
        canonical.dedup();
        Ok(Self { roots: canonical })
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    pub fn resolve_existing(&self, path: &Path) -> Result<PathBuf> {
        let resolved = fs::canonicalize(path)
            .with_context(|| format!("path does not exist: {}", path.display()))?;
        self.ensure_allowed(&resolved)?;
        Ok(resolved)
    }

    pub fn resolve_for_write(&self, path: &Path) -> Result<PathBuf> {
        if path.exists() {
            return self.resolve_existing(path);
        }
        let parent = path.parent().context("write path has no parent")?;
        let resolved_parent = fs::canonicalize(parent)
            .with_context(|| format!("parent does not exist: {}", parent.display()))?;
        self.ensure_allowed(&resolved_parent)?;
        let name = path.file_name().context("write path has no file name")?;
        Ok(resolved_parent.join(name))
    }

    pub fn list(&self, path: &Path) -> Result<Vec<DirectoryEntry>> {
        let resolved = self.resolve_existing(path)?;
        if !resolved.is_dir() {
            bail!("not a directory: {}", resolved.display());
        }
        let mut entries = fs::read_dir(&resolved)?
            .map(|entry| {
                let entry = entry?;
                let metadata = entry.metadata()?;
                let kind = if metadata.is_dir() {
                    "directory"
                } else if metadata.is_file() {
                    "file"
                } else if metadata.file_type().is_symlink() {
                    "symlink"
                } else {
                    "other"
                };
                Ok(DirectoryEntry {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    path: entry.path(),
                    kind: kind.to_owned(),
                    bytes: metadata.is_file().then_some(metadata.len()),
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(entries)
    }

    pub fn read_text(&self, path: &Path, max_bytes: usize) -> Result<(String, bool)> {
        if max_bytes == 0 {
            bail!("read limit must be greater than zero");
        }
        let resolved = self.resolve_existing(path)?;
        let metadata = fs::metadata(&resolved)?;
        if !metadata.is_file() {
            bail!("path is not a regular file: {}", resolved.display());
        }
        let mut file = fs::File::open(&resolved)?;
        if !file.metadata()?.is_file() {
            bail!("path changed before it could be read safely");
        }

        let capture_limit = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
        let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1_024).saturating_add(1));
        file.by_ref().take(capture_limit).read_to_end(&mut bytes)?;
        let truncated = bytes.len() > max_bytes || metadata.len() > max_bytes as u64;
        bytes.truncate(max_bytes);

        let valid_length = match std::str::from_utf8(&bytes) {
            Ok(_) => bytes.len(),
            Err(error) if error.error_len().is_none() => error.valid_up_to(),
            Err(_) => bail!("file is not valid UTF-8"),
        };
        bytes.truncate(valid_length);
        let text = String::from_utf8(bytes).context("file is not valid UTF-8")?;
        Ok((text, truncated))
    }

    pub fn write_atomic(&self, path: &Path, contents: &[u8]) -> Result<PathBuf> {
        let resolved = self.resolve_for_write(path)?;
        atomic::write(&resolved, contents, 0o600)?;
        Ok(resolved)
    }

    pub fn search_names(&self, root: &Path, pattern: &str, limit: usize) -> Result<Vec<PathBuf>> {
        let resolved = self.resolve_existing(root)?;
        let needle = pattern.to_lowercase();
        let mut matches = Vec::new();
        for entry in WalkDir::new(resolved)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if entry
                .file_name()
                .to_string_lossy()
                .to_lowercase()
                .contains(&needle)
            {
                matches.push(entry.path().to_path_buf());
                if matches.len() >= limit {
                    break;
                }
            }
        }
        Ok(matches)
    }

    pub fn move_path(&self, from: &Path, to: &Path) -> Result<()> {
        let from = self.resolve_existing(from)?;
        let to = self.resolve_for_write(to)?;
        fs::rename(from, to)?;
        Ok(())
    }

    pub fn move_to_trash(&self, path: &Path) -> Result<()> {
        let resolved = self.resolve_existing(path)?;
        trash::delete(&resolved)
            .with_context(|| format!("failed to move {} to trash", resolved.display()))
    }

    fn ensure_allowed(&self, resolved: &Path) -> Result<()> {
        if self
            .roots
            .iter()
            .any(|root| resolved == root || resolved.starts_with(root))
        {
            return Ok(());
        }
        bail!("path is outside the configured roots")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_paths_outside_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        assert!(scoped.resolve_existing(outside.path()).is_err());
        Ok(())
    }

    #[test]
    fn writes_atomically_inside_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let target = root.path().join("hello.txt");
        scoped.write_atomic(&target, b"hello")?;
        assert_eq!(fs::read_to_string(target)?, "hello");
        Ok(())
    }

    #[test]
    fn rejects_non_regular_paths() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        assert!(scoped.read_text(root.path(), 1_024).is_err());
        Ok(())
    }

    #[test]
    fn reads_only_the_configured_prefix() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let target = root.path().join("large.txt");
        fs::write(&target, "x".repeat(32 * 1_024))?;
        let (content, truncated) = scoped.read_text(&target, 1_024)?;
        assert_eq!(content.len(), 1_024);
        assert!(truncated);
        Ok(())
    }

    #[test]
    fn preserves_utf8_boundaries_when_truncated() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let target = root.path().join("utf8.txt");
        fs::write(&target, "abcé")?;
        let (content, truncated) = scoped.read_text(&target, 4)?;
        assert_eq!(content, "abc");
        assert!(truncated);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, "secret")?;
        let link = root.path().join("link.txt");
        symlink(&outside_file, &link)?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        assert!(scoped.resolve_existing(&link).is_err());
        Ok(())
    }
}
