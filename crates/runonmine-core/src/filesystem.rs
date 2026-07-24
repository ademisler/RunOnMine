use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

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

#[derive(Clone, Debug, serde::Serialize)]
pub struct DirectoryListing {
    pub entries: Vec<DirectoryEntry>,
    pub offset: usize,
    pub truncated: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SearchResults {
    pub matches: Vec<PathBuf>,
    pub visited: usize,
    pub truncated: bool,
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
        Ok(self.list_limited(path, 0, usize::MAX)?.entries)
    }

    pub fn list_limited(
        &self,
        path: &Path,
        offset: usize,
        limit: usize,
    ) -> Result<DirectoryListing> {
        if limit == 0 {
            bail!("directory listing limit must be greater than zero");
        }
        let resolved = self.resolve_existing(path)?;
        if !resolved.is_dir() {
            bail!("not a directory: {}", resolved.display());
        }
        let mut entries = Vec::with_capacity(limit.min(1_024));
        let mut truncated = false;
        for entry in fs::read_dir(&resolved)?.skip(offset) {
            let entry = entry?;
            if entries.len() >= limit {
                truncated = true;
                break;
            }
            let file_type = entry.file_type()?;
            let metadata = if file_type.is_symlink() {
                fs::symlink_metadata(entry.path())?
            } else {
                entry.metadata()?
            };
            let kind = if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "file"
            } else {
                "other"
            };
            entries.push(DirectoryEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path(),
                kind: kind.to_owned(),
                bytes: file_type.is_file().then_some(metadata.len()),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(DirectoryListing {
            entries,
            offset,
            truncated,
        })
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
        let unix_mode = existing_unix_mode(&resolved)?.unwrap_or(0o600);
        atomic::write(&resolved, contents, unix_mode)?;
        Ok(resolved)
    }

    pub fn search_names(&self, root: &Path, pattern: &str, limit: usize) -> Result<Vec<PathBuf>> {
        Ok(self
            .search_names_bounded(root, pattern, limit, 32, 100_000, Duration::from_secs(5))?
            .matches)
    }

    pub fn search_names_bounded(
        &self,
        root: &Path,
        pattern: &str,
        limit: usize,
        max_depth: usize,
        max_nodes: usize,
        max_duration: Duration,
    ) -> Result<SearchResults> {
        if pattern.is_empty() || pattern.len() > 4_096 {
            bail!("search pattern is empty or too large");
        }
        if limit == 0 || max_depth == 0 || max_nodes == 0 || max_duration.is_zero() {
            bail!("search limits must be greater than zero");
        }
        let resolved = self.resolve_existing(root)?;
        let needle = pattern.to_lowercase();
        let started = Instant::now();
        let mut matches = Vec::with_capacity(limit.min(1_000));
        let mut visited = 0_usize;
        let mut truncated = false;
        for entry in WalkDir::new(resolved)
            .follow_links(false)
            .max_depth(max_depth)
        {
            if visited >= max_nodes || started.elapsed() >= max_duration {
                truncated = true;
                break;
            }
            let entry = entry?;
            visited = visited.saturating_add(1);
            if entry
                .file_name()
                .to_string_lossy()
                .to_lowercase()
                .contains(&needle)
            {
                matches.push(entry.path().to_path_buf());
                if matches.len() >= limit {
                    truncated = true;
                    break;
                }
            }
        }
        Ok(SearchResults {
            matches,
            visited,
            truncated,
        })
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

#[cfg(unix)]
fn existing_unix_mode(path: &Path) -> Result<Option<u32>> {
    use std::os::unix::fs::PermissionsExt;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("write target must be a regular non-symlink file");
            }
            Ok(Some(metadata.permissions().mode() & 0o777))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(unix))]
fn existing_unix_mode(path: &Path) -> Result<Option<u32>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("write target must be a regular non-symlink file");
            }
            Ok(Some(0o600))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
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
    #[test]
    fn directory_listing_and_search_are_bounded() -> Result<()> {
        let root = tempfile::tempdir()?;
        for index in 0..6 {
            fs::write(root.path().join(format!("match-{index}.txt")), "data")?;
        }
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let listing = scoped.list_limited(root.path(), 0, 2)?;
        assert_eq!(listing.entries.len(), 2);
        assert!(listing.truncated);

        let search =
            scoped.search_names_bounded(root.path(), "match", 2, 4, 100, Duration::from_secs(1))?;
        assert_eq!(search.matches.len(), 2);
        assert!(search.truncated);
        assert!(search.visited >= 2);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn atomic_overwrite_preserves_existing_mode() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir()?;
        let target = root.path().join("script.sh");
        fs::write(&target, "old")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o750))?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        scoped.write_atomic(&target, b"new")?;
        assert_eq!(fs::metadata(&target)?.permissions().mode() & 0o777, 0o750);
        Ok(())
    }
}
