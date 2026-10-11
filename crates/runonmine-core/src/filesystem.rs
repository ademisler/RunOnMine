use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};

#[derive(Clone)]
pub struct ScopedFilesystem {
    roots: Vec<RootCapability>,
}

#[derive(Clone)]
struct RootCapability {
    path: PathBuf,
    #[cfg(windows)]
    requested_path: PathBuf,
    dir: Arc<Dir>,
}

impl fmt::Debug for ScopedFilesystem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedFilesystem")
            .field("roots", &self.roots())
            .finish()
    }
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
        let mut capabilities = Vec::with_capacity(roots.len());
        let mut canonical_roots = Vec::with_capacity(roots.len());
        for root in roots {
            let requested = if root.is_absolute() {
                root.clone()
            } else {
                std::env::current_dir()?.join(root)
            };
            validate_lexical_path(&requested)?;
            let resolved = std::fs::canonicalize(&requested)
                .with_context(|| format!("allowed root does not exist: {}", root.display()))?;
            if !resolved.is_dir() {
                bail!("allowed root is not a directory: {}", resolved.display());
            }
            let identity = root_identity_path(&requested, &resolved);
            #[cfg(windows)]
            let requested_identity = filesystem_identity_path(&requested);
            if canonical_roots.contains(&identity) {
                continue;
            }
            let dir = Dir::open_ambient_dir(&resolved, ambient_authority())
                .with_context(|| format!("failed to open allowed root: {}", resolved.display()))?;
            if !dir.dir_metadata()?.is_dir() {
                bail!("allowed root is not a directory: {}", resolved.display());
            }
            canonical_roots.push(identity.clone());
            capabilities.push(RootCapability {
                path: identity,
                #[cfg(windows)]
                requested_path: requested_identity,
                dir: Arc::new(dir),
            });
        }
        capabilities.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(Self {
            roots: capabilities,
        })
    }

    pub fn roots(&self) -> Vec<PathBuf> {
        self.roots.iter().map(|root| root.path.clone()).collect()
    }

    /// Resolve a requested path to the selected-root identity used by
    /// filesystem execution without requiring the final entry to exist.
    pub fn resolve_policy_path(&self, path: &Path) -> Result<PathBuf> {
        let (root, relative) = self.select_root(path)?;
        Ok(root.path.join(relative))
    }

    pub fn resolve_existing(&self, path: &Path) -> Result<PathBuf> {
        let (root, relative) = self.select_root(path)?;
        let metadata = root.dir.symlink_metadata(&relative).with_context(|| {
            format!("path does not exist or is inaccessible: {}", path.display())
        })?;
        if metadata.is_symlink() {
            bail!("symbolic links and reparse points are not allowed");
        }
        validate_existing_components(root, &relative)?;
        Ok(root.path.join(relative))
    }

    pub fn resolve_for_write(&self, path: &Path) -> Result<PathBuf> {
        let (root, relative) = self.select_root(path)?;
        let (parent, name, _) = open_parent(root, &relative)?;
        match parent.symlink_metadata(&name) {
            Ok(metadata) => {
                if metadata.is_symlink() || !metadata.is_file() {
                    bail!("write target must be a regular non-symlink file");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(root.path.join(relative))
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
        let (root, relative) = self.select_root(path)?;
        let directory = open_directory(root, &relative)?;
        let mut entries = Vec::new();
        for entry in directory.read_dir(".")? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let metadata = entry.metadata()?;
            let kind = if file_type.is_symlink() {
                "symlink"
            } else if file_type.is_dir() {
                "directory"
            } else if file_type.is_file() {
                "file"
            } else {
                "other"
            };
            let name = entry.file_name();
            entries.push(DirectoryEntry {
                name: name.to_string_lossy().into_owned(),
                path: root.path.join(&relative).join(&name),
                kind: kind.to_owned(),
                bytes: file_type.is_file().then_some(metadata.len()),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let total = entries.len();
        let entries = entries.into_iter().skip(offset).take(limit).collect();
        Ok(DirectoryListing {
            entries,
            offset,
            truncated: offset.saturating_add(limit) < total,
        })
    }

    pub fn read_text(&self, path: &Path, max_bytes: usize) -> Result<(String, bool)> {
        if max_bytes == 0 {
            bail!("read limit must be greater than zero");
        }
        let (root, relative) = self.select_root(path)?;
        let (parent, name, _) = open_parent(root, &relative)?;
        let before = parent.symlink_metadata(&name)?;
        if before.is_symlink() || !before.is_file() {
            bail!("path is not a regular non-symlink file: {}", path.display());
        }
        let mut file = parent.open(&name)?;
        let opened = file.metadata()?;
        if !opened.is_file() {
            bail!("path changed before it could be read safely");
        }

        let capture_limit = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
        let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1_024).saturating_add(1));
        std::io::Read::by_ref(&mut file)
            .take(capture_limit)
            .read_to_end(&mut bytes)?;
        let truncated = bytes.len() > max_bytes || opened.len() > max_bytes as u64;
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
        let (root, relative) = self.select_root(path)?;
        let (parent, name, _) = open_parent(root, &relative)?;
        let permissions = existing_permissions(&parent, &name)?;
        let temporary = OsString::from(format!(
            ".runonmine-write-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        let mut file = parent.open_with(&temporary, &options)?;
        if let Some(permissions) = permissions {
            file.set_permissions(permissions)?;
        } else {
            set_private_permissions(&file)?;
        }
        if let Err(error) = (|| -> Result<()> {
            file.write_all(contents)?;
            file.sync_all()?;
            parent.rename(&temporary, &parent, &name)?;
            Ok(())
        })() {
            let _ignored = parent.remove_file(&temporary);
            return Err(error);
        }
        Ok(root.path.join(relative))
    }

    pub fn search_names(&self, root: &Path, pattern: &str, limit: usize) -> Result<Vec<PathBuf>> {
        Ok(self
            .search_names_bounded(root, pattern, limit, 32, 100_000, Duration::from_secs(5))?
            .matches)
    }

    pub fn search_names_bounded(
        &self,
        root_path: &Path,
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
        let (root, relative) = self.select_root(root_path)?;
        let directory = open_directory(root, &relative)?;
        let needle = pattern.to_lowercase();
        let started = Instant::now();
        let mut state = SearchState {
            matches: Vec::with_capacity(limit.min(1_000)),
            visited: 0,
            truncated: false,
        };
        let display_root = root.path.join(&relative);
        search_directory(
            &directory,
            &display_root,
            &needle,
            0,
            limit,
            max_depth,
            max_nodes,
            max_duration,
            started,
            &mut state,
        )?;
        Ok(SearchResults {
            matches: state.matches,
            visited: state.visited,
            truncated: state.truncated,
        })
    }

    pub fn move_path(&self, from: &Path, to: &Path) -> Result<()> {
        let (from_root, from_relative) = self.select_root(from)?;
        let (to_root, to_relative) = self.select_root(to)?;
        let (from_parent, from_name, _) = open_parent(from_root, &from_relative)?;
        let from_metadata = from_parent.symlink_metadata(&from_name)?;
        if from_metadata.is_symlink() {
            bail!("symbolic links and reparse points are not allowed");
        }
        let (to_parent, to_name, _) = open_parent(to_root, &to_relative)?;
        if let Ok(metadata) = to_parent.symlink_metadata(&to_name)
            && metadata.is_symlink()
        {
            bail!("destination symbolic links and reparse points are not allowed");
        }
        from_parent.rename(&from_name, &to_parent, &to_name)?;
        Ok(())
    }

    pub fn move_to_trash(&self, path: &Path) -> Result<()> {
        let (root, relative) = self.select_root(path)?;
        let (parent, name, _) = open_parent(root, &relative)?;
        let metadata = parent.symlink_metadata(&name)?;
        if metadata.is_symlink() {
            bail!("symbolic links and reparse points are not allowed");
        }
        let trash_name = Path::new(".runonmine-trash");
        match root.dir.symlink_metadata(trash_name) {
            Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
            Ok(_) => bail!("managed trash path is not a safe directory"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                root.dir.create_dir(trash_name)?;
            }
            Err(error) => return Err(error.into()),
        }
        let trash_dir = root.dir.open_dir(trash_name)?;
        // A source name may already occupy the platform's entire filename
        // component limit. Use a fixed-size opaque destination so moving a
        // valid file into managed trash cannot fail due to name expansion.
        let destination = OsString::from(uuid::Uuid::new_v4().to_string());
        parent.rename(&name, &trash_dir, destination)?;
        Ok(())
    }

    fn select_root<'a>(&'a self, path: &Path) -> Result<(&'a RootCapability, PathBuf)> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else if self.roots.len() == 1 {
            self.roots[0].path.join(path)
        } else {
            bail!("relative paths require exactly one configured root");
        };
        validate_lexical_path(&absolute)?;
        let absolute = filesystem_identity_path(&absolute);
        let mut selected: Option<(&RootCapability, PathBuf)> = None;
        for root in &self.roots {
            #[cfg(windows)]
            let relative = absolute
                .strip_prefix(&root.path)
                .ok()
                .or(absolute.strip_prefix(&root.requested_path).ok());
            #[cfg(not(windows))]
            let relative = absolute.strip_prefix(&root.path).ok();
            if let Some(relative) = relative {
                let relative = relative.to_path_buf();
                if selected.as_ref().is_none_or(|(current, _)| {
                    root.path.as_os_str().len() > current.path.as_os_str().len()
                }) {
                    selected = Some((root, relative));
                }
            }
        }
        selected.context("path is outside the configured roots")
    }
}

struct SearchState {
    matches: Vec<PathBuf>,
    visited: usize,
    truncated: bool,
}

#[allow(clippy::too_many_arguments)]
fn search_directory(
    directory: &Dir,
    display_path: &Path,
    needle: &str,
    depth: usize,
    limit: usize,
    max_depth: usize,
    max_nodes: usize,
    max_duration: Duration,
    started: Instant,
    state: &mut SearchState,
) -> Result<()> {
    if depth >= max_depth {
        return Ok(());
    }
    for entry in directory.read_dir(".")? {
        if state.visited >= max_nodes || started.elapsed() >= max_duration {
            state.truncated = true;
            return Ok(());
        }
        let entry = entry?;
        state.visited = state.visited.saturating_add(1);
        let name = entry.file_name();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        let child_path = display_path.join(&name);
        if name.to_string_lossy().to_lowercase().contains(needle) {
            state.matches.push(child_path.clone());
            if state.matches.len() >= limit {
                state.truncated = true;
                return Ok(());
            }
        }
        if file_type.is_dir() {
            let child = directory.open_dir(&name)?;
            search_directory(
                &child,
                &child_path,
                needle,
                depth.saturating_add(1),
                limit,
                max_depth,
                max_nodes,
                max_duration,
                started,
                state,
            )?;
            if state.truncated {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn root_identity_path(_requested: &Path, resolved: &Path) -> PathBuf {
    filesystem_identity_path(resolved)
}

#[cfg(not(windows))]
fn root_identity_path(requested: &Path, _resolved: &Path) -> PathBuf {
    requested.to_path_buf()
}

#[cfg(windows)]
fn filesystem_identity_path(path: &Path) -> PathBuf {
    use std::path::Prefix;

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return path.to_path_buf();
    };
    let mut normalized = match prefix.kind() {
        Prefix::Disk(drive) => PathBuf::from(format!("\\\\?\\{}:\\", char::from(drive))),
        Prefix::UNC(server, share) => {
            let mut normalized = PathBuf::from(r"\\?\UNC");
            normalized.push(server);
            normalized.push(share);
            normalized
        }
        _ => return path.to_path_buf(),
    };
    for component in components {
        if !matches!(component, Component::RootDir) {
            normalized.push(component.as_os_str());
        }
    }
    normalized
}

#[cfg(not(windows))]
fn filesystem_identity_path(path: &Path) -> PathBuf {
    path.to_path_buf()
}

fn validate_lexical_path(path: &Path) -> Result<()> {
    for component in path.components() {
        if matches!(component, Component::ParentDir | Component::CurDir) {
            bail!("path traversal components are not allowed");
        }
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!("capability-relative path must not be absolute");
    }
    for component in path.components() {
        if !matches!(component, Component::Normal(_)) {
            bail!("path traversal components are not allowed");
        }
    }
    Ok(())
}

fn validate_existing_components(root: &RootCapability, relative: &Path) -> Result<()> {
    if relative.as_os_str().is_empty() {
        return Ok(());
    }
    validate_relative_path(relative)?;
    let mut current = root.dir.try_clone()?;
    let components: Vec<_> = relative.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            bail!("path traversal components are not allowed");
        };
        let metadata = current.symlink_metadata(name)?;
        if metadata.is_symlink() {
            bail!("symbolic links and reparse points are not allowed");
        }
        if index + 1 < components.len() {
            if !metadata.is_dir() {
                bail!("intermediate path component is not a directory");
            }
            current = current.open_dir(name)?;
        }
    }
    Ok(())
}

fn open_directory(root: &RootCapability, relative: &Path) -> Result<Dir> {
    if relative.as_os_str().is_empty() {
        return Ok(root.dir.try_clone()?);
    }
    validate_relative_path(relative)?;
    let mut current = root.dir.try_clone()?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("path traversal components are not allowed");
        };
        let metadata = current.symlink_metadata(name)?;
        if metadata.is_symlink() || !metadata.is_dir() {
            bail!("directory path contains a symlink, reparse point, or non-directory component");
        }
        current = current.open_dir(name)?;
    }
    Ok(current)
}

fn open_parent(root: &RootCapability, relative: &Path) -> Result<(Dir, OsString, PathBuf)> {
    validate_relative_path(relative)?;
    let name = relative
        .file_name()
        .context("path must identify an entry below an allowed root")?
        .to_os_string();
    let parent_relative = relative.parent().unwrap_or_else(|| Path::new(""));
    let parent = open_directory(root, parent_relative)?;
    Ok((parent, name, parent_relative.to_path_buf()))
}

fn existing_permissions(parent: &Dir, name: &OsStr) -> Result<Option<cap_std::fs::Permissions>> {
    match parent.symlink_metadata(name) {
        Ok(metadata) => {
            if metadata.is_symlink() || !metadata.is_file() {
                bail!("write target must be a regular non-symlink file");
            }
            Ok(Some(metadata.permissions()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn set_private_permissions(file: &cap_std::fs::File) -> Result<()> {
    use cap_std::fs::PermissionsExt as _;
    file.set_permissions(cap_std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Unix mode hardening is a no-op on Windows while secure writes keep one fallible interface"
)]
fn set_private_permissions(_file: &cap_std::fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn normal_component_strategy() -> impl Strategy<Value = String> {
        "[A-Za-z0-9_-]{1,16}"
    }

    fn path_from_components(components: &[String]) -> PathBuf {
        components
            .iter()
            .fold(PathBuf::new(), |mut path, component| {
                path.push(component);
                path
            })
    }

    #[test]
    fn policy_paths_use_the_same_selected_root_identity_as_execution() -> Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::create_dir_all(root.path().join("private"))?;
        std::fs::write(root.path().join("private/report.txt"), b"report")?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;

        let selected_root = scoped
            .roots()
            .into_iter()
            .next()
            .context("selected filesystem root is missing")?;
        assert_eq!(
            scoped.resolve_policy_path(Path::new("private/report.txt"))?,
            selected_root.join("private/report.txt")
        );
        assert_eq!(
            scoped.resolve_policy_path(&root.path().join("private/report.txt"))?,
            scoped.resolve_existing(Path::new("private/report.txt"))?
        );
        assert!(scoped.resolve_policy_path(Path::new("../outside")).is_err());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn requested_windows_root_spelling_maps_to_canonical_selected_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let canonical = scoped
            .roots()
            .into_iter()
            .next()
            .context("selected filesystem root is missing")?;
        let requested_target = root.path().join("mapped.txt");

        assert_eq!(
            scoped.resolve_policy_path(&requested_target)?,
            canonical.join("mapped.txt")
        );
        scoped.write_atomic(&requested_target, b"mapped")?;
        assert_eq!(std::fs::read(canonical.join("mapped.txt"))?, b"mapped");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn normal_windows_absolute_path_matches_verbatim_selected_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let canonical = root.path().canonicalize()?;
        let canonical_text = canonical.to_string_lossy();
        let normal = canonical_text
            .strip_prefix("\\\\?\\")
            .context("Windows canonical path did not use a verbatim prefix")?;
        let target = PathBuf::from(normal).join("approved.txt");
        let scoped = ScopedFilesystem::new(std::slice::from_ref(&canonical))?;

        assert_eq!(
            scoped.resolve_policy_path(&target)?,
            canonical.join("approved.txt")
        );
        scoped.write_atomic(&target, b"approved")?;
        assert_eq!(std::fs::read(canonical.join("approved.txt"))?, b"approved");
        Ok(())
    }

    #[test]
    fn rejects_paths_outside_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        assert!(scoped.resolve_existing(outside.path()).is_err());
        Ok(())
    }

    #[test]
    fn rejects_parent_traversal() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        assert!(
            scoped
                .resolve_for_write(&root.path().join("nested/../escape"))
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn writes_atomically_inside_root() -> Result<()> {
        let root = tempfile::tempdir()?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let target = root.path().join("hello.txt");
        scoped.write_atomic(&target, b"hello")?;
        assert_eq!(std::fs::read_to_string(target)?, "hello");
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
        std::fs::write(&target, "x".repeat(32 * 1_024))?;
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
        std::fs::write(&target, "abcé")?;
        let (content, truncated) = scoped.read_text(&target, 4)?;
        assert_eq!(content, "abc");
        assert!(truncated);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_nested_symlink_escape() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let outside_file = outside.path().join("secret.txt");
        std::fs::write(&outside_file, "secret")?;
        std::fs::create_dir(root.path().join("nested"))?;
        symlink(outside.path(), root.path().join("nested/link"))?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        assert!(
            scoped
                .read_text(&root.path().join("nested/link/secret.txt"), 1_024)
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn directory_listing_and_search_are_bounded() -> Result<()> {
        let root = tempfile::tempdir()?;
        for index in 0..6 {
            std::fs::write(root.path().join(format!("match-{index}.txt")), "data")?;
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

    #[test]
    fn directory_pagination_is_stable_after_sorting() -> Result<()> {
        let root = tempfile::tempdir()?;
        for name in ["zeta", "beta", "delta", "alpha", "gamma"] {
            std::fs::write(root.path().join(name), name)?;
        }
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        let first = scoped.list_limited(root.path(), 0, 2)?;
        let second = scoped.list_limited(root.path(), 2, 2)?;
        let third = scoped.list_limited(root.path(), 4, 2)?;
        assert_eq!(
            first
                .entries
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
        assert_eq!(
            second
                .entries
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["delta", "gamma"]
        );
        assert_eq!(
            third
                .entries
                .iter()
                .map(|item| item.name.as_str())
                .collect::<Vec<_>>(),
            vec!["zeta"]
        );
        assert!(first.truncated);
        assert!(second.truncated);
        assert!(!third.truncated);
        Ok(())
    }

    #[test]
    fn managed_trash_accepts_a_maximum_length_source_name() -> Result<()> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("x".repeat(240));
        std::fs::write(&target, "data")?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        scoped.move_to_trash(&target)?;
        let moved = std::fs::read_dir(root.path().join(".runonmine-trash"))?
            .next()
            .transpose()?
            .context("trash entry was not created")?;
        assert!(moved.file_name().len() <= 64);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn atomic_overwrite_preserves_existing_mode() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir()?;
        let target = root.path().join("script.sh");
        std::fs::write(&target, "old")?;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o750))?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        scoped.write_atomic(&target, b"new")?;
        assert_eq!(
            std::fs::metadata(&target)?.permissions().mode() & 0o777,
            0o750
        );
        Ok(())
    }

    #[test]
    fn managed_trash_is_descriptor_relative() -> Result<()> {
        let root = tempfile::tempdir()?;
        let target = root.path().join("delete-me.txt");
        std::fs::write(&target, "data")?;
        let scoped = ScopedFilesystem::new(&[root.path().to_path_buf()])?;
        scoped.move_to_trash(&target)?;
        assert!(!target.exists());
        assert_eq!(
            std::fs::read_dir(root.path().join(".runonmine-trash"))?.count(),
            1
        );
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn normal_relative_components_are_accepted(
            components in prop::collection::vec(normal_component_strategy(), 1..8),
        ) {
            let path = path_from_components(&components);
            prop_assert!(validate_lexical_path(&path).is_ok());
            prop_assert!(validate_relative_path(&path).is_ok());
        }

        #[test]
        fn parent_components_are_rejected_at_every_position(
            before in prop::collection::vec(normal_component_strategy(), 0..6),
            after in prop::collection::vec(normal_component_strategy(), 0..6),
        ) {
            let mut path = path_from_components(&before);
            path.push("..");
            for component in after {
                path.push(component);
            }
            prop_assert!(validate_lexical_path(&path).is_err());
            prop_assert!(validate_relative_path(&path).is_err());
        }
    }
}
