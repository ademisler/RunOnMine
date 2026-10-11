//! Crash-safe ownership leases and startup reconciliation for owned Chromium sessions.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use chromiumoxide::browser::Browser;
use serde::{Deserialize, Serialize};
use sysinfo::{Pid, Process, ProcessStatus, System};
use uuid::Uuid;
use walkdir::WalkDir;

const LEASE_VERSION: u32 = 1;
const LEASE_PREFIX: &str = ".runonmine-browser-lease-";
const LEASE_SUFFIX: &str = ".json";
const MAX_LEASE_BYTES: u64 = 64 * 1024;
const PROCESS_EXIT_WAIT: Duration = Duration::from_secs(3);
const PROCESS_EXIT_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct BrowserOrphanReport {
    pub leases_examined: usize,
    pub processes_reaped: usize,
    pub stale_leases_removed: usize,
    pub ephemeral_profiles_removed: usize,
    pub live_owners_deferred: usize,
    pub live_profiles_deferred: usize,
    pub unsafe_entries: usize,
    pub failed_reaps: usize,
}

impl BrowserOrphanReport {
    pub fn changed(&self) -> bool {
        self.processes_reaped > 0
            || self.stale_leases_removed > 0
            || self.ephemeral_profiles_removed > 0
    }

    pub fn has_warnings(&self) -> bool {
        self.unsafe_entries > 0 || self.failed_reaps > 0 || self.live_profiles_deferred > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserLeaseRecord {
    version: u32,
    token: Uuid,
    profile_directory: PathBuf,
    executable: PathBuf,
    ephemeral: bool,
    owner_pid: u32,
    owner_start_time_unix_seconds: u64,
    browser_pid: Option<u32>,
    browser_start_time_unix_seconds: Option<u64>,
    created_unix_seconds: u64,
}

#[derive(Debug)]
pub(crate) struct BrowserLease {
    path: PathBuf,
    record: BrowserLeaseRecord,
    released: bool,
}

impl BrowserLease {
    pub(crate) fn prepare(profile: &Path, executable: &Path, ephemeral: bool) -> Result<Self> {
        ensure_real_private_directory(profile)?;
        let profile_directory = profile
            .canonicalize()
            .with_context(|| format!("failed to resolve browser profile {}", profile.display()))?;
        let executable = executable.canonicalize().with_context(|| {
            format!(
                "failed to resolve Chromium executable {}",
                executable.display()
            )
        })?;
        let system = System::new_all();
        let owner_pid = std::process::id();
        let owner = system
            .process(Pid::from_u32(owner_pid))
            .context("current process identity is unavailable for browser ownership lease")?;
        let token = Uuid::new_v4();
        let path = profile_directory.join(format!("{LEASE_PREFIX}{token}{LEASE_SUFFIX}"));
        let record = BrowserLeaseRecord {
            version: LEASE_VERSION,
            token,
            profile_directory,
            executable,
            ephemeral,
            owner_pid,
            owner_start_time_unix_seconds: owner.start_time(),
            browser_pid: None,
            browser_start_time_unix_seconds: None,
            created_unix_seconds: unix_seconds()?,
        };
        write_lease(&path, &record)?;
        Ok(Self {
            path,
            record,
            released: false,
        })
    }

    pub(crate) fn chromium_argument(&self) -> (String, String) {
        (
            "runonmine-owner-token".to_owned(),
            self.record.token.to_string(),
        )
    }

    pub(crate) fn activate(&mut self, browser: &mut Browser) -> Result<()> {
        let pid = browser
            .get_mut_child()
            .and_then(|child| child.as_mut_inner().id())
            .context("owned Chromium process ID is unavailable")?;
        let system = System::new_all();
        let current_user = current_user_id(&system)
            .context("current user identity is unavailable for browser ownership lease")?;
        let process = system
            .process(Pid::from_u32(pid))
            .context("owned Chromium process disappeared before lease activation")?;
        if !process_matches(
            process,
            &self.record,
            Some(current_user),
            ProcessMatchMode::Pending,
        ) {
            let token = format!("--runonmine-owner-token={}", self.record.token);
            bail!(
                "owned Chromium identity did not match its prepared ownership lease (user={}, token={}, profile={}, executable_family={})",
                process.user_id() == Some(current_user),
                command_contains_exact(process.cmd(), OsStr::new(&token)),
                command_references_profile(process.cmd(), &self.record.profile_directory),
                process.exe().is_some_and(|actual| {
                    executable_matches(actual, &self.record.executable, ProcessMatchMode::Pending)
                }),
            );
        }
        self.record.executable = process
            .exe()
            .context("owned Chromium executable identity is unavailable")?
            .canonicalize()
            .context("failed to resolve owned Chromium executable identity")?;
        self.record.browser_pid = Some(pid);
        self.record.browser_start_time_unix_seconds = Some(process.start_time());
        write_lease(&self.path, &self.record)
    }

    pub(crate) fn release(&mut self) {
        if self.released {
            return;
        }
        match fs::remove_file(&self.path) {
            Ok(()) => self.released = true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.released = true,
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                %error,
                "failed to remove browser ownership lease"
            ),
        }
    }

    pub(crate) fn profile_directory(&self) -> &Path {
        &self.record.profile_directory
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.record.executable
    }

    pub(crate) const fn ephemeral(&self) -> bool {
        self.record.ephemeral
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessMatchMode {
    Pending,
    Active,
}

pub fn reap_orphaned_browser_sessions(profiles_root: &Path) -> Result<BrowserOrphanReport> {
    match fs::symlink_metadata(profiles_root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BrowserOrphanReport::default());
        }
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("browser profiles root must be a real directory")
        }
        Ok(_) => {}
    }
    let root = profiles_root
        .canonicalize()
        .context("failed to resolve browser profiles root")?;
    let mut report = BrowserOrphanReport::default();
    let mut system = System::new_all();
    let current_user = current_user_id(&system).cloned();
    let lease_paths = collect_lease_paths(&root, &mut report);
    for path in lease_paths {
        reconcile_lease(
            &root,
            &path,
            &mut system,
            current_user.as_ref(),
            &mut report,
        );
    }
    reconcile_legacy_ephemeral_profiles(&root, &system, current_user.as_ref(), &mut report);
    Ok(report)
}

fn collect_lease_paths(root: &Path, report: &mut BrowserOrphanReport) -> Vec<PathBuf> {
    let mut leases = Vec::new();
    for entry in WalkDir::new(root).follow_links(false).max_depth(8) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                report.unsafe_entries += 1;
                tracing::warn!(%error, "browser profile inventory skipped an unreadable entry");
                continue;
            }
        };
        if entry.file_type().is_symlink() {
            report.unsafe_entries += 1;
            continue;
        }
        if entry.file_type().is_file() && is_lease_name(entry.file_name()) {
            leases.push(entry.into_path());
        }
    }
    leases
}

fn reconcile_lease(
    root: &Path,
    path: &Path,
    system: &mut System,
    current_user: Option<&sysinfo::Uid>,
    report: &mut BrowserOrphanReport,
) {
    report.leases_examined += 1;
    let record = match load_validated_lease(root, path) {
        Ok(record) => record,
        Err(error) => {
            report.unsafe_entries += 1;
            tracing::warn!(path = %path.display(), %error, "ignored unsafe browser ownership lease");
            return;
        }
    };
    if owner_is_live(system, &record) {
        report.live_owners_deferred += 1;
        return;
    }
    let exact = matching_processes(system, &record, current_user);
    if exact.is_empty() {
        if profile_has_live_reference(system, &record.profile_directory, current_user) {
            report.live_profiles_deferred += 1;
            return;
        }
        remove_stale_lease_and_profile(path, &record, report);
        return;
    }
    if current_user.is_none() {
        report.failed_reaps += 1;
        tracing::warn!(path = %path.display(), "cannot verify current user for orphan Chromium reaping");
        return;
    }
    let mut pids = Vec::new();
    for process in exact {
        let pid = process.pid();
        if process.kill() {
            pids.push((pid, process.start_time()));
        } else {
            report.failed_reaps += 1;
        }
    }
    if pids.is_empty() {
        return;
    }
    let deadline = std::time::Instant::now() + PROCESS_EXIT_WAIT;
    while std::time::Instant::now() < deadline {
        thread::sleep(PROCESS_EXIT_POLL);
        *system = System::new_all();
        if pids.iter().all(|(pid, start)| {
            system
                .process(*pid)
                .is_none_or(|process| process.start_time() != *start || !process_is_live(process))
        }) {
            report.processes_reaped += pids.len();
            if profile_has_live_reference(system, &record.profile_directory, current_user) {
                report.live_profiles_deferred += 1;
            } else {
                remove_stale_lease_and_profile(path, &record, report);
            }
            return;
        }
    }
    report.failed_reaps += pids
        .iter()
        .filter(|(pid, start)| {
            system
                .process(*pid)
                .is_some_and(|process| process.start_time() == *start && process_is_live(process))
        })
        .count();
}

fn matching_processes<'a>(
    system: &'a System,
    record: &BrowserLeaseRecord,
    current_user: Option<&sysinfo::Uid>,
) -> Vec<&'a Process> {
    if let (Some(pid), Some(start)) = (record.browser_pid, record.browser_start_time_unix_seconds)
        && let Some(process) = system.process(Pid::from_u32(pid))
        && process.start_time() == start
        && process_matches(process, record, current_user, ProcessMatchMode::Active)
    {
        return vec![process];
    }
    system
        .processes()
        .values()
        .filter(|process| process_matches(process, record, current_user, ProcessMatchMode::Pending))
        .collect()
}

fn process_matches(
    process: &Process,
    record: &BrowserLeaseRecord,
    current_user: Option<&sysinfo::Uid>,
    mode: ProcessMatchMode,
) -> bool {
    if current_user.is_none() || process.user_id() != current_user {
        return false;
    }
    if mode == ProcessMatchMode::Active
        && record
            .browser_start_time_unix_seconds
            .is_some_and(|expected| process.start_time() != expected)
    {
        return false;
    }
    let token = format!("--runonmine-owner-token={}", record.token);
    command_contains_exact(process.cmd(), OsStr::new(&token))
        && command_references_profile(process.cmd(), &record.profile_directory)
        && process
            .exe()
            .is_some_and(|actual| executable_matches(actual, &record.executable, mode))
}

fn executable_matches(actual: &Path, expected: &Path, mode: ProcessMatchMode) -> bool {
    if paths_match(actual, expected) {
        return true;
    }
    mode == ProcessMatchMode::Pending
        && browser_executable_family(actual).is_some()
        && browser_executable_family(actual) == browser_executable_family(expected)
}

fn browser_executable_family(path: &Path) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    if name.contains("chromium") || name.contains("chrome") {
        Some("chromium")
    } else if name.contains("msedge") || name.contains("microsoft-edge") {
        Some("edge")
    } else {
        None
    }
}

fn profile_has_live_reference(
    system: &System,
    profile: &Path,
    current_user: Option<&sysinfo::Uid>,
) -> bool {
    system.processes().values().any(|process| {
        process_is_live(process)
            && process.user_id() == current_user
            && command_references_profile(process.cmd(), profile)
    })
}

fn owner_is_live(system: &System, record: &BrowserLeaseRecord) -> bool {
    system
        .process(Pid::from_u32(record.owner_pid))
        .is_some_and(|process| {
            process_is_live(process) && process.start_time() == record.owner_start_time_unix_seconds
        })
}

fn process_is_live(process: &Process) -> bool {
    !matches!(
        process.status(),
        ProcessStatus::Dead | ProcessStatus::Zombie
    )
}

fn command_contains_exact(command: &[OsString], expected: &OsStr) -> bool {
    command.iter().any(|argument| argument == expected)
}

fn command_references_profile(command: &[OsString], profile: &Path) -> bool {
    let mut arguments = command.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--user-data-dir" {
            if arguments
                .next()
                .is_some_and(|value| paths_match(Path::new(value), profile))
            {
                return true;
            }
            continue;
        }
        let text = argument.to_string_lossy();
        if let Some(value) = text.strip_prefix("--user-data-dir=")
            && paths_match(Path::new(value), profile)
        {
            return true;
        }
    }
    false
}

fn paths_match(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn load_validated_lease(root: &Path, path: &Path) -> Result<BrowserLeaseRecord> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > MAX_LEASE_BYTES
    {
        bail!("browser lease must be a bounded real file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("browser lease permissions are broader than owner-only");
        }
    }
    let bytes = fs::read(path)?;
    let record: BrowserLeaseRecord = serde_json::from_slice(&bytes)?;
    if record.version != LEASE_VERSION
        || record.owner_pid == 0
        || record.created_unix_seconds == 0
        || record.browser_pid == Some(0)
        || record.browser_pid.is_some() != record.browser_start_time_unix_seconds.is_some()
        || !record.profile_directory.is_absolute()
        || !record.executable.is_absolute()
    {
        bail!("browser lease fields are invalid");
    }
    let expected_name = format!("{LEASE_PREFIX}{}{LEASE_SUFFIX}", record.token);
    let parent = path
        .parent()
        .context("browser lease has no profile directory")?;
    let canonical_parent = parent.canonicalize()?;
    if path.file_name() != Some(OsStr::new(&expected_name))
        || !canonical_parent.starts_with(root)
        || canonical_parent != record.profile_directory
    {
        bail!("browser lease identity does not match its filesystem location");
    }
    Ok(record)
}

fn remove_stale_lease_and_profile(
    path: &Path,
    record: &BrowserLeaseRecord,
    report: &mut BrowserOrphanReport,
) {
    match fs::remove_file(path) {
        Ok(()) => report.stale_leases_removed += 1,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            report.unsafe_entries += 1;
            tracing::warn!(path = %path.display(), %error, "failed to remove stale browser lease");
            return;
        }
    }
    if record.ephemeral && !profile_contains_other_leases(&record.profile_directory) {
        match remove_real_directory(&record.profile_directory) {
            Ok(true) => report.ephemeral_profiles_removed += 1,
            Ok(false) => {}
            Err(error) => {
                report.unsafe_entries += 1;
                tracing::warn!(
                    path = %record.profile_directory.display(),
                    %error,
                    "failed to remove stale ephemeral browser profile"
                );
            }
        }
    }
}

fn reconcile_legacy_ephemeral_profiles(
    root: &Path,
    system: &System,
    current_user: Option<&sysinfo::Uid>,
    report: &mut BrowserOrphanReport,
) {
    for entry in WalkDir::new(root)
        .follow_links(false)
        .min_depth(3)
        .max_depth(3)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_dir() || entry.path_is_symlink() {
            continue;
        }
        let Ok(relative) = entry.path().strip_prefix(root) else {
            report.unsafe_entries += 1;
            continue;
        };
        if relative.components().count() != 3
            || Uuid::parse_str(&entry.file_name().to_string_lossy()).is_err()
            || profile_contains_other_leases(entry.path())
        {
            continue;
        }
        let Ok(profile) = entry.path().canonicalize() else {
            report.unsafe_entries += 1;
            continue;
        };
        if profile_has_live_reference(system, &profile, current_user) {
            report.live_profiles_deferred += 1;
            continue;
        }
        match remove_real_directory(&profile) {
            Ok(true) => report.ephemeral_profiles_removed += 1,
            Ok(false) => {}
            Err(error) => {
                report.unsafe_entries += 1;
                tracing::warn!(path = %profile.display(), %error, "failed to remove legacy ephemeral browser profile");
            }
        }
    }
}

fn profile_contains_other_leases(profile: &Path) -> bool {
    fs::read_dir(profile).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|entry| {
            entry
                .file_type()
                .is_ok_and(|kind| kind.is_file() && is_lease_name(&entry.file_name()))
        })
    })
}

fn is_lease_name(name: &OsStr) -> bool {
    let name = name.to_string_lossy();
    name.starts_with(LEASE_PREFIX) && name.ends_with(LEASE_SUFFIX)
}

fn write_lease(path: &Path, record: &BrowserLeaseRecord) -> Result<()> {
    let parent = path.parent().context("browser lease path has no parent")?;
    ensure_real_private_directory(parent)?;
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to replace a symlinked browser ownership lease");
    }
    let payload = serde_json::to_vec_pretty(record)?;
    if payload.len() as u64 > MAX_LEASE_BYTES {
        bail!("browser ownership lease exceeds its size limit");
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&payload)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .context("failed to atomically replace browser ownership lease")?;
    sync_directory(parent)
}

fn ensure_real_private_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("browser profile path must be a real directory")
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(path)?,
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn remove_real_directory(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            bail!("refusing to remove a non-directory or symlinked browser profile")
        }
        Ok(_) => {
            fs::remove_dir_all(path)?;
            Ok(true)
        }
    }
}

fn current_user_id(system: &System) -> Option<&sysinfo::Uid> {
    system
        .process(Pid::from_u32(std::process::id()))
        .and_then(Process::user_id)
}

fn unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "directory fsync is Unix-only while orphan cleanup keeps one fallible interface"
)]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_matching_requires_exact_token_and_profile() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let profile = directory.path().join("profile");
        fs::create_dir(&profile)?;
        let command = vec![
            OsString::from("chromium"),
            OsString::from("--runonmine-owner-token=6cdba4f1-8075-48f6-a225-c7fe9cedfe9c"),
            OsString::from(format!("--user-data-dir={}", profile.display())),
        ];
        assert!(command_contains_exact(
            &command,
            OsStr::new("--runonmine-owner-token=6cdba4f1-8075-48f6-a225-c7fe9cedfe9c")
        ));
        assert!(command_references_profile(&command, &profile));
        assert!(!command_references_profile(
            &command,
            &directory.path().join("other")
        ));
        Ok(())
    }

    #[test]
    fn lease_update_atomically_replaces_existing_record() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let profile = directory.path().join("profile");
        fs::create_dir(&profile)?;
        let executable = std::env::current_exe()?.canonicalize()?;
        let token = Uuid::new_v4();
        let path = profile.join(format!("{LEASE_PREFIX}{token}{LEASE_SUFFIX}"));
        let mut record = BrowserLeaseRecord {
            version: LEASE_VERSION,
            token,
            profile_directory: profile.canonicalize()?,
            executable,
            ephemeral: true,
            owner_pid: 1,
            owner_start_time_unix_seconds: 1,
            browser_pid: None,
            browser_start_time_unix_seconds: None,
            created_unix_seconds: 1,
        };
        write_lease(&path, &record)?;
        record.browser_pid = Some(42);
        record.browser_start_time_unix_seconds = Some(99);
        write_lease(&path, &record)?;
        let updated: BrowserLeaseRecord = serde_json::from_slice(&fs::read(&path)?)?;
        assert_eq!(updated.browser_pid, Some(42));
        assert_eq!(updated.browser_start_time_unix_seconds, Some(99));
        Ok(())
    }

    #[test]
    fn stale_ephemeral_lease_removes_only_its_real_profile() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("profiles");
        let profile = root
            .join("default")
            .join("connector")
            .join(Uuid::new_v4().to_string());
        fs::create_dir_all(&profile)?;
        let executable = std::env::current_exe()?;
        let system = System::new_all();
        let owner = system
            .process(Pid::from_u32(std::process::id()))
            .context("test process missing")?;
        let record = BrowserLeaseRecord {
            version: LEASE_VERSION,
            token: Uuid::new_v4(),
            profile_directory: profile.canonicalize()?,
            executable: executable.canonicalize()?,
            ephemeral: true,
            owner_pid: u32::MAX,
            owner_start_time_unix_seconds: owner.start_time().saturating_sub(1),
            browser_pid: None,
            browser_start_time_unix_seconds: None,
            created_unix_seconds: unix_seconds()?,
        };
        let lease = profile.join(format!("{LEASE_PREFIX}{}{LEASE_SUFFIX}", record.token));
        write_lease(&lease, &record)?;
        let report = reap_orphaned_browser_sessions(&root)?;
        assert_eq!(report.stale_leases_removed, 1);
        assert_eq!(report.ephemeral_profiles_removed, 1);
        assert!(!profile.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_reaper_terminates_only_a_matching_orphan_chromium() -> Result<()> {
        use std::process::{Command, Stdio};

        let Some(executable) = crate::chromium_executable() else {
            return Ok(());
        };
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("profiles");
        let profile = root
            .join("default")
            .join("connector")
            .join(Uuid::new_v4().to_string());
        let mut lease = BrowserLease::prepare(&profile, &executable, true)?;
        let (token_name, token_value) = lease.chromium_argument();
        let mut child = Command::new(&executable)
            .arg("--headless=new")
            .arg("--disable-gpu")
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", profile.display()))
            .arg(format!("--{token_name}={token_value}"))
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        let current_user = current_user_id(&System::new_all())
            .cloned()
            .context("test user identity is unavailable")?;
        let token = format!("--runonmine-owner-token={}", lease.record.token);
        let process = wait_for_matching_process(pid, Duration::from_secs(15), |process| {
            process.user_id.as_ref() == Some(&current_user)
                && process_is_live_snapshot(process.status)
                && command_contains_exact(&process.command, OsStr::new(&token))
                && command_references_profile(&process.command, &lease.record.profile_directory)
                && process.exe().is_some_and(|actual| {
                    executable_matches(actual, &lease.record.executable, ProcessMatchMode::Pending)
                })
        });
        let Some(process) = process else {
            let _ignored = child.kill();
            let _ignored = child.wait();
            bail!("test Chromium did not reach the prepared lease identity before timeout");
        };
        lease.record.owner_pid = u32::MAX;
        lease.record.owner_start_time_unix_seconds = 1;
        lease.record.browser_pid = Some(pid);
        lease.record.browser_start_time_unix_seconds = Some(process.start_time());
        lease.record.executable = process
            .exe()
            .context("test Chromium executable is unavailable")?
            .canonicalize()?;
        write_lease(&lease.path, &lease.record)?;

        let report = reap_orphaned_browser_sessions(&root)?;
        assert_eq!(report.processes_reaped, 1);
        assert_eq!(report.stale_leases_removed, 1);
        assert_eq!(report.ephemeral_profiles_removed, 1);
        assert!(!profile.exists());
        let _status = child.wait()?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn wait_for_matching_process(
        pid: u32,
        timeout: Duration,
        matches: impl Fn(&OwnedProcessSnapshot) -> bool,
    ) -> Option<OwnedProcessSnapshot> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            let system = System::new_all();
            if let Some(process) = system.process(Pid::from_u32(pid)) {
                let snapshot = OwnedProcessSnapshot::from_process(process);
                if matches(&snapshot) {
                    return Some(snapshot);
                }
                if !process_is_live_snapshot(snapshot.status) {
                    return None;
                }
            }
            thread::sleep(Duration::from_millis(25));
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn process_is_live_snapshot(status: ProcessStatus) -> bool {
        !matches!(status, ProcessStatus::Dead | ProcessStatus::Zombie)
    }

    #[cfg(target_os = "linux")]
    #[derive(Debug)]
    struct OwnedProcessSnapshot {
        start_time: u64,
        command: Vec<OsString>,
        executable: Option<PathBuf>,
        user_id: Option<sysinfo::Uid>,
        status: ProcessStatus,
    }

    #[cfg(target_os = "linux")]
    impl OwnedProcessSnapshot {
        fn from_process(process: &Process) -> Self {
            Self {
                start_time: process.start_time(),
                command: process.cmd().to_vec(),
                executable: process.exe().map(Path::to_path_buf),
                user_id: process.user_id().cloned(),
                status: process.status(),
            }
        }

        fn start_time(&self) -> u64 {
            self.start_time
        }

        fn exe(&self) -> Option<&Path> {
            self.executable.as_deref()
        }
    }

    #[cfg(unix)]
    #[test]
    fn broad_lease_permissions_fail_closed() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let root = directory.path().join("profiles");
        let profile = root.join("default").join("connector");
        fs::create_dir_all(&profile)?;
        let lease = profile.join(format!("{LEASE_PREFIX}{}{LEASE_SUFFIX}", Uuid::new_v4()));
        fs::write(&lease, b"{}")?;
        fs::set_permissions(&lease, fs::Permissions::from_mode(0o644))?;
        let report = reap_orphaned_browser_sessions(&root)?;
        assert_eq!(report.unsafe_entries, 1);
        assert!(lease.exists());
        Ok(())
    }
}
