//! Installation and lifecycle management for the opt-in privileged helper.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use super::{AdminPolicy, HelperClient, HelperRequest, HelperResult, OwnerIdentity};

#[cfg(target_os = "macos")]
const MACOS_SERVICE_LABEL: &str = "dev.runonmine.helper";
#[cfg(target_os = "linux")]
const LINUX_SERVICE_NAME: &str = "runonmine-helper.service";
#[cfg(windows)]
const WINDOWS_SERVICE_NAME: &str = "RunOnMineHelper";

#[derive(Clone, Debug)]
pub struct HelperInstallOptions {
    pub owner: OwnerIdentity,
    pub allowed_programs: Vec<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HelperServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub available: bool,
    pub owner: Option<OwnerIdentity>,
    pub allowlisted_programs: usize,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct HelperManager {
    source_executable: PathBuf,
}

impl HelperManager {
    pub fn discover() -> Result<Self> {
        let source_executable =
            std::env::current_exe().context("failed to locate the RunOnMine helper executable")?;
        Ok(Self { source_executable })
    }

    #[must_use]
    pub fn with_source_executable(source_executable: PathBuf) -> Self {
        Self { source_executable }
    }

    pub async fn install(&self, options: HelperInstallOptions) -> Result<()> {
        super::require_installer_identity()?;
        options.owner.validate()?;
        let policy = AdminPolicy::build(options.owner.clone(), &options.allowed_programs)?;
        let paths = SystemPaths::discover()?;
        validate_source_executable(&self.source_executable)?;
        prepare_system_directory(&paths.binary)?;
        prepare_system_directory(&paths.policy)?;
        if let Some(service) = &paths.service_definition {
            prepare_system_directory(service)?;
        }

        atomic_copy_executable(&self.source_executable, &paths.binary)?;
        atomic_write_json(&paths.policy, &policy, 0o600)?;
        install_platform_service(&paths)?;

        let client = HelperClient::new(options.owner)?;
        let mut last_error = None;
        for _ in 0..30 {
            match client.request(&HelperRequest::health()).await {
                Ok(response) if matches!(response.result, HelperResult::Healthy { .. }) => {
                    return Ok(());
                }
                Ok(_) => {
                    last_error = Some("helper returned an unexpected health response".to_owned());
                }
                Err(error) => last_error = Some(error.to_string()),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        bail!(
            "the helper service was installed but did not pass its health check: {}",
            last_error.unwrap_or_else(|| "no response".to_owned())
        )
    }

    pub fn uninstall(&self) -> Result<()> {
        super::require_installer_identity()?;
        let paths = SystemPaths::discover()?;
        uninstall_platform_service(&paths)?;
        remove_regular_file_if_present(&paths.socket)?;
        remove_regular_file_if_present(&paths.policy)?;
        remove_regular_file_if_present(&paths.binary)?;
        if let Some(service) = &paths.service_definition {
            remove_regular_file_if_present(service)?;
        }
        remove_empty_parent(&paths.socket)?;
        Ok(())
    }

    pub async fn status(&self) -> Result<HelperServiceStatus> {
        let paths = SystemPaths::discover()?;
        let policy = AdminPolicy::load(&paths.policy).ok();
        let installed = paths.binary.is_file()
            && paths.policy.is_file()
            && paths
                .service_definition
                .as_ref()
                .is_none_or(|definition| definition.is_file())
            && platform_service_installed()?;
        let service_output = platform_service_status()?;
        let running = service_output.status.success();
        let mut available = false;
        let mut health_allowlisted_programs = None;
        let client = policy
            .as_ref()
            .and_then(|policy| HelperClient::new(policy.owner.clone()).ok())
            .or_else(|| HelperClient::for_current_user().ok());
        if let Some(client) = client
            && let Ok(response) = client.request(&HelperRequest::health()).await
            && let HelperResult::Healthy {
                allowlisted_programs,
            } = response.result
        {
            available = true;
            health_allowlisted_programs = Some(allowlisted_programs);
        }
        Ok(HelperServiceStatus {
            installed,
            running,
            available,
            owner: policy.as_ref().map(|policy| policy.owner.clone()),
            allowlisted_programs: health_allowlisted_programs.unwrap_or_else(|| {
                policy
                    .as_ref()
                    .map_or(0, |policy| policy.allowed_programs.len())
            }),
            detail: sanitized_output(&service_output),
        })
    }
}

pub fn installed_policy_path() -> Result<PathBuf> {
    Ok(SystemPaths::discover()?.policy)
}

#[cfg(unix)]
#[allow(clippy::needless_pass_by_value)]
pub fn resolve_install_owner(
    explicit_unix_uid: Option<u32>,
    explicit_windows_sid: Option<String>,
) -> Result<OwnerIdentity> {
    if explicit_windows_sid.is_some() {
        bail!("--owner-sid is only supported on Windows");
    }
    let uid = if let Some(uid) = explicit_unix_uid {
        uid
    } else {
        let value = std::env::var("SUDO_UID")
            .context("owner UID is required; run through sudo or pass --owner-uid explicitly")?;
        parse_uid(&value)?
    };
    let owner = OwnerIdentity::UnixUid { uid };
    owner.validate()?;
    Ok(owner)
}

#[cfg(windows)]
pub fn resolve_install_owner(
    explicit_unix_uid: Option<u32>,
    explicit_windows_sid: Option<String>,
) -> Result<OwnerIdentity> {
    if explicit_unix_uid.is_some() {
        bail!("--owner-uid is unavailable on Windows");
    }
    let sid = match explicit_windows_sid {
        Some(sid) => sid,
        None => super::windows::current_user_sid()?,
    };
    let owner = OwnerIdentity::WindowsSid { sid };
    owner.validate()?;
    Ok(owner)
}

#[cfg(not(any(unix, windows)))]
pub fn resolve_install_owner(
    _explicit_unix_uid: Option<u32>,
    _explicit_windows_sid: Option<String>,
) -> Result<OwnerIdentity> {
    bail!("the privileged helper is unsupported on this operating system")
}

#[cfg(unix)]
fn parse_uid(value: &str) -> Result<u32> {
    let uid = value
        .parse::<u32>()
        .context("owner UID must be an unsigned integer")?;
    if uid == 0 {
        bail!("the helper owner may not be root");
    }
    Ok(uid)
}

#[derive(Clone, Debug)]
struct SystemPaths {
    binary: PathBuf,
    policy: PathBuf,
    service_definition: Option<PathBuf>,
    socket: PathBuf,
}

impl SystemPaths {
    #[cfg(target_os = "macos")]
    #[allow(clippy::unnecessary_wraps)]
    fn discover() -> Result<Self> {
        Ok(Self {
            binary: PathBuf::from("/Library/PrivilegedHelperTools/dev.runonmine.helper"),
            policy: PathBuf::from("/Library/Application Support/RunOnMine/helper-policy.json"),
            service_definition: Some(PathBuf::from(
                "/Library/LaunchDaemons/dev.runonmine.helper.plist",
            )),
            socket: PathBuf::from("/var/run/runonmine-helper/helper.sock"),
        })
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::unnecessary_wraps)]
    fn discover() -> Result<Self> {
        Ok(Self {
            binary: PathBuf::from("/usr/local/libexec/runonmine-helper"),
            policy: PathBuf::from("/etc/runonmine/helper-policy.json"),
            service_definition: Some(PathBuf::from(
                "/etc/systemd/system/runonmine-helper.service",
            )),
            socket: PathBuf::from("/run/runonmine-helper/helper.sock"),
        })
    }

    #[cfg(windows)]
    #[allow(clippy::unnecessary_wraps)]
    fn discover() -> Result<Self> {
        let program_files = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        let program_data = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        Ok(Self {
            binary: program_files.join("RunOnMine/runonmine-helper.exe"),
            policy: program_data.join("RunOnMine/helper-policy.json"),
            service_definition: None,
            socket: PathBuf::from(r"\\.\pipe\RunOnMine.Helper"),
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    fn discover() -> Result<Self> {
        bail!("the privileged helper is unsupported on this operating system")
    }
}

fn validate_source_executable(source: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(source).context("failed to inspect the helper source executable")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("the helper source must be a regular, non-symlink executable");
    }
    Ok(())
}

fn prepare_system_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("system path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create system directory {}", parent.display()))?;
    let metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("failed to inspect system directory {}", parent.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("refusing to use a symlinked or non-directory system path");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != 0 {
            bail!("privileged helper directories must be owned by root");
        }
        if metadata.mode() & 0o022 != 0 {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

fn atomic_copy_executable(source: &Path, destination: &Path) -> Result<()> {
    reject_existing_symlink(destination)?;
    let parent = destination
        .parent()
        .context("helper destination has no parent directory")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut input = fs::File::open(source).context("failed to open the helper executable")?;
    std::io::copy(&mut input, temporary.as_file_mut())
        .context("failed to stage the helper executable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    temporary.as_file().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)
        .context("failed to activate helper executable")?;
    #[cfg(windows)]
    harden_windows_file_acl(destination, true)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn atomic_write_json<T>(destination: &Path, value: &T, mode: u32) -> Result<()>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).context("failed to encode helper policy")?;
    atomic_write(destination, &bytes, mode)?;
    #[cfg(windows)]
    harden_windows_file_acl(destination, false)?;
    Ok(())
}

fn atomic_write(destination: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    reject_existing_symlink(destination)?;
    let parent = destination
        .parent()
        .context("system file has no parent directory")?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(parent).context("failed to stage a helper system file")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)
        .context("failed to activate helper system file")?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn reject_existing_symlink(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to replace a symlinked helper system file");
    }
    Ok(())
}

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect helper system file"),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("refusing to remove a non-regular helper system path");
    }
    fs::remove_file(path).context("failed to remove helper system file")
}

fn remove_empty_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    match fs::remove_dir(parent) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error).context("failed to remove empty helper runtime directory"),
    }
}

#[cfg(target_os = "macos")]
fn install_platform_service(paths: &SystemPaths) -> Result<()> {
    let definition = paths
        .service_definition
        .as_ref()
        .context("LaunchDaemon definition path is unavailable")?;
    let executable = xml_escape(&paths.binary.to_string_lossy());
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
         \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\"><dict>\n\
         <key>Label</key><string>{MACOS_SERVICE_LABEL}</string>\n\
         <key>ProgramArguments</key><array><string>{executable}</string><string>serve</string></array>\n\
         <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n\
         <key>ProcessType</key><string>Background</string>\n\
         <key>StandardOutPath</key><string>/var/log/runonmine-helper.log</string>\n\
         <key>StandardErrorPath</key><string>/var/log/runonmine-helper.log</string>\n\
         </dict></plist>\n"
    );
    atomic_write(definition, plist.as_bytes(), 0o644)?;
    let _ignored = Command::new("launchctl")
        .args(["bootout", &format!("system/{MACOS_SERVICE_LABEL}")])
        .output();
    command_success(
        Command::new("launchctl").args([
            "bootstrap",
            "system",
            definition.to_string_lossy().as_ref(),
        ]),
        "failed to bootstrap the RunOnMine LaunchDaemon",
    )
}

#[cfg(target_os = "linux")]
fn install_platform_service(paths: &SystemPaths) -> Result<()> {
    let definition = paths
        .service_definition
        .as_ref()
        .context("systemd service definition path is unavailable")?;
    let executable = systemd_escape(&paths.binary.to_string_lossy());
    let unit = format!(
        "[Unit]\nDescription=RunOnMine opt-in privileged helper\nAfter=local-fs.target\n\n\
         [Service]\nType=simple\nExecStart={executable} serve\nUser=root\nGroup=root\n\
         Restart=on-failure\nRestartSec=2\nRuntimeDirectory=runonmine-helper\n\
         RuntimeDirectoryMode=0755\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n\
         ReadWritePaths=/run/runonmine-helper\nLockPersonality=true\n\
         [Install]\nWantedBy=multi-user.target\n"
    );
    atomic_write(definition, unit.as_bytes(), 0o644)?;
    command_success(
        Command::new("systemctl").arg("daemon-reload"),
        "failed to reload systemd",
    )?;
    command_success(
        Command::new("systemctl").args(["enable", "--now", LINUX_SERVICE_NAME]),
        "failed to enable the RunOnMine helper service",
    )
}

#[cfg(windows)]
fn install_platform_service(paths: &SystemPaths) -> Result<()> {
    let command_line = format!("\"{}\" service", paths.binary.display());
    let _ignored = Command::new("sc.exe")
        .args(["stop", WINDOWS_SERVICE_NAME])
        .output();
    let _ignored = Command::new("sc.exe")
        .args(["delete", WINDOWS_SERVICE_NAME])
        .output();
    command_success(
        Command::new("sc.exe").args([
            "create",
            WINDOWS_SERVICE_NAME,
            "binPath=",
            &command_line,
            "start=",
            "auto",
            "obj=",
            "LocalSystem",
            "DisplayName=",
            "RunOnMine Privileged Helper",
        ]),
        "failed to create the RunOnMine LocalSystem service",
    )?;
    command_success(
        Command::new("sc.exe").args([
            "description",
            WINDOWS_SERVICE_NAME,
            "Opt-in RunOnMine privileged helper restricted to its installing user",
        ]),
        "failed to describe the RunOnMine LocalSystem service",
    )?;
    command_success(
        Command::new("sc.exe").args(["start", WINDOWS_SERVICE_NAME]),
        "failed to start the RunOnMine LocalSystem service",
    )
}

#[cfg(target_os = "macos")]
fn uninstall_platform_service(_paths: &SystemPaths) -> Result<()> {
    let output = Command::new("launchctl")
        .args(["bootout", &format!("system/{MACOS_SERVICE_LABEL}")])
        .output()
        .context("failed to request LaunchDaemon removal")?;
    if output.status.success() || output.status.code() == Some(3) {
        Ok(())
    } else {
        bail!(
            "failed to stop the RunOnMine LaunchDaemon: {}",
            sanitized_output(&output)
        )
    }
}

#[cfg(target_os = "linux")]
fn uninstall_platform_service(_paths: &SystemPaths) -> Result<()> {
    let output = Command::new("systemctl")
        .args(["disable", "--now", LINUX_SERVICE_NAME])
        .output()
        .context("failed to request systemd service removal")?;
    if !output.status.success()
        && !String::from_utf8_lossy(&output.stderr).contains("does not exist")
    {
        bail!(
            "failed to stop the RunOnMine helper service: {}",
            sanitized_output(&output)
        );
    }
    command_success(
        Command::new("systemctl").arg("daemon-reload"),
        "failed to reload systemd",
    )
}

#[cfg(windows)]
fn uninstall_platform_service(_paths: &SystemPaths) -> Result<()> {
    let _ignored = Command::new("sc.exe")
        .args(["stop", WINDOWS_SERVICE_NAME])
        .output();
    let output = Command::new("sc.exe")
        .args(["delete", WINDOWS_SERVICE_NAME])
        .output()
        .context("failed to request Windows service removal")?;
    if output.status.success()
        || String::from_utf8_lossy(&output.stdout).contains("1060")
        || String::from_utf8_lossy(&output.stderr).contains("1060")
    {
        Ok(())
    } else {
        bail!(
            "failed to delete the RunOnMine helper service: {}",
            sanitized_output(&output)
        )
    }
}

#[cfg(target_os = "macos")]
fn platform_service_installed() -> Result<bool> {
    Ok(Command::new("launchctl")
        .args(["print", &format!("system/{MACOS_SERVICE_LABEL}")])
        .output()?
        .status
        .success())
}

#[cfg(target_os = "linux")]
fn platform_service_installed() -> Result<bool> {
    Ok(Command::new("systemctl")
        .args(["is-enabled", LINUX_SERVICE_NAME])
        .output()?
        .status
        .success())
}

#[cfg(windows)]
fn platform_service_installed() -> Result<bool> {
    Ok(Command::new("sc.exe")
        .args(["query", WINDOWS_SERVICE_NAME])
        .output()?
        .status
        .success())
}

#[cfg(target_os = "macos")]
fn platform_service_status() -> Result<Output> {
    Command::new("launchctl")
        .args(["print", &format!("system/{MACOS_SERVICE_LABEL}")])
        .output()
        .context("failed to query the RunOnMine LaunchDaemon")
}

#[cfg(target_os = "linux")]
fn platform_service_status() -> Result<Output> {
    Command::new("systemctl")
        .args(["is-active", LINUX_SERVICE_NAME])
        .output()
        .context("failed to query the RunOnMine helper service")
}

#[cfg(windows)]
fn platform_service_status() -> Result<Output> {
    Command::new("sc.exe")
        .args(["query", WINDOWS_SERVICE_NAME])
        .output()
        .context("failed to query the RunOnMine helper service")
}

fn command_success(command: &mut Command, context: &str) -> Result<()> {
    let output = command.output().with_context(|| context.to_owned())?;
    if output.status.success() {
        Ok(())
    } else {
        bail!("{context}: {}", sanitized_output(&output))
    }
}

fn sanitized_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    format!("{} {}", stdout.trim(), stderr.trim())
        .trim()
        .chars()
        .filter(|character| !character.is_control() || *character == ' ')
        .take(1_000)
        .collect()
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(target_os = "linux")]
fn systemd_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(windows)]
fn harden_windows_file_acl(path: &Path, _executable: bool) -> Result<()> {
    command_success(
        Command::new("icacls.exe").args([
            path.to_string_lossy().as_ref(),
            "/inheritance:r",
            "/grant:r",
            "SYSTEM:F",
            "*S-1-5-32-544:F",
        ]),
        "failed to restrict a helper system file ACL",
    )
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::*;

    #[cfg(unix)]
    #[test]
    fn owner_resolution_rejects_root() {
        assert!(resolve_install_owner(Some(0), None).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn system_paths_do_not_overlap_legacy_macmcp() -> Result<()> {
        let paths = SystemPaths::discover()?;
        for path in [paths.binary, paths.policy, paths.socket] {
            assert!(!path.to_string_lossy().contains("macmcp"));
            assert!(!path.to_string_lossy().contains("45799"));
        }
        Ok(())
    }
}
