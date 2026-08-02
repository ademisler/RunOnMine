//! Installation and lifecycle management for the opt-in privileged helper.

use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;

#[cfg(test)]
use super::install_transaction::InstallFault;
use super::install_transaction::{
    InstallLock, InstallRequest, ServiceLifecycle, ServiceState, install_lock_path,
    install_transaction,
};
use super::{
    AdminPolicy, AdminProgramRule, HelperAvailability, HelperClient, HelperRequest, HelperResult,
    OwnerIdentity,
};

#[cfg(target_os = "macos")]
const MACOS_SERVICE_LABEL: &str = "dev.runonmine.helper";
#[cfg(target_os = "linux")]
const LINUX_SERVICE_NAME: &str = "runonmine-helper.service";
#[cfg(windows)]
const WINDOWS_SERVICE_NAME: &str = "RunOnMineHelper";

#[derive(Clone, Debug)]
pub struct HelperInstallOptions {
    pub owner: OwnerIdentity,
    pub allowed_programs: Vec<AdminProgramRule>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HelperServiceStatus {
    pub state: HelperAvailability,
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
        let policy_bytes =
            serde_json::to_vec_pretty(&policy).context("failed to encode helper policy")?;
        let paths = SystemPaths::discover()?;
        validate_source_executable(&self.source_executable)?;
        prepare_system_directory(&paths.binary)?;
        prepare_system_directory(&paths.policy)?;
        if let Some(service) = &paths.service_definition {
            prepare_system_directory(service)?;
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let service_definition = Some(platform_service_definition(&paths));
        #[cfg(windows)]
        let service_definition: Option<Vec<u8>> = None;
        install_transaction(
            InstallRequest {
                paths: &paths,
                source_executable: &self.source_executable,
                policy_bytes: &policy_bytes,
                service_definition: service_definition.as_deref(),
                owner: options.owner,
                #[cfg(test)]
                fault: InstallFault::None,
            },
            &PlatformServiceLifecycle,
        )
        .await
    }

    pub fn uninstall(&self) -> Result<()> {
        super::require_installer_identity()?;
        let paths = SystemPaths::discover()?;
        prepare_system_directory(&paths.policy)?;
        let install_lock = InstallLock::acquire(&paths)?;
        uninstall_platform_service(&paths)?;
        remove_regular_file_if_present(&paths.socket)?;
        remove_regular_file_if_present(&paths.policy)?;
        remove_regular_file_if_present(&paths.binary)?;
        if let Some(service) = &paths.service_definition {
            remove_regular_file_if_present(service)?;
        }
        remove_empty_parent(&paths.socket)?;
        drop(install_lock);
        remove_regular_file_if_present(&install_lock_path(&paths))?;
        remove_empty_parent(&paths.policy)?;
        Ok(())
    }

    pub async fn status(&self) -> Result<HelperServiceStatus> {
        let paths = SystemPaths::discover()?;
        let (policy, policy_state) = match AdminPolicy::load(&paths.policy) {
            Ok(policy) => {
                let allowlisted_programs = policy.allowed_programs.len();
                (
                    Some(policy),
                    HelperAvailability::Available {
                        allowlisted_programs,
                    },
                )
            }
            Err(error) => (None, HelperAvailability::from_error(&error)),
        };
        let binary_present = paths.binary.is_file();
        let policy_present = paths.policy.is_file();
        let service_definition_present = paths
            .service_definition
            .as_ref()
            .is_some_and(|definition| definition.is_file());
        let service_definition_complete = paths
            .service_definition
            .as_ref()
            .is_none_or(|definition| definition.is_file());
        let (service_installed, installed_query_state) = match platform_service_installed() {
            Ok(installed) => (installed, None),
            Err(error) => (false, Some(service_query_error_state(&error))),
        };
        let (running, detail, status_query_state) = match platform_service_status() {
            Ok(output) => (
                output.status.success(),
                bounded_command_output(&output),
                None,
            ),
            Err(error) => (
                false,
                String::new(),
                Some(service_query_error_state(&error)),
            ),
        };
        let service_query_state = installed_query_state.or(status_query_state);
        let installed =
            binary_present && policy_present && service_definition_complete && service_installed;
        let any_artifact =
            binary_present || policy_present || service_definition_present || service_installed;
        let state = if matches!(policy_state, HelperAvailability::PermissionDenied)
            || matches!(
                service_query_state,
                Some(HelperAvailability::PermissionDenied)
            ) {
            HelperAvailability::PermissionDenied
        } else if service_query_state.is_some() {
            HelperAvailability::Unavailable
        } else if !any_artifact {
            HelperAvailability::Missing
        } else if !installed {
            match policy_state {
                HelperAvailability::Unavailable => HelperAvailability::Unavailable,
                _ => HelperAvailability::Corrupt,
            }
        } else if !running {
            HelperAvailability::Disabled
        } else if let Some(policy) = &policy {
            match HelperClient::new(policy.owner.clone()) {
                Ok(client) => tokio::time::timeout(Duration::from_secs(2), client.availability())
                    .await
                    .unwrap_or(HelperAvailability::Unavailable),
                Err(error) => HelperAvailability::from_error(&error),
            }
        } else {
            policy_state
        };
        let allowlisted_programs = state.allowlisted_programs().unwrap_or_else(|| {
            policy
                .as_ref()
                .map_or(0, |policy| policy.allowed_programs.len())
        });
        Ok(HelperServiceStatus {
            available: state.is_available(),
            state,
            installed,
            running,
            owner: policy.as_ref().map(|policy| policy.owner.clone()),
            allowlisted_programs,
            detail,
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
pub(super) struct SystemPaths {
    pub(super) binary: PathBuf,
    pub(super) policy: PathBuf,
    pub(super) service_definition: Option<PathBuf>,
    pub(super) socket: PathBuf,
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
            .map_or_else(|| PathBuf::from(r"C:\Program Files"), PathBuf::from);
        let program_data = std::env::var_os("ProgramData")
            .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
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

pub(super) fn reject_existing_symlink(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to replace a symlinked helper system file");
    }
    Ok(())
}

pub(super) fn remove_regular_file_if_present(path: &Path) -> Result<()> {
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

pub(super) fn apply_artifact_permissions(path: &Path, executable: bool, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to secure helper artifact {}", path.display()))?;
    }
    #[cfg(windows)]
    harden_windows_file_acl(path, executable)?;
    #[cfg(not(windows))]
    let _ = executable;
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

#[derive(Debug)]
struct PlatformServiceLifecycle;

impl ServiceLifecycle for PlatformServiceLifecycle {
    fn state(&self, paths: &SystemPaths) -> Result<ServiceState> {
        platform_service_state(paths)
    }

    fn stop(&self, paths: &SystemPaths) -> Result<()> {
        stop_platform_service_for_update(paths)
    }

    fn activate(&self, paths: &SystemPaths) -> Result<()> {
        activate_platform_service(paths)
    }

    fn restore(&self, paths: &SystemPaths, previous: ServiceState) -> Result<()> {
        restore_platform_service(paths, previous)
    }

    fn health(
        &self,
        owner: OwnerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>> {
        Box::pin(wait_for_helper_health(owner))
    }
}

async fn wait_for_helper_health(owner: OwnerIdentity) -> Result<()> {
    let client = HelperClient::new(owner)?;
    let mut last_error = None;
    for _ in 0..30 {
        match client.request(&HelperRequest::health()).await {
            Ok(response) => match validate_helper_health(response.result) {
                Ok(()) => return Ok(()),
                Err(error) => last_error = Some(error.to_string()),
            },
            Err(error) => last_error = Some(error.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!(
        "the helper service did not pass its health check: {}",
        last_error.unwrap_or_else(|| "no response".to_owned())
    )
}

fn validate_helper_health(result: HelperResult) -> Result<()> {
    let HelperResult::Healthy {
        protocol_version,
        package_version,
        ..
    } = result
    else {
        bail!("helper returned an unexpected health response");
    };
    if protocol_version != super::PROTOCOL_VERSION {
        bail!("running helper protocol version does not match the installer");
    }
    if package_version != super::HELPER_VERSION {
        bail!("running helper package version does not match the installer");
    }
    Ok(())
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
fn platform_service_definition(paths: &SystemPaths) -> Vec<u8> {
    let executable = xml_escape(&paths.binary.to_string_lossy());
    format!(
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
        )
        .into_bytes()
}

#[cfg(target_os = "linux")]
fn platform_service_definition(paths: &SystemPaths) -> Vec<u8> {
    let executable = systemd_escape(&paths.binary.to_string_lossy());
    format!(
        "[Unit]\nDescription=RunOnMine opt-in privileged helper\nAfter=local-fs.target\n\n\
             [Service]\nType=simple\nExecStart={executable} serve\nUser=root\nGroup=root\n\
             Restart=on-failure\nRestartSec=2\nRuntimeDirectory=runonmine-helper\n\
             RuntimeDirectoryMode=0755\nPrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n\
             ReadWritePaths=/run/runonmine-helper\nLockPersonality=true\n\
             [Install]\nWantedBy=multi-user.target\n"
    )
    .into_bytes()
}

#[cfg(target_os = "macos")]
fn platform_service_state(paths: &SystemPaths) -> Result<ServiceState> {
    let loaded = Command::new("launchctl")
        .args(["print", &format!("system/{MACOS_SERVICE_LABEL}")])
        .output()
        .context("failed to query the RunOnMine LaunchDaemon")?
        .status
        .success();
    Ok(ServiceState {
        installed: loaded
            || paths
                .service_definition
                .as_ref()
                .is_some_and(|definition| definition.is_file()),
        enabled: loaded,
        running: loaded,
    })
}

#[cfg(target_os = "linux")]
fn platform_service_state(paths: &SystemPaths) -> Result<ServiceState> {
    let load_state = Command::new("systemctl")
        .args([
            "show",
            "--property=LoadState",
            "--value",
            LINUX_SERVICE_NAME,
        ])
        .output()
        .context("failed to query the RunOnMine helper unit load state")?;
    let known_to_systemd = load_state.status.success()
        && !matches!(
            String::from_utf8_lossy(&load_state.stdout).trim(),
            "" | "not-found"
        );
    let enabled = Command::new("systemctl")
        .args(["is-enabled", LINUX_SERVICE_NAME])
        .output()
        .context("failed to query the RunOnMine helper enable state")?
        .status
        .success();
    let running = Command::new("systemctl")
        .args(["is-active", LINUX_SERVICE_NAME])
        .output()
        .context("failed to query the RunOnMine helper running state")?
        .status
        .success();
    Ok(ServiceState {
        installed: known_to_systemd
            || paths
                .service_definition
                .as_ref()
                .is_some_and(|definition| definition.is_file()),
        enabled,
        running,
    })
}

#[cfg(windows)]
fn platform_service_state(_paths: &SystemPaths) -> Result<ServiceState> {
    let query = Command::new("sc.exe")
        .args(["query", WINDOWS_SERVICE_NAME])
        .output()
        .context("failed to query the RunOnMine helper service")?;
    let installed = query.status.success();
    let query_text = format!(
        "{} {}",
        String::from_utf8_lossy(&query.stdout),
        String::from_utf8_lossy(&query.stderr)
    );
    let configuration = if installed {
        Some(
            Command::new("sc.exe")
                .args(["qc", WINDOWS_SERVICE_NAME])
                .output()
                .context("failed to query the RunOnMine helper start type")?,
        )
    } else {
        None
    };
    let enabled = configuration.as_ref().is_some_and(|output| {
        output.status.success() && String::from_utf8_lossy(&output.stdout).contains("AUTO_START")
    });
    Ok(ServiceState {
        installed,
        enabled,
        running: installed
            && (query_text.contains("RUNNING") || query_text.contains("STATE              : 4")),
    })
}

#[cfg(target_os = "macos")]
fn stop_platform_service_for_update(_paths: &SystemPaths) -> Result<()> {
    macos_bootout_allow_absent()
}

#[cfg(target_os = "linux")]
fn stop_platform_service_for_update(_paths: &SystemPaths) -> Result<()> {
    linux_service_command_allow_absent(
        &["stop", LINUX_SERVICE_NAME],
        "failed to stop the RunOnMine helper service",
    )
}

#[cfg(windows)]
fn stop_platform_service_for_update(_paths: &SystemPaths) -> Result<()> {
    windows_stop_allow_absent()
}

#[cfg(target_os = "macos")]
fn activate_platform_service(paths: &SystemPaths) -> Result<()> {
    let definition = paths
        .service_definition
        .as_ref()
        .context("LaunchDaemon definition path is unavailable")?;
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
fn activate_platform_service(_paths: &SystemPaths) -> Result<()> {
    command_success(
        Command::new("systemctl").arg("daemon-reload"),
        "failed to reload systemd",
    )?;
    command_success(
        Command::new("systemctl").args(["enable", LINUX_SERVICE_NAME]),
        "failed to enable the RunOnMine helper service",
    )?;
    command_success(
        Command::new("systemctl").args(["restart", LINUX_SERVICE_NAME]),
        "failed to restart the RunOnMine helper service",
    )
}

#[cfg(windows)]
fn activate_platform_service(paths: &SystemPaths) -> Result<()> {
    configure_windows_service(paths, true)?;
    command_success(
        Command::new("sc.exe").args(["start", WINDOWS_SERVICE_NAME]),
        "failed to start the RunOnMine LocalSystem service",
    )
}

#[cfg(target_os = "macos")]
fn restore_platform_service(paths: &SystemPaths, previous: ServiceState) -> Result<()> {
    macos_bootout_allow_absent()?;
    if previous.enabled || previous.running {
        activate_platform_service(paths)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn restore_platform_service(_paths: &SystemPaths, previous: ServiceState) -> Result<()> {
    command_success(
        Command::new("systemctl").arg("daemon-reload"),
        "failed to reload systemd during helper rollback",
    )?;
    if !previous.installed {
        return linux_service_command_allow_absent(
            &["disable", "--now", LINUX_SERVICE_NAME],
            "failed to remove the newly installed helper service",
        );
    }
    if previous.enabled {
        command_success(
            Command::new("systemctl").args(["enable", LINUX_SERVICE_NAME]),
            "failed to restore the helper enable state",
        )?;
    } else {
        linux_service_command_allow_absent(
            &["disable", LINUX_SERVICE_NAME],
            "failed to restore the helper disabled state",
        )?;
    }
    if previous.running {
        command_success(
            Command::new("systemctl").args(["start", LINUX_SERVICE_NAME]),
            "failed to restart the restored helper service",
        )
    } else {
        linux_service_command_allow_absent(
            &["stop", LINUX_SERVICE_NAME],
            "failed to restore the helper stopped state",
        )
    }
}

#[cfg(windows)]
fn restore_platform_service(paths: &SystemPaths, previous: ServiceState) -> Result<()> {
    windows_stop_allow_absent()?;
    if !previous.installed {
        return windows_delete_allow_absent();
    }
    configure_windows_service(paths, previous.enabled)?;
    if previous.running {
        command_success(
            Command::new("sc.exe").args(["start", WINDOWS_SERVICE_NAME]),
            "failed to restart the restored RunOnMine helper service",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_bootout_allow_absent() -> Result<()> {
    let output = Command::new("launchctl")
        .args(["bootout", &format!("system/{MACOS_SERVICE_LABEL}")])
        .output()
        .context("failed to request RunOnMine LaunchDaemon shutdown")?;
    if output.status.success() || output.status.code() == Some(3) {
        Ok(())
    } else {
        bail!(
            "failed to stop the RunOnMine LaunchDaemon: {}",
            bounded_command_output(&output)
        )
    }
}

#[cfg(target_os = "linux")]
fn linux_service_command_allow_absent(args: &[&str], context: &str) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .with_context(|| context.to_owned())?;
    let detail = bounded_command_output(&output).to_ascii_lowercase();
    if output.status.success()
        || detail.contains("not loaded")
        || detail.contains("not found")
        || detail.contains("does not exist")
    {
        Ok(())
    } else {
        bail!("{context}: {}", bounded_command_output(&output))
    }
}

#[cfg(windows)]
fn configure_windows_service(paths: &SystemPaths, automatic: bool) -> Result<()> {
    let command_line = format!("\"{}\" service", paths.binary.display());
    let start_type = if automatic { "auto" } else { "demand" };
    if platform_service_installed()? {
        command_success(
            Command::new("sc.exe").args([
                "config",
                WINDOWS_SERVICE_NAME,
                "binPath=",
                &command_line,
                "start=",
                start_type,
                "obj=",
                "LocalSystem",
                "DisplayName=",
                "RunOnMine Privileged Helper",
            ]),
            "failed to update the RunOnMine LocalSystem service",
        )?;
    } else {
        command_success(
            Command::new("sc.exe").args([
                "create",
                WINDOWS_SERVICE_NAME,
                "binPath=",
                &command_line,
                "start=",
                start_type,
                "obj=",
                "LocalSystem",
                "DisplayName=",
                "RunOnMine Privileged Helper",
            ]),
            "failed to create the RunOnMine LocalSystem service",
        )?;
    }
    command_success(
        Command::new("sc.exe").args([
            "description",
            WINDOWS_SERVICE_NAME,
            "Opt-in RunOnMine privileged helper restricted to its installing user",
        ]),
        "failed to describe the RunOnMine LocalSystem service",
    )
}

#[cfg(windows)]
fn windows_stop_allow_absent() -> Result<()> {
    let output = Command::new("sc.exe")
        .args(["stop", WINDOWS_SERVICE_NAME])
        .output()
        .context("failed to request RunOnMine helper service shutdown")?;
    let detail = bounded_command_output(&output);
    if detail.contains("1060") {
        return Ok(());
    }
    if !output.status.success() && !detail.contains("1062") {
        bail!("failed to stop the RunOnMine helper service: {detail}");
    }
    for _ in 0..50 {
        let query = Command::new("sc.exe")
            .args(["query", WINDOWS_SERVICE_NAME])
            .output()
            .context("failed to wait for RunOnMine helper service shutdown")?;
        let query_detail = bounded_command_output(&query);
        if query_detail.contains("1060")
            || query_detail.contains("STOPPED")
            || query_detail.contains("STATE              : 1")
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("the RunOnMine helper service did not stop before artifact activation")
}

#[cfg(windows)]
fn windows_delete_allow_absent() -> Result<()> {
    let output = Command::new("sc.exe")
        .args(["delete", WINDOWS_SERVICE_NAME])
        .output()
        .context("failed to request RunOnMine helper service removal")?;
    let detail = bounded_command_output(&output);
    if output.status.success() || detail.contains("1060") {
        Ok(())
    } else {
        bail!("failed to delete the RunOnMine helper service: {detail}")
    }
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
            bounded_command_output(&output)
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
            bounded_command_output(&output)
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
            bounded_command_output(&output)
        )
    }
}

fn service_query_error_state(error: &anyhow::Error) -> HelperAvailability {
    if matches!(
        HelperAvailability::from_error(error),
        HelperAvailability::PermissionDenied
    ) {
        HelperAvailability::PermissionDenied
    } else {
        HelperAvailability::Unavailable
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
        bail!("{context}: {}", bounded_command_output(&output))
    }
}

fn bounded_command_output(output: &Output) -> String {
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

#[cfg(all(windows, not(test)))]
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

#[cfg(all(windows, test))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "unit tests exercise transactional file replacement without mutating host ACLs"
)]
fn harden_windows_file_acl(_path: &Path, _executable: bool) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_query_errors_distinguish_permission_denied_from_unavailable() {
        let denied = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
        let missing_command =
            anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(
            service_query_error_state(&denied),
            HelperAvailability::PermissionDenied
        );
        assert_eq!(
            service_query_error_state(&missing_command),
            HelperAvailability::Unavailable
        );
    }

    #[test]
    fn helper_health_requires_matching_protocol_and_package_versions() {
        assert!(
            validate_helper_health(HelperResult::Healthy {
                allowlisted_programs: 1,
                protocol_version: super::super::PROTOCOL_VERSION,
                package_version: super::super::HELPER_VERSION.to_owned(),
            })
            .is_ok()
        );
        assert!(
            validate_helper_health(HelperResult::Healthy {
                allowlisted_programs: 1,
                protocol_version: super::super::PROTOCOL_VERSION.saturating_add(1),
                package_version: super::super::HELPER_VERSION.to_owned(),
            })
            .is_err()
        );
        assert!(
            validate_helper_health(HelperResult::Healthy {
                allowlisted_programs: 1,
                protocol_version: super::super::PROTOCOL_VERSION,
                package_version: "stale-helper".to_owned(),
            })
            .is_err()
        );
        assert!(
            validate_helper_health(HelperResult::Failed {
                message: "not healthy".to_owned(),
            })
            .is_err()
        );
    }

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
