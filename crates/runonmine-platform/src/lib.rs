//! Operating-system capability detection and service integration.

mod output;

pub mod agent_status;
pub mod desktop;
pub mod helper;
pub mod native;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use crate::agent_status::{AgentRestartExpectation, agent_status_path};
use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use directories::BaseDirs;
use directories::ProjectDirs;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct PlatformInfo {
    pub os: &'static str,
    pub architecture: &'static str,
    pub desktop_session: bool,
    pub supports_admin_helper: bool,
}

pub fn current() -> PlatformInfo {
    PlatformInfo {
        os: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        desktop_session: desktop_session_available(),
        supports_admin_helper: matches!(std::env::consts::OS, "macos" | "linux" | "windows"),
    }
}

/// Restrict a newly created regular file to the current operating-system user.
///
/// Callers should create the file with no-overwrite semantics before invoking
/// this function. Symlinks and non-regular files are rejected.
pub fn restrict_current_user_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect private file {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("private output must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let helper::OwnerIdentity::WindowsSid { sid } = helper::resolve_install_owner(None, None)?
        else {
            bail!("failed to resolve the current Windows user SID");
        };
        let grant = format!("*{sid}:F");
        command_success(
            Command::new("icacls.exe").args([
                path.to_string_lossy().as_ref(),
                "/inheritance:r",
                "/grant:r",
                &grant,
            ]),
            "failed to restrict private output to the current Windows user",
        )
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = path;
        bail!("private file permissions are unsupported on this operating system")
    }
}

fn desktop_session_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

pub const USER_SERVICE_NAME: &str = "runonmine-agent";
#[cfg(any(windows, test))]
const WINDOWS_RECOVERY_COMMAND: &str = "$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -StartWhenAvailable; Set-ScheduledTask -TaskName 'RunOnMine Agent' -Settings $settings | Out-Null";
#[cfg(target_os = "macos")]
const MACOS_SERVICE_LOG_LIMIT_BYTES: u64 = 5 * 1_024 * 1_024;

#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatus {
    pub installed: bool,
    pub running: bool,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct UserService {
    agent_executable: PathBuf,
}

/// Explicit, headless Linux deployment managed by the system service manager.
///
/// The service itself never runs as root: installation requires root only to
/// place the executable and unit, then systemd drops to the selected account.
#[derive(Clone, Debug)]
pub struct LinuxSystemService {
    #[cfg(target_os = "linux")]
    agent_executable: PathBuf,
    #[cfg(not(target_os = "linux"))]
    _unsupported: (),
}

impl LinuxSystemService {
    pub fn discover() -> Result<Self> {
        let current =
            std::env::current_exe().context("failed to locate the RunOnMine executable")?;
        let directory = current
            .parent()
            .context("RunOnMine executable has no parent directory")?;
        #[cfg(windows)]
        let agent = directory.join("runonmine-agent.exe");
        #[cfg(not(windows))]
        let agent = directory.join("runonmine-agent");
        #[cfg(target_os = "linux")]
        return Ok(Self {
            agent_executable: agent,
        });
        #[cfg(not(target_os = "linux"))]
        {
            let _ = agent;
            Ok(Self { _unsupported: () })
        }
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn with_agent_executable(agent_executable: PathBuf) -> Self {
        #[cfg(target_os = "linux")]
        return Self { agent_executable };
        #[cfg(not(target_os = "linux"))]
        {
            let _ = agent_executable;
            Self { _unsupported: () }
        }
    }

    pub fn install(&self, run_as_user: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.install_linux(run_as_user)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = run_as_user;
            bail!("system service installation is supported only on Linux")
        }
    }

    pub fn uninstall(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.uninstall_linux()
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("system service removal is supported only on Linux")
        }
    }

    pub fn start(&self) -> Result<()> {
        linux_systemctl(
            &["start", LINUX_SYSTEM_SERVICE],
            "failed to start the system service",
        )
    }

    pub fn stop(&self) -> Result<()> {
        linux_systemctl(
            &["stop", LINUX_SYSTEM_SERVICE],
            "failed to stop the system service",
        )
    }

    pub fn status(&self) -> Result<ServiceStatus> {
        #[cfg(target_os = "linux")]
        {
            let output = Command::new("systemctl")
                .args(["is-active", LINUX_SYSTEM_SERVICE])
                .output()?;
            Ok(ServiceStatus {
                installed: Path::new(LINUX_SYSTEM_UNIT_PATH).is_file(),
                running: output.status.success(),
                detail: bounded_command_output(&output),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("system service status is supported only on Linux")
        }
    }

    #[cfg(target_os = "linux")]
    fn install_linux(&self, run_as_user: &str) -> Result<()> {
        require_root()?;
        validate_service_user(run_as_user)?;
        if !self.agent_executable.is_file() {
            bail!(
                "runonmine-agent was not found beside the CLI at {}",
                self.agent_executable.display()
            );
        }
        let account = service_account(run_as_user)?;
        validate_linux_system_master_key_credential()?;
        if account.uid.is_root() {
            bail!("the headless system service must not run as root");
        }
        let home = account.dir;
        if !home.is_absolute() {
            bail!("the service account home directory is invalid");
        }
        let install_directory = Path::new(LINUX_SYSTEM_BINARY_PATH)
            .parent()
            .context("system agent path has no parent")?;
        fs::create_dir_all(install_directory)?;
        reject_symlink(install_directory, "system binary directory")?;
        atomic_copy_executable(&self.agent_executable, Path::new(LINUX_SYSTEM_BINARY_PATH))?;

        let status_path = linux_system_agent_status_path(&home);
        let home_environment = systemd_escape(&format!("HOME={}", home.display()));
        let xdg_config = systemd_escape(&format!("XDG_CONFIG_HOME={}/.config", home.display()));
        let xdg_data = systemd_escape(&format!("XDG_DATA_HOME={}/.local/share", home.display()));
        let status_environment = systemd_escape(&format!(
            "RUNONMINE_AGENT_STATUS_FILE={}",
            status_path.display()
        ));
        let unit = format!(
            "[Unit]\nDescription=RunOnMine headless MCP agent\nAfter=network-online.target\nWants=network-online.target\n\n\
             [Service]\nType=simple\nUser={run_as_user}\nExecStart={LINUX_SYSTEM_BINARY_PATH} run\n\
             WorkingDirectory={}\nEnvironment={home_environment}\nEnvironment={xdg_config}\nEnvironment={xdg_data}\nEnvironment={status_environment}\n\
             LoadCredential=runonmine-master-key:{LINUX_SYSTEM_MASTER_KEY_PATH}\n\
             Restart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\n\
             PrivateDevices=true\nProtectSystem=full\nProtectKernelTunables=true\nProtectKernelModules=true\n\
             ProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nRestrictRealtime=true\n\
             SystemCallArchitectures=native\n\n[Install]\nWantedBy=multi-user.target\n",
            systemd_escape(&home.to_string_lossy())
        );
        atomic_write_mode(Path::new(LINUX_SYSTEM_UNIT_PATH), unit.as_bytes(), 0o644)?;
        linux_systemctl(&["daemon-reload"], "failed to reload systemd")?;
        linux_systemctl(
            &["enable", LINUX_SYSTEM_SERVICE],
            "failed to enable the system service",
        )?;
        let expectation =
            AgentRestartExpectation::begin(status_path, Path::new(LINUX_SYSTEM_BINARY_PATH))?;
        linux_systemctl(
            &["restart", LINUX_SYSTEM_SERVICE],
            "failed to restart the system service",
        )?;
        let status = self.status()?;
        if !status.running {
            bail!(
                "the installed system agent service is not active: {}",
                status.detail
            );
        }
        expectation.wait_blocking(Duration::from_secs(15))?;
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::unused_self)]
    fn uninstall_linux(&self) -> Result<()> {
        require_root()?;
        let _ignored = Command::new("systemctl")
            .args(["disable", "--now", LINUX_SYSTEM_SERVICE])
            .output();
        for path in [LINUX_SYSTEM_UNIT_PATH, LINUX_SYSTEM_BINARY_PATH] {
            let path = Path::new(path);
            if path.symlink_metadata().is_ok() {
                fs::remove_file(path)?;
            }
        }
        if let Some(directory) = Path::new(LINUX_SYSTEM_BINARY_PATH).parent() {
            let _ignored = fs::remove_dir(directory);
        }
        linux_systemctl(&["daemon-reload"], "failed to reload systemd")
    }
}

const LINUX_SYSTEM_SERVICE: &str = "runonmine-agent.service";
#[cfg(target_os = "linux")]
const LINUX_SYSTEM_UNIT_PATH: &str = "/etc/systemd/system/runonmine-agent.service";
#[cfg(target_os = "linux")]
const LINUX_SYSTEM_BINARY_PATH: &str = "/usr/local/libexec/runonmine/runonmine-agent";
#[cfg(target_os = "linux")]
const LINUX_SYSTEM_MASTER_KEY_PATH: &str = "/etc/runonmine/master-key";

#[cfg(target_os = "linux")]
fn validate_linux_system_master_key_credential() -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let path = Path::new(LINUX_SYSTEM_MASTER_KEY_PATH);
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "headless system service requires a master-key credential at {LINUX_SYSTEM_MASTER_KEY_PATH}"
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > 4 * 1_024
    {
        bail!("system master-key credential must be a bounded regular non-symlink file");
    }
    if metadata.uid() != 0 || metadata.permissions().mode() & 0o077 != 0 {
        bail!("system master-key credential must be root-owned and inaccessible to group/other");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_system_agent_status_path(home: &Path) -> PathBuf {
    home.join(".local/state/runonmine/agent-runtime.json")
}

fn linux_systemctl(arguments: &[&str], context: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        command_success(Command::new("systemctl").args(arguments), context)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (arguments, context);
        bail!("system service operations are supported only on Linux")
    }
}

#[cfg(target_os = "linux")]
fn require_root() -> Result<()> {
    if !nix::unistd::geteuid().is_root() {
        bail!("system service installation and removal must be run as root");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn service_account(user: &str) -> Result<nix::unistd::User> {
    nix::unistd::User::from_name(user)?.context("the requested service account does not exist")
}

#[cfg(target_os = "linux")]
fn validate_service_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user.len() > 32
        || !user.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase() || byte == b'_'
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            }
        })
    {
        bail!("service user name is invalid");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reject_symlink(path: &Path, label: &str) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("{label} must not be a symbolic link");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn atomic_copy_executable(source: &Path, destination: &Path) -> Result<()> {
    let contents = fs::read(source)?;
    atomic_write_mode(destination, &contents, 0o755)
}

#[cfg(target_os = "linux")]
fn atomic_write_mode(destination: &Path, contents: &[u8], mode: u32) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    let parent = destination
        .parent()
        .context("system-managed file has no parent directory")?;
    reject_symlink(parent, "system-managed directory")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(mode))?;
    temporary
        .persist(destination)
        .map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

impl UserService {
    pub fn discover() -> Result<Self> {
        let current =
            std::env::current_exe().context("failed to locate the RunOnMine executable")?;
        let directory = current
            .parent()
            .context("RunOnMine executable has no parent directory")?;
        #[cfg(windows)]
        let agent = directory.join("runonmine-agent.exe");
        #[cfg(not(windows))]
        let agent = directory.join("runonmine-agent");
        Ok(Self {
            agent_executable: agent,
        })
    }

    pub fn with_agent_executable(agent_executable: PathBuf) -> Self {
        Self { agent_executable }
    }

    pub fn install(&self, allowed_roots: &[PathBuf]) -> Result<()> {
        let installed_agent = stage_versioned_user_service_agent(&self.agent_executable)?;
        let installed_service = Self::with_agent_executable(installed_agent.clone());
        let expectation = AgentRestartExpectation::begin(agent_status_path()?, &installed_agent)?;
        #[cfg(target_os = "macos")]
        {
            let _ = allowed_roots;
            installed_service.install_macos()?;
        }
        #[cfg(target_os = "linux")]
        installed_service.install_linux(allowed_roots)?;
        #[cfg(windows)]
        {
            let _ = allowed_roots;
            installed_service.install_windows()?;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            let _ = (allowed_roots, expectation);
            bail!("service installation is unsupported on this operating system");
        }
        let status = installed_service.status()?;
        if !status.running {
            bail!(
                "the installed agent service is not active: {}",
                status.detail
            );
        }
        expectation.wait_blocking(Duration::from_secs(15))?;
        Ok(())
    }

    /// Re-render the installed user service with the current selected roots.
    /// A running Linux service is restarted so the new systemd sandbox takes
    /// effect immediately. Other platforms do not need root path directives.
    pub fn reconcile_allowed_roots(&self, allowed_roots: &[PathBuf]) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let installed = installed_user_service_agent_path()?;
            Self::with_agent_executable(installed).reconcile_linux_allowed_roots(allowed_roots)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = allowed_roots;
            Ok(false)
        }
    }

    pub fn uninstall(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.uninstall_macos()?;
            remove_versioned_user_service_agent()
        }
        #[cfg(target_os = "linux")]
        {
            self.uninstall_linux()?;
            remove_versioned_user_service_agent()
        }
        #[cfg(windows)]
        {
            self.uninstall_windows()?;
            remove_versioned_user_service_agent()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            bail!("service removal is unsupported on this operating system")
        }
    }

    pub fn start(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            rotate_macos_service_logs()?;
            command_success(
                Command::new("launchctl").args([
                    "kickstart",
                    "-k",
                    &format!("{}/dev.runonmine.agent", launch_domain()),
                ]),
                "failed to start the LaunchAgent",
            )
        }
        #[cfg(target_os = "linux")]
        {
            command_success(
                Command::new("systemctl").args(["--user", "start", "runonmine-agent.service"]),
                "failed to start the systemd user service",
            )
        }
        #[cfg(windows)]
        {
            command_success(
                Command::new("schtasks.exe").args(["/Run", "/TN", "RunOnMine Agent"]),
                "failed to start the scheduled task",
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            bail!("service start is unsupported on this operating system")
        }
    }

    pub fn restart_if_running(&self) -> Result<bool> {
        let current = self.status()?;
        #[cfg(windows)]
        let should_restart = current.installed;
        #[cfg(not(windows))]
        let should_restart = current.running;
        if !should_restart {
            return Ok(false);
        }
        let installed_agent = installed_user_service_agent_path()?;
        let expectation = AgentRestartExpectation::begin(agent_status_path()?, &installed_agent)?;
        #[cfg(target_os = "macos")]
        {
            rotate_macos_service_logs()?;
            command_success(
                Command::new("launchctl").args([
                    "kickstart",
                    "-k",
                    &format!("{}/dev.runonmine.agent", launch_domain()),
                ]),
                "failed to restart the LaunchAgent",
            )?;
        }
        #[cfg(target_os = "linux")]
        command_success(
            Command::new("systemctl").args(["--user", "restart", "runonmine-agent.service"]),
            "failed to restart the systemd user service",
        )?;
        #[cfg(windows)]
        {
            let _ignored = Command::new("schtasks.exe")
                .args(["/End", "/TN", "RunOnMine Agent"])
                .output();
            command_success(
                Command::new("schtasks.exe").args(["/Run", "/TN", "RunOnMine Agent"]),
                "failed to restart the scheduled task",
            )?;
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        bail!("service restart is unsupported on this operating system");
        #[cfg(not(windows))]
        {
            let restarted = self.status()?;
            if !restarted.running {
                bail!(
                    "the agent service did not become active after restart: {}",
                    restarted.detail
                );
            }
        }
        expectation.wait_blocking(Duration::from_secs(15))?;
        Ok(true)
    }

    pub fn stop(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            command_success(
                Command::new("launchctl").args([
                    "kill",
                    "SIGTERM",
                    &format!("{}/dev.runonmine.agent", launch_domain()),
                ]),
                "failed to stop the LaunchAgent",
            )
        }
        #[cfg(target_os = "linux")]
        {
            command_success(
                Command::new("systemctl").args(["--user", "stop", "runonmine-agent.service"]),
                "failed to stop the systemd user service",
            )
        }
        #[cfg(windows)]
        {
            command_success(
                Command::new("schtasks.exe").args(["/End", "/TN", "RunOnMine Agent"]),
                "failed to stop the scheduled task",
            )
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            bail!("service stop is unsupported on this operating system")
        }
    }

    pub fn status(&self) -> Result<ServiceStatus> {
        #[cfg(not(windows))]
        let service_path = service_definition_path()?;
        #[cfg(target_os = "macos")]
        let output = Command::new("launchctl")
            .args(["print", &format!("{}/dev.runonmine.agent", launch_domain())])
            .output()?;
        #[cfg(target_os = "linux")]
        let output = Command::new("systemctl")
            .args(["--user", "is-active", "runonmine-agent.service"])
            .output()?;
        #[cfg(windows)]
        let output = Command::new("schtasks.exe")
            .args(["/Query", "/TN", "RunOnMine Agent", "/FO", "LIST"])
            .output()?;
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        let output = Output {
            status: Command::new("false").status()?,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        #[cfg(windows)]
        let installed = output.status.success();
        #[cfg(not(windows))]
        let installed = service_path.as_ref().is_some_and(|path| path.exists());
        #[cfg(windows)]
        let running = installed && windows_scheduled_task_running()?;
        #[cfg(not(windows))]
        let running = output.status.success();
        let detail = bounded_command_output(&output);
        #[cfg(target_os = "macos")]
        let detail = if let Ok(summary) = macos_service_log_summary() {
            if detail.is_empty() {
                summary
            } else {
                format!("{detail} {summary}")
            }
        } else {
            detail
        };
        Ok(ServiceStatus {
            installed,
            running,
            detail,
        })
    }

    #[cfg(target_os = "macos")]
    fn install_macos(&self) -> Result<()> {
        let path = service_definition_path()?.context("LaunchAgent path is unavailable")?;
        ensure_parent(&path)?;
        rotate_macos_service_logs()?;
        let (stdout_path, stderr_path) = macos_service_log_paths()?;
        let executable = xml_escape(&self.agent_executable.to_string_lossy());
        let stdout = xml_escape(&stdout_path.to_string_lossy());
        let stderr = xml_escape(&stderr_path.to_string_lossy());
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>Label</key><string>dev.runonmine.agent</string>\n\
             <key>ProgramArguments</key><array><string>{executable}</string><string>run</string></array>\n\
             <key>RunAtLoad</key><true/>\n\
             <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n\
             <key>ThrottleInterval</key><integer>10</integer>\n\
             <key>ProcessType</key><string>Background</string>\n\
             <key>StandardOutPath</key><string>{stdout}</string>\n\
             <key>StandardErrorPath</key><string>{stderr}</string>\n\
             <key>EnvironmentVariables</key><dict>\n\
             <key>RUNONMINE_SERVICE_STDERR_LOG</key><string>{stderr}</string>\n\
             </dict>\n\
             </dict></plist>\n"
        );
        write_private(&path, plist.as_bytes())?;
        let domain = launch_domain();
        let _ignored = Command::new("launchctl")
            .args(["bootout", &domain, path.to_string_lossy().as_ref()])
            .output();
        command_success(
            Command::new("launchctl").args(["bootstrap", &domain, path.to_string_lossy().as_ref()]),
            "failed to install the LaunchAgent",
        )?;
        command_success(
            Command::new("launchctl").args([
                "kickstart",
                "-k",
                &format!("{domain}/dev.runonmine.agent"),
            ]),
            "failed to restart the installed LaunchAgent",
        )
    }

    #[cfg(target_os = "macos")]
    #[allow(clippy::unused_self)]
    fn uninstall_macos(&self) -> Result<()> {
        let path = service_definition_path()?.context("LaunchAgent path is unavailable")?;
        if path.exists() {
            let domain = launch_domain();
            let _ignored = Command::new("launchctl")
                .args(["bootout", &domain, path.to_string_lossy().as_ref()])
                .output();
            fs::remove_file(path)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn install_linux(&self, allowed_roots: &[PathBuf]) -> Result<()> {
        let path = service_definition_path()?.context("systemd user path is unavailable")?;
        ensure_parent(&path)?;
        self.write_linux_user_unit(&path, allowed_roots)?;
        command_success(
            Command::new("systemctl").args(["--user", "daemon-reload"]),
            "failed to reload the systemd user manager",
        )?;
        command_success(
            Command::new("systemctl").args(["--user", "enable", "runonmine-agent.service"]),
            "failed to enable the systemd user service",
        )?;
        command_success(
            Command::new("systemctl").args(["--user", "restart", "runonmine-agent.service"]),
            "failed to start the systemd user service with the current sandbox",
        )
    }

    #[cfg(target_os = "linux")]
    fn reconcile_linux_allowed_roots(&self, allowed_roots: &[PathBuf]) -> Result<bool> {
        let path = service_definition_path()?.context("systemd user path is unavailable")?;
        if !path.is_file() {
            return Ok(false);
        }
        if !self.agent_executable.is_file() {
            bail!(
                "runonmine-agent was not found beside the current application at {}",
                self.agent_executable.display()
            );
        }
        self.write_linux_user_unit(&path, allowed_roots)?;
        command_success(
            Command::new("systemctl").args(["--user", "daemon-reload"]),
            "failed to reload the systemd user manager",
        )?;
        let running = Command::new("systemctl")
            .args(["--user", "is-active", "--quiet", "runonmine-agent.service"])
            .status()
            .context("failed to inspect the systemd user service")?
            .success();
        if running {
            command_success(
                Command::new("systemctl").args(["--user", "restart", "runonmine-agent.service"]),
                "failed to restart the systemd user service with updated roots",
            )?;
        }
        Ok(true)
    }

    #[cfg(target_os = "linux")]
    fn write_linux_user_unit(&self, path: &Path, allowed_roots: &[PathBuf]) -> Result<()> {
        let internal_paths = linux_user_internal_writable_paths()?;
        for internal_path in &internal_paths {
            ensure_private_directory(internal_path)?;
        }
        let writable_paths = linux_user_writable_paths(internal_paths, allowed_roots)?;
        let unit = render_linux_user_unit(&self.agent_executable, &writable_paths);
        write_private(path, unit.as_bytes())
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::unused_self)]
    fn uninstall_linux(&self) -> Result<()> {
        let path = service_definition_path()?.context("systemd user path is unavailable")?;
        let _ignored = Command::new("systemctl")
            .args(["--user", "disable", "--now", "runonmine-agent.service"])
            .output();
        if path.exists() {
            fs::remove_file(path)?;
        }
        command_success(
            Command::new("systemctl").args(["--user", "daemon-reload"]),
            "failed to reload the systemd user manager",
        )
    }

    #[cfg(windows)]
    fn install_windows(&self) -> Result<()> {
        let _ignored = Command::new("schtasks.exe")
            .args(["/End", "/TN", "RunOnMine Agent"])
            .output();
        let action = format!("\"{}\" run", self.agent_executable.display());
        command_success(
            Command::new("schtasks.exe").args([
                "/Create",
                "/F",
                "/SC",
                "ONLOGON",
                "/RL",
                "LIMITED",
                "/TN",
                "RunOnMine Agent",
                "/TR",
                &action,
            ]),
            "failed to create the logon scheduled task",
        )?;
        command_success(
            Command::new("powershell.exe").args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                WINDOWS_RECOVERY_COMMAND,
            ]),
            "failed to configure scheduled-task crash recovery",
        )?;
        command_success(
            Command::new("schtasks.exe").args(["/Run", "/TN", "RunOnMine Agent"]),
            "failed to restart the installed logon scheduled task",
        )
    }

    #[cfg(windows)]
    #[allow(clippy::unused_self)]
    fn uninstall_windows(&self) -> Result<()> {
        command_success(
            Command::new("schtasks.exe").args(["/Delete", "/F", "/TN", "RunOnMine Agent"]),
            "failed to remove the logon scheduled task",
        )
    }
}

fn installed_user_service_agent_path() -> Result<PathBuf> {
    let directories = ProjectDirs::from("dev", "RunOnMine", "RunOnMine")
        .context("the operating system did not provide a RunOnMine data directory")?;
    #[cfg(windows)]
    let filename = "runonmine-agent.exe";
    #[cfg(not(windows))]
    let filename = "runonmine-agent";
    Ok(directories
        .data_local_dir()
        .join("service-bin")
        .join(env!("CARGO_PKG_VERSION"))
        .join(filename))
}

fn stage_versioned_user_service_agent(source: &Path) -> Result<PathBuf> {
    let destination = installed_user_service_agent_path()?;
    stage_versioned_user_service_agent_to(source, &destination)?;
    Ok(destination)
}

fn stage_versioned_user_service_agent_to(source: &Path, destination: &Path) -> Result<()> {
    use std::io::{Read as _, Write as _};

    let source_metadata = source
        .symlink_metadata()
        .with_context(|| format!("runonmine-agent is missing at {}", source.display()))?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_file() {
        bail!("runonmine-agent source must be a regular non-symlink file");
    }
    let parent = destination
        .parent()
        .context("versioned user-service binary has no parent")?;
    ensure_user_service_directory(parent)?;
    if let Ok(metadata) = destination.symlink_metadata() {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("versioned user-service binary is not a safe regular file");
        }
        let mut source_bytes = Vec::new();
        fs::File::open(source)?.read_to_end(&mut source_bytes)?;
        let mut destination_bytes = Vec::new();
        fs::File::open(destination)?.read_to_end(&mut destination_bytes)?;
        if source_bytes != destination_bytes {
            bail!(
                "immutable user-service binary for version {} already exists with different bytes",
                env!("CARGO_PKG_VERSION")
            );
        }
        return Ok(());
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let mut source_file = fs::File::open(source)?;
    std::io::copy(&mut source_file, &mut temporary)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700))?;
    }
    temporary
        .persist_noclobber(destination)
        .map_err(|error| error.error)?;
    #[cfg(windows)]
    restrict_current_user_file(destination)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn ensure_user_service_directory(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked user-service binary directory");
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn remove_versioned_user_service_agent() -> Result<()> {
    let binary = installed_user_service_agent_path()?;
    match binary.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("refusing to remove an unsafe user-service binary")
        }
        Ok(_) => fs::remove_file(&binary)?,
    }
    if let Some(version_directory) = binary.parent() {
        let _ignored = fs::remove_dir(version_directory);
        if let Some(service_bin) = version_directory.parent() {
            let _ignored = fs::remove_dir(service_bin);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
#[allow(clippy::unnecessary_wraps)]
fn service_definition_path() -> Result<Option<PathBuf>> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let base = BaseDirs::new().context("the operating system did not provide a home directory")?;
    #[cfg(target_os = "macos")]
    return Ok(Some(
        base.home_dir()
            .join("Library/LaunchAgents/dev.runonmine.agent.plist"),
    ));
    #[cfg(target_os = "linux")]
    return Ok(Some(
        base.config_dir()
            .join("systemd/user/runonmine-agent.service"),
    ));
    #[cfg(windows)]
    return Ok(None);
    #[allow(unreachable_code)]
    Ok(None)
}

#[cfg(windows)]
fn windows_scheduled_task_running() -> Result<bool> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[int](Get-ScheduledTask -TaskName 'RunOnMine Agent').State",
        ])
        .output()
        .context("failed to query the RunOnMine scheduled task state")?;
    if !output.status.success() {
        bail!(
            "failed to query the RunOnMine scheduled task state: {}",
            bounded_command_output(&output)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "4")
}

fn command_success(command: &mut Command, context: &str) -> Result<()> {
    let output = command.output().with_context(|| context.to_owned())?;
    if output.status.success() {
        return Ok(());
    }
    bail!("{context}: {}", bounded_command_output(&output))
}

fn bounded_command_output(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let text = format!("{} {}", stdout.trim(), stderr.trim());
    text.trim().chars().take(1_000).collect()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ensure_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("service definition has no parent directory")?;
    fs::create_dir_all(parent)?;
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;

    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!(
            "refusing to replace symlinked service definition: {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .context("service definition has no parent directory")?;
    ensure_parent(path)?;
    if parent
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked service definition directory");
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
    }
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_service_log_paths() -> Result<(PathBuf, PathBuf)> {
    let directories = ProjectDirs::from("dev", "RunOnMine", "RunOnMine")
        .context("the operating system did not provide a RunOnMine data directory")?;
    let directory = directories.data_local_dir().join("logs");
    ensure_user_service_directory(&directory)?;
    Ok((
        directory.join("agent.stdout.log"),
        directory.join("agent.stderr.log"),
    ))
}

#[cfg(target_os = "macos")]
fn rotate_macos_service_logs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let (stdout, stderr) = macos_service_log_paths()?;
    for path in [stdout, stderr] {
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to use a symlinked LaunchAgent log");
        }
        if path
            .metadata()
            .is_ok_and(|metadata| metadata.len() > MACOS_SERVICE_LOG_LIMIT_BYTES)
        {
            let file = fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)?;
            file.sync_all()?;
        }
        if !path.exists() {
            let file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            file.sync_all()?;
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_service_log_summary() -> Result<String> {
    let (stdout, stderr) = macos_service_log_paths()?;
    let stdout_bytes = stdout
        .metadata()
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let stderr_bytes = stderr
        .metadata()
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    Ok(format!(
        "launchagent_logs stdout_bytes={stdout_bytes} stderr_bytes={stderr_bytes} limit_bytes={MACOS_SERVICE_LOG_LIMIT_BYTES}"
    ))
}

#[cfg(target_os = "macos")]
fn launch_domain() -> String {
    format!("gui/{}", nix::unistd::geteuid().as_raw())
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "linux")]
fn linux_user_internal_writable_paths() -> Result<Vec<PathBuf>> {
    let directories = ProjectDirs::from("dev", "RunOnMine", "RunOnMine")
        .context("the operating system did not provide RunOnMine user directories")?;
    let state = directories
        .state_dir()
        .unwrap_or_else(|| directories.data_local_dir())
        .to_path_buf();
    let mut paths = vec![
        directories.config_dir().to_path_buf(),
        state,
        directories.data_local_dir().to_path_buf(),
    ];
    paths.sort();
    paths.dedup();
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn linux_user_writable_paths(
    mut internal_paths: Vec<PathBuf>,
    allowed_roots: &[PathBuf],
) -> Result<Vec<PathBuf>> {
    for root in allowed_roots {
        if !root.is_absolute() {
            bail!("selected service roots must be absolute paths");
        }
        let canonical = fs::canonicalize(root)
            .with_context(|| format!("selected service root does not exist: {}", root.display()))?;
        if !canonical.is_dir() {
            bail!(
                "selected service root is not a directory: {}",
                canonical.display()
            );
        }
        internal_paths.push(canonical);
    }
    internal_paths.sort();
    internal_paths.dedup();
    Ok(internal_paths)
}

#[cfg(target_os = "linux")]
fn render_linux_user_unit(agent_executable: &Path, writable_paths: &[PathBuf]) -> String {
    let executable = systemd_escape(&agent_executable.to_string_lossy());
    let mut writable_directives = String::new();
    for item in writable_paths {
        writable_directives.push_str("ReadWritePaths=");
        writable_directives.push_str(&systemd_escape(&item.to_string_lossy()));
        writable_directives.push('\n');
    }
    format!(
        "[Unit]\nDescription=RunOnMine MCP Agent\nAfter=network-online.target\n\n\
         [Service]\nType=simple\nExecStart={executable} run\nRestart=on-failure\nRestartSec=3\n\
         UMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n\
         {writable_directives}\
         [Install]\nWantedBy=default.target\n"
    )
}

#[cfg(target_os = "linux")]
fn ensure_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked RunOnMine service directory");
    }
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn systemd_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod service_policy_tests {
    use super::*;

    #[test]
    fn windows_recovery_policy_restarts_crashed_tasks() {
        assert!(WINDOWS_RECOVERY_COMMAND.contains("RestartCount 3"));
        assert!(WINDOWS_RECOVERY_COMMAND.contains("RestartInterval"));
        assert!(WINDOWS_RECOVERY_COMMAND.contains("MultipleInstances IgnoreNew"));
    }
}

#[cfg(all(test, unix))]
mod private_file_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn versioned_user_service_binary_is_immutable_and_private() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("source-agent");
        let destination = temporary
            .path()
            .join("service-bin")
            .join("0.1.0-test")
            .join("runonmine-agent");
        fs::write(&source, b"agent-v1")?;
        fs::set_permissions(&source, fs::Permissions::from_mode(0o700))?;
        stage_versioned_user_service_agent_to(&source, &destination)?;
        assert_eq!(fs::read(&destination)?, b"agent-v1");
        assert_eq!(
            fs::metadata(&destination)?.permissions().mode() & 0o777,
            0o700
        );

        stage_versioned_user_service_agent_to(&source, &destination)?;
        fs::write(&source, b"different-bytes")?;
        assert!(stage_versioned_user_service_agent_to(&source, &destination).is_err());
        assert_eq!(fs::read(&destination)?, b"agent-v1");

        let link_source = temporary.path().join("source-link");
        symlink(&source, &link_source)?;
        assert!(stage_versioned_user_service_agent_to(&link_source, &destination).is_err());
        Ok(())
    }

    #[test]
    fn private_service_definition_replaces_atomically_with_owner_permissions() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let definition = temporary.path().join("agent.service");
        write_private(&definition, b"first")?;
        write_private(&definition, b"second")?;
        assert_eq!(fs::read(&definition)?, b"second");
        assert_eq!(
            fs::metadata(&definition)?.permissions().mode() & 0o777,
            0o600
        );

        let target = temporary.path().join("target");
        fs::write(&target, b"target")?;
        let link = temporary.path().join("definition-link");
        symlink(&target, &link)?;
        assert!(write_private(&link, b"blocked").is_err());
        assert_eq!(fs::read(&target)?, b"target");
        Ok(())
    }

    #[test]
    fn private_file_permissions_are_owner_only_and_symlinks_are_rejected() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let file = temporary.path().join("secret.json");
        fs::write(&file, b"secret")?;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o666))?;
        restrict_current_user_file(&file)?;
        assert_eq!(fs::metadata(&file)?.permissions().mode() & 0o777, 0o600);

        let link = temporary.path().join("secret-link.json");
        symlink(&file, &link)?;
        assert!(restrict_current_user_file(&link).is_err());
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_user_service_tests {
    use super::*;

    #[test]
    fn selected_roots_are_rendered_as_systemd_write_exceptions() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let root_with_space = temporary.path().join("project files");
        let nested = root_with_space.join("nested");
        fs::create_dir_all(&nested)?;
        let internal = vec![temporary.path().join("state")];
        fs::create_dir_all(&internal[0])?;
        let paths = linux_user_writable_paths(
            internal,
            &[
                root_with_space.clone(),
                nested.clone(),
                root_with_space.clone(),
            ],
        )?;
        let canonical_root = root_with_space.canonicalize()?;
        let canonical_nested = nested.canonicalize()?;
        assert!(paths.contains(&canonical_root));
        assert!(paths.contains(&canonical_nested));
        assert_eq!(
            paths
                .iter()
                .filter(|candidate| *candidate == &canonical_root)
                .count(),
            1
        );

        let unit = render_linux_user_unit(Path::new("/opt/RunOnMine/runonmine-agent"), &paths);
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ProtectHome=read-only"));
        assert!(unit.contains("UMask=0077"));
        assert!(unit.contains(&format!(
            "ReadWritePaths={}",
            systemd_escape(&canonical_root.to_string_lossy())
        )));
        assert!(unit.contains(&format!(
            "ReadWritePaths={}",
            systemd_escape(&canonical_nested.to_string_lossy())
        )));
        Ok(())
    }

    #[test]
    fn service_roots_must_exist_and_be_absolute_directories() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let relative = PathBuf::from("relative-root");
        assert!(linux_user_writable_paths(Vec::new(), &[relative]).is_err());
        assert!(
            linux_user_writable_paths(Vec::new(), &[temporary.path().join("missing")]).is_err()
        );
        let file = temporary.path().join("file");
        fs::write(&file, b"not a directory")?;
        assert!(linux_user_writable_paths(Vec::new(), &[file]).is_err());
        Ok(())
    }
}
