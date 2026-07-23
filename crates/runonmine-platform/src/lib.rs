//! Operating-system capability detection and service integration.

pub mod desktop;
pub mod helper;
pub mod native;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::fs;
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::path::Path;
use std::path::PathBuf;
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use directories::BaseDirs;
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
                detail: sanitized_output(&output),
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
        let uid = account_number("-u", run_as_user)?;
        if uid == 0 {
            bail!("the headless system service must not run as root");
        }
        let home = account_home(run_as_user)?;
        let install_directory = Path::new(LINUX_SYSTEM_BINARY_PATH)
            .parent()
            .context("system agent path has no parent")?;
        fs::create_dir_all(install_directory)?;
        reject_symlink(install_directory, "system binary directory")?;
        atomic_copy_executable(&self.agent_executable, Path::new(LINUX_SYSTEM_BINARY_PATH))?;

        let home_environment = systemd_escape(&format!("HOME={}", home.display()));
        let xdg_config = systemd_escape(&format!("XDG_CONFIG_HOME={}/.config", home.display()));
        let xdg_data = systemd_escape(&format!("XDG_DATA_HOME={}/.local/share", home.display()));
        let unit = format!(
            "[Unit]\nDescription=RunOnMine headless MCP agent\nAfter=network-online.target\nWants=network-online.target\n\n\
             [Service]\nType=simple\nUser={run_as_user}\nExecStart={LINUX_SYSTEM_BINARY_PATH} run\n\
             WorkingDirectory={}\nEnvironment={home_environment}\nEnvironment={xdg_config}\nEnvironment={xdg_data}\n\
             Restart=on-failure\nRestartSec=3\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\n\
             PrivateDevices=true\nProtectSystem=full\nProtectKernelTunables=true\nProtectKernelModules=true\n\
             ProtectControlGroups=true\nRestrictSUIDSGID=true\nLockPersonality=true\nRestrictRealtime=true\n\
             SystemCallArchitectures=native\n\n[Install]\nWantedBy=multi-user.target\n",
            systemd_escape(&home.to_string_lossy())
        );
        atomic_write_mode(Path::new(LINUX_SYSTEM_UNIT_PATH), unit.as_bytes(), 0o644)?;
        linux_systemctl(&["daemon-reload"], "failed to reload systemd")?;
        linux_systemctl(
            &["enable", "--now", LINUX_SYSTEM_SERVICE],
            "failed to enable the system service",
        )
    }

    #[cfg(target_os = "linux")]
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
    if account_number("-u", "")? != 0 {
        bail!("system service installation and removal must be run as root");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn account_number(flag: &str, user: &str) -> Result<u32> {
    let mut command = Command::new("id");
    command.arg(flag);
    if !user.is_empty() {
        command.arg(user);
    }
    let output = command.output()?;
    if !output.status.success() {
        bail!("the requested service account does not exist");
    }
    let value = String::from_utf8(output.stdout)?;
    value
        .trim()
        .parse::<u32>()
        .context("the service account id is invalid")
}

#[cfg(target_os = "linux")]
fn account_home(user: &str) -> Result<PathBuf> {
    let output = Command::new("getent").args(["passwd", user]).output()?;
    if !output.status.success() {
        bail!("the requested service account has no passwd entry");
    }
    let record = String::from_utf8(output.stdout)?;
    let home = record
        .trim_end()
        .split(':')
        .nth(5)
        .filter(|value| !value.is_empty())
        .context("the service account has no home directory")?;
    let path = PathBuf::from(home);
    if !path.is_absolute() || home.contains(['\n', '\r', '\0']) {
        bail!("the service account home directory is invalid");
    }
    Ok(path)
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

    pub fn install(&self) -> Result<()> {
        if !self.agent_executable.is_file() {
            bail!(
                "runonmine-agent was not found beside the CLI at {}",
                self.agent_executable.display()
            );
        }
        #[cfg(target_os = "macos")]
        {
            self.install_macos()
        }
        #[cfg(target_os = "linux")]
        {
            self.install_linux()
        }
        #[cfg(windows)]
        {
            self.install_windows()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            bail!("service installation is unsupported on this operating system")
        }
    }

    pub fn uninstall(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.uninstall_macos()
        }
        #[cfg(target_os = "linux")]
        {
            self.uninstall_linux()
        }
        #[cfg(windows)]
        {
            self.uninstall_windows()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        {
            bail!("service removal is unsupported on this operating system")
        }
    }

    pub fn start(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            command_success(
                Command::new("launchctl").args([
                    "kickstart",
                    "-k",
                    &format!("{}/dev.runonmine.agent", launch_domain()?),
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

    pub fn stop(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            command_success(
                Command::new("launchctl").args([
                    "kill",
                    "SIGTERM",
                    &format!("{}/dev.runonmine.agent", launch_domain()?),
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
            .args([
                "print",
                &format!("{}/dev.runonmine.agent", launch_domain()?),
            ])
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
        Ok(ServiceStatus {
            installed,
            running: output.status.success(),
            detail: sanitized_output(&output),
        })
    }

    #[cfg(target_os = "macos")]
    fn install_macos(&self) -> Result<()> {
        let path = service_definition_path()?.context("LaunchAgent path is unavailable")?;
        ensure_parent(&path)?;
        let executable = xml_escape(&self.agent_executable.to_string_lossy());
        let plist = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\"><dict>\n\
             <key>Label</key><string>dev.runonmine.agent</string>\n\
             <key>ProgramArguments</key><array><string>{executable}</string><string>run</string></array>\n\
             <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n\
             <key>ProcessType</key><string>Interactive</string>\n\
             </dict></plist>\n"
        );
        write_private(&path, plist.as_bytes())?;
        let domain = launch_domain()?;
        let _ignored = Command::new("launchctl")
            .args(["bootout", &domain, path.to_string_lossy().as_ref()])
            .output();
        command_success(
            Command::new("launchctl").args(["bootstrap", &domain, path.to_string_lossy().as_ref()]),
            "failed to install the LaunchAgent",
        )
    }

    #[cfg(target_os = "macos")]
    #[allow(clippy::unused_self)]
    fn uninstall_macos(&self) -> Result<()> {
        let path = service_definition_path()?.context("LaunchAgent path is unavailable")?;
        if path.exists() {
            let domain = launch_domain()?;
            let _ignored = Command::new("launchctl")
                .args(["bootout", &domain, path.to_string_lossy().as_ref()])
                .output();
            fs::remove_file(path)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn install_linux(&self) -> Result<()> {
        let path = service_definition_path()?.context("systemd user path is unavailable")?;
        ensure_parent(&path)?;
        let executable = systemd_escape(&self.agent_executable.to_string_lossy());
        let unit = format!(
            "[Unit]\nDescription=RunOnMine MCP Agent\nAfter=network-online.target\n\n\
             [Service]\nType=simple\nExecStart={executable} run\nRestart=on-failure\nRestartSec=3\n\
             NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=read-only\n\
             [Install]\nWantedBy=default.target\n"
        );
        write_private(&path, unit.as_bytes())?;
        command_success(
            Command::new("systemctl").args(["--user", "daemon-reload"]),
            "failed to reload the systemd user manager",
        )?;
        command_success(
            Command::new("systemctl").args([
                "--user",
                "enable",
                "--now",
                "runonmine-agent.service",
            ]),
            "failed to enable the systemd user service",
        )
    }

    #[cfg(target_os = "linux")]
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

fn command_success(command: &mut Command, context: &str) -> Result<()> {
    let output = command.output().with_context(|| context.to_owned())?;
    if output.status.success() {
        return Ok(());
    }
    bail!("{context}: {}", sanitized_output(&output))
}

fn sanitized_output(output: &Output) -> String {
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
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!(
            "refusing to replace symlinked service definition: {}",
            path.display()
        );
    }
    fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn launch_domain() -> Result<String> {
    let output = Command::new("id").arg("-u").output()?;
    if !output.status.success() {
        bail!("failed to determine the current user id");
    }
    let uid = String::from_utf8(output.stdout)?.trim().to_owned();
    if uid.is_empty() || !uid.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid current user id");
    }
    Ok(format!("gui/{uid}"))
}

#[cfg(target_os = "macos")]
fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(target_os = "linux")]
fn systemd_escape(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
