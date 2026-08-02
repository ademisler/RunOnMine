use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::binary::{BinaryKind, InstalledBinary, validate_profile};
use crate::health::HealthCheck;
use crate::process::{CommandSpec, SecretValue};

const LEGACY_MACMCP_PORT: u16 = 45_799;
const RUNTIME_KEY_ENVIRONMENT: &str = "CONTROL_PLANE_API_KEY";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "snake_case")]
pub enum OpenAiMcpTarget {
    Stdio {
        executable: PathBuf,
        args: Vec<String>,
    },
    Http {
        url: Url,
    },
}

impl OpenAiMcpTarget {
    pub fn runonmine_stdio(
        runonmine_executable: PathBuf,
        connector_id: impl Into<String>,
    ) -> Result<Self> {
        validate_absolute_executable_path(&runonmine_executable)?;
        let connector_id = connector_id.into();
        validate_connector_id(&connector_id)?;
        Ok(Self::Stdio {
            executable: runonmine_executable,
            args: vec![
                "mcp".to_owned(),
                "stdio".to_owned(),
                "--connector".to_owned(),
                connector_id,
            ],
        })
    }

    pub fn loopback_http(url: Url) -> Result<Self> {
        validate_loopback_mcp_url(&url)?;
        Ok(Self::Http { url })
    }

    fn sample(&self) -> &'static str {
        match self {
            Self::Stdio { .. } => "sample_mcp_stdio_local",
            Self::Http { .. } => "sample_mcp_with_dcr",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenAiTunnelProfile {
    profile: String,
    tunnel_id: String,
    target: OpenAiMcpTarget,
    profile_directory: PathBuf,
    health_address: SocketAddr,
    health_url_file: PathBuf,
}

impl OpenAiTunnelProfile {
    pub fn builder(
        profile: impl Into<String>,
        tunnel_id: impl Into<String>,
        target: OpenAiMcpTarget,
    ) -> OpenAiTunnelProfileBuilder {
        OpenAiTunnelProfileBuilder {
            profile: profile.into(),
            tunnel_id: tunnel_id.into(),
            target,
            profile_directory: None,
            health_address: None,
            health_url_file: None,
        }
    }

    pub fn init_command(&self, binary: &InstalledBinary) -> Result<CommandSpec> {
        require_tunnel_client(binary)?;
        let mut command = CommandSpec::new("openai-tunnel-profile-init", binary.path.clone())?
            .arg("init")?
            .arg("--sample")?
            .arg(self.target.sample())?
            .arg("--profile")?
            .arg(&self.profile)?
            .arg("--profile-dir")?
            .arg(self.profile_directory.to_string_lossy())?
            .arg("--tunnel-id")?
            .arg(&self.tunnel_id)?;
        command = match &self.target {
            OpenAiMcpTarget::Stdio { executable, args } => command
                .arg("--mcp-command")?
                .arg(render_stdio_command(executable, args))?,
            OpenAiMcpTarget::Http { url } => command.arg("--mcp-server-url")?.arg(url.as_str())?,
        };
        Ok(command)
    }

    pub fn doctor_command(
        &self,
        binary: &InstalledBinary,
        runtime_api_key: SecretValue,
    ) -> Result<CommandSpec> {
        require_tunnel_client(binary)?;
        CommandSpec::new("openai-tunnel-doctor", binary.path.clone())?
            .arg("doctor")?
            .arg("--profile")?
            .arg(&self.profile)?
            .arg("--profile-dir")?
            .arg(self.profile_directory.to_string_lossy())?
            .arg("--explain")?
            .secret_env(RUNTIME_KEY_ENVIRONMENT, runtime_api_key)
    }

    pub fn run_command(
        &self,
        binary: &InstalledBinary,
        runtime_api_key: SecretValue,
    ) -> Result<CommandSpec> {
        require_tunnel_client(binary)?;
        CommandSpec::new("openai-secure-mcp-tunnel", binary.path.clone())?
            .arg("run")?
            .arg("--profile")?
            .arg(&self.profile)?
            .arg("--profile-dir")?
            .arg(self.profile_directory.to_string_lossy())?
            .arg("--health.listen-addr")?
            .arg(self.health_address.to_string())?
            .arg("--health.url-file")?
            .arg(self.health_url_file.to_string_lossy())?
            .arg("--log.format=struct-text")?
            .secret_env(RUNTIME_KEY_ENVIRONMENT, runtime_api_key)
    }

    pub fn liveness_check(&self) -> Result<HealthCheck> {
        self.health_check("healthz")
    }

    pub fn readiness_check(&self) -> Result<HealthCheck> {
        self.health_check("readyz")
    }

    pub fn admin_ui_url(&self) -> Result<Url> {
        Url::parse(&format!("http://{}/ui", self.health_address))
            .context("failed to construct OpenAI tunnel-client admin URL")
    }

    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn tunnel_id(&self) -> &str {
        &self.tunnel_id
    }

    pub fn profile_directory(&self) -> &Path {
        &self.profile_directory
    }

    pub fn health_url_file(&self) -> &Path {
        &self.health_url_file
    }

    fn health_check(&self, endpoint: &str) -> Result<HealthCheck> {
        HealthCheck::loopback_http(
            Url::parse(&format!("http://{}/{endpoint}", self.health_address))?,
            Duration::from_secs(2),
            vec![200],
        )
    }
}

#[derive(Clone, Debug)]
pub struct OpenAiTunnelProfileBuilder {
    profile: String,
    tunnel_id: String,
    target: OpenAiMcpTarget,
    profile_directory: Option<PathBuf>,
    health_address: Option<SocketAddr>,
    health_url_file: Option<PathBuf>,
}

impl OpenAiTunnelProfileBuilder {
    pub fn profile_directory(mut self, path: PathBuf) -> Self {
        self.profile_directory = Some(path);
        self
    }

    pub fn health_address(mut self, address: SocketAddr) -> Self {
        self.health_address = Some(address);
        self
    }

    pub fn health_url_file(mut self, path: PathBuf) -> Self {
        self.health_url_file = Some(path);
        self
    }

    pub fn build(self) -> Result<OpenAiTunnelProfile> {
        validate_profile(&self.profile)?;
        validate_tunnel_id(&self.tunnel_id)?;
        match &self.target {
            OpenAiMcpTarget::Stdio { executable, args } => {
                validate_absolute_executable_path(executable)?;
                if args.iter().any(|argument| argument.contains('\0')) {
                    bail!("OpenAI stdio command arguments must not contain NUL bytes");
                }
            }
            OpenAiMcpTarget::Http { url } => validate_loopback_mcp_url(url)?,
        }
        let profile_directory = self
            .profile_directory
            .context("OpenAI tunnel-client profile directory is required")?;
        validate_private_directory(&profile_directory, "profile directory")?;
        let health_address = self
            .health_address
            .context("OpenAI tunnel-client health address is required")?;
        if !health_address.ip().is_loopback()
            || health_address.port() == 0
            || health_address.port() == LEGACY_MACMCP_PORT
        {
            bail!("OpenAI tunnel-client health address must use a non-reserved loopback port");
        }
        let health_url_file = self
            .health_url_file
            .context("OpenAI tunnel-client health URL file is required")?;
        validate_health_url_file(&health_url_file)?;
        Ok(OpenAiTunnelProfile {
            profile: self.profile,
            tunnel_id: self.tunnel_id,
            target: self.target,
            profile_directory,
            health_address,
            health_url_file,
        })
    }
}

fn require_tunnel_client(binary: &InstalledBinary) -> Result<()> {
    if binary.kind != BinaryKind::OpenAiTunnelClient {
        bail!("OpenAI connector requires a tunnel-client binary");
    }
    Ok(())
}

fn validate_tunnel_id(value: &str) -> Result<()> {
    let Some(identifier) = value.strip_prefix("tunnel_") else {
        bail!("OpenAI tunnel ID must start with tunnel_");
    };
    if identifier.len() != 32
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("OpenAI tunnel ID must contain exactly 32 lowercase hexadecimal characters");
    }
    Ok(())
}

fn validate_connector_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        bail!("connector ID contains unsupported characters");
    }
    Ok(())
}

fn validate_absolute_executable_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("OpenAI stdio executable must use an absolute path");
    }
    if path.to_string_lossy().contains('\0') {
        bail!("OpenAI stdio executable path contains a NUL byte");
    }
    Ok(())
}

fn validate_loopback_mcp_url(url: &Url) -> Result<()> {
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("RunOnMine MCP URL must be a credential-free loopback HTTP URL");
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    };
    if !loopback
        || url.port().is_none_or(|port| port == 0)
        || url.port() == Some(LEGACY_MACMCP_PORT)
    {
        bail!("RunOnMine MCP URL must use a non-reserved explicit non-zero loopback port");
    }
    Ok(())
}

fn validate_health_url_file(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("OpenAI health URL file must use an absolute path");
    }
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("OpenAI health URL file must be a regular non-symlink file");
        }
    }
    let parent = path
        .parent()
        .context("OpenAI health URL file has no parent directory")?;
    let metadata = std::fs::symlink_metadata(parent)
        .context("OpenAI health URL file directory does not exist")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("OpenAI health URL file directory must be a real directory");
    }
    Ok(())
}

fn validate_private_directory(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("OpenAI {label} must use an absolute path");
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("OpenAI {label} does not exist"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("OpenAI {label} must be a real directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("OpenAI {label} must not be accessible by group or other users");
        }
    }
    Ok(())
}

fn render_stdio_command(executable: &Path, args: &[String]) -> String {
    std::iter::once(executable.to_string_lossy().into_owned())
        .chain(args.iter().cloned())
        .map(|argument| quote_command_argument(&argument))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(not(windows))]
fn quote_command_argument(argument: &str) -> String {
    if !argument.is_empty()
        && argument
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_+-./:=@".contains(character))
    {
        argument.to_owned()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

#[cfg(windows)]
fn quote_command_argument(argument: &str) -> String {
    if !argument.is_empty()
        && !argument
            .chars()
            .any(|character| character.is_whitespace() || character == '"')
    {
        return argument.to_owned();
    }
    let mut quoted = String::from("\"");
    let mut backslashes = 0_usize;
    for character in argument.chars() {
        if character == '\\' {
            backslashes = backslashes.saturating_add(1);
        } else {
            if character == '"' {
                quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2).saturating_add(1)));
            } else {
                quoted.push_str(&"\\".repeat(backslashes));
            }
            backslashes = 0;
            quoted.push(character);
        }
    }
    quoted.push_str(&"\\".repeat(backslashes.saturating_mul(2)));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use tempfile::tempdir;

    fn connector_port_strategy() -> impl Strategy<Value = u16> {
        (1_u16..=u16::MAX).prop_filter("reserved MacMCP port", |port| *port != LEGACY_MACMCP_PORT)
    }

    fn test_executable() -> Result<PathBuf> {
        Ok(std::env::current_exe()?)
    }

    #[cfg(unix)]
    fn restrict_test_directory(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    #[cfg(not(unix))]
    #[expect(
        clippy::unnecessary_wraps,
        reason = "Unix test-directory mode hardening is intentionally a no-op on Windows"
    )]
    fn restrict_test_directory(_path: &Path) -> Result<()> {
        Ok(())
    }

    #[test]
    fn tunnel_id_validation_is_strict() {
        assert!(validate_tunnel_id("tunnel_0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_tunnel_id("0123456789abcdef0123456789abcdef").is_err());
        assert!(validate_tunnel_id("tunnel_0123456789ABCDEF0123456789ABCDEF").is_err());
    }

    #[test]
    fn stdio_renderer_quotes_paths_without_changing_arguments() {
        let rendered = render_stdio_command(
            Path::new("/Applications/Run On Mine/runonmine"),
            &[
                "mcp".to_owned(),
                "stdio".to_owned(),
                "connector value".to_owned(),
            ],
        );
        #[cfg(not(windows))]
        assert_eq!(
            rendered,
            "'/Applications/Run On Mine/runonmine' mcp stdio 'connector value'"
        );
        #[cfg(windows)]
        assert!(rendered.contains("\"/Applications/Run On Mine/runonmine\""));
    }

    #[test]
    fn loopback_mcp_url_rejects_zero_port() -> Result<()> {
        assert!(validate_loopback_mcp_url(&Url::parse("http://127.0.0.1:0/mcp")?).is_err());
        Ok(())
    }

    #[test]
    fn profile_health_surfaces_are_loopback_only() -> Result<()> {
        let directory = tempdir()?;
        restrict_test_directory(directory.path())?;
        let profile = OpenAiTunnelProfile::builder(
            "local-stdio",
            "tunnel_0123456789abcdef0123456789abcdef",
            OpenAiMcpTarget::Stdio {
                executable: test_executable()?,
                args: vec!["mcp".to_owned(), "stdio".to_owned()],
            },
        )
        .profile_directory(directory.path().to_path_buf())
        .health_address("127.0.0.1:47823".parse()?)
        .health_url_file(directory.path().join("tunnel-health.url"))
        .build()?;
        assert_eq!(
            profile.admin_ui_url()?.as_str(),
            "http://127.0.0.1:47823/ui"
        );
        Ok(())
    }

    #[test]
    fn profile_rejects_legacy_macmcp_port() -> Result<()> {
        let directory = tempdir()?;
        restrict_test_directory(directory.path())?;
        let result = OpenAiTunnelProfile::builder(
            "local-stdio",
            "tunnel_0123456789abcdef0123456789abcdef",
            OpenAiMcpTarget::Stdio {
                executable: PathBuf::from("/opt/runonmine/bin/runonmine"),
                args: Vec::new(),
            },
        )
        .profile_directory(directory.path().to_path_buf())
        .health_address("127.0.0.1:45799".parse()?)
        .health_url_file(directory.path().join("tunnel-health.url"))
        .build();
        assert!(result.is_err());
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn generated_openai_loopback_mcp_urls_are_accepted(
            second in any::<u8>(),
            third in any::<u8>(),
            fourth in any::<u8>(),
            port in connector_port_strategy(),
            path in "[a-z][a-z0-9_-]{0,20}",
        ) {
            let url = Url::parse(&format!(
                "http://127.{second}.{third}.{fourth}:{port}/{path}"
            ))?;
            prop_assert!(validate_loopback_mcp_url(&url).is_ok());
        }

        #[test]
        fn malformed_openai_mcp_urls_are_rejected(
            port in connector_port_strategy(),
            variant in 0_u8..10,
        ) {
            let value = match variant {
                0 => format!("https://127.0.0.1:{port}/mcp"),
                1 => format!("http://localhost:{port}/mcp"),
                2 => format!("http://172.16.0.10:{port}/mcp"),
                3 => format!("http://user@127.0.0.1:{port}/mcp"),
                4 => format!("http://user:secret@127.0.0.1:{port}/mcp"),
                5 => format!("http://127.0.0.1:{port}/mcp?token=value"),
                6 => format!("http://127.0.0.1:{port}/mcp#fragment"),
                7 => "http://127.0.0.1/mcp".to_owned(),
                8 => "http://127.0.0.1:0/mcp".to_owned(),
                _ => format!("http://127.0.0.1:{LEGACY_MACMCP_PORT}/mcp"),
            };
            let url = Url::parse(&value)?;
            prop_assert!(validate_loopback_mcp_url(&url).is_err(), "accepted {value}");
        }
    }
}
