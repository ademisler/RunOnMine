use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io::Write};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::binary::{BinaryKind, InstalledBinary};
use crate::health::HealthCheck;
use crate::process::{CommandSpec, SecretValue};

const LEGACY_MACMCP_PORT: u16 = 45_799;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflaredProtocol {
    Auto,
    Quic,
    Http2,
}

impl CloudflaredProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Quic => "quic",
            Self::Http2 => "http2",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuickTunnelConfig {
    origin: Url,
    metrics_address: SocketAddr,
    protocol: CloudflaredProtocol,
}

impl QuickTunnelConfig {
    pub fn builder(origin: Url) -> QuickTunnelConfigBuilder {
        QuickTunnelConfigBuilder {
            origin,
            metrics_address: None,
            protocol: CloudflaredProtocol::Auto,
        }
    }

    pub fn command(&self, binary: &InstalledBinary) -> Result<CommandSpec> {
        require_cloudflared(binary)?;
        CommandSpec::new("cloudflare-quick-tunnel", binary.path.clone())?
            .arg("tunnel")?
            .arg("--no-autoupdate")?
            .arg("--protocol")?
            .arg(self.protocol.as_str())?
            .arg("--metrics")?
            .arg(self.metrics_address.to_string())?
            .arg("--http-host-header")?
            .arg(origin_authority(&self.origin)?)?
            .arg("--url")?
            .arg(self.origin.as_str())
    }

    pub fn health_check(&self) -> Result<HealthCheck> {
        HealthCheck::loopback_http(
            Url::parse(&format!("http://{}/ready", self.metrics_address))?,
            Duration::from_secs(2),
            vec![200],
        )
    }

    pub fn origin(&self) -> &Url {
        &self.origin
    }
}

fn origin_authority(origin: &Url) -> Result<String> {
    let host = origin
        .host_str()
        .context("Cloudflare origin host is missing")?;
    let port = origin.port().context("Cloudflare origin port is missing")?;
    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

#[derive(Clone, Debug)]
pub struct QuickTunnelConfigBuilder {
    origin: Url,
    metrics_address: Option<SocketAddr>,
    protocol: CloudflaredProtocol,
}

impl QuickTunnelConfigBuilder {
    pub fn metrics_address(mut self, address: SocketAddr) -> Self {
        self.metrics_address = Some(address);
        self
    }

    pub fn protocol(mut self, protocol: CloudflaredProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn build(self) -> Result<QuickTunnelConfig> {
        validate_loopback_origin(&self.origin)?;
        let metrics_address = self
            .metrics_address
            .context("Quick Tunnel metrics address is required")?;
        validate_runonmine_loopback(metrics_address, "Quick Tunnel metrics")?;
        Ok(QuickTunnelConfig {
            origin: self.origin,
            metrics_address,
            protocol: self.protocol,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NamedTunnelConfig {
    tunnel_id: String,
    credentials_file: PathBuf,
    hostname: String,
    origin: Url,
    metrics_address: SocketAddr,
    protocol: CloudflaredProtocol,
    config_path: PathBuf,
}

impl NamedTunnelConfig {
    pub fn builder(
        tunnel_id: impl Into<String>,
        credentials_file: PathBuf,
        hostname: impl Into<String>,
        origin: Url,
        config_path: PathBuf,
    ) -> NamedTunnelConfigBuilder {
        NamedTunnelConfigBuilder {
            tunnel_id: tunnel_id.into(),
            credentials_file,
            hostname: hostname.into(),
            origin,
            config_path,
            metrics_address: None,
            protocol: CloudflaredProtocol::Auto,
        }
    }

    pub fn render_yaml(&self) -> String {
        format!(
            "tunnel: {}\ncredentials-file: {}\nno-autoupdate: true\nprotocol: {}\nmetrics: {}\ningress:\n  - hostname: {}\n    service: {}\n  - service: http_status:404\n",
            yaml_string(&self.tunnel_id),
            yaml_string(&self.credentials_file.to_string_lossy()),
            yaml_string(self.protocol.as_str()),
            yaml_string(&self.metrics_address.to_string()),
            yaml_string(&self.hostname),
            yaml_string(self.origin.as_str()),
        )
    }

    pub fn command(&self, binary: &InstalledBinary) -> Result<CommandSpec> {
        require_cloudflared(binary)?;
        CommandSpec::new("cloudflare-named-tunnel", binary.path.clone())?
            .arg("tunnel")?
            .arg("--no-autoupdate")?
            .arg("--config")?
            .arg(self.config_path.to_string_lossy())?
            .arg("run")?
            .arg(&self.tunnel_id)
    }

    pub fn diagnostic_command(&self, binary: &InstalledBinary) -> Result<CommandSpec> {
        require_cloudflared(binary)?;
        CommandSpec::new("cloudflare-named-tunnel-diagnostic", binary.path.clone())?
            .arg("tunnel")?
            .arg("--config")?
            .arg(self.config_path.to_string_lossy())?
            .arg("diag")?
            .arg(&self.tunnel_id)
    }

    pub fn health_check(&self) -> Result<HealthCheck> {
        HealthCheck::loopback_http(
            Url::parse(&format!("http://{}/ready", self.metrics_address))?,
            Duration::from_secs(2),
            vec![200],
        )
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Writes the generated configuration with private permissions and an
    /// atomic rename. Existing symlinks are always rejected.
    pub fn write_config(&self) -> Result<()> {
        validate_absolute_config_path(&self.config_path)?;
        let parent = self
            .config_path
            .parent()
            .context("Cloudflare config path has no parent")?;
        let parent_metadata =
            fs::symlink_metadata(parent).context("Cloudflare config directory does not exist")?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            bail!("Cloudflare config directory must be a real directory");
        }
        let mut output = tempfile::NamedTempFile::new_in(parent)
            .context("failed to create private Cloudflare config")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            output
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        output.write_all(self.render_yaml().as_bytes())?;
        output.as_file().sync_all()?;
        output
            .persist(&self.config_path)
            .map_err(|error| error.error)
            .context("failed to atomically install Cloudflare config")?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct NamedTunnelConfigBuilder {
    tunnel_id: String,
    credentials_file: PathBuf,
    hostname: String,
    origin: Url,
    config_path: PathBuf,
    metrics_address: Option<SocketAddr>,
    protocol: CloudflaredProtocol,
}

impl NamedTunnelConfigBuilder {
    pub fn metrics_address(mut self, address: SocketAddr) -> Self {
        self.metrics_address = Some(address);
        self
    }

    pub fn protocol(mut self, protocol: CloudflaredProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    pub fn build(self) -> Result<NamedTunnelConfig> {
        validate_tunnel_id(&self.tunnel_id)?;
        validate_hostname(&self.hostname)?;
        validate_loopback_origin(&self.origin)?;
        validate_private_absolute_path(&self.credentials_file, "credentials file")?;
        validate_absolute_config_path(&self.config_path)?;
        let metrics_address = self
            .metrics_address
            .context("Named Tunnel metrics address is required")?;
        validate_runonmine_loopback(metrics_address, "Named Tunnel metrics")?;
        Ok(NamedTunnelConfig {
            tunnel_id: self.tunnel_id,
            credentials_file: self.credentials_file,
            hostname: self.hostname,
            origin: self.origin,
            metrics_address,
            protocol: self.protocol,
            config_path: self.config_path,
        })
    }
}

/// A remotely managed Named Tunnel. The token is passed as a redacted argument
/// and never appears in a command description or supervisor event.
pub fn remotely_managed_command(
    binary: &InstalledBinary,
    token: SecretValue,
) -> Result<CommandSpec> {
    require_cloudflared(binary)?;
    Ok(
        CommandSpec::new("cloudflare-remotely-managed-tunnel", binary.path.clone())?
            .arg("tunnel")?
            .arg("--no-autoupdate")?
            .arg("run")?
            .arg("--token")?
            .secret_arg(token),
    )
}

/// Extracts only the public `trycloudflare.com` URL printed by cloudflared.
/// Arbitrary log text, URLs with credentials, and lookalike domains are ignored.
pub fn parse_quick_tunnel_url(line: &str) -> Option<Url> {
    line.split_whitespace().find_map(|word| {
        let candidate = word.trim_matches(|character: char| {
            matches!(
                character,
                '`' | '\'' | '"' | '(' | ')' | '[' | ']' | ',' | ';'
            )
        });
        let url = Url::parse(candidate).ok()?;
        let host = url.host_str()?;
        if url.scheme() == "https"
            && host.ends_with(".trycloudflare.com")
            && host.len() > ".trycloudflare.com".len()
            && !host[..host.len() - ".trycloudflare.com".len()].contains('.')
            && url.username().is_empty()
            && url.password().is_none()
            && url.port().is_none()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
        {
            Some(url)
        } else {
            None
        }
    })
}

fn require_cloudflared(binary: &InstalledBinary) -> Result<()> {
    if binary.kind != BinaryKind::Cloudflared {
        bail!("Cloudflare connector requires a cloudflared binary");
    }
    Ok(())
}

fn validate_loopback_origin(url: &Url) -> Result<()> {
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("Cloudflare origin must be a credential-free loopback HTTP URL");
    }
    let loopback = match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(_)) | None => false,
    };
    if !loopback || url.port().is_none() {
        bail!("Cloudflare origin must use an explicit loopback IP and port");
    }
    if url.port() == Some(LEGACY_MACMCP_PORT) {
        bail!("port 45799 is reserved for the existing MacMCP installation");
    }
    Ok(())
}

fn validate_runonmine_loopback(address: SocketAddr, label: &str) -> Result<()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        bail!("{label} address must use a non-zero loopback port");
    }
    if address.port() == LEGACY_MACMCP_PORT {
        bail!("port 45799 is reserved for the existing MacMCP installation");
    }
    Ok(())
}

fn validate_tunnel_id(value: &str) -> Result<()> {
    let segments = [8_usize, 4, 4, 4, 12];
    let valid = value.split('-').zip(segments).all(|(segment, length)| {
        segment.len() == length && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) && value.split('-').count() == segments.len();
    if !valid {
        bail!("Cloudflare tunnel ID must be a UUID");
    }
    Ok(())
}

fn validate_hostname(hostname: &str) -> Result<()> {
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.ends_with('.')
        || hostname.split('.').count() < 2
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        bail!("Cloudflare hostname is invalid");
    }
    Ok(())
}

fn validate_private_absolute_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("Cloudflare {label} must use an absolute path");
    }
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("Cloudflare {label} does not exist"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("Cloudflare {label} must be a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            bail!("Cloudflare {label} must not be accessible by group or other users");
        }
    }
    Ok(())
}

fn validate_absolute_config_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("Cloudflare config path must be absolute");
    }
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("Cloudflare config path must be a regular non-symlink file");
        }
    }
    Ok(())
}

fn yaml_string(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn quick_url_parser_rejects_lookalikes() -> Result<()> {
        let url = parse_quick_tunnel_url(
            "INF Your quick Tunnel has been created! https://quiet-bird.trycloudflare.com",
        )
        .context("valid Quick Tunnel URL was not parsed")?;
        assert_eq!(url.host_str(), Some("quiet-bird.trycloudflare.com"));
        assert!(parse_quick_tunnel_url("https://trycloudflare.com.evil.example").is_none());
        assert!(parse_quick_tunnel_url("https://a.b.trycloudflare.com").is_none());
        assert!(parse_quick_tunnel_url("http://quiet-bird.trycloudflare.com").is_none());
        assert!(parse_quick_tunnel_url("https://quiet-bird.trycloudflare.com/mcp").is_none());
        Ok(())
    }

    #[test]
    fn quick_config_rejects_legacy_macmcp_port() -> Result<()> {
        let config = QuickTunnelConfig::builder(Url::parse("http://127.0.0.1:45799/mcp")?)
            .metrics_address("127.0.0.1:47822".parse()?)
            .build();
        assert!(config.is_err());
        Ok(())
    }

    #[test]
    fn named_config_is_closed_with_a_404_fallback() -> Result<()> {
        let directory = tempdir()?;
        let credentials = directory.path().join("credentials.json");
        fs::write(&credentials, "{}")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&credentials, fs::Permissions::from_mode(0o600))?;
        }
        let config = NamedTunnelConfig::builder(
            "11111111-2222-3333-4444-555555555555",
            credentials,
            "mine.example.com",
            Url::parse("http://127.0.0.1:47821/mcp")?,
            directory.path().join("cloudflared.yml"),
        )
        .metrics_address("127.0.0.1:47822".parse()?)
        .build()?;
        let yaml = config.render_yaml();
        assert!(yaml.contains("service: http_status:404"));
        assert!(yaml.contains("127.0.0.1:47821/mcp"));
        Ok(())
    }
}
