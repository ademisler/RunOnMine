use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{fs, io::Write};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::{Host, Url};

use crate::binary::{BinaryKind, InstalledBinary};
use crate::health::HealthCheck;
use crate::process::{CommandSpec, SecretValue};

const QUICK_TUNNEL_METRICS_MAX_BYTES: usize = 256 * 1_024;
const QUICK_TUNNEL_METRICS_TIMEOUT: Duration = Duration::from_secs(2);

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

    pub fn metrics_address(&self) -> SocketAddr {
        self.metrics_address
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
            yaml_string(&self.origin.origin().ascii_serialization()),
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
        validate_named_tunnel_origin(&self.origin)?;
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
        validated_quick_tunnel_url(candidate)
    })
}

/// Recovers the Quick Tunnel public URL from cloudflared's loopback-only metrics endpoint.
/// This is a bounded fallback for the one-shot startup log line used by the normal observer.
pub async fn discover_quick_tunnel_url_from_metrics(
    metrics_address: SocketAddr,
) -> Result<Option<Url>> {
    validate_runonmine_loopback(metrics_address, "Quick Tunnel metrics")?;
    let response = tokio::time::timeout(QUICK_TUNNEL_METRICS_TIMEOUT, async move {
        let mut stream = tokio::net::TcpStream::connect(metrics_address)
            .await
            .context("failed to connect to Quick Tunnel metrics")?;
        let request = format!(
            "GET /metrics HTTP/1.0\r\nHost: {metrics_address}\r\nConnection: close\r\n\r\n"
        );
        stream
            .write_all(request.as_bytes())
            .await
            .context("failed to request Quick Tunnel metrics")?;
        let mut response = Vec::with_capacity(16 * 1_024);
        let mut chunk = [0_u8; 8 * 1_024];
        loop {
            let count = stream
                .read(&mut chunk)
                .await
                .context("failed to read Quick Tunnel metrics")?;
            if count == 0 {
                break;
            }
            if response.len().saturating_add(count) > QUICK_TUNNEL_METRICS_MAX_BYTES {
                bail!("Quick Tunnel metrics response exceeds the size limit");
            }
            response.extend_from_slice(&chunk[..count]);
        }
        Ok::<Vec<u8>, anyhow::Error>(response)
    })
    .await
    .context("Quick Tunnel metrics request timed out")??;

    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("Quick Tunnel metrics response is malformed")?;
    let headers = std::str::from_utf8(&response[..split])
        .context("Quick Tunnel metrics headers are not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .context("Quick Tunnel metrics status line is missing")?;
    if !(status.starts_with("HTTP/1.0 200 ") || status.starts_with("HTTP/1.1 200 ")) {
        bail!("Quick Tunnel metrics endpoint returned a non-success status");
    }
    let body = std::str::from_utf8(&response[split + 4..])
        .context("Quick Tunnel metrics body is not UTF-8")?;
    Ok(parse_quick_tunnel_metrics(body))
}

fn parse_quick_tunnel_metrics(metrics: &str) -> Option<Url> {
    const METRIC: &str = "cloudflared_tunnel_user_hostnames_counts{";
    const LABEL: &str = "userHostname=\"";
    metrics.lines().find_map(|line| {
        if !line.starts_with(METRIC) {
            return None;
        }
        let start = line.find(LABEL)? + LABEL.len();
        let tail = &line[start..];
        let end = tail.find('\"')?;
        validated_quick_tunnel_url(&tail[..end])
    })
}

fn validated_quick_tunnel_url(candidate: &str) -> Option<Url> {
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
    if !loopback || url.port().is_none_or(|port| port == 0) {
        bail!("Cloudflare origin must use an explicit loopback IP and non-zero port");
    }
    Ok(())
}

fn validate_named_tunnel_origin(url: &Url) -> Result<()> {
    validate_loopback_origin(url)?;
    if url.path() != "/" {
        bail!("Cloudflare Named Tunnel origin must not contain a path");
    }
    Ok(())
}

fn validate_runonmine_loopback(address: SocketAddr, label: &str) -> Result<()> {
    if !address.ip().is_loopback() || address.port() == 0 {
        bail!("{label} address must use a non-zero loopback port");
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
    use proptest::prelude::*;
    use std::fs;
    use tempfile::tempdir;

    fn connector_port_strategy() -> impl Strategy<Value = u16> {
        1_u16..=u16::MAX
    }

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
    fn quick_metrics_parser_rejects_lookalikes() -> Result<()> {
        let valid = parse_quick_tunnel_metrics(
            r#"cloudflared_tunnel_user_hostnames_counts{userHostname="https://metrics-recovery.trycloudflare.com"} 1"#,
        )
        .context("valid Quick Tunnel metrics hostname was not parsed")?;
        assert_eq!(
            valid,
            Url::parse("https://metrics-recovery.trycloudflare.com/")?
        );
        for value in [
            r#"cloudflared_tunnel_user_hostnames_counts{userHostname="https://a.b.trycloudflare.com"} 1"#,
            r#"cloudflared_tunnel_user_hostnames_counts{userHostname="http://metrics-recovery.trycloudflare.com"} 1"#,
            r#"cloudflared_tunnel_user_hostnames_counts{userHostname="https://metrics-recovery.trycloudflare.com/path"} 1"#,
            r#"cloudflared_tunnel_user_hostnames_counts{userHostname="https://metrics-recovery.trycloudflare.com.evil.example"} 1"#,
            r#"unrelated_metric{userHostname="https://metrics-recovery.trycloudflare.com"} 1"#,
        ] {
            assert!(
                parse_quick_tunnel_metrics(value).is_none(),
                "accepted {value}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn quick_metrics_probe_is_loopback_bounded_and_parses_hostname() -> Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4 * 1_024];
            let count = stream.read(&mut request).await?;
            let request = std::str::from_utf8(&request[..count])?;
            assert!(request.starts_with("GET /metrics HTTP/1.0\r\n"));
            let body = concat!(
                "# HELP cloudflared_tunnel_user_hostnames_counts Which user hostnames cloudflared is serving\n",
                "cloudflared_tunnel_user_hostnames_counts{userHostname=\"https://metrics-probe.trycloudflare.com\"} 1\n",
            );
            let response = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await?;
            stream.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        });

        let discovered = discover_quick_tunnel_url_from_metrics(address)
            .await?
            .context("Quick Tunnel metrics fallback returned no hostname")?;
        assert_eq!(
            discovered,
            Url::parse("https://metrics-probe.trycloudflare.com/")?
        );
        server.await??;
        assert!(
            discover_quick_tunnel_url_from_metrics("192.168.10.20:47822".parse()?)
                .await
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn quick_metrics_probe_rejects_oversized_response() -> Result<()> {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0_u8; 4 * 1_024];
            let _count = stream.read(&mut request).await?;
            let body = vec![b'x'; QUICK_TUNNEL_METRICS_MAX_BYTES + 8 * 1_024];
            let header = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).await?;
            let _ignored = stream.write_all(&body).await;
            Ok::<(), anyhow::Error>(())
        });

        let result = discover_quick_tunnel_url_from_metrics(address).await;
        assert!(result.is_err());
        server.await??;
        Ok(())
    }

    #[test]
    fn loopback_origin_rejects_zero_port() -> Result<()> {
        assert!(validate_loopback_origin(&Url::parse("http://127.0.0.1:0/mcp")?).is_err());
        Ok(())
    }

    #[test]
    fn quick_config_accepts_arbitrary_nonzero_loopback_port() -> Result<()> {
        let config = QuickTunnelConfig::builder(Url::parse("http://127.0.0.1:49152/mcp")?)
            .metrics_address("127.0.0.1:47822".parse()?)
            .build();
        assert!(config.is_ok());
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
            credentials.clone(),
            "mine.example.com",
            Url::parse("http://127.0.0.1:47821/")?,
            directory.path().join("cloudflared.yml"),
        )
        .metrics_address("127.0.0.1:47822".parse()?)
        .build()?;
        let yaml = config.render_yaml();
        assert!(yaml.contains("service: http_status:404"));
        assert!(yaml.contains("service: \"http://127.0.0.1:47821\""));
        assert!(!yaml.contains("127.0.0.1:47821/mcp"));

        let with_path = NamedTunnelConfig::builder(
            "11111111-2222-3333-4444-555555555555",
            credentials,
            "mine.example.com",
            Url::parse("http://127.0.0.1:47821/mcp")?,
            directory.path().join("cloudflared-path.yml"),
        )
        .metrics_address("127.0.0.1:47823".parse()?)
        .build();
        assert!(with_path.is_err());
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn generated_cloudflare_loopback_origins_are_accepted(
            second in any::<u8>(),
            third in any::<u8>(),
            fourth in any::<u8>(),
            port in connector_port_strategy(),
            path in "[a-z][a-z0-9_-]{0,20}",
        ) {
            let url = Url::parse(&format!(
                "http://127.{second}.{third}.{fourth}:{port}/{path}"
            ))?;
            prop_assert!(validate_loopback_origin(&url).is_ok());
        }

        #[test]
        fn malformed_cloudflare_origins_are_rejected(
            port in connector_port_strategy(),
            variant in 0_u8..9,
        ) {
            let value = match variant {
                0 => format!("https://127.0.0.1:{port}/mcp"),
                1 => format!("http://localhost:{port}/mcp"),
                2 => format!("http://192.168.1.10:{port}/mcp"),
                3 => format!("http://user@127.0.0.1:{port}/mcp"),
                4 => format!("http://user:secret@127.0.0.1:{port}/mcp"),
                5 => format!("http://127.0.0.1:{port}/mcp?token=value"),
                6 => format!("http://127.0.0.1:{port}/mcp#fragment"),
                7 => "http://127.0.0.1/mcp".to_owned(),
                _ => "http://127.0.0.1:0/mcp".to_owned(),
            };
            let url = Url::parse(&value)?;
            prop_assert!(validate_loopback_origin(&url).is_err(), "accepted {value}");
        }
    }
}
