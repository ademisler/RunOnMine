use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::atomic;
use crate::policy::{Capability, PolicyMode, PolicyPreset};
use crate::{CONFIG_VERSION, DEFAULT_PORT};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    LocalStdio,
    LocalHttp,
    CloudflareQuick,
    CloudflareOauth,
    OpenAiTunnel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareQuickSettings {
    #[serde(default)]
    pub cloudflared_path: Option<PathBuf>,
    #[serde(default = "default_cloudflare_metrics_port")]
    pub metrics_port: u16,
}

impl Default for CloudflareQuickSettings {
    fn default() -> Self {
        Self {
            cloudflared_path: None,
            metrics_port: default_cloudflare_metrics_port(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudflareNamedSettings {
    pub tunnel_id: String,
    pub credentials_file: PathBuf,
    pub hostname: String,
    #[serde(default)]
    pub cloudflared_path: Option<PathBuf>,
    #[serde(default = "default_cloudflare_named_metrics_port")]
    pub metrics_port: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthOwnerSettings {
    pub github_login: String,
    #[serde(default)]
    pub github_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenAiTunnelSettings {
    pub tunnel_id: String,
    #[serde(default = "default_openai_profile")]
    pub profile: String,
    #[serde(default)]
    pub tunnel_client_path: Option<PathBuf>,
    #[serde(default = "default_openai_health_port")]
    pub health_port: u16,
}

const fn default_cloudflare_metrics_port() -> u16 {
    47_822
}

const fn default_cloudflare_named_metrics_port() -> u16 {
    47_824
}

const fn default_openai_health_port() -> u16 {
    47_823
}

fn default_openai_profile() -> String {
    "runonmine".to_owned()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorConfig {
    pub id: String,
    pub name: String,
    pub kind: ConnectorKind,
    pub enabled: bool,
    pub policy_preset: PolicyPreset,
    #[serde(default)]
    pub pack_overrides: BTreeMap<Capability, PolicyMode>,
    #[serde(default)]
    pub tool_overrides: BTreeMap<String, PolicyMode>,
    #[serde(default)]
    pub public_base_url: Option<Url>,
    #[serde(default)]
    pub cloudflare_quick: Option<CloudflareQuickSettings>,
    #[serde(default)]
    pub cloudflare_named: Option<CloudflareNamedSettings>,
    #[serde(default)]
    pub oauth_owner: Option<OAuthOwnerSettings>,
    #[serde(default)]
    pub openai_tunnel: Option<OpenAiTunnelSettings>,
}

impl ConnectorConfig {
    pub fn local_default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Local stdio".to_owned(),
            kind: ConnectorKind::LocalStdio,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: None,
        }
    }

    pub fn local_http_default() -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: "Local loopback HTTP".to_owned(),
            kind: ConnectorKind::LocalHttp,
            enabled: true,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    pub profile_name: String,
    pub external_cdp_url: Option<Url>,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            profile_name: "default".to_owned(),
            external_cdp_url: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    pub approval_timeout_seconds: u64,
    pub session_idle_minutes: u64,
    pub max_sessions: usize,
    pub calls_per_minute: u32,
    pub default_process_timeout_seconds: u64,
    pub max_process_timeout_seconds: u64,
    pub max_output_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            approval_timeout_seconds: 90,
            session_idle_minutes: 30,
            max_sessions: 32,
            calls_per_minute: 120,
            default_process_timeout_seconds: 300,
            max_process_timeout_seconds: 1_800,
            max_output_bytes: 1_000_000,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub version: u32,
    pub bind_host: String,
    pub port: u16,
    pub default_preset: PolicyPreset,
    #[serde(default)]
    pub allowed_roots: Vec<PathBuf>,
    #[serde(default)]
    pub connectors: Vec<ConnectorConfig>,
    #[serde(default)]
    pub browser: BrowserConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            bind_host: "127.0.0.1".to_owned(),
            port: DEFAULT_PORT,
            default_preset: PolicyPreset::Safe,
            allowed_roots: Vec::new(),
            connectors: vec![
                ConnectorConfig::local_default(),
                ConnectorConfig::local_http_default(),
            ],
            browser: BrowserConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("configuration must be a regular non-symlink file");
        }
        if metadata.len() > 1_048_576 {
            bail!("configuration exceeds the permitted size");
        }
        let text = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("invalid config at {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        let config = Self::default();
        config.save(path)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path.parent().context("config path has no parent")?;
        fs::create_dir_all(parent)?;
        if path
            .symlink_metadata()
            .is_ok_and(|meta| meta.file_type().is_symlink())
        {
            bail!("refusing to replace symlinked config: {}", path.display());
        }
        let serialized = toml::to_string_pretty(self)?;
        atomic::write(path, serialized.as_bytes(), 0o600)?;
        restrict_file(path)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            bail!("unsupported config version: {}", self.version);
        }
        if self.bind_host != "127.0.0.1" {
            bail!(
                "RunOnMine HTTP must bind to 127.0.0.1; got {}",
                self.bind_host
            );
        }
        if self.port == 45_799 {
            bail!("port 45799 is reserved for the existing MacMCP installation");
        }
        if self.port == 0 {
            bail!("RunOnMine agent port must be non-zero");
        }
        if self.limits.session_idle_minutes == 0
            || self.limits.max_sessions == 0
            || self.limits.calls_per_minute == 0
            || self.limits.max_sessions > 1_024
            || self.limits.calls_per_minute > 100_000
            || self.limits.approval_timeout_seconds == 0
            || self.limits.approval_timeout_seconds > 3_600
            || self.limits.max_output_bytes == 0
            || self.limits.max_output_bytes > 64 * 1_024 * 1_024
            || self.limits.default_process_timeout_seconds == 0
            || self.limits.default_process_timeout_seconds > self.limits.max_process_timeout_seconds
        {
            bail!("configured limits are invalid or exceed safe bounds");
        }
        if self.allowed_roots.len() > 256 {
            bail!("too many selected filesystem roots");
        }
        for connector in &self.connectors {
            if connector.id.is_empty()
                || connector.id.len() > 128
                || !connector
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || connector.name.trim().is_empty()
                || connector.name.len() > 100
                || connector.name.chars().any(char::is_control)
            {
                bail!("connector id or name is invalid");
            }
            validate_connector_settings(connector, self.port)?;
        }
        let mut auxiliary_ports = std::collections::BTreeSet::new();
        for port in self
            .connectors
            .iter()
            .filter(|connector| connector.enabled)
            .filter_map(|connector| {
                connector
                    .cloudflare_quick
                    .as_ref()
                    .map(|settings| settings.metrics_port)
                    .or_else(|| {
                        connector
                            .cloudflare_named
                            .as_ref()
                            .map(|settings| settings.metrics_port)
                    })
                    .or_else(|| {
                        connector
                            .openai_tunnel
                            .as_ref()
                            .map(|settings| settings.health_port)
                    })
            })
        {
            if !auxiliary_ports.insert(port) {
                bail!("enabled connectors must use distinct auxiliary ports");
            }
        }
        for kind in [
            ConnectorKind::LocalHttp,
            ConnectorKind::CloudflareQuick,
            ConnectorKind::CloudflareOauth,
        ] {
            if self
                .connectors
                .iter()
                .filter(|connector| connector.enabled && connector.kind == kind)
                .count()
                > 1
            {
                bail!("only one enabled {kind:?} connector is supported");
            }
        }
        Ok(())
    }

    pub fn connector(&self, id: &str) -> Option<&ConnectorConfig> {
        self.connectors.iter().find(|connector| connector.id == id)
    }

    pub fn connector_mut(&mut self, id: &str) -> Option<&mut ConnectorConfig> {
        self.connectors
            .iter_mut()
            .find(|connector| connector.id == id)
    }
}

fn validate_connector_settings(connector: &ConnectorConfig, agent_port: u16) -> Result<()> {
    let settings_match = match connector.kind {
        ConnectorKind::LocalStdio | ConnectorKind::LocalHttp => {
            connector.cloudflare_quick.is_none()
                && connector.cloudflare_named.is_none()
                && connector.oauth_owner.is_none()
                && connector.openai_tunnel.is_none()
                && connector.public_base_url.is_none()
        }
        ConnectorKind::CloudflareQuick => {
            connector.cloudflare_quick.is_some()
                && connector.cloudflare_named.is_none()
                && connector.oauth_owner.is_none()
                && connector.openai_tunnel.is_none()
        }
        ConnectorKind::CloudflareOauth => {
            connector.cloudflare_quick.is_none()
                && connector.cloudflare_named.is_some()
                && connector.oauth_owner.is_some()
                && connector.openai_tunnel.is_none()
                && connector.public_base_url.is_some()
        }
        ConnectorKind::OpenAiTunnel => {
            connector.cloudflare_quick.is_none()
                && connector.cloudflare_named.is_none()
                && connector.oauth_owner.is_none()
                && connector.openai_tunnel.is_some()
                && connector.public_base_url.is_none()
        }
    };
    if !settings_match {
        bail!("connector-specific settings do not match connector kind");
    }
    if let Some(settings) = &connector.cloudflare_quick {
        validate_auxiliary_port(settings.metrics_port, agent_port)?;
        validate_optional_binary_path(settings.cloudflared_path.as_deref())?;
    }
    if let Some(settings) = &connector.cloudflare_named {
        validate_auxiliary_port(settings.metrics_port, agent_port)?;
        validate_optional_binary_path(settings.cloudflared_path.as_deref())?;
        if !is_uuid(&settings.tunnel_id)
            || !is_valid_hostname(&settings.hostname)
            || !settings.credentials_file.is_absolute()
            || !is_private_regular_file(&settings.credentials_file)?
        {
            bail!("Cloudflare Named Tunnel settings are incomplete");
        }
        let public = connector
            .public_base_url
            .as_ref()
            .context("OAuth connector public URL is missing")?;
        if public.scheme() != "https"
            || public.port_or_known_default() != Some(443)
            || public.path() != "/"
            || public.query().is_some()
            || public.fragment().is_some()
            || !public.username().is_empty()
            || public.password().is_some()
            || public.host_str() != Some(settings.hostname.as_str())
        {
            bail!("OAuth connector public URL must be the configured HTTPS hostname root");
        }
        let owner = connector
            .oauth_owner
            .as_ref()
            .context("OAuth connector owner is missing")?;
        if owner.github_login.trim().is_empty() || owner.github_login.len() > 39 {
            bail!("OAuth connector GitHub owner login is invalid");
        }
    }
    if let Some(settings) = &connector.openai_tunnel {
        validate_auxiliary_port(settings.health_port, agent_port)?;
        validate_optional_binary_path(settings.tunnel_client_path.as_deref())?;
        let tunnel_suffix = settings.tunnel_id.strip_prefix("tunnel_");
        if !tunnel_suffix.is_some_and(|suffix| {
            suffix.len() == 32
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) || settings.profile.trim().is_empty()
            || settings.profile.len() > 64
            || !settings
                .profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            bail!("OpenAI tunnel settings are invalid");
        }
    }
    Ok(())
}

fn validate_optional_binary_path(path: Option<&Path>) -> Result<()> {
    if path.is_some_and(|path| !path.is_absolute()) {
        bail!("connector binary paths must be absolute");
    }
    Ok(())
}

fn is_uuid(value: &str) -> bool {
    let expected = [8_usize, 4, 4, 4, 12];
    value.split('-').count() == expected.len()
        && value.split('-').zip(expected).all(|(segment, length)| {
            segment.len() == length && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

fn is_valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.ends_with('.')
        && value.split('.').count() >= 2
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn is_private_regular_file(path: &Path) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_auxiliary_port(port: u16, agent_port: u16) -> Result<()> {
    if port == 0 || port == agent_port || port == 45_799 {
        bail!("connector auxiliary port is invalid or reserved");
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_legacy_port() {
        let config = AppConfig {
            port: 45_799,
            ..AppConfig::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn round_trips_config() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        let config = AppConfig::default();
        config.save(&path)?;
        let loaded = AppConfig::load(&path)?;
        assert_eq!(loaded.port, DEFAULT_PORT);
        assert_eq!(loaded.default_preset, PolicyPreset::Safe);
        Ok(())
    }
}
