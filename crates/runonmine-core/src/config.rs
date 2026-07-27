use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::atomic;
use crate::policy::{
    Capability, PolicyMode, PolicyPreset, PolicyRule, PrincipalMatcher, ResourceMatcher,
};
use crate::{CONFIG_VERSION, DEFAULT_PORT};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    pub github_id: u64,
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
    pub policy_rules: Vec<PolicyRule>,
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
            policy_rules: Vec::new(),
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
            enabled: false,
            policy_preset: PolicyPreset::Safe,
            pack_overrides: BTreeMap::new(),
            tool_overrides: BTreeMap::new(),
            policy_rules: Vec::new(),
            public_base_url: None,
            cloudflare_quick: None,
            cloudflare_named: None,
            oauth_owner: None,
            openai_tunnel: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProfileMode {
    #[default]
    Ephemeral,
    Persistent,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    pub profile_name: String,
    #[serde(default)]
    pub profile_mode: BrowserProfileMode,
    pub external_cdp_url: Option<Url>,
    #[serde(default)]
    pub allow_private_network: bool,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        Self {
            profile_name: "default".to_owned(),
            profile_mode: BrowserProfileMode::Ephemeral,
            external_cdp_url: None,
            allow_private_network: false,
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

#[derive(Debug)]
struct ConfigFileLock(File);

impl ConfigFileLock {
    fn acquire(config_path: &Path) -> Result<Self> {
        let lock_path = config_lock_path(config_path)?;
        if lock_path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            bail!("refusing to use a symlinked configuration lock");
        }
        let parent = lock_path
            .parent()
            .context("config lock path has no parent")?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&lock_path)?
        };
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        restrict_file(&lock_path)?;
        file.lock_exclusive()
            .context("failed to lock RunOnMine configuration")?;
        Ok(Self(file))
    }
}

impl Drop for ConfigFileLock {
    fn drop(&mut self) {
        let _ignored = self.0.unlock();
    }
}

fn config_lock_path(path: &Path) -> Result<PathBuf> {
    let filename = path.file_name().context("config path has no file name")?;
    let mut lock_name = filename.to_os_string();
    lock_name.push(".lock");
    Ok(path.with_file_name(lock_name))
}

fn rollback_before_unlock<T, S>(
    state: &mut S,
    rollback: impl FnOnce(&mut S) -> Result<()>,
    error: anyhow::Error,
) -> Result<T> {
    if let Err(rollback_error) = rollback(state) {
        return Err(error.context(format!(
            "transaction rollback also failed: {rollback_error:#}"
        )));
    }
    Err(error)
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
        let _lock = ConfigFileLock::acquire(path)?;
        if path.exists() {
            return Self::load(path);
        }
        let config = Self::default();
        config.save_unlocked(path)?;
        Ok(config)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let _lock = ConfigFileLock::acquire(path)?;
        self.save_unlocked(path)
    }

    pub fn update<T>(path: &Path, update: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        Self::update_with_rollback(path, &mut (), |config, ()| update(config), |()| Ok(()))
    }

    /// Updates the latest configuration under the sidecar lock and runs the
    /// supplied rollback before releasing that lock when the mutation or
    /// validated atomic save returns an error. This coordinates handled error
    /// paths; it is not a crash-proof transaction across external stores.
    pub fn update_with_rollback<T, S>(
        path: &Path,
        state: &mut S,
        update: impl FnOnce(&mut Self, &mut S) -> Result<T>,
        rollback: impl FnOnce(&mut S) -> Result<()>,
    ) -> Result<T> {
        let _lock = ConfigFileLock::acquire(path)?;
        let mut config = if path.exists() {
            Self::load(path)?
        } else {
            Self::default()
        };
        let output = match update(&mut config, state) {
            Ok(output) => output,
            Err(error) => {
                return rollback_before_unlock(state, rollback, error);
            }
        };
        if let Err(error) = config.save_unlocked(path) {
            return rollback_before_unlock(state, rollback, error);
        }
        Ok(output)
    }

    fn save_unlocked(&self, path: &Path) -> Result<()> {
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
        validate_app_endpoint(self)?;
        validate_limits(&self.limits)?;
        validate_browser(&self.browser)?;
        if self.allowed_roots.len() > 256 {
            bail!("too many selected filesystem roots");
        }
        validate_connectors(&self.connectors, self.port)
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

fn validate_app_endpoint(config: &AppConfig) -> Result<()> {
    if config.version != CONFIG_VERSION {
        bail!("unsupported config version: {}", config.version);
    }
    if config.bind_host != "127.0.0.1" {
        bail!(
            "RunOnMine HTTP must bind to 127.0.0.1; got {}",
            config.bind_host
        );
    }
    if config.port == 45_799 {
        bail!("port 45799 is reserved for the existing MacMCP installation");
    }
    if config.port == 0 {
        bail!("RunOnMine agent port must be non-zero");
    }
    Ok(())
}

fn validate_limits(limits: &LimitsConfig) -> Result<()> {
    if limits.session_idle_minutes == 0
        || limits.session_idle_minutes > 24 * 60
        || limits.max_sessions == 0
        || limits.calls_per_minute == 0
        || limits.max_sessions > 1_024
        || limits.calls_per_minute > 100_000
        || limits.approval_timeout_seconds == 0
        || limits.approval_timeout_seconds > 3_600
        || limits.max_output_bytes == 0
        || limits.max_output_bytes > 64 * 1_024 * 1_024
        || limits.default_process_timeout_seconds == 0
        || limits.max_process_timeout_seconds == 0
        || limits.max_process_timeout_seconds > 86_400
        || limits.default_process_timeout_seconds > limits.max_process_timeout_seconds
    {
        bail!("configured limits are invalid or exceed safe bounds");
    }
    Ok(())
}

fn validate_browser(browser: &BrowserConfig) -> Result<()> {
    if browser.profile_name.is_empty()
        || browser.profile_name.len() > 64
        || !browser
            .profile_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!("browser profile name is invalid");
    }
    if let Some(endpoint) = &browser.external_cdp_url {
        let host = endpoint.host_str().unwrap_or_default();
        if !matches!(endpoint.scheme(), "http" | "https" | "ws" | "wss")
            || !matches!(host, "127.0.0.1" | "::1" | "localhost")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!(
                "external browser CDP endpoint must use credential-free loopback HTTP or WebSocket transport without query or fragment data"
            );
        }
    }
    Ok(())
}

fn validate_connectors(connectors: &[ConnectorConfig], agent_port: u16) -> Result<()> {
    if connectors.len() > 64 {
        bail!("too many configured connectors");
    }
    let mut connector_ids = BTreeSet::new();
    for connector in connectors {
        validate_connector_identity(connector)?;
        validate_policy_rules(&connector.policy_rules)?;
        if !connector_ids.insert(connector.id.as_str()) {
            bail!("connector ids must be unique");
        }
        validate_connector_settings(connector, agent_port)?;
    }
    validate_connector_ports(connectors)?;
    validate_singleton_connectors(connectors)
}

fn validate_policy_rules(rules: &[PolicyRule]) -> Result<()> {
    if rules.len() > 256 {
        bail!("too many connector policy rules");
    }
    for rule in rules {
        if rule.tool.as_ref().is_some_and(|tool| {
            tool.is_empty()
                || tool.len() > 128
                || !tool
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        }) {
            bail!("policy rule tool name is invalid");
        }
        match &rule.principal {
            PrincipalMatcher::OAuthClient { client_id }
                if client_id.is_empty() || client_id.len() > 256 =>
            {
                bail!("policy rule OAuth client is invalid")
            }
            PrincipalMatcher::OAuthSubject { subject }
                if subject.is_empty() || subject.len() > 256 =>
            {
                bail!("policy rule OAuth subject is invalid")
            }
            _ => {}
        }
        match &rule.resource {
            ResourceMatcher::FilesystemPrefix { path } | ResourceMatcher::Executable { path }
                if !path.is_absolute() =>
            {
                bail!("policy filesystem and executable resources must be absolute")
            }
            ResourceMatcher::BrowserOrigin { origin }
                if !matches!(origin.scheme(), "http" | "https")
                    || origin.host_str().is_none()
                    || origin.path() != "/"
                    || origin.query().is_some()
                    || origin.fragment().is_some() =>
            {
                bail!("policy browser resource must be an HTTP(S) origin")
            }
            ResourceMatcher::CommandPrefix { prefix }
                if prefix.is_empty()
                    || prefix.len() > 4096
                    || prefix.chars().any(char::is_control) =>
            {
                bail!("policy command prefix is invalid")
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_connector_identity(connector: &ConnectorConfig) -> Result<()> {
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
    Ok(())
}

fn validate_connector_ports(connectors: &[ConnectorConfig]) -> Result<()> {
    let mut auxiliary_ports = BTreeSet::new();
    for port in connectors
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
    Ok(())
}

fn validate_singleton_connectors(connectors: &[ConnectorConfig]) -> Result<()> {
    for kind in [
        ConnectorKind::LocalHttp,
        ConnectorKind::CloudflareQuick,
        ConnectorKind::CloudflareOauth,
    ] {
        if connectors
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
        if owner.github_login.trim().is_empty()
            || owner.github_login.len() > 39
            || owner.github_id == 0
        {
            bail!(
                "OAuth connector owner must include a valid GitHub login and immutable numeric ID; rerun connector setup to migrate older configurations"
            );
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
#[allow(clippy::unnecessary_wraps)]
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
    #[test]
    fn concurrent_updates_preserve_both_changes() -> Result<()> {
        use std::sync::{Arc, Barrier};

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        AppConfig::default().save(&path)?;
        let roots = [dir.path().join("root-a"), dir.path().join("root-b")];
        for root in &roots {
            fs::create_dir(root)?;
        }
        let barrier = Arc::new(Barrier::new(roots.len()));
        let mut handles = Vec::new();
        for root in roots {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || -> Result<()> {
                let root = root.canonicalize()?;
                barrier.wait();
                AppConfig::update(&path, |config| {
                    config.allowed_roots.push(root);
                    config.allowed_roots.sort();
                    Ok(())
                })
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("config update thread panicked"))??;
        }
        let loaded = AppConfig::load(&path)?;
        assert_eq!(loaded.allowed_roots.len(), 2);
        Ok(())
    }

    #[test]
    fn failed_update_does_not_replace_configuration() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        let original = AppConfig::default();
        original.save(&path)?;

        let result: Result<()> = AppConfig::update(&path, |config| {
            config.port = 1;
            bail!("abort update")
        });
        assert!(result.is_err());
        assert_eq!(AppConfig::load(&path)?.port, original.port);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn configuration_lock_is_private_and_rejects_symlinks() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        AppConfig::default().save(&path)?;
        let lock_path = config_lock_path(&path)?;
        assert_eq!(
            fs::metadata(&lock_path)?.permissions().mode() & 0o777,
            0o600
        );

        fs::remove_file(&lock_path)?;
        let target = dir.path().join("lock-target");
        fs::write(&target, b"target")?;
        symlink(&target, &lock_path)?;
        assert!(AppConfig::update(&path, |_| Ok(())).is_err());
        Ok(())
    }

    #[test]
    fn rollback_completes_before_a_competing_update_acquires_the_lock() -> Result<()> {
        use std::sync::mpsc;
        use std::time::Duration;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("config.toml");
        AppConfig::default().save(&path)?;
        let (rollback_started_tx, rollback_started_rx) = mpsc::channel();
        let (release_rollback_tx, release_rollback_rx) = mpsc::channel();
        let failing_path = path.clone();
        let failing = std::thread::spawn(move || -> Result<()> {
            let mut state = (rollback_started_tx, release_rollback_rx);
            let result: Result<()> = AppConfig::update_with_rollback(
                &failing_path,
                &mut state,
                |config, _state| {
                    config.port = 0;
                    Ok(())
                },
                |(started, release)| {
                    started.send(())?;
                    release.recv()?;
                    Ok(())
                },
            );
            assert!(result.is_err());
            Ok(())
        });
        rollback_started_rx.recv()?;

        let (update_started_tx, update_started_rx) = mpsc::channel();
        let (update_done_tx, update_done_rx) = mpsc::channel();
        let competing_path = path.clone();
        let competing = std::thread::spawn(move || -> Result<()> {
            update_started_tx.send(())?;
            AppConfig::update(&competing_path, |config| {
                config.default_preset = PolicyPreset::Developer;
                Ok(())
            })?;
            update_done_tx.send(())?;
            Ok(())
        });
        update_started_rx.recv()?;
        assert!(
            update_done_rx
                .recv_timeout(Duration::from_millis(100))
                .is_err()
        );
        release_rollback_tx.send(())?;
        update_done_rx.recv_timeout(Duration::from_secs(5))?;

        failing
            .join()
            .map_err(|_| anyhow::anyhow!("failing transaction thread panicked"))??;
        competing
            .join()
            .map_err(|_| anyhow::anyhow!("competing transaction thread panicked"))??;
        let loaded = AppConfig::load(&path)?;
        assert_eq!(loaded.port, AppConfig::default().port);
        assert_eq!(loaded.default_preset, PolicyPreset::Developer);
        Ok(())
    }

    #[test]
    fn local_http_is_disabled_by_default() -> Result<()> {
        let config = AppConfig::default();
        let local_http = config
            .connectors
            .iter()
            .find(|connector| connector.kind == ConnectorKind::LocalHttp)
            .context("default local HTTP connector is missing")?;
        assert!(!local_http.enabled);
        assert_eq!(config.browser.profile_mode, BrowserProfileMode::Ephemeral);
        Ok(())
    }

    #[test]
    fn duplicate_connector_ids_are_rejected() {
        let mut config = AppConfig::default();
        let duplicate = config.connectors[0].clone();
        config.connectors.push(duplicate);
        assert!(config.validate().is_err());
    }

    #[test]
    fn invalid_browser_profile_and_remote_cdp_are_rejected() {
        let mut config = AppConfig::default();
        config.browser.profile_name = "../escape".to_owned();
        assert!(config.validate().is_err());

        let mut config = AppConfig::default();
        config.browser.external_cdp_url = Url::parse("http://example.com:9222").ok();
        assert!(config.validate().is_err());
    }
}
