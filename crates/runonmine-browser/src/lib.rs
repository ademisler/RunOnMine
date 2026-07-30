//! Isolated browser-profile and CDP automation primitives.

mod network_proxy;
mod orphan_reaper;

pub use orphan_reaper::{BrowserOrphanReport, reap_orphaned_browser_sessions};

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chromiumoxide::Handler;
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, DisableParams as FetchDisableParams, EnableParams as FetchEnableParams,
    EventRequestPaused, FailRequestParams,
};
use chromiumoxide::cdp::browser_protocol::network::ErrorReason;
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
use network_proxy::{
    BrowserNetworkGuard, DestinationResolver, SystemDestinationResolver, canonical_destination_host,
};
use orphan_reaper::BrowserLease;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard};
use url::Url;

const MAX_BROWSER_INPUT_BYTES: usize = 256 * 1_024;
const DEFAULT_BROWSER_OPERATION_TIMEOUT: Duration = Duration::from_secs(45);
const BROWSER_RECOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const BROWSER_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const BROWSER_REQUEST_GUARD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserProfile {
    Isolated { directory: PathBuf, ephemeral: bool },
    ExternalCdp { endpoint: Url },
}

impl BrowserProfile {
    pub fn isolated_ephemeral(directory: PathBuf) -> Self {
        Self::Isolated {
            directory,
            ephemeral: true,
        }
    }

    pub fn isolated_persistent(directory: PathBuf) -> Self {
        Self::Isolated {
            directory,
            ephemeral: false,
        }
    }

    pub fn external(endpoint: Url) -> Result<Self> {
        let host = endpoint.host_str().unwrap_or_default();
        if !matches!(endpoint.scheme(), "http" | "https" | "ws" | "wss")
            || !matches!(host, "127.0.0.1" | "::1" | "localhost")
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            bail!(
                "external CDP endpoints must use credential-free loopback HTTP or WebSocket transport without query or fragment data"
            );
        }
        Ok(Self::ExternalCdp { endpoint })
    }

    fn cleanup_directory(&self) -> Option<PathBuf> {
        match self {
            Self::Isolated {
                directory,
                ephemeral: true,
            } => Some(directory.clone()),
            Self::Isolated { .. } | Self::ExternalCdp { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserExecutableSource {
    AutoDetected,
    Explicit,
}

impl std::fmt::Display for BrowserExecutableSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AutoDetected => "auto-detected",
            Self::Explicit => "explicit",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserProduct {
    GoogleChrome,
    Chromium,
    MicrosoftEdge,
}

impl std::fmt::Display for BrowserProduct {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::GoogleChrome => "Google Chrome",
            Self::Chromium => "Chromium",
            Self::MicrosoftEdge => "Microsoft Edge",
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrowserExecutableIdentity {
    pub source: BrowserExecutableSource,
    pub product: BrowserProduct,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BrowserExecutableSummary {
    pub source: BrowserExecutableSource,
    pub product: BrowserProduct,
    pub executable_name: String,
}

impl BrowserExecutableSummary {
    fn from_identity(identity: &BrowserExecutableIdentity) -> Self {
        Self {
            source: identity.source,
            product: identity.product,
            executable_name: identity.path.file_name().map_or_else(
                || "browser".to_owned(),
                |name| name.to_string_lossy().into_owned(),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BrowserExecutableState {
    Available {
        executable: BrowserExecutableSummary,
    },
    Missing,
    Disabled,
    Corrupt,
    Unavailable,
    PermissionDenied,
}

impl BrowserExecutableState {
    #[must_use]
    pub const fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    #[must_use]
    pub const fn executable(&self) -> Option<&BrowserExecutableSummary> {
        match self {
            Self::Available { executable } => Some(executable),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrowserExecutableFailureKind {
    Missing,
    Corrupt,
    Unavailable,
    PermissionDenied,
}

impl BrowserExecutableFailureKind {
    const fn priority(self) -> u8 {
        match self {
            Self::Missing => 1,
            Self::Unavailable => 2,
            Self::Corrupt => 3,
            Self::PermissionDenied => 4,
        }
    }

    const fn state(self) -> BrowserExecutableState {
        match self {
            Self::Missing => BrowserExecutableState::Missing,
            Self::Corrupt => BrowserExecutableState::Corrupt,
            Self::Unavailable => BrowserExecutableState::Unavailable,
            Self::PermissionDenied => BrowserExecutableState::PermissionDenied,
        }
    }
}

#[derive(Debug)]
struct BrowserExecutableFailure {
    kind: BrowserExecutableFailureKind,
    message: String,
}

impl BrowserExecutableFailure {
    fn new(kind: BrowserExecutableFailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    fn from_io(error: &std::io::Error, path: &Path) -> Self {
        let kind = match error.kind() {
            std::io::ErrorKind::NotFound => BrowserExecutableFailureKind::Missing,
            std::io::ErrorKind::PermissionDenied => BrowserExecutableFailureKind::PermissionDenied,
            _ => BrowserExecutableFailureKind::Unavailable,
        };
        Self::new(
            kind,
            format!(
                "browser executable is unavailable at {}: {error}",
                path.display()
            ),
        )
    }
}

impl std::fmt::Display for BrowserExecutableFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for BrowserExecutableFailure {}

#[derive(Debug, Serialize)]
pub struct BrowserSessionInfo {
    pub profile: BrowserProfile,
    pub active: bool,
    pub current_url: Option<String>,
    pub executable_selection: Option<BrowserExecutableSource>,
    pub executable_state: BrowserExecutableState,
    pub executable_available: Option<bool>,
    pub selected_executable: Option<BrowserExecutableSummary>,
    pub active_executable: Option<BrowserExecutableSummary>,
    pub operation_timeout_seconds: u64,
    pub timeout_recoveries: u64,
    pub last_timeout_operation: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct BoundedBrowserText {
    pub content: String,
    pub truncated: bool,
}

#[derive(Debug, Deserialize)]
struct BoundedValue {
    content: String,
    truncated: bool,
}

#[derive(Debug)]
struct ActiveBrowser {
    browser: Browser,
    page: Page,
    handler_task: tokio::task::JoinHandle<()>,
    interceptor_task: tokio::task::JoinHandle<()>,
    network_guard: Option<BrowserNetworkGuard>,
    lease: Option<BrowserLease>,
    executable: Option<BrowserExecutableIdentity>,
    owned_process: bool,
    page_owned: bool,
}

struct BrowserLaunch {
    browser: Browser,
    handler: Handler,
    network_guard: Option<BrowserNetworkGuard>,
    lease: Option<BrowserLease>,
    executable: Option<BrowserExecutableIdentity>,
    owned_process: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TeardownMode {
    Graceful,
    Forced,
}

async fn teardown_active_browser(mut active: ActiveBrowser, mode: TeardownMode) {
    active.interceptor_task.abort();

    if mode == TeardownMode::Graceful {
        let _ignored = tokio::time::timeout(
            Duration::from_secs(1),
            active.page.execute(FetchDisableParams::default()),
        )
        .await;
        if active.page_owned {
            let _ignored =
                tokio::time::timeout(Duration::from_secs(2), active.page.clone().close()).await;
        }
    }

    let mut process_stopped = !active.owned_process;
    if active.owned_process
        && mode == TeardownMode::Graceful
        && matches!(
            tokio::time::timeout(Duration::from_secs(2), active.browser.close()).await,
            Ok(Ok(_))
        )
        && matches!(
            tokio::time::timeout(Duration::from_secs(3), active.browser.wait()).await,
            Ok(Ok(_))
        )
    {
        process_stopped = true;
    }
    if active.owned_process && !process_stopped {
        let killed = tokio::time::timeout(BROWSER_RECOVERY_TIMEOUT, async {
            match active.browser.kill().await {
                Some(result) => result,
                None => Ok(()),
            }
        })
        .await;
        if matches!(killed, Ok(Ok(()))) {
            process_stopped = true;
        } else {
            tracing::warn!("owned Chromium did not confirm forced termination before its deadline");
        }
    }

    active.handler_task.abort();
    if let Some(mut guard) = active.network_guard.take() {
        guard.stop().await;
    }
    if process_stopped && let Some(mut lease) = active.lease.take() {
        if lease.ephemeral() {
            let profile = lease.profile_directory().to_path_buf();
            if remove_ephemeral_profile_with_retries(&profile).await {
                lease.release();
            } else {
                tracing::warn!(
                    path = %profile.display(),
                    "retained browser ownership lease because the ephemeral profile could not be removed"
                );
            }
        } else {
            lease.release();
        }
    }
}

async fn remove_ephemeral_profile_with_retries(profile: &Path) -> bool {
    for delay in [0_u64, 50, 200, 500, 1_000] {
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match std::fs::remove_dir_all(profile) {
            Ok(()) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if !profile.exists() {
                    return true;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return true,
            Err(_) => {}
        }
    }
    false
}

pub struct BrowserSession {
    profile: BrowserProfile,
    headless: bool,
    allow_private_network: bool,
    max_output_bytes: usize,
    explicit_executable: Option<PathBuf>,
    operation_timeout: Duration,
    timeout_recoveries: AtomicU64,
    last_timeout_operation: StdMutex<Option<&'static str>>,
    resolver: Arc<dyn DestinationResolver>,
    #[cfg(test)]
    extra_browser_args: Vec<(String, String)>,
    active: Mutex<Option<ActiveBrowser>>,
}

impl std::fmt::Debug for BrowserSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrowserSession")
            .field("profile", &self.profile)
            .field("headless", &self.headless)
            .field("allow_private_network", &self.allow_private_network)
            .field("max_output_bytes", &self.max_output_bytes)
            .field("explicit_executable", &self.explicit_executable)
            .field("operation_timeout", &self.operation_timeout)
            .field(
                "timeout_recoveries",
                &self.timeout_recoveries.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl BrowserSession {
    pub fn new(
        profile: BrowserProfile,
        headless: bool,
        allow_private_network: bool,
        max_output_bytes: usize,
    ) -> Self {
        Self::with_operation_timeout(
            profile,
            headless,
            allow_private_network,
            max_output_bytes,
            DEFAULT_BROWSER_OPERATION_TIMEOUT,
        )
    }

    pub fn with_operation_timeout(
        profile: BrowserProfile,
        headless: bool,
        allow_private_network: bool,
        max_output_bytes: usize,
        operation_timeout: Duration,
    ) -> Self {
        Self::with_executable_and_operation_timeout(
            profile,
            headless,
            allow_private_network,
            max_output_bytes,
            None,
            operation_timeout,
        )
    }

    pub fn with_executable_and_operation_timeout(
        profile: BrowserProfile,
        headless: bool,
        allow_private_network: bool,
        max_output_bytes: usize,
        explicit_executable: Option<PathBuf>,
        operation_timeout: Duration,
    ) -> Self {
        Self {
            profile,
            headless,
            allow_private_network,
            max_output_bytes: max_output_bytes.max(1),
            explicit_executable,
            operation_timeout: operation_timeout.max(Duration::from_millis(1)),
            timeout_recoveries: AtomicU64::new(0),
            last_timeout_operation: StdMutex::new(None),
            resolver: Arc::new(SystemDestinationResolver),
            #[cfg(test)]
            extra_browser_args: Vec::new(),
            active: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn with_network_test_support(
        profile: BrowserProfile,
        headless: bool,
        max_output_bytes: usize,
        resolver: Arc<dyn DestinationResolver>,
        extra_browser_args: Vec<(String, String)>,
    ) -> Self {
        Self {
            profile,
            headless,
            allow_private_network: false,
            max_output_bytes: max_output_bytes.max(1),
            explicit_executable: None,
            operation_timeout: DEFAULT_BROWSER_OPERATION_TIMEOUT,
            timeout_recoveries: AtomicU64::new(0),
            last_timeout_operation: StdMutex::new(None),
            resolver,
            extra_browser_args,
            active: Mutex::new(None),
        }
    }

    pub async fn open(&self, url: &str) -> Result<String> {
        self.run_with_deadline("open", self.open_inner(url)).await
    }

    pub async fn navigate(&self, url: &str) -> Result<String> {
        self.run_with_deadline("navigate", self.navigate_inner(url))
            .await
    }

    pub async fn policy_url(&self) -> Result<Url> {
        self.run_with_deadline("policy_url", self.policy_url_inner())
            .await
    }

    pub async fn current_url(&self) -> Result<Option<String>> {
        self.run_with_deadline("current_url", self.current_url_inner())
            .await
    }

    pub async fn text(&self) -> Result<BoundedBrowserText> {
        self.run_with_deadline("text", self.text_inner()).await
    }

    pub async fn snapshot(&self) -> Result<BoundedBrowserText> {
        self.run_with_deadline("snapshot", self.snapshot_inner())
            .await
    }

    pub async fn click(&self, selector: &str) -> Result<()> {
        self.run_with_deadline("click", self.click_inner(selector))
            .await
    }

    pub async fn type_text(&self, selector: &str, text: &str) -> Result<()> {
        self.run_with_deadline("type_text", self.type_text_inner(selector, text))
            .await
    }

    pub async fn press(&self, key: &str) -> Result<()> {
        self.run_with_deadline("press", self.press_inner(key)).await
    }

    pub async fn screenshot_jpeg(&self, quality: u8, full_page: bool) -> Result<Vec<u8>> {
        self.run_with_deadline("screenshot", self.screenshot_jpeg_inner(quality, full_page))
            .await
    }

    pub async fn evaluate(&self, expression: &str) -> Result<serde_json::Value> {
        self.run_with_deadline("evaluate", self.evaluate_inner(expression))
            .await
    }

    pub async fn close(&self) -> Result<()> {
        self.run_with_deadline("close", self.close_inner()).await
    }

    pub async fn info(&self) -> Result<BrowserSessionInfo> {
        self.run_with_deadline("info", self.info_inner()).await
    }

    async fn run_with_deadline<T, F>(&self, operation: &'static str, future: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        if let Ok(result) = tokio::time::timeout(self.operation_timeout, future).await {
            return result;
        }
        let reset = self.recover_stuck_session(operation).await;
        let outcome = if reset {
            "the browser session was reset"
        } else {
            "the browser session could not be reset promptly"
        };
        bail!(
            "browser operation `{operation}` exceeded its {} second deadline; {outcome}",
            self.operation_timeout.as_secs_f64()
        )
    }

    async fn recover_stuck_session(&self, operation: &'static str) -> bool {
        self.timeout_recoveries.fetch_add(1, Ordering::Relaxed);
        *self
            .last_timeout_operation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(operation);
        let Ok(mut slot) = tokio::time::timeout(BROWSER_RECOVERY_TIMEOUT, self.active.lock()).await
        else {
            tracing::error!(
                operation,
                "timed-out browser session lock could not be recovered"
            );
            return false;
        };
        let active = slot.take();
        if let Some(active) = active {
            let cleanup = teardown_active_browser(active, TeardownMode::Forced);
            if tokio::time::timeout(BROWSER_TEARDOWN_TIMEOUT, cleanup)
                .await
                .is_err()
            {
                tracing::warn!(operation, "forced browser cleanup exceeded its deadline");
            }
        }
        drop(slot);
        true
    }

    async fn open_inner(&self, url: &str) -> Result<String> {
        validate_navigation_url_with_resolver(
            url,
            self.allow_private_network,
            self.resolver.as_ref(),
        )
        .await?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let page = active.browser.new_page("about:blank").await?;
        let interceptor_task = install_request_guard(
            &page,
            self.allow_private_network,
            Arc::clone(&self.resolver),
        )
        .await?;
        if let Err(error) = page.goto(url).await {
            interceptor_task.abort();
            let _ignored = page.close().await;
            return Err(error.into());
        }
        let current_url = page.url().await?.unwrap_or_else(|| url.to_owned());
        if let Err(error) = validate_navigation_url_with_resolver(
            &current_url,
            self.allow_private_network,
            self.resolver.as_ref(),
        )
        .await
        {
            stop_request_guard(&page, &interceptor_task).await;
            let _ignored = page.close().await;
            return Err(error.context("browser navigation ended at a disallowed destination"));
        }
        stop_request_guard(&active.page, &active.interceptor_task).await;
        if active.page_owned {
            let _ignored = active.page.clone().close().await;
        }
        active.page = page;
        active.page_owned = true;
        active.interceptor_task = interceptor_task;
        Ok(current_url)
    }

    async fn navigate_inner(&self, url: &str) -> Result<String> {
        validate_navigation_url_with_resolver(
            url,
            self.allow_private_network,
            self.resolver.as_ref(),
        )
        .await?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.goto(url).await?;
        let current = active.page.url().await?.unwrap_or_else(|| url.to_owned());
        validate_navigation_url_with_resolver(
            &current,
            self.allow_private_network,
            self.resolver.as_ref(),
        )
        .await?;
        Ok(current)
    }

    /// Return the page identity used for policy evaluation without launching a
    /// browser when the session is inactive. New sessions begin at about:blank.
    async fn policy_url_inner(&self) -> Result<Url> {
        let slot = self.active.lock().await;
        let value = match slot.as_ref() {
            Some(active) => active
                .page
                .url()
                .await?
                .unwrap_or_else(|| "about:blank".to_owned()),
            None => "about:blank".to_owned(),
        };
        Url::parse(&value).context("current browser page has an invalid URL")
    }

    async fn current_url_inner(&self) -> Result<Option<String>> {
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.url().await.map_err(Into::into)
    }

    async fn text_inner(&self) -> Result<BoundedBrowserText> {
        let limit = self.max_output_bytes.min(i32::MAX as usize);
        let expression = format!(
            "() => {{ const value = document.body ? document.body.innerText : ''; return {{ content: value.slice(0, {limit}), truncated: value.length > {limit} }}; }}"
        );
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let value: BoundedValue = active
            .page
            .evaluate(expression)
            .await?
            .into_value()
            .map_err(anyhow::Error::from)?;
        Ok(bound_utf8(value, self.max_output_bytes))
    }

    async fn snapshot_inner(&self) -> Result<BoundedBrowserText> {
        let limit = self.max_output_bytes.min(i32::MAX as usize);
        let expression = format!(
            "() => {{ const value = document.documentElement ? document.documentElement.outerHTML : ''; return {{ content: value.slice(0, {limit}), truncated: value.length > {limit} }}; }}"
        );
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let value: BoundedValue = active
            .page
            .evaluate(expression)
            .await?
            .into_value()
            .map_err(anyhow::Error::from)?;
        Ok(bound_utf8(value, self.max_output_bytes))
    }

    async fn click_inner(&self, selector: &str) -> Result<()> {
        validate_selector(selector)?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.find_element(selector).await?.click().await?;
        Ok(())
    }

    async fn type_text_inner(&self, selector: &str, text: &str) -> Result<()> {
        validate_selector(selector)?;
        if text.len() > MAX_BROWSER_INPUT_BYTES {
            bail!("browser text input exceeds the size limit");
        }
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active
            .page
            .find_element(selector)
            .await?
            .click()
            .await?
            .type_str(text)
            .await?;
        Ok(())
    }

    async fn press_inner(&self, key: &str) -> Result<()> {
        if key.is_empty() || key.len() > 64 {
            bail!("invalid key name");
        }
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active
            .page
            .find_element(":focus, body")
            .await?
            .press_key(key)
            .await?;
        Ok(())
    }

    async fn screenshot_jpeg_inner(&self, quality: u8, full_page: bool) -> Result<Vec<u8>> {
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let bytes = active
            .page
            .screenshot(
                ScreenshotParams::builder()
                    .format(CaptureScreenshotFormat::Jpeg)
                    .quality(i64::from(quality.clamp(10, 90)))
                    .full_page(full_page)
                    .build(),
            )
            .await?;
        if bytes.len() > self.max_output_bytes {
            bail!("browser screenshot exceeds the output size limit");
        }
        Ok(bytes)
    }

    async fn evaluate_inner(&self, expression: &str) -> Result<serde_json::Value> {
        if expression.len() > MAX_BROWSER_INPUT_BYTES {
            bail!("browser expression exceeds the size limit");
        }
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let value: serde_json::Value = active
            .page
            .evaluate(expression)
            .await?
            .into_value()
            .map_err(anyhow::Error::from)?;
        if serde_json::to_vec(&value)?.len() > self.max_output_bytes {
            bail!("browser evaluation result exceeds the output size limit");
        }
        Ok(value)
    }

    async fn close_inner(&self) -> Result<()> {
        let mut slot = self.active.lock().await;
        if let Some(active) = slot.take() {
            teardown_active_browser(active, TeardownMode::Graceful).await;
        } else {
            self.cleanup_profile();
        }
        Ok(())
    }

    async fn info_inner(&self) -> Result<BrowserSessionInfo> {
        let slot = self.active.lock().await;
        let current_url = match slot.as_ref() {
            Some(active) => active.page.url().await?,
            None => None,
        };
        let (executable_selection, executable_state, executable_available, selected_executable) =
            match &self.profile {
                BrowserProfile::Isolated { .. } => {
                    let source = if self.explicit_executable.is_some() {
                        BrowserExecutableSource::Explicit
                    } else {
                        BrowserExecutableSource::AutoDetected
                    };
                    let state = browser_executable_state(self.explicit_executable.as_deref());
                    let selected = state.executable().cloned();
                    (
                        Some(source),
                        state.clone(),
                        Some(state.is_available()),
                        selected,
                    )
                }
                BrowserProfile::ExternalCdp { .. } => {
                    (None, BrowserExecutableState::Disabled, None, None)
                }
            };
        let active_executable = slot.as_ref().and_then(|active| {
            active
                .executable
                .as_ref()
                .map(BrowserExecutableSummary::from_identity)
        });
        Ok(BrowserSessionInfo {
            profile: self.profile.clone(),
            active: slot.is_some(),
            current_url,
            executable_selection,
            executable_state,
            executable_available,
            selected_executable,
            active_executable,
            operation_timeout_seconds: self.operation_timeout.as_secs(),
            timeout_recoveries: self.timeout_recoveries.load(Ordering::Relaxed),
            last_timeout_operation: self
                .last_timeout_operation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .map(str::to_owned),
        })
    }

    async fn ensure_active(&self) -> Result<MutexGuard<'_, Option<ActiveBrowser>>> {
        let mut slot = self.active.lock().await;
        if slot.is_none() {
            *slot = Some(Box::pin(self.start_active_browser()).await?);
        }
        Ok(slot)
    }

    async fn start_active_browser(&self) -> Result<ActiveBrowser> {
        validate_browser_network_mode(&self.profile, self.allow_private_network)?;
        let launch = match &self.profile {
            BrowserProfile::Isolated {
                directory,
                ephemeral,
            } => self.launch_isolated_browser(directory, *ephemeral).await?,
            BrowserProfile::ExternalCdp { endpoint } => {
                let (browser, handler) = Browser::connect(endpoint.to_string()).await?;
                BrowserLaunch {
                    browser,
                    handler,
                    network_guard: None,
                    lease: None,
                    executable: None,
                    owned_process: false,
                }
            }
        };
        self.finish_browser_launch(launch).await
    }

    async fn launch_isolated_browser(
        &self,
        directory: &Path,
        ephemeral: bool,
    ) -> Result<BrowserLaunch> {
        ensure_private_directory(directory)?;
        let selected = resolve_browser_executable(self.explicit_executable.as_deref())?;
        let mut lease = BrowserLease::prepare(directory, &selected.path, ephemeral)?;
        let mut network_guard = if self.allow_private_network {
            None
        } else {
            Some(BrowserNetworkGuard::start(Arc::clone(&self.resolver)).await?)
        };
        let config = match self.build_isolated_browser_config(
            directory,
            selected.path.clone(),
            network_guard.as_ref(),
            &lease,
        ) {
            Ok(config) => config,
            Err(error) => {
                lease.release();
                self.cleanup_profile();
                return Err(error);
            }
        };
        let launched = Browser::launch(config).await;
        if launched.is_err() {
            if let Some(guard) = network_guard.as_mut() {
                guard.stop().await;
            }
            lease.release();
            self.cleanup_profile();
        }
        let (mut browser, handler) = launched?;
        if let Err(error) = lease.activate(&mut browser) {
            let stopped = matches!(
                tokio::time::timeout(BROWSER_RECOVERY_TIMEOUT, browser.kill()).await,
                Ok(Some(Ok(())))
            );
            if stopped {
                lease.release();
                self.cleanup_profile();
            }
            if let Some(guard) = network_guard.as_mut() {
                guard.stop().await;
            }
            return Err(error.context("failed to activate browser ownership lease"));
        }
        let executable = Some(inspect_resolved_browser_executable(
            lease.executable(),
            selected.source,
        )?);
        Ok(BrowserLaunch {
            browser,
            handler,
            network_guard,
            lease: Some(lease),
            executable,
            owned_process: true,
        })
    }

    fn build_isolated_browser_config(
        &self,
        directory: &Path,
        executable: PathBuf,
        network_guard: Option<&BrowserNetworkGuard>,
        lease: &BrowserLease,
    ) -> Result<BrowserConfig> {
        let (lease_argument, lease_token) = lease.chromium_argument();
        let mut builder = BrowserConfig::builder()
            .chrome_executable(executable)
            .user_data_dir(directory)
            .arg((lease_argument.as_str(), lease_token.as_str()))
            .window_size(1_280, 900)
            .launch_timeout(self.operation_timeout.min(Duration::from_secs(30)))
            .request_timeout(self.operation_timeout.min(Duration::from_secs(30)));
        if let Some(guard) = network_guard {
            for argument in guarded_browser_arguments(guard.address()) {
                builder = match argument.value {
                    Some(value) => builder.arg((argument.key, value.as_str())),
                    None => builder.arg(argument.key),
                };
            }
        }
        #[cfg(test)]
        for (key, value) in &self.extra_browser_args {
            builder = builder.arg((key.as_str(), value.as_str()));
        }
        if !self.headless {
            builder = builder.with_head();
        }
        builder.build().map_err(anyhow::Error::msg)
    }

    async fn finish_browser_launch(&self, mut launch: BrowserLaunch) -> Result<ActiveBrowser> {
        let mut handler = launch.handler;
        let handler_task = tokio::spawn(async move {
            while let Some(event) = handler.next().await {
                if let Err(error) = event {
                    tracing::warn!(%error, "Chromium handler stopped");
                    break;
                }
            }
        });
        if !launch.owned_process {
            launch.browser.fetch_targets().await?;
        }
        let existing_page = launch.browser.pages().await?.into_iter().next();
        let (page, page_owned) = match existing_page {
            Some(page) => (page, launch.owned_process),
            None => (launch.browser.new_page("about:blank").await?, true),
        };
        let interceptor_task = install_request_guard(
            &page,
            self.allow_private_network,
            Arc::clone(&self.resolver),
        )
        .await?;
        Ok(ActiveBrowser {
            browser: launch.browser,
            page,
            handler_task,
            interceptor_task,
            network_guard: launch.network_guard,
            lease: launch.lease,
            executable: launch.executable,
            owned_process: launch.owned_process,
            page_owned,
        })
    }

    fn cleanup_profile(&self) {
        if let Some(directory) = self.profile.cleanup_directory() {
            let _ignored = std::fs::remove_dir_all(directory);
        }
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.active.try_lock()
            && let Some(active) = slot.take()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            runtime.spawn(teardown_active_browser(active, TeardownMode::Forced));
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct BrowserArgument {
    key: &'static str,
    value: Option<String>,
}

fn guarded_browser_arguments(proxy_address: std::net::SocketAddr) -> Vec<BrowserArgument> {
    vec![
        BrowserArgument {
            key: "proxy-server",
            value: Some(format!("http://{proxy_address}")),
        },
        BrowserArgument {
            key: "proxy-bypass-list",
            value: Some("<-loopback>".to_owned()),
        },
        BrowserArgument {
            key: "host-resolver-rules",
            value: Some("MAP * ~NOTFOUND, EXCLUDE 127.0.0.1".to_owned()),
        },
        BrowserArgument {
            key: "force-webrtc-ip-handling-policy",
            value: Some("disable_non_proxied_udp".to_owned()),
        },
        BrowserArgument {
            key: "disable-quic",
            value: None,
        },
    ]
}

fn validate_browser_network_mode(
    profile: &BrowserProfile,
    allow_private_network: bool,
) -> Result<()> {
    if matches!(profile, BrowserProfile::ExternalCdp { .. }) && !allow_private_network {
        bail!(
            "external CDP cannot provide browser-wide private-network enforcement; enable the explicit local private-network option or use an isolated profile"
        );
    }
    Ok(())
}

async fn stop_request_guard(page: &Page, task: &tokio::task::JoinHandle<()>) {
    task.abort();
    let _ignored = tokio::time::timeout(
        Duration::from_secs(1),
        page.execute(FetchDisableParams::default()),
    )
    .await;
}

async fn install_request_guard(
    page: &Page,
    allow_private_network: bool,
    resolver: Arc<dyn DestinationResolver>,
) -> Result<tokio::task::JoinHandle<()>> {
    let mut requests = page.event_listener::<EventRequestPaused>().await?;
    page.execute(FetchEnableParams::default()).await?;
    let guarded_page = page.clone();
    Ok(tokio::spawn(async move {
        while let Some(event) = requests.next().await {
            let request_id = event.request_id.clone();
            let allowed =
                if event.response_status_code.is_some() || event.response_error_reason.is_some() {
                    true
                } else {
                    matches!(
                        tokio::time::timeout(
                            BROWSER_REQUEST_GUARD_TIMEOUT,
                            validate_request_url_with_resolver(
                                &event.request.url,
                                allow_private_network,
                                resolver.as_ref(),
                            ),
                        )
                        .await,
                        Ok(Ok(()))
                    )
                };
            let command = async {
                if allowed {
                    guarded_page
                        .execute(ContinueRequestParams::new(request_id))
                        .await
                        .map(|_| ())
                } else {
                    tracing::warn!(
                        destination = %redacted_destination(&event.request.url),
                        "blocked browser request to a private, unsupported, or unresolved destination"
                    );
                    guarded_page
                        .execute(FailRequestParams::new(
                            request_id,
                            ErrorReason::BlockedByClient,
                        ))
                        .await
                        .map(|_| ())
                }
            };
            match tokio::time::timeout(BROWSER_REQUEST_GUARD_TIMEOUT, command).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%error, "browser request interception ended");
                }
                Err(_) => {
                    tracing::warn!("browser request interception exceeded its deadline");
                    break;
                }
            }
        }
    }))
}

fn bound_utf8(mut value: BoundedValue, maximum: usize) -> BoundedBrowserText {
    let mut truncated = value.truncated || value.content.len() > maximum;
    if value.content.len() > maximum {
        let mut boundary = maximum;
        while boundary > 0 && !value.content.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.content.truncate(boundary);
        truncated = true;
    }
    BoundedBrowserText {
        content: value.content,
        truncated,
    }
}

pub fn chromium_available() -> bool {
    browser_executable_state(None).is_available()
}

pub fn browser_executable_available(explicit: Option<&Path>) -> bool {
    browser_executable_state(explicit).is_available()
}

pub fn browser_executable_state(explicit: Option<&Path>) -> BrowserExecutableState {
    match resolve_browser_executable_classified(explicit) {
        Ok(identity) => BrowserExecutableState::Available {
            executable: BrowserExecutableSummary::from_identity(&identity),
        },
        Err(error) => error.kind.state(),
    }
}

pub fn inspect_explicit_browser_executable(path: &Path) -> Result<BrowserExecutableIdentity> {
    inspect_browser_executable_classified(path, BrowserExecutableSource::Explicit)
        .map_err(anyhow::Error::new)
}

pub fn resolve_browser_executable(explicit: Option<&Path>) -> Result<BrowserExecutableIdentity> {
    resolve_browser_executable_classified(explicit).map_err(anyhow::Error::new)
}

fn resolve_browser_executable_classified(
    explicit: Option<&Path>,
) -> std::result::Result<BrowserExecutableIdentity, BrowserExecutableFailure> {
    if let Some(path) = explicit {
        return inspect_browser_executable_classified(path, BrowserExecutableSource::Explicit);
    }
    let mut strongest_failure: Option<BrowserExecutableFailure> = None;
    for path in browser_executable_candidates() {
        match inspect_browser_executable_classified(&path, BrowserExecutableSource::AutoDetected) {
            Ok(identity) => return Ok(identity),
            Err(failure) => {
                let replace = strongest_failure
                    .as_ref()
                    .is_none_or(|current| failure.kind.priority() > current.kind.priority());
                if replace {
                    strongest_failure = Some(failure);
                }
            }
        }
    }
    Err(strongest_failure.unwrap_or_else(|| {
        BrowserExecutableFailure::new(
            BrowserExecutableFailureKind::Missing,
            "a supported Chromium installation was not found",
        )
    }))
}

pub fn chromium_executable() -> Option<PathBuf> {
    match resolve_browser_executable_classified(None) {
        Ok(identity) => Some(identity.path),
        Err(_) => None,
    }
}

fn inspect_browser_executable_classified(
    path: &Path,
    source: BrowserExecutableSource,
) -> std::result::Result<BrowserExecutableIdentity, BrowserExecutableFailure> {
    let resolved = path
        .canonicalize()
        .map_err(|error| BrowserExecutableFailure::from_io(&error, path))?;
    let metadata = std::fs::symlink_metadata(&resolved)
        .map_err(|error| BrowserExecutableFailure::from_io(&error, &resolved))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BrowserExecutableFailure::new(
            BrowserExecutableFailureKind::Corrupt,
            "browser executable must resolve to a real regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(BrowserExecutableFailure::new(
                BrowserExecutableFailureKind::Corrupt,
                "browser executable is not executable",
            ));
        }
    }
    let Some(product) = classify_browser_executable(&resolved) else {
        return Err(BrowserExecutableFailure::new(
            BrowserExecutableFailureKind::Corrupt,
            "browser executable is not a supported Chrome, Chromium, or Edge binary",
        ));
    };
    Ok(BrowserExecutableIdentity {
        source,
        product,
        path: resolved,
    })
}

fn inspect_resolved_browser_executable(
    path: &Path,
    source: BrowserExecutableSource,
) -> Result<BrowserExecutableIdentity> {
    inspect_browser_executable_classified(path, source).map_err(anyhow::Error::new)
}

fn classify_browser_executable(path: &Path) -> Option<BrowserProduct> {
    let name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let full_path = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if matches!(
        name.as_str(),
        "msedge" | "msedge.exe" | "microsoft edge" | "microsoft-edge" | "microsoft-edge-stable"
    ) || full_path.contains("/microsoft/edge/")
    {
        return Some(BrowserProduct::MicrosoftEdge);
    }
    if matches!(
        name.as_str(),
        "chromium" | "chromium.exe" | "chromium-browser"
    ) || full_path.contains("/chromium/")
    {
        return Some(BrowserProduct::Chromium);
    }
    if matches!(
        name.as_str(),
        "chrome" | "chrome.exe" | "google chrome" | "google-chrome" | "google-chrome-stable"
    ) {
        return Some(BrowserProduct::GoogleChrome);
    }
    None
}

fn browser_executable_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    #[cfg(target_os = "macos")]
    candidates.extend([
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    ]);
    #[cfg(target_os = "linux")]
    candidates.extend([
        PathBuf::from("/opt/google/chrome/google-chrome"),
        PathBuf::from("/opt/google/chrome/chrome"),
        PathBuf::from("/usr/bin/google-chrome"),
        PathBuf::from("/usr/bin/google-chrome-stable"),
        PathBuf::from("/usr/bin/chromium"),
        PathBuf::from("/usr/bin/chromium-browser"),
        PathBuf::from("/usr/bin/microsoft-edge"),
        PathBuf::from("/usr/bin/microsoft-edge-stable"),
        PathBuf::from("/usr/local/bin/chromium"),
        PathBuf::from("/snap/bin/chromium"),
    ]);
    #[cfg(windows)]
    {
        for root in [
            std::env::var_os("PROGRAMFILES"),
            std::env::var_os("PROGRAMFILES(X86)"),
            std::env::var_os("LOCALAPPDATA"),
        ]
        .into_iter()
        .flatten()
        {
            let root = PathBuf::from(root);
            candidates.extend([
                root.join("Google/Chrome/Application/chrome.exe"),
                root.join("Microsoft/Edge/Application/msedge.exe"),
                root.join("Chromium/Application/chrome.exe"),
            ]);
        }
    }
    candidates
}

#[cfg(test)]
async fn validate_navigation_url(value: &str, allow_private_network: bool) -> Result<()> {
    validate_navigation_url_with_resolver(value, allow_private_network, &SystemDestinationResolver)
        .await
}

async fn validate_navigation_url_with_resolver(
    value: &str,
    allow_private_network: bool,
    resolver: &dyn DestinationResolver,
) -> Result<()> {
    if value.len() > 16 * 1_024 {
        bail!("browser URL exceeds the size limit");
    }
    let url = Url::parse(value).context("invalid browser URL")?;
    if url.scheme() == "about" {
        if url.as_str() != "about:blank" {
            bail!("only about:blank is permitted");
        }
        return Ok(());
    }
    validate_web_url_with_resolver(&url, allow_private_network, resolver).await
}

#[cfg(test)]
async fn validate_request_url(value: &str, allow_private_network: bool) -> Result<()> {
    validate_request_url_with_resolver(value, allow_private_network, &SystemDestinationResolver)
        .await
}

async fn validate_request_url_with_resolver(
    value: &str,
    allow_private_network: bool,
    resolver: &dyn DestinationResolver,
) -> Result<()> {
    if value.len() > 1024 * 1_024 {
        bail!("browser request URL exceeds the size limit");
    }
    let url = Url::parse(value).context("invalid browser request URL")?;
    match url.scheme() {
        "about" if url.as_str() == "about:blank" => Ok(()),
        "data" | "blob" => Ok(()),
        "http" | "https" | "ws" | "wss" => {
            validate_web_url_with_resolver(&url, allow_private_network, resolver).await
        }
        _ => bail!("unsupported browser request protocol"),
    }
}

async fn validate_web_url_with_resolver(
    url: &Url,
    allow_private_network: bool,
    resolver: &dyn DestinationResolver,
) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https" | "ws" | "wss") {
        bail!("browser navigation only supports HTTP, HTTPS, WebSocket, and about:blank URLs");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("browser URLs must not contain embedded credentials");
    }
    if allow_private_network {
        return Ok(());
    }
    let host = canonical_destination_host(url.host_str().context("browser URL has no host")?);
    if host == "localhost" || host.ends_with(".localhost") {
        bail!("private-network browser navigation is disabled");
    }
    let port = url
        .port_or_known_default()
        .context("browser URL has no effective port")?;
    let destination = resolver.resolve(&host, port).await?;
    if destination.addresses.is_empty()
        || destination
            .addresses
            .iter()
            .map(std::net::SocketAddr::ip)
            .any(is_non_public_address)
    {
        bail!("browser host resolves to a private or non-routable address");
    }
    Ok(())
}

fn redacted_destination(value: &str) -> String {
    Url::parse(value).map_or_else(
        |_| "invalid-url".to_owned(),
        |url| {
            let host = url.host_str().unwrap_or("local");
            match url.port() {
                Some(port) => format!("{}://{host}:{port}", url.scheme()),
                None => format!("{}://{host}", url.scheme()),
            }
        },
    )
}

fn is_non_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_non_public_ipv4(address),
        IpAddr::V6(address) => is_non_public_ipv6(address),
    }
}

fn is_non_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_unspecified()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && matches!(b, 18 | 19))
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240
}

fn is_non_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let ipv4_compatible = segments[..6] == [0, 0, 0, 0, 0, 0];
    let nat64_well_known = segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0];
    let nat64_local = segments[0..3] == [0x0064, 0xff9b, 0x0001];
    let discard_only = segments[..4] == [0x0100, 0, 0, 0];
    let special_2001 = segments[0] == 0x2001 && segments[1] & 0xfe00 == 0;
    let documentation_2001 = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let documentation_3fff = segments[0] == 0x3fff && segments[1] & 0xf000 == 0;
    let six_to_four = segments[0] == 0x2002;
    let segment_routing = segments[0] == 0x5f00;

    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.to_ipv4_mapped().is_some_and(is_non_public_ipv4)
        || ipv4_compatible
        || nat64_well_known
        || nat64_local
        || discard_only
        || special_2001
        || documentation_2001
        || documentation_3fff
        || six_to_four
        || segment_routing
}

fn validate_selector(selector: &str) -> Result<()> {
    if selector.trim().is_empty() || selector.len() > 8_192 {
        bail!("invalid CSS selector");
    }
    Ok(())
}

fn ensure_private_directory(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing to use a symlinked browser profile directory");
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use futures::FutureExt as _;
    use futures::future::BoxFuture;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    use super::*;
    use crate::network_proxy::ResolvedDestination;

    #[test]
    fn browser_executable_identity_classifies_supported_products() {
        assert_eq!(
            classify_browser_executable(Path::new("/opt/google/chrome/chrome")),
            Some(BrowserProduct::GoogleChrome)
        );
        assert_eq!(
            classify_browser_executable(Path::new("/usr/bin/chromium")),
            Some(BrowserProduct::Chromium)
        );
        assert_eq!(
            classify_browser_executable(Path::new(
                "C:/Program Files/Microsoft/Edge/Application/msedge.exe"
            )),
            Some(BrowserProduct::MicrosoftEdge)
        );
        assert_eq!(
            classify_browser_executable(Path::new(
                "C:/Program Files/Chromium/Application/chrome.exe"
            )),
            Some(BrowserProduct::Chromium)
        );
        assert_eq!(
            classify_browser_executable(Path::new("/usr/bin/firefox")),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn explicit_browser_executable_is_canonicalized_and_must_be_supported() -> Result<()> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let browser = directory.path().join("chromium");
        std::fs::write(&browser, b"#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(&browser, std::fs::Permissions::from_mode(0o700))?;
        let identity = inspect_explicit_browser_executable(&browser)?;
        assert_eq!(identity.source, BrowserExecutableSource::Explicit);
        assert_eq!(identity.product, BrowserProduct::Chromium);
        assert_eq!(identity.path, browser.canonicalize()?);

        let unsupported = directory.path().join("firefox");
        std::fs::write(&unsupported, b"#!/bin/sh\nexit 0\n")?;
        std::fs::set_permissions(&unsupported, std::fs::Permissions::from_mode(0o700))?;
        assert!(inspect_explicit_browser_executable(&unsupported).is_err());
        Ok(())
    }

    #[test]
    fn external_cdp_rejects_remote_host_unsupported_scheme_and_sensitive_url_data() -> Result<()> {
        for endpoint in [
            "http://example.com:9222",
            "ftp://127.0.0.1:9222",
            "http://user:pass@localhost:9222",
            "http://localhost:9222?token=secret",
            "ws://localhost:9222/#session",
        ] {
            assert!(BrowserProfile::external(Url::parse(endpoint)?).is_err());
        }
        assert!(
            BrowserProfile::external(Url::parse("http://localhost:9222/devtools/browser")?).is_ok()
        );
        Ok(())
    }

    #[test]
    fn guarded_browser_arguments_are_process_wide_and_fail_closed() -> Result<()> {
        let address: std::net::SocketAddr = "127.0.0.1:43123".parse()?;
        assert_eq!(
            guarded_browser_arguments(address),
            vec![
                BrowserArgument {
                    key: "proxy-server",
                    value: Some("http://127.0.0.1:43123".to_owned()),
                },
                BrowserArgument {
                    key: "proxy-bypass-list",
                    value: Some("<-loopback>".to_owned()),
                },
                BrowserArgument {
                    key: "host-resolver-rules",
                    value: Some("MAP * ~NOTFOUND, EXCLUDE 127.0.0.1".to_owned()),
                },
                BrowserArgument {
                    key: "force-webrtc-ip-handling-policy",
                    value: Some("disable_non_proxied_udp".to_owned()),
                },
                BrowserArgument {
                    key: "disable-quic",
                    value: None,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn protected_mode_rejects_external_cdp_before_connection() -> Result<()> {
        let external =
            BrowserProfile::external(Url::parse("http://127.0.0.1:9222/devtools/browser")?)?;
        assert!(validate_browser_network_mode(&external, false).is_err());
        assert!(validate_browser_network_mode(&external, true).is_ok());
        assert!(
            validate_browser_network_mode(
                &BrowserProfile::isolated_ephemeral(PathBuf::from("profile")),
                false,
            )
            .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn operation_deadline_resets_and_records_the_session() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let session = BrowserSession::with_operation_timeout(
            BrowserProfile::isolated_ephemeral(temporary.path().join("profile")),
            true,
            false,
            1_024,
            Duration::from_millis(20),
        );
        let result = session
            .run_with_deadline("test_hang", futures::future::pending::<Result<()>>())
            .await;
        let Err(error) = result else {
            bail!("pending browser operation unexpectedly completed");
        };
        assert!(error.to_string().contains("test_hang"));
        assert!(error.to_string().contains("session was reset"));

        let info = session.info_inner().await?;
        assert!(!info.active);
        assert_eq!(info.timeout_recoveries, 1);
        assert_eq!(info.last_timeout_operation.as_deref(), Some("test_hang"));
        Ok(())
    }

    #[tokio::test]
    async fn completed_operation_does_not_record_recovery() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let session = BrowserSession::with_operation_timeout(
            BrowserProfile::isolated_ephemeral(temporary.path().join("profile")),
            true,
            false,
            1_024,
            Duration::from_millis(50),
        );
        let value = session
            .run_with_deadline("test_ready", async { Ok::<_, anyhow::Error>(7_u8) })
            .await?;
        assert_eq!(value, 7);
        assert_eq!(session.timeout_recoveries.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn explicit_executable_state_distinguishes_missing_and_corrupt() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing-chromium");
        assert_eq!(
            browser_executable_state(Some(&missing)),
            BrowserExecutableState::Missing
        );

        let corrupt = directory.path().join("chromium");
        std::fs::write(&corrupt, b"not a browser")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&corrupt, std::fs::Permissions::from_mode(0o600))?;
        }
        assert_eq!(
            browser_executable_state(Some(&corrupt)),
            BrowserExecutableState::Corrupt
        );
        Ok(())
    }

    #[tokio::test]
    async fn external_cdp_disables_local_executable_selection() -> Result<()> {
        let session = BrowserSession::new(
            BrowserProfile::external(Url::parse("http://127.0.0.1:9222")?)?,
            true,
            false,
            1_024,
        );
        let info = session.info_inner().await?;
        assert_eq!(info.executable_state, BrowserExecutableState::Disabled);
        assert_eq!(info.executable_available, None);
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn explicit_executable_identity_is_reported_before_and_after_launch() -> Result<()> {
        let Ok(detected) = resolve_browser_executable(None) else {
            return Ok(());
        };
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("profile");
        let session = BrowserSession::with_executable_and_operation_timeout(
            BrowserProfile::isolated_ephemeral(profile.clone()),
            true,
            false,
            1_024 * 1_024,
            Some(detected.path.clone()),
            Duration::from_secs(10),
        );

        let before = session.info().await?;
        let selected = before
            .selected_executable
            .context("explicit browser selection was not reported")?;
        assert_eq!(
            before.executable_selection,
            Some(BrowserExecutableSource::Explicit)
        );
        assert_eq!(before.executable_available, Some(true));
        assert!(matches!(
            before.executable_state,
            BrowserExecutableState::Available { .. }
        ));
        assert_eq!(selected.source, BrowserExecutableSource::Explicit);
        assert_eq!(selected.product, detected.product);
        assert!(before.active_executable.is_none());

        assert_eq!(session.open("about:blank").await?, "about:blank");
        let after = session.info().await?;
        let active = after
            .active_executable
            .context("active browser executable was not reported")?;
        assert_eq!(active.source, BrowserExecutableSource::Explicit);
        assert_eq!(active.product, detected.product);
        assert!(!active.executable_name.is_empty());
        assert!(!active.executable_name.contains('/'));
        session.close().await?;
        assert!(!profile.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn active_timeout_quarantines_owned_chromium_and_allows_restart() -> Result<()> {
        if !chromium_available() {
            return Ok(());
        }
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("profile");
        let session = BrowserSession::with_operation_timeout(
            BrowserProfile::isolated_ephemeral(profile.clone()),
            true,
            false,
            1_024 * 1_024,
            Duration::from_secs(5),
        );

        assert_eq!(session.open("about:blank").await?, "about:blank");
        let result = session
            .run_with_deadline("test_active_hang", async {
                let _slot = session.active.lock().await;
                futures::future::pending::<Result<()>>().await
            })
            .await;
        let Err(error) = result else {
            bail!("active browser operation unexpectedly completed");
        };
        assert!(error.to_string().contains("test_active_hang"));

        let after_timeout = session.info_inner().await?;
        assert!(!after_timeout.active);
        assert_eq!(after_timeout.timeout_recoveries, 1);
        assert_eq!(
            after_timeout.last_timeout_operation.as_deref(),
            Some("test_active_hang")
        );
        assert!(!profile.exists());

        assert_eq!(session.open("about:blank").await?, "about:blank");
        assert!(session.info().await?.active);
        session.close().await?;
        assert!(!profile.exists());
        Ok(())
    }

    #[tokio::test]
    async fn inactive_policy_url_is_about_blank_without_creating_a_profile() -> Result<()> {
        let temporary = tempfile::tempdir()?;
        let profile = temporary.path().join("profile");
        let session = BrowserSession::new(
            BrowserProfile::isolated_ephemeral(profile.clone()),
            true,
            false,
            1_024,
        );
        assert_eq!(session.policy_url().await?.as_str(), "about:blank");
        assert!(!profile.exists());
        Ok(())
    }

    #[tokio::test]
    async fn navigation_rejects_non_web_protocols_and_credentials() {
        assert!(
            validate_navigation_url("file:///etc/passwd", false)
                .await
                .is_err()
        );
        assert!(
            validate_navigation_url("about:config", false)
                .await
                .is_err()
        );
        assert!(
            validate_navigation_url("https://user:pass@example.com", false)
                .await
                .is_err()
        );
        assert!(validate_navigation_url("about:blank", false).await.is_ok());
    }

    #[tokio::test]
    async fn private_network_is_denied_for_navigation_and_subresources() {
        for url in [
            "http://127.0.0.1:3000",
            "http://10.0.0.1",
            "http://169.254.169.254",
            "http://[::1]",
            "http://localhost",
        ] {
            assert!(validate_navigation_url(url, false).await.is_err());
            assert!(validate_request_url(url, false).await.is_err());
            assert!(validate_navigation_url(url, true).await.is_ok());
        }
    }

    #[test]
    fn special_ipv6_translation_and_documentation_ranges_are_non_public() -> Result<()> {
        for address in [
            "::c0a8:101",
            "::ffff:192.168.1.1",
            "64:ff9b::7f00:1",
            "64:ff9b:1::c0a8:1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002:c0a8:101::1",
            "3fff::1",
            "5f00::1",
        ] {
            assert!(is_non_public_ipv6(address.parse()?));
        }
        assert!(!is_non_public_ipv6("2606:4700:4700::1111".parse()?));
        Ok(())
    }

    #[test]
    fn bounded_text_preserves_utf8_boundaries() {
        let bounded = bound_utf8(
            BoundedValue {
                content: "abé".to_owned(),
                truncated: false,
            },
            3,
        );
        assert_eq!(bounded.content, "ab");
        assert!(bounded.truncated);
    }

    #[test]
    fn ephemeral_profile_cleanup_is_explicit() {
        let profile = BrowserProfile::isolated_ephemeral(PathBuf::from("/tmp/example"));
        assert_eq!(
            profile.cleanup_directory(),
            Some(PathBuf::from("/tmp/example"))
        );
        let persistent = BrowserProfile::isolated_persistent(PathBuf::from("/tmp/example"));
        assert!(persistent.cleanup_directory().is_none());
    }

    #[derive(Debug)]
    struct BrowserTestResolver {
        host: String,
        port: u16,
        connect_address: std::net::SocketAddr,
    }

    impl DestinationResolver for BrowserTestResolver {
        fn resolve<'a>(
            &'a self,
            host: &'a str,
            port: u16,
        ) -> BoxFuture<'a, Result<ResolvedDestination>> {
            async move {
                if host == self.host && port == self.port {
                    return Ok(ResolvedDestination {
                        addresses: vec![std::net::SocketAddr::new(
                            IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                            port,
                        )],
                        connect_override: Some(vec![self.connect_address]),
                    });
                }
                let address = host
                    .parse::<IpAddr>()
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
                Ok(ResolvedDestination {
                    addresses: vec![std::net::SocketAddr::new(address, port)],
                    connect_override: None,
                })
            }
            .boxed()
        }
    }

    async fn spawn_seed_server(
        private_url: String,
    ) -> Result<(
        std::net::SocketAddr,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    )> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        let private_url = private_url.clone();
                        tokio::spawn(async move {
                            let mut request = Vec::new();
                            let mut chunk = [0_u8; 4096];
                            loop {
                                let Ok(read) = stream.read(&mut chunk).await else { return; };
                                if read == 0 { return; }
                                request.extend_from_slice(&chunk[..read]);
                                if request.windows(4).any(|window| window == b"\r\n\r\n")
                                    || request.len() > 64 * 1024
                                {
                                    break;
                                }
                            }
                            let first_line = String::from_utf8_lossy(&request)
                                .lines()
                                .next()
                                .unwrap_or_default()
                                .to_owned();
                            let (content_type, body) = if first_line.contains(" /sw.js ") {
                                (
                                    "application/javascript",
                                    format!(
                                        "self.addEventListener('message', event => {{ fetch('{private_url}/service-worker', {{mode:'no-cors'}}).then(() => event.source.postMessage('proxy-response')).catch(() => event.source.postMessage('blocked')); }});"
                                    ),
                                )
                            } else {
                                (
                                    "text/html",
                                    "<!doctype html><meta charset=utf-8><title>RunOnMine browser network test</title><body>ready</body>".to_owned(),
                                )
                            };
                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nCache-Control: no-store\r\nService-Worker-Allowed: /\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ignored = stream.write_all(response.as_bytes()).await;
                        });
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });
        Ok((address, shutdown, task))
    }

    async fn spawn_private_probe() -> Result<(
        std::net::SocketAddr,
        Arc<AtomicUsize>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    )> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&connections);
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        observed.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(async move {
                            let mut buffer = [0_u8; 4096];
                            let _ignored = stream.read(&mut buffer).await;
                            let _ignored = stream.write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                            ).await;
                        });
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
        });
        Ok((address, connections, shutdown, task))
    }

    fn browser_attack_script(
        private_url: &str,
        private_address: std::net::SocketAddr,
    ) -> Result<String> {
        let script = include_str!("../tests/fixtures/network_attacks.js");
        Ok(script
            .replace(
                "__PRIVATE_HTTP_JSON__",
                &serde_json::to_string(private_url)?,
            )
            .replace(
                "__PRIVATE_WS_JSON__",
                &serde_json::to_string(&format!("ws://{private_address}"))?,
            )
            .replace("__PRIVATE_PORT__", &private_address.port().to_string()))
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn browser_wide_proxy_blocks_popup_workers_websocket_and_rebinding() -> Result<()> {
        if !chromium_available() {
            return Ok(());
        }
        let (private_address, private_connections, private_shutdown, private_task) =
            spawn_private_probe().await?;
        let private_url = format!("http://{private_address}");
        let (seed_address, seed_shutdown, seed_task) =
            spawn_seed_server(private_url.clone()).await?;
        let public_host = "public.browser.test";
        let public_origin = format!("http://{public_host}:{}", seed_address.port());
        let resolver = Arc::new(BrowserTestResolver {
            host: public_host.to_owned(),
            port: seed_address.port(),
            connect_address: seed_address,
        });
        let temporary = tempfile::tempdir()?;
        let session = BrowserSession::with_network_test_support(
            BrowserProfile::isolated_ephemeral(temporary.path().join("profile")),
            true,
            1024 * 1024,
            resolver,
            vec![(
                "unsafely-treat-insecure-origin-as-secure".to_owned(),
                public_origin.clone(),
            )],
        );
        session.open(&format!("{public_origin}/")).await?;
        let script = browser_attack_script(&private_url, private_address)?;
        let result = session.evaluate(&script).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        let private_connection_count = private_connections.load(Ordering::SeqCst);

        session.close().await?;
        let _ignored = seed_shutdown.send(());
        let _ignored = private_shutdown.send(());
        seed_task.await?;
        private_task.await?;

        for key in [
            "fetch",
            "worker",
            "sharedWorker",
            "serviceWorker",
            "rebinding",
        ] {
            let outcome = result
                .get(key)
                .and_then(serde_json::Value::as_str)
                .with_context(|| format!("browser probe {key} produced no result: {result}"))?;
            assert!(
                matches!(outcome, "blocked" | "proxy-response"),
                "browser probe {key} did not complete through the guarded network path: {result}"
            );
        }
        assert_eq!(result["websocket"], "blocked", "WebSocket result: {result}");
        assert!(
            matches!(result["popup"].as_str(), Some("attempted" | "blocked")),
            "popup target did not execute: {result}"
        );
        assert_eq!(
            private_connection_count, 0,
            "a popup, worker, WebSocket, background target, or rebinding request reached the private probe: {result}"
        );
        Ok(())
    }
}
