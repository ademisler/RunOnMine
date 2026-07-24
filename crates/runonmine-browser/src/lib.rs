//! Isolated browser-profile and CDP automation primitives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::fetch::{
    ContinueRequestParams, DisableParams as FetchDisableParams, EnableParams as FetchEnableParams,
    EventRequestPaused, FailRequestParams,
};
use chromiumoxide::cdp::browser_protocol::network::ErrorReason;
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, MutexGuard};
use url::Url;

const MAX_BROWSER_INPUT_BYTES: usize = 256 * 1_024;

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
        {
            bail!("external CDP endpoints must use loopback HTTP or WebSocket transport");
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

#[derive(Debug, Serialize)]
pub struct BrowserSessionInfo {
    pub profile: BrowserProfile,
    pub active: bool,
    pub current_url: Option<String>,
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
    owned_process: bool,
    page_owned: bool,
}

#[derive(Debug)]
pub struct BrowserSession {
    profile: BrowserProfile,
    headless: bool,
    allow_private_network: bool,
    max_output_bytes: usize,
    active: Mutex<Option<ActiveBrowser>>,
}

impl BrowserSession {
    pub fn new(
        profile: BrowserProfile,
        headless: bool,
        allow_private_network: bool,
        max_output_bytes: usize,
    ) -> Self {
        Self {
            profile,
            headless,
            allow_private_network,
            max_output_bytes: max_output_bytes.max(1),
            active: Mutex::new(None),
        }
    }

    pub async fn open(&self, url: &str) -> Result<String> {
        validate_navigation_url(url, self.allow_private_network).await?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let page = active.browser.new_page("about:blank").await?;
        let interceptor_task = install_request_guard(&page, self.allow_private_network).await?;
        if let Err(error) = page.goto(url).await {
            interceptor_task.abort();
            let _ignored = page.close().await;
            return Err(error.into());
        }
        let current_url = page.url().await?.unwrap_or_else(|| url.to_owned());
        stop_request_guard(&active.page, &active.interceptor_task).await;
        if active.page_owned {
            let _ignored = active.page.clone().close().await;
        }
        active.page = page;
        active.page_owned = true;
        active.interceptor_task = interceptor_task;
        Ok(current_url)
    }

    pub async fn navigate(&self, url: &str) -> Result<String> {
        validate_navigation_url(url, self.allow_private_network).await?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.goto(url).await?;
        let current = active.page.url().await?.unwrap_or_else(|| url.to_owned());
        validate_navigation_url(&current, self.allow_private_network).await?;
        Ok(current)
    }

    pub async fn current_url(&self) -> Result<Option<String>> {
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.url().await.map_err(Into::into)
    }

    pub async fn text(&self) -> Result<BoundedBrowserText> {
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

    pub async fn snapshot(&self) -> Result<BoundedBrowserText> {
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

    pub async fn click(&self, selector: &str) -> Result<()> {
        validate_selector(selector)?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.find_element(selector).await?.click().await?;
        Ok(())
    }

    pub async fn type_text(&self, selector: &str, text: &str) -> Result<()> {
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

    pub async fn press(&self, key: &str) -> Result<()> {
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

    pub async fn screenshot_jpeg(&self, quality: u8, full_page: bool) -> Result<Vec<u8>> {
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

    pub async fn evaluate(&self, expression: &str) -> Result<serde_json::Value> {
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

    pub async fn close(&self) -> Result<()> {
        let mut slot = self.active.lock().await;
        let Some(mut active) = slot.take() else {
            self.cleanup_profile();
            return Ok(());
        };
        stop_request_guard(&active.page, &active.interceptor_task).await;
        if active.page_owned {
            let _result = active.page.close().await;
        }
        if active.owned_process {
            let _result = active.browser.close().await;
            let _result = tokio::time::timeout(Duration::from_secs(5), active.browser.wait()).await;
        }
        active.handler_task.abort();
        self.cleanup_profile();
        Ok(())
    }

    pub async fn info(&self) -> Result<BrowserSessionInfo> {
        let slot = self.active.lock().await;
        let current_url = match slot.as_ref() {
            Some(active) => active.page.url().await?,
            None => None,
        };
        Ok(BrowserSessionInfo {
            profile: self.profile.clone(),
            active: slot.is_some(),
            current_url,
        })
    }

    async fn ensure_active(&self) -> Result<MutexGuard<'_, Option<ActiveBrowser>>> {
        let mut slot = self.active.lock().await;
        if slot.is_none() {
            let (mut browser, mut handler, owned_process) = match &self.profile {
                BrowserProfile::Isolated { directory, .. } => {
                    ensure_private_directory(directory)?;
                    let executable = chromium_executable()
                        .context("a supported Chromium installation was not found")?;
                    let mut builder = BrowserConfig::builder()
                        .chrome_executable(executable)
                        .user_data_dir(directory)
                        .window_size(1_280, 900)
                        .launch_timeout(Duration::from_secs(30))
                        .request_timeout(Duration::from_mins(1));
                    if !self.headless {
                        builder = builder.with_head();
                    }
                    let config = builder.build().map_err(anyhow::Error::msg)?;
                    let (browser, handler) = Browser::launch(config).await?;
                    (browser, handler, true)
                }
                BrowserProfile::ExternalCdp { endpoint } => {
                    let (browser, handler) = Browser::connect(endpoint.to_string()).await?;
                    (browser, handler, false)
                }
            };
            let handler_task = tokio::spawn(async move {
                while let Some(event) = handler.next().await {
                    if let Err(error) = event {
                        tracing::warn!(%error, "Chromium handler stopped");
                        break;
                    }
                }
            });
            if !owned_process {
                browser.fetch_targets().await?;
            }
            let existing_page = browser.pages().await?.into_iter().next();
            let (page, page_owned) = match existing_page {
                Some(page) => (page, owned_process),
                None => (browser.new_page("about:blank").await?, true),
            };
            let interceptor_task = install_request_guard(&page, self.allow_private_network).await?;
            *slot = Some(ActiveBrowser {
                browser,
                page,
                handler_task,
                interceptor_task,
                owned_process,
                page_owned,
            });
        }
        Ok(slot)
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
        {
            let page = active.page.clone();
            let interceptor_task = active.interceptor_task;
            let handler_task = active.handler_task;
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    let _ignored = page.execute(FetchDisableParams::default()).await;
                    interceptor_task.abort();
                    handler_task.abort();
                });
            } else {
                interceptor_task.abort();
                handler_task.abort();
            }
        }
        if let Some(directory) = self.profile.cleanup_directory() {
            std::thread::spawn(move || {
                for delay in [50_u64, 200, 500, 1_000] {
                    std::thread::sleep(Duration::from_millis(delay));
                    if !directory.exists() || std::fs::remove_dir_all(&directory).is_ok() {
                        return;
                    }
                }
            });
        }
    }
}

async fn stop_request_guard(page: &Page, task: &tokio::task::JoinHandle<()>) {
    let _ignored = page.execute(FetchDisableParams::default()).await;
    task.abort();
}

async fn install_request_guard(
    page: &Page,
    allow_private_network: bool,
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
                    validate_request_url(&event.request.url, allow_private_network)
                        .await
                        .is_ok()
                };
            let result = if allowed {
                guarded_page
                    .execute(ContinueRequestParams::new(request_id))
                    .await
                    .map(|_| ())
            } else {
                tracing::warn!(
                    destination = %redacted_destination(&event.request.url),
                    "blocked browser request to a private or unsupported destination"
                );
                guarded_page
                    .execute(FailRequestParams::new(
                        request_id,
                        ErrorReason::BlockedByClient,
                    ))
                    .await
                    .map(|_| ())
            };
            if let Err(error) = result {
                tracing::debug!(%error, "browser request interception ended");
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
    chromium_executable().is_some()
}

pub fn chromium_executable() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    #[cfg(target_os = "macos")]
    candidates.extend([
        PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
        PathBuf::from("/Applications/Chromium.app/Contents/MacOS/Chromium"),
        PathBuf::from("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    ]);
    #[cfg(target_os = "linux")]
    candidates.extend([
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
    candidates.into_iter().find(|path| {
        std::fs::symlink_metadata(path)
            .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
    })
}

async fn validate_navigation_url(value: &str, allow_private_network: bool) -> Result<()> {
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
    validate_web_url(&url, allow_private_network).await
}

async fn validate_request_url(value: &str, allow_private_network: bool) -> Result<()> {
    if value.len() > 1024 * 1_024 {
        bail!("browser request URL exceeds the size limit");
    }
    let url = Url::parse(value).context("invalid browser request URL")?;
    match url.scheme() {
        "about" if url.as_str() == "about:blank" => Ok(()),
        "data" | "blob" => Ok(()),
        "http" | "https" => validate_web_url(&url, allow_private_network).await,
        _ => bail!("unsupported browser request protocol"),
    }
}

async fn validate_web_url(url: &Url, allow_private_network: bool) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https") {
        bail!("browser navigation only supports HTTP, HTTPS, and about:blank URLs");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("browser URLs must not contain embedded credentials");
    }
    if allow_private_network {
        return Ok(());
    }
    let host = url.host_str().context("browser URL has no host")?;
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        bail!("private-network browser navigation is disabled");
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        if is_non_public_address(address) {
            bail!("private-network browser navigation is disabled");
        }
        return Ok(());
    }
    let port = url
        .port_or_known_default()
        .context("browser URL has no effective port")?;
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .context("browser host could not be resolved")?;
    if addresses
        .map(|address| address.ip())
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
    address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.to_ipv4_mapped().is_some_and(is_non_public_ipv4)
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
    use super::*;

    #[test]
    fn external_cdp_rejects_remote_host_and_unsupported_scheme() -> Result<()> {
        let endpoint = Url::parse("http://example.com:9222")?;
        assert!(BrowserProfile::external(endpoint).is_err());
        let endpoint = Url::parse("ftp://127.0.0.1:9222")?;
        assert!(BrowserProfile::external(endpoint).is_err());
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
}
