//! Isolated browser-profile and CDP automation primitives.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::cdp::browser_protocol::page::CaptureScreenshotFormat;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::StreamExt;
use serde::Serialize;
use tokio::sync::{Mutex, MutexGuard};
use url::Url;

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserProfile {
    Isolated { directory: PathBuf },
    ExternalCdp { endpoint: Url },
}

impl BrowserProfile {
    pub fn external(endpoint: Url) -> Result<Self> {
        let host = endpoint.host_str().unwrap_or_default();
        if !matches!(host, "127.0.0.1" | "::1" | "localhost") {
            bail!("external CDP endpoints must use loopback");
        }
        Ok(Self::ExternalCdp { endpoint })
    }
}

#[derive(Debug, Serialize)]
pub struct BrowserSessionInfo {
    pub profile: BrowserProfile,
    pub active: bool,
    pub current_url: Option<String>,
}

#[derive(Debug)]
struct ActiveBrowser {
    browser: Browser,
    page: Page,
    handler_task: tokio::task::JoinHandle<()>,
    owned_process: bool,
}

#[derive(Debug)]
pub struct BrowserSession {
    profile: BrowserProfile,
    headless: bool,
    allow_private_network: bool,
    active: Mutex<Option<ActiveBrowser>>,
}

impl BrowserSession {
    pub fn new(profile: BrowserProfile, headless: bool, allow_private_network: bool) -> Self {
        Self {
            profile,
            headless,
            allow_private_network,
            active: Mutex::new(None),
        }
    }

    pub async fn open(&self, url: &str) -> Result<String> {
        validate_navigation_url(url, self.allow_private_network).await?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        let page = active.browser.new_page(url).await?;
        active.page = page;
        Ok(active.page.url().await?.unwrap_or_else(|| url.to_owned()))
    }

    pub async fn navigate(&self, url: &str) -> Result<String> {
        validate_navigation_url(url, self.allow_private_network).await?;
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.goto(url).await?;
        Ok(active.page.url().await?.unwrap_or_else(|| url.to_owned()))
    }

    pub async fn current_url(&self) -> Result<Option<String>> {
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.url().await.map_err(Into::into)
    }

    pub async fn text(&self) -> Result<String> {
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active
            .page
            .evaluate("() => document.body ? document.body.innerText : ''")
            .await?
            .into_value()
            .map_err(Into::into)
    }

    pub async fn snapshot(&self) -> Result<String> {
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active.page.content().await.map_err(Into::into)
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
        active
            .page
            .screenshot(
                ScreenshotParams::builder()
                    .format(CaptureScreenshotFormat::Jpeg)
                    .quality(i64::from(quality.clamp(10, 90)))
                    .full_page(full_page)
                    .build(),
            )
            .await
            .map_err(Into::into)
    }

    pub async fn evaluate(&self, expression: &str) -> Result<serde_json::Value> {
        if expression.len() > 256 * 1_024 {
            bail!("browser expression exceeds the size limit");
        }
        let mut slot = self.ensure_active().await?;
        let active = slot.as_mut().context("browser session is unavailable")?;
        active
            .page
            .evaluate(expression)
            .await?
            .into_value()
            .map_err(Into::into)
    }

    pub async fn close(&self) -> Result<()> {
        let mut slot = self.active.lock().await;
        let Some(mut active) = slot.take() else {
            return Ok(());
        };
        let _result = active.page.close().await;
        if active.owned_process {
            let _result = active.browser.close().await;
            let _result = tokio::time::timeout(Duration::from_secs(5), active.browser.wait()).await;
        }
        active.handler_task.abort();
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
                BrowserProfile::Isolated { directory } => {
                    std::fs::create_dir_all(directory)?;
                    let mut builder = BrowserConfig::builder()
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
            let page = browser.pages().await?.into_iter().next();
            let page = match page {
                Some(page) => page,
                None => browser.new_page("about:blank").await?,
            };
            *slot = Some(ActiveBrowser {
                browser,
                page,
                handler_task,
                owned_process,
            });
        }
        Ok(slot)
    }
}

pub fn chromium_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        if [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
        .iter()
        .any(|path| std::path::Path::new(path).is_file())
        {
            return true;
        }
    }
    #[cfg(windows)]
    let candidates = ["chrome.exe", "msedge.exe", "chromium.exe"];
    #[cfg(not(windows))]
    let candidates = ["google-chrome", "chromium", "chromium-browser"];
    candidates.iter().any(|candidate| {
        Command::new(candidate)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    })
}

async fn validate_navigation_url(value: &str, allow_private_network: bool) -> Result<()> {
    let url = Url::parse(value).context("invalid browser URL")?;
    if url.scheme() == "about" {
        if url.as_str() != "about:blank" {
            bail!("only about:blank is permitted");
        }
        return Ok(());
    }
    if !matches!(url.scheme(), "http" | "https") {
        bail!("browser navigation only supports HTTP, HTTPS, and about:blank URLs");
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_cdp_rejects_remote_host() -> Result<()> {
        let endpoint = Url::parse("http://example.com:9222")?;
        assert!(BrowserProfile::external(endpoint).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn navigation_rejects_non_web_protocols() {
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
        assert!(validate_navigation_url("about:blank", false).await.is_ok());
    }

    #[tokio::test]
    async fn private_network_is_denied_unless_explicitly_enabled() {
        for url in [
            "http://127.0.0.1:3000",
            "http://10.0.0.1",
            "http://169.254.169.254",
            "http://[::1]",
            "http://localhost",
        ] {
            assert!(validate_navigation_url(url, false).await.is_err());
            assert!(validate_navigation_url(url, true).await.is_ok());
        }
    }
}
