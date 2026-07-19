use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use url::{Host, Url};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HealthCheck {
    Disabled,
    Tcp {
        address: SocketAddr,
        timeout: Duration,
    },
    Http {
        url: Url,
        timeout: Duration,
        accepted_statuses: Vec<u16>,
    },
}

impl HealthCheck {
    pub fn loopback_http(url: Url, timeout: Duration, accepted_statuses: Vec<u16>) -> Result<Self> {
        validate_loopback_url(&url)?;
        if timeout.is_zero() {
            bail!("health-check timeout must be greater than zero");
        }
        if accepted_statuses.is_empty()
            || accepted_statuses
                .iter()
                .any(|status| !(100..=599).contains(status))
        {
            bail!("HTTP health check requires valid accepted status codes");
        }
        Ok(Self::Http {
            url,
            timeout,
            accepted_statuses,
        })
    }

    pub fn loopback_tcp(address: SocketAddr, timeout: Duration) -> Result<Self> {
        if !address.ip().is_loopback() {
            bail!("health-check address must be loopback");
        }
        if timeout.is_zero() {
            bail!("health-check timeout must be greater than zero");
        }
        Ok(Self::Tcp { address, timeout })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HealthCheckResult {
    pub healthy: bool,
    pub status: Option<u16>,
    pub latency_ms: u64,
    pub detail: String,
}

#[derive(Clone, Debug)]
pub struct HealthChecker {
    http: reqwest::Client,
}

impl HealthChecker {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(Policy::none())
            .user_agent(concat!("RunOnMine/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("failed to build connector health client")?;
        Ok(Self { http })
    }

    pub async fn check(&self, check: &HealthCheck) -> HealthCheckResult {
        let started = Instant::now();
        let (healthy, status, detail) = match check {
            HealthCheck::Disabled => (true, None, "health check disabled".to_owned()),
            HealthCheck::Tcp { address, timeout } => {
                match tokio::time::timeout(*timeout, TcpStream::connect(address)).await {
                    Ok(Ok(_stream)) => {
                        (true, None, "TCP endpoint accepted a connection".to_owned())
                    }
                    Ok(Err(_error)) => (false, None, "TCP endpoint is unavailable".to_owned()),
                    Err(_) => (false, None, "TCP health check timed out".to_owned()),
                }
            }
            HealthCheck::Http {
                url,
                timeout,
                accepted_statuses,
            } => match tokio::time::timeout(*timeout, self.http.get(url.clone()).send()).await {
                Ok(Ok(response)) => {
                    let status = response.status().as_u16();
                    let healthy = accepted_statuses.contains(&status);
                    let detail = if healthy {
                        "HTTP endpoint is healthy"
                    } else {
                        "HTTP endpoint returned an unexpected status"
                    };
                    (healthy, Some(status), detail.to_owned())
                }
                Ok(Err(_error)) => (false, None, "HTTP endpoint is unavailable".to_owned()),
                Err(_) => (false, None, "HTTP health check timed out".to_owned()),
            },
        };
        HealthCheckResult {
            healthy,
            status,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            detail,
        }
    }
}

pub(crate) fn validate_loopback_url(url: &Url) -> Result<()> {
    if url.scheme() != "http" {
        bail!("local health URL must use plain HTTP over loopback");
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() {
        bail!("local health URL must not contain credentials or query parameters");
    }
    let is_loopback = match url.host() {
        Some(Host::Ipv4(address)) => IpAddr::V4(address).is_loopback(),
        Some(Host::Ipv6(address)) => IpAddr::V6(address).is_loopback(),
        Some(Host::Domain(_)) | None => false,
    };
    if !is_loopback {
        bail!("local health URL must use an explicit loopback IP address");
    }
    if url.port().is_none() {
        bail!("local health URL must include an explicit port");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_explicit_loopback_health_urls() -> Result<()> {
        assert!(validate_loopback_url(&Url::parse("http://127.0.0.1:44123/readyz")?).is_ok());
        assert!(validate_loopback_url(&Url::parse("http://[::1]:44123/readyz")?).is_ok());
        assert!(validate_loopback_url(&Url::parse("http://localhost:44123/readyz")?).is_err());
        assert!(validate_loopback_url(&Url::parse("https://127.0.0.1:44123/readyz")?).is_err());
        assert!(validate_loopback_url(&Url::parse("http://10.0.0.1:44123/readyz")?).is_err());
        Ok(())
    }

    #[test]
    fn rejects_redirect_status_when_not_allowlisted() -> Result<()> {
        let check = HealthCheck::loopback_http(
            Url::parse("http://127.0.0.1:44123/readyz")?,
            Duration::from_secs(1),
            vec![200, 204],
        )?;
        match check {
            HealthCheck::Http {
                accepted_statuses, ..
            } => assert!(!accepted_statuses.contains(&302)),
            _ => unreachable!(),
        }
        Ok(())
    }
}
