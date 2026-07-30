use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use runonmine_core::secrets::{default_secret_store, recover_pending_config_secret_transaction};
use runonmine_core::{
    AppConfig, AppPaths, ApprovalRequest, AuditRecord, AuditVerificationReport, ConnectorKind,
    PersistentGrant, QuickTunnelRuntimeStore, StateStore,
};
use runonmine_oauth::{OAuthSession, RegisteredClient, SqliteOAuthStore};
use serde::Deserialize;
use url::Url;

const HEALTH_TIMEOUT: Duration = Duration::from_millis(250);
const MAX_HEALTH_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ConnectorLifecycle {
    pub(crate) connector_id: String,
    pub(crate) kind: ConnectorKind,
    pub(crate) phase: String,
    #[serde(default)]
    pub(crate) stage: Option<String>,
    #[serde(default)]
    pub(crate) message: Option<String>,
}

#[derive(Debug)]
pub(crate) struct DesktopSnapshot {
    pub(crate) config: AppConfig,
    pub(crate) pending: Vec<ApprovalRequest>,
    pub(crate) persistent_grants: Vec<PersistentGrant>,
    pub(crate) audit: Vec<AuditRecord>,
    pub(crate) audit_verification: AuditVerificationReport,
    pub(crate) oauth_clients: Vec<RegisteredClient>,
    pub(crate) oauth_sessions: Vec<OAuthSession>,
    pub(crate) quick_runtime_urls: HashMap<String, Url>,
    pub(crate) connector_lifecycle: HashMap<String, ConnectorLifecycle>,
    pub(crate) agent_reachable: bool,
}

pub(crate) struct BackgroundDesktopSnapshot {
    result: Receiver<std::result::Result<DesktopSnapshot, String>>,
    thread: Option<JoinHandle<()>>,
}

impl BackgroundDesktopSnapshot {
    pub(crate) fn spawn(paths: AppPaths, audit_limit: usize) -> Self {
        let (sender, result) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let snapshot = load_snapshot(&paths, audit_limit).map_err(|error| error.to_string());
            let _ignored = sender.send(snapshot);
        });
        Self {
            result,
            thread: Some(thread),
        }
    }

    pub(crate) fn try_take(&mut self) -> Option<std::result::Result<DesktopSnapshot, String>> {
        match self.result.try_recv() {
            Ok(result) => {
                self.join();
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.join();
                Some(Err(
                    "desktop snapshot worker stopped unexpectedly".to_owned()
                ))
            }
        }
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ignored = thread.join();
        }
    }
}

impl Drop for BackgroundDesktopSnapshot {
    fn drop(&mut self) {
        self.join();
    }
}

fn load_snapshot(paths: &AppPaths, audit_limit: usize) -> Result<DesktopSnapshot> {
    let secrets = default_secret_store(paths)?;
    recover_pending_config_secret_transaction(&paths.config_file(), secrets.as_ref())?;
    let config = AppConfig::load(&paths.config_file())?;
    let store = StateStore::open(&paths.state_db())?;
    let pending = store.pending_approvals()?;
    let persistent_grants = store.persistent_grants(None)?;
    let audit = store.audit_tail(audit_limit)?;
    let audit_verification = store.verify_audit_chain_incremental()?;
    let oauth = SqliteOAuthStore::open(&paths.state_db())?;
    let oauth_clients = oauth.registered_clients()?;
    let oauth_sessions = oauth.sessions(None)?;
    let quick_runtime_urls = quick_runtime_urls(paths, &config)?;
    let (agent_reachable, connector_lifecycle) = connector_health(config.port);
    Ok(DesktopSnapshot {
        config,
        pending,
        persistent_grants,
        audit,
        audit_verification,
        oauth_clients,
        oauth_sessions,
        quick_runtime_urls,
        connector_lifecycle,
        agent_reachable,
    })
}

fn quick_runtime_urls(paths: &AppPaths, config: &AppConfig) -> Result<HashMap<String, Url>> {
    let runtime = QuickTunnelRuntimeStore::new(paths);
    let mut urls = HashMap::new();
    for connector in config
        .connectors
        .iter()
        .filter(|connector| connector.kind == ConnectorKind::CloudflareQuick)
    {
        if let Some(url) = runtime
            .get(&connector.id)?
            .and_then(|record| record.public_url)
        {
            urls.insert(connector.id.clone(), url);
        }
    }
    Ok(urls)
}

#[derive(Deserialize)]
struct ConnectorHealthResponse {
    connectors: Vec<ConnectorLifecycle>,
}

fn connector_health(port: u16) -> (bool, HashMap<String, ConnectorLifecycle>) {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, HEALTH_TIMEOUT) else {
        return (false, HashMap::new());
    };
    if stream.set_read_timeout(Some(HEALTH_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(HEALTH_TIMEOUT)).is_err()
    {
        return (true, HashMap::new());
    }
    let request = format!(
        "GET /healthz/connectors HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).is_err() {
        return (true, HashMap::new());
    }
    let Ok(bytes) = read_bounded_response(&mut stream) else {
        return (true, HashMap::new());
    };
    let Ok(response) = parse_health_response(&bytes) else {
        return (true, HashMap::new());
    };
    (
        true,
        response
            .connectors
            .into_iter()
            .map(|status| (status.connector_id.clone(), status))
            .collect(),
    )
}

fn read_bounded_response(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > MAX_HEALTH_RESPONSE_BYTES {
            bail!("connector health response exceeds the desktop limit");
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

fn parse_health_response(bytes: &[u8]) -> Result<ConnectorHealthResponse> {
    let separator = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("connector health response has no header boundary")?;
    let headers = std::str::from_utf8(&bytes[..separator])?;
    let status = headers
        .lines()
        .next()
        .context("connector health response has no status line")?;
    if !status.starts_with("HTTP/1.1 200 ") && !status.starts_with("HTTP/1.0 200 ") {
        bail!("connector health endpoint did not return success");
    }
    serde_json::from_slice(&bytes[separator + 4..])
        .context("connector health response is not valid JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bounded_connector_health_response() -> Result<()> {
        let body = br#"{"status":"degraded","connectors":[{"connector_id":"connector-a","kind":"open_ai_tunnel","phase":"backoff","stage":"readiness","message":"waiting"}]}"#;
        let mut response = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n".to_vec();
        response.extend_from_slice(body);
        let parsed = parse_health_response(&response)?;
        assert_eq!(parsed.connectors.len(), 1);
        assert_eq!(parsed.connectors[0].connector_id, "connector-a");
        assert_eq!(parsed.connectors[0].phase, "backoff");
        Ok(())
    }
}
