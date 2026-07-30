use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::FutureExt as _;
use futures::future::BoxFuture;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio::task::{JoinHandle, JoinSet};
use url::Url;

use crate::is_non_public_address;

const MAX_PROXY_HEADER_BYTES: usize = 64 * 1_024;
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_PROXY_CONNECTIONS: usize = 64;

#[derive(Debug)]
pub(super) struct ResolvedDestination {
    pub(super) addresses: Vec<SocketAddr>,
    #[cfg(test)]
    pub(super) connect_override: Option<Vec<SocketAddr>>,
}

impl ResolvedDestination {
    fn into_connect_addresses(self) -> Vec<SocketAddr> {
        #[cfg(test)]
        if let Some(override_addresses) = self.connect_override {
            return override_addresses;
        }
        self.addresses
    }
}

pub(super) trait DestinationResolver: fmt::Debug + Send + Sync {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<ResolvedDestination>>;
}

#[derive(Clone, Debug, Default)]
pub(super) struct SystemDestinationResolver;

impl DestinationResolver for SystemDestinationResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> BoxFuture<'a, Result<ResolvedDestination>> {
        async move {
            let mut addresses = if let Ok(address) = host.parse::<IpAddr>() {
                vec![SocketAddr::new(address, port)]
            } else {
                tokio::net::lookup_host((host, port))
                    .await
                    .context("browser proxy destination could not be resolved")?
                    .collect::<Vec<_>>()
            };
            addresses.sort_unstable();
            addresses.dedup();
            if addresses.is_empty() {
                bail!("browser proxy destination resolved to no addresses");
            }
            Ok(ResolvedDestination {
                addresses,
                #[cfg(test)]
                connect_override: None,
            })
        }
        .boxed()
    }
}

pub(super) struct BrowserNetworkGuard {
    address: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl fmt::Debug for BrowserNetworkGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrowserNetworkGuard")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl BrowserNetworkGuard {
    pub(super) async fn start(resolver: Arc<dyn DestinationResolver>) -> Result<Self> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("failed to bind browser network guard")?;
        let address = listener.local_addr()?;
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let connections = Arc::new(Semaphore::new(MAX_PROXY_CONNECTIONS));
        let task = tokio::spawn(async move {
            let mut connection_tasks = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, peer)) = result else {
                            break;
                        };
                        if !peer.ip().is_loopback() {
                            continue;
                        }
                        let Ok(permit) = Arc::clone(&connections).try_acquire_owned() else {
                            continue;
                        };
                        let resolver = Arc::clone(&resolver);
                        connection_tasks.spawn(async move {
                            let _permit = permit;
                            if let Err(error) = serve_connection(stream, resolver).await {
                                tracing::debug!(%error, "browser network guard connection ended");
                            }
                        });
                    }
                    Some(_result) = connection_tasks.join_next(), if !connection_tasks.is_empty() => {}
                    _ = &mut shutdown_rx => break,
                }
            }
            connection_tasks.abort_all();
            while connection_tasks.join_next().await.is_some() {}
        });
        Ok(Self {
            address,
            shutdown: Some(shutdown),
            task: Some(task),
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(super) async fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ignored = shutdown.send(());
        }
        if let Some(mut task) = self.task.take()
            && tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
        {
            task.abort();
            let _ignored = task.await;
        }
    }
}

impl Drop for BrowserNetworkGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ignored = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[derive(Debug)]
enum ProxyRequest {
    Connect {
        host: String,
        port: u16,
        buffered: Vec<u8>,
    },
    Forward {
        host: String,
        port: u16,
        request: Vec<u8>,
    },
}

async fn serve_connection(
    mut client: TcpStream,
    resolver: Arc<dyn DestinationResolver>,
) -> Result<()> {
    let request = match read_proxy_request(&mut client).await {
        Ok(request) => request,
        Err(error) => {
            let _ignored = write_proxy_error(&mut client, "400 Bad Request").await;
            return Err(error);
        }
    };
    let result = match request {
        ProxyRequest::Connect {
            host,
            port,
            buffered,
        } => serve_connect(&mut client, &host, port, &buffered, resolver.as_ref()).await,
        ProxyRequest::Forward {
            host,
            port,
            request,
        } => serve_forward(&mut client, &host, port, &request, resolver.as_ref()).await,
    };
    if let Err(error) = result {
        // A policy denial must surface as a network failure. Returning an HTTP
        // status would make opaque `no-cors` fetches appear successful even
        // though the protected destination was never reached.
        let _ignored = client.shutdown().await;
        return Err(error);
    }
    Ok(())
}

async fn serve_connect(
    client: &mut TcpStream,
    host: &str,
    port: u16,
    buffered: &[u8],
    resolver: &dyn DestinationResolver,
) -> Result<()> {
    let mut upstream = connect_public_destination(host, port, resolver).await?;
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\nConnection: close\r\n\r\n")
        .await?;
    if !buffered.is_empty() {
        upstream.write_all(buffered).await?;
    }
    let _transferred = tokio::io::copy_bidirectional(client, &mut upstream).await?;
    Ok(())
}

async fn serve_forward(
    client: &mut TcpStream,
    host: &str,
    port: u16,
    request: &[u8],
    resolver: &dyn DestinationResolver,
) -> Result<()> {
    let mut upstream = connect_public_destination(host, port, resolver).await?;
    upstream.write_all(request).await?;
    let _transferred = tokio::io::copy_bidirectional(client, &mut upstream).await?;
    Ok(())
}

async fn connect_public_destination(
    host: &str,
    port: u16,
    resolver: &dyn DestinationResolver,
) -> Result<TcpStream> {
    if port == 0 {
        bail!("browser proxy rejected destination port zero");
    }
    let host = canonical_destination_host(host);
    if host == "localhost" || host.ends_with(".localhost") {
        bail!("browser proxy rejected a local hostname");
    }
    let destination = resolver.resolve(&host, port).await?;
    if destination.addresses.is_empty()
        || destination
            .addresses
            .iter()
            .map(std::net::SocketAddr::ip)
            .any(is_non_public_address)
    {
        bail!("browser proxy rejected a private or non-routable destination");
    }
    let mut last_error = None;
    for address in destination.into_connect_addresses() {
        match tokio::time::timeout(PROXY_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error.into()),
            Err(error) => last_error = Some(error.into()),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("browser proxy could not connect")))
}

async fn read_proxy_request(stream: &mut TcpStream) -> Result<ProxyRequest> {
    let bytes = tokio::time::timeout(PROXY_HEADER_TIMEOUT, read_header(stream))
        .await
        .context("browser proxy request header timed out")??;
    let header_end = find_header_end(&bytes).context("incomplete browser proxy request")?;
    let head = std::str::from_utf8(&bytes[..header_end])
        .context("browser proxy request header is not UTF-8")?;
    let first_line_end = head
        .find("\r\n")
        .context("browser proxy request has no request line")?;
    let first_line = &head[..first_line_end];
    let mut parts = first_line.split_whitespace();
    let method = parts
        .next()
        .context("browser proxy request has no method")?;
    let target = parts
        .next()
        .context("browser proxy request has no target")?;
    let version = parts
        .next()
        .context("browser proxy request has no version")?;
    if parts.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|byte| byte.is_ascii_uppercase())
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        bail!("invalid browser proxy request line");
    }

    if method == "CONNECT" {
        let (host, port) = parse_authority(target, 443)?;
        return Ok(ProxyRequest::Connect {
            host,
            port,
            buffered: bytes[header_end..].to_vec(),
        });
    }

    let url = Url::parse(target).context("browser proxy requires an absolute request target")?;
    if !matches!(url.scheme(), "http" | "ws")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("browser proxy rejected an unsupported absolute request target");
    }
    let host = canonical_destination_host(
        url.host_str()
            .context("browser proxy request target has no host")?,
    );
    let port = url
        .port_or_known_default()
        .context("browser proxy request target has no effective port")?;
    let mut origin_target = url.path().to_owned();
    if origin_target.is_empty() {
        origin_target.push('/');
    }
    if let Some(query) = url.query() {
        origin_target.push('?');
        origin_target.push_str(query);
    }
    let mut rewritten = format!("{method} {origin_target} {version}\r\n").into_bytes();
    rewritten.extend_from_slice(&bytes[first_line_end + 2..]);
    Ok(ProxyRequest::Forward {
        host,
        port,
        request: rewritten,
    })
}

async fn read_header(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(4 * 1_024);
    let mut chunk = [0_u8; 4 * 1_024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("browser proxy client closed before sending a request");
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > MAX_PROXY_HEADER_BYTES {
            bail!("browser proxy request header exceeds the size limit");
        }
        if find_header_end(&bytes).is_some() {
            return Ok(bytes);
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn parse_authority(value: &str, default_port: u16) -> Result<(String, u16)> {
    if value.len() > 4 * 1_024 || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("invalid browser proxy authority");
    }
    let url = Url::parse(&format!("http://{value}/")).context("invalid browser proxy authority")?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        bail!("browser proxy authority contains unsupported data");
    }
    let host = canonical_destination_host(
        url.host_str()
            .context("browser proxy authority has no host")?,
    );
    let port = url.port().unwrap_or(default_port);
    if port == 0 {
        bail!("browser proxy authority uses port zero");
    }
    Ok((host, port))
}

pub(super) fn canonical_destination_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

async fn write_proxy_error(stream: &mut TcpStream, status: &str) -> Result<()> {
    stream
        .write_all(
            format!("HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let _ignored = stream.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Debug)]
    struct SequenceResolver {
        answers: StdMutex<VecDeque<ResolvedDestination>>,
        calls: AtomicUsize,
    }

    impl SequenceResolver {
        fn new(answers: Vec<ResolvedDestination>) -> Self {
            Self {
                answers: StdMutex::new(answers.into()),
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl DestinationResolver for SequenceResolver {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> BoxFuture<'a, Result<ResolvedDestination>> {
            async move {
                self.calls.fetch_add(1, Ordering::SeqCst);
                self.answers
                    .lock()
                    .map_err(|_| anyhow::anyhow!("test resolver mutex was poisoned"))?
                    .pop_front()
                    .context("test resolver has no remaining answer")
            }
            .boxed()
        }
    }

    fn private_destination(address: SocketAddr) -> ResolvedDestination {
        ResolvedDestination {
            addresses: vec![address],
            connect_override: None,
        }
    }

    fn test_public_destination(address: SocketAddr) -> ResolvedDestination {
        ResolvedDestination {
            addresses: vec![SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
                address.port(),
            )],
            connect_override: Some(vec![address]),
        }
    }

    async fn proxy_exchange(address: SocketAddr, request: &[u8]) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect(address).await?;
        stream.write_all(request).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
        Ok(response)
    }

    #[tokio::test]
    async fn private_http_connect_and_websocket_targets_are_rejected() -> Result<()> {
        for request in [
            b"CONNECT private.test:443 HTTP/1.1\r\nHost: private.test:443\r\n\r\n".as_slice(),
            b"GET http://private.test/resource HTTP/1.1\r\nHost: private.test\r\n\r\n".as_slice(),
            b"GET ws://private.test/socket HTTP/1.1\r\nHost: private.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n".as_slice(),
        ] {
            let resolver = Arc::new(SequenceResolver::new(vec![private_destination(
                "127.0.0.1:9".parse()?,
            )]));
            let mut guard = BrowserNetworkGuard::start(resolver).await?;
            let response = proxy_exchange(guard.address(), request).await?;
            assert!(response.is_empty());
            guard.stop().await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn destination_is_resolved_again_for_every_connection() -> Result<()> {
        let upstream = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_address = upstream.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let accepted_task = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            if let Ok((mut stream, _)) = upstream.accept().await {
                accepted_task.fetch_add(1, Ordering::SeqCst);
                let mut request = [0_u8; 4 * 1_024];
                let _ignored = stream.read(&mut request).await;
                let _ignored = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });
        let resolver = Arc::new(SequenceResolver::new(vec![
            test_public_destination(upstream_address),
            private_destination(upstream_address),
        ]));
        let mut guard = BrowserNetworkGuard::start(resolver.clone()).await?;
        let request = b"GET http://rebind.test/resource HTTP/1.1\r\nHost: rebind.test\r\nConnection: close\r\n\r\n";
        let first = proxy_exchange(guard.address(), request).await?;
        assert!(first.starts_with(b"HTTP/1.1 200 OK"));
        let second = proxy_exchange(guard.address(), request).await?;
        assert!(second.is_empty());
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
        guard.stop().await;
        server.await?;
        Ok(())
    }

    #[tokio::test]
    async fn stopping_the_guard_terminates_active_tunnels() -> Result<()> {
        let upstream = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let upstream_address = upstream.local_addr()?;
        let upstream_task = tokio::spawn(async move {
            let (_stream, _) = upstream.accept().await?;
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok::<_, std::io::Error>(())
        });
        let resolver = Arc::new(SequenceResolver::new(vec![test_public_destination(
            upstream_address,
        )]));
        let mut guard = BrowserNetworkGuard::start(resolver).await?;
        let mut client = TcpStream::connect(guard.address()).await?;
        client
            .write_all(
                format!(
                    "CONNECT public.test:{} HTTP/1.1\r\nHost: public.test:{}\r\n\r\n",
                    upstream_address.port(),
                    upstream_address.port()
                )
                .as_bytes(),
            )
            .await?;
        let mut response = [0_u8; 128];
        let read =
            tokio::time::timeout(Duration::from_secs(2), client.read(&mut response)).await??;
        assert!(response[..read].starts_with(b"HTTP/1.1 200 Connection Established"));

        guard.stop().await;
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte)).await??;
        assert_eq!(read, 0);
        upstream_task.abort();
        let _ignored = upstream_task.await;
        Ok(())
    }

    #[tokio::test]
    async fn mixed_public_and_private_dns_answers_fail_closed() -> Result<()> {
        let resolver = Arc::new(SequenceResolver::new(vec![ResolvedDestination {
            addresses: vec!["8.8.8.8:443".parse()?, "127.0.0.1:443".parse()?],
            connect_override: None,
        }]));
        let mut guard = BrowserNetworkGuard::start(resolver).await?;
        let response = proxy_exchange(
            guard.address(),
            b"CONNECT mixed.test:443 HTTP/1.1\r\nHost: mixed.test:443\r\n\r\n",
        )
        .await?;
        assert!(response.is_empty());
        guard.stop().await;
        Ok(())
    }

    #[test]
    fn authority_parser_rejects_path_port_zero_and_normalizes_local_names() {
        assert!(parse_authority("example.com/path", 443).is_err());
        assert!(parse_authority("example.com:0", 443).is_err());
        assert_eq!(canonical_destination_host("LOCALHOST."), "localhost");
        assert_eq!(canonical_destination_host("[::1]"), "::1");
    }

    #[test]
    fn authority_parser_handles_dns_ipv4_and_ipv6() -> Result<()> {
        assert_eq!(
            parse_authority("example.com:8443", 443)?,
            ("example.com".to_owned(), 8443)
        );
        assert_eq!(
            parse_authority("127.0.0.1", 443)?,
            ("127.0.0.1".to_owned(), 443)
        );
        assert_eq!(
            parse_authority("[::1]:9443", 443)?,
            ("::1".to_owned(), 9443)
        );
        Ok(())
    }
}
