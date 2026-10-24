//! The resolver containers are pointed at when a DNS allow-list governs
//! them: one UDP socket and one TCP listener on the configured address,
//! each query decided by [`DnsAllowListService`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use application::dns_allowlist_service::DnsAllowListService;
use ports::secondary::dns_upstream_port::DnsTransport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// Queries in flight at once over UDP; past it a datagram is dropped and
/// the client retries, which is what an overloaded resolver looks like.
const UDP_IN_FLIGHT: usize = 512;

/// TCP connections held at once.
const TCP_CONNECTIONS: usize = 64;

/// How long a TCP connection may sit without sending its next query.
const TCP_IDLE: Duration = Duration::from_secs(10);

/// Largest query read over UDP.
const UDP_QUERY_MAX: usize = 4096;

/// Bind both sockets, so a port already taken or a missing capability stops
/// the agent at startup rather than leaving containers with no resolver.
///
/// # Errors
///
/// Returns the bind failure, naming the address.
pub async fn bind(listen: SocketAddr) -> anyhow::Result<(UdpSocket, TcpListener)> {
    let hint = "binding port 53 needs CAP_NET_BIND_SERVICE, and the address must be one the \
                host holds, such as the bridge gateway";
    let udp = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("DNS allow-list resolver could not bind udp {listen}: {hint}"))?;
    let tcp = TcpListener::bind(listen)
        .await
        .with_context(|| format!("DNS allow-list resolver could not bind tcp {listen}: {hint}"))?;
    Ok((udp, tcp))
}

/// Serve both sockets until `cancel` fires.
pub fn spawn(
    service: Arc<DnsAllowListService>,
    udp: UdpSocket,
    tcp: TcpListener,
    cancel: CancellationToken,
) {
    tokio::spawn(serve_udp(Arc::clone(&service), udp, cancel.clone()));
    tokio::spawn(serve_tcp(service, tcp, cancel));
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

async fn serve_udp(
    service: Arc<DnsAllowListService>,
    socket: UdpSocket,
    cancel: CancellationToken,
) {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(UDP_IN_FLIGHT));
    let mut buf = vec![0u8; UDP_QUERY_MAX];
    loop {
        let received = tokio::select! {
            () = cancel.cancelled() => return,
            received = socket.recv_from(&mut buf) => received,
        };
        let (len, peer) = match received {
            Ok(received) => received,
            Err(e) => {
                warn!(error = %e, "DNS allow-list resolver failed to read a datagram");
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            debug!(%peer, "DNS allow-list resolver busy, datagram dropped");
            continue;
        };
        let query = buf[..len].to_vec();
        let service = Arc::clone(&service);
        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            let _slot = slot;
            if let Some(answer) = service
                .answer(peer.ip(), &query, DnsTransport::Udp, now_ns())
                .await
                && let Err(e) = socket.send_to(&answer, peer).await
            {
                debug!(%peer, error = %e, "DNS allow-list resolver failed to answer");
            }
        });
    }
}

async fn serve_tcp(
    service: Arc<DnsAllowListService>,
    listener: TcpListener,
    cancel: CancellationToken,
) {
    let slots = Arc::new(Semaphore::new(TCP_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            () = cancel.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "DNS allow-list resolver failed to accept");
                continue;
            }
        };
        let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
            debug!(%peer, "DNS allow-list resolver busy, connection closed");
            continue;
        };
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            let _slot = slot;
            serve_connection(&service, stream, peer).await;
        });
    }
}

/// Answer length-prefixed queries on one connection until the client goes
/// quiet, closes, or a query gets no answer.
async fn serve_connection(service: &DnsAllowListService, mut stream: TcpStream, peer: SocketAddr) {
    loop {
        let Ok(Ok(len)) = tokio::time::timeout(TCP_IDLE, stream.read_u16()).await else {
            return;
        };
        let mut query = vec![0u8; usize::from(len)];
        if !matches!(
            tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut query)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        let Some(answer) = service
            .answer(peer.ip(), &query, DnsTransport::Tcp, now_ns())
            .await
        else {
            return;
        };
        let Ok(answer_len) = u16::try_from(answer.len()) else {
            return;
        };
        let mut framed = Vec::with_capacity(answer.len() + 2);
        framed.extend_from_slice(&answer_len.to_be_bytes());
        framed.extend_from_slice(&answer);
        if stream.write_all(&framed).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use adapters::metrics::AgentMetrics;
    use adapters::net::dns_upstream::UpstreamResolver;
    use async_trait::async_trait;
    use domain::container::error::ContainerError;
    use domain::dns::allowlist::DnsAllowList;
    use domain::learning::segmentation::{BridgeMember, BridgeNetwork};
    use ports::secondary::bridge_network_port::BridgeNetworkPort;
    use ports::secondary::metrics_port::MetricsPort;

    use super::*;

    /// Loopback stands in for a container on a bridge.
    struct LoopbackIsWeb;

    #[async_trait]
    impl BridgeNetworkPort for LoopbackIsWeb {
        async fn bridge_networks(&self) -> Result<Vec<BridgeNetwork>, ContainerError> {
            Ok(vec![BridgeNetwork {
                name: "app".to_string(),
                subnets: Vec::new(),
                embedded_dns: true,
                members: vec![BridgeMember {
                    id: "0123abcd".to_string(),
                    name: "web".to_string(),
                    addresses: vec!["127.0.0.1".parse().unwrap()],
                }],
            }])
        }
    }

    async fn echo_upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                let mut answer = buf[..len].to_vec();
                answer[2] |= 0x80;
                socket.send_to(&answer, peer).await.unwrap();
            }
        });
        address
    }

    fn query(name: &str) -> Vec<u8> {
        let mut out = vec![0x42, 0x42, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.extend_from_slice(&[0, 0, 1, 0, 1]);
        out
    }

    async fn ask_udp(resolver: SocketAddr, name: &str) -> Vec<u8> {
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query(name), resolver).await.unwrap();
        let mut buf = [0u8; 512];
        let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        buf[..len].to_vec()
    }

    #[tokio::test]
    async fn a_governed_container_is_refused_over_udp_and_tcp_and_served_otherwise() {
        let metrics = Arc::new(AgentMetrics::new());
        let service = DnsAllowListService::new(
            DnsAllowList::new([("web", vec!["*.debian.org"])]).unwrap(),
            Arc::new(LoopbackIsWeb),
            Arc::new(UpstreamResolver::new(
                vec![echo_upstream().await],
                Duration::from_secs(1),
            )),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
        );
        let (udp, tcp) = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let udp_at = udp.local_addr().unwrap();
        let tcp_at = tcp.local_addr().unwrap();
        let cancel = CancellationToken::new();
        spawn(Arc::new(service), udp, tcp, cancel.clone());

        let refused = ask_udp(udp_at, "evil.example").await;
        assert_eq!(refused[3] & 0x0f, 5);
        let served = ask_udp(udp_at, "deb.debian.org").await;
        assert_eq!(served[3] & 0x0f, 0);
        assert_eq!(served[2] & 0x80, 0x80);

        let mut stream = TcpStream::connect(tcp_at).await.unwrap();
        let asked = query("evil.example");
        stream
            .write_u16(u16::try_from(asked.len()).unwrap())
            .await
            .unwrap();
        stream.write_all(&asked).await.unwrap();
        let len = stream.read_u16().await.unwrap();
        let mut answer = vec![0u8; usize::from(len)];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(answer[3] & 0x0f, 5);

        let encoded = metrics.encode();
        assert!(
            encoded.contains(
                "ebpfsentinel_dns_allowlist_queries_total{container=\"web\",verdict=\"refused\"} 2"
            ),
            "{encoded}"
        );
        assert!(
            encoded.contains(
                "ebpfsentinel_dns_allowlist_queries_total{container=\"web\",verdict=\"allowed\"} 1"
            ),
            "{encoded}"
        );
        cancel.cancel();
    }
}
