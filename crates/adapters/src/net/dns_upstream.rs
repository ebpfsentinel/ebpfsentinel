//! Forwarding a DNS query to the resolvers the agent's own resolver sits in
//! front of.
//!
//! Each upstream is tried in order with its own deadline, and an answer is
//! taken only when it carries the query's id, so a stray datagram reaching
//! the ephemeral port is never relayed to a container.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use async_trait::async_trait;
use domain::dns::error::DnsError;
use ports::secondary::dns_upstream_port::{DnsTransport, DnsUpstreamPort};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// Largest answer read over UDP; an EDNS answer past it comes back
/// truncated and the client retries over TCP, as it would with any resolver.
const UDP_ANSWER_MAX: usize = 4096;

/// Forwards to a fixed list of upstream resolvers.
pub struct UpstreamResolver {
    upstreams: Vec<SocketAddr>,
    deadline: Duration,
}

impl UpstreamResolver {
    #[must_use]
    pub fn new(upstreams: Vec<SocketAddr>, deadline: Duration) -> Self {
        Self {
            upstreams,
            deadline,
        }
    }

    async fn over_udp(&self, upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let local: SocketAddr = if upstream.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = UdpSocket::bind(local).await?;
        socket.connect(upstream).await?;
        socket.send(query).await?;
        let mut buf = vec![0u8; UDP_ANSWER_MAX];
        loop {
            let len = socket.recv(&mut buf).await?;
            if len >= 2 && query.len() >= 2 && buf[..2] == query[..2] {
                buf.truncate(len);
                return Ok(buf);
            }
        }
    }

    async fn over_tcp(&self, upstream: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
        let length = u16::try_from(query.len()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "query past 65535 bytes")
        })?;
        let mut stream = TcpStream::connect(upstream).await?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(query);
        stream.write_all(&framed).await?;
        let answer_len = stream.read_u16().await?;
        let mut answer = vec![0u8; usize::from(answer_len)];
        stream.read_exact(&mut answer).await?;
        Ok(answer)
    }
}

#[async_trait]
impl DnsUpstreamPort for UpstreamResolver {
    async fn resolve(&self, query: &[u8], transport: DnsTransport) -> Result<Vec<u8>, DnsError> {
        let mut last = String::from("no upstream configured");
        for upstream in &self.upstreams {
            let attempt = match transport {
                DnsTransport::Udp => timeout(self.deadline, self.over_udp(*upstream, query)).await,
                DnsTransport::Tcp => timeout(self.deadline, self.over_tcp(*upstream, query)).await,
            };
            match attempt {
                Ok(Ok(answer)) => return Ok(answer),
                Ok(Err(e)) => last = format!("{upstream}: {e}"),
                Err(_) => last = format!("{upstream}: no answer within {:?}", self.deadline),
            }
        }
        Err(DnsError::Upstream(last))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;

    const QUERY: &[u8] = &[0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1];

    /// An upstream that first sends a datagram with the wrong id, then the
    /// real answer.
    async fn udp_upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(&[0, 0, 0x81, 0x80], peer).await.unwrap();
            let mut answer = buf[..len].to_vec();
            answer[2] |= 0x80;
            socket.send_to(&answer, peer).await.unwrap();
        });
        address
    }

    #[tokio::test]
    async fn a_udp_answer_is_taken_only_with_the_query_id() {
        let resolver = UpstreamResolver::new(vec![udp_upstream().await], Duration::from_secs(2));
        let answer = resolver.resolve(QUERY, DnsTransport::Udp).await.unwrap();
        assert_eq!(&answer[..2], &[0xab, 0xcd]);
        assert_eq!(answer[2] & 0x80, 0x80);
    }

    #[tokio::test]
    async fn a_silent_upstream_is_passed_over_for_the_next() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = UpstreamResolver::new(
            vec![silent.local_addr().unwrap(), udp_upstream().await],
            Duration::from_millis(200),
        );
        assert!(resolver.resolve(QUERY, DnsTransport::Udp).await.is_ok());
    }

    #[tokio::test]
    async fn no_answer_anywhere_is_an_upstream_error() {
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = UpstreamResolver::new(
            vec![silent.local_addr().unwrap()],
            Duration::from_millis(100),
        );
        assert!(matches!(
            resolver.resolve(QUERY, DnsTransport::Udp).await,
            Err(DnsError::Upstream(_))
        ));
    }

    #[tokio::test]
    async fn a_tcp_query_is_framed_with_its_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let len = stream.read_u16().await.unwrap();
            let mut query = vec![0u8; usize::from(len)];
            stream.read_exact(&mut query).await.unwrap();
            query[2] |= 0x80;
            stream.write_u16(len).await.unwrap();
            stream.write_all(&query).await.unwrap();
        });
        let resolver = UpstreamResolver::new(vec![address], Duration::from_secs(2));
        let answer = resolver.resolve(QUERY, DnsTransport::Tcp).await.unwrap();
        assert_eq!(answer.len(), QUERY.len());
        assert_eq!(&answer[..2], &[0xab, 0xcd]);
    }
}
