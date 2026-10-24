use async_trait::async_trait;

use domain::dns::error::DnsError;

/// How a query reached the agent's resolver, and so how it goes upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[async_trait]
pub trait DnsUpstreamPort: Send + Sync {
    /// Send `query` to an upstream resolver over `transport` and return its
    /// answer, as wire bytes without any TCP length prefix.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::Upstream`] when no upstream answered in time.
    async fn resolve(&self, query: &[u8], transport: DnsTransport) -> Result<Vec<u8>, DnsError>;
}
