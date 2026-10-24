use std::net::SocketAddr;

use domain::common::error::DomainError;

/// Where a connection the kernel redirected to a local listener was going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedirectedConnection {
    /// The destination the workload passed to `connect()`.
    pub destination: SocketAddr,
    /// The cgroup of the task that opened it.
    pub cgroup_id: u64,
}

/// Secondary port a listener asks, on accepting a connection, where that
/// connection was really going.
///
/// The answer is keyed on the address the listener sees the connection come
/// from, which the kernel recorded once it had chosen the source port. It is
/// consumed by the lookup: a source port is reused, and an answer left behind
/// would route the next connection from it to the previous one's destination.
///
/// Implemented by `RedirectOriginTable` in the adapter layer.
pub trait RedirectOriginPort: Send + Sync {
    /// The original destination of the connection accepted from `peer`, or
    /// `None` when the kernel did not redirect it.
    ///
    /// # Errors
    ///
    /// Whatever the map lookup refused, which is not the same as a
    /// connection nobody redirected and must not be treated as one.
    fn take(&self, peer: SocketAddr) -> Result<Option<RedirectedConnection>, DomainError>;
}
