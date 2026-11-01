//! The addresses a network namespace holds, read through a task inside it.

use std::net::IpAddr;

/// Reads which network namespace a task is in and which addresses that
/// namespace holds.
///
/// A namespace is named by its inode, which is the kernel's own identity for
/// it and what two tasks sharing one have in common. A task that is gone, or
/// that the agent may not inspect, answers `None`.
pub trait NamespaceAddressReader: Send + Sync {
    /// The network namespace `pid` is in.
    fn namespace_of(&self, pid: u32) -> Option<u64>;

    /// The host's network namespace.
    fn host_namespace(&self) -> Option<u64>;

    /// Every address configured in the namespace `pid` is in, of both
    /// families, loopback included: deciding what is worth publishing is
    /// the caller's.
    fn addresses_of(&self, pid: u32) -> Option<Vec<IpAddr>>;

    /// Every address configured in the host's namespace.
    fn host_addresses(&self) -> Option<Vec<IpAddr>>;
}
