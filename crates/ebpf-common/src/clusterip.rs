//! Resolving a Service's cluster address at `connect()`, for the workloads
//! that opted in, and leaving every other connection to kube-proxy.
//!
//! The decision is taken while the destination is still an argument of the
//! system call, so a translated connection never carries the cluster address
//! on the wire and no NAT is applied to it on the way out or back. Four
//! properties are deliberate:
//!
//! - Nothing is translated unless the calling task's cgroup, or an ancestor
//!   of it, is in `CLUSTERIP_CGROUPS`. The map starts empty, so a loaded
//!   program with no selection written behaves exactly as an unloaded one.
//! - Every way of not deciding is a connection left as the task wrote it,
//!   which kube-proxy then routes the way it always did: a cluster address
//!   the table does not hold, a Service with no ready backend, a backend
//!   slot that is missing, a reverse record that could not be written.
//! - A translated socket is recorded under its cookie, so `getpeername()`
//!   and the source address of a datagram read back on a connected UDP
//!   socket answer with the cluster address the task asked for.
//! - Session affinity is kept per network namespace, which is per pod, the
//!   same client a `ClientIP` affinity names, and a remembered backend is
//!   used only while it is still one of the Service's ready backends.

/// Address family of a [`ClusterIpKey`] or [`ClusterIpBackend`]: IPv4.
pub const CLUSTERIP_FAMILY_IPV4: u8 = 4;
/// Address family of a [`ClusterIpKey`] or [`ClusterIpBackend`]: IPv6.
pub const CLUSTERIP_FAMILY_IPV6: u8 = 6;

/// Protocol number of TCP, as a [`ClusterIpKey`] carries it.
pub const CLUSTERIP_PROTO_TCP: u8 = 6;
/// Protocol number of UDP, as a [`ClusterIpKey`] carries it.
pub const CLUSTERIP_PROTO_UDP: u8 = 17;

/// Metric index: connections whose cluster address was resolved to a backend.
pub const CLUSTERIP_METRIC_TRANSLATED: u32 = 0;
/// Metric index: connections to a cluster address the table holds that were
/// left to kube-proxy, because no backend could be read or the reverse record
/// could not be written.
pub const CLUSTERIP_METRIC_LEFT: u32 = 1;
/// Metric index: translations that reused the backend a session affinity
/// remembered.
pub const CLUSTERIP_METRIC_AFFINITY_HIT: u32 = 2;
/// Metric index: `getpeername()` answers and datagram source addresses
/// rewritten back to the cluster address.
pub const CLUSTERIP_METRIC_REVERSED: u32 = 3;
/// Total number of metric slots (one past the last index).
pub const CLUSTERIP_METRIC_COUNT: u32 = 4;

/// How many service ports, one per cluster address, port and protocol.
pub const CLUSTERIP_MAX_SERVICES: u32 = 16_384;
/// How many backend slots across every service port, both revisions of a
/// service port included while it is being replaced.
pub const CLUSTERIP_MAX_BACKENDS: u32 = 262_144;
/// How many backends one service port may carry.
pub const CLUSTERIP_MAX_BACKENDS_PER_SERVICE: u32 = 4_096;
/// How many cgroups may be selected at once.
pub const CLUSTERIP_MAX_CGROUPS: u32 = 4_096;
/// How many remembered affinities. LRU: a client that stopped connecting
/// ages out rather than holding a slot.
pub const CLUSTERIP_MAX_AFFINITY: u32 = 65_536;
/// How many translated sockets are remembered for the reverse answer. LRU:
/// a cookie is never reused, so an entry for a closed socket only ages out.
pub const CLUSTERIP_MAX_REVERSE: u32 = 262_144;
/// How many ancestors of the task's cgroup are tested after its own, which
/// is how a selection naming a pod's cgroup covers every container under it.
pub const CLUSTERIP_ANCESTOR_LEVELS: u32 = 8;

/// A cluster address, port and protocol, the key a connection is looked up by.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct ClusterIpKey {
    /// Address. IPv4 sits in the first word, the rest zero; each word is the
    /// host-order value of the big-endian word.
    pub addr: [u32; 4],
    /// Port, host order.
    pub port: u16,
    /// `CLUSTERIP_PROTO_*`.
    pub proto: u8,
    /// `CLUSTERIP_FAMILY_*`.
    pub family: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpKey {}

/// One service port as the hooks read it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClusterIpService {
    /// Identifier of the service port for as long as the agent runs, which
    /// affinity and the ready set are keyed by.
    pub stable: u32,
    /// Identifier of the backend list currently in force. A new list is
    /// written under a new revision before this entry points at it, so a
    /// connection never reads half of one list and half of another.
    pub revision: u32,
    /// Backends in the list, slots `0..count`.
    pub count: u32,
    /// `ClientIP` affinity timeout in seconds, zero for none.
    pub affinity_secs: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpService {}

/// One slot of a backend list.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct ClusterIpSlot {
    pub revision: u32,
    pub slot: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpSlot {}

/// A backend address and port, in the encoding of [`ClusterIpKey`].
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct ClusterIpBackend {
    pub addr: [u32; 4],
    pub port: u16,
    pub family: u8,
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpBackend {}

/// A backend that is ready behind a service port, the test a remembered
/// affinity must pass before it is used again.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct ClusterIpReady {
    pub stable: u32,
    pub backend: ClusterIpBackend,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpReady {}

/// Who a remembered affinity belongs to: a network namespace and a service
/// port.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClusterIpAffinityKey {
    pub netns: u64,
    pub stable: u32,
    pub _pad: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpAffinityKey {}

/// The backend a client was last sent to, and when.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClusterIpAffinity {
    pub backend: ClusterIpBackend,
    pub _pad: u32,
    /// `bpf_ktime_get_ns` at the last connection that used it.
    pub last_ns: u64,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpAffinity {}

/// What a translated socket was asked to reach, and where it was sent.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClusterIpReverse {
    /// The cluster address and port, in the encoding of [`ClusterIpBackend`].
    pub cluster: ClusterIpBackend,
    /// The backend the connection was sent to.
    pub backend: ClusterIpBackend,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ClusterIpReverse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_hold_no_implicit_padding() {
        assert_eq!(core::mem::size_of::<ClusterIpKey>(), 20);
        assert_eq!(core::mem::size_of::<ClusterIpService>(), 16);
        assert_eq!(core::mem::size_of::<ClusterIpSlot>(), 8);
        assert_eq!(core::mem::size_of::<ClusterIpBackend>(), 20);
        assert_eq!(core::mem::size_of::<ClusterIpReady>(), 24);
        assert_eq!(core::mem::size_of::<ClusterIpAffinityKey>(), 16);
        assert_eq!(core::mem::size_of::<ClusterIpAffinity>(), 32);
        assert_eq!(core::mem::size_of::<ClusterIpReverse>(), 40);
    }
}
