//! Socket attribution: who opened the flow the datapath is looking at.
//!
//! The datapath sees packets. A packet carries addresses, and on the egress
//! hook a cgroup id, and that is the whole of what a tc or XDP program can
//! know about the workload behind it. The identity exists one layer up, in the
//! task that called `connect()` or `sendmsg()`, and it exists there before the
//! first packet does.
//!
//! The cgroup socket hooks run exactly at that moment. They record the calling
//! task against the socket's cookie - the one identifier the kernel gives both
//! to a socket hook and to a packet hook holding an `skb` - so the join from a
//! flow to a process is a lookup by key rather than a walk of `/proc` and a
//! guess about timing.
//!
//! Nothing here enforces anything, and nothing here invents anything: a flow
//! with no local socket, which is every flow a router or a NAT transits,
//! resolves to nothing and carries no workload.

/// Capacity of `SOCKET_IDENTITY` unless the configuration says otherwise.
///
/// An LRU map, so a node opening more sockets than this evicts the oldest
/// rather than refusing the insert: attribution degrades to absent on the
/// coldest sockets instead of failing on the newest. The bound is the point -
/// an unbounded table of every socket a busy node ever opened is a memory
/// incident, and the memory is locked whether the slots are used or not.
pub const ATTRIBUTION_MAX_SOCKETS: u32 = 65_536;

/// How long an identity stays usable after the hook recorded it.
///
/// A socket cookie is unique for the life of the socket and is not reused
/// while it lives, so the window is not what makes the join correct. It is
/// what stops an entry that outlived its socket, and was evicted from
/// everything but this map, from naming a process for a cookie the kernel has
/// since handed to another socket. Twelve hours covers a long-lived
/// connection; past it the flow carries no workload rather than a stale one.
pub const ATTRIBUTION_IDENTITY_TTL_NS: u64 = 12 * 60 * 60 * 1_000_000_000;

/// Capacity of `SOCKET_FLOW`, the index from an established five-tuple back
/// to the socket cookie.
///
/// One entry per established TCP connection, which is why it is the same
/// order as the socket table rather than a fraction of it: every connection
/// the node holds open wants to stay nameable for as long as it is in the
/// kernel's own conntrack table.
pub const ATTRIBUTION_MAX_FLOWS: u32 = 65_536;

/// Which hook recorded an identity: `cgroup/connect4` or `cgroup/connect6`.
pub const ATTRIBUTION_HOOK_CONNECT: u8 = 1;
/// Which hook recorded an identity: `cgroup/post_bind4` or `post_bind6`.
pub const ATTRIBUTION_HOOK_POST_BIND: u8 = 2;
/// Which hook recorded an identity: `cgroup/sendmsg4` or `sendmsg6`, the
/// connectionless path a datagram socket takes instead of `connect()`.
pub const ATTRIBUTION_HOOK_SENDMSG: u8 = 3;
/// Which hook recorded an identity: `sockops`, on an established connection.
pub const ATTRIBUTION_HOOK_SOCK_OPS: u8 = 4;

/// Address family of a recorded identity: `AF_INET`, as the kernel numbers it.
pub const ATTRIBUTION_FAMILY_IPV4: u8 = 2;
/// Address family of a recorded identity: `AF_INET6`.
pub const ATTRIBUTION_FAMILY_IPV6: u8 = 10;

/// Metric index: identities written by the connect hooks.
pub const ATTRIBUTION_METRIC_CONNECT: u32 = 0;
/// Metric index: identities written by the post-bind hooks.
pub const ATTRIBUTION_METRIC_POST_BIND: u32 = 1;
/// Metric index: identities written by the sendmsg hooks.
pub const ATTRIBUTION_METRIC_SENDMSG: u32 = 2;
/// Metric index: identities written or refreshed by the `sockops` hook.
pub const ATTRIBUTION_METRIC_SOCK_OPS: u32 = 3;
/// Metric index: hook invocations where the socket cookie came back zero, so
/// there was no key to record the task against.
pub const ATTRIBUTION_METRIC_NO_COOKIE: u32 = 4;
/// Metric index: inserts the map refused. An LRU evicts rather than refuses,
/// so a non-zero count here is the kernel saying something other than capacity
/// went wrong.
pub const ATTRIBUTION_METRIC_INSERT_FAILED: u32 = 5;
/// Metric index: established flows indexed by their five-tuple, which is what
/// lets a connection read out of the kernel's own conntrack table name a
/// process the agent never saw a packet for.
pub const ATTRIBUTION_METRIC_FLOW: u32 = 6;
/// Total number of attribution metric slots (one past the last index).
pub const ATTRIBUTION_METRIC_COUNT: u32 = 7;

/// The task that owned a socket at the moment the kernel first saw it used.
///
/// Keyed by socket cookie in `SOCKET_IDENTITY`. The cookie is what a packet
/// hook can also obtain, which is the whole reason the join works without a
/// scan: the kernel produces the key on both sides.
///
/// Everything here is read from the calling task, never derived: `pid` and
/// `tgid` from `bpf_get_current_pid_tgid`, `uid` and `gid` from
/// `bpf_get_current_uid_gid`, `cgroup_id` from `bpf_get_current_cgroup_id`.
/// The name a pid stands for is resolved in userspace, because a path lives in
/// `linux_binprm` and not in a socket hook.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SocketIdentity {
    /// `bpf_ktime_get_boot_ns` when the hook recorded this socket.
    pub at_ns: u64,
    /// cgroup v2 id of the calling task, 0 where the kernel has none.
    pub cgroup_id: u64,
    /// Thread id (lower half of `bpf_get_current_pid_tgid`).
    pub pid: u32,
    /// Process id (upper half), which is what a userspace process table keys on.
    pub tgid: u32,
    /// Real user id of the calling task.
    pub uid: u32,
    /// Real group id of the calling task.
    pub gid: u32,
    /// `ATTRIBUTION_HOOK_*`: which hook wrote this entry.
    pub hook: u8,
    /// `ATTRIBUTION_FAMILY_*` where the hook knew it, 0 otherwise.
    pub family: u8,
    /// IP protocol as the kernel numbers it, 0 where the hook did not carry one.
    pub protocol: u8,
    pub _pad: [u8; 5],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SocketIdentity {}

/// The five-tuple of an established connection, as `SOCKET_FLOW` keys it.
///
/// A packet hook has the socket cookie and needs nothing else. A connection
/// read out of the kernel's own conntrack table has no cookie at all: it is a
/// row of addresses and ports, and the join back to a task has to start from
/// those. This is that key, written by the `sockops` hook because it is the
/// only one that knows both ends of a connection at once.
///
/// `local` is this node's side, whichever direction opened the connection,
/// and addresses are the host-order value of the big-endian word, exactly as
/// the DLP socket records them, so one encoding serves both joins. A reader
/// starting from a conntrack row does not know which side is local and tries
/// the key both ways round.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct FlowIdentityKey {
    /// This node's address. IPv4 sits in the first word, the rest zero.
    pub local_addr: [u32; 4],
    /// The peer's address, in the same encoding.
    pub remote_addr: [u32; 4],
    /// This node's port, host order.
    pub local_port: u16,
    /// The peer's port, host order.
    pub remote_port: u16,
    /// IP protocol as the kernel numbers it.
    pub protocol: u8,
    /// `ATTRIBUTION_FAMILY_*`.
    pub family: u8,
    pub _pad: [u8; 2],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FlowIdentityKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_identity_is_forty_bytes_with_no_implicit_padding() {
        // The kernel and userspace sides of this map are compiled separately
        // and agree on nothing but this layout. An implicit hole would be
        // read as a field by one of the two.
        assert_eq!(mem::size_of::<SocketIdentity>(), 40);
        assert_eq!(mem::align_of::<SocketIdentity>(), 8);
        assert_eq!(mem::offset_of!(SocketIdentity, at_ns), 0);
        assert_eq!(mem::offset_of!(SocketIdentity, cgroup_id), 8);
        assert_eq!(mem::offset_of!(SocketIdentity, pid), 16);
        assert_eq!(mem::offset_of!(SocketIdentity, tgid), 20);
        assert_eq!(mem::offset_of!(SocketIdentity, uid), 24);
        assert_eq!(mem::offset_of!(SocketIdentity, gid), 28);
        assert_eq!(mem::offset_of!(SocketIdentity, hook), 32);
        assert_eq!(mem::offset_of!(SocketIdentity, family), 33);
        assert_eq!(mem::offset_of!(SocketIdentity, protocol), 34);
    }

    #[test]
    fn the_flow_key_is_forty_bytes_with_no_implicit_padding() {
        // Same reason as the identity: the two sides of this map are compiled
        // separately, and a hole one of them does not know about is a lookup
        // that never hits.
        assert_eq!(mem::size_of::<FlowIdentityKey>(), 40);
        assert_eq!(mem::offset_of!(FlowIdentityKey, local_addr), 0);
        assert_eq!(mem::offset_of!(FlowIdentityKey, remote_addr), 16);
        assert_eq!(mem::offset_of!(FlowIdentityKey, local_port), 32);
        assert_eq!(mem::offset_of!(FlowIdentityKey, remote_port), 34);
        assert_eq!(mem::offset_of!(FlowIdentityKey, protocol), 36);
        assert_eq!(mem::offset_of!(FlowIdentityKey, family), 37);
    }

    #[test]
    fn a_flow_key_is_the_same_key_whichever_side_built_it() {
        // Two readers building the key from the same connection must produce
        // the same bytes, padding included, or the lookup misses on one of
        // them and the flow silently carries no workload.
        let one = FlowIdentityKey {
            local_addr: [0x0a00_0007, 0, 0, 0],
            remote_addr: [0xcb00_7109, 0, 0, 0],
            local_port: 45_112,
            remote_port: 443,
            protocol: 6,
            family: ATTRIBUTION_FAMILY_IPV4,
            _pad: [0; 2],
        };
        let two = FlowIdentityKey {
            _pad: [0; 2],
            ..one
        };
        assert_eq!(one, two);
    }

    #[test]
    fn every_hook_has_its_own_number_and_none_of_them_is_zero() {
        // Zero is "no hook wrote this", which a zeroed value already says.
        let hooks = [
            ATTRIBUTION_HOOK_CONNECT,
            ATTRIBUTION_HOOK_POST_BIND,
            ATTRIBUTION_HOOK_SENDMSG,
            ATTRIBUTION_HOOK_SOCK_OPS,
        ];
        assert!(hooks.iter().all(|h| *h != 0));
        for (i, a) in hooks.iter().enumerate() {
            assert!(hooks[i + 1..].iter().all(|b| a != b));
        }
    }

    #[test]
    fn the_metric_count_is_one_past_the_last_slot() {
        assert_eq!(ATTRIBUTION_METRIC_COUNT, ATTRIBUTION_METRIC_FLOW + 1);
        const {
            assert!(ATTRIBUTION_METRIC_INSERT_FAILED < ATTRIBUTION_METRIC_FLOW);
        }
    }
}
