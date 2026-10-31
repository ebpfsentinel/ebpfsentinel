//! TCP health per edge, counted where the kernel decides it.
//!
//! Four tracepoints the TCP stack already fires carry everything a
//! connection's health is made of: a segment sent again
//! (`tcp_retransmit_skb`), a reset this node sent (`tcp_send_reset`) or
//! received (`tcp_receive_reset`), and a socket changing state
//! (`inet_sock_set_state`), from which an opened, a failed and a closed
//! connection are told apart. The program behind this module adds each of
//! them to a per-CPU counter keyed by the edge the connection runs on, and
//! sends no event: a retransmission storm costs a hash update per segment.
//!
//! An edge is the two addresses and the service port, never the ephemeral
//! one, so every connection a client opens to the same server lands on the
//! same counter. The service port is the lower of the two, because an
//! ephemeral port is drawn from the top of the range; which end it belongs to
//! is kept beside it. The cgroup the local socket belongs to rides along, so
//! the local end is named after the workload that holds it whether it is the
//! client or the server.
//!
//! The structure reads all come from the running kernel's BTF through the
//! configuration, and a program handed none counts nothing.

/// How many distinct edges the counter map holds.
///
/// One per local workload, peer address and service port that saw a
/// connection, a reset or a retransmission since the agent started. An edge
/// that finds the map full is counted in `TCP_HEALTH_METRIC_KEYS_FULL`, never
/// folded into another one.
pub const TCP_HEALTH_MAX_KEYS: u32 = 8_192;

/// Metric index: events counted under their edge.
pub const TCP_HEALTH_METRIC_COUNTED: u32 = 0;
/// Metric index: events whose edge found the counter map full.
pub const TCP_HEALTH_METRIC_KEYS_FULL: u32 = 1;
/// Metric index: events seen before userspace wrote the configuration.
pub const TCP_HEALTH_METRIC_UNCONFIGURED: u32 = 2;
/// Metric index: events whose socket or packet could not be read.
pub const TCP_HEALTH_METRIC_UNREADABLE: u32 = 3;
/// Total number of metric slots (one past the last index).
pub const TCP_HEALTH_METRIC_COUNT: u32 = 4;

/// `AF_INET`, as `sock_common.skc_family` holds it.
pub const TCP_HEALTH_AF_INET: u8 = 2;
/// `AF_INET6`.
pub const TCP_HEALTH_AF_INET6: u8 = 10;

/// `TCP_ESTABLISHED` in the kernel's state numbering.
pub const TCP_STATE_ESTABLISHED: u32 = 1;
/// `TCP_SYN_SENT`.
pub const TCP_STATE_SYN_SENT: u32 = 2;
/// `TCP_SYN_RECV`.
pub const TCP_STATE_SYN_RECV: u32 = 3;
/// `TCP_CLOSE`.
pub const TCP_STATE_CLOSE: u32 = 7;
/// `TCP_TIME_WAIT`.
pub const TCP_STATE_TIME_WAIT: u32 = 6;
/// `TCP_LISTEN`.
pub const TCP_STATE_LISTEN: u32 = 10;
/// `TCP_NEW_SYN_RECV`, a request socket.
pub const TCP_STATE_NEW_SYN_RECV: u32 = 12;

/// `IPPROTO_TCP`, as `sock.sk_protocol` holds it.
pub const TCP_HEALTH_IPPROTO_TCP: u16 = 6;

/// One counter's identity: the edge a connection runs on.
///
/// Addresses are four words, each the host-order value of the big-endian
/// address the way the rest of the datapath stores them, an IPv4 address in
/// the first and zeros after it. A reset answering a segment no socket was there
/// to take - a connection attempt to a closed port, which is what a scan
/// looks like - has no service port to keep: it is counted with `port` zero,
/// so a scan of every port of a node is one edge per source rather than one
/// per port probed.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct TcpEdgeKey {
    pub local: [u32; 4],
    pub remote: [u32; 4],
    /// cgroup v2 id of the local socket, `0` where it had none or none could
    /// be read.
    pub cgroup: u64,
    /// The service port, `0` for a reset with no socket behind it.
    pub port: u16,
    /// `TCP_HEALTH_AF_INET` or `TCP_HEALTH_AF_INET6`.
    pub family: u8,
    /// `1` when the service port is the local one, so this node is the server.
    pub port_is_local: u8,
    pub _pad: [u8; 4],
}

/// What one edge has counted, per CPU.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpEdgeCounts {
    /// Segments sent again.
    pub retransmits: u64,
    /// Resets this node sent.
    pub resets_sent: u64,
    /// Resets this node received.
    pub resets_received: u64,
    /// Connections that reached `ESTABLISHED`.
    pub opened: u64,
    /// Established connections that closed.
    pub closed: u64,
    /// Connections that closed before they were established.
    pub failed: u64,
}

/// What the program needs from the running kernel before it counts.
///
/// Every field is a byte offset read off BTF. `ready` is written last and
/// alone says whether the rest may be trusted.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpHealthConfig {
    /// Non-zero once userspace has written every offset.
    pub ready: u32,
    /// `sock.__sk_common`.
    pub sk_common: u32,
    /// `sock_common.skc_family`.
    pub skc_family: u32,
    /// `sock_common.skc_num`, the local port in host order.
    pub skc_num: u32,
    /// `sock_common.skc_dport`, the remote port in network order.
    pub skc_dport: u32,
    /// `sock_common.skc_rcv_saddr`.
    pub skc_rcv_saddr: u32,
    /// `sock_common.skc_daddr`.
    pub skc_daddr: u32,
    /// `sock_common.skc_v6_rcv_saddr`.
    pub skc_v6_rcv_saddr: u32,
    /// `sock_common.skc_v6_daddr`.
    pub skc_v6_daddr: u32,
    /// `sock.sk_protocol`.
    pub sk_protocol: u32,
    /// `sock.sk_cgrp_data`.
    pub sk_cgrp_data: u32,
    /// `sock_cgroup_data.cgroup`.
    pub cgrp_data_cgroup: u32,
    /// `cgroup.kn`.
    pub cgroup_kn: u32,
    /// `kernfs_node.id`.
    pub kn_id: u32,
    /// `sk_buff.head`.
    pub skb_head: u32,
    /// `sk_buff.network_header`.
    pub skb_network_header: u32,
    /// `sk_buff.transport_header`.
    pub skb_transport_header: u32,
    /// `sock_common.skc_state`, which tells a full socket from the time-wait
    /// and request sockets that share only `sock_common` with it.
    pub skc_state: u32,
    /// `inet_sock.inet_sport`, the local port in network order. The kernel
    /// releases a socket's port before it reports the move to `CLOSE`, so
    /// `skc_num` reads zero on the transition that ends a connection; the
    /// source port of the full socket is still set there.
    pub inet_sport: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TcpEdgeKey {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TcpEdgeCounts {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TcpHealthConfig {}

/// The service port of a connection and whether it is the local one: the
/// lower of the two ports, the local one on a tie.
#[must_use]
pub const fn service_port(local: u16, remote: u16) -> (u16, bool) {
    if local <= remote {
        (local, true)
    } else {
        (remote, false)
    }
}

/// Which counter a socket's state change adds to, if any.
#[must_use]
pub const fn transition(old: u32, new: u32) -> Transition {
    if new == TCP_STATE_ESTABLISHED {
        return Transition::Opened;
    }
    if new != TCP_STATE_CLOSE {
        return Transition::None;
    }
    match old {
        TCP_STATE_SYN_SENT | TCP_STATE_SYN_RECV => Transition::Failed,
        // A listener closing or a socket that never left `CLOSE` is no
        // connection.
        TCP_STATE_LISTEN | TCP_STATE_CLOSE => Transition::None,
        _ => Transition::Closed,
    }
}

/// What a state change means for an edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    Opened,
    Closed,
    Failed,
    None,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_shared_types_carry_no_implicit_padding() {
        assert_eq!(mem::size_of::<TcpEdgeKey>(), 48);
        assert_eq!(mem::size_of::<TcpEdgeCounts>(), 48);
        assert_eq!(mem::size_of::<TcpHealthConfig>(), 76);
    }

    #[test]
    fn the_service_port_is_the_lower_one() {
        assert_eq!(service_port(443, 51_000), (443, true));
        assert_eq!(service_port(51_000, 5432), (5432, false));
        assert_eq!(service_port(80, 80), (80, true));
    }

    #[test]
    fn a_connection_opens_fails_or_closes() {
        assert_eq!(
            transition(TCP_STATE_SYN_SENT, TCP_STATE_ESTABLISHED),
            Transition::Opened
        );
        assert_eq!(
            transition(TCP_STATE_SYN_RECV, TCP_STATE_ESTABLISHED),
            Transition::Opened
        );
        assert_eq!(
            transition(TCP_STATE_SYN_SENT, TCP_STATE_CLOSE),
            Transition::Failed
        );
        assert_eq!(
            transition(TCP_STATE_SYN_RECV, TCP_STATE_CLOSE),
            Transition::Failed
        );
        assert_eq!(
            transition(TCP_STATE_ESTABLISHED, TCP_STATE_CLOSE),
            Transition::Closed
        );
        assert_eq!(transition(8, TCP_STATE_CLOSE), Transition::Closed);
        assert_eq!(
            transition(TCP_STATE_LISTEN, TCP_STATE_CLOSE),
            Transition::None
        );
        assert_eq!(
            transition(TCP_STATE_CLOSE, TCP_STATE_SYN_SENT),
            Transition::None
        );
        assert_eq!(transition(TCP_STATE_ESTABLISHED, 4), Transition::None);
    }
}
