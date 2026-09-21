pub use crate::firewall::VLAN_ANY;

/// Maximum number of `QoS` pipe configurations.
pub const MAX_QOS_PIPES: u32 = 64;
/// Maximum number of `QoS` queue configurations.
pub const MAX_QOS_QUEUES: u32 = 256;
/// Maximum number of `QoS` classifier entries.
pub const MAX_QOS_CLASSIFIERS: u32 = 1024;
/// Maximum number of per-flow `QoS` states.
pub const MAX_QOS_FLOW_STATES: u32 = 65536;

// ── Metric indices ───────────────────────────────────────────────────

/// Metric index: total packets seen by `QoS`.
pub const QOS_METRIC_TOTAL_SEEN: u32 = 0;
/// Metric index: packets shaped (delayed or rate-limited).
pub const QOS_METRIC_SHAPED: u32 = 1;
/// Metric index: packets dropped due to configured loss rate.
pub const QOS_METRIC_DROPPED_LOSS: u32 = 2;
/// Metric index: packets dropped due to queue overflow.
pub const QOS_METRIC_DROPPED_QUEUE: u32 = 3;
/// Metric index: packets delayed by pipe configuration.
pub const QOS_METRIC_DELAYED: u32 = 4;
/// Metric index: internal errors.
pub const QOS_METRIC_ERRORS: u32 = 5;
/// Metric index: events dropped (ring buffer full).
pub const QOS_METRIC_EVENTS_DROPPED: u32 = 6;
/// Total number of `QoS` metric slots.
pub const QOS_METRIC_COUNT: u32 = 7;

// ── Shared eBPF map types ────────────────────────────────────────────

/// `QoS` pipe configuration written by userspace, read by eBPF.
///
/// Models a dummynet-style pipe: bandwidth limit, propagation delay, and
/// random packet loss.
///
/// Size: 40 bytes (aligned to 8 bytes due to u64 fields).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosPipeConfig {
    /// Bandwidth expressed as nanoseconds per byte (`8e9 / bw_bps`).
    /// The token bucket grants one byte of credit every `ns_per_byte`
    /// nanoseconds. 0 = unlimited (rate too high to represent, or unset).
    pub ns_per_byte: u64,
    /// Maximum burst size in bytes (token bucket capacity).
    pub burst_bytes: u64,
    /// Propagation delay in nanoseconds.
    pub delay_ns: u64,
    /// Random loss rate in basis points (0-10000 = 0%-100%).
    pub loss_rate: u16,
    /// Pipe identifier (0-63).
    pub pipe_id: u8,
    /// Whether this pipe is enabled (1) or disabled (0).
    pub enabled: u8,
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
    /// Tenant ID (0 = floating rule, applies to all tenants).
    pub tenant_id: u32,
    /// Which hook this pipe shapes: [`QOS_DIR_EGRESS`], [`QOS_DIR_INGRESS`]
    /// or [`QOS_DIR_BOTH`]. The program is attached to both TC hooks, so a
    /// pipe that does not name the hook it is running on must be skipped;
    /// without this every pipe would be applied twice, once per direction.
    pub direction: u8,
    /// Explicit trailing padding to reach 8-byte alignment (40 bytes total).
    pub _pad: [u8; 3],
}

// ── Pipe direction ───────────────────────────────────────────────────

/// [`QosPipeConfig::direction`]: shape packets leaving the interface.
pub const QOS_DIR_EGRESS: u8 = 0;
/// [`QosPipeConfig::direction`]: shape packets arriving on the interface.
pub const QOS_DIR_INGRESS: u8 = 1;
/// [`QosPipeConfig::direction`]: shape both directions.
pub const QOS_DIR_BOTH: u8 = 2;

/// Whether a pipe with `direction` shapes packets on the hook described by
/// `is_ingress`.
///
/// Egress is the encoding of the default, so an unknown value shapes egress
/// rather than nothing: a pipe whose direction userspace failed to translate
/// still does the thing its configuration most likely asked for.
#[must_use]
pub const fn qos_direction_matches(direction: u8, is_ingress: bool) -> bool {
    match direction {
        QOS_DIR_BOTH => true,
        QOS_DIR_INGRESS => is_ingress,
        _ => !is_ingress,
    }
}

/// `QoS` queue configuration written by userspace, read by eBPF.
///
/// A queue names the pipe that shapes the traffic reaching it. Shaping itself
/// lives entirely on the pipe, so the queue carries no scheduling parameters.
///
/// Size: 4 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosQueueConfig {
    /// Pipe this queue is attached to.
    pub pipe_id: u8,
    /// Whether this queue is enabled (1) or disabled (0).
    pub enabled: u8,
    /// Explicit trailing padding to reach 4-byte alignment.
    pub _padding: [u8; 2],
}

/// Key for the `QoS` classifier `HashMap`.
///
/// Identifies a flow by 5-tuple plus DSCP and VLAN.
///
/// Size: 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QosClassifierKey {
    /// Source IPv4 address (0 = wildcard).
    pub src_ip: u32,
    /// Destination IPv4 address (0 = wildcard).
    pub dst_ip: u32,
    /// Source port (0 = wildcard).
    pub src_port: u16,
    /// Destination port (0 = wildcard).
    pub dst_port: u16,
    /// IP protocol number (0 = wildcard).
    pub protocol: u8,
    /// DSCP value (0 = wildcard).
    pub dscp: u8,
    /// 802.1Q VLAN ID: [`VLAN_ANY`] = any, 0 = untagged only, 1-4094 = exact.
    ///
    /// Unlike the other fields, 0 cannot mean "wildcard" here: an untagged
    /// frame is reported as VLAN 0, so 0 is a value an operator may legitimately
    /// want to single out. Hence the out-of-band sentinel.
    pub vlan_id: u16,
}

/// Value for the `QoS` classifier `HashMap`.
///
/// Maps a classified flow to the queue that carries it.
///
/// Size: 12 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosClassifierValue {
    /// Queue ID this flow is assigned to.
    pub queue_id: u8,
    /// Explicit padding before the 4-byte-aligned fields below.
    pub _padding: [u8; 3],
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
    /// Tenant ID (0 = floating rule, applies to all tenants).
    pub tenant_id: u32,
}

/// Per-pipe token bucket state managed by the eBPF program.
///
/// The bucket belongs to the pipe, not to the flow: a pipe declaring 100 Mbps
/// caps the traffic reaching it at 100 Mbps in total, however many flows are
/// classified into it. The entry is shared by every CPU, so concurrent
/// accounting on a multi-queue NIC is approximate at the packet level.
///
/// Size: 16 bytes (aligned to 8 bytes due to u64 fields).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosPipeState {
    /// Current token count (bytes). Zero on a never-used pipe, which the
    /// first packet turns into a full bucket via the elapsed-time refill.
    pub tokens: u64,
    /// Last token refill timestamp from `bpf_ktime_get_boot_ns()`.
    pub last_refill_ns: u64,
}

/// Per-flow `QoS` state managed by the eBPF program.
///
/// Pacing is the one thing that has to be tracked per flow: the departure
/// time of the next packet is only meaningful relative to the previous packet
/// of the same flow. Bandwidth lives on [`QosPipeState`].
///
/// Size: 16 bytes (aligned to 8 bytes due to the u64 field).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosFlowState {
    /// Earliest departure time for next packet (monotonic ns).
    /// Used by EDT pacing to space out packets according to `delay_ns`.
    pub last_edt_ns: u64,
    /// Pipe this flow is using.
    pub pipe_id: u8,
    /// Queue this flow is assigned to.
    pub queue_id: u8,
    pub _padding: [u8; 6],
}

// SAFETY: All types are #[repr(C)], Copy, 'static, and contain only primitive types
// with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QosPipeConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QosQueueConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QosClassifierKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QosClassifierValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QosFlowState {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QosPipeState {}

// ── Classifier shapes ────────────────────────────────────────────────

// Which classifier shapes hold no rule, one bit each.
//
// The shaper's classification ladder is the widest lookup in the datapath: a
// classifier encodes "any" as a zero, so a rule is found by rebuilding its key
// from the packet with the fields it left open zeroed out, and the ladder has
// to walk every shape a rule could have been written in. That is eight hash
// lookups per VLAN scope for an unmarked packet and fifteen for a marked one,
// and it walks both scopes, so sixteen and thirty. An estate shaping on
// destination port alone pays twenty-nine misses for one hit.
//
// Userspace knows which shapes were actually loaded, so it publishes them and
// the datapath walks only those. The sense is inverted exactly as
// `FW_EMPTY_FEATURES` is: a bit *set* means that shape holds nothing, so a map
// that was never written reads zero and every step of the ladder still runs.
// A stale mask can only be slower, never wrong.
//
// The bits are laid out as two scopes of [`QOS_SCOPE_STRIDE`], the rules
// naming a VLAN first and the rules naming none second, because the ladder
// walks the two in that order and a scope whose every bit is set is a scope it
// can skip whole.
/// Shape: source and destination host, both ports.
pub const QOS_SHAPE_FULL: u32 = 0;
/// Shape: both hosts, destination port.
pub const QOS_SHAPE_HOSTS_DPORT: u32 = 1;
/// Shape: both hosts, no port.
pub const QOS_SHAPE_HOSTS: u32 = 2;
/// Shape: both ports, any host.
pub const QOS_SHAPE_PORTS: u32 = 3;
/// Shape: destination port, any host.
pub const QOS_SHAPE_DPORT: u32 = 4;
/// Shape: source port, any host.
pub const QOS_SHAPE_SPORT: u32 = 5;
/// Shape: a DSCP marking and nothing else.
pub const QOS_SHAPE_DSCP: u32 = 6;
/// Shape: a protocol and nothing else.
pub const QOS_SHAPE_PROTO: u32 = 7;
/// Shape: the catch-all that names nothing.
pub const QOS_SHAPE_CATCHALL: u32 = 8;

/// How many shapes the ladder walks in one scope.
pub const QOS_SHAPE_COUNT: u32 = 9;

/// Bit saying no rule in this scope names a DSCP.
///
/// Not a shape: it cuts the whole first pass of the ladder rather than one of
/// its steps. Every one of the six host and port shapes is probed twice, once
/// at the packet's own DSCP and once with the DSCP left open, and when no rule
/// names a DSCP the first pass can only miss.
pub const QOS_SHAPE_NO_DSCP: u32 = 9;

/// Bits one scope occupies.
pub const QOS_SCOPE_STRIDE: u32 = 10;

/// Every bit one scope occupies, the DSCP bit included.
pub const QOS_SCOPE_MASK: u32 = (1u32 << QOS_SCOPE_STRIDE) - 1;

/// The shape bits of one scope, which is the mask of a scope holding nothing.
///
/// [`QOS_SHAPE_NO_DSCP`] is deliberately left out: it says something about the
/// rules a scope holds rather than that it holds none, so a scope carrying it
/// alone is a scope full of rules that name no marking.
pub const QOS_SCOPE_SHAPES_EMPTY: u32 = (1u32 << QOS_SHAPE_COUNT) - 1;

/// The bit for `shape` in the scope of rules naming a VLAN.
#[must_use]
pub const fn qos_shape_bit_vlan(shape: u32) -> u32 {
    1u32 << shape
}

/// The bit for `shape` in the scope of rules naming no VLAN.
#[must_use]
pub const fn qos_shape_bit_any(shape: u32) -> u32 {
    1u32 << (shape + QOS_SCOPE_STRIDE)
}

/// Every bit of both scopes, which is the mask of a table holding nothing.
pub const QOS_SHAPES_ALL_EMPTY: u32 =
    ((1u32 << QOS_SCOPE_STRIDE) - 1) | (((1u32 << QOS_SCOPE_STRIDE) - 1) << QOS_SCOPE_STRIDE);

/// Which shape a classifier key has, where the ladder probes it at all.
///
/// `None` is a key no step of the ladder ever builds, so a rule holding it is
/// unreachable today and publishing anything about it would be a claim about a
/// shape that is never looked up. The caller treats it as "this set is not
/// understood" and publishes an empty mask, which leaves the ladder walking
/// every step exactly as it does now.
#[must_use]
pub const fn qos_shape_of(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    dscp: u8,
) -> Option<u32> {
    match (src_ip != 0, dst_ip != 0) {
        // Both hosts named: the ladder probes three of the four port shapes.
        // A rule naming a source port and no destination port is not one of
        // them.
        (true, true) => match (src_port != 0, dst_port != 0) {
            (true, true) => Some(QOS_SHAPE_FULL),
            (false, true) => Some(QOS_SHAPE_HOSTS_DPORT),
            (false, false) => Some(QOS_SHAPE_HOSTS),
            (true, false) => None,
        },
        // One host named and not the other. Every step of the ladder that
        // carries a host carries both, taken from the packet, so such a key is
        // never built.
        (true, false) | (false, true) => None,
        (false, false) => match (src_port != 0, dst_port != 0) {
            (true, true) => Some(QOS_SHAPE_PORTS),
            (false, true) => Some(QOS_SHAPE_DPORT),
            (true, false) => Some(QOS_SHAPE_SPORT),
            // Nothing but a protocol, a marking, or neither. A rule naming
            // both a protocol and a marking and nothing else is not probed:
            // the ladder's two bottom steps each leave the other field open.
            (false, false) => match (protocol != 0, dscp != 0) {
                (false, true) => Some(QOS_SHAPE_DSCP),
                (true, false) => Some(QOS_SHAPE_PROTO),
                (false, false) => Some(QOS_SHAPE_CATCHALL),
                (true, true) => None,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn every_shape_has_a_bit_of_its_own_in_each_scope() {
        let mut seen = 0u32;
        for shape in 0..=QOS_SHAPE_NO_DSCP {
            let vlan = qos_shape_bit_vlan(shape);
            let any = qos_shape_bit_any(shape);
            assert_eq!(seen & vlan, 0, "shape {shape} reuses a VLAN-scope bit");
            assert_eq!(seen & any, 0, "shape {shape} reuses a VLAN-agnostic bit");
            seen |= vlan | any;
        }
        assert_eq!(seen, QOS_SHAPES_ALL_EMPTY);
    }

    #[test]
    fn the_shape_count_leaves_room_for_the_dscp_bit() {
        const {
            assert!(QOS_SHAPE_NO_DSCP >= QOS_SHAPE_COUNT);
            assert!(QOS_SHAPE_NO_DSCP < QOS_SCOPE_STRIDE);
        }
    }

    #[test]
    fn a_key_the_ladder_builds_has_a_shape() {
        // One per step of the ladder, in the order it walks them.
        assert_eq!(qos_shape_of(1, 2, 3, 4, 6, 0), Some(QOS_SHAPE_FULL));
        assert_eq!(qos_shape_of(1, 2, 0, 4, 6, 0), Some(QOS_SHAPE_HOSTS_DPORT));
        assert_eq!(qos_shape_of(1, 2, 0, 0, 6, 0), Some(QOS_SHAPE_HOSTS));
        assert_eq!(qos_shape_of(0, 0, 3, 4, 6, 0), Some(QOS_SHAPE_PORTS));
        assert_eq!(qos_shape_of(0, 0, 0, 4, 6, 0), Some(QOS_SHAPE_DPORT));
        assert_eq!(qos_shape_of(0, 0, 3, 0, 6, 0), Some(QOS_SHAPE_SPORT));
        assert_eq!(qos_shape_of(0, 0, 0, 0, 0, 46), Some(QOS_SHAPE_DSCP));
        assert_eq!(qos_shape_of(0, 0, 0, 0, 6, 0), Some(QOS_SHAPE_PROTO));
        assert_eq!(qos_shape_of(0, 0, 0, 0, 0, 0), Some(QOS_SHAPE_CATCHALL));
    }

    #[test]
    fn a_key_the_ladder_never_builds_has_none() {
        // A source port with both hosts and no destination port: the ladder
        // wildcards the source port before the destination one and never the
        // other way round.
        assert_eq!(qos_shape_of(1, 2, 3, 0, 6, 0), None);
        // One host and not the other: every step carrying a host carries both.
        assert_eq!(qos_shape_of(1, 0, 0, 0, 6, 0), None);
        assert_eq!(qos_shape_of(0, 2, 0, 0, 6, 0), None);
        // A protocol and a marking and nothing else: the two bottom steps each
        // leave the other field open.
        assert_eq!(qos_shape_of(0, 0, 0, 0, 6, 46), None);
    }

    #[test]
    fn the_shape_ignores_the_marking_wherever_a_host_or_a_port_is_named() {
        // The six host and port shapes are probed at the packet's DSCP and
        // again with it left open, so a rule naming one is the same shape
        // whether or not it names a marking.
        assert_eq!(qos_shape_of(1, 2, 3, 4, 6, 46), Some(QOS_SHAPE_FULL));
        assert_eq!(qos_shape_of(0, 0, 0, 4, 6, 46), Some(QOS_SHAPE_DPORT));
    }

    // ── Size tests ───────────────────────────────────────────────────

    #[test]
    fn qos_pipe_config_size() {
        assert_eq!(mem::size_of::<QosPipeConfig>(), 40);
    }

    #[test]
    fn qos_pipe_config_alignment() {
        assert_eq!(mem::align_of::<QosPipeConfig>(), 8);
    }

    #[test]
    fn qos_queue_config_size() {
        assert_eq!(mem::size_of::<QosQueueConfig>(), 4);
    }

    #[test]
    fn qos_queue_config_alignment() {
        assert_eq!(mem::align_of::<QosQueueConfig>(), 1);
    }

    #[test]
    fn qos_classifier_key_size() {
        assert_eq!(mem::size_of::<QosClassifierKey>(), 16);
    }

    #[test]
    fn qos_classifier_key_alignment() {
        assert_eq!(mem::align_of::<QosClassifierKey>(), 4);
    }

    #[test]
    fn qos_classifier_value_size() {
        assert_eq!(mem::size_of::<QosClassifierValue>(), 12);
    }

    #[test]
    fn qos_classifier_value_alignment() {
        assert_eq!(mem::align_of::<QosClassifierValue>(), 4);
    }

    #[test]
    fn qos_flow_state_size() {
        assert_eq!(mem::size_of::<QosFlowState>(), 16);
    }

    #[test]
    fn qos_flow_state_alignment() {
        assert_eq!(mem::align_of::<QosFlowState>(), 8);
    }

    #[test]
    fn qos_pipe_state_size() {
        assert_eq!(mem::size_of::<QosPipeState>(), 16);
    }

    #[test]
    fn qos_pipe_state_alignment() {
        assert_eq!(mem::align_of::<QosPipeState>(), 8);
    }

    // ── Field offset tests ───────────────────────────────────────────

    #[test]
    fn qos_pipe_config_field_offsets() {
        assert_eq!(mem::offset_of!(QosPipeConfig, ns_per_byte), 0);
        assert_eq!(mem::offset_of!(QosPipeConfig, burst_bytes), 8);
        assert_eq!(mem::offset_of!(QosPipeConfig, delay_ns), 16);
        assert_eq!(mem::offset_of!(QosPipeConfig, loss_rate), 24);
        assert_eq!(mem::offset_of!(QosPipeConfig, pipe_id), 26);
        assert_eq!(mem::offset_of!(QosPipeConfig, enabled), 27);
        assert_eq!(mem::offset_of!(QosPipeConfig, group_mask), 28);
        assert_eq!(mem::offset_of!(QosPipeConfig, tenant_id), 32);
        assert_eq!(mem::offset_of!(QosPipeConfig, direction), 36);
        assert_eq!(mem::offset_of!(QosPipeConfig, _pad), 37);
    }

    // ── Direction ────────────────────────────────────────────────────

    #[test]
    fn egress_pipes_only_shape_the_egress_hook() {
        assert!(qos_direction_matches(QOS_DIR_EGRESS, false));
        assert!(!qos_direction_matches(QOS_DIR_EGRESS, true));
    }

    #[test]
    fn ingress_pipes_only_shape_the_ingress_hook() {
        assert!(qos_direction_matches(QOS_DIR_INGRESS, true));
        assert!(!qos_direction_matches(QOS_DIR_INGRESS, false));
    }

    #[test]
    fn bidirectional_pipes_shape_both_hooks() {
        assert!(qos_direction_matches(QOS_DIR_BOTH, true));
        assert!(qos_direction_matches(QOS_DIR_BOTH, false));
    }

    #[test]
    fn an_unknown_direction_falls_back_to_egress() {
        assert!(qos_direction_matches(u8::MAX, false));
        assert!(!qos_direction_matches(u8::MAX, true));
    }

    #[test]
    fn qos_queue_config_field_offsets() {
        assert_eq!(mem::offset_of!(QosQueueConfig, pipe_id), 0);
        assert_eq!(mem::offset_of!(QosQueueConfig, enabled), 1);
        assert_eq!(mem::offset_of!(QosQueueConfig, _padding), 2);
    }

    #[test]
    fn qos_classifier_key_field_offsets() {
        assert_eq!(mem::offset_of!(QosClassifierKey, src_ip), 0);
        assert_eq!(mem::offset_of!(QosClassifierKey, dst_ip), 4);
        assert_eq!(mem::offset_of!(QosClassifierKey, src_port), 8);
        assert_eq!(mem::offset_of!(QosClassifierKey, dst_port), 10);
        assert_eq!(mem::offset_of!(QosClassifierKey, protocol), 12);
        assert_eq!(mem::offset_of!(QosClassifierKey, dscp), 13);
        assert_eq!(mem::offset_of!(QosClassifierKey, vlan_id), 14);
    }

    #[test]
    fn qos_classifier_value_field_offsets() {
        assert_eq!(mem::offset_of!(QosClassifierValue, queue_id), 0);
        assert_eq!(mem::offset_of!(QosClassifierValue, _padding), 1);
        assert_eq!(mem::offset_of!(QosClassifierValue, group_mask), 4);
        assert_eq!(mem::offset_of!(QosClassifierValue, tenant_id), 8);
    }

    #[test]
    fn qos_flow_state_field_offsets() {
        assert_eq!(mem::offset_of!(QosFlowState, last_edt_ns), 0);
        assert_eq!(mem::offset_of!(QosFlowState, pipe_id), 8);
        assert_eq!(mem::offset_of!(QosFlowState, queue_id), 9);
        assert_eq!(mem::offset_of!(QosFlowState, _padding), 10);
    }

    #[test]
    fn qos_pipe_state_field_offsets() {
        assert_eq!(mem::offset_of!(QosPipeState, tokens), 0);
        assert_eq!(mem::offset_of!(QosPipeState, last_refill_ns), 8);
    }

    // ── Constant tests ───────────────────────────────────────────────

    #[test]
    fn map_size_constants() {
        assert_eq!(MAX_QOS_PIPES, 64);
        assert_eq!(MAX_QOS_QUEUES, 256);
        assert_eq!(MAX_QOS_CLASSIFIERS, 1024);
        assert_eq!(MAX_QOS_FLOW_STATES, 65536);
    }

    #[test]
    fn metric_constants() {
        assert_eq!(QOS_METRIC_TOTAL_SEEN, 0);
        assert_eq!(QOS_METRIC_SHAPED, 1);
        assert_eq!(QOS_METRIC_DROPPED_LOSS, 2);
        assert_eq!(QOS_METRIC_DROPPED_QUEUE, 3);
        assert_eq!(QOS_METRIC_DELAYED, 4);
        assert_eq!(QOS_METRIC_ERRORS, 5);
        assert_eq!(QOS_METRIC_EVENTS_DROPPED, 6);
        assert_eq!(QOS_METRIC_COUNT, 7);
    }

    #[test]
    fn metric_count_covers_all() {
        // QOS_METRIC_COUNT should be one past the last index
        const _: () = assert!(QOS_METRIC_EVENTS_DROPPED < QOS_METRIC_COUNT);
    }
}
