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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

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
