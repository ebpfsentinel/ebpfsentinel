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
/// Size: 32 bytes (aligned to 8 bytes due to u64 fields).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosPipeConfig {
    /// Bandwidth expressed as bytes per nanosecond (`bw_bps / 8 / 1e9`).
    /// 0 = unlimited.
    pub bytes_per_ns: u64,
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
}

/// `QoS` queue configuration written by userspace, read by eBPF.
///
/// Each queue is attached to a pipe and has a scheduling weight.
///
/// Size: 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosQueueConfig {
    /// Pipe this queue is attached to.
    pub pipe_id: u8,
    pub _padding1: u8,
    /// Scheduling weight for `WF2Q+` (1-100).
    pub weight: u16,
    /// Whether this queue is enabled (1) or disabled (0).
    pub enabled: u8,
    pub _padding2: [u8; 3],
}

/// Key for the `QoS` classifier `HashMap`.
///
/// Identifies a flow by 5-tuple plus DSCP.
///
/// Size: 16 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub _padding: [u8; 2],
}

/// Value for the `QoS` classifier `HashMap`.
///
/// Maps a classified flow to a queue and priority.
///
/// Size: 8 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QosClassifierValue {
    /// Queue ID this flow is assigned to.
    pub queue_id: u8,
    /// Priority within the queue (lower = higher priority).
    pub priority: u8,
    pub _padding: [u8; 2],
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
}

/// Per-flow `QoS` state managed by the eBPF program.
///
/// Tracks token bucket state for bandwidth enforcement.
///
/// Size: 24 bytes (aligned to 8 bytes due to u64 fields).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QosFlowState {
    /// Current token count (bytes).
    pub tokens: u64,
    /// Last token refill timestamp from `bpf_ktime_get_ns()`.
    pub last_refill_ns: u64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // ── Size tests ───────────────────────────────────────────────────

    #[test]
    fn qos_pipe_config_size() {
        assert_eq!(mem::size_of::<QosPipeConfig>(), 32);
    }

    #[test]
    fn qos_pipe_config_alignment() {
        assert_eq!(mem::align_of::<QosPipeConfig>(), 8);
    }

    #[test]
    fn qos_queue_config_size() {
        assert_eq!(mem::size_of::<QosQueueConfig>(), 8);
    }

    #[test]
    fn qos_queue_config_alignment() {
        assert_eq!(mem::align_of::<QosQueueConfig>(), 2);
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
        assert_eq!(mem::size_of::<QosClassifierValue>(), 8);
    }

    #[test]
    fn qos_classifier_value_alignment() {
        assert_eq!(mem::align_of::<QosClassifierValue>(), 4);
    }

    #[test]
    fn qos_flow_state_size() {
        assert_eq!(mem::size_of::<QosFlowState>(), 24);
    }

    #[test]
    fn qos_flow_state_alignment() {
        assert_eq!(mem::align_of::<QosFlowState>(), 8);
    }

    // ── Field offset tests ───────────────────────────────────────────

    #[test]
    fn qos_pipe_config_field_offsets() {
        assert_eq!(mem::offset_of!(QosPipeConfig, bytes_per_ns), 0);
        assert_eq!(mem::offset_of!(QosPipeConfig, burst_bytes), 8);
        assert_eq!(mem::offset_of!(QosPipeConfig, delay_ns), 16);
        assert_eq!(mem::offset_of!(QosPipeConfig, loss_rate), 24);
        assert_eq!(mem::offset_of!(QosPipeConfig, pipe_id), 26);
        assert_eq!(mem::offset_of!(QosPipeConfig, enabled), 27);
        assert_eq!(mem::offset_of!(QosPipeConfig, group_mask), 28);
    }

    #[test]
    fn qos_queue_config_field_offsets() {
        assert_eq!(mem::offset_of!(QosQueueConfig, pipe_id), 0);
        assert_eq!(mem::offset_of!(QosQueueConfig, _padding1), 1);
        assert_eq!(mem::offset_of!(QosQueueConfig, weight), 2);
        assert_eq!(mem::offset_of!(QosQueueConfig, enabled), 4);
        assert_eq!(mem::offset_of!(QosQueueConfig, _padding2), 5);
    }

    #[test]
    fn qos_classifier_key_field_offsets() {
        assert_eq!(mem::offset_of!(QosClassifierKey, src_ip), 0);
        assert_eq!(mem::offset_of!(QosClassifierKey, dst_ip), 4);
        assert_eq!(mem::offset_of!(QosClassifierKey, src_port), 8);
        assert_eq!(mem::offset_of!(QosClassifierKey, dst_port), 10);
        assert_eq!(mem::offset_of!(QosClassifierKey, protocol), 12);
        assert_eq!(mem::offset_of!(QosClassifierKey, dscp), 13);
        assert_eq!(mem::offset_of!(QosClassifierKey, _padding), 14);
    }

    #[test]
    fn qos_classifier_value_field_offsets() {
        assert_eq!(mem::offset_of!(QosClassifierValue, queue_id), 0);
        assert_eq!(mem::offset_of!(QosClassifierValue, priority), 1);
        assert_eq!(mem::offset_of!(QosClassifierValue, _padding), 2);
        assert_eq!(mem::offset_of!(QosClassifierValue, group_mask), 4);
    }

    #[test]
    fn qos_flow_state_field_offsets() {
        assert_eq!(mem::offset_of!(QosFlowState, tokens), 0);
        assert_eq!(mem::offset_of!(QosFlowState, last_refill_ns), 8);
        assert_eq!(mem::offset_of!(QosFlowState, pipe_id), 16);
        assert_eq!(mem::offset_of!(QosFlowState, queue_id), 17);
        assert_eq!(mem::offset_of!(QosFlowState, _padding), 18);
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
