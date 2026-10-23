//! Sending a signal to the task behind a flow, from the task's own context.
//!
//! Every other response this agent takes acts on the network: an address is
//! dropped, a flow is denied, a bucket shapes a sender. None of them touches
//! what produced the traffic, so a compromised process keeps running and opens
//! the next connection.
//!
//! `bpf_send_signal` signals the thread group of whichever task the program is
//! running in, which is the whole design constraint: the helper cannot pick a
//! victim, so the program has to already be executing as the victim. That
//! rules out the cgroup and TC hooks the rest of the datapath uses (the helper
//! is not in their proto at all) and leaves a tracing program, fired on a
//! moment every live process reaches: a syscall entry.
//!
//! Userspace therefore does not kill anything. It arms a target - a thread
//! group id, a signal and an expiry - and the kernel fires once the target is
//! next on the CPU. Two things follow, and both are the point:
//!
//! - A target that never makes another syscall is never signalled. The arming
//!   expires and userspace reports a survivor rather than assuming a death.
//! - The expiry is the kernel's, not a timer's. A target armed and forgotten
//!   stops being a target at the instant written into it, even if the agent
//!   died in between.
//!
//! The protected map is the other half. Userspace refuses a protected target
//! before arming it, and the kernel refuses it again on its own, so the only
//! way to signal pid 1 is a kernel that disagrees with its own map.

/// Outcome written to the ring: the helper accepted the signal.
pub const SIGNAL_OUTCOME_SENT: u32 = 1;
/// Outcome written to the ring: the target was on the protected map, so no
/// signal was sent and the arming was dropped.
pub const SIGNAL_OUTCOME_PROTECTED: u32 = 2;
/// Outcome written to the ring: the arming had expired before the target came
/// back on the CPU.
pub const SIGNAL_OUTCOME_EXPIRED: u32 = 3;
/// Outcome written to the ring: the helper refused the signal. The arming is
/// kept, so the next syscall tries again until the expiry.
pub const SIGNAL_OUTCOME_HELPER_FAILED: u32 = 4;

/// Metric index: armings that resolved to a signal the kernel accepted.
pub const SIGNAL_METRIC_SENT: u32 = 0;
/// Metric index: armings refused in the kernel because the target was
/// protected.
pub const SIGNAL_METRIC_PROTECTED: u32 = 1;
/// Metric index: armings that expired without the target coming back on the
/// CPU.
pub const SIGNAL_METRIC_EXPIRED: u32 = 2;
/// Metric index: helper refusals. Counted separately from a protected refusal
/// because one is a decision and the other is a kernel saying no.
pub const SIGNAL_METRIC_HELPER_FAILED: u32 = 3;
/// Metric index: outcome records the ring buffer had no room for.
pub const SIGNAL_METRIC_EVENT_LOST: u32 = 4;
/// Total number of signal metric slots (one past the last index).
pub const SIGNAL_METRIC_COUNT: u32 = 5;

/// Index of the single armed-count slot in `SIGNAL_ARMED`.
pub const SIGNAL_ARMED_SLOT: u32 = 0;

/// How many targets may be armed at once.
///
/// A response that needs more than a few hundred processes killed at once is
/// not a response, it is an outage, and the budget of the response rules is
/// what is supposed to stop it long before this map fills.
pub const SIGNAL_MAX_TARGETS: u32 = 256;

/// How many thread group ids the kernel-side protected map holds.
///
/// It carries the handful userspace can name by number - pid 1, the agent, the
/// warden - rather than every process matching a protected name, because the
/// name match needs a path read and that happens in userspace before arming.
pub const SIGNAL_MAX_PROTECTED: u32 = 64;

/// Capacity of the signal outcome ring buffer, in bytes.
///
/// One record per armed target at most, and the map holds 256, so four pages
/// is already two orders of magnitude more than a burst can produce.
pub const SIGNAL_EVENTS_RINGBUF_BYTES: u32 = 4 * 4096;

/// Highest signal number the kernel defines, including the real-time range.
pub const SIGNAL_NUMBER_MAX: u32 = 64;

/// An armed target: what to send, and until when.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalTarget {
    /// `bpf_ktime_get_boot_ns` after which this arming means nothing. The
    /// kernel compares against it before every send, so an agent that dies
    /// holding armed targets leaves no standing authority to kill.
    pub expires_at_ns: u64,
    /// Signal number to send, in `1..=SIGNAL_NUMBER_MAX`.
    pub signal: u32,
    pub _pad: u32,
}

/// What came of one arming, as the kernel writes it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalEvent {
    /// `bpf_ktime_get_boot_ns` when the decision was taken.
    pub at_ns: u64,
    /// Thread group the program was running in, which is the target.
    pub tgid: u32,
    /// Signal the arming asked for, whether or not it was sent.
    pub signal: u32,
    /// `SIGNAL_OUTCOME_*`.
    pub outcome: u32,
    pub _pad: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SignalTarget {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SignalEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_target_is_sixteen_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<SignalTarget>(), 16);
        assert_eq!(mem::align_of::<SignalTarget>(), 8);
        assert_eq!(mem::offset_of!(SignalTarget, expires_at_ns), 0);
        assert_eq!(mem::offset_of!(SignalTarget, signal), 8);
    }

    #[test]
    fn the_event_is_twenty_four_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<SignalEvent>(), 24);
        assert_eq!(mem::align_of::<SignalEvent>(), 8);
        assert_eq!(mem::offset_of!(SignalEvent, at_ns), 0);
        assert_eq!(mem::offset_of!(SignalEvent, tgid), 8);
        assert_eq!(mem::offset_of!(SignalEvent, signal), 12);
        assert_eq!(mem::offset_of!(SignalEvent, outcome), 16);
    }

    #[test]
    fn every_outcome_is_distinct_and_none_is_zero() {
        // A zeroed record says nothing, so no outcome may read as one.
        let all = [
            SIGNAL_OUTCOME_SENT,
            SIGNAL_OUTCOME_PROTECTED,
            SIGNAL_OUTCOME_EXPIRED,
            SIGNAL_OUTCOME_HELPER_FAILED,
        ];
        for (i, left) in all.iter().enumerate() {
            assert_ne!(*left, 0);
            for right in &all[i + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn the_metric_count_is_one_past_the_last_slot() {
        assert_eq!(SIGNAL_METRIC_COUNT, SIGNAL_METRIC_EVENT_LOST + 1);
    }
}
