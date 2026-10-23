//! Cutting a workload off the network without stopping it.
//!
//! Signalling the process behind a flow ends the process, and an operator who
//! wants the evidence rather than the silence has nowhere to go: a dropped
//! address stops one destination, and a killed process stops the investigation
//! too. Quarantine is the middle answer - the workload keeps running, keeps its
//! memory and its open files, and reaches nothing.
//!
//! It is keyed on the cgroup rather than on an address or a thread group, which
//! is what makes it both exact and durable. Exact, because a cgroup is the one
//! identifier a container keeps across every process it forks, so a quarantined
//! workload cannot escape by spawning a child. Durable, because the kernel's own
//! socket hooks ask the question - the cgroup of the task opening the socket is
//! `bpf_get_current_cgroup_id`, read in the hook itself, so there is no table to
//! keep in step and no race between arming and the next `connect()`.
//!
//! Three properties are deliberate:
//!
//! - The expiry is the kernel's, written into the entry as a boot-clock
//!   deadline. An agent that dies holding quarantines leaves no standing
//!   authority to cut anything off: every entry stops matching at the instant
//!   written into it, whether or not anything is left to sweep it.
//! - The check runs before the workload rule array, so a node carrying no
//!   workload policy at all still quarantines. The rules are a policy document;
//!   this is a response.
//! - A quarantine refuses the new socket and says nothing about the old ones.
//!   Tearing existing flows down is userspace's job, through conntrack, because
//!   an established connection has no `connect()` left to refuse.

/// Outcome written to the ring: the socket operation was refused because the
/// task's cgroup is quarantined.
pub const QUARANTINE_OUTCOME_REFUSED: u32 = 1;
/// Outcome written to the ring: the entry matched and had expired, so the
/// operation was allowed through and the entry is stale.
pub const QUARANTINE_OUTCOME_EXPIRED: u32 = 2;
/// Outcome written to the ring: the cgroup is quarantined in report-only mode,
/// so the operation was allowed and recorded.
pub const QUARANTINE_OUTCOME_OBSERVED: u32 = 3;

/// Metric index: socket operations refused by a live quarantine.
pub const QUARANTINE_METRIC_REFUSED: u32 = 0;
/// Metric index: operations that matched an expired entry and went through.
pub const QUARANTINE_METRIC_EXPIRED: u32 = 1;
/// Metric index: operations a report-only quarantine recorded and allowed.
pub const QUARANTINE_METRIC_OBSERVED: u32 = 2;
/// Metric index: outcome records the ring buffer had no room for.
pub const QUARANTINE_METRIC_EVENT_LOST: u32 = 3;
/// Total number of quarantine metric slots (one past the last index).
pub const QUARANTINE_METRIC_COUNT: u32 = 4;

/// How many cgroups may be quarantined at once.
///
/// A response cutting off more than this many workloads at once is an outage
/// rather than a response, and the budget on the response rules is what is
/// meant to stop it long before the map fills.
pub const QUARANTINE_MAX_CGROUPS: u32 = 1_024;

/// Capacity of the quarantine outcome ring buffer, in bytes.
///
/// A quarantined workload retries, so this ring carries far more traffic than
/// the signal one: a process in a reconnect loop produces a record per attempt.
/// Sixteen pages absorbs a burst, and the counters are what is authoritative
/// when it does not.
pub const QUARANTINE_EVENTS_RINGBUF_BYTES: u32 = 16 * 4096;

/// Mode value: the quarantine refuses the socket operation.
pub const QUARANTINE_MODE_ENFORCE: u32 = 0;
/// Mode value: the quarantine records what it would have refused and allows it.
///
/// It is the same arming path and the same entry, so an operator who wants to
/// know the blast radius before cutting a production workload off gets it from
/// the capability itself rather than from a guess.
pub const QUARANTINE_MODE_REPORT: u32 = 1;

/// A quarantined cgroup: until when, and whether it refuses or only reports.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuarantineEntry {
    /// `bpf_ktime_get_boot_ns` after which this entry means nothing. The kernel
    /// compares against it on every socket operation, so an expiry needs no
    /// userspace timer to take effect.
    pub expires_at_ns: u64,
    /// `QUARANTINE_MODE_*`.
    pub mode: u32,
    pub _pad: u32,
}

/// What came of one socket operation against a quarantined cgroup.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuarantineEvent {
    /// `bpf_ktime_get_boot_ns` when the decision was taken.
    pub at_ns: u64,
    /// The cgroup the task belongs to, which is the quarantine key.
    pub cgroup_id: u64,
    /// Thread group that tried, so the record names something an operator can
    /// look up while the process is still alive.
    pub tgid: u32,
    /// Which cgroup hook took the decision, as `WORKLOAD_HOOK_*`.
    pub hook: u32,
    /// `QUARANTINE_OUTCOME_*`.
    pub outcome: u32,
    pub _pad: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QuarantineEntry {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for QuarantineEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_entry_is_sixteen_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<QuarantineEntry>(), 16);
        assert_eq!(mem::align_of::<QuarantineEntry>(), 8);
        assert_eq!(mem::offset_of!(QuarantineEntry, expires_at_ns), 0);
        assert_eq!(mem::offset_of!(QuarantineEntry, mode), 8);
    }

    #[test]
    fn the_event_is_thirty_two_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<QuarantineEvent>(), 32);
        assert_eq!(mem::align_of::<QuarantineEvent>(), 8);
        assert_eq!(mem::offset_of!(QuarantineEvent, at_ns), 0);
        assert_eq!(mem::offset_of!(QuarantineEvent, cgroup_id), 8);
        assert_eq!(mem::offset_of!(QuarantineEvent, tgid), 16);
        assert_eq!(mem::offset_of!(QuarantineEvent, hook), 20);
        assert_eq!(mem::offset_of!(QuarantineEvent, outcome), 24);
    }

    #[test]
    fn every_outcome_is_distinct_and_none_is_zero() {
        // A zeroed record says nothing, so no outcome may read as one.
        let all = [
            QUARANTINE_OUTCOME_REFUSED,
            QUARANTINE_OUTCOME_EXPIRED,
            QUARANTINE_OUTCOME_OBSERVED,
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
        assert_eq!(QUARANTINE_METRIC_COUNT, QUARANTINE_METRIC_EVENT_LOST + 1);
    }

    #[test]
    fn enforcing_is_the_zero_mode_so_a_zeroed_entry_refuses() {
        // An entry whose mode byte was lost reads as enforcing rather than as
        // report-only: a quarantine that quietly stopped refusing is the
        // failure worth making impossible.
        assert_eq!(QUARANTINE_MODE_ENFORCE, 0);
        assert_ne!(QUARANTINE_MODE_REPORT, QUARANTINE_MODE_ENFORCE);
    }
}
