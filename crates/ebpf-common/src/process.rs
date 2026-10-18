//! Process lifecycle: the two moments a pid starts and stops meaning
//! something.
//!
//! A pid is not an identity. It is a number the kernel reuses, and a table
//! built by walking `/proc` learns about a process some time after it started
//! and about its death whenever the walk next happens to look. Between those
//! two inaccuracies sits the only question an operator asks of attribution:
//! which binary is this.
//!
//! `sched_process_exec` and `sched_process_exit` answer it at the two instants
//! that matter. The exec notification arrives with the new image already in
//! place, so the userspace table reads `/proc/<pid>/exe` while the process is
//! certain to exist; the exit notification is what purges the entry, so a pid
//! the kernel hands out again cannot be read as the process that held it
//! before.
//!
//! What the kernel sends is deliberately thin: the task's own numbers, its
//! cgroup and its `comm`. The executable path, the command line, the parent
//! and the container are resolved in userspace, because they live in
//! structures a raw tracepoint cannot read without pinning itself to one
//! kernel's layout.

/// Event kind: a task replaced its image, so a pid now means something new.
pub const PROCESS_EVENT_EXEC: u8 = 1;
/// Event kind: a thread group leader exited, so the pid means nothing again.
pub const PROCESS_EVENT_EXIT: u8 = 2;

/// Metric index: exec notifications written to the ring buffer.
pub const PROCESS_METRIC_EXEC: u32 = 0;
/// Metric index: exit notifications written to the ring buffer.
pub const PROCESS_METRIC_EXIT: u32 = 1;
/// Metric index: notifications the ring buffer had no room for. A full ring
/// means the table misses a start or keeps a dead entry until its pid is
/// reused, which is why it is counted rather than inferred.
pub const PROCESS_METRIC_DROPPED: u32 = 2;
/// Metric index: exit notifications for a thread rather than for the process,
/// which are discarded in the kernel so the ring carries only what the table
/// can act on.
pub const PROCESS_METRIC_THREAD_EXIT: u32 = 3;
/// Total number of process metric slots (one past the last index).
pub const PROCESS_METRIC_COUNT: u32 = 4;

/// Length of the `comm` field, as the kernel defines `TASK_COMM_LEN`.
pub const PROCESS_COMM_LEN: usize = 16;

/// Capacity of the process ring buffer, in bytes.
///
/// Exec and exit are rare next to packets - a busy node runs thousands a
/// minute, not millions a second - so 64 pages is several seconds of burst at
/// a rate no realistic host sustains, and a kernel build or a container storm
/// is exactly the burst it has to absorb.
pub const PROCESS_EVENTS_RINGBUF_BYTES: u32 = 64 * 4096;

/// One process lifecycle notification, as the kernel sends it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessEvent {
    /// `bpf_ktime_get_boot_ns` when the tracepoint fired.
    pub at_ns: u64,
    /// cgroup v2 id of the task, 0 where the kernel has none. The same number
    /// a socket identity carries, which is what lets a flow and a process be
    /// talked about in the same sentence.
    pub cgroup_id: u64,
    /// Thread id (lower half of `bpf_get_current_pid_tgid`).
    pub pid: u32,
    /// Process id (upper half), the key the userspace table uses.
    pub tgid: u32,
    /// Real user id of the task.
    pub uid: u32,
    /// Real group id of the task.
    pub gid: u32,
    /// The kernel's `comm`, NUL-padded. Sixteen bytes and truncated by the
    /// kernel itself, so it is a hint and never the identity: the path is
    /// resolved in userspace and the hash is what will eventually prove it.
    pub comm: [u8; PROCESS_COMM_LEN],
    /// `PROCESS_EVENT_*`.
    pub kind: u8,
    pub _pad: [u8; 7],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProcessEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_event_is_fifty_six_bytes_with_no_implicit_padding() {
        // Written by a kernel program and read by a userspace reader, compiled
        // separately and agreeing on nothing but this layout.
        assert_eq!(mem::size_of::<ProcessEvent>(), 56);
        assert_eq!(mem::align_of::<ProcessEvent>(), 8);
        assert_eq!(mem::offset_of!(ProcessEvent, at_ns), 0);
        assert_eq!(mem::offset_of!(ProcessEvent, cgroup_id), 8);
        assert_eq!(mem::offset_of!(ProcessEvent, pid), 16);
        assert_eq!(mem::offset_of!(ProcessEvent, tgid), 20);
        assert_eq!(mem::offset_of!(ProcessEvent, uid), 24);
        assert_eq!(mem::offset_of!(ProcessEvent, gid), 28);
        assert_eq!(mem::offset_of!(ProcessEvent, comm), 32);
        assert_eq!(mem::offset_of!(ProcessEvent, kind), 48);
    }

    #[test]
    fn exec_and_exit_are_different_and_neither_is_zero() {
        // Zero is "no kind", which a zeroed record already says.
        assert_ne!(PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT);
        assert_ne!(PROCESS_EVENT_EXEC, 0);
        assert_ne!(PROCESS_EVENT_EXIT, 0);
    }

    #[test]
    fn the_metric_count_is_one_past_the_last_slot() {
        assert_eq!(PROCESS_METRIC_COUNT, PROCESS_METRIC_THREAD_EXIT + 1);
    }
}
