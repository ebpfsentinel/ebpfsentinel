//! Process lifecycle: the moments a pid starts, stops and begets another.
//!
//! A pid is not an identity. It is a number the kernel reuses, and a table
//! built by walking `/proc` learns about a process some time after it started
//! and about its death whenever the walk next happens to look. Between those
//! two inaccuracies sits the only question an operator asks of attribution:
//! which binary is this, and what started it.
//!
//! `sched_process_exec`, `sched_process_fork` and `sched_process_exit` answer
//! it at the instants that matter. The exec notification arrives with the new
//! image already in place, so the userspace table reads `/proc/<pid>/exe`
//! while the process is certain to exist; the fork notification creates the
//! child before it has had a chance to do anything, so a worker that never
//! execs still has a name and a parent; the exit notification is what purges
//! the entry, so a pid the kernel hands out again cannot be read as the
//! process that held it before.
//!
//! The parent travels with every record, read from `task_struct` in the
//! kernel rather than from `/proc` afterwards, because a parent that has
//! exited by the time userspace looks has already been replaced by whichever
//! reaper adopted the child. It is named by its tgid and by its start time,
//! the pair that survives pid reuse. The offsets that walk takes are read
//! from the running kernel's BTF by userspace and written into
//! `PROCESS_LAYOUT` before anything attaches, so the object pins no layout;
//! a layout that was never written leaves the parent unknown rather than
//! guessed. The executable path, the command line and the container are
//! still resolved in userspace.

/// Event kind: a task replaced its image, so a pid now means something new.
pub const PROCESS_EVENT_EXEC: u8 = 1;
/// Event kind: a thread group leader exited, so the pid means nothing again.
pub const PROCESS_EVENT_EXIT: u8 = 2;
/// Event kind: a process forked a new process (not a thread). The record
/// describes the child; its parent is the task that forked it.
pub const PROCESS_EVENT_FORK: u8 = 3;
/// Event kind: the arguments a task was started with, sent as a
/// [`ProcessArgv`] just before the exec record of the same task.
pub const PROCESS_EVENT_ARGV: u8 = 4;

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
/// Metric index: fork notifications written to the ring buffer.
pub const PROCESS_METRIC_FORK: u32 = 4;
/// Metric index: forks that created a thread rather than a process, which
/// are discarded in the kernel for the same reason a thread exit is.
pub const PROCESS_METRIC_THREAD_FORK: u32 = 5;
/// Metric index: records sent with no parent because the layout was never
/// written or a read through it failed, and forks not sent at all because
/// the child could not be read. Nonzero means lineage on this node is
/// partial, which is what the counter is for.
pub const PROCESS_METRIC_UNRESOLVED: u32 = 6;
/// Metric index: records not sent because the task has no number in the pid
/// namespace the agent reads `/proc` in, so no pid the table could act on.
/// Only a node whose agent reads a namespace other than the initial one, a
/// container node, counts here: the tasks of the machine around it.
pub const PROCESS_METRIC_OUTSIDE_NAMESPACE: u32 = 7;
/// Metric index: argument records written to the ring buffer.
pub const PROCESS_METRIC_ARGV: u32 = 8;
/// Metric index: execs whose arguments were not sent, because the ring was
/// more than half full, the layout was never written or the first read
/// failed. Userspace then reads `/proc/<pid>/cmdline` as it would with no
/// kernel copy at all, so the counter says how often that race is run.
pub const PROCESS_METRIC_ARGV_LOST: u32 = 9;
/// Total number of process metric slots (one past the last index).
pub const PROCESS_METRIC_COUNT: u32 = 10;

/// Deepest pid namespace nesting the kernel allows (`MAX_PID_NS_LEVEL`), so
/// one more than the highest level a `struct pid` holds a number at.
pub const PROCESS_PID_NS_LEVELS: u32 = 33;

/// Size of `struct upid`, one entry of `struct pid.numbers`: an `int` and a
/// pointer, which userspace confirms from BTF before it writes the layout.
pub const PROCESS_UPID_SIZE: u32 = 16;

/// Length of the `comm` field, as the kernel defines `TASK_COMM_LEN`.
pub const PROCESS_COMM_LEN: usize = 16;

/// Capacity of the process ring buffer, in bytes.
///
/// Exec, fork and exit are rare next to packets - a busy node runs thousands a
/// minute, not millions a second - but a fork precedes nearly every exec, so a
/// kernel build or a container storm sends about twice the records an exec
/// ring would see. 256 pages is a megabyte, room for some thirteen thousand
/// records of eighty bytes with their ring header, which is the burst it has
/// to absorb between two drains.
pub const PROCESS_EVENTS_RINGBUF_BYTES: u32 = 256 * 4096;

/// Most bytes of arguments an argument record carries, the same bound the
/// command line read from `/proc` is held to.
pub const PROCESS_ARGV_BOUND: u32 = 4096;

/// Bytes one kernel read of an argument may write. An argument longer than
/// this is read again from where the previous read stopped.
pub const PROCESS_ARGV_CHUNK: u32 = 512;

/// Most reads one exec spends on its arguments. Every argument costs one
/// read and a long one a read per chunk, so this bounds the loop the
/// verifier walks whatever the argument count.
pub const PROCESS_ARGV_MAX_READS: u32 = 64;

/// Where `linux_binprm` keeps what the argument read needs, for the running
/// kernel, as userspace read it from BTF.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessArgvLayout {
    /// Byte offset of `linux_binprm.p`, the user address of the first
    /// argument once the strings are copied into the new image.
    pub binprm_p: u32,
    /// Byte offset of `linux_binprm.argc`.
    pub binprm_argc: u32,
    /// Nonzero once userspace wrote the layout.
    pub valid: u32,
    pub _pad: u32,
}

/// The arguments of one exec, as the kernel read them from the new image.
///
/// The bytes are what `/proc/<pid>/cmdline` holds: each argument followed by
/// a NUL, in order. The tail past the last read reaches into the chunk a
/// final read may write, which is why the buffer is one chunk longer than
/// the bound.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessArgv {
    /// The same header an exec record carries, kind `PROCESS_EVENT_ARGV`.
    pub header: ProcessEvent,
    /// How many arguments the task was started with.
    pub argc: u32,
    /// How many were read whole. Fewer than `argc` means the line was cut.
    pub args_read: u32,
    /// Bytes of `bytes` written.
    pub len: u32,
    pub _pad: u32,
    pub bytes: [u8; (PROCESS_ARGV_BOUND + PROCESS_ARGV_CHUNK) as usize],
}

// Enough reads to fill the bound with arguments of a chunk each.
const _: () = assert!(PROCESS_ARGV_MAX_READS * PROCESS_ARGV_CHUNK >= PROCESS_ARGV_BOUND);
// Half the ring, the share argument records may take, holds a hundred.
const _: () = assert!(
    PROCESS_EVENTS_RINGBUF_BYTES / 2 / (core::mem::size_of::<ProcessArgv>() as u32 + 8) >= 100
);

/// Where `task_struct` keeps what the parent walk reads, for the running
/// kernel, as userspace read it from BTF.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessLayout {
    /// Byte offset of `task_struct.real_parent`.
    pub task_real_parent: u32,
    /// Byte offset of `task_struct.group_leader`.
    pub task_group_leader: u32,
    /// Byte offset of `task_struct.tgid`.
    pub task_tgid: u32,
    /// Byte offset of `task_struct.start_boottime`.
    pub task_start_boottime: u32,
    /// Nonzero once userspace wrote the layout. Zero is what an unwritten
    /// array slot holds, and the programs then read no parent at all.
    pub valid: u32,
    /// Nonzero once the five offsets below were read, which numbering a task
    /// other than the caller in the agent's pid namespace needs: the child
    /// of a fork and the parent of every record.
    pub ns_valid: u32,
    /// Byte offset of `task_struct.thread_pid`.
    pub task_thread_pid: u32,
    /// Byte offset of `pid.level`.
    pub pid_level: u32,
    /// Byte offset of `pid.numbers`.
    pub pid_numbers: u32,
    /// Byte offset of `upid.ns`.
    pub upid_ns: u32,
    /// Byte offset of `ns_common.inum` from the start of `pid_namespace`,
    /// the `ns` member's offset and the inode's within it added together.
    pub pid_namespace_inum: u32,
    pub _pad: u32,
}

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
    /// The process's own start, `start_boottime` of its thread group leader,
    /// on the clock `at_ns` uses. With the tgid it is the identity a reused
    /// pid cannot impersonate. 0 where it could not be read.
    pub start_ns: u64,
    /// The parent's start, read the same way. 0 where it could not be read.
    pub parent_start_ns: u64,
    /// Thread id (lower half of `bpf_get_current_pid_tgid`), and the child's
    /// tgid on a fork record.
    pub pid: u32,
    /// Process id, the key the userspace table uses. The child on a fork.
    pub tgid: u32,
    /// Real user id of the task.
    pub uid: u32,
    /// Real group id of the task.
    pub gid: u32,
    /// The parent's tgid, `real_parent` at the moment of the record. 0 where
    /// it could not be read, which no live process has as a parent.
    pub parent_tgid: u32,
    /// `PROCESS_EVENT_*`.
    pub kind: u8,
    pub _pad: [u8; 3],
    /// The kernel's `comm`, NUL-padded. Sixteen bytes and truncated by the
    /// kernel itself, so it is a hint and never the identity: the path is
    /// resolved in userspace and the hash is what will eventually prove it.
    pub comm: [u8; PROCESS_COMM_LEN],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProcessEvent {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProcessLayout {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ProcessArgvLayout {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_event_is_seventy_two_bytes_with_no_implicit_padding() {
        // Written by a kernel program and read by a userspace reader, compiled
        // separately and agreeing on nothing but this layout.
        assert_eq!(mem::size_of::<ProcessEvent>(), 72);
        assert_eq!(mem::align_of::<ProcessEvent>(), 8);
        assert_eq!(mem::offset_of!(ProcessEvent, at_ns), 0);
        assert_eq!(mem::offset_of!(ProcessEvent, cgroup_id), 8);
        assert_eq!(mem::offset_of!(ProcessEvent, start_ns), 16);
        assert_eq!(mem::offset_of!(ProcessEvent, parent_start_ns), 24);
        assert_eq!(mem::offset_of!(ProcessEvent, pid), 32);
        assert_eq!(mem::offset_of!(ProcessEvent, tgid), 36);
        assert_eq!(mem::offset_of!(ProcessEvent, uid), 40);
        assert_eq!(mem::offset_of!(ProcessEvent, gid), 44);
        assert_eq!(mem::offset_of!(ProcessEvent, parent_tgid), 48);
        assert_eq!(mem::offset_of!(ProcessEvent, kind), 52);
        assert_eq!(mem::offset_of!(ProcessEvent, comm), 56);
    }

    #[test]
    fn the_layout_is_twelve_words() {
        assert_eq!(mem::size_of::<ProcessLayout>(), 48);
        assert_eq!(mem::offset_of!(ProcessLayout, valid), 16);
        assert_eq!(mem::offset_of!(ProcessLayout, ns_valid), 20);
        assert_eq!(mem::offset_of!(ProcessLayout, pid_namespace_inum), 40);
        // An unwritten slot reads as no layout.
        assert_eq!(ProcessLayout::default().valid, 0);
    }

    #[test]
    fn exec_and_exit_are_different_and_neither_is_zero() {
        // Zero is "no kind", which a zeroed record already says.
        assert_ne!(PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT);
        assert_ne!(PROCESS_EVENT_EXEC, 0);
        assert_ne!(PROCESS_EVENT_EXIT, 0);
        assert_ne!(PROCESS_EVENT_FORK, 0);
        assert_ne!(PROCESS_EVENT_FORK, PROCESS_EVENT_EXEC);
        assert_ne!(PROCESS_EVENT_FORK, PROCESS_EVENT_EXIT);
        assert_ne!(PROCESS_EVENT_ARGV, 0);
        assert_ne!(PROCESS_EVENT_ARGV, PROCESS_EVENT_EXEC);
        assert_ne!(PROCESS_EVENT_ARGV, PROCESS_EVENT_EXIT);
        assert_ne!(PROCESS_EVENT_ARGV, PROCESS_EVENT_FORK);
    }

    #[test]
    fn the_argument_record_starts_with_the_event_and_has_no_implicit_padding() {
        assert_eq!(mem::offset_of!(ProcessArgv, header), 0);
        assert_eq!(mem::offset_of!(ProcessArgv, argc), 72);
        assert_eq!(mem::offset_of!(ProcessArgv, args_read), 76);
        assert_eq!(mem::offset_of!(ProcessArgv, len), 80);
        assert_eq!(mem::offset_of!(ProcessArgv, bytes), 88);
        assert_eq!(
            mem::size_of::<ProcessArgv>(),
            88 + (PROCESS_ARGV_BOUND + PROCESS_ARGV_CHUNK) as usize
        );
        assert_eq!(mem::align_of::<ProcessArgv>(), 8);
    }

    #[test]
    fn the_argument_layout_is_four_words() {
        assert_eq!(mem::size_of::<ProcessArgvLayout>(), 16);
        assert_eq!(ProcessArgvLayout::default().valid, 0);
    }

    #[test]
    fn the_metric_count_is_one_past_the_last_slot() {
        assert_eq!(PROCESS_METRIC_ARGV, PROCESS_METRIC_OUTSIDE_NAMESPACE + 1);
        assert_eq!(PROCESS_METRIC_COUNT, PROCESS_METRIC_ARGV_LOST + 1);
    }
}
