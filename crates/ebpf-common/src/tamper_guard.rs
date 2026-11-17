//! Nobody but the agent stops it, traces it or takes its pins away, decided
//! at the BPF LSM hooks.
//!
//! Five hooks, all inert until userspace writes a valid configuration slot,
//! which only a licensed build does:
//!
//! - `task_kill` refuses the signals in the configured set to the protected
//!   thread groups when they come from any other task. The kernel calls the
//!   hook only for a signal a task sends, so the kernel's own (the OOM
//!   killer's, a parent's death signal) are never decided here.
//! - `ptrace_access_check` refuses an attach-mode access to a protected task:
//!   `ptrace(2)`, `process_vm_writev(2)` and opening `/proc/<pid>/mem`, all of
//!   which the kernel asks this hook about before it proceeds. Read-mode
//!   access, which `ps` and `/proc/<pid>/status` need, is let through.
//! - `inode_unlink` and `inode_rename` refuse removing or moving away a
//!   protected file, or anything inside a protected directory: the pinned
//!   links and the configuration.
//! - `file_open` refuses a write-open of `cgroup.kill` or `cgroup.freeze` in
//!   a protected cgroup directory, which would kill or freeze the agent
//!   without sending it a signal.
//!
//! A protected task, and any task while the stop window is open, passes all
//! of them except `ptrace_access_check`: a stop that was authorised needs to
//! deliver a signal and to remove the pins, never to read the agent's memory.
//!
//! Tasks are named as the bpf guard names them, a thread group in a pid
//! namespace userspace stat-ed, and both the caller and the target of a
//! signal are read off their `struct pid` at every level, so a container
//! numbering is compared in the container.

/// Index of the single slot in `TAMPER_GUARD_CONFIG` and in
/// `TAMPER_GUARD_WINDOW`.
pub const TAMPER_GUARD_CONFIG_SLOT: u32 = 0;

/// How many thread groups the guard protects: the agent and the warden, with
/// room for both to have restarted once.
pub const TAMPER_GUARD_MAX_TASKS: u32 = 4;

/// How many inodes the guard protects: the pin directory, the configuration
/// files and the cgroup directories above the agent.
pub const TAMPER_GUARD_MAX_INODES: u32 = 256;

/// Deepest pid namespace nesting the walk reads. The kernel allows 32.
pub const TAMPER_GUARD_PID_NS_LEVELS: u32 = 8;

/// Bytes of one `struct upid` (`int nr` padded, then `struct pid_namespace *`).
pub const TAMPER_GUARD_UPID_SIZE: u32 = 16;

/// What a hook returns to refuse: `-EPERM`.
pub const TAMPER_GUARD_REFUSAL: i32 = -1;

/// `PTRACE_MODE_ATTACH`, the access mode a tracer or a memory writer asks.
pub const TAMPER_GUARD_PTRACE_MODE_ATTACH: u32 = 0x02;

/// `FMODE_WRITE`, the bit a file opened for writing carries.
pub const TAMPER_GUARD_FMODE_WRITE: u32 = 0x2;

/// Bytes of a file name the record and the `file_open` hook read.
pub const TAMPER_GUARD_NAME_BYTES: usize = 16;

/// Size of the ring the refusals are reported through.
pub const TAMPER_GUARD_EVENTS_RINGBUF_BYTES: u32 = 64 * 1024;

/// An inode whose entries are protected: the pin directory.
pub const TAMPER_GUARD_INODE_DIRECTORY: u8 = 1;
/// An inode protected itself: a configuration file.
pub const TAMPER_GUARD_INODE_FILE: u8 = 2;
/// A cgroup directory holding a protected task, whose `cgroup.kill` and
/// `cgroup.freeze` are refused for writing.
pub const TAMPER_GUARD_INODE_CGROUP: u8 = 3;

/// A signal was refused.
pub const TAMPER_GUARD_KIND_SIGNAL: u8 = 1;
/// A trace or a memory access was refused.
pub const TAMPER_GUARD_KIND_PTRACE: u8 = 2;
/// An unlink was refused.
pub const TAMPER_GUARD_KIND_UNLINK: u8 = 3;
/// A rename was refused.
pub const TAMPER_GUARD_KIND_RENAME: u8 = 4;
/// A write-open of a cgroup's kill or freeze file was refused.
pub const TAMPER_GUARD_KIND_CGROUP: u8 = 5;

/// Metric index: decisions about a protected object.
pub const TAMPER_GUARD_METRIC_CHECKED: u32 = 0;
/// Metric index: refusals.
pub const TAMPER_GUARD_METRIC_REFUSED: u32 = 1;
/// Metric index: decisions let through because the stop window was open.
pub const TAMPER_GUARD_METRIC_WINDOW: u32 = 2;
/// Metric index: refusals the ring had no room to report.
pub const TAMPER_GUARD_METRIC_EVENT_LOST: u32 = 3;
/// How many counters the metrics array holds.
pub const TAMPER_GUARD_METRIC_COUNT: u32 = 4;

/// Bit of signal `n` in a signal set.
#[must_use]
pub const fn tamper_guard_signal_bit(signal: u32) -> u64 {
    if signal == 0 || signal >= 64 {
        0
    } else {
        1u64 << signal
    }
}

/// The signals refused by default: every one whose default action ends or
/// stops the agent and that it is not expected to receive from anybody but
/// itself. `SIGHUP` 1, `SIGINT` 2, `SIGQUIT` 3, `SIGKILL` 9, `SIGTERM` 15,
/// `SIGSTOP` 19, `SIGTSTP` 20.
pub const TAMPER_GUARD_DEFAULT_SIGNALS: u64 = tamper_guard_signal_bit(1)
    | tamper_guard_signal_bit(2)
    | tamper_guard_signal_bit(3)
    | tamper_guard_signal_bit(9)
    | tamper_guard_signal_bit(15)
    | tamper_guard_signal_bit(19)
    | tamper_guard_signal_bit(20);

/// The configuration slot: the signal set and the offsets the hooks read,
/// from the running kernel's BTF.
///
/// `valid` stays zero until userspace has written the slot, the tasks and the
/// inodes. A hook reading an invalid slot refuses nothing.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TamperGuardConfig {
    /// Signals refused, one bit per signal number.
    pub signals: u64,
    /// Non-zero once everything is written.
    pub valid: u32,
    /// Byte offset of `task_struct.group_leader`.
    pub task_group_leader: u32,
    /// Byte offset of `task_struct.thread_pid`.
    pub task_thread_pid: u32,
    /// Byte offset of `pid.level`.
    pub pid_level: u32,
    /// Byte offset of `pid.numbers`.
    pub pid_numbers: u32,
    /// Byte offset of `upid.ns`.
    pub upid_ns: u32,
    /// Byte offset of `ns_common.inum` from the start of `pid_namespace`.
    pub pid_namespace_inum: u32,
    /// Byte offset of `file.f_mode`.
    pub file_mode: u32,
    /// Byte offset of `file.f_path` plus `path.dentry`.
    pub file_dentry: u32,
    /// Byte offset of `dentry.d_parent`.
    pub dentry_parent: u32,
    /// Byte offset of `dentry.d_inode`.
    pub dentry_inode: u32,
    /// Byte offset of `dentry.d_name` plus `qstr.name`.
    pub dentry_name: u32,
    /// Byte offset of `inode.i_ino`.
    pub inode_ino: u32,
    /// Byte offset of `inode.i_sb`.
    pub inode_sb: u32,
    /// Byte offset of `super_block.s_dev`.
    pub sb_dev: u32,
    pub _pad: u32,
}

/// One protected inode, by number and by device in the kernel's encoding.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct TamperGuardInode {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

/// One refusal, as the ring carries it to userspace.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TamperGuardEvent {
    /// `bpf_ktime_get_boot_ns` at the refusal.
    pub at_ns: u64,
    /// Inode refused, for an unlink, a rename or a cgroup file; zero
    /// otherwise.
    pub ino: u64,
    /// Thread group of the caller, as the kernel numbers it at the top.
    pub caller_tgid: u32,
    /// Thread group of the protected target, as its own namespace numbers it,
    /// for a signal or a trace; zero otherwise.
    pub target_tgid: u32,
    /// Device of the inode refused, in the kernel's encoding.
    pub dev: u32,
    /// The signal refused, or the ptrace mode.
    pub detail: u32,
    /// One of the `TAMPER_GUARD_KIND_*` values.
    pub kind: u8,
    pub _pad: [u8; 7],
    /// The caller's command name.
    pub comm: [u8; TAMPER_GUARD_NAME_BYTES],
    /// The file name refused, when there is one.
    pub name: [u8; TAMPER_GUARD_NAME_BYTES],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TamperGuardConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for TamperGuardInode {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_config_is_laid_out_as_the_kernel_reads_it() {
        assert_eq!(mem::size_of::<TamperGuardConfig>(), 72);
        assert_eq!(mem::offset_of!(TamperGuardConfig, valid), 8);
        assert_eq!(mem::offset_of!(TamperGuardConfig, sb_dev), 64);
    }

    #[test]
    fn the_inode_key_is_sixteen_bytes() {
        assert_eq!(mem::size_of::<TamperGuardInode>(), 16);
    }

    #[test]
    fn the_event_has_no_implicit_padding() {
        assert_eq!(mem::size_of::<TamperGuardEvent>(), 72);
        assert_eq!(mem::offset_of!(TamperGuardEvent, kind), 32);
        assert_eq!(mem::offset_of!(TamperGuardEvent, comm), 40);
        assert_eq!(mem::offset_of!(TamperGuardEvent, name), 56);
    }

    #[test]
    fn the_default_set_is_the_signals_that_end_or_stop_a_process() {
        for signal in [1, 2, 3, 9, 15, 19, 20] {
            assert_ne!(
                TAMPER_GUARD_DEFAULT_SIGNALS & tamper_guard_signal_bit(signal),
                0
            );
        }
        for signal in [0, 10, 12, 17, 18, 28] {
            assert_eq!(
                TAMPER_GUARD_DEFAULT_SIGNALS & tamper_guard_signal_bit(signal),
                0
            );
        }
        assert_eq!(tamper_guard_signal_bit(64), 0);
    }
}
