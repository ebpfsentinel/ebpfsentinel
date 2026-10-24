//! Which executables may reach the network, decided at the LSM hooks.
//!
//! A workload rule naming a binary is decided in a cgroup socket hook against
//! a bit userspace wrote for the task, after reading `/proc` for it. That
//! leaves a window: a task that execs and connects before userspace has seen
//! the exec carries no bit yet. An allow-list cannot live with that window,
//! because the window is exactly where something unexpected starts.
//!
//! The LSM hooks close it by reading the identity in the kernel, from the task
//! that is making the call: `current->mm->exe_file->f_inode`, its inode number
//! and the device of its superblock. Userspace resolves the field offsets once
//! from the running kernel's BTF and stats each configured path for its
//! `(device, inode)`, so the kernel compares two integers against a hash map
//! and never a string. An inode, unlike a path, is not changed by copying a
//! binary somewhere else or by calling it through a symlink.
//!
//! Only `AF_INET` and `AF_INET6` are decided. A local socket is not the
//! network, and refusing one would break the node long before it protected
//! anything. Sockets the kernel opens for itself, and calls made by a kernel
//! thread, which has no executable to name, are never decided either.
//!
//! Observe is the default. An observing hook counts and reports what it would
//! have refused and lets the call through.

/// `mode` in the configuration slot: count and report, refuse nothing.
pub const EXEC_NET_MODE_OBSERVE: u32 = 0;
/// `mode` in the configuration slot: refuse a task outside the set.
pub const EXEC_NET_MODE_ENFORCE: u32 = 1;

/// Index of the single slot in `EXEC_NET_CONFIG`.
pub const EXEC_NET_CONFIG_SLOT: u32 = 0;

/// How many executables the allow-list holds.
///
/// A host has tens of binaries that talk to the network on purpose. A list in
/// the thousands is a list nobody reviewed, and the map is a plain hash rather
/// than an LRU, because an eviction here would be an allowed binary silently
/// refused.
pub const EXEC_NET_MAX_EXECUTABLES: u32 = 1_024;

/// How many `(thread group, hook)` pairs the report throttle remembers.
pub const EXEC_NET_MAX_REPORTED: u32 = 4_096;

/// How long a thread group is quiet on one hook after it was reported.
///
/// The counters are exact whatever this is. The throttle is on the records
/// only, because an unlisted daemon in observe mode opens a socket every few
/// milliseconds and one alert a minute says as much as a thousand.
pub const EXEC_NET_REPORT_INTERVAL_NS: u64 = 60_000_000_000;

/// Capacity of `EXEC_NET_EVENTS`, in bytes. A record is thirty-two bytes and
/// the throttle allows one per task and hook a minute, so four pages are far
/// more than a node produces.
pub const EXEC_NET_EVENTS_RINGBUF_BYTES: u32 = 4 * 4096;

/// `hook` on a record: the task was creating a socket.
pub const EXEC_NET_HOOK_CREATE: u8 = 0;
/// `hook` on a record: the task was connecting one.
pub const EXEC_NET_HOOK_CONNECT: u8 = 1;

/// `AF_INET`, one of the two families the hooks decide.
pub const EXEC_NET_AF_INET: u16 = 2;
/// `AF_INET6`, the other.
pub const EXEC_NET_AF_INET6: u16 = 10;

/// What the hook returns to refuse: `-EPERM`.
pub const EXEC_NET_REFUSAL: i32 = -1;

/// Metric index: socket creations and connections the hooks decided.
pub const EXEC_NET_METRIC_CHECKED: u32 = 0;
/// Metric index: decided calls by an executable in the set.
pub const EXEC_NET_METRIC_ALLOWED: u32 = 1;
/// Metric index: calls the kernel refused.
pub const EXEC_NET_METRIC_REFUSED: u32 = 2;
/// Metric index: calls an observing hook would have refused.
pub const EXEC_NET_METRIC_WOULD_REFUSE: u32 = 3;
/// Metric index: calls whose executable could not be read.
///
/// Such a call is outside the set. An allow-list that opened whenever a read
/// failed would be open to anybody able to make it fail, so this counter is
/// what says how often that costs a legitimate call.
pub const EXEC_NET_METRIC_UNREADABLE: u32 = 4;
/// Metric index: records the ring buffer had no room for. The decision is
/// taken whatever happens to the record.
pub const EXEC_NET_METRIC_EVENT_LOST: u32 = 5;
/// How many counters the metrics array holds.
pub const EXEC_NET_METRIC_COUNT: u32 = 6;

/// One executable, as the kernel names it.
///
/// `dev` is the kernel's own encoding of the superblock's device,
/// `(major << 20) | minor`, which is not the encoding `stat(2)` returns, so
/// userspace converts before writing.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ExecNetKey {
    pub ino: u64,
    pub dev: u32,
    pub _pad: u32,
}

/// The configuration slot: the mode, and the offsets the hooks walk from the
/// current task to the executable's inode, read from the running kernel's BTF.
///
/// `valid` stays zero until userspace has written a complete layout. A hook
/// reading an invalid slot decides nothing and lets the call through: the
/// program is attached before the slot is written, and a hook that refused
/// every call in between would be the agent cutting its own node off.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecNetConfig {
    /// `task_struct.mm`
    pub task_mm: u32,
    /// `mm_struct.exe_file`
    pub mm_exe_file: u32,
    /// `file.f_inode`
    pub file_inode: u32,
    /// `inode.i_ino`
    pub inode_ino: u32,
    /// `inode.i_sb`
    pub inode_sb: u32,
    /// `super_block.s_dev`
    pub sb_dev: u32,
    /// `EXEC_NET_MODE_*`.
    pub mode: u32,
    /// Non-zero once the slot is complete.
    pub valid: u32,
}

/// A call outside the set, as the kernel reports it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExecNetEvent {
    /// `bpf_ktime_get_boot_ns` at the decision.
    pub at_ns: u64,
    /// Inode of the executable, zero when it could not be read.
    pub ino: u64,
    /// Thread group that made the call.
    pub tgid: u32,
    /// Kernel encoding of the executable's device, zero when unread.
    pub dev: u32,
    /// `EXEC_NET_HOOK_*`.
    pub hook: u8,
    /// Non-zero when the kernel refused the call rather than observed it.
    pub refused: u8,
    /// Address family of the socket.
    pub family: u16,
    pub _pad: u32,
}

/// The kernel's encoding of a device number, from its major and minor.
///
/// The superblock keeps `MKDEV(major, minor)`, twelve bits of major above
/// twenty of minor, while `stat(2)` hands userspace a different packing of the
/// same two numbers.
#[must_use]
pub const fn kernel_dev(major: u32, minor: u32) -> u32 {
    (major << 20) | (minor & 0x000f_ffff)
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ExecNetKey {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ExecNetConfig {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ExecNetEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_key_is_sixteen_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<ExecNetKey>(), 16);
        assert_eq!(mem::offset_of!(ExecNetKey, ino), 0);
        assert_eq!(mem::offset_of!(ExecNetKey, dev), 8);
    }

    #[test]
    fn the_config_is_eight_words() {
        assert_eq!(mem::size_of::<ExecNetConfig>(), 32);
        assert_eq!(mem::offset_of!(ExecNetConfig, mode), 24);
        assert_eq!(mem::offset_of!(ExecNetConfig, valid), 28);
    }

    #[test]
    fn the_event_is_thirty_two_bytes_with_no_implicit_padding() {
        assert_eq!(mem::size_of::<ExecNetEvent>(), 32);
        assert_eq!(mem::align_of::<ExecNetEvent>(), 8);
        assert_eq!(mem::offset_of!(ExecNetEvent, tgid), 16);
        assert_eq!(mem::offset_of!(ExecNetEvent, dev), 20);
        assert_eq!(mem::offset_of!(ExecNetEvent, hook), 24);
        assert_eq!(mem::offset_of!(ExecNetEvent, refused), 25);
        assert_eq!(mem::offset_of!(ExecNetEvent, family), 26);
    }

    #[test]
    fn the_kernel_dev_is_major_above_twenty_bits_of_minor() {
        assert_eq!(kernel_dev(8, 1), 0x0080_0001);
        assert_eq!(kernel_dev(0, 0x1f_ffff), 0x000f_ffff);
    }

    #[test]
    fn the_refusal_is_eperm() {
        assert_eq!(EXEC_NET_REFUSAL, -1);
    }
}
