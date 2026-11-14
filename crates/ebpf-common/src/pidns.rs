//! The pid namespace a program numbers tasks in.
//!
//! `bpf_get_current_pid_tgid` answers with the number the initial pid
//! namespace gives a task. The agent reads `/proc` to name a task, and a
//! procfs answers in the pid namespace it was mounted from: on a machine the
//! two agree, but where the agent's procfs belongs to another namespace - a
//! node that is itself a container, as in a kind cluster - the same task has
//! two numbers and every pid the kernel sent would name the wrong process or
//! none.
//!
//! Userspace writes the namespace of the procfs it reads into `PIDNS_VIEW`,
//! and the programs that send a pid ask the kernel for the task's number in
//! that namespace instead. A view that was never written, or that names the
//! initial namespace, leaves the kernel's own number in place. A task the
//! namespace cannot see has no number there and is sent as pid 0, which no
//! task has, rather than with a number belonging to some other namespace.
//!
//! The kernel's helper answers only for a task whose own namespace is the
//! one asked about. A pod's task on a kind node lives in a namespace below
//! the node's, where it has a number all the same, so a refused helper is
//! followed by a walk: the `struct pid` of the task holds one number per
//! level from the initial namespace down, and the entry at the view's level
//! carries the number the procfs shows. The walk reads the level and offsets
//! userspace took from the running kernel; a view written without them sends
//! such a task as pid 0.

/// The pid namespace userspace reads `/proc` in, as `stat(2)` of its
/// `ns/pid` link describes it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PidNsView {
    /// Device of the nsfs inode, in the encoding the kernel compares
    /// (`new_encode_dev`), not the one `stat(2)` returns.
    pub dev: u64,
    /// Inode of the namespace, the number `/proc/<pid>/ns/pid` names.
    pub ino: u64,
    /// Nonzero once userspace wrote a namespace other than the initial one.
    /// Zero is what an unwritten array slot holds.
    pub valid: u32,
    /// Nonzero once `level` and the six offsets below were read, which
    /// numbering a task of a namespace below the view's needs.
    pub walk_valid: u32,
    /// Depth of the view's namespace, the initial one being 0: the entry of
    /// a task's `pid.numbers` that holds its number there.
    pub level: u32,
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
    pub _pad: u32,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for PidNsView {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_view_is_laid_out_as_the_kernel_reads_it() {
        assert_eq!(mem::size_of::<PidNsView>(), 56);
        assert_eq!(mem::offset_of!(PidNsView, level), 24);
        assert_eq!(mem::offset_of!(PidNsView, ino), 8);
        assert_eq!(mem::offset_of!(PidNsView, valid), 16);
        assert_eq!(mem::offset_of!(PidNsView, walk_valid), 20);
        assert_eq!(mem::offset_of!(PidNsView, pid_namespace_inum), 48);
        assert_eq!(PidNsView::default().valid, 0);
    }
}
