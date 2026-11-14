//! Pids as the agent's procfs numbers them.
//!
//! A program that sends a pid declares the shared view with
//! [`pidns_view!`](crate::pidns_view) and reads the calling task through the
//! `current_pid_tgid` it defines, which answers in the namespace userspace
//! wrote and falls back to the kernel's own number when it wrote none. See
//! `ebpf_common::pidns` for why the two can differ.

use aya_ebpf::{
    bindings::bpf_pidns_info,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task,
        generated::{bpf_get_ns_current_pid_tgid, bpf_probe_read_kernel},
    },
};
use ebpf_common::pidns::PidNsView;
use ebpf_common::process::{PROCESS_PID_NS_LEVELS, PROCESS_UPID_SIZE};

/// `pid_tgid` of the calling task (tgid in the upper half) as `view`
/// numbers it, the kernel's own number without a view, and 0 for a task the
/// view's namespace cannot see. The kernel's helper answers for a task of
/// the view's namespace itself; one of a namespace below it, a pod's on a
/// container node, is read off its `struct pid`.
#[inline(always)]
#[must_use]
pub fn current_pid_tgid(view: Option<&PidNsView>) -> u64 {
    let Some(view) = view.filter(|v| v.valid != 0) else {
        return bpf_get_current_pid_tgid();
    };
    let mut info = bpf_pidns_info { pid: 0, tgid: 0 };
    let rc = unsafe {
        bpf_get_ns_current_pid_tgid(
            view.dev,
            view.ino,
            &raw mut info,
            core::mem::size_of::<bpf_pidns_info>() as u32,
        )
    };
    if rc == 0 {
        return (u64::from(info.tgid) << 32) | u64::from(info.pid);
    }
    if view.walk_valid == 0 {
        return 0;
    }
    walk_current(view)
}

/// The calling task's numbers in the view's namespace read off its `struct
/// pid`, for a task whose own namespace sits below the view's, and 0 for one
/// the namespace cannot see or a failed read.
#[inline(always)]
fn walk_current(view: &PidNsView) -> u64 {
    let task = unsafe { bpf_get_current_task() };
    let Some(leader) = read::<u64>(task, view.task_group_leader).filter(|l| *l != 0) else {
        return 0;
    };
    let Some(tgid) = number_of(leader, view) else {
        return 0;
    };
    // A thread is in its leader's namespace, so its own number sits at the
    // same level.
    match number_of(task, view) {
        Some(pid) => (u64::from(tgid) << 32) | u64::from(pid),
        None => 0,
    }
}

/// The number `task` carries in the view's namespace, `None` where the
/// namespace cannot see it or a read failed. The view's namespace is at a
/// fixed depth, so its entry in `pid.numbers` is known without a search, and
/// its inode confirms the task's chain passes through it.
#[inline(always)]
fn number_of(task: u64, view: &PidNsView) -> Option<u32> {
    if view.level >= PROCESS_PID_NS_LEVELS {
        return None;
    }
    let pid = read::<u64>(task, view.task_thread_pid).filter(|p| *p != 0)?;
    let level = read::<u32>(pid, view.pid_level)?;
    if level < view.level {
        return None;
    }
    let upid =
        pid + u64::from(view.pid_numbers) + u64::from(view.level) * u64::from(PROCESS_UPID_SIZE);
    let ns = read::<u64>(upid, view.upid_ns).filter(|n| *n != 0)?;
    let inum = read::<u32>(ns, view.pid_namespace_inum)?;
    if u64::from(inum) != view.ino {
        return None;
    }
    read::<u32>(upid, 0).filter(|n| *n != 0)
}

#[inline(always)]
fn read<T: Default>(base: u64, offset: u32) -> Option<T> {
    let mut out = T::default();
    let rc = unsafe {
        bpf_probe_read_kernel(
            (&raw mut out).cast(),
            core::mem::size_of::<T>() as u32,
            (base + u64::from(offset)) as *const core::ffi::c_void,
        )
    };
    if rc < 0 { None } else { Some(out) }
}

/// Declare `PIDNS_VIEW`, the array userspace writes the namespace into, and
/// a `current_pid_tgid()` reading the calling task through it.
///
/// The map is shared by name across every object loaded with the agent's pin
/// path, so one write at start-up serves them all.
#[macro_export]
macro_rules! pidns_view {
    () => {
        /// The pid namespace the agent reads `/proc` in, written by
        /// userspace at start-up.
        #[aya_ebpf::macros::btf_map]
        static PIDNS_VIEW: aya_ebpf::btf_maps::Array<ebpf_common::pidns::PidNsView, 1> =
            aya_ebpf::btf_maps::Array::new();

        /// `pid_tgid` of the calling task in the agent's pid namespace.
        #[inline(always)]
        fn current_pid_tgid() -> u64 {
            $crate::pidns::current_pid_tgid(PIDNS_VIEW.get(0))
        }
    };
}
