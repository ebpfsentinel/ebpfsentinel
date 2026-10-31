//! Process lifecycle: three raw tracepoints, so a pid means one thing at a
//! time and always says who started it.
//!
//! `sched_process_exec` fires once the new image is installed,
//! `sched_process_fork` once a new process exists and `sched_process_exit`
//! once a thread is gone. The executable path, the command line and the
//! container are read in userspace from `/proc` on the strength of these
//! notifications; the parent is not, because by the time userspace looks a
//! parent that exited has been replaced by whichever reaper adopted the
//! child, and the lineage would name `init` for every orphan.
//!
//! The parent is therefore read here, from `task_struct.real_parent`, along
//! with its tgid and the start time of its thread group leader: the pair that
//! survives pid reuse. The offsets of that walk are not compiled in. Userspace
//! reads them from the running kernel's BTF and writes them into
//! `PROCESS_LAYOUT` before attaching, and a layout that was never written
//! sends the record with no parent and counts it, rather than reading some
//! other field as a pid.
//!
//! Nothing here enforces anything. Every program returns zero
//! unconditionally, a raw tracepoint has no verdict to give, and the only
//! side effect is a record in a ring buffer a full userspace side may fail to
//! read.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
        bpf_probe_read_kernel,
    },
    macros::{btf_map, raw_tracepoint},
    programs::RawTracePointContext,
};
use ebpf_common::process::{
    PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT, PROCESS_EVENT_FORK, PROCESS_EVENTS_RINGBUF_BYTES,
    PROCESS_METRIC_COUNT, PROCESS_METRIC_DROPPED, PROCESS_METRIC_EXEC, PROCESS_METRIC_EXIT,
    PROCESS_METRIC_FORK, PROCESS_METRIC_THREAD_EXIT, PROCESS_METRIC_THREAD_FORK,
    PROCESS_METRIC_UNRESOLVED, ProcessEvent, ProcessLayout,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// Exec, fork and exit notifications on their way to the process table.
///
/// Its own ring rather than a share of the packet ring: a process event is
/// rare and must not be dropped behind a flood of packets, and the table that
/// reads it wants to be woken immediately - an exec record read a second late
/// is an alert naming a pid instead of a binary.
#[btf_map]
static PROCESS_EVENTS: RingBuf<ProcessEvent, { PROCESS_EVENTS_RINGBUF_BYTES as usize }> =
    RingBuf::new();

/// Per-CPU process counters. Index: 0=exec, 1=exit, 2=dropped, 3=thread_exit,
/// 4=fork, 5=thread_fork, 6=unresolved.
#[btf_map]
static PROCESS_METRICS: PerCpuArray<u64, { PROCESS_METRIC_COUNT as usize }> = PerCpuArray::new();

/// Where the running kernel keeps the fields of the parent walk, written by
/// userspace from BTF before the tracepoints are attached.
#[btf_map]
static PROCESS_LAYOUT: Array<ProcessLayout, 1> = Array::new();

// ── Programs ────────────────────────────────────────────────────────

/// A task has replaced its image: the pid now stands for a different binary.
///
/// The hook runs in the exec'ing task's own context and after the new image
/// is in place, which is what makes the userspace read of `/proc/<pid>/exe`
/// answer with the new path rather than the shell that called it.
#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn process_exec(_ctx: RawTracePointContext) -> i32 {
    let task = unsafe { bpf_get_current_task() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let mut event = current_event(PROCESS_EVENT_EXEC, pid_tgid as u32, (pid_tgid >> 32) as u32);
    if !with_lineage(&mut event, task) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_UNRESOLVED);
    }
    if submit(event) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_EXEC);
    }
    0
}

/// A task created another. `TP_PROTO(parent, child)`, run in the parent.
///
/// A thread is discarded here for the same reason its exit is: it shares the
/// tgid the table is keyed on, and the table holds processes. A child that
/// cannot be read is not sent, because a record naming no pid is not a
/// record anything can act on; it is counted instead.
#[raw_tracepoint(tracepoint = "sched_process_fork")]
pub fn process_fork(ctx: RawTracePointContext) -> i32 {
    let child = ctx.arg::<u64>(1);
    let Some(layout) = layout() else {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_UNRESOLVED);
        return 0;
    };
    let (child_tgid, read_tgid) = read::<u32>(child, layout.task_tgid);
    if !read_tgid {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_UNRESOLVED);
        return 0;
    }
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if child_tgid == parent_tgid {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_THREAD_FORK);
        return 0;
    }
    // The child is a fresh thread group leader, so its own start is the
    // process's. Uid, gid, cgroup and comm are the parent's, which is what
    // the child inherited a moment ago.
    let mut event = current_event(PROCESS_EVENT_FORK, child_tgid, child_tgid);
    if !with_lineage(&mut event, child) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_UNRESOLVED);
    }
    if submit(event) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_FORK);
    }
    0
}

/// A task is gone. Only the thread group leader is reported: a thread exiting
/// does not free the pid the table is keyed on, and forwarding it would make
/// userspace drop a live process the moment any of its threads ended.
///
/// The exit carries the process's own start so the table removes that
/// process and not a later one that inherited the pid; it carries no parent,
/// which the table already holds.
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn process_exit(_ctx: RawTracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if pid != tgid {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_THREAD_EXIT);
        return 0;
    }
    let mut event = current_event(PROCESS_EVENT_EXIT, pid, tgid);
    if let Some(layout) = layout() {
        let task = unsafe { bpf_get_current_task() };
        event.start_ns = start_of(task, &layout).0;
    }
    if submit(event) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_EXIT);
    }
    0
}

// ── Recording ───────────────────────────────────────────────────────

/// A record of `kind` about the calling task, with no lineage yet.
#[inline(always)]
fn current_event(kind: u8, pid: u32, tgid: u32) -> ProcessEvent {
    let uid_gid = bpf_get_current_uid_gid();
    ProcessEvent {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        start_ns: 0,
        parent_start_ns: 0,
        pid,
        tgid,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        parent_tgid: 0,
        kind,
        _pad: [0u8; 3],
        comm: bpf_get_current_comm().unwrap_or([0u8; 16]),
    }
}

/// Fill in the start of `task`'s process and its parent, returning whether
/// all three were read. A field that could not be read stays zero, which
/// userspace takes for unknown.
#[inline(always)]
fn with_lineage(event: &mut ProcessEvent, task: u64) -> bool {
    let Some(layout) = layout() else {
        return false;
    };
    let (start, read_start) = start_of(task, &layout);
    event.start_ns = start;
    let (parent, read_parent) = read::<u64>(task, layout.task_real_parent);
    if !read_parent || parent == 0 {
        return false;
    }
    let (parent_tgid, read_parent_tgid) = read::<u32>(parent, layout.task_tgid);
    let (parent_start, read_parent_start) = start_of(parent, &layout);
    event.parent_tgid = parent_tgid;
    event.parent_start_ns = parent_start;
    read_start && read_parent_tgid && read_parent_start
}

/// The start of the process `task` belongs to: its thread group leader's
/// `start_boottime`, because a thread's own start is not the process's.
/// Zero and `false` when either read failed.
#[inline(always)]
fn start_of(task: u64, layout: &ProcessLayout) -> (u64, bool) {
    let (leader, read_leader) = read::<u64>(task, layout.task_group_leader);
    if !read_leader || leader == 0 {
        return (0, false);
    }
    read::<u64>(leader, layout.task_start_boottime)
}

/// The layout userspace wrote, or nothing when it never did.
#[inline(always)]
fn layout() -> Option<ProcessLayout> {
    PROCESS_LAYOUT.get(0).copied().filter(|l| l.valid != 0)
}

/// Read a `T` at `offset` into the kernel object at `base`, with whether the
/// read succeeded.
///
/// A failed read answers zero rather than nothing. An `Option` carried across
/// the next helper call leaves its payload register undefined on the `None`
/// path, the compiler is free to spill that register anyway, and the verifier
/// refuses a program that stores a register it never saw written.
#[inline(always)]
fn read<T: Default>(base: u64, offset: u32) -> (T, bool) {
    if base == 0 {
        return (T::default(), false);
    }
    let at = (base + u64::from(offset)) as *const T;
    match unsafe { bpf_probe_read_kernel(at) } {
        Ok(value) => (value, true),
        Err(_) => (T::default(), false),
    }
}

/// Write one record, returning whether it went.
///
/// A ring with no room costs the table one notification, counted here so the
/// gap is visible rather than inferred from a table that drifts: a lost exec
/// or fork is a process the table never learns about, a lost exit is an entry
/// that waits for its pid to be reused.
#[inline(always)]
fn submit(event: ProcessEvent) -> bool {
    let Some(mut entry) = PROCESS_EVENTS.reserve(0) else {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_DROPPED);
        return false;
    };
    entry.write(event);
    entry.submit(0);
    true
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
