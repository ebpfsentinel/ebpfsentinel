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
        bpf_probe_read_kernel, generated::bpf_get_current_task_btf,
    },
    macros::{btf_map, lsm, raw_tracepoint},
    programs::{LsmContext, RawTracePointContext},
};
use ebpf_common::process::{
    PROCESS_ARGV_BOUND, PROCESS_ARGV_CHUNK, PROCESS_ARGV_MAX_READS, PROCESS_EVENT_ARGV,
    PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT, PROCESS_EVENT_FORK, PROCESS_EVENTS_RINGBUF_BYTES,
    PROCESS_METRIC_ARGV, PROCESS_METRIC_ARGV_LOST, PROCESS_METRIC_COUNT, PROCESS_METRIC_DROPPED,
    PROCESS_METRIC_EXEC, PROCESS_METRIC_EXIT, PROCESS_METRIC_FORK,
    PROCESS_METRIC_OUTSIDE_NAMESPACE, PROCESS_METRIC_THREAD_EXIT, PROCESS_METRIC_THREAD_FORK,
    PROCESS_METRIC_UNRESOLVED, PROCESS_PID_NS_LEVELS, PROCESS_UPID_SIZE, ProcessArgv,
    ProcessArgvLayout, ProcessEvent, ProcessLayout,
};
use ebpf_helpers::kfuncs::{bpf_copy_from_user_task_str, task_struct};
use ebpf_helpers::ringbuf::avail_data;
use ebpf_helpers::{increment_metric, opaque_usize};

ebpf_helpers::pidns_view!();

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
/// 4=fork, 5=thread_fork, 6=unresolved, 7=outside_namespace, 8=argv,
/// 9=argv_lost.
#[btf_map]
static PROCESS_METRICS: PerCpuArray<u64, { PROCESS_METRIC_COUNT as usize }> = PerCpuArray::new();

/// Where the running kernel keeps the fields of the parent walk, written by
/// userspace from BTF before the tracepoints are attached.
#[btf_map]
static PROCESS_LAYOUT: Array<ProcessLayout, 1> = Array::new();

/// Where the running kernel keeps the fields of `linux_binprm` the argument
/// read needs, written by userspace from BTF before the hook is attached.
#[btf_map]
static PROCESS_ARGV_LAYOUT: Array<ProcessArgvLayout, 1> = Array::new();

/// Unread bytes above which an argument record is not sent: half the ring.
/// The exec, fork and exit records keep the other half, so a burst of
/// starts costs the table command lines, which `/proc` can still answer,
/// before it costs it processes, which nothing else reports.
const ARGV_RING_SHARE: u64 = PROCESS_EVENTS_RINGBUF_BYTES as u64 / 2;

// ── Programs ────────────────────────────────────────────────────────

/// A task has replaced its image: the pid now stands for a different binary.
///
/// The hook runs in the exec'ing task's own context and after the new image
/// is in place, which is what makes the userspace read of `/proc/<pid>/exe`
/// answer with the new path rather than the shell that called it.
#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn process_exec(_ctx: RawTracePointContext) -> i32 {
    let pid_tgid = current_pid_tgid();
    if pid_tgid == 0 {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_OUTSIDE_NAMESPACE);
        return 0;
    }
    let task = unsafe { bpf_get_current_task() };
    let mut event = current_event(PROCESS_EVENT_EXEC, pid_tgid as u32, (pid_tgid >> 32) as u32);
    if !with_lineage(&mut event, task) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_UNRESOLVED);
    }
    if submit(event) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_EXEC);
    }
    0
}

/// The arguments of a task that is replacing its image, read from the new
/// image itself.
///
/// `bprm_committed_creds` runs in the exec'ing task once its new memory is
/// in place and before the exec tracepoint fires, so this record reaches the
/// ring ahead of the exec record it belongs to. The strings sit where
/// `linux_binprm.p` points, the argument vector first and contiguous, each
/// argument ending in a NUL: the same bytes `/proc/<pid>/cmdline` shows once
/// the image runs, read before the image can exit or rewrite them.
///
/// `bpf_copy_from_user_task_str` may fault a page in, which is why the
/// program is sleepable and why it is an LSM hook rather than the raw
/// tracepoint the exec record comes from. It decides nothing: the hook
/// returns nothing the kernel reads.
#[lsm(hook = "bprm_committed_creds", sleepable)]
pub fn process_exec_argv(ctx: LsmContext) -> i32 {
    let pid_tgid = current_pid_tgid();
    if pid_tgid == 0 {
        return 0;
    }
    if argv(&ctx, pid_tgid) {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_ARGV);
    } else {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_ARGV_LOST);
    }
    0
}

/// Read and send the arguments of the calling task, returning whether a
/// record went.
#[inline(always)]
fn argv(ctx: &LsmContext, pid_tgid: u64) -> bool {
    let Some(argv_layout) = PROCESS_ARGV_LAYOUT.get(0).copied().filter(|l| l.valid != 0) else {
        return false;
    };
    let bprm = ctx.arg::<u64>(0);
    let (mut at_user, read_p) = read::<u64>(bprm, argv_layout.binprm_p);
    let (argc, read_argc) = read::<i32>(bprm, argv_layout.binprm_argc);
    if !read_p || !read_argc || at_user == 0 {
        return false;
    }
    let argc = if argc > 0 { argc as u32 } else { 0 };
    if avail_data(&PROCESS_EVENTS) > ARGV_RING_SHARE {
        return false;
    }
    let Some(mut entry) = PROCESS_EVENTS.reserve_untyped::<ProcessArgv>(0) else {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_DROPPED);
        return false;
    };
    let record = entry.as_mut_ptr();
    let mut header = current_event(PROCESS_EVENT_ARGV, pid_tgid as u32, (pid_tgid >> 32) as u32);
    if let Some(layout) = layout() {
        // SAFETY: a helper with no argument; the pointer it returns is only
        // handed back to `bpf_probe_read_kernel` through `read`.
        let task = unsafe { bpf_get_current_task() };
        header.start_ns = start_of(task, &layout).0;
    }
    // SAFETY: a helper with no argument returning the calling task as the
    // trusted pointer the kfunc below requires.
    let task = unsafe { bpf_get_current_task_btf() }.cast::<task_struct>();

    let mut off = 0usize;
    let mut args_read = 0u32;
    let mut reads = 0u32;
    while reads < PROCESS_ARGV_MAX_READS && args_read < argc {
        // Through a barrier so the compiler keeps the bound check below on
        // the very register the destination is computed from.
        let at = opaque_usize(off);
        if at >= PROCESS_ARGV_BOUND as usize {
            break;
        }
        // SAFETY: `record` is the reservation of a whole `ProcessArgv`,
        // whose `bytes` hold the bound plus one chunk, and `at` is below
        // the bound, so the chunk the kfunc may write stays inside them.
        let n = unsafe {
            let dst = (*record).bytes.as_mut_ptr().add(at);
            bpf_copy_from_user_task_str(
                dst.cast(),
                PROCESS_ARGV_CHUNK,
                at_user as *const core::ffi::c_void,
                task,
                0,
            )
        };
        if n <= 0 || n as u32 > PROCESS_ARGV_CHUNK {
            break;
        }
        // Without a branch: two paths per read, 64 reads deep, are more
        // states than the verifier walks. `n` is in 1..=512 here, so `full`
        // is 1 exactly when the chunk filled and the argument goes on where
        // the read stopped, over the NUL the kfunc put at the end of the
        // chunk; otherwise a whole argument and its NUL were read.
        const _: () = assert!(PROCESS_ARGV_CHUNK == 1 << 9);
        let full = (n as u32 >> 9) as usize;
        let step = n as usize - full;
        args_read += 1 - full as u32;
        off = at + step;
        at_user += step as u64;
        reads += 1;
    }
    if off == 0 {
        entry.discard(0);
        return false;
    }
    // SAFETY: `record` is the live reservation; every field written here is
    // inside it.
    unsafe {
        (*record).header = header;
        (*record).argc = argc;
        (*record).args_read = args_read;
        (*record).len = off as u32;
        (*record)._pad = 0;
    }
    entry.submit(0);
    true
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
    // Both numbers above are the kernel's own, which is all the thread test
    // needs. The record carries the child's number where userspace reads it.
    let child_tgid = match viewed() {
        None => child_tgid,
        Some(ino) => match ns_tgid(child, &layout, ino) {
            (tgid, NS_FOUND) => tgid,
            (_, NS_OUTSIDE) => {
                increment_metric!(PROCESS_METRICS, PROCESS_METRIC_OUTSIDE_NAMESPACE);
                return 0;
            }
            _ => {
                increment_metric!(PROCESS_METRICS, PROCESS_METRIC_UNRESOLVED);
                return 0;
            }
        },
    };
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
    let pid_tgid = current_pid_tgid();
    if pid_tgid == 0 {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_OUTSIDE_NAMESPACE);
        return 0;
    }
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
    let (parent_tgid, read_parent_tgid) = match viewed() {
        None => read::<u32>(parent, layout.task_tgid),
        // A parent the agent's namespace cannot see, the runtime that started
        // a container's first task, is a parent the table has no number for:
        // the record says none rather than one from another namespace.
        Some(ino) => match ns_tgid(parent, &layout, ino) {
            (tgid, NS_FOUND) => (tgid, true),
            (_, NS_OUTSIDE) => (0, true),
            _ => (0, false),
        },
    };
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

/// `ns_tgid` found the task's number in the namespace.
const NS_FOUND: u8 = 0;
/// The task has no number there: the namespace cannot see it.
const NS_OUTSIDE: u8 = 1;
/// A read failed or the offsets were never written, so nothing is known.
const NS_UNREAD: u8 = 2;

/// The inode of the pid namespace userspace reads `/proc` in, when it wrote
/// one other than the initial namespace.
#[inline(always)]
fn viewed() -> Option<u64> {
    PIDNS_VIEW.get(0).filter(|v| v.valid != 0).map(|v| v.ino)
}

/// The tgid of `task` in the pid namespace whose inode is `ino`, and whether
/// it was found there, the namespace cannot see the task, or a read failed.
///
/// `bpf_get_ns_current_pid_tgid` answers this for the calling task alone. A
/// fork's child and a record's parent are other tasks, so their number is
/// read where the kernel keeps it: the `struct pid` of the thread group
/// leader holds one `upid` per namespace level from the initial one down,
/// and the entry whose namespace is the agent's carries the number `/proc`
/// shows there.
#[inline(always)]
fn ns_tgid(task: u64, layout: &ProcessLayout, ino: u64) -> (u32, u8) {
    if layout.ns_valid == 0 {
        return (0, NS_UNREAD);
    }
    let (leader, read_leader) = read::<u64>(task, layout.task_group_leader);
    if !read_leader || leader == 0 {
        return (0, NS_UNREAD);
    }
    let (pid, read_pid) = read::<u64>(leader, layout.task_thread_pid);
    if !read_pid || pid == 0 {
        return (0, NS_UNREAD);
    }
    let (level, read_level) = read::<u32>(pid, layout.pid_level);
    if !read_level {
        return (0, NS_UNREAD);
    }
    let mut at = 0u32;
    while at < PROCESS_PID_NS_LEVELS && at <= level {
        let upid =
            pid + u64::from(layout.pid_numbers) + u64::from(at) * u64::from(PROCESS_UPID_SIZE);
        let (ns, read_ns) = read::<u64>(upid, layout.upid_ns);
        if !read_ns || ns == 0 {
            return (0, NS_UNREAD);
        }
        let (inum, read_inum) = read::<u32>(ns, layout.pid_namespace_inum);
        if !read_inum {
            return (0, NS_UNREAD);
        }
        if u64::from(inum) == ino {
            let (nr, read_nr) = read::<u32>(upid, 0);
            return if read_nr && nr != 0 {
                (nr, NS_FOUND)
            } else {
                (0, NS_UNREAD)
            };
        }
        at += 1;
    }
    (0, NS_OUTSIDE)
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
