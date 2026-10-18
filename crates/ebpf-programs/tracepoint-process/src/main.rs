//! Process lifecycle: two raw tracepoints, so a pid means one thing at a time.
//!
//! `sched_process_exec` fires once the new image is installed and
//! `sched_process_exit` once a thread is gone. Everything else about a process
//! - the executable path, the command line, the parent, the container - is
//! read in userspace from `/proc` on the strength of these two notifications,
//! because those live in `task_struct` and `linux_binprm` and reading them
//! here would pin the object to one kernel's field offsets.
//!
//! What a raw tracepoint can read without that risk is the calling task's own
//! numbers, and that is exactly what goes on the ring: pid, tgid, uid, gid,
//! cgroup id, `comm`. The exec record is the invitation to go and look; the
//! exit record is the order to forget.
//!
//! Nothing here enforces anything. Both programs return zero unconditionally,
//! a raw tracepoint has no verdict to give, and the only side effect is a
//! record in a ring buffer a full userspace side may fail to read.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{PerCpuArray, RingBuf},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_boot_ns,
    },
    macros::{btf_map, raw_tracepoint},
    programs::RawTracePointContext,
};
use ebpf_common::process::{
    PROCESS_EVENT_EXEC, PROCESS_EVENT_EXIT, PROCESS_EVENTS_RINGBUF_BYTES, PROCESS_METRIC_COUNT,
    PROCESS_METRIC_DROPPED, PROCESS_METRIC_EXEC, PROCESS_METRIC_EXIT, PROCESS_METRIC_THREAD_EXIT,
    ProcessEvent,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// Exec and exit notifications on their way to the process table.
///
/// Its own ring rather than a share of the packet ring: a process event is
/// rare and must not be dropped behind a flood of packets, and the table that
/// reads it wants to be woken immediately - an exec record read a second late
/// is an alert naming a pid instead of a binary.
#[btf_map]
static PROCESS_EVENTS: RingBuf<ProcessEvent, { PROCESS_EVENTS_RINGBUF_BYTES as usize }> =
    RingBuf::new();

/// Per-CPU process counters. Index: 0=exec, 1=exit, 2=dropped, 3=thread_exit.
#[btf_map]
static PROCESS_METRICS: PerCpuArray<u64, { PROCESS_METRIC_COUNT as usize }> = PerCpuArray::new();

// ── Programs ────────────────────────────────────────────────────────

/// A task has replaced its image: the pid now stands for a different binary.
///
/// The hook runs in the exec'ing task's own context and after the new image
/// is in place, which is what makes the userspace read of `/proc/<pid>/exe`
/// answer with the new path rather than the shell that called it.
#[raw_tracepoint(tracepoint = "sched_process_exec")]
pub fn process_exec(_ctx: RawTracePointContext) -> i32 {
    emit(PROCESS_EVENT_EXEC);
    0
}

/// A task is gone. Only the thread group leader is reported: a thread exiting
/// does not free the pid the table is keyed on, and forwarding it would make
/// userspace drop a live process the moment any of its threads ended.
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn process_exit(_ctx: RawTracePointContext) -> i32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if pid != tgid {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_THREAD_EXIT);
        return 0;
    }
    emit(PROCESS_EVENT_EXIT);
    0
}

// ── Recording ───────────────────────────────────────────────────────

/// Write one record about the calling task.
///
/// A ring with no room costs the table one notification, counted here so the
/// gap is visible rather than inferred from a table that drifts: a lost exec
/// is a process the table never learns about, a lost exit is an entry that
/// waits for its pid to be reused.
#[inline(always)]
fn emit(kind: u8) {
    let Some(mut entry) = PROCESS_EVENTS.reserve(0) else {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_DROPPED);
        return;
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let event = ProcessEvent {
        at_ns: unsafe { bpf_ktime_get_boot_ns() },
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        pid: pid_tgid as u32,
        tgid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        comm,
        kind,
        _pad: [0u8; 7],
    };
    entry.write(event);
    entry.submit(0);

    if kind == PROCESS_EVENT_EXEC {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_EXEC);
    } else {
        increment_metric!(PROCESS_METRICS, PROCESS_METRIC_EXIT);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
