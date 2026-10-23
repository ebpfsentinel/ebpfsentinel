//! Signalling the task behind a flow, from inside that task.
//!
//! `bpf_send_signal` signals the thread group of whatever task the program is
//! running in. It takes no pid, which is the whole reason this program exists
//! as a syscall-entry tracepoint rather than as part of the cgroup hook that
//! already decides what a workload may reach: the helper is not in the cgroup
//! or TC program protos at all, and even where it were, those hooks run in the
//! context of whoever happens to be sending a packet.
//!
//! So userspace never kills. It writes a target into `SIGNAL_TARGETS` - a
//! thread group id, a signal number and an expiry - and this program fires the
//! signal the next time that thread group enters a syscall. The arming is
//! removed on the way out, so one decision is one signal however many syscalls
//! the task makes afterwards.
//!
//! Three refusals are the kernel's own and do not depend on userspace being
//! correct: an expiry in the past, a thread group id of 0 or 1, and an entry in
//! `SIGNAL_PROTECTED`. Userspace refuses a protected target before arming it,
//! and the map is the second fence behind that, because the first one is a
//! program that could be wrong.
//!
//! The cost on a node with nothing armed is one array read and a branch:
//! `SIGNAL_ARMED` is written by userspace before any target exists and brought
//! back to zero after the last one is gone, which keeps a hash lookup off the
//! syscall path of every process on the machine.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, PerCpuArray, RingBuf},
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns},
    macros::{btf_map, raw_tracepoint},
    programs::RawTracePointContext,
};
use aya_ebpf_bindings::helpers::bpf_send_signal;
use ebpf_common::signal::{
    SIGNAL_ARMED_SLOT, SIGNAL_EVENTS_RINGBUF_BYTES, SIGNAL_MAX_PROTECTED, SIGNAL_MAX_TARGETS,
    SIGNAL_METRIC_COUNT, SIGNAL_METRIC_EVENT_LOST, SIGNAL_METRIC_EXPIRED,
    SIGNAL_METRIC_HELPER_FAILED, SIGNAL_METRIC_PROTECTED, SIGNAL_METRIC_SENT,
    SIGNAL_OUTCOME_EXPIRED, SIGNAL_OUTCOME_HELPER_FAILED, SIGNAL_OUTCOME_PROTECTED,
    SIGNAL_OUTCOME_SENT, SignalEvent, SignalTarget,
};
use ebpf_helpers::increment_metric;

// ── Maps ────────────────────────────────────────────────────────────

/// How many targets userspace currently has armed.
///
/// The fast path of every syscall on the node reads this one slot. It is
/// written before a target is inserted and cleared after the last one is
/// removed, so it is never lower than the truth: a stale non-zero costs a hash
/// lookup, a stale zero would cost a kill nobody took.
#[btf_map]
static SIGNAL_ARMED: Array<u64, 1> = Array::new();

/// Thread groups a response has armed, keyed by tgid.
///
/// A plain hash rather than an LRU: an eviction here is an armed kill silently
/// becoming a survivor, and the map is small enough that filling it is a
/// budget failure upstream rather than a capacity question.
#[btf_map]
static SIGNAL_TARGETS: HashMap<u32, SignalTarget, { SIGNAL_MAX_TARGETS as usize }> = HashMap::new();

/// Thread groups that may never be signalled, whatever is armed.
///
/// Userspace fills it with the numbers it can name - pid 1, itself, the warden
/// - and refuses the protected names before arming. The value is unread: a key
/// being present is the whole statement.
#[btf_map]
static SIGNAL_PROTECTED: HashMap<u32, u8, { SIGNAL_MAX_PROTECTED as usize }> = HashMap::new();

/// What came of each arming, for the audit record userspace writes.
#[btf_map]
static SIGNAL_EVENTS: RingBuf<SignalEvent, { SIGNAL_EVENTS_RINGBUF_BYTES as usize }> =
    RingBuf::new();

/// Per-CPU signal counters. Index: 0=sent, 1=protected, 2=expired,
/// 3=helper_failed, 4=event_lost.
#[btf_map]
static SIGNAL_METRICS: PerCpuArray<u64, { SIGNAL_METRIC_COUNT as usize }> = PerCpuArray::new();

// ── Program ─────────────────────────────────────────────────────────

/// A task entered a syscall. If it is an armed target, this is where it dies.
///
/// Returns zero in every case: a raw tracepoint has no verdict, and a refused
/// signal is reported through the ring rather than through a return value
/// nobody reads.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn signal_on_syscall_entry(_ctx: RawTracePointContext) -> i32 {
    if armed_count() == 0 {
        return 0;
    }

    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let Some(target) = (unsafe { SIGNAL_TARGETS.get(&tgid) }).copied() else {
        return 0;
    };

    let now_ns = unsafe { bpf_ktime_get_boot_ns() };
    if now_ns >= target.expires_at_ns {
        drop_target(tgid);
        increment_metric!(SIGNAL_METRICS, SIGNAL_METRIC_EXPIRED);
        report(now_ns, tgid, target.signal, SIGNAL_OUTCOME_EXPIRED);
        return 0;
    }

    // pid 1 is the init process of whichever pid namespace the agent reads, and
    // 0 is no thread group at all. Neither is a target a configuration can
    // argue its way into.
    if tgid <= 1 || unsafe { SIGNAL_PROTECTED.get(&tgid) }.is_some() {
        drop_target(tgid);
        increment_metric!(SIGNAL_METRICS, SIGNAL_METRIC_PROTECTED);
        report(now_ns, tgid, target.signal, SIGNAL_OUTCOME_PROTECTED);
        return 0;
    }

    // One signal per decision: the arming goes before the outcome is recorded,
    // so a task that survives a signal it was sent is not signalled again on
    // its next syscall.
    if unsafe { bpf_send_signal(target.signal) } == 0 {
        drop_target(tgid);
        increment_metric!(SIGNAL_METRICS, SIGNAL_METRIC_SENT);
        report(now_ns, tgid, target.signal, SIGNAL_OUTCOME_SENT);
    } else {
        // The arming stays. A helper refusal is transient in the cases that
        // produce it, and the expiry above is what bounds the retrying.
        increment_metric!(SIGNAL_METRICS, SIGNAL_METRIC_HELPER_FAILED);
        report(now_ns, tgid, target.signal, SIGNAL_OUTCOME_HELPER_FAILED);
    }
    0
}

// ── Helpers ─────────────────────────────────────────────────────────

/// How many targets userspace says are armed, 0 when the slot cannot be read.
#[inline(always)]
fn armed_count() -> u64 {
    SIGNAL_ARMED
        .get(SIGNAL_ARMED_SLOT)
        .copied()
        .unwrap_or_default()
}

/// Forget an arming. A failed delete leaves the entry for the next syscall,
/// which the expiry then resolves.
#[inline(always)]
fn drop_target(tgid: u32) {
    let _ = SIGNAL_TARGETS.remove(&tgid);
}

/// Write one outcome record, counting the loss when the ring is full.
#[inline(always)]
fn report(at_ns: u64, tgid: u32, signal: u32, outcome: u32) {
    let Some(mut entry) = SIGNAL_EVENTS.reserve(0) else {
        increment_metric!(SIGNAL_METRICS, SIGNAL_METRIC_EVENT_LOST);
        return;
    };
    entry.write(SignalEvent {
        at_ns,
        tgid,
        signal,
        outcome,
        _pad: 0,
    });
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
