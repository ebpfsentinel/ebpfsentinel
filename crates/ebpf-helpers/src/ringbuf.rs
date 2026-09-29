//! Ring buffer backpressure and wakeup helpers.
//!
//! Each eBPF program defines its own `RingBuf` map. The macro checks
//! whether the ring buffer is more than 75% full, allowing callers to
//! skip event emission under backpressure, and [`submit_flags`] decides
//! whether a commit wakes the reader.
//!
//! The 75% line is read off the ring's own type by
//! [`backpressure_threshold`], so a ring is resized in its declaration and
//! nowhere else: a threshold written out beside it is a second figure that
//! goes stale the day the first one changes.
//!
//! # Sizing
//!
//! A ring is sized in records, not in bytes: what it has to hold is what
//! arrives while the reader is not running, beyond the [`WAKEUP_THRESHOLD`]
//! at which it is woken. Every record carries an 8-byte ring header.
//!
//! | Ring | Size | Largest record | Records before refusal |
//! |------|------|----------------|------------------------|
//! | packet events (firewall, ratelimit, loadbalancer, qos, threatintel) | 1 MiB | 104 B | about 7,500 |
//! | tc-ids, L7 payload of 2 KiB | 4 MiB | 2,152 B | about 1,460 |
//! | uprobe-dlp, 4 KiB excerpt | 4 MiB | 4,136 B | about 1,010, reserve fails only when full |
//! | tc-dns | 256 KiB | 584 B | about 335 |
//!
//! The two 4 MiB rings are large because their records are: at 1 MiB,
//! tc-ids would hold about 365 L7 records, a few milliseconds of a noisy
//! segment. Ring memory is allocated once per ring rather than once per CPU,
//! 13.25 MiB across all eight, so it scales with neither the host's cores
//! nor the configuration and is not where the agent's memory goes.

use aya_ebpf::btf_maps::RingBuf;

/// `BPF_RB_AVAIL_DATA` flag for `bpf_ringbuf_query`.
pub const BPF_RB_AVAIL_DATA: u64 = 0;

/// `bpf_ringbuf_submit` flag: commit without waking the reader.
pub const BPF_RB_NO_WAKEUP: u64 = 1;

/// `bpf_ringbuf_submit` flag: commit and wake the reader unconditionally.
pub const BPF_RB_FORCE_WAKEUP: u64 = 2;

/// Unconsumed bytes at which a commit wakes the reader (64 KiB).
///
/// About 630 packet events or 15 full DLP events, each record carrying an
/// 8-byte ring header. Below it a commit leaves the reader asleep and the
/// reader's own drain tick collects the record, so the latency a quiet ring
/// adds is bounded by that tick rather than by this figure.
pub const WAKEUP_THRESHOLD: u64 = 64 * 1024;

/// Unconsumed bytes above which `ringbuf` refuses new records: 75% of its
/// size.
///
/// Evaluated at compile time from the ring's declared size, so it costs
/// nothing on the packet path and cannot disagree with the declaration.
/// The quarter left free is what keeps a burst from filling the ring to the
/// last byte, where a large record fails to reserve while a small one still
/// fits and the loss stops being attributable to backpressure.
#[inline(always)]
#[must_use]
pub const fn backpressure_threshold<T, const MAX_ENTRIES: usize, const FLAGS: usize>(
    _ringbuf: &RingBuf<T, MAX_ENTRIES, FLAGS>,
) -> u64 {
    (MAX_ENTRIES as u64) * 3 / 4
}

/// Returns `true` if the given `RingBuf` has backpressure (>75% full).
///
/// # Usage
///
/// ```ignore
/// use ebpf_helpers::ringbuf_has_backpressure;
///
/// #[btf_map]
/// static EVENTS: RingBuf<Event, { 256 * 4096 }> = RingBuf::new();
///
/// if ringbuf_has_backpressure!(EVENTS) {
///     return; // skip emission
/// }
/// ```
#[macro_export]
macro_rules! ringbuf_has_backpressure {
    ($ringbuf:expr) => {
        $crate::ringbuf::avail_data(&$ringbuf) > $crate::ringbuf::backpressure_threshold(&$ringbuf)
    };
}

/// Returns the number of bytes still unconsumed in `ringbuf`.
///
/// The BTF-defined `RingBuf` exposes no `query`, and its internal map
/// pointer accessor is crate-private, so call `bpf_ringbuf_query` on the
/// map definition directly. Taking the address of the `.maps` static is
/// exactly what the map wrapper does internally: the compiler emits an
/// `ld_imm64` against the map symbol and the loader rewrites it to the map
/// fd, which is the `ARG_CONST_MAP_PTR` the verifier expects.
#[inline(always)]
pub fn avail_data<T>(ringbuf: &T) -> u64 {
    let ptr = core::ptr::from_ref(ringbuf).cast_mut().cast();
    // SAFETY: `ptr` is the address of a `.maps` ring-buffer definition, which
    // the loader patches into a map fd before the program runs.
    unsafe { aya_ebpf::helpers::bpf_ringbuf_query(ptr, BPF_RB_AVAIL_DATA) }
}

/// Submit flags for a record committed while `backlog` bytes were unconsumed.
///
/// The kernel's default wakes the reader whenever it has caught up, which
/// under a steady event rate is once per record: the reader drains one
/// record, sleeps, and the next commit wakes it again, each wakeup being an
/// `irq_work` on the packet's CPU and a thread switch in userspace. Waking
/// only once a batch has built up turns that into one wakeup per batch; the
/// reader's periodic drain picks up whatever never reaches the threshold.
///
/// `backlog` is [`avail_data`] read either before the record was reserved
/// (a call site that already queried it for backpressure passes that figure
/// rather than asking the kernel twice) or after, where it also counts the
/// record being committed; the one record either way changes nothing.
#[inline(always)]
#[must_use]
pub fn submit_flags(backlog: u64) -> u64 {
    if backlog >= WAKEUP_THRESHOLD {
        BPF_RB_FORCE_WAKEUP
    } else {
        BPF_RB_NO_WAKEUP
    }
}
