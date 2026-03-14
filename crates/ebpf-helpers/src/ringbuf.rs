//! Ring buffer backpressure constants and helper macro.
//!
//! Each eBPF program defines its own `RingBuf` map. The macro checks
//! whether the ring buffer is more than 75% full, allowing callers to
//! skip event emission under backpressure.

/// `BPF_RB_AVAIL_DATA` flag for `bpf_ringbuf_query`.
pub const BPF_RB_AVAIL_DATA: u64 = 0;

/// Default ring buffer size used by most programs (1 MB).
pub const DEFAULT_RINGBUF_SIZE: u64 = 256 * 4096;

/// Default backpressure threshold (75% of 1 MB ring buffer).
pub const DEFAULT_BACKPRESSURE_THRESHOLD: u64 = DEFAULT_RINGBUF_SIZE * 3 / 4;

/// Returns `true` if the given `RingBuf` has backpressure (>75% full).
///
/// # Usage
///
/// ```ignore
/// use ebpf_helpers::ringbuf_has_backpressure;
///
/// #[map]
/// static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);
///
/// if ringbuf_has_backpressure!(EVENTS) {
///     return; // skip emission
/// }
/// ```
///
/// You can also pass a custom threshold:
///
/// ```ignore
/// if ringbuf_has_backpressure!(EVENTS, MY_THRESHOLD) {
///     return;
/// }
/// ```
#[macro_export]
macro_rules! ringbuf_has_backpressure {
    ($ringbuf:expr) => {
        $ringbuf.query($crate::ringbuf::BPF_RB_AVAIL_DATA)
            > $crate::ringbuf::DEFAULT_BACKPRESSURE_THRESHOLD
    };
    ($ringbuf:expr, $threshold:expr) => {
        $ringbuf.query($crate::ringbuf::BPF_RB_AVAIL_DATA) > $threshold
    };
}
