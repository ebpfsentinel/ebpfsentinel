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
/// #[btf_map]
/// static EVENTS: RingBuf<Event, { 256 * 4096 }> = RingBuf::new();
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
        $crate::ringbuf::avail_data(&$ringbuf) > $crate::ringbuf::DEFAULT_BACKPRESSURE_THRESHOLD
    };
    ($ringbuf:expr, $threshold:expr) => {
        $crate::ringbuf::avail_data(&$ringbuf) > $threshold
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
