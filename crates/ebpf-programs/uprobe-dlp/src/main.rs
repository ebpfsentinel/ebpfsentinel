#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, r#gen},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use core::ffi::c_void;
use ebpf_helpers::increment_metric;
use ebpf_common::dlp::{
    DlpEvent, DlpEventSmall, SslReadArgs, DLP_DIRECTION_READ, DLP_DIRECTION_WRITE,
    DLP_MAX_EXCERPT, DLP_METRIC_ERRORS, DLP_METRIC_EVENTS_DROPPED, DLP_METRIC_READ_EVENTS,
    DLP_METRIC_TOTAL_SEEN, DLP_METRIC_WRITE_EVENTS, DLP_SMALL_EXCERPT,
};

// ── Per-connection DLP context via SK_STORAGE (kernel 5.2+) ─────────
//
// BPF_MAP_TYPE_SK_STORAGE attaches arbitrary data to a socket, surviving
// across multiple uprobe invocations on the same connection.
//
// Use case: track cumulative data exfiltration across multiple SSL_write
// calls on the same socket. Currently each uprobe invocation is stateless.
//
// Architecture:
//   #[map]
//   static DLP_SK_STORAGE: SkStorage<DlpConnectionContext> = SkStorage::new(0);
//
//   struct DlpConnectionContext {
//       total_bytes_inspected: u64,
//       pattern_match_count: u32,
//       data_categories_seen: u32,  // bitmask of PCI/PII/credentials
//       first_seen_ns: u64,
//   }
//
// On each SSL_write uprobe:
//   1. bpf_sk_storage_get(&DLP_SK_STORAGE, sk, NULL, BPF_SK_STORAGE_GET_F_CREATE)
//   2. Update cumulative stats
//   3. Alert if thresholds exceeded (e.g., >100KB PII data on one connection)
//
// NOTE(future): SK_STORAGE for per-connection DLP context — requires aya kfunc support.

// ── Maps ────────────────────────────────────────────────────────────

/// Kernel→userspace event ring buffer (4 MB) for DLP events.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0);

/// Per-task context: saves SSL_read entry arguments for the uretprobe.
#[map]
static SSL_READ_ARGS: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(10240, 0);

/// Per-CPU DLP counters: write_events, read_events, errors, events_dropped, total_seen.
#[map]
static DLP_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);

// ── Probes ──────────────────────────────────────────────────────────

/// Intercept `SSL_write(ssl, buf, num)` at entry.
/// The plaintext buffer is filled before the call, so we capture it here.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_ssl_write(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept `SSL_read(ssl, buf, num)` at entry.
/// Save the buffer pointer and length; the buffer will be filled by the time
/// the uretprobe fires.
#[uprobe]
pub fn ssl_read_entry(ctx: ProbeContext) {
    increment_metric(DLP_METRIC_TOTAL_SEEN);
    match try_ssl_read_entry(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

/// Intercept `SSL_read` return. Read the now-filled buffer using the
/// pointer saved at entry.
#[uretprobe]
pub fn ssl_read_ret(ctx: RetProbeContext) {
    match try_ssl_read_ret(&ctx) {
        Ok(()) => {}
        Err(()) => increment_metric(DLP_METRIC_ERRORS),
    }
}

// ── Implementation ──────────────────────────────────────────────────

#[inline(always)]
fn try_ssl_write(ctx: &ProbeContext) -> Result<(), ()> {
    // SSL_write(SSL *ssl, const void *buf, int num)
    //   arg(0) = ssl, arg(1) = buf, arg(2) = num
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;

    if num <= 0 || buf.is_null() {
        return Ok(());
    }

    emit_dlp_event(buf, num as u32, DLP_DIRECTION_WRITE);
    increment_metric(DLP_METRIC_WRITE_EVENTS);
    Ok(())
}

#[inline(always)]
fn try_ssl_read_entry(ctx: &ProbeContext) -> Result<(), ()> {
    // SSL_read(SSL *ssl, void *buf, int num)
    //   arg(0) = ssl, arg(1) = buf, arg(2) = num
    let buf: *const u8 = ctx.arg(1).ok_or(())?;
    let num: i32 = ctx.arg(2).ok_or(())?;

    if num <= 0 || buf.is_null() {
        return Ok(());
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let args = SslReadArgs {
        buf_ptr: buf as u64,
        buf_len: num as u32,
        _padding: 0,
    };

    // Save args for the uretprobe; ignore insert errors.
    let _ = SSL_READ_ARGS.insert(&pid_tgid, &args, 0);
    Ok(())
}

#[inline(always)]
fn try_ssl_read_ret(ctx: &RetProbeContext) -> Result<(), ()> {
    let pid_tgid = bpf_get_current_pid_tgid();

    // Lookup saved entry args. If missing, nothing to do.
    let args_ptr = SSL_READ_ARGS.get_ptr(&pid_tgid).ok_or(())?;
    let args = unsafe { *args_ptr };

    // Always clean up the map entry.
    let _ = SSL_READ_ARGS.remove(&pid_tgid);

    // SSL_read returns the number of bytes read, or ≤0 on error/EOF.
    let ret: i32 = ctx.ret().ok_or(())?;
    if ret <= 0 {
        return Ok(());
    }

    // Clamp to what the buffer can actually hold.
    let actual_len = if (ret as u32) < args.buf_len {
        ret as u32
    } else {
        args.buf_len
    };

    emit_dlp_event(args.buf_ptr as *const u8, actual_len, DLP_DIRECTION_READ);
    increment_metric(DLP_METRIC_READ_EVENTS);
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Emit a `DlpEvent` to the EVENTS `RingBuf`.
///
/// # RingBuf fixed-size reservation tradeoff
///
/// We always reserve `size_of::<DlpEvent>()` bytes, which includes a
/// `DLP_MAX_EXCERPT` (4096) byte excerpt buffer, regardless of the actual
/// `data_len`. This wastes ring buffer space when `data_len` is small, but
/// is necessary because:
///
/// 1. **Verifier constraints**: `RingBuf::reserve` in aya-ebpf requires a
///    compile-time type parameter (`reserve::<T>`). The eBPF verifier
///    needs a statically-known reservation size to validate memory access
///    bounds on the returned pointer.
///
/// 2. **`bpf_probe_read_user` length**: On kernel 6.17+ the verifier
///    rejects variable-length arguments to `bpf_probe_read_user`. We must
///    pass the compile-time constant `DLP_MAX_EXCERPT` as the read length.
///
/// 3. **No variable-size ring entries**: The BPF ring buffer does support
///    `bpf_ringbuf_reserve` with a runtime size at the C API level, but
///    the Rust/aya binding only exposes the typed `reserve::<T>()` API.
///    Even with a raw helper call, the verifier would need to track the
///    dynamic allocation size through all subsequent pointer arithmetic,
///    which is fragile and version-dependent.
///
/// The `data_len` field in the event header tells userspace how many bytes
/// Emit a DLP event with tiered RingBuf reservation:
/// - `data_len ≤ 256` → `DlpEventSmall` (280 bytes, saves ~94%)
/// - `data_len > 256`  → `DlpEvent` (4120 bytes, full capture)
#[inline(always)]
fn emit_dlp_event(user_buf: *const u8, data_len: u32, direction: u8) {
    if data_len <= DLP_SMALL_EXCERPT as u32 {
        emit_dlp_small(user_buf, data_len, direction);
    } else {
        emit_dlp_full(user_buf, data_len, direction);
    }
}

/// Small DLP event (280 bytes): for SSL payloads ≤ 256 bytes.
///
/// `#[inline(never)]` gives this function its own stack frame, reducing
/// per-function verifier complexity and keeping it separate from the
/// full-size path.
#[inline(never)]
fn emit_dlp_small(user_buf: *const u8, data_len: u32, direction: u8) {
    if let Some(mut entry) = EVENTS.reserve::<DlpEventSmall>(0) {
        let ptr = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*ptr).pid = pid_tgid as u32;
            (*ptr).tgid = (pid_tgid >> 32) as u32;
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_SMALL_EXCERPT);
            // Use compile-time constant size: kernel 6.17+ verifier rejects
            // variable-length arguments to bpf_probe_read_user. The buffer is
            // zero-initialized above, so excess bytes beyond data_len stay zero.
            // data_len in the header tells userspace the meaningful byte count.
            let _ = r#gen::bpf_probe_read_user(
                (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                DLP_SMALL_EXCERPT as u32,
                user_buf as *const c_void,
            );
        }
        entry.submit(0);
    } else {
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Full DLP event (4120 bytes): for SSL payloads > 256 bytes.
///
/// `#[inline(never)]` gives this function its own stack frame, reducing
/// per-function verifier complexity and keeping it separate from the
/// small-size path.
#[inline(never)]
fn emit_dlp_full(user_buf: *const u8, data_len: u32, direction: u8) {
    if let Some(mut entry) = EVENTS.reserve::<DlpEvent>(0) {
        let ptr = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*ptr).pid = pid_tgid as u32;
            (*ptr).tgid = (pid_tgid >> 32) as u32;
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_MAX_EXCERPT);
            // Use compile-time constant size: kernel 6.17+ verifier rejects
            // variable-length arguments to bpf_probe_read_user. The buffer is
            // zero-initialized above, so excess bytes beyond data_len stay zero.
            // data_len in the header tells userspace the meaningful byte count.
            let _ = r#gen::bpf_probe_read_user(
                (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                DLP_MAX_EXCERPT as u32,
                user_buf as *const c_void,
            );
        }
        entry.submit(0);
    } else {
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(DLP_METRICS, index);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
