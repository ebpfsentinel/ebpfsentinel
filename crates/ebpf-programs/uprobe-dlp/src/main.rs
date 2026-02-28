#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, r#gen},
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use core::ffi::c_void;
use ebpf_common::dlp::{
    DlpEvent, SslReadArgs, DLP_DIRECTION_READ, DLP_DIRECTION_WRITE, DLP_MAX_EXCERPT,
    DLP_METRIC_ERRORS, DLP_METRIC_EVENTS_DROPPED, DLP_METRIC_READ_EVENTS,
    DLP_METRIC_WRITE_EVENTS,
};

// ── Maps ────────────────────────────────────────────────────────────

/// Kernel→userspace event ring buffer (4 MB) for DLP events.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0);

/// Per-task context: saves SSL_read entry arguments for the uretprobe.
#[map]
static SSL_READ_ARGS: HashMap<u64, SslReadArgs> = HashMap::with_max_entries(10240, 0);

/// Per-CPU DLP counters: write_events, read_events, errors, events_dropped.
#[map]
static DLP_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

// ── Probes ──────────────────────────────────────────────────────────

/// Intercept `SSL_write(ssl, buf, num)` at entry.
/// The plaintext buffer is filled before the call, so we capture it here.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) {
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

/// Emit a DlpEvent to the EVENTS RingBuf. Reserves a slot, fills the
/// header fields via raw pointer, zeros the payload, then copies user-space
/// data using the raw `bpf_probe_read_user` helper (avoids constructing a
/// slice from the uninitialised RingBuf memory).
#[inline(always)]
fn emit_dlp_event(user_buf: *const u8, data_len: u32, direction: u8) {
    if let Some(mut entry) = EVENTS.reserve::<DlpEvent>(0) {
        let ptr = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();

        unsafe {
            // Fill header fields.
            (*ptr).pid = pid_tgid as u32;
            (*ptr).tgid = (pid_tgid >> 32) as u32;
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];

            // Zero the entire excerpt buffer to prevent leaking uninitialised
            // memory to userspace.
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_MAX_EXCERPT);

            // Bound copy length to DLP_MAX_EXCERPT for the eBPF verifier.
            let copy_len = if data_len < DLP_MAX_EXCERPT as u32 {
                data_len
            } else {
                DLP_MAX_EXCERPT as u32
            };

            // Use the raw BPF helper to avoid constructing a &mut [u8] from
            // the RingBuf pointer (which would be UB on uninitialised memory).
            r#gen::bpf_probe_read_user(
                (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                copy_len,
                user_buf as *const c_void,
            );
        }

        entry.submit(0);
    } else {
        // RingBuf full — drop event, increment counter.
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = DLP_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
