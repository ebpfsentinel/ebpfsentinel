#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, r#gen},
    macros::{map, uprobe, uretprobe},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use core::ffi::c_void;
use ebpf_common::arena::{
    ArenaEventHeader, DLP_ARENA_FIXED_VA, DLP_ARENA_PAGES, DLP_SLOT_COUNT, DLP_WRITE_SEQ_OFFSET,
    dlp_slot_offset,
};
use ebpf_common::dlp::{
    DLP_DIRECTION_READ, DLP_DIRECTION_WRITE, DLP_MAX_EXCERPT, DLP_METRIC_ERRORS,
    DLP_METRIC_EVENTS_DROPPED, DLP_METRIC_READ_EVENTS, DLP_METRIC_TOTAL_SEEN,
    DLP_METRIC_WRITE_EVENTS, DLP_SMALL_EXCERPT, DlpEvent, DlpEventSmall, SslReadArgs,
};
use ebpf_helpers::arena_map::{RawMapDef, arena_def};
use ebpf_helpers::increment_metric;

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
/// Used as fallback when the arena map is not available.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0);

/// Arena map for zero-copy DLP event delivery to userspace.
/// 4 pages = 16 KiB — laid out as a 64-byte ring header followed by
/// 50 fixed slots × 320 B (24 B `ArenaEventHeader` + 288 B
/// `DlpEventSmall`). BPF allocates the 4 pages once, anchored at
/// `DLP_ARENA_FIXED_VA`, so userspace's `mmap(MAP_FIXED_NOREPLACE)`
/// at the same address shares the same pointer space and reads slot
/// contents zero-copy.
#[unsafe(link_section = ".maps")]
#[unsafe(no_mangle)]
static DLP_ARENA: RawMapDef = arena_def(DLP_ARENA_PAGES);

/// Cached arena base pointer, set on first successful allocation.
/// Stored as `u64` because BPF lacks `AtomicPtr` and the sentinel
/// value 0 marks "not allocated yet".
static mut ARENA_BASE: u64 = 0;

/// Monotonically increasing sequence counter for arena events.
/// uprobes are per-task and the verifier serialises map writes, so
/// a non-atomic `u64` is sufficient — duplicate sequences would only
/// cause one slot overwrite, which is benign because userspace double
/// checks `slot.sequence` before consuming.
static mut ARENA_SEQUENCE: u64 = 0;

/// Per-task context: saves SSL_read entry arguments for the uretprobe.
/// Uses LRU eviction so entries from crashed processes (SIGKILL during
/// SSL_read) are automatically reclaimed when the map is full.
#[map]
static SSL_READ_ARGS: LruHashMap<u64, SslReadArgs> = LruHashMap::with_max_entries(10240, 0);

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
/// 2. **`bpf_probe_read_user` length**: the read length is clamped to
///    `data_len`, capped at the excerpt size, so only the bytes the SSL
///    payload actually holds are copied — never adjacent process memory
///    past the buffer. The verifier accepts this runtime length because
///    the clamp proves `copy_len <= ` the destination excerpt size.
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
            // Uprobes always run in process context, so cgroup_id is
            // reliably populated on cgroup v2 systems.
            (*ptr).cgroup_id = bpf_get_current_cgroup_id();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_SMALL_EXCERPT);
            // Read only the bytes the payload actually holds — never the
            // full excerpt — so we don't capture adjacent process memory
            // past the SSL buffer. The clamp keeps copy_len <= the
            // destination size, which the verifier needs to accept a
            // runtime length (same bound as the arena path).
            let copy_len = if data_len > DLP_SMALL_EXCERPT as u32 {
                DLP_SMALL_EXCERPT as u32
            } else {
                data_len
            };
            if copy_len > 0 {
                let _ = r#gen::bpf_probe_read_user(
                    (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                    copy_len,
                    user_buf as *const c_void,
                );
            }
        }
        entry.submit(0);
    } else {
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Full DLP event (4120 bytes): for SSL payloads > 256 bytes.
///
/// Tries arena zero-copy path first (direct write to mmap'd page),
/// falls back to RingBuf if arena_alloc_pages fails or the arena
/// was not loaded.
#[inline(never)]
fn emit_dlp_full(user_buf: *const u8, data_len: u32, direction: u8) {
    // Try arena path: write header + DlpEvent directly into mmap'd
    // arena page. Userspace reads via pointer deref — zero-copy.
    if try_emit_arena(user_buf, data_len, direction) {
        return;
    }

    // Fallback: RingBuf path (copy-based).
    if let Some(mut entry) = EVENTS.reserve::<DlpEvent>(0) {
        let ptr = entry.as_mut_ptr();
        let pid_tgid = bpf_get_current_pid_tgid();
        unsafe {
            (*ptr).pid = pid_tgid as u32;
            (*ptr).tgid = (pid_tgid >> 32) as u32;
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).cgroup_id = bpf_get_current_cgroup_id();
            (*ptr).data_len = data_len;
            (*ptr).direction = direction;
            (*ptr)._padding = [0; 3];
            core::ptr::write_bytes((*ptr).data_excerpt.as_mut_ptr(), 0, DLP_MAX_EXCERPT);
            // Clamp the read to the payload length (capped at the excerpt
            // size) so we never copy adjacent process memory past the SSL
            // buffer. The clamp keeps copy_len <= the destination size,
            // which the verifier needs to accept a runtime length.
            let copy_len = if data_len > DLP_MAX_EXCERPT as u32 {
                DLP_MAX_EXCERPT as u32
            } else {
                data_len
            };
            if copy_len > 0 {
                let _ = r#gen::bpf_probe_read_user(
                    (*ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                    copy_len,
                    user_buf as *const c_void,
                );
            }
        }
        entry.submit(0);
    } else {
        increment_metric(DLP_METRIC_EVENTS_DROPPED);
    }
}

/// Attempt to write a DLP event into the arena ring. Returns `true`
/// on success, `false` if the arena allocation failed (falls back to
/// RingBuf).
///
/// Layout: pages are allocated once at `DLP_ARENA_FIXED_VA` so the
/// userspace mmap shares the same address space. Each event writes
/// the slot body first, then publishes the new sequence to the ring
/// header so userspace observes a complete record.
#[inline(always)]
fn try_emit_arena(user_buf: *const u8, data_len: u32, direction: u8) -> bool {
    use ebpf_helpers::kfuncs::arena_alloc_pages_at;

    let arena_ptr = &raw const DLP_ARENA as *mut c_void;

    // Lazy init: anchor the arena at DLP_ARENA_FIXED_VA on first call.
    let base = unsafe {
        let cached = core::ptr::read_volatile(&raw const ARENA_BASE);
        if cached != 0 {
            cached as *mut u8
        } else {
            let allocated = arena_alloc_pages_at(
                arena_ptr,
                DLP_ARENA_FIXED_VA as *mut c_void,
                DLP_ARENA_PAGES,
            );
            match allocated {
                Some(ptr) => {
                    core::ptr::write_volatile(&raw mut ARENA_BASE, ptr as u64);
                    ptr as *mut u8
                }
                None => {
                    // Lost a race or the kernel rejected the hint. Recheck
                    // the cache once before falling back to RingBuf.
                    let now = core::ptr::read_volatile(&raw const ARENA_BASE);
                    if now != 0 {
                        now as *mut u8
                    } else {
                        return false;
                    }
                }
            }
        }
    };

    let seq = unsafe {
        ARENA_SEQUENCE += 1;
        ARENA_SEQUENCE
    };
    let slot_idx = ((seq - 1) as usize) % DLP_SLOT_COUNT;
    let slot_offset = dlp_slot_offset(slot_idx);
    let slot_ptr = unsafe { base.add(slot_offset) };

    // Slot body: copy the SSL plaintext excerpt (truncated to
    // DLP_SMALL_EXCERPT for the arena fast-path; full excerpt still
    // available via the RingBuf fallback when the caller needs it).
    let event_ptr =
        unsafe { slot_ptr.add(core::mem::size_of::<ArenaEventHeader>()) } as *mut DlpEventSmall;
    let pid_tgid = bpf_get_current_pid_tgid();
    let copy_len = if data_len > DLP_SMALL_EXCERPT as u32 {
        DLP_SMALL_EXCERPT as u32
    } else {
        data_len
    };
    unsafe {
        (*event_ptr).pid = pid_tgid as u32;
        (*event_ptr).tgid = (pid_tgid >> 32) as u32;
        (*event_ptr).timestamp_ns = bpf_ktime_get_boot_ns();
        (*event_ptr).cgroup_id = bpf_get_current_cgroup_id();
        (*event_ptr).data_len = data_len;
        (*event_ptr).direction = direction;
        (*event_ptr)._padding = [0; 3];
        core::ptr::write_bytes((*event_ptr).data_excerpt.as_mut_ptr(), 0, DLP_SMALL_EXCERPT);
        if copy_len > 0 {
            let _ = r#gen::bpf_probe_read_user(
                (*event_ptr).data_excerpt.as_mut_ptr() as *mut c_void,
                copy_len,
                user_buf as *const c_void,
            );
        }
    }

    // Slot header: written *after* the body so userspace can detect
    // torn slots by comparing slot.sequence to the expected value.
    let header = ArenaEventHeader {
        sequence: seq,
        timestamp_ns: unsafe { bpf_ktime_get_boot_ns() },
        payload_len: core::mem::size_of::<DlpEventSmall>() as u32,
        event_type: 3, // EVENT_TYPE_DLP
        _pad: [0; 3],
    };
    unsafe {
        core::ptr::write_volatile(slot_ptr.cast::<ArenaEventHeader>(), header);
    }

    // Publish: bump the global write_seq at the arena head so
    // userspace knows a new slot is ready.
    unsafe {
        core::ptr::write_volatile(base.add(DLP_WRITE_SEQ_OFFSET).cast::<u64>(), seq);
    }

    true
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
