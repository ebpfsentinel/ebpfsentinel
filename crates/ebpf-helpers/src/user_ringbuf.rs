//! User RingBuf map type for userspace→kernel config push.
//!
//! Wraps `BPF_MAP_TYPE_USER_RINGBUF` with a safe drain API.
//! Userspace writes config commands; the eBPF program drains them
//! at entry via `bpf_user_ringbuf_drain`.

use core::cell::UnsafeCell;

use aya_ebpf::bindings::bpf_map_def;
use aya_ebpf::bindings::bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF;
use aya_ebpf::maps::PinningType;
use aya_ebpf_bindings::helpers::bpf_user_ringbuf_drain;

/// A `BPF_MAP_TYPE_USER_RINGBUF` map for receiving config commands from userspace.
///
/// The eBPF program calls [`drain`] at entry to consume pending commands.
/// Each command is passed to a callback function for processing.
///
/// [`drain`]: UserRingBuf::drain
#[repr(transparent)]
pub struct UserRingBuf {
    def: UnsafeCell<bpf_map_def>,
}

unsafe impl Sync for UserRingBuf {}

impl UserRingBuf {
    /// Declare a User RingBuf with the given byte size.
    ///
    /// `byte_size` must be a power-of-2 multiple of the page size.
    pub const fn with_byte_size(byte_size: u32, flags: u32) -> Self {
        Self {
            def: UnsafeCell::new(bpf_map_def {
                type_: BPF_MAP_TYPE_USER_RINGBUF,
                key_size: 0,
                value_size: 0,
                max_entries: byte_size,
                map_flags: flags,
                id: 0,
                pinning: PinningType::None as u32,
            }),
        }
    }

    /// Drain all pending entries from the User RingBuf.
    ///
    /// `callback_fn` is called once per entry with:
    /// - `ctx`: user-provided context pointer (passed through)
    /// - `data`: pointer to the entry data
    /// - `data_sz`: size of the entry
    ///
    /// The callback must return 0 to continue draining or non-zero to stop.
    ///
    /// Returns the number of entries drained, or a negative error code.
    ///
    /// # Safety
    ///
    /// The callback function pointer must be valid and compatible with the
    /// `bpf_user_ringbuf_drain` callback signature:
    /// `fn(ctx: *mut c_void, data: *mut c_void, data_sz: u64) -> i64`
    pub unsafe fn drain(
        &self,
        callback_fn: *mut core::ffi::c_void,
        ctx: *mut core::ffi::c_void,
        flags: u64,
    ) -> i64 {
        bpf_user_ringbuf_drain(
            self.def.get() as *mut _,
            callback_fn,
            ctx,
            flags,
        )
    }
}
