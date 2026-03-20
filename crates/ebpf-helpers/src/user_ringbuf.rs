//! User RingBuf map type for userspace→kernel config push.
//!
//! Wraps `BPF_MAP_TYPE_USER_RINGBUF` with a safe drain API.
//! Userspace writes config commands; the eBPF program drains them
//! at entry via `bpf_user_ringbuf_drain`.

use core::cell::UnsafeCell;

use aya_ebpf::bindings::bpf_map_def;
use aya_ebpf::bindings::bpf_map_type::BPF_MAP_TYPE_USER_RINGBUF;
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
                pinning: 0, // PinningType::None
            }),
        }
    }

    /// Drain all pending entries from the User RingBuf.
    ///
    /// # Safety
    ///
    /// `callback_fn` must be a valid function pointer compatible with the
    /// `bpf_user_ringbuf_drain` callback signature:
    /// `fn(ctx: *mut c_void, data: *mut c_void, data_sz: u64) -> i64`.
    /// The pointer is passed directly to a kernel helper; passing an invalid
    /// or mismatched pointer will cause undefined behaviour in the eBPF VM.
    pub unsafe fn drain(
        &self,
        callback_fn: *mut core::ffi::c_void,
        ctx: *mut core::ffi::c_void,
        flags: u64,
    ) -> i64 {
        unsafe { bpf_user_ringbuf_drain(self.def.get() as *mut _, callback_fn, ctx, flags) }
    }
}
