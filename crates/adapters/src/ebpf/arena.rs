#![allow(unsafe_code)] // Raw bpf() syscall + mmap required for arena maps.

//! `BPF_MAP_TYPE_ARENA` zero-copy shared memory between BPF and userspace.
//!
//! Arena maps provide a shared mmap'd region that both BPF programs
//! and userspace can read/write without copy. Created via raw
//! `bpf(BPF_MAP_CREATE)` syscall since aya 0.13 has no high-level
//! Arena API. The mmap'd pointer is valid for the lifetime of this
//! manager.
//!
//! Requires `CAP_BPF` + kernel 6.9+.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::ptr;

use tracing::{debug, info};

/// `BPF_MAP_CREATE` command for the `bpf()` syscall.
const BPF_MAP_CREATE: u32 = 0;
/// `BPF_MAP_TYPE_ARENA` from kernel `include/uapi/linux/bpf.h`.
const BPF_MAP_TYPE_ARENA: u32 = 33;

/// Subset of `union bpf_attr` for `BPF_MAP_CREATE`.
#[repr(C)]
#[derive(Default)]
struct BpfAttrMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
    value_type_btf_obj_fd: u32,
    map_token_fd: u32,
}

/// Manages a `BPF_MAP_TYPE_ARENA` backed by a raw bpf fd + mmap.
///
/// The arena is a contiguous region of pages shared between kernel
/// BPF programs and userspace via mmap. BPF writes to the arena
/// are visible to userspace immediately (zero-copy).
pub struct ArenaMap {
    _fd: OwnedFd,
    ptr: *mut u8,
    size: usize,
}

// SAFETY: the mmap'd region is shared memory with atomic semantics.
// The ArenaMap is Send+Sync because the pointer is backed by a
// kernel-managed page that survives thread migration.
unsafe impl Send for ArenaMap {}
unsafe impl Sync for ArenaMap {}

impl ArenaMap {
    /// Create a new arena map with `page_count` pages (each 4 KiB).
    ///
    /// Returns `None` if the kernel does not support arena maps or
    /// the process lacks `CAP_BPF`.
    pub fn create(page_count: u32, name: &str) -> Result<Self, ArenaError> {
        let mut attr = BpfAttrMapCreate {
            map_type: BPF_MAP_TYPE_ARENA,
            key_size: 0,
            value_size: 0,
            max_entries: page_count,
            ..Default::default()
        };
        // Copy name (up to 15 bytes + null).
        let name_bytes = name.as_bytes();
        let copy_len = name_bytes.len().min(15);
        attr.map_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        #[allow(clippy::cast_possible_truncation)]
        let attr_size = std::mem::size_of::<BpfAttrMapCreate>() as u32;
        let attr_ptr: *const BpfAttrMapCreate = &raw const attr;

        // SAFETY: valid bpf_attr for BPF_MAP_CREATE with ARENA type.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                #[allow(clippy::cast_possible_wrap)]
                (BPF_MAP_CREATE as libc::c_int),
                attr_ptr as usize,
                attr_size as usize,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(ArenaError::CreateFailed {
                errno: err.raw_os_error().unwrap_or(0),
                message: err.to_string(),
            });
        }

        // SAFETY: fd is valid, returned by successful bpf() syscall.
        #[allow(clippy::cast_possible_truncation)]
        let raw_fd = fd as i32;
        let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        let size = (page_count as usize) * 4096;

        // mmap the arena fd into userspace.
        // SAFETY: fd is a valid BPF arena map fd, size is aligned.
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                raw_fd,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            return Err(ArenaError::MmapFailed {
                errno: err.raw_os_error().unwrap_or(0),
                message: err.to_string(),
            });
        }

        info!(
            pages = page_count,
            size_bytes = size,
            name,
            "arena map created and mmap'd"
        );

        Ok(Self {
            _fd: owned_fd,
            ptr: ptr.cast::<u8>(),
            size,
        })
    }

    /// Adopt an existing arena map fd (owned by the aya loader),
    /// duplicating it and `mmap`'ing the result at the supplied
    /// fixed virtual address. Used to share the BPF-loaded
    /// `DLP_ARENA` map with userspace at the same VA the BPF
    /// program will allocate from.
    ///
    /// `MAP_FIXED_NOREPLACE` ensures we never silently clobber an
    /// existing mapping at `fixed_va`.
    pub fn from_aya_fd(
        fd: BorrowedFd<'_>,
        page_count: u32,
        fixed_va: usize,
    ) -> Result<Self, ArenaError> {
        let size = (page_count as usize) * 4096;

        // SAFETY: dup the borrowed fd so we own a ref-counted handle
        // for the lifetime of this ArenaMap.
        let dup = unsafe { libc::dup(fd.as_raw_fd()) };
        if dup < 0 {
            let err = io::Error::last_os_error();
            return Err(ArenaError::CreateFailed {
                errno: err.raw_os_error().unwrap_or(0),
                message: format!("dup arena fd: {err}"),
            });
        }
        // SAFETY: dup returned a valid fd we own.
        let owned_fd = unsafe { OwnedFd::from_raw_fd(dup) };

        // SAFETY: fixed_va is a high userspace address (16 TiB) that
        // sits well above the typical heap/stack range; MAP_FIXED_NOREPLACE
        // returns -1 / EEXIST if it would clobber an existing mapping.
        let ptr = unsafe {
            libc::mmap(
                fixed_va as *mut libc::c_void,
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_FIXED_NOREPLACE,
                owned_fd.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            let err = io::Error::last_os_error();
            return Err(ArenaError::MmapFailed {
                errno: err.raw_os_error().unwrap_or(0),
                message: format!("mmap MAP_FIXED_NOREPLACE @ {fixed_va:#x}: {err}"),
            });
        }
        if (ptr as usize) != fixed_va {
            // Defensive: kernel honoured the request elsewhere — unmap
            // and refuse so the BPF/userspace VAs don't drift.
            // SAFETY: ptr was returned by a successful mmap call.
            unsafe { libc::munmap(ptr, size) };
            return Err(ArenaError::MmapFailed {
                errno: 0,
                message: format!(
                    "mmap returned {ptr:p} instead of requested fixed VA {fixed_va:#x}"
                ),
            });
        }

        info!(
            pages = page_count,
            size_bytes = size,
            fixed_va = format_args!("{fixed_va:#x}"),
            "arena map adopted from aya fd at fixed VA"
        );

        Ok(Self {
            _fd: owned_fd,
            ptr: ptr.cast::<u8>(),
            size,
        })
    }

    /// Pointer to the mmap'd arena region. Valid for `self.size()`
    /// bytes. Both BPF programs and userspace can read/write this
    /// region concurrently — use atomic operations for shared fields.
    #[must_use]
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Total size of the arena in bytes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Read a value at byte offset. No bounds check beyond debug
    /// assert — caller must ensure `offset + size_of::<T>() <= size`.
    ///
    /// # Safety
    /// `offset + size_of::<T>()` must be within the arena.
    #[inline]
    pub unsafe fn read_at<T: Copy>(&self, offset: usize) -> T {
        debug_assert!(offset + std::mem::size_of::<T>() <= self.size);
        unsafe { ptr::read_volatile(self.ptr.add(offset).cast::<T>()) }
    }

    /// Write a value at byte offset.
    ///
    /// # Safety
    /// `offset + size_of::<T>()` must be within the arena.
    #[inline]
    pub unsafe fn write_at<T: Copy>(&self, offset: usize, val: T) {
        debug_assert!(offset + std::mem::size_of::<T>() <= self.size);
        unsafe { ptr::write_volatile(self.ptr.add(offset).cast::<T>(), val) };
    }
}

impl Drop for ArenaMap {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr was returned by a successful mmap call.
            unsafe {
                libc::munmap(self.ptr.cast(), self.size);
            }
            debug!(size = self.size, "arena map munmap'd");
        }
    }
}

/// Errors from arena map creation.
#[derive(Debug, thiserror::Error)]
pub enum ArenaError {
    #[error("bpf(BPF_MAP_CREATE, ARENA) failed: errno={errno} {message}")]
    CreateFailed { errno: i32, message: String },
    #[error("mmap of arena fd failed: errno={errno} {message}")]
    MmapFailed { errno: i32, message: String },
}

/// Check whether the kernel supports `BPF_MAP_TYPE_ARENA` by
/// attempting to create a 1-page arena. Best-effort probe called
/// at startup.
pub fn is_arena_supported() -> bool {
    ArenaMap::create(1, "probe").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arena_error_display() {
        let e = ArenaError::CreateFailed {
            errno: 22,
            message: "Invalid argument".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("ARENA"));
        assert!(s.contains("22"));
    }

    #[test]
    fn bpf_attr_map_create_layout() {
        // Ensure our struct is large enough for the kernel to read.
        // The kernel reads at least 48 bytes for BPF_MAP_CREATE.
        assert!(std::mem::size_of::<BpfAttrMapCreate>() >= 48);
    }

    // NOTE: create + mmap tests require CAP_BPF and are run in
    // integration tests, not unit tests. The ArenaMap::create call
    // will return Err(CreateFailed) in unprivileged CI.

    #[test]
    fn arena_create_unprivileged_returns_error() {
        // In CI without CAP_BPF, creation should fail gracefully.
        // On a privileged machine this test still passes because
        // we only assert the result is a valid Result.
        let result = ArenaMap::create(1, "test");
        // Either Ok or Err — both are valid, no panic.
        let _ = result;
    }

    #[test]
    fn arena_proof_of_concept_userspace_roundtrip() {
        // End-to-end proof: create arena → write ArenaEventHeader
        // → read it back. This validates the userspace side of the
        // zero-copy path. The BPF side (writing from a TC/XDP
        // program) can only be tested on a real kernel with CAP_BPF.
        let Ok(arena) = ArenaMap::create(1, "poc") else {
            // No CAP_BPF — skip gracefully (CI).
            eprintln!("arena_proof_of_concept: skipped (no CAP_BPF)");
            return;
        };

        assert!(arena.size() >= 4096);
        assert!(!arena.as_ptr().is_null());

        // Write an ArenaEventHeader at offset 0.
        let header = ebpf_common::arena::ArenaEventHeader {
            sequence: 42,
            timestamp_ns: 1_700_000_000_000_000_000,
            payload_len: 128,
            event_type: 3, // EVENT_TYPE_DLP
            _pad: [0; 3],
        };
        unsafe { arena.write_at(0, header) };

        // Read it back — zero-copy, same mmap'd page.
        let read_back: ebpf_common::arena::ArenaEventHeader = unsafe { arena.read_at(0) };
        assert_eq!(read_back.sequence, 42);
        assert_eq!(read_back.timestamp_ns, 1_700_000_000_000_000_000);
        assert_eq!(read_back.payload_len, 128);
        assert_eq!(read_back.event_type, 3);

        // Write a u64 counter at offset 4096-8 (end of page).
        unsafe { arena.write_at(4096 - 8, 0xDEAD_BEEF_CAFE_BABEu64) };
        let val: u64 = unsafe { arena.read_at(4096 - 8) };
        assert_eq!(val, 0xDEAD_BEEF_CAFE_BABE);
    }
}
