//! Raw `BPF_MAP_TYPE_ARENA` map definition for eBPF programs.
//!
//! aya-ebpf 0.13 has no built-in Arena map type. This module provides
//! a raw map definition struct that BPF programs can declare via
//! `#[link_section = ".maps"]` to create an arena map visible to both
//! the BPF verifier and the userspace loader.
//!
//! The arena is mmap'd by userspace after loading; BPF programs write
//! into it via `bpf_arena_alloc_pages` or direct pointer access.

/// Raw BPF map definition matching the kernel's `struct bpf_map_def`.
/// Used to declare arena maps in BPF programs without aya-ebpf
/// high-level support.
#[repr(C)]
pub struct RawMapDef {
    pub type_: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
}

/// `BPF_MAP_TYPE_ARENA` constant.
pub const BPF_MAP_TYPE_ARENA: u32 = 33;

/// Declare an arena map definition. The map will be created by the
/// kernel loader when the BPF program is loaded. Userspace can then
/// mmap it for zero-copy access.
///
/// Usage in a BPF program:
/// ```ignore
/// use ebpf_helpers::arena_map::{RawMapDef, BPF_MAP_TYPE_ARENA};
///
/// #[link_section = ".maps"]
/// #[no_mangle]
/// static DLP_ARENA: RawMapDef = RawMapDef {
///     type_: BPF_MAP_TYPE_ARENA,
///     key_size: 0,
///     value_size: 0,
///     max_entries: 4, // 4 pages = 16 KiB
///     map_flags: 0,
/// };
/// ```
///
/// Then from BPF code:
/// ```ignore
/// let page = arena_alloc_pages(&raw const DLP_ARENA as *mut _, 1);
/// ```
///
/// And from userspace:
/// ```ignore
/// let arena_map = ebpf.map("DLP_ARENA");
/// // mmap the fd for zero-copy reads
/// ```
pub const fn arena_def(page_count: u32) -> RawMapDef {
    RawMapDef {
        type_: BPF_MAP_TYPE_ARENA,
        key_size: 0,
        value_size: 0,
        max_entries: page_count,
        map_flags: 0,
    }
}
