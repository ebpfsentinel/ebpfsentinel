//! XDP-specific helpers: bounds-checked pointer access and IPv6 extension
//! header skipping for [`aya_ebpf::programs::XdpContext`].

use aya_ebpf::programs::XdpContext;
use core::mem;

/// Bounds-checked read-only pointer access for XDP programs.
///
/// Critical for eBPF verifier compliance: every memory access must be
/// validated against `data_end`.
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Bounds-checked mutable pointer access for XDP programs.
#[inline(always)]
pub unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *mut T)
}

/// Skip IPv6 extension headers, returning the final `next_header` (protocol)
/// and the byte offset after the last extension header.
///
/// Bounded to 6 iterations for eBPF verifier compliance. Handles:
/// Hop-by-hop (0), Routing (43), Fragment (44), ESP (50), AH (51),
/// Destination (60), and Mobility (135).
#[inline(always)]
pub fn skip_ipv6_ext_headers(
    ctx: &XdpContext,
    mut offset: usize,
    mut next_hdr: u8,
) -> Option<(u8, usize)> {
    let mut i = 0u32;
    while i < 6 {
        match next_hdr {
            0 | 43 | 44 | 50 | 51 | 60 | 135 => {
                let hdr_len_byte: u8 = unsafe { *ptr_at(ctx, offset + 1).ok()? };
                if next_hdr == 44 {
                    // Fragment header is fixed 8 bytes
                    next_hdr = unsafe { *ptr_at(ctx, offset).ok()? };
                    offset += 8;
                } else {
                    next_hdr = unsafe { *ptr_at(ctx, offset).ok()? };
                    offset += (hdr_len_byte as usize + 1) * 8;
                }
            }
            _ => break,
        }
        i += 1;
    }
    Some((next_hdr, offset))
}
