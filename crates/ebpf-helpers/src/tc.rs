//! TC-specific helpers: bounds-checked pointer access and IPv6 extension
//! header skipping for [`aya_ebpf::programs::TcContext`].

use aya_ebpf::programs::TcContext;
use core::mem;

/// Bounds-checked read-only pointer access for TC programs.
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let len = mem::size_of::<T>();
    let end = ctx.data_end();
    let ptr = start + offset;
    if ptr + len > end {
        return Err(());
    }
    Ok(ptr as *const T)
}

/// Skip IPv6 extension headers, returning the final `next_header` (protocol)
/// and the byte offset after the last extension header.
///
/// Bounded to 6 iterations for eBPF verifier compliance. Handles:
/// Hop-by-hop (0), Routing (43), Fragment (44), AH (51),
/// Destination (60), and Mobility (135).
///
/// ESP (50) is a terminal header and is not consumed — when encountered it is
/// returned immediately as the upper-layer protocol.
/// Parse IPv6 extension headers using raw pointer advancement (TC variant).
#[inline(always)]
pub fn skip_ipv6_ext_headers(
    ctx: &TcContext,
    start_offset: usize,
    mut next_hdr: u8,
) -> Option<(u8, usize)> {
    let start = ctx.data();
    let end = ctx.data_end();
    let mut pos = start + start_offset;

    let mut i = 0u32;
    while i < 6 {
        match next_hdr {
            0 | 43 | 44 | 51 | 60 | 135 => {
                if pos + 2 > end {
                    return None;
                }
                let hdr_ptr = pos as *const u8;
                next_hdr = unsafe { *hdr_ptr };

                if next_hdr == 44 {
                    pos += 8;
                } else {
                    let hdr_len_byte = unsafe { *hdr_ptr.add(1) };
                    let clamped = (hdr_len_byte & 0x1F) as usize;
                    if next_hdr == 51 {
                        // AH header: length in 4-byte units, max (31+2)*4 = 132
                        pos += (clamped + 2) * 4;
                    } else {
                        // Other ext headers: length in 8-byte units, max (31+1)*8 = 256
                        pos += (clamped + 1) * 8;
                    }
                }
                // Bounds check after each header advancement
                if pos > end {
                    return None;
                }
            }
            _ => break,
        }
        i += 1;
    }

    let final_offset = pos - start;
    if final_offset > 512 {
        return None;
    }
    Some((next_hdr, final_offset))
}
