//! TC-specific helpers: bounds-checked pointer access and IPv6 extension
//! header skipping for [`aya_ebpf::programs::TcContext`].

use aya_ebpf::programs::TcContext;
use core::mem;

/// Bounds-checked read-only pointer access for TC programs.
///
/// Returns a pointer to a `T` at `offset` bytes into the packet, or
/// `Err(())` when `[offset, offset + size_of::<T>())` falls outside the
/// `[data, data_end)` window.
///
/// # Safety
/// `ctx` must be a live `TcContext` for the current program invocation.
/// The returned pointer is valid only until the packet is modified by a
/// helper that adjusts its head/tail, and must not be dereferenced
/// beyond `size_of::<T>()` bytes.
// `()` error follows the established aya eBPF bounds-check idiom; a richer
// error type would bloat every call site across the no_std programs for no
// added signal (callers only branch on Ok/Err).
#[allow(clippy::result_unit_err)]
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
                    // Use the full 8-bit Hdr-Ext-Len field. Masking it makes
                    // this parser advance fewer bytes than the host stack for
                    // headers longer than the mask, so the L4 offset diverges
                    // and crafted IPv6 extension chains evade inspection.
                    // `u8 as usize` is provably 0..=255, so the multiply stays
                    // bounded for the verifier.
                    let hdr_len_byte = unsafe { *hdr_ptr.add(1) } as usize;
                    if next_hdr == 51 {
                        // AH header: length in 4-byte units, max (255+2)*4 = 1028.
                        pos += (hdr_len_byte + 2) * 4;
                    } else {
                        // Other ext headers: length in 8-byte units,
                        // max (255+1)*8 = 2048.
                        pos += (hdr_len_byte + 1) * 8;
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
