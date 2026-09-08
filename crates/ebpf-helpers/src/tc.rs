//! TC-specific helpers: bounds-checked pointer access and IPv6 extension
//! header skipping for [`aya_ebpf::programs::TcContext`].

use aya_ebpf::programs::TcContext;
use core::mem;
use ebpf_common::ipv6::{
    IPV6_EXT_MAX_HEADERS, IPV6_EXT_MAX_OFFSET, ipv6_ext_header_len, is_ipv6_ext_header,
};

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
/// ESP (50) is a terminal header and is not consumed - when encountered it is
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
    while i < IPV6_EXT_MAX_HEADERS {
        if !is_ipv6_ext_header(next_hdr) {
            break;
        }
        // Bounds check: need at least 2 bytes (next_hdr + len)
        if pos + 2 > end {
            return None;
        }
        let hdr_ptr = pos as *const u8;
        // The header being measured is the one this iteration entered on, not
        // the Next Header value read out of it: those two are one header apart,
        // and measuring the following one is how a Fragment header carrying a
        // non-zero reserved byte moves this parser off the L4 offset the host
        // stack lands on.
        let this_hdr = next_hdr;
        next_hdr = unsafe { *hdr_ptr };
        let hdr_ext_len = unsafe { *hdr_ptr.add(1) };
        pos += ipv6_ext_header_len(this_hdr, hdr_ext_len);
        // Bounds check after each header advancement
        if pos > end {
            return None;
        }
        i += 1;
    }

    let final_offset = pos - start;
    // Sanity cap
    if final_offset > IPV6_EXT_MAX_OFFSET {
        return None;
    }
    Some((next_hdr, final_offset))
}
