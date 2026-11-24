//! XDP-specific helpers: bounds-checked pointer access and IPv6 extension
//! header skipping for [`aya_ebpf::programs::XdpContext`].

use aya_ebpf::helpers::generated::bpf_xdp_get_buff_len;
use aya_ebpf::programs::XdpContext;
use core::mem;
use ebpf_common::ipv6::walk_ipv6_ext_headers;

use crate::kfuncs::xdp_pull_data;

/// Bounds-checked read-only pointer access for XDP programs.
///
/// Returns a pointer to a `T` at `offset` bytes into the packet, or
/// `Err(())` when `[offset, offset + size_of::<T>())` falls outside the
/// `[data, data_end)` window.
///
/// # Safety
/// `ctx` must be a live `XdpContext` for the current program invocation.
/// The returned pointer is valid only until the packet is modified by a
/// helper that adjusts its head/tail, and must not be dereferenced
/// beyond `size_of::<T>()` bytes.
// `()` error follows the established aya eBPF bounds-check idiom; a richer
// error type would bloat every call site across the no_std programs for no
// added signal (callers only branch on Ok/Err).
#[allow(clippy::result_unit_err)]
#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let len = mem::size_of::<T>();
    let end = ctx.data_end();
    let ptr = start + offset;
    if ptr + len > end {
        return Err(());
    }
    Ok(ptr as *const T)
}

/// Bounds-checked mutable pointer access for XDP programs.
///
/// Returns a mutable pointer to a `T` at `offset` bytes into the packet,
/// or `Err(())` when `[offset, offset + size_of::<T>())` falls outside
/// the `[data, data_end)` window.
///
/// # Safety
/// `ctx` must be a live `XdpContext` for the current program invocation.
/// The returned pointer is valid only until the packet is modified by a
/// helper that adjusts its head/tail, and must not be dereferenced
/// beyond `size_of::<T>()` bytes.
// `()` error follows the established aya eBPF bounds-check idiom; a richer
// error type would bloat every call site across the no_std programs for no
// added signal (callers only branch on Ok/Err).
#[allow(clippy::result_unit_err)]
#[inline(always)]
pub unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let len = mem::size_of::<T>();
    let end = ctx.data_end();
    let ptr = start + offset;
    if ptr + len > end {
        return Err(());
    }
    Ok(ptr as *mut T)
}

/// Skip IPv6 extension headers, returning the final `next_header` (protocol)
/// and the byte offset after the last extension header.
///
/// The walk itself is [`ebpf_common::ipv6::walk_ipv6_ext_headers`], which is in
/// the workspace and therefore under test; this is the XDP half of handing it
/// the packet window.
#[inline(always)]
pub fn skip_ipv6_ext_headers(
    ctx: &XdpContext,
    start_offset: usize,
    next_hdr: u8,
) -> Option<(u8, usize)> {
    // SAFETY: `data()..data_end()` is the readable packet window the kernel
    // handed this program invocation.
    unsafe { walk_ipv6_ext_headers(ctx.data(), ctx.data_end(), start_offset, next_hdr) }
}

/// The whole length of the frame, every buffer of it counted.
///
/// `data_end - data` is only the first buffer of a frame larger than one;
/// a rewrite that sizes the frame with `bpf_xdp_adjust_tail` reads this so
/// the trailing buffers are released along with the bytes it cuts.
#[inline(always)]
#[must_use]
pub fn frame_len(ctx: &XdpContext) -> usize {
    // SAFETY: `ctx.ctx` is the live context of this invocation; the helper
    // only reads the buffer lengths.
    let total = unsafe { bpf_xdp_get_buff_len(ctx.ctx) };
    total as usize
}

/// How much of a frame larger than one buffer a pull brings into its first
/// buffer: an Ethernet header, two VLAN tags, an IPv6 header with a run of
/// extension headers and a TCP header with its options all fit.
pub const XDP_PULL_LEN: u32 = 256;

/// Bring the head of a frame larger than one buffer into its first buffer.
///
/// A jumbo frame or a hardware GRO aggregate reaches XDP as several buffers,
/// and only the first is readable through `data..data_end`. When the headers
/// a parse needs fall past it, the parse fails although the frame is whole.
/// This moves the first [`XDP_PULL_LEN`] bytes (or the whole frame, if
/// smaller) into the first buffer so the parse can run again.
///
/// Returns `true` only when bytes were moved: a frame already holding that
/// much in its first buffer, a single-buffer frame, a host whose verifier
/// refused the kfunc (the loader rewrites the call to fail) and a first
/// buffer without the room all return `false`, and the frame is left as it
/// was.
///
/// # Safety
/// `ctx_raw` must be the trusted `xdp_md*` the program was entered with,
/// passed by value from the entry frame. Every packet pointer taken before
/// the call is invalid after it.
#[inline(always)]
pub unsafe fn pull_past_first_buffer(ctx_raw: *mut core::ffi::c_void) -> bool {
    let ctx = XdpContext::new(ctx_raw.cast());
    let linear = (ctx.data_end() - ctx.data()) as u64;
    if linear >= u64::from(XDP_PULL_LEN) {
        return false;
    }
    // SAFETY: `ctx_raw` is the live context of this invocation.
    let total = unsafe { bpf_xdp_get_buff_len(ctx_raw.cast()) };
    if total <= linear {
        return false;
    }
    let len = if total < u64::from(XDP_PULL_LEN) {
        total as u32
    } else {
        XDP_PULL_LEN
    };
    // SAFETY: the trusted context is passed straight through; the caller
    // takes every packet pointer again after the call.
    let pulled = unsafe { xdp_pull_data(ctx_raw, len) } == 0;
    // SAFETY: an empty clobber, so `data`/`data_end` are read again below
    // the call rather than reused from above it.
    unsafe { crate::barrier() };
    pulled
}
