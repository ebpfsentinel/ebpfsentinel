//! XDP-specific helpers: bounds-checked pointer access and IPv6 extension
//! header skipping for [`aya_ebpf::programs::XdpContext`].

use aya_ebpf::programs::XdpContext;
use core::mem;
use ebpf_common::ipv6::walk_ipv6_ext_headers;

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
