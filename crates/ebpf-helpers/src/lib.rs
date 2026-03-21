//! Shared helpers for eBPF programs.
//!
//! This `#![no_std]` crate centralises network header structs, byte conversion
//! helpers, pointer access functions, and metric/ringbuf macros that were
//! previously duplicated across every eBPF program.
//!
//! # Modules
//!
//! - [`net`] -- Network header structs (`Ipv6Hdr`, `VlanHdr`, `IcmpHdr`),
//!   Ethernet constants, and byte conversion functions.
//! - [`xdp`] -- `ptr_at`, `ptr_at_mut`, and `skip_ipv6_ext_headers` for
//!   `XdpContext`.
//! - [`tc`] -- `ptr_at` and `skip_ipv6_ext_headers` for `TcContext`.
//! - [`metrics`] -- `increment_metric!` and `add_metric!` macros.
//! - [`ringbuf`] -- Backpressure constants and `ringbuf_has_backpressure!`
//!   macro.

#![no_std]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

pub mod asm;
pub mod checksum;
pub mod event;
pub mod metrics;
pub mod net;
pub mod ringbuf;
pub mod tc;
pub mod user_ringbuf;
pub mod xdp;

/// Compiler barrier: prevents LLVM from reordering memory accesses across this
/// point. Insert after any BPF helper that invalidates packet pointers
/// (`bpf_xdp_adjust_tail`, `bpf_skb_store_bytes`, `bpf_skb_pull_data`, etc.)
/// so that subsequent reads of `data`/`data_end` are not hoisted before the
/// helper call. Equivalent to C's `asm volatile("" ::: "memory")`.
#[inline(always)]
pub unsafe fn barrier() {
    #[cfg(target_arch = "bpf")]
    unsafe {
        core::arch::asm!("", options(nostack, preserves_flags));
    }
}
