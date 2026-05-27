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
pub mod kfuncs;
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
///
/// # Safety
/// Always safe to call: the body is an empty inline-asm memory clobber on
/// the BPF target and a no-op elsewhere. It is `unsafe` only because it
/// wraps the `asm!` primitive; it touches no memory and has no
/// preconditions.
#[inline(always)]
pub unsafe fn barrier() {
    #[cfg(target_arch = "bpf")]
    unsafe {
        core::arch::asm!("", options(nostack, preserves_flags));
    }
}

/// Value barrier (libbpf's `barrier_var`): returns `v` but forces LLVM to
/// treat it as an opaque runtime value at this point.
///
/// Use it when a value is mathematically in range but the compiler can prove
/// the fact statically and so elides the bound check the verifier needs — the
/// canonical case being `x % N` for a constant `N`. Without the barrier LLVM
/// drops the `if idx < N` guard as redundant, leaving the verifier with the
/// unbounded modulo result ("unbounded memory access" on the following array
/// deref). Passing the index through this barrier first makes the guard a real
/// runtime branch the verifier uses to constrain the value.
///
/// On non-BPF targets it is the identity function.
#[inline(always)]
#[must_use]
pub fn opaque_usize(mut v: usize) -> usize {
    #[cfg(target_arch = "bpf")]
    unsafe {
        // Empty template + register operand = libbpf's `barrier_var`. The
        // operand must appear in the template, so name it inside an assembler
        // comment: it emits no instruction but still forces `v` through a
        // register the compiler must treat as opaque.
        core::arch::asm!("/* {0} */", inout(reg) v, options(nostack, preserves_flags, nomem));
    }
    v
}
