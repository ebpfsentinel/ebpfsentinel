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

pub mod metrics;
pub mod net;
pub mod ringbuf;
pub mod tc;
pub mod xdp;
