//! Saying that this installation exists, and which eBPF programs it is running.
//!
//! Three things go out and nothing else does: a random installation
//! identifier, the agent version, and the fixed set of eBPF program names with
//! whether each one is loaded. What the agent is *configured* to do - rules,
//! interfaces, addresses, feeds, hostnames - has no field to travel in, which
//! is the distinction this module exists to keep.

pub mod engine;
pub mod entity;
pub mod error;
