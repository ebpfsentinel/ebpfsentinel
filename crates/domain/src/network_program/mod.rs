//! Who else has a program on the node's network path.
//!
//! A program attached ahead of the agent's sees, drops, rewrites or redirects
//! a packet before the agent does. A CNI puts one there on purpose, so does a
//! load balancer or a capture tool, and so can anybody holding `CAP_BPF` and
//! `CAP_NET_ADMIN`. This module holds the inventory of those programs, with
//! the agent's own set apart.

pub mod entity;

pub use entity::{NetworkHook, NetworkProgram, OwnBpfObjects, split_own};
