//! What this node exposes, read from the kernel rather than guessed from
//! outside.
//!
//! A scanner says what answered from where it stood, and a host inventory
//! says what listens. This module holds the second half as the socket hooks
//! record it: every socket holding a local address, the task that bound it,
//! and whether that address was one interface, the loopback, or all of them.

pub mod entity;
