//! Who else reads frames off the node's interfaces.
//!
//! A packet socket (`AF_PACKET`) receives frames before the network stack
//! does. A capture tool opens one, a DHCP client opens one, and so does a
//! backdoor waiting for a magic packet, which attaches a classic BPF filter so
//! that only that packet ever wakes it. This module holds the inventory of
//! those sockets and what changed between two readings of it.

pub mod entity;

pub use entity::{FilterState, RAW_SOCKET_COMPONENT, RawSocket, RawSocketKind, new_sockets};
