//! Layer-2 self-binding model (VIP → owned MAC) shared across the L2
//! VIP announcer and the (later) ARP-guard.
//!
//! The announcer is the **live producer**: while this node is the
//! elected speaker it registers one binding per owned VIP; on speaker
//! loss every binding is removed. The ARP-guard is the consumer — it
//! uses [`OwnedBindings::is_self_announced`] to recognise this node's
//! own gratuitous ARP / binding changes and avoid raising a false
//! binding-change anomaly on traffic the node itself generated.

pub mod binding;

pub use binding::{L2Binding, OwnedBindings};
