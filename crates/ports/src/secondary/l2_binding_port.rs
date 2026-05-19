use std::net::IpAddr;

use domain::common::error::DomainError;
use domain::l2::L2Binding;

/// Secondary port for the kernel `SELF_OWNED_BINDINGS` map.
///
/// The L2 VIP announcer is the live producer: while this node is the
/// elected speaker it registers one binding per owned VIP; on speaker
/// loss every binding is removed. The bounded XDP responder reads the
/// map to source the forged ARP reply's `sha`, and the later ARP-guard
/// epic reads the same map to ignore this node's own gratuitous ARP.
///
/// Implemented by `SelfBindingManager` in the adapter layer. Non-IPv4
/// bindings are a documented no-op (ARP is IPv4-only).
pub trait L2BindingPort: Send + Sync {
    /// Insert or update a self-owned binding, keyed by the IPv4 address
    /// as a big-endian numeric `u32` (same key space as `VIP_SET`).
    fn register_binding(&mut self, binding: &L2Binding) -> Result<(), DomainError>;

    /// Remove the binding for `ip` (idempotent if absent).
    fn deregister_binding(&mut self, ip: IpAddr) -> Result<(), DomainError>;

    /// Remove every entry — called on speaker loss so a standby node
    /// owns nothing (keeps the kernel map split-brain safe).
    fn clear_bindings(&mut self) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2_binding_port_is_object_safe() {
        fn _b(_p: &dyn L2BindingPort) {}
    }
}
