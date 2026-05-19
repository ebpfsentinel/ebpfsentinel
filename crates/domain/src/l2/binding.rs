//! Self-owned Layer-2 binding entity and the owned-binding set.

use std::collections::HashMap;
use std::net::IpAddr;

/// A single (IP → Ethernet MAC) binding this node legitimately
/// announces while it is the elected speaker.
///
/// Only IPv4 is meaningful for ARP; an IPv6 address is accepted by the
/// model but the announcer/adapter skip it (Neighbor Discovery is out
/// of scope), so it can never become self-announced in practice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L2Binding {
    ip: IpAddr,
    mac: [u8; 6],
}

impl L2Binding {
    /// Construct a binding for `ip` answered with `mac`.
    #[must_use]
    pub const fn new(ip: IpAddr, mac: [u8; 6]) -> Self {
        Self { ip, mac }
    }

    /// The bound IP address.
    #[must_use]
    pub const fn ip(&self) -> IpAddr {
        self.ip
    }

    /// The Ethernet MAC this node answers with for [`Self::ip`].
    #[must_use]
    pub const fn mac(&self) -> [u8; 6] {
        self.mac
    }
}

/// The set of bindings this node currently owns (self-whitelist).
///
/// Keyed by IP: registering an IP that is already present overwrites
/// its MAC (a VIP can only be answered with one MAC at a time). The
/// announcer keeps this in lock-step with the kernel
/// `SELF_OWNED_BINDINGS` map via the `L2BindingPort`.
#[derive(Debug, Default, Clone)]
pub struct OwnedBindings {
    by_ip: HashMap<IpAddr, [u8; 6]>,
}

impl OwnedBindings {
    /// An empty set (this node owns nothing — e.g. standby/disabled).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or overwrite) a binding. Returns `true` if this
    /// changed the set (new IP, or the MAC for an existing IP changed).
    pub fn register(&mut self, binding: L2Binding) -> bool {
        self.by_ip.insert(binding.ip, binding.mac) != Some(binding.mac)
    }

    /// Remove the binding for `ip`. Returns `true` if one was present.
    pub fn deregister(&mut self, ip: &IpAddr) -> bool {
        self.by_ip.remove(ip).is_some()
    }

    /// Drop every binding (speaker loss → own nothing).
    pub fn clear(&mut self) {
        self.by_ip.clear();
    }

    /// Whether `(ip, mac)` is a binding this node itself announces.
    ///
    /// Returns `false` for an unknown IP, and `false` when the IP is
    /// known but the MAC differs (a *foreign* claim — exactly the case
    /// the ARP-guard must still flag).
    #[must_use]
    pub fn is_self_announced(&self, ip: IpAddr, mac: [u8; 6]) -> bool {
        self.by_ip.get(&ip) == Some(&mac)
    }

    /// Whether any binding exists for `ip` regardless of MAC.
    #[must_use]
    pub fn contains_ip(&self, ip: &IpAddr) -> bool {
        self.by_ip.contains_key(ip)
    }

    /// Number of owned bindings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }

    /// Iterate the owned bindings.
    pub fn iter(&self) -> impl Iterator<Item = L2Binding> + '_ {
        self.by_ip.iter().map(|(&ip, &mac)| L2Binding::new(ip, mac))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, d))
    }
    const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
    const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];

    #[test]
    fn register_makes_pair_self_announced() {
        let mut o = OwnedBindings::new();
        assert!(o.register(L2Binding::new(ip(10), MAC_A)));
        assert!(o.is_self_announced(ip(10), MAC_A));
        assert_eq!(o.len(), 1);
        assert!(o.contains_ip(&ip(10)));
        // Re-registering the identical pair is a no-op change.
        assert!(!o.register(L2Binding::new(ip(10), MAC_A)));
        // Overwriting the MAC for a known IP is a change.
        assert!(o.register(L2Binding::new(ip(10), MAC_B)));
        assert!(o.is_self_announced(ip(10), MAC_B));
        assert!(!o.is_self_announced(ip(10), MAC_A));
    }

    #[test]
    fn deregister_drops_the_binding() {
        let mut o = OwnedBindings::new();
        o.register(L2Binding::new(ip(10), MAC_A));
        assert!(o.deregister(&ip(10)));
        assert!(!o.is_self_announced(ip(10), MAC_A));
        assert!(o.is_empty());
        // Deregistering an absent IP reports nothing was removed.
        assert!(!o.deregister(&ip(10)));
    }

    #[test]
    fn false_on_foreign() {
        let mut o = OwnedBindings::new();
        o.register(L2Binding::new(ip(10), MAC_A));
        // Unknown IP → not self-announced.
        assert!(!o.is_self_announced(ip(99), MAC_A));
        // Known IP, foreign MAC → not self-announced (guard must flag).
        assert!(!o.is_self_announced(ip(10), MAC_B));
    }

    #[test]
    fn false_after_loss() {
        let mut o = OwnedBindings::new();
        o.register(L2Binding::new(ip(10), MAC_A));
        o.register(L2Binding::new(ip(11), MAC_B));
        o.clear();
        assert!(o.is_empty());
        assert!(!o.is_self_announced(ip(10), MAC_A));
        assert!(!o.is_self_announced(ip(11), MAC_B));
    }

    #[test]
    fn iter_yields_registered_bindings() {
        let mut o = OwnedBindings::new();
        o.register(L2Binding::new(ip(10), MAC_A));
        o.register(L2Binding::new(ip(11), MAC_B));
        let mut got: Vec<_> = o.iter().map(|b| (b.ip(), b.mac())).collect();
        got.sort_by_key(|(ip, _)| *ip);
        assert_eq!(got, vec![(ip(10), MAC_A), (ip(11), MAC_B)]);
    }
}
