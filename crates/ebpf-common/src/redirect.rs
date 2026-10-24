//! Sending a chosen workload's connections to a local listener, and telling
//! that listener where each one was going.
//!
//! A TLS client that links its library statically, or carries one nobody
//! publishes symbols for, is out of reach of every uprobe: there is no
//! function to hook and no buffer to read. The one place its plaintext still
//! exists outside the process is at a proxy that terminates the session, and
//! the one moment its connection can be steered there without touching the
//! workload is `connect()`, while the destination is still an argument.
//!
//! Four properties are deliberate:
//!
//! - Nothing is redirected unless its cgroup, or an ancestor of it, is in
//!   `REDIRECT_CGROUPS`. The map starts empty, so a loaded program with no
//!   selection written behaves exactly as an unloaded one.
//! - The original destination is recorded before the address is rewritten,
//!   and a connection whose destination could not be recorded is refused
//!   rather than sent on: a proxy that receives a connection it cannot route
//!   either guesses or drops it, and a guess is a connection to somewhere the
//!   workload never asked for.
//! - The agent's own cgroup is exempt, so the listener's onward connection
//!   to the real destination is never sent back to the listener.
//! - The listener finds the destination by the address it sees the
//!   connection come from, written by the `sockops` hook once the kernel has
//!   chosen a source port. Nothing else is shared between the two sides.

/// Address family of a [`RedirectPeerKey`] or [`RedirectOrigin`]: IPv4.
pub const REDIRECT_FAMILY_IPV4: u8 = 4;
/// Address family of a [`RedirectPeerKey`] or [`RedirectOrigin`]: IPv6.
pub const REDIRECT_FAMILY_IPV6: u8 = 6;

/// Metric index: connections steered to the listener.
pub const REDIRECT_METRIC_REDIRECTED: u32 = 0;
/// Metric index: connections refused because their destination could not be
/// recorded.
pub const REDIRECT_METRIC_REFUSED: u32 = 1;
/// Metric index: connections from a selected cgroup to a destination outside
/// the redirected ports, left alone.
pub const REDIRECT_METRIC_PORT_SKIPPED: u32 = 2;
/// Metric index: redirected connections whose source address was published
/// to the listener.
pub const REDIRECT_METRIC_PUBLISHED: u32 = 3;
/// Metric index: redirected connections whose source address could not be
/// published, which the listener sees as a connection with no destination.
pub const REDIRECT_METRIC_PUBLISH_FAILED: u32 = 4;
/// Total number of redirect metric slots (one past the last index).
pub const REDIRECT_METRIC_COUNT: u32 = 5;

/// How many cgroups may be selected at once.
pub const REDIRECT_MAX_CGROUPS: u32 = 4_096;
/// How many cgroups may be exempted at once. The agent's own is the one
/// that matters; the rest is room for a sidecar that relays on its behalf.
pub const REDIRECT_MAX_EXEMPT: u32 = 16;
/// How many destination ports may be redirected at once.
pub const REDIRECT_MAX_PORTS: u32 = 64;
/// How many connections may be waiting between `connect()` and the
/// listener's lookup. LRU: a connection nobody ever accepted ages out rather
/// than holding a slot.
pub const REDIRECT_MAX_PENDING: u32 = 65_536;

/// How many ancestors of the task's cgroup are tested after its own, which
/// is how a selection naming a pod slice covers every container under it.
pub const REDIRECT_ANCESTOR_LEVELS: u32 = 8;

/// Where redirected connections go. One entry, index 0.
///
/// The address must be one the workload can reach from its own network
/// namespace: a pod's loopback is the pod's, so a listener on the node is
/// named by the node's address rather than by `127.0.0.1`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedirectTarget {
    /// IPv4 listener address, the host-order value of the big-endian word.
    /// Zero leaves IPv4 connections alone.
    pub addr4: u32,
    /// IPv6 listener address, four host-order words. All zero leaves IPv6
    /// connections alone.
    pub addr6: [u32; 4],
    /// Listener port, host order. Zero disables the redirect entirely.
    pub port: u16,
    pub _pad: [u8; 2],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RedirectTarget {}

/// The address the listener sees a redirected connection come from.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct RedirectPeerKey {
    /// Source address. IPv4 sits in the first word, the rest zero; each word
    /// is the host-order value of the big-endian word.
    pub addr: [u32; 4],
    /// Source port, host order.
    pub port: u16,
    /// `REDIRECT_FAMILY_*`.
    pub family: u8,
    pub _pad: u8,
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RedirectPeerKey {}

/// Where a redirected connection was going, and who opened it.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RedirectOrigin {
    /// The cgroup of the task that called `connect()`.
    pub cgroup_id: u64,
    /// Destination address, in the encoding of [`RedirectPeerKey::addr`].
    pub addr: [u32; 4],
    /// Destination port, host order.
    pub port: u16,
    /// `REDIRECT_FAMILY_*`.
    pub family: u8,
    pub _pad: [u8; 5],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for RedirectOrigin {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn the_shared_layouts_carry_no_implicit_padding() {
        // The kernel and userspace halves are compiled apart and agree on
        // nothing but these offsets; a hole one side does not know about is
        // a lookup that never hits.
        assert_eq!(mem::size_of::<RedirectTarget>(), 24);
        assert_eq!(mem::offset_of!(RedirectTarget, addr6), 4);
        assert_eq!(mem::offset_of!(RedirectTarget, port), 20);

        assert_eq!(mem::size_of::<RedirectPeerKey>(), 20);
        assert_eq!(mem::offset_of!(RedirectPeerKey, port), 16);
        assert_eq!(mem::offset_of!(RedirectPeerKey, family), 18);

        assert_eq!(mem::size_of::<RedirectOrigin>(), 32);
        assert_eq!(mem::offset_of!(RedirectOrigin, addr), 8);
        assert_eq!(mem::offset_of!(RedirectOrigin, port), 24);
        assert_eq!(mem::offset_of!(RedirectOrigin, family), 26);
    }

    #[test]
    fn every_metric_slot_is_below_the_count() {
        for slot in [
            REDIRECT_METRIC_REDIRECTED,
            REDIRECT_METRIC_REFUSED,
            REDIRECT_METRIC_PORT_SKIPPED,
            REDIRECT_METRIC_PUBLISHED,
            REDIRECT_METRIC_PUBLISH_FAILED,
        ] {
            assert!(slot < REDIRECT_METRIC_COUNT);
        }
    }
}
