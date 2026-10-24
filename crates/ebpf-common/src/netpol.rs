//! A Kubernetes `NetworkPolicy`, as the cgroup hooks enforce it.
//!
//! Userspace compiles every policy selecting a pod on this node into one
//! longest-prefix table per distinct rule set, called a slot, and tells the
//! kernel which slot each of the pod's cgroups answers to. The hooks then do
//! one trie lookup per new connection: the longest prefix holding the peer
//! address says which ports are open to it, and an address no prefix holds is
//! closed. The except clauses of an `ipBlock` are prefixes of their own in the
//! same table, carrying what remains open inside them, so the longest match is
//! always the exact answer and the kernel never walks a rule.

/// How many port ranges one prefix can carry.
///
/// A rule set naming more distinct ranges for one peer than this has the
/// extra ones dropped, which closes them, and the drop is reported by name
/// rather than discovered.
pub const NETPOL_MAX_RANGES: usize = 16;

/// How many prefixes the table holds across every slot of the node.
pub const NETPOL_MAX_ENTRIES: u32 = 65_536;

/// How many distinct rule sets the node can hold. Pods selected by the same
/// policies with the same ports share one.
pub const NETPOL_MAX_SLOTS: u32 = 4_096;

/// How many cgroups the slot map can name, one per container of a selected
/// pod.
pub const NETPOL_MAX_CGROUPS: u32 = 8_192;

/// How many UDP exchanges an ingress-isolated pod started can have their
/// replies admitted at once.
pub const NETPOL_MAX_REPLIES: u32 = 65_536;

/// How long a datagram a pod sent opens the way back for the answer, in
/// nanoseconds. Refreshed by every datagram the pod sends on that pair.
pub const NETPOL_REPLY_WINDOW_NS: u64 = 120_000_000_000;

/// The cgroup is selected by a policy governing its ingress.
pub const NETPOL_FLAG_INGRESS_ISOLATED: u8 = 1;
/// The cgroup is selected by a policy governing its egress.
pub const NETPOL_FLAG_EGRESS_ISOLATED: u8 = 1 << 1;
/// A refusal is carried out rather than counted.
pub const NETPOL_FLAG_ENFORCE: u8 = 1 << 2;

/// The direction bit of a key.
pub const NETPOL_DIR_INGRESS: u32 = 0;
pub const NETPOL_DIR_EGRESS: u32 = 1;

/// Bytes of a key's data: one word naming the slot, the family and the
/// direction, then sixteen address bytes, an IPv4 address in the first four.
pub const NETPOL_KEY_LEN: usize = 20;

/// The first word of a key, always matched in full.
pub const fn netpol_key_word(slot: u16, v6: bool, direction: u32) -> u32 {
    ((slot as u32) << 2) | ((v6 as u32) << 1) | (direction & 1)
}

/// A key's data, network order throughout so the trie compares the slot word
/// first and the address bits from the top.
pub const fn netpol_key_data(word: u32, addr: [u8; 16]) -> [u8; NETPOL_KEY_LEN] {
    let w = word.to_be_bytes();
    let mut data = [0u8; NETPOL_KEY_LEN];
    data[0] = w[0];
    data[1] = w[1];
    data[2] = w[2];
    data[3] = w[3];
    let mut index = 0;
    while index < 16 {
        data[4 + index] = addr[index];
        index += 1;
    }
    data
}

/// The trie's prefix length for an address prefix of `bits`: the slot word is
/// always matched whole.
pub const fn netpol_prefix_len(bits: u8) -> u32 {
    32 + bits as u32
}

/// What a cgroup of a selected pod answers to.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetpolCgroup {
    pub slot: u16,
    /// `NETPOL_FLAG_*`.
    pub flags: u8,
    pub _pad: [u8; 5],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NetpolCgroup {}

/// One open range of ports, inclusive.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetpolPortRange {
    /// IP protocol number.
    pub protocol: u8,
    pub _pad: u8,
    pub lo: u16,
    pub hi: u16,
}

/// What a prefix opens: every port, or up to `NETPOL_MAX_RANGES` ranges.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetpolEntry {
    /// Ranges in use, from the first.
    pub count: u8,
    /// Non-zero when every port of every protocol is open.
    pub all: u8,
    pub ranges: [NetpolPortRange; NETPOL_MAX_RANGES],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NetpolEntry {}

/// A UDP exchange an ingress-isolated pod started, whose replies are let in.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetpolReplyKey {
    pub cgroup_id: u64,
    /// The peer, network order, an IPv4 address in the first four bytes.
    pub addr: [u8; 16],
    /// The peer's port, host order.
    pub port: u16,
    /// 0 for IPv4, 1 for IPv6.
    pub family: u8,
    pub _pad: [u8; 5],
}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NetpolReplyKey {}

// ── Metrics ─────────────────────────────────────────────────────────

/// New outbound connections and datagrams a policy was consulted for.
pub const NETPOL_METRIC_EGRESS_CHECKED: u32 = 0;
/// Refused outbound.
pub const NETPOL_METRIC_EGRESS_REFUSED: u32 = 1;
/// Outbound that enforcement would have refused.
pub const NETPOL_METRIC_EGRESS_WOULD_REFUSE: u32 = 2;
/// New inbound connections and datagrams a policy was consulted for.
pub const NETPOL_METRIC_INGRESS_CHECKED: u32 = 3;
/// Refused inbound.
pub const NETPOL_METRIC_INGRESS_REFUSED: u32 = 4;
/// Inbound that enforcement would have refused.
pub const NETPOL_METRIC_INGRESS_WOULD_REFUSE: u32 = 5;
/// Inbound datagrams let in as replies to one the pod sent.
pub const NETPOL_METRIC_REPLY_ADMITTED: u32 = 6;
/// Slots in the metrics array.
pub const NETPOL_METRIC_COUNT: u32 = 7;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn the_shared_records_are_the_size_both_sides_compiled_against() {
        assert_eq!(size_of::<NetpolCgroup>(), 8);
        assert_eq!(size_of::<NetpolPortRange>(), 6);
        assert_eq!(size_of::<NetpolEntry>(), 2 + 6 * NETPOL_MAX_RANGES);
        assert_eq!(size_of::<NetpolReplyKey>(), 32);
    }

    #[test]
    fn a_key_word_keeps_slot_family_and_direction_apart() {
        assert_eq!(netpol_key_word(0, false, NETPOL_DIR_INGRESS), 0);
        assert_eq!(netpol_key_word(0, false, NETPOL_DIR_EGRESS), 1);
        assert_eq!(netpol_key_word(0, true, NETPOL_DIR_INGRESS), 2);
        assert_eq!(netpol_key_word(3, true, NETPOL_DIR_EGRESS), 15);
        assert_eq!(
            netpol_key_word(u16::MAX, true, NETPOL_DIR_EGRESS) >> 2,
            u32::from(u16::MAX)
        );
    }

    #[test]
    fn a_key_is_the_word_then_the_address_in_network_order() {
        let mut addr = [0u8; 16];
        addr[..4].copy_from_slice(&[10, 0, 0, 1]);
        let data = netpol_key_data(netpol_key_word(1, false, NETPOL_DIR_EGRESS), addr);
        assert_eq!(&data[..4], &[0, 0, 0, 5]);
        assert_eq!(&data[4..8], &[10, 0, 0, 1]);
        assert_eq!(netpol_prefix_len(24), 56);
    }

    #[test]
    fn every_slot_fits_the_word_and_every_metric_is_distinct() {
        assert!(NETPOL_MAX_SLOTS <= u32::from(u16::MAX) + 1);
        let metrics = [
            NETPOL_METRIC_EGRESS_CHECKED,
            NETPOL_METRIC_EGRESS_REFUSED,
            NETPOL_METRIC_EGRESS_WOULD_REFUSE,
            NETPOL_METRIC_INGRESS_CHECKED,
            NETPOL_METRIC_INGRESS_REFUSED,
            NETPOL_METRIC_INGRESS_WOULD_REFUSE,
            NETPOL_METRIC_REPLY_ADMITTED,
        ];
        for (index, metric) in metrics.iter().enumerate() {
            assert_eq!(*metric as usize, index);
        }
        assert_eq!(metrics.len(), NETPOL_METRIC_COUNT as usize);
    }
}
