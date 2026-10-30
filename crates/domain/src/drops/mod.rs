//! Why the kernel dropped packets, as counts a person can read.
//!
//! The kernel names the reason it frees a packet it did not deliver, and the
//! agent counts each drop under that name and the interface the packet was
//! on. This module turns those raw counts into a reading: one count per
//! reason and interface label, the reason described in plain language where
//! the agent knows it, and the share of drops the kernel side had no room to
//! count.
//!
//! Every label is bounded. A reason is a member of an enumeration the
//! running kernel defines, an interface is a device name of at most fifteen
//! bytes, and the kernel-side map holds a fixed number of pairs.

use std::collections::{BTreeMap, HashMap};

/// The label for a drop whose packet had neither a device nor an input
/// interface left to read.
pub const NO_INTERFACE: &str = "none";

/// One counter as the kernel side holds it, its reason already named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDrop {
    /// The reason as the running kernel names it, without its
    /// `SKB_DROP_REASON_` prefix, for instance `NO_SOCKET`.
    pub reason: String,
    /// The interface index, `0` when there was none.
    pub ifindex: u32,
    /// The device name read off the packet in the kernel, empty when the
    /// packet no longer had a device.
    pub name: String,
    /// Drops counted under this pair since the counter was loaded.
    pub packets: u64,
}

/// One count of a reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropCount {
    pub reason: String,
    pub interface: String,
    pub packets: u64,
}

/// What the counter holds right now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropReading {
    /// Counts sorted busiest first, ties by reason then interface.
    pub counts: Vec<DropCount>,
    /// Drops the kernel side saw but could not count under their pair,
    /// because the pair map was full.
    pub uncounted: u64,
}

/// The label a drop's interface is counted under.
///
/// The device name when the kernel could read one, which is the name the
/// device has in its own namespace. A packet freed after the stack let go of
/// its device carries only the index it arrived on, and that index means
/// something in the namespace it arrived in rather than in the agent's, so
/// it is labelled `if<index>` rather than resolved to a name that may be
/// another device's.
#[must_use]
pub fn interface_label(name: &str, ifindex: u32) -> String {
    if !name.is_empty() {
        name.to_owned()
    } else if ifindex == 0 {
        NO_INTERFACE.to_owned()
    } else {
        format!("if{ifindex}")
    }
}

impl DropReading {
    /// Fold the raw counters into a reading. Two counters that land on one
    /// label - the same device name in two namespaces - add up, and a pair
    /// whose slots all read zero says nothing and is left out.
    #[must_use]
    pub fn from_raw(raw: &[RawDrop], uncounted: u64) -> Self {
        let mut folded: BTreeMap<(String, String), u64> = BTreeMap::new();
        for drop in raw.iter().filter(|drop| drop.packets > 0) {
            let slot = folded
                .entry((
                    drop.reason.clone(),
                    interface_label(&drop.name, drop.ifindex),
                ))
                .or_default();
            *slot = slot.saturating_add(drop.packets);
        }
        let mut counts: Vec<DropCount> = folded
            .into_iter()
            .map(|((reason, interface), packets)| DropCount {
                reason,
                interface,
                packets,
            })
            .collect();
        counts.sort_by(|a, b| {
            b.packets
                .cmp(&a.packets)
                .then_with(|| a.reason.cmp(&b.reason))
                .then_with(|| a.interface.cmp(&b.interface))
        });
        Self { counts, uncounted }
    }

    /// Total drops counted under a pair.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts
            .iter()
            .fold(0_u64, |sum, c| sum.saturating_add(c.packets))
    }
}

/// What has been added to each count since the last reading, so a counter
/// fed from it follows the kernel's counts rather than the poll cadence.
#[derive(Debug, Default)]
pub struct DropDeltas {
    last: HashMap<(String, String), u64>,
    last_uncounted: u64,
}

/// What one reading added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DropIncrements {
    /// `(reason, interface, added)` for every pair that moved.
    pub counts: Vec<(String, String, u64)>,
    pub uncounted: u64,
}

impl DropDeltas {
    /// The increments `reading` carries over the previous one.
    ///
    /// The kernel side never evicts a pair, so a count only goes down when
    /// the counter itself was loaded again; the new count is then all new.
    pub fn advance(&mut self, reading: &DropReading) -> DropIncrements {
        let mut counts = Vec::new();
        for count in &reading.counts {
            let key = (count.reason.clone(), count.interface.clone());
            let before = self.last.insert(key, count.packets).unwrap_or(0);
            let added = if count.packets >= before {
                count.packets - before
            } else {
                count.packets
            };
            if added > 0 {
                counts.push((count.reason.clone(), count.interface.clone(), added));
            }
        }
        let uncounted = if reading.uncounted >= self.last_uncounted {
            reading.uncounted - self.last_uncounted
        } else {
            reading.uncounted
        };
        self.last_uncounted = reading.uncounted;
        DropIncrements { counts, uncounted }
    }
}

/// The reasons the agent describes in plain language, as the kernel names
/// them. A reason the running kernel adds after these is still counted under
/// its own name; it is only not described.
pub const DESCRIBED_REASONS: &[(&str, &str)] = &[
    (
        "NOT_SPECIFIED",
        "Freed without a reason: the path that dropped it was not annotated.",
    ),
    (
        "NO_SOCKET",
        "Nothing listens on the destination port, or the socket closed before the packet arrived.",
    ),
    (
        "SOCKET_CLOSE",
        "The socket was closed with data still queued on it.",
    ),
    (
        "SOCKET_FILTER",
        "A socket filter (classic BPF, for instance a capture filter) refused the packet.",
    ),
    (
        "SOCKET_RCVBUFF",
        "The receiving socket's buffer was full: the application is reading too slowly.",
    ),
    (
        "SOCKET_BACKLOG",
        "The socket's backlog was full while the application held the socket.",
    ),
    (
        "PROTO_MEM",
        "The protocol's global memory limit was reached (net.ipv4.tcp_mem or udp_mem).",
    ),
    (
        "PKT_TOO_SMALL",
        "The packet is shorter than its own headers say.",
    ),
    (
        "PKT_TOO_BIG",
        "The packet is larger than the path or the device accepts.",
    ),
    ("HDR_TRUNC", "A header is cut short."),
    (
        "OTHERHOST",
        "The packet is addressed to another host's hardware address.",
    ),
    ("IP_CSUM", "The IPv4 header checksum is wrong."),
    (
        "IP_INHDR",
        "The IP header is malformed: bad version, length or options.",
    ),
    (
        "IP_RPFILTER",
        "Reverse path filtering refused it: the source is not routed back through this interface.",
    ),
    (
        "IP_NOPROTO",
        "No handler is registered for the IP protocol the packet carries.",
    ),
    (
        "IP_INADDRERRORS",
        "The destination address is not valid for this host.",
    ),
    (
        "IP_INNOROUTES",
        "No route matches the destination of an incoming packet.",
    ),
    (
        "IP_OUTNOROUTES",
        "No route matches the destination of an outgoing packet.",
    ),
    (
        "IP_TUNNEL_ECN",
        "A tunnelled packet carries an ECN marking that cannot be decapsulated.",
    ),
    (
        "UNICAST_IN_L2_MULTICAST",
        "A unicast IP packet arrived in a link-layer multicast or broadcast frame.",
    ),
    (
        "IPV6DISABLED",
        "IPv6 is disabled on the interface the packet arrived on.",
    ),
    ("IPV6_BAD_EXTHDR", "An IPv6 extension header is malformed."),
    ("TCP_CSUM", "The TCP checksum is wrong."),
    ("UDP_CSUM", "The UDP checksum is wrong."),
    ("ICMP_CSUM", "The ICMP checksum is wrong."),
    (
        "TCP_FLAGS",
        "The TCP flags make no sense for the connection's state.",
    ),
    (
        "TCP_ZEROWINDOW",
        "The receiver advertised a zero window and the sender sent anyway.",
    ),
    (
        "TCP_OLD_DATA",
        "The segment carries data that was already received.",
    ),
    (
        "TCP_OVERWINDOW",
        "The segment lies beyond the receive window.",
    ),
    ("TCP_OFOMERGE", "An out-of-order segment was already held."),
    (
        "TCP_RFC7323_PAWS",
        "The timestamp is older than the last one seen (protection against wrapped sequences).",
    ),
    (
        "TCP_INVALID_SEQUENCE",
        "The sequence number is outside what the connection accepts.",
    ),
    (
        "TCP_INVALID_ACK_SEQUENCE",
        "The acknowledgement number is outside what the connection accepts.",
    ),
    (
        "TCP_OLD_ACK",
        "The acknowledgement covers data acknowledged already.",
    ),
    (
        "TCP_TOO_OLD_ACK",
        "The acknowledgement is too old to be meaningful.",
    ),
    (
        "TCP_ACK_UNSENT_DATA",
        "The peer acknowledges data that was never sent.",
    ),
    (
        "TCP_RESET",
        "The segment is a reset, and the connection is torn down.",
    ),
    (
        "TCP_INVALID_SYN",
        "A SYN arrived on a connection that does not accept one.",
    ),
    (
        "TCP_CLOSE",
        "The connection is closed and takes no more data.",
    ),
    ("TCP_FASTOPEN", "A TCP Fast Open cookie was refused."),
    (
        "TCP_OFO_QUEUE_PRUNE",
        "Out-of-order segments were pruned to free memory.",
    ),
    (
        "TCP_OFO_DROP",
        "An out-of-order segment was dropped for lack of room.",
    ),
    (
        "TCP_MINTTL",
        "The TTL is below the minimum the socket requires.",
    ),
    (
        "TCP_MD5NOTFOUND",
        "The segment lacks the TCP MD5 signature the socket requires.",
    ),
    (
        "TCP_MD5UNEXPECTED",
        "The segment carries a TCP MD5 signature the socket does not expect.",
    ),
    ("TCP_MD5FAILURE", "The TCP MD5 signature does not verify."),
    (
        "NETFILTER_DROP",
        "A netfilter rule (iptables or nftables) dropped it.",
    ),
    (
        "BPF_CGROUP_EGRESS",
        "A cgroup eBPF program refused an outgoing packet.",
    ),
    (
        "SECURITY_HOOK",
        "A security module (SELinux, AppArmor, a BPF LSM) refused it.",
    ),
    ("XFRM_POLICY", "An IPsec policy refused it."),
    (
        "XDP",
        "An XDP program dropped it, or an XDP redirect failed.",
    ),
    (
        "TC_INGRESS",
        "A traffic-control program or filter dropped it on the way in.",
    ),
    (
        "TC_EGRESS",
        "A traffic-control program or filter dropped it on the way out.",
    ),
    (
        "QDISC_DROP",
        "The queueing discipline dropped it: an egress queue is full or a shaper limits it.",
    ),
    (
        "CPU_BACKLOG",
        "The per-CPU input backlog was full (net.core.netdev_max_backlog).",
    ),
    ("FULL_RING", "The device's ring was full."),
    ("NOMEM", "Memory could not be allocated for the packet."),
    (
        "DEV_HDR",
        "The device could not build the link-layer header.",
    ),
    ("DEV_READY", "The device is down or not ready to transmit."),
    (
        "UNHANDLED_PROTO",
        "No handler is registered for the link-layer protocol.",
    ),
    (
        "NEIGH_CREATEFAIL",
        "No neighbour entry could be created for the next hop.",
    ),
    (
        "NEIGH_FAILED",
        "The next hop's hardware address could not be resolved (ARP or neighbour discovery failed).",
    ),
    (
        "NEIGH_QUEUEFULL",
        "Too many packets wait for the next hop's address to resolve.",
    ),
    (
        "NEIGH_DEAD",
        "The neighbour entry was removed while packets waited on it.",
    ),
    ("SKB_CSUM", "The checksum could not be computed."),
    ("SKB_GSO_SEG", "A large packet could not be segmented."),
    (
        "SKB_UCOPY_FAULT",
        "Copying the payload from the application faulted.",
    ),
    ("TAP_FILTER", "A tap device's filter refused it."),
    ("TAP_TXFILTER", "A tap device's transmit filter refused it."),
    (
        "INVALID_PROTO",
        "The protocol field is not one this path handles.",
    ),
    ("DUP_FRAG", "A fragment was received twice."),
    (
        "FRAG_REASM_TIMEOUT",
        "Fragments did not all arrive before reassembly timed out.",
    ),
    (
        "FRAG_TOO_FAR",
        "A fragment arrived too far out of order to be kept.",
    ),
    (
        "QUEUE_PURGE",
        "A queue was purged, for instance when a device or socket went away.",
    ),
    (
        "TC_CHAIN_NOTFOUND",
        "A traffic-control action jumped to a chain that does not exist.",
    ),
    (
        "TC_RECLASSIFY_LOOP",
        "A traffic-control reclassification looped.",
    ),
    ("VXLAN_INVALID_HDR", "The VXLAN header is malformed."),
    (
        "VXLAN_VNI_NOT_FOUND",
        "No VXLAN device is configured for the packet's VNI.",
    ),
    (
        "MAC_INVALID_SOURCE",
        "The source hardware address is invalid.",
    ),
    (
        "MAC_IS_MULTICAST",
        "The source hardware address is a multicast address.",
    ),
    (
        "LOCAL_MAC",
        "The source hardware address is the receiving device's own.",
    ),
];

/// The plain-language description of a reason, `None` when the agent does
/// not describe it.
#[must_use]
pub fn describe(reason: &str) -> Option<&'static str> {
    DESCRIBED_REASONS
        .iter()
        .find(|(name, _)| *name == reason)
        .map(|(_, text)| *text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(reason: &str, ifindex: u32, name: &str, packets: u64) -> RawDrop {
        RawDrop {
            reason: reason.to_owned(),
            ifindex,
            name: name.to_owned(),
            packets,
        }
    }

    #[test]
    fn an_interface_is_labelled_by_its_name_then_its_index() {
        assert_eq!(interface_label("eth0", 2), "eth0");
        assert_eq!(interface_label("", 7), "if7");
        assert_eq!(interface_label("", 0), NO_INTERFACE);
    }

    #[test]
    fn a_pair_with_no_packets_is_left_out() {
        let reading = DropReading::from_raw(
            &[
                raw("NO_SOCKET", 2, "eth0", 5),
                raw("NOT_SPECIFIED", 0, "", 0),
            ],
            0,
        );
        assert_eq!(reading.counts.len(), 1);
        assert_eq!(reading.total(), 5);
    }

    #[test]
    fn a_reading_folds_one_label_and_ranks_busiest_first() {
        let reading = DropReading::from_raw(
            &[
                raw("NO_SOCKET", 2, "eth0", 3),
                raw("NO_SOCKET", 9, "eth0", 4),
                raw("TCP_CSUM", 0, "", 10),
                raw("NETFILTER_DROP", 5, "", 1),
            ],
            2,
        );
        let flat: Vec<(&str, &str, u64)> = reading
            .counts
            .iter()
            .map(|c| (c.reason.as_str(), c.interface.as_str(), c.packets))
            .collect();
        assert_eq!(
            flat,
            vec![
                ("TCP_CSUM", "none", 10),
                ("NO_SOCKET", "eth0", 7),
                ("NETFILTER_DROP", "if5", 1),
            ]
        );
        assert_eq!(reading.total(), 18);
        assert_eq!(reading.uncounted, 2);
    }

    #[test]
    fn increments_follow_the_kernel_counts_and_survive_a_reload() {
        let mut deltas = DropDeltas::default();
        let first = DropReading::from_raw(&[raw("NO_SOCKET", 2, "eth0", 5)], 1);
        assert_eq!(
            deltas.advance(&first),
            DropIncrements {
                counts: vec![("NO_SOCKET".into(), "eth0".into(), 5)],
                uncounted: 1,
            }
        );
        let same = deltas.advance(&first);
        assert!(same.counts.is_empty());
        assert_eq!(same.uncounted, 0);
        let reloaded = DropReading::from_raw(&[raw("NO_SOCKET", 2, "eth0", 2)], 0);
        assert_eq!(
            deltas.advance(&reloaded).counts,
            vec![("NO_SOCKET".into(), "eth0".into(), 2)]
        );
    }

    #[test]
    fn every_described_reason_is_named_once_and_described() {
        let mut names: Vec<&str> = DESCRIBED_REASONS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before);
        assert!(
            DESCRIBED_REASONS
                .iter()
                .all(|(_, text)| text.ends_with('.'))
        );
        assert!(describe("NO_SOCKET").is_some());
        assert_eq!(describe("SOMETHING_NEW"), None);
    }
}
