//! Which configured firewall rule a trace record's identifier names.
//!
//! The firewall installs each rule in one of three places: an exact
//! five-tuple goes to a hash map, a protocol and destination port to another,
//! and every other rule to an array scanned in priority order. The kernel
//! reports an array hit by its slot and a hash hit by which map answered, so
//! naming the rule takes what the loader did with each one: the slot it wrote,
//! or the key it inserted. A later rule with the same key overwrote an earlier
//! one in the map, and the index keeps the later one for the same reason.

use std::collections::HashMap;
use std::net::IpAddr;

use ebpf_common::firewall::FirewallRuleEntry;
use ebpf_common::trace::fast_path;

use crate::common::entity::RuleId;

/// Where the loader installed one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulePlacement {
    /// Slot of the array the datapath scans in priority order.
    Array(u32),
    /// The exact five-tuple map.
    Hash5Tuple,
    /// The protocol and destination port map.
    HashPort,
    /// Not installed: the array was full.
    NotInstalled,
}

/// The tuple a fast-path hit is looked up with: source, destination, source
/// port, destination port, protocol. Addresses are in the entry's host order.
type FiveTuple = (u32, u32, u16, u16, u8);

/// Names the rule behind a firewall trace record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirewallTraceIndex {
    v4_array: HashMap<u32, RuleId>,
    v6_array: HashMap<u32, RuleId>,
    five_tuple: HashMap<FiveTuple, RuleId>,
    port: HashMap<(u16, u8), RuleId>,
}

impl FirewallTraceIndex {
    /// Record where an IPv4 rule went, in the order the loader saw them.
    pub fn record_v4(&mut self, id: RuleId, entry: &FirewallRuleEntry, placement: RulePlacement) {
        match placement {
            RulePlacement::Array(slot) => {
                self.v4_array.insert(slot, id);
            }
            RulePlacement::Hash5Tuple => {
                self.five_tuple.insert(
                    (
                        entry.src_ip,
                        entry.dst_ip,
                        entry.src_port_start,
                        entry.dst_port_start,
                        entry.protocol,
                    ),
                    id,
                );
            }
            RulePlacement::HashPort => {
                self.port.insert((entry.dst_port_start, entry.protocol), id);
            }
            RulePlacement::NotInstalled => {}
        }
    }

    /// Record where an IPv6 rule went. Every IPv6 rule is in the array.
    pub fn record_v6(&mut self, id: RuleId, placement: RulePlacement) {
        if let RulePlacement::Array(slot) = placement {
            self.v6_array.insert(slot, id);
        }
    }

    /// The rule a firewall record's identifier names, for the packet that
    /// was traced.
    #[must_use]
    pub fn name(
        &self,
        rule_id: u32,
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Option<&RuleId> {
        match rule_id {
            fast_path::HASH_5TUPLE => match (src, dst) {
                (IpAddr::V4(src), IpAddr::V4(dst)) => self.five_tuple.get(&(
                    u32::from(src),
                    u32::from(dst),
                    src_port,
                    dst_port,
                    protocol,
                )),
                _ => None,
            },
            fast_path::HASH_PORT => self.port.get(&(dst_port, protocol)),
            slot if dst.is_ipv4() => self.v4_array.get(&slot),
            slot => self.v6_array.get(&slot),
        }
    }

    /// How many rules the index can name.
    #[must_use]
    pub fn len(&self) -> usize {
        self.v4_array.len() + self.v6_array.len() + self.five_tuple.len() + self.port.len()
    }

    /// Whether the index names no rule.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn entry(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, proto: u8) -> FirewallRuleEntry {
        FirewallRuleEntry {
            src_ip: u32::from(src),
            dst_ip: u32::from(dst),
            src_port_start: sport,
            src_port_end: sport,
            dst_port_start: dport,
            dst_port_end: dport,
            protocol: proto,
            src_mask: u32::MAX,
            dst_mask: u32::MAX,
            match_flags: 0,
            vlan_id: 0,
            action: 0,
            ct_state_mask: 0,
            src_set_id: 0,
            dst_set_id: 0,
            tcp_flags_match: 0,
            tcp_flags_mask: 0,
            icmp_type: 0xFF,
            icmp_code: 0xFF,
            match_flags2: 0,
            dscp_match: 0xFF,
            max_states: 0,
            src_mac: [0; 6],
            dst_mac: [0; 6],
            dscp_mark: 0xFF,
            _reserved: [0; 3],
            group_mask: 0,
            tenant_id: 0,
        }
    }

    fn id(name: &str) -> RuleId {
        RuleId(name.to_string())
    }

    const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    #[test]
    fn an_array_slot_is_named_by_the_family_of_the_packet() {
        let mut index = FirewallTraceIndex::default();
        index.record_v4(
            id("v4-rule"),
            &entry(A, B, 0, 0, 6),
            RulePlacement::Array(0),
        );
        index.record_v6(id("v6-rule"), RulePlacement::Array(0));
        let v4 = index.name(0, A.into(), B.into(), 1, 2, 6);
        assert_eq!(v4, Some(&id("v4-rule")));
        let v6 = index.name(
            0,
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            1,
            2,
            6,
        );
        assert_eq!(v6, Some(&id("v6-rule")));
        assert_eq!(index.name(1, A.into(), B.into(), 1, 2, 6), None);
    }

    #[test]
    fn a_fast_path_hit_is_named_by_the_traced_tuple() {
        let mut index = FirewallTraceIndex::default();
        index.record_v4(
            id("exact"),
            &entry(A, B, 40000, 443, 6),
            RulePlacement::Hash5Tuple,
        );
        index.record_v4(
            id("https"),
            &entry(A, B, 0, 443, 6),
            RulePlacement::HashPort,
        );
        assert_eq!(
            index.name(fast_path::HASH_5TUPLE, A.into(), B.into(), 40000, 443, 6),
            Some(&id("exact"))
        );
        assert_eq!(
            index.name(fast_path::HASH_5TUPLE, A.into(), B.into(), 40001, 443, 6),
            None
        );
        assert_eq!(
            index.name(fast_path::HASH_PORT, B.into(), A.into(), 9, 443, 6),
            Some(&id("https"))
        );
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn a_later_rule_on_the_same_key_is_the_one_named() {
        let mut index = FirewallTraceIndex::default();
        index.record_v4(id("first"), &entry(A, B, 0, 22, 6), RulePlacement::HashPort);
        index.record_v4(
            id("second"),
            &entry(A, B, 0, 22, 6),
            RulePlacement::HashPort,
        );
        assert_eq!(
            index.name(fast_path::HASH_PORT, A.into(), B.into(), 1, 22, 6),
            Some(&id("second"))
        );
    }

    #[test]
    fn a_rule_not_installed_names_nothing() {
        let mut index = FirewallTraceIndex::default();
        index.record_v4(
            id("lost"),
            &entry(A, B, 0, 0, 6),
            RulePlacement::NotInstalled,
        );
        index.record_v6(id("lost6"), RulePlacement::NotInstalled);
        assert!(index.is_empty());
    }
}
