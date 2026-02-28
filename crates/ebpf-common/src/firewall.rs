/// Firewall action constants — used in `FirewallRuleEntry.action`
pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;
pub const ACTION_LOG: u8 = 2;

/// Maximum number of firewall rules per address family (V4 / V6).
///
/// Requires kernel 5.17+ (`bpf_loop` helper) for the XDP firewall to iterate
/// over this many rules without hitting verifier complexity limits.
pub const MAX_FIREWALL_RULES: u32 = 4096;

/// Default policy constants for `FIREWALL_DEFAULT_POLICY` map.
pub const DEFAULT_POLICY_PASS: u8 = 0;
pub const DEFAULT_POLICY_DROP: u8 = 1;

/// Maximum LPM Trie entries per map (4 maps: src/dst × v4/v6).
pub const MAX_LPM_RULES: u32 = 4096;

/// Match-flag bitmask: which fields of a rule are active (non-wildcard).
pub const MATCH_SRC_IP: u8 = 0x01;
pub const MATCH_DST_IP: u8 = 0x02;
pub const MATCH_SRC_PORT: u8 = 0x04;
pub const MATCH_DST_PORT: u8 = 0x08;
pub const MATCH_PROTO: u8 = 0x10;
/// Match on conntrack state (ct_state_mask field).
pub const MATCH_CT_STATE: u8 = 0x20;
/// Match source IP against an IP set (src_set_id field).
pub const MATCH_SRC_SET: u8 = 0x40;
/// Match destination IP against an IP set (dst_set_id field).
pub const MATCH_DST_SET: u8 = 0x80;

// ── Extended match flags (match_flags2) ─────────────────────────────

/// Match TCP flags (tcp_flags_match/tcp_flags_mask fields).
pub const MATCH2_TCP_FLAGS: u8 = 0x01;
/// Match ICMP type (icmp_type field).
pub const MATCH2_ICMP_TYPE: u8 = 0x02;
/// Match ICMP code (icmp_code field).
pub const MATCH2_ICMP_CODE: u8 = 0x04;
/// Negate source IP match (match if CIDR does NOT match).
pub const MATCH2_NEGATE_SRC: u8 = 0x08;
/// Negate destination IP match (match if CIDR does NOT match).
pub const MATCH2_NEGATE_DST: u8 = 0x10;
/// Match DSCP value (dscp_match field).
pub const MATCH2_DSCP: u8 = 0x20;
/// Match source MAC address (src_mac field).
pub const MATCH2_SRC_MAC: u8 = 0x40;
/// Match destination MAC address (dst_mac field).
pub const MATCH2_DST_MAC: u8 = 0x80;

/// Wildcard value for ICMP type/code: skip comparison.
pub const ICMP_WILDCARD: u8 = 0xFF;

// ── Route action constants (Epic 29) ────────────────────────────────

/// No routing action (normal pass/drop/log behaviour).
pub const ROUTE_ACTION_NONE: u8 = 0;
/// Force route to a specific gateway/interface.
pub const ROUTE_ACTION_ROUTE_TO: u8 = 1;
/// Store ingress interface in conntrack for reply routing.
pub const ROUTE_ACTION_REPLY_TO: u8 = 2;
/// Mirror packet to another interface.
pub const ROUTE_ACTION_DUP_TO: u8 = 3;

// ── Conntrack state match bitmask (for ct_state_mask field) ─────────

/// Bitmask: match packets in NEW state.
pub const CT_MATCH_NEW: u8 = 0x01;
/// Bitmask: match packets in ESTABLISHED state.
pub const CT_MATCH_ESTABLISHED: u8 = 0x02;
/// Bitmask: match packets in RELATED state.
pub const CT_MATCH_RELATED: u8 = 0x04;
/// Bitmask: match packets in INVALID state.
pub const CT_MATCH_INVALID: u8 = 0x08;

// ── IP/Port set types ───────────────────────────────────────────────

/// Maximum entries per IP set HashMap.
pub const MAX_IPSET_ENTRIES_V4: u32 = 65_536;
pub const MAX_IPSET_ENTRIES_V6: u32 = 16_384;
pub const MAX_PORTSET_ENTRIES: u32 = 8_192;

/// Key for IPv4 IP set lookup (set_id + address).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSetKeyV4 {
    pub set_id: u16,
    pub _pad: [u8; 2],
    pub addr: u32,
}

/// Key for IPv6 IP set lookup (set_id + address).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpSetKeyV6 {
    pub set_id: u16,
    pub _pad: [u8; 2],
    pub addr: [u32; 4],
}

/// Key for port set lookup (set_id + port).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortSetKey {
    pub set_id: u16,
    pub port: u16,
}

/// Array-based IPv4 firewall rule entry (56 bytes).
///
/// Stored in the `FIREWALL_RULES` `Array` map, indexed 0..count.
/// Each field that is a wildcard has its corresponding `MATCH_*` flag unset
/// in `match_flags`, so the XDP program skips that comparison.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallRuleEntry {
    /// Source IPv4 address pre-masked (host byte order). 0 if wildcard.
    pub src_ip: u32,
    /// CIDR mask for source (e.g. `0xFFFF_FF00` for /24, 0 for wildcard).
    pub src_mask: u32,
    /// Destination IPv4 address pre-masked (host byte order). 0 if wildcard.
    pub dst_ip: u32,
    /// CIDR mask for destination.
    pub dst_mask: u32,
    /// Source port range start (0 if wildcard).
    pub src_port_start: u16,
    /// Source port range end.
    pub src_port_end: u16,
    /// Destination port range start (0 if wildcard).
    pub dst_port_start: u16,
    /// Destination port range end.
    pub dst_port_end: u16,
    /// IP protocol number (6=TCP, 17=UDP, 0=any).
    pub protocol: u8,
    /// Bitmask of active `MATCH_*` flags.
    pub match_flags: u8,
    /// 802.1Q VLAN ID filter (0 = match any, 1-4094 = exact).
    pub vlan_id: u16,
    /// Action: `ACTION_PASS`, `ACTION_DROP`, or `ACTION_LOG`.
    pub action: u8,
    /// Bitmask of allowed conntrack states (CT_MATCH_*). 0 = ignore state.
    pub ct_state_mask: u8,
    /// IP set ID for source matching (used with MATCH_SRC_SET).
    pub src_set_id: u8,
    /// IP set ID for destination matching (used with MATCH_DST_SET).
    pub dst_set_id: u8,
    // ── Extended fields (Epic 24+) ──────────────────────────────────
    /// TCP flags that must be SET for a match (e.g. SYN=0x02).
    pub tcp_flags_match: u8,
    /// Which TCP flag bits to inspect (e.g. SYN+ACK mask=0x12).
    pub tcp_flags_mask: u8,
    /// ICMP type to match (0xFF = wildcard).
    pub icmp_type: u8,
    /// ICMP code to match (0xFF = wildcard).
    pub icmp_code: u8,
    /// Extended match flags (`MATCH2_*` constants).
    pub match_flags2: u8,
    /// DSCP value to match (0-63, 0xFF = wildcard). Used with `MATCH2_DSCP`.
    pub dscp_match: u8,
    /// Maximum states allowed for this rule (0 = unlimited).
    pub max_states: u16,
    /// Source MAC address for L2 matching (all zeros = wildcard).
    pub src_mac: [u8; 6],
    /// Destination MAC address for L2 matching (all zeros = wildcard).
    pub dst_mac: [u8; 6],
    /// DSCP value to mark on matched packets (0xFF = no marking).
    pub dscp_mark: u8,
    /// Routing action (`ROUTE_ACTION_*`): 0=none, 1=route-to, 2=reply-to, 3=dup-to.
    pub route_action: u8,
    /// Target interface index for route-to / dup-to (0 = none).
    pub route_ifindex: u16,
}

/// Array-based IPv6 firewall rule entry (104 bytes).
///
/// Same semantics as `FirewallRuleEntry` but with 128-bit addresses
/// stored as `[u32; 4]` in network byte order.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallRuleEntryV6 {
    /// Source IPv6 address pre-masked, as `[u32; 4]` in network byte order.
    pub src_addr: [u32; 4],
    /// Source CIDR mask as `[u32; 4]`.
    pub src_mask: [u32; 4],
    /// Destination IPv6 address pre-masked, as `[u32; 4]` in network byte order.
    pub dst_addr: [u32; 4],
    /// Destination CIDR mask as `[u32; 4]`.
    pub dst_mask: [u32; 4],
    /// Source port range start (0 if wildcard).
    pub src_port_start: u16,
    /// Source port range end.
    pub src_port_end: u16,
    /// Destination port range start (0 if wildcard).
    pub dst_port_start: u16,
    /// Destination port range end.
    pub dst_port_end: u16,
    /// IP protocol number (6=TCP, 17=UDP, 0=any).
    pub protocol: u8,
    /// Bitmask of active `MATCH_*` flags.
    pub match_flags: u8,
    /// 802.1Q VLAN ID filter (0 = match any, 1-4094 = exact).
    pub vlan_id: u16,
    /// Action: `ACTION_PASS`, `ACTION_DROP`, or `ACTION_LOG`.
    pub action: u8,
    /// Bitmask of allowed conntrack states (CT_MATCH_*). 0 = ignore state.
    pub ct_state_mask: u8,
    /// IP set ID for source matching (used with MATCH_SRC_SET).
    pub src_set_id: u8,
    /// IP set ID for destination matching (used with MATCH_DST_SET).
    pub dst_set_id: u8,
    // ── Extended fields (Epic 24+) ──────────────────────────────────
    /// TCP flags that must be SET for a match (e.g. SYN=0x02).
    pub tcp_flags_match: u8,
    /// Which TCP flag bits to inspect (e.g. SYN+ACK mask=0x12).
    pub tcp_flags_mask: u8,
    /// ICMP type to match (0xFF = wildcard).
    pub icmp_type: u8,
    /// ICMP code to match (0xFF = wildcard).
    pub icmp_code: u8,
    /// Extended match flags (`MATCH2_*` constants).
    pub match_flags2: u8,
    /// DSCP value to match (0-63, 0xFF = wildcard). Used with `MATCH2_DSCP`.
    pub dscp_match: u8,
    /// Maximum states allowed for this rule (0 = unlimited).
    pub max_states: u16,
    /// Source MAC address for L2 matching (all zeros = wildcard).
    pub src_mac: [u8; 6],
    /// Destination MAC address for L2 matching (all zeros = wildcard).
    pub dst_mac: [u8; 6],
    /// DSCP value to mark on matched packets (0xFF = no marking).
    pub dscp_mark: u8,
    /// Routing action (`ROUTE_ACTION_*`): 0=none, 1=route-to, 2=reply-to, 3=dup-to.
    pub route_action: u8,
    /// Target interface index for route-to / dup-to (0 = none).
    pub route_ifindex: u16,
}

/// Value stored in firewall LPM Trie maps (action only, 4 bytes).
///
/// Used as the value type in `FW_LPM_SRC_V4`, `FW_LPM_DST_V4`,
/// `FW_LPM_SRC_V6`, `FW_LPM_DST_V6` maps.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LpmValue {
    /// Action: `ACTION_PASS`, `ACTION_DROP`, or `ACTION_LOG`.
    pub action: u8,
    /// Padding to 4 bytes.
    pub _padding: [u8; 3],
}

/// IPv4 CIDR rule for LPM Trie-based firewall lookup.
///
/// Used in the port trait to pass CIDR-only rules from domain to adapter.
/// The adapter converts these to `Key<[u8; 4]>` + `LpmValue` for the eBPF map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallLpmEntryV4 {
    /// CIDR prefix length (0-32).
    pub prefix_len: u32,
    /// IPv4 address in network byte order, pre-masked to prefix.
    pub addr: [u8; 4],
    /// Action: `ACTION_PASS`, `ACTION_DROP`, or `ACTION_LOG`.
    pub action: u8,
}

/// IPv6 CIDR rule for LPM Trie-based firewall lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FirewallLpmEntryV6 {
    /// CIDR prefix length (0-128).
    pub prefix_len: u32,
    /// IPv6 address in network byte order, pre-masked to prefix.
    pub addr: [u8; 16],
    /// Action: `ACTION_PASS`, `ACTION_DROP`, or `ACTION_LOG`.
    pub action: u8,
}

// SAFETY: All types are #[repr(C)], Copy, 'static, and contain only primitive types
// with explicit padding. Safe for zero-copy eBPF map operations via aya.
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FirewallRuleEntry {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for FirewallRuleEntryV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for LpmValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IpSetKeyV4 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for IpSetKeyV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for PortSetKey {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // ── FirewallRuleEntry (V4) ──────────────────────────────────────

    #[test]
    fn test_firewall_rule_entry_size() {
        assert_eq!(mem::size_of::<FirewallRuleEntry>(), 56);
    }

    #[test]
    fn test_firewall_rule_entry_alignment() {
        assert_eq!(mem::align_of::<FirewallRuleEntry>(), 4);
    }

    #[test]
    fn test_firewall_rule_entry_field_offsets() {
        assert_eq!(mem::offset_of!(FirewallRuleEntry, src_ip), 0);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, src_mask), 4);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dst_ip), 8);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dst_mask), 12);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, src_port_start), 16);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, src_port_end), 18);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dst_port_start), 20);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dst_port_end), 22);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, protocol), 24);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, match_flags), 25);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, vlan_id), 26);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, action), 28);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, ct_state_mask), 29);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, src_set_id), 30);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dst_set_id), 31);
        // Extended fields
        assert_eq!(mem::offset_of!(FirewallRuleEntry, tcp_flags_match), 32);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, tcp_flags_mask), 33);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, icmp_type), 34);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, icmp_code), 35);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, match_flags2), 36);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dscp_match), 37);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, max_states), 38);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, src_mac), 40);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dst_mac), 46);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, dscp_mark), 52);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, route_action), 53);
        assert_eq!(mem::offset_of!(FirewallRuleEntry, route_ifindex), 54);
    }

    // ── FirewallRuleEntryV6 ─────────────────────────────────────────

    #[test]
    fn test_firewall_rule_entry_v6_size() {
        assert_eq!(mem::size_of::<FirewallRuleEntryV6>(), 104);
    }

    #[test]
    fn test_firewall_rule_entry_v6_alignment() {
        assert_eq!(mem::align_of::<FirewallRuleEntryV6>(), 4);
    }

    #[test]
    fn test_firewall_rule_entry_v6_field_offsets() {
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, src_addr), 0);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, src_mask), 16);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dst_addr), 32);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dst_mask), 48);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, src_port_start), 64);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, src_port_end), 66);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dst_port_start), 68);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dst_port_end), 70);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, protocol), 72);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, match_flags), 73);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, vlan_id), 74);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, action), 76);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, ct_state_mask), 77);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, src_set_id), 78);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dst_set_id), 79);
        // Extended fields
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, tcp_flags_match), 80);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, tcp_flags_mask), 81);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, icmp_type), 82);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, icmp_code), 83);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, match_flags2), 84);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dscp_match), 85);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, max_states), 86);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, src_mac), 88);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dst_mac), 94);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, dscp_mark), 100);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, route_action), 101);
        assert_eq!(mem::offset_of!(FirewallRuleEntryV6, route_ifindex), 102);
    }

    // ── LpmValue ─────────────────────────────────────────────────────

    #[test]
    fn test_lpm_value_size() {
        assert_eq!(mem::size_of::<LpmValue>(), 4);
    }

    #[test]
    fn test_lpm_value_alignment() {
        assert_eq!(mem::align_of::<LpmValue>(), 1);
    }

    // ── Constants ───────────────────────────────────────────────────

    #[test]
    fn test_action_constants() {
        assert_eq!(ACTION_PASS, 0);
        assert_eq!(ACTION_DROP, 1);
        assert_eq!(ACTION_LOG, 2);
    }

    #[test]
    fn test_default_policy_constants() {
        assert_eq!(DEFAULT_POLICY_PASS, 0);
        assert_eq!(DEFAULT_POLICY_DROP, 1);
    }

    #[test]
    fn test_match_flag_bits_are_distinct() {
        let flags = [
            MATCH_SRC_IP,
            MATCH_DST_IP,
            MATCH_SRC_PORT,
            MATCH_DST_PORT,
            MATCH_PROTO,
            MATCH_CT_STATE,
            MATCH_SRC_SET,
            MATCH_DST_SET,
        ];
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(a & b, 0, "flags 0x{a:02x} and 0x{b:02x} overlap");
            }
        }
    }

    #[test]
    fn test_match2_flag_bits_are_distinct() {
        let flags = [
            MATCH2_TCP_FLAGS,
            MATCH2_ICMP_TYPE,
            MATCH2_ICMP_CODE,
            MATCH2_NEGATE_SRC,
            MATCH2_NEGATE_DST,
            MATCH2_DSCP,
            MATCH2_SRC_MAC,
            MATCH2_DST_MAC,
        ];
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(a & b, 0, "match2 flags 0x{a:02x} and 0x{b:02x} overlap");
            }
        }
    }

    #[test]
    fn test_ct_match_bits_are_distinct() {
        let bits = [
            CT_MATCH_NEW,
            CT_MATCH_ESTABLISHED,
            CT_MATCH_RELATED,
            CT_MATCH_INVALID,
        ];
        for (i, &a) in bits.iter().enumerate() {
            for &b in &bits[i + 1..] {
                assert_eq!(a & b, 0, "ct match bits 0x{a:02x} and 0x{b:02x} overlap");
            }
        }
    }

    // ── IP Set types ─────────────────────────────────────────────────

    #[test]
    fn test_ipset_key_v4_size() {
        assert_eq!(mem::size_of::<IpSetKeyV4>(), 8);
    }

    #[test]
    fn test_ipset_key_v6_size() {
        assert_eq!(mem::size_of::<IpSetKeyV6>(), 20);
    }

    #[test]
    fn test_portset_key_size() {
        assert_eq!(mem::size_of::<PortSetKey>(), 4);
    }

    #[test]
    fn test_ipset_key_v4_field_offsets() {
        assert_eq!(mem::offset_of!(IpSetKeyV4, set_id), 0);
        assert_eq!(mem::offset_of!(IpSetKeyV4, addr), 4);
    }

    #[test]
    fn test_ipset_key_v6_field_offsets() {
        assert_eq!(mem::offset_of!(IpSetKeyV6, set_id), 0);
        assert_eq!(mem::offset_of!(IpSetKeyV6, addr), 4);
    }
}
