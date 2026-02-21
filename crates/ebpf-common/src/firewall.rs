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

/// Array-based IPv4 firewall rule entry (32 bytes).
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
    /// Padding to 32 bytes.
    pub _padding: [u8; 3],
}

/// Array-based IPv6 firewall rule entry (80 bytes).
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
    /// Padding to 80 bytes.
    pub _padding: [u8; 3],
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

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // ── FirewallRuleEntry (V4) ──────────────────────────────────────

    #[test]
    fn test_firewall_rule_entry_size() {
        assert_eq!(mem::size_of::<FirewallRuleEntry>(), 32);
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
    }

    // ── FirewallRuleEntryV6 ─────────────────────────────────────────

    #[test]
    fn test_firewall_rule_entry_v6_size() {
        assert_eq!(mem::size_of::<FirewallRuleEntryV6>(), 80);
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
        ];
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(a & b, 0, "flags 0x{a:02x} and 0x{b:02x} overlap");
            }
        }
    }
}
