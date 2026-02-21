use serde::{Deserialize, Serialize};

use crate::common::entity::{Protocol, RuleId};
use ebpf_common::firewall::{
    ACTION_DROP, ACTION_LOG, ACTION_PASS, FirewallRuleEntry, FirewallRuleEntryV6, MATCH_DST_IP,
    MATCH_DST_PORT, MATCH_PROTO, MATCH_SRC_IP, MATCH_SRC_PORT,
};

use super::error::FirewallError;

// ── Actions ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirewallAction {
    Allow,
    Deny,
    Log,
}

// ── IP Network ──────────────────────────────────────────────────────

/// IP address with CIDR prefix for subnet matching (IPv4 or IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpNetwork {
    /// IPv4 address as host-byte-order u32, prefix 0-32.
    V4 { addr: u32, prefix_len: u8 },
    /// IPv6 address as 16 bytes in network order, prefix 0-128.
    V6 { addr: [u8; 16], prefix_len: u8 },
}

impl IpNetwork {
    /// Check if the given IPv4 address falls within this network (V4 only).
    /// Returns `false` if this is a V6 network.
    pub fn contains_v4(&self, ip: u32) -> bool {
        match *self {
            Self::V4 {
                addr, prefix_len, ..
            } => cidr_match_v4(addr, prefix_len, ip),
            Self::V6 { .. } => false,
        }
    }

    /// Check if the given IPv6 address falls within this network (V6 only).
    /// Returns `false` if this is a V4 network.
    pub fn contains_v6(&self, ip: &[u8; 16]) -> bool {
        match *self {
            Self::V4 { .. } => false,
            Self::V6 {
                addr, prefix_len, ..
            } => cidr_match_v6(&addr, prefix_len, ip),
        }
    }

    /// Check whether the given address (v4 u32 or v6 `[u32; 4]`) falls
    /// within this network, selecting v4/v6 comparison by `is_ipv6`.
    pub fn contains_addr(&self, addr: &[u32; 4], is_ipv6: bool) -> bool {
        if is_ipv6 {
            let bytes = u32x4_to_bytes(addr);
            self.contains_v6(&bytes)
        } else {
            self.contains_v4(addr[0])
        }
    }

    /// Returns `true` if this is an IPv6 network.
    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6 { .. })
    }

    pub fn validate(&self) -> Result<(), FirewallError> {
        match *self {
            Self::V4 { prefix_len, .. } => {
                if prefix_len > 32 {
                    return Err(FirewallError::InvalidCidr { prefix_len });
                }
            }
            Self::V6 { prefix_len, .. } => {
                if prefix_len > 128 {
                    return Err(FirewallError::InvalidCidr { prefix_len });
                }
            }
        }
        Ok(())
    }

    /// Convert an IPv6 address stored as `[u8; 16]` to `[u32; 4]` for eBPF maps.
    pub fn v6_addr_to_u32x4(addr: &[u8; 16]) -> [u32; 4] {
        [
            u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
            u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
            u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
            u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
        ]
    }
}

/// Backward-compatible alias for IPv4 CIDR.
pub type IpCidr = IpNetwork;

/// Construct a V4 `IpNetwork` from the legacy `IpCidr` fields.
pub fn ip_cidr(addr: u32, prefix_len: u8) -> IpNetwork {
    IpNetwork::V4 { addr, prefix_len }
}

fn cidr_match_v4(net_addr: u32, prefix_len: u8, ip: u32) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 32 {
        return net_addr == ip;
    }
    let mask = !0u32 << (32 - prefix_len);
    (net_addr & mask) == (ip & mask)
}

fn cidr_match_v6(net_addr: &[u8; 16], prefix_len: u8, ip: &[u8; 16]) -> bool {
    if prefix_len == 0 {
        return true;
    }
    if prefix_len >= 128 {
        return net_addr == ip;
    }
    let full_bytes = (prefix_len / 8) as usize;
    if net_addr[..full_bytes] != ip[..full_bytes] {
        return false;
    }
    let remaining_bits = prefix_len % 8;
    if remaining_bits > 0 {
        let mask = !0u8 << (8 - remaining_bits);
        if (net_addr[full_bytes] & mask) != (ip[full_bytes] & mask) {
            return false;
        }
    }
    true
}

/// Convert `[u32; 4]` (eBPF representation) to `[u8; 16]` for domain matching.
pub fn u32x4_to_bytes(addr: &[u32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, &word) in addr.iter().enumerate() {
        let b = word.to_be_bytes();
        bytes[i * 4] = b[0];
        bytes[i * 4 + 1] = b[1];
        bytes[i * 4 + 2] = b[2];
        bytes[i * 4 + 3] = b[3];
    }
    bytes
}

// ── CIDR mask helpers ───────────────────────────────────────────────

/// Convert an IPv4 prefix length (0-32) to a bitmask.
/// e.g. 24 -> `0xFFFF_FF00`, 0 -> `0`, 32 -> `0xFFFF_FFFF`.
fn prefix_to_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 32 {
        !0u32
    } else {
        !0u32 << (32 - prefix_len)
    }
}

/// Convert an IPv6 prefix length (0-128) to a `[u32; 4]` mask.
fn prefix_to_mask_v6(prefix_len: u8) -> [u32; 4] {
    let mut mask = [0u32; 4];
    let mut remaining = u32::from(prefix_len);
    for word in &mut mask {
        if remaining >= 32 {
            *word = !0u32;
            remaining -= 32;
        } else if remaining > 0 {
            *word = !0u32 << (32 - remaining);
            remaining = 0;
        }
    }
    mask
}

/// Pre-mask an IPv6 address with a prefix mask: `addr[i] & mask[i]`.
fn apply_mask_v6(addr: &[u32; 4], mask: &[u32; 4]) -> [u32; 4] {
    [
        addr[0] & mask[0],
        addr[1] & mask[1],
        addr[2] & mask[2],
        addr[3] & mask[3],
    ]
}

// ── Port range ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }

    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.start > self.end {
            return Err(FirewallError::InvalidPortRange {
                start: self.start,
                end: self.end,
            });
        }
        Ok(())
    }
}

// ── Scope ───────────────────────────────────────────────────────────

/// Rule scope for segmentation (FR5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Scope {
    /// Applies to all interfaces/namespaces.
    Global,
    /// Applies to a specific network interface (standalone mode).
    Interface(String),
    /// Applies to a specific Kubernetes namespace.
    Namespace(String),
}

// ── Firewall rule ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: RuleId,
    pub priority: u32,
    pub action: FirewallAction,
    pub protocol: Protocol,
    pub src_ip: Option<IpNetwork>,
    pub dst_ip: Option<IpNetwork>,
    pub src_port: Option<PortRange>,
    pub dst_port: Option<PortRange>,
    pub scope: Scope,
    pub enabled: bool,
    /// Optional 802.1Q VLAN ID filter (None = match any VLAN, Some(vid) = exact).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
}

impl FirewallRule {
    /// Returns `true` if this rule targets IPv6 addresses.
    pub fn is_v6(&self) -> bool {
        self.src_ip.as_ref().is_some_and(IpNetwork::is_v6)
            || self.dst_ip.as_ref().is_some_and(IpNetwork::is_v6)
    }

    /// Validate all fields of this rule.
    pub fn validate(&self) -> Result<(), FirewallError> {
        self.id
            .validate()
            .map_err(|reason| FirewallError::InvalidRuleId { reason })?;

        if self.priority == 0 {
            return Err(FirewallError::InvalidPriority);
        }

        if let Some(ref cidr) = self.src_ip {
            cidr.validate()?;
        }
        if let Some(ref cidr) = self.dst_ip {
            cidr.validate()?;
        }
        if let Some(ref range) = self.src_port {
            range.validate()?;
        }
        if let Some(ref range) = self.dst_port {
            range.validate()?;
        }

        // Reject mixed address families
        if let (Some(src), Some(dst)) = (&self.src_ip, &self.dst_ip)
            && src.is_v6() != dst.is_v6()
        {
            return Err(FirewallError::MixedAddressFamilies);
        }

        // VLAN ID must be 0-4094
        if let Some(vid) = self.vlan_id
            && vid > 4094
        {
            return Err(FirewallError::InvalidVlanId { vlan_id: vid });
        }

        Ok(())
    }

    /// Convert to an array-based IPv4 eBPF rule entry.
    ///
    /// - Wildcard fields have their `MATCH_*` flag unset.
    /// - CIDR addresses are pre-masked (`addr & mask`).
    /// - Port ranges encode both start and end.
    pub fn to_ebpf_entry(&self) -> FirewallRuleEntry {
        let mut flags: u8 = 0;

        // Source IP
        let (src_ip, src_mask) = match self.src_ip {
            Some(IpNetwork::V4 { addr, prefix_len }) => {
                let mask = prefix_to_mask_v4(prefix_len);
                flags |= MATCH_SRC_IP;
                (addr & mask, mask)
            }
            _ => (0, 0),
        };

        // Destination IP
        let (dst_ip, dst_mask) = match self.dst_ip {
            Some(IpNetwork::V4 { addr, prefix_len }) => {
                let mask = prefix_to_mask_v4(prefix_len);
                flags |= MATCH_DST_IP;
                (addr & mask, mask)
            }
            _ => (0, 0),
        };

        // Source port range
        let (src_port_start, src_port_end) = match self.src_port {
            Some(range) => {
                flags |= MATCH_SRC_PORT;
                (range.start, range.end)
            }
            None => (0, 0),
        };

        // Destination port range
        let (dst_port_start, dst_port_end) = match self.dst_port {
            Some(range) => {
                flags |= MATCH_DST_PORT;
                (range.start, range.end)
            }
            None => (0, 0),
        };

        // Protocol
        let protocol = self.protocol.to_u8();
        if self.protocol != Protocol::Any {
            flags |= MATCH_PROTO;
        }

        FirewallRuleEntry {
            src_ip,
            src_mask,
            dst_ip,
            dst_mask,
            src_port_start,
            src_port_end,
            dst_port_start,
            dst_port_end,
            protocol,
            match_flags: flags,
            vlan_id: self.vlan_id.unwrap_or(0),
            action: action_to_u8(self.action),
            _padding: [0; 3],
        }
    }

    /// Convert to an array-based IPv6 eBPF rule entry.
    ///
    /// Same semantics as `to_ebpf_entry()` but with 128-bit addresses.
    pub fn to_ebpf_entry_v6(&self) -> FirewallRuleEntryV6 {
        let mut flags: u8 = 0;

        // Source IPv6
        let (src_addr, src_mask) = match self.src_ip {
            Some(IpNetwork::V6 { addr, prefix_len }) => {
                let addr_u32 = IpNetwork::v6_addr_to_u32x4(&addr);
                let mask = prefix_to_mask_v6(prefix_len);
                flags |= MATCH_SRC_IP;
                (apply_mask_v6(&addr_u32, &mask), mask)
            }
            _ => ([0; 4], [0; 4]),
        };

        // Destination IPv6
        let (dst_addr, dst_mask) = match self.dst_ip {
            Some(IpNetwork::V6 { addr, prefix_len }) => {
                let addr_u32 = IpNetwork::v6_addr_to_u32x4(&addr);
                let mask = prefix_to_mask_v6(prefix_len);
                flags |= MATCH_DST_IP;
                (apply_mask_v6(&addr_u32, &mask), mask)
            }
            _ => ([0; 4], [0; 4]),
        };

        // Source port range
        let (src_port_start, src_port_end) = match self.src_port {
            Some(range) => {
                flags |= MATCH_SRC_PORT;
                (range.start, range.end)
            }
            None => (0, 0),
        };

        // Destination port range
        let (dst_port_start, dst_port_end) = match self.dst_port {
            Some(range) => {
                flags |= MATCH_DST_PORT;
                (range.start, range.end)
            }
            None => (0, 0),
        };

        // Protocol
        let protocol = self.protocol.to_u8();
        if self.protocol != Protocol::Any {
            flags |= MATCH_PROTO;
        }

        FirewallRuleEntryV6 {
            src_addr,
            src_mask,
            dst_addr,
            dst_mask,
            src_port_start,
            src_port_end,
            dst_port_start,
            dst_port_end,
            protocol,
            match_flags: flags,
            vlan_id: self.vlan_id.unwrap_or(0),
            action: action_to_u8(self.action),
            _padding: [0; 3],
        }
    }
}

/// Map a domain `FirewallAction` to the eBPF action constant.
fn action_to_u8(action: FirewallAction) -> u8 {
    match action {
        FirewallAction::Allow => ACTION_PASS,
        FirewallAction::Deny => ACTION_DROP,
        FirewallAction::Log => ACTION_LOG,
    }
}

// ── Packet info (evaluation input) ──────────────────────────────────

/// Domain-level packet information used for rule evaluation.
/// Converted from `PacketEvent` by the adapter layer.
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6.
    pub src_addr: [u32; 4],
    /// Destination address: same encoding as `src_addr`.
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub interface: String,
    /// `true` if the packet is IPv6.
    pub is_ipv6: bool,
    /// 802.1Q VLAN ID (None if no VLAN tag).
    pub vlan_id: Option<u16>,
}

impl PacketInfo {
    /// Returns the source IPv4 address (first element of `src_addr`).
    pub fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Returns the destination IPv4 address (first element of `dst_addr`).
    pub fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::RuleId;

    // ── IpNetwork V4 tests (backward compat) ────────────────────────

    #[test]
    fn cidr_exact_match() {
        let cidr = IpNetwork::V4 {
            addr: 0xC0A8_0001, // 192.168.0.1
            prefix_len: 32,
        };
        assert!(cidr.contains_v4(0xC0A8_0001));
        assert!(!cidr.contains_v4(0xC0A8_0002));
    }

    #[test]
    fn cidr_subnet_match() {
        // 192.168.1.0/24
        let cidr = IpNetwork::V4 {
            addr: 0xC0A8_0100,
            prefix_len: 24,
        };
        assert!(cidr.contains_v4(0xC0A8_0100)); // 192.168.1.0
        assert!(cidr.contains_v4(0xC0A8_01FF)); // 192.168.1.255
        assert!(!cidr.contains_v4(0xC0A8_0200)); // 192.168.2.0
    }

    #[test]
    fn cidr_wildcard_matches_all() {
        let cidr = IpNetwork::V4 {
            addr: 0,
            prefix_len: 0,
        };
        assert!(cidr.contains_v4(0));
        assert!(cidr.contains_v4(0xFFFF_FFFF));
        assert!(cidr.contains_v4(0xC0A8_0001));
    }

    #[test]
    fn cidr_validate_ok() {
        let cidr = IpNetwork::V4 {
            addr: 0,
            prefix_len: 32,
        };
        assert!(cidr.validate().is_ok());
    }

    #[test]
    fn cidr_validate_invalid_prefix() {
        let cidr = IpNetwork::V4 {
            addr: 0,
            prefix_len: 33,
        };
        assert!(cidr.validate().is_err());
    }

    // ── IpNetwork V6 tests ──────────────────────────────────────────

    #[test]
    fn v6_exact_match() {
        // ::1
        let mut addr = [0u8; 16];
        addr[15] = 1;
        let net = IpNetwork::V6 {
            addr,
            prefix_len: 128,
        };
        assert!(net.contains_v6(&addr));

        let mut other = [0u8; 16];
        other[15] = 2;
        assert!(!net.contains_v6(&other));
    }

    #[test]
    fn v6_subnet_match() {
        // 2001:db8::/32
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        let net = IpNetwork::V6 {
            addr,
            prefix_len: 32,
        };

        // 2001:db8::1 should match
        let mut test = [0u8; 16];
        test[0] = 0x20;
        test[1] = 0x01;
        test[2] = 0x0d;
        test[3] = 0xb8;
        test[15] = 1;
        assert!(net.contains_v6(&test));

        // 2001:db9::1 should NOT match
        let mut test2 = [0u8; 16];
        test2[0] = 0x20;
        test2[1] = 0x01;
        test2[2] = 0x0d;
        test2[3] = 0xb9;
        test2[15] = 1;
        assert!(!net.contains_v6(&test2));
    }

    #[test]
    fn v6_wildcard_matches_all() {
        let net = IpNetwork::V6 {
            addr: [0u8; 16],
            prefix_len: 0,
        };
        assert!(net.contains_v6(&[0u8; 16]));
        assert!(net.contains_v6(&[0xFF; 16]));
    }

    #[test]
    fn v6_validate_ok() {
        let net = IpNetwork::V6 {
            addr: [0u8; 16],
            prefix_len: 128,
        };
        assert!(net.validate().is_ok());
    }

    #[test]
    fn v6_validate_invalid_prefix() {
        let net = IpNetwork::V6 {
            addr: [0u8; 16],
            prefix_len: 129,
        };
        assert!(net.validate().is_err());
    }

    #[test]
    fn v6_does_not_match_v4() {
        let net = IpNetwork::V6 {
            addr: [0u8; 16],
            prefix_len: 0,
        };
        assert!(!net.contains_v4(0xC0A8_0001));

        let v4 = IpNetwork::V4 {
            addr: 0,
            prefix_len: 0,
        };
        assert!(!v4.contains_v6(&[0u8; 16]));
    }

    #[test]
    fn v6_addr_to_u32x4_roundtrip() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 1;
        let u32s = IpNetwork::v6_addr_to_u32x4(&addr);
        let back = u32x4_to_bytes(&u32s);
        assert_eq!(addr, back);
    }

    // ── PortRange tests ────────────────────────────────────────────

    #[test]
    fn port_range_contains() {
        let range = PortRange {
            start: 80,
            end: 443,
        };
        assert!(range.contains(80));
        assert!(range.contains(443));
        assert!(range.contains(200));
        assert!(!range.contains(79));
        assert!(!range.contains(444));
    }

    #[test]
    fn port_range_single_port() {
        let range = PortRange { start: 22, end: 22 };
        assert!(range.contains(22));
        assert!(!range.contains(21));
        assert!(!range.contains(23));
    }

    #[test]
    fn port_range_validate_ok() {
        let range = PortRange {
            start: 80,
            end: 443,
        };
        assert!(range.validate().is_ok());
    }

    #[test]
    fn port_range_validate_inverted() {
        let range = PortRange {
            start: 443,
            end: 80,
        };
        assert!(range.validate().is_err());
    }

    // ── FirewallRule validation tests ──────────────────────────────

    fn make_rule(id: &str, priority: u32) -> FirewallRule {
        FirewallRule {
            id: RuleId(id.to_string()),
            priority,
            action: FirewallAction::Deny,
            protocol: Protocol::Tcp,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
        }
    }

    #[test]
    fn rule_validate_ok() {
        let rule = make_rule("rule-1", 10);
        assert!(rule.validate().is_ok());
    }

    #[test]
    fn rule_validate_empty_id() {
        let rule = make_rule("", 10);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_zero_priority() {
        let rule = make_rule("rule-1", 0);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_invalid_src_cidr() {
        let mut rule = make_rule("rule-1", 10);
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0,
            prefix_len: 33,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_invalid_dst_cidr() {
        let mut rule = make_rule("rule-1", 10);
        rule.dst_ip = Some(IpNetwork::V4 {
            addr: 0,
            prefix_len: 40,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_invalid_src_port() {
        let mut rule = make_rule("rule-1", 10);
        rule.src_port = Some(PortRange {
            start: 1000,
            end: 80,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_invalid_dst_port() {
        let mut rule = make_rule("rule-1", 10);
        rule.dst_port = Some(PortRange {
            start: 500,
            end: 100,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_special_chars_in_id() {
        let rule = make_rule("rule with spaces", 10);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_mixed_address_families() {
        let mut rule = make_rule("rule-1", 10);
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A8_0001,
            prefix_len: 32,
        });
        rule.dst_ip = Some(IpNetwork::V6 {
            addr: [0u8; 16],
            prefix_len: 128,
        });
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_vlan_id_too_large() {
        let mut rule = make_rule("rule-1", 10);
        rule.vlan_id = Some(4095);
        assert!(rule.validate().is_err());
    }

    #[test]
    fn rule_validate_vlan_id_ok() {
        let mut rule = make_rule("rule-1", 10);
        rule.vlan_id = Some(100);
        assert!(rule.validate().is_ok());
    }

    // ── prefix_to_mask helpers ───────────────────────────────────────

    #[test]
    fn prefix_to_mask_v4_values() {
        assert_eq!(prefix_to_mask_v4(0), 0);
        assert_eq!(prefix_to_mask_v4(8), 0xFF00_0000);
        assert_eq!(prefix_to_mask_v4(16), 0xFFFF_0000);
        assert_eq!(prefix_to_mask_v4(24), 0xFFFF_FF00);
        assert_eq!(prefix_to_mask_v4(32), 0xFFFF_FFFF);
    }

    #[test]
    fn prefix_to_mask_v6_values() {
        assert_eq!(prefix_to_mask_v6(0), [0, 0, 0, 0]);
        assert_eq!(prefix_to_mask_v6(32), [!0u32, 0, 0, 0]);
        assert_eq!(prefix_to_mask_v6(64), [!0u32, !0u32, 0, 0]);
        assert_eq!(prefix_to_mask_v6(128), [!0u32, !0u32, !0u32, !0u32]);
        // /48: first 32 bits all 1s, next 16 bits all 1s
        assert_eq!(prefix_to_mask_v6(48), [!0u32, 0xFFFF_0000, 0, 0]);
    }

    // ── to_ebpf_entry() tests ───────────────────────────────────────

    #[test]
    fn to_ebpf_entry_full_wildcard() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        let entry = rule.to_ebpf_entry();
        assert_eq!(entry.match_flags, 0, "all wildcards -> no flags");
        assert_eq!(entry.src_ip, 0);
        assert_eq!(entry.src_mask, 0);
        assert_eq!(entry.dst_ip, 0);
        assert_eq!(entry.dst_mask, 0);
        assert_eq!(entry.src_port_start, 0);
        assert_eq!(entry.dst_port_start, 0);
        assert_eq!(entry.protocol, 0);
    }

    #[test]
    fn to_ebpf_entry_with_protocol_only() {
        let rule = make_rule("r", 1); // TCP
        let entry = rule.to_ebpf_entry();
        assert_eq!(entry.match_flags, MATCH_PROTO);
        assert_eq!(entry.protocol, 6);
    }

    #[test]
    fn to_ebpf_entry_cidr_24() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        // 192.168.1.123/24 — addr should be pre-masked to 192.168.1.0
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A8_017B, // 192.168.1.123
            prefix_len: 24,
        });
        let entry = rule.to_ebpf_entry();
        assert_eq!(entry.match_flags, MATCH_SRC_IP);
        assert_eq!(entry.src_mask, 0xFFFF_FF00);
        assert_eq!(entry.src_ip, 0xC0A8_0100); // pre-masked!
    }

    #[test]
    fn to_ebpf_entry_host_32() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        rule.dst_ip = Some(IpNetwork::V4 {
            addr: 0x0A000001, // 10.0.0.1
            prefix_len: 32,
        });
        let entry = rule.to_ebpf_entry();
        assert_eq!(entry.match_flags, MATCH_DST_IP);
        assert_eq!(entry.dst_ip, 0x0A000001);
        assert_eq!(entry.dst_mask, 0xFFFF_FFFF);
    }

    #[test]
    fn to_ebpf_entry_port_range() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        rule.dst_port = Some(PortRange {
            start: 80,
            end: 443,
        });
        let entry = rule.to_ebpf_entry();
        assert_eq!(entry.match_flags, MATCH_DST_PORT);
        assert_eq!(entry.dst_port_start, 80);
        assert_eq!(entry.dst_port_end, 443);
    }

    #[test]
    fn to_ebpf_entry_single_port() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        rule.src_port = Some(PortRange { start: 22, end: 22 });
        let entry = rule.to_ebpf_entry();
        assert_eq!(entry.match_flags, MATCH_SRC_PORT);
        assert_eq!(entry.src_port_start, 22);
        assert_eq!(entry.src_port_end, 22);
    }

    #[test]
    fn to_ebpf_entry_all_fields() {
        let mut rule = make_rule("r", 1);
        rule.action = FirewallAction::Allow;
        rule.protocol = Protocol::Tcp;
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A80000,
            prefix_len: 16,
        });
        rule.dst_ip = Some(IpNetwork::V4 {
            addr: 0x0A000001,
            prefix_len: 32,
        });
        rule.src_port = Some(PortRange {
            start: 1024,
            end: 65535,
        });
        rule.dst_port = Some(PortRange { start: 80, end: 80 });
        rule.vlan_id = Some(100);

        let entry = rule.to_ebpf_entry();
        assert_eq!(
            entry.match_flags,
            MATCH_SRC_IP | MATCH_DST_IP | MATCH_SRC_PORT | MATCH_DST_PORT | MATCH_PROTO
        );
        assert_eq!(entry.src_ip, 0xC0A80000);
        assert_eq!(entry.src_mask, 0xFFFF0000);
        assert_eq!(entry.dst_ip, 0x0A000001);
        assert_eq!(entry.dst_mask, 0xFFFFFFFF);
        assert_eq!(entry.src_port_start, 1024);
        assert_eq!(entry.src_port_end, 65535);
        assert_eq!(entry.dst_port_start, 80);
        assert_eq!(entry.dst_port_end, 80);
        assert_eq!(entry.protocol, 6);
        assert_eq!(entry.vlan_id, 100);
        assert_eq!(entry.action, ACTION_PASS);
    }

    #[test]
    fn to_ebpf_entry_actions() {
        let mut rule = make_rule("r", 1);

        rule.action = FirewallAction::Allow;
        assert_eq!(rule.to_ebpf_entry().action, ACTION_PASS);

        rule.action = FirewallAction::Deny;
        assert_eq!(rule.to_ebpf_entry().action, ACTION_DROP);

        rule.action = FirewallAction::Log;
        assert_eq!(rule.to_ebpf_entry().action, ACTION_LOG);
    }

    // ── to_ebpf_entry_v6() tests ────────────────────────────────────

    #[test]
    fn to_ebpf_entry_v6_wildcard() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        let entry = rule.to_ebpf_entry_v6();
        assert_eq!(entry.match_flags, 0);
        assert_eq!(entry.src_addr, [0; 4]);
        assert_eq!(entry.src_mask, [0; 4]);
    }

    #[test]
    fn to_ebpf_entry_v6_with_addr() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        // 2001:db8::1/128
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 1;
        rule.src_ip = Some(IpNetwork::V6 {
            addr,
            prefix_len: 128,
        });
        let entry = rule.to_ebpf_entry_v6();
        assert_eq!(entry.match_flags, MATCH_SRC_IP);
        assert_eq!(entry.src_addr[0], 0x2001_0db8);
        assert_eq!(entry.src_addr[3], 1);
        assert_eq!(entry.src_mask, [!0u32; 4]);
    }

    #[test]
    fn to_ebpf_entry_v6_subnet_premasked() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Any;
        // 2001:db8:1234:5678::1/32 — should mask to 2001:db8::
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[4] = 0x12;
        addr[5] = 0x34;
        addr[15] = 1;
        rule.src_ip = Some(IpNetwork::V6 {
            addr,
            prefix_len: 32,
        });
        let entry = rule.to_ebpf_entry_v6();
        assert_eq!(entry.src_addr[0], 0x2001_0db8); // first 32 bits kept
        assert_eq!(entry.src_addr[1], 0); // masked away
        assert_eq!(entry.src_addr[2], 0);
        assert_eq!(entry.src_addr[3], 0);
        assert_eq!(entry.src_mask, [!0u32, 0, 0, 0]);
    }

    #[test]
    fn to_ebpf_entry_v6_with_ports() {
        let mut rule = make_rule("r", 1);
        rule.protocol = Protocol::Tcp;
        rule.dst_port = Some(PortRange {
            start: 443,
            end: 443,
        });
        let entry = rule.to_ebpf_entry_v6();
        assert_eq!(entry.match_flags, MATCH_DST_PORT | MATCH_PROTO);
        assert_eq!(entry.dst_port_start, 443);
        assert_eq!(entry.dst_port_end, 443);
        assert_eq!(entry.protocol, 6);
    }
}
