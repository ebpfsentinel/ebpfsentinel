//! NAT shared types for kernel (eBPF) and userspace.
//!
//! Used by: tc-nat-ingress (DNAT), tc-nat-egress (SNAT/masquerade),
//! and userspace configuration.

/// Maximum NAT rules per direction.
pub const MAX_NAT_RULES: u32 = 256;

/// Maximum NAT port allocation entries.
pub const MAX_NAT_PORT_ALLOC: u32 = 65_536;

// ── NAT type constants ──────────────────────────────────────────────

pub const NAT_TYPE_NONE: u8 = 0;
pub const NAT_TYPE_SNAT: u8 = 1;
pub const NAT_TYPE_DNAT: u8 = 2;
pub const NAT_TYPE_MASQUERADE: u8 = 3;
pub const NAT_TYPE_REDIRECT: u8 = 4;
pub const NAT_TYPE_ONETOONE: u8 = 5;
pub const NAT_TYPE_NPTV6: u8 = 6;

/// Maximum NPTv6 (RFC 6296) prefix translation rules.
pub const MAX_NPTV6_RULES: u32 = 64;

// ── NAT metric indices ──────────────────────────────────────────────

pub const NAT_METRIC_SNAT_APPLIED: u32 = 0;
pub const NAT_METRIC_DNAT_APPLIED: u32 = 1;
pub const NAT_METRIC_MASQ_APPLIED: u32 = 2;
pub const NAT_METRIC_PORT_ALLOC_FAIL: u32 = 3;
pub const NAT_METRIC_ERRORS: u32 = 4;
/// Metric index: total packets seen (unconditional, first instruction).
pub const NAT_METRIC_TOTAL_SEEN: u32 = 5;
/// Metric index: NPTv6 prefix translations applied.
pub const NAT_METRIC_NPTV6_TRANSLATED: u32 = 6;
/// Metric index: hairpin NAT (NAT reflection) applied.
pub const NAT_METRIC_HAIRPIN_APPLIED: u32 = 7;
pub const NAT_METRIC_COUNT: u32 = 8;

// ── NAT match flags ─────────────────────────────────────────────────

pub const NAT_MATCH_SRC_IP: u8 = 0x01;
pub const NAT_MATCH_DST_IP: u8 = 0x02;
pub const NAT_MATCH_DST_PORT: u8 = 0x04;
pub const NAT_MATCH_PROTO: u8 = 0x08;

// ── NAT HashMap fast-path types ─────────────────────────────────────

/// Maximum entries in the NAT exact-match HashMap.
pub const MAX_NAT_HASH_EXACT: u32 = 16_384;

/// Key for NAT exact-match HashMap lookup (O(1) fast path).
///
/// NAT rules with exact (proto, dst_ip, dst_port) — covers port_forward,
/// dnat, and redirect rules. Checked before the Array+bpf_loop scan.
///
/// Size: 8 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatHashKeyExact {
    /// Destination IPv4 address (host byte order).
    pub dst_ip: u32,
    /// Destination port.
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP).
    pub protocol: u8,
    pub _pad: u8,
}

/// Value for NAT exact-match HashMap.
///
/// Contains the translated address/port and NAT type, allowing the eBPF
/// program to perform the rewrite without scanning the rule array.
///
/// Size: 16 bytes (aligned to 4 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatHashValue {
    /// Translated address (IPv4, host byte order).
    pub nat_addr: u32,
    /// Translated port start.
    pub nat_port_start: u16,
    /// Translated port end.
    pub nat_port_end: u16,
    /// NAT type (`NAT_TYPE_*`).
    pub nat_type: u8,
    /// IP protocol from the original rule.
    pub protocol: u8,
    pub _pad: [u8; 2],
    /// Interface index for masquerade.
    pub nat_interface: u32,
}

// ── NAT rule entry — 40 bytes ───────────────────────────────────────

/// NAT rule stored in Array maps, scanned linearly.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatRuleEntry {
    /// Source IP to match (pre-masked).
    pub match_src_ip: u32,
    /// Source IP mask.
    pub match_src_mask: u32,
    /// Destination IP to match (pre-masked).
    pub match_dst_ip: u32,
    /// Destination IP mask.
    pub match_dst_mask: u32,
    /// Destination port range start.
    pub match_dst_port_start: u16,
    /// Destination port range end.
    pub match_dst_port_end: u16,
    /// IP protocol (6=TCP, 17=UDP, 0=any).
    pub match_protocol: u8,
    /// Bitmask of active NAT_MATCH_* flags.
    pub match_flags: u8,
    /// NAT type (NAT_TYPE_*).
    pub nat_type: u8,
    pub _pad: u8,
    /// Translated address.
    pub nat_addr: u32,
    /// Translated port range start.
    pub nat_port_start: u16,
    /// Translated port range end.
    pub nat_port_end: u16,
    /// Interface index for masquerade.
    pub nat_interface: u32,
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
}

/// Maximum NAT rules per direction (IPv6).
pub const MAX_NAT_RULES_V6: u32 = 128;

// ── NAT rule entry (IPv6) — 100 bytes ──────────────────────────────

/// NAT rule for IPv6 traffic, stored in Array maps and scanned linearly.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatRuleEntryV6 {
    /// Source IPv6 address to match (pre-masked).
    pub match_src_addr: [u32; 4],
    /// Source IPv6 address mask.
    pub match_src_mask: [u32; 4],
    /// Destination IPv6 address to match (pre-masked).
    pub match_dst_addr: [u32; 4],
    /// Destination IPv6 address mask.
    pub match_dst_mask: [u32; 4],
    /// Destination port range start.
    pub match_dst_port_start: u16,
    /// Destination port range end.
    pub match_dst_port_end: u16,
    /// IP protocol (6=TCP, 17=UDP, 58=ICMPv6, 0=any).
    pub match_protocol: u8,
    /// Bitmask of active NAT_MATCH_* flags.
    pub match_flags: u8,
    /// NAT type (NAT_TYPE_*).
    pub nat_type: u8,
    pub _pad: u8,
    /// Translated IPv6 address.
    pub nat_addr: [u32; 4],
    /// Translated port range start.
    pub nat_port_start: u16,
    /// Translated port range end.
    pub nat_port_end: u16,
    /// Interface index for masquerade.
    pub nat_interface: u32,
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
}

// ── NPTv6 rule entry — 40 bytes ─────────────────────────────────────

/// NPTv6 rule entry — stateless IPv6 prefix translation (RFC 6296).
/// Bidirectional: egress rewrites src (internal->external),
/// ingress rewrites dst (external->internal).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NptV6RuleEntry {
    /// Internal (site-local) prefix, host byte order.
    pub internal_prefix: [u32; 4],
    /// External (provider) prefix, host byte order.
    pub external_prefix: [u32; 4],
    /// Prefix length (1-64).
    pub prefix_len: u8,
    /// 1 = enabled, 0 = disabled.
    pub enabled: u8,
    /// Pre-computed RFC 6296 checksum adjustment.
    pub adjustment: u16,
    /// Interface group bitmask (0 = floating/all interfaces).
    /// Bits 0-30: group membership, bit 31: invert flag.
    pub group_mask: u32,
}

// ── Hairpin NAT (NAT reflection) ─────────────────────────────────────

/// Hairpin NAT configuration. 16 bytes, 4-byte aligned.
///
/// When a client on the internal subnet accesses the external (public) IP of
/// the firewall for a service that is DNAT'd back to the same subnet, hairpin
/// NAT rewrites the source to the firewall's internal IP so the reply goes
/// through the firewall instead of being routed directly (which would be
/// dropped as asymmetric).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HairpinConfig {
    /// Internal subnet address (host byte order, pre-masked).
    pub internal_subnet: u32,
    /// Internal subnet mask (host byte order).
    pub internal_mask: u32,
    /// Firewall's internal IP for SNAT (host byte order).
    pub hairpin_snat_ip: u32,
    /// 1 = enabled, 0 = disabled.
    pub enabled: u8,
    pub _pad: [u8; 3],
}

/// Hairpin reverse-mapping value. 12 bytes.
///
/// Stored in the hairpin conntrack table so that return traffic from the
/// internal server can be un-SNATed (restore original client src) and
/// un-DNATed (restore external dst) before forwarding back to the client.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HairpinCtValue {
    /// Original source IP before hairpin SNAT.
    pub orig_src_ip: u32,
    /// Original destination IP before DNAT (external IP).
    pub orig_dst_ip: u32,
    /// Original source port.
    pub orig_src_port: u16,
    pub _pad: u16,
}

/// Maximum hairpin conntrack entries.
pub const MAX_HAIRPIN_CT: u32 = 16_384;

// ── NAT port allocation key — 8 bytes ───────────────────────────────

/// Key for NAT port allocation (LRU HashMap).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPortAllocKey {
    pub orig_addr: u32,
    pub orig_port: u16,
    pub _pad: u16,
}

/// Value for NAT port allocation — allocated translated port.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatPortAllocValue {
    pub nat_addr: u32,
    pub nat_port: u16,
    pub _pad: u16,
}

// ── Pod impls ────────────────────────────────────────────────────────

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatRuleEntry {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatRuleEntryV6 {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NptV6RuleEntry {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatPortAllocKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatPortAllocValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for HairpinConfig {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for HairpinCtValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatHashKeyExact {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatHashValue {}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn nat_rule_entry_size() {
        assert_eq!(mem::size_of::<NatRuleEntry>(), 40);
    }

    #[test]
    fn nat_rule_entry_alignment() {
        assert_eq!(mem::align_of::<NatRuleEntry>(), 4);
    }

    #[test]
    fn nat_rule_entry_field_offsets() {
        assert_eq!(mem::offset_of!(NatRuleEntry, match_src_ip), 0);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_src_mask), 4);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_dst_ip), 8);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_dst_mask), 12);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_dst_port_start), 16);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_dst_port_end), 18);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_protocol), 20);
        assert_eq!(mem::offset_of!(NatRuleEntry, match_flags), 21);
        assert_eq!(mem::offset_of!(NatRuleEntry, nat_type), 22);
        assert_eq!(mem::offset_of!(NatRuleEntry, nat_addr), 24);
        assert_eq!(mem::offset_of!(NatRuleEntry, nat_port_start), 28);
        assert_eq!(mem::offset_of!(NatRuleEntry, nat_port_end), 30);
        assert_eq!(mem::offset_of!(NatRuleEntry, nat_interface), 32);
        assert_eq!(mem::offset_of!(NatRuleEntry, group_mask), 36);
    }

    #[test]
    fn nat_rule_entry_v6_size() {
        assert_eq!(mem::size_of::<NatRuleEntryV6>(), 100);
    }

    #[test]
    fn nat_rule_entry_v6_alignment() {
        assert_eq!(mem::align_of::<NatRuleEntryV6>(), 4);
    }

    #[test]
    fn nat_rule_entry_v6_field_offsets() {
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_src_addr), 0);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_src_mask), 16);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_dst_addr), 32);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_dst_mask), 48);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_dst_port_start), 64);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_dst_port_end), 66);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_protocol), 68);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, match_flags), 69);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, nat_type), 70);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, nat_addr), 72);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, nat_port_start), 88);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, nat_port_end), 90);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, nat_interface), 92);
        assert_eq!(mem::offset_of!(NatRuleEntryV6, group_mask), 96);
    }

    #[test]
    fn nptv6_rule_entry_size() {
        assert_eq!(mem::size_of::<NptV6RuleEntry>(), 40);
    }

    #[test]
    fn nptv6_rule_entry_alignment() {
        assert_eq!(mem::align_of::<NptV6RuleEntry>(), 4);
    }

    #[test]
    fn nptv6_rule_entry_field_offsets() {
        assert_eq!(mem::offset_of!(NptV6RuleEntry, internal_prefix), 0);
        assert_eq!(mem::offset_of!(NptV6RuleEntry, external_prefix), 16);
        assert_eq!(mem::offset_of!(NptV6RuleEntry, prefix_len), 32);
        assert_eq!(mem::offset_of!(NptV6RuleEntry, enabled), 33);
        assert_eq!(mem::offset_of!(NptV6RuleEntry, adjustment), 34);
        assert_eq!(mem::offset_of!(NptV6RuleEntry, group_mask), 36);
    }

    #[test]
    fn nat_port_alloc_key_size() {
        assert_eq!(mem::size_of::<NatPortAllocKey>(), 8);
    }

    #[test]
    fn nat_port_alloc_value_size() {
        assert_eq!(mem::size_of::<NatPortAllocValue>(), 8);
    }

    #[test]
    fn nat_type_constants_distinct() {
        let types = [
            NAT_TYPE_NONE,
            NAT_TYPE_SNAT,
            NAT_TYPE_DNAT,
            NAT_TYPE_MASQUERADE,
            NAT_TYPE_REDIRECT,
            NAT_TYPE_ONETOONE,
            NAT_TYPE_NPTV6,
        ];
        for (i, &a) in types.iter().enumerate() {
            for &b in &types[i + 1..] {
                assert_ne!(a, b, "NAT types {a} and {b} collide");
            }
        }
    }

    #[test]
    fn hairpin_config_size() {
        assert_eq!(mem::size_of::<HairpinConfig>(), 16);
    }

    #[test]
    fn hairpin_config_alignment() {
        assert_eq!(mem::align_of::<HairpinConfig>(), 4);
    }

    #[test]
    fn hairpin_config_field_offsets() {
        assert_eq!(mem::offset_of!(HairpinConfig, internal_subnet), 0);
        assert_eq!(mem::offset_of!(HairpinConfig, internal_mask), 4);
        assert_eq!(mem::offset_of!(HairpinConfig, hairpin_snat_ip), 8);
        assert_eq!(mem::offset_of!(HairpinConfig, enabled), 12);
        assert_eq!(mem::offset_of!(HairpinConfig, _pad), 13);
    }

    #[test]
    fn hairpin_ct_value_size() {
        assert_eq!(mem::size_of::<HairpinCtValue>(), 12);
    }

    #[test]
    fn hairpin_ct_value_alignment() {
        assert_eq!(mem::align_of::<HairpinCtValue>(), 4);
    }

    #[test]
    fn hairpin_ct_value_field_offsets() {
        assert_eq!(mem::offset_of!(HairpinCtValue, orig_src_ip), 0);
        assert_eq!(mem::offset_of!(HairpinCtValue, orig_dst_ip), 4);
        assert_eq!(mem::offset_of!(HairpinCtValue, orig_src_port), 8);
        assert_eq!(mem::offset_of!(HairpinCtValue, _pad), 10);
    }

    // ── HashMap fast-path types ─────────────────────────────────────

    #[test]
    fn nat_hash_key_exact_size() {
        assert_eq!(mem::size_of::<NatHashKeyExact>(), 8);
    }

    #[test]
    fn nat_hash_key_exact_alignment() {
        assert_eq!(mem::align_of::<NatHashKeyExact>(), 4);
    }

    #[test]
    fn nat_hash_key_exact_offsets() {
        assert_eq!(mem::offset_of!(NatHashKeyExact, dst_ip), 0);
        assert_eq!(mem::offset_of!(NatHashKeyExact, dst_port), 4);
        assert_eq!(mem::offset_of!(NatHashKeyExact, protocol), 6);
    }

    #[test]
    fn nat_hash_value_size() {
        assert_eq!(mem::size_of::<NatHashValue>(), 16);
    }

    #[test]
    fn nat_hash_value_alignment() {
        assert_eq!(mem::align_of::<NatHashValue>(), 4);
    }

    #[test]
    fn nat_hash_value_offsets() {
        assert_eq!(mem::offset_of!(NatHashValue, nat_addr), 0);
        assert_eq!(mem::offset_of!(NatHashValue, nat_port_start), 4);
        assert_eq!(mem::offset_of!(NatHashValue, nat_port_end), 6);
        assert_eq!(mem::offset_of!(NatHashValue, nat_type), 8);
        assert_eq!(mem::offset_of!(NatHashValue, protocol), 9);
        assert_eq!(mem::offset_of!(NatHashValue, nat_interface), 12);
    }

    #[test]
    fn nat_match_flags_distinct() {
        let flags = [
            NAT_MATCH_SRC_IP,
            NAT_MATCH_DST_IP,
            NAT_MATCH_DST_PORT,
            NAT_MATCH_PROTO,
        ];
        for (i, &a) in flags.iter().enumerate() {
            for &b in &flags[i + 1..] {
                assert_eq!(a & b, 0, "flags 0x{a:02x} and 0x{b:02x} overlap");
            }
        }
    }
}
