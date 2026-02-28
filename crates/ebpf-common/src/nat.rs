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

// ── NAT metric indices ──────────────────────────────────────────────

pub const NAT_METRIC_SNAT_APPLIED: u32 = 0;
pub const NAT_METRIC_DNAT_APPLIED: u32 = 1;
pub const NAT_METRIC_MASQ_APPLIED: u32 = 2;
pub const NAT_METRIC_PORT_ALLOC_FAIL: u32 = 3;
pub const NAT_METRIC_ERRORS: u32 = 4;
pub const NAT_METRIC_COUNT: u32 = 8;

// ── NAT match flags ─────────────────────────────────────────────────

pub const NAT_MATCH_SRC_IP: u8 = 0x01;
pub const NAT_MATCH_DST_IP: u8 = 0x02;
pub const NAT_MATCH_DST_PORT: u8 = 0x04;
pub const NAT_MATCH_PROTO: u8 = 0x08;

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
    pub _pad2: [u8; 4],
}

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
unsafe impl aya::Pod for NatPortAllocKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for NatPortAllocValue {}

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
        ];
        for (i, &a) in types.iter().enumerate() {
            for &b in &types[i + 1..] {
                assert_ne!(a, b, "NAT types {a} and {b} collide");
            }
        }
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
