//! Network header structs, Ethernet constants, and byte conversion helpers.

// ── Ethernet constants ──────────────────────────────────────────────

/// IPv4 `EtherType`.
pub const ETH_P_IP: u16 = 0x0800;
/// IPv6 `EtherType`.
pub const ETH_P_IPV6: u16 = 0x86DD;
/// 802.1Q VLAN `EtherType`.
pub const ETH_P_8021Q: u16 = 0x8100;
/// 802.1ad (QinQ) `EtherType`.
pub const ETH_P_8021AD: u16 = 0x88A8;

/// Size of an 802.1Q VLAN tag in bytes.
pub const VLAN_HDR_LEN: usize = 4;
/// Size of the IPv6 fixed header in bytes.
pub const IPV6_HDR_LEN: usize = 40;

/// IP protocol number for TCP.
pub const PROTO_TCP: u8 = 6;
/// IP protocol number for UDP.
pub const PROTO_UDP: u8 = 17;
/// IP protocol number for ICMP.
pub const PROTO_ICMP: u8 = 1;
/// IP protocol number for ICMPv6.
pub const PROTO_ICMPV6: u8 = 58;

// ── Inline header structs ───────────────────────────────────────────

/// IPv6 fixed header (40 bytes).
#[repr(C)]
pub struct Ipv6Hdr {
    pub _vtcfl: u32,
    pub _payload_len: u16,
    pub next_hdr: u8,
    pub hop_limit: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

/// 802.1Q VLAN tag (4 bytes after `EthHdr` when `ether_type` == 0x8100).
#[repr(C)]
pub struct VlanHdr {
    pub tci: u16,
    pub ether_type: u16,
}

/// ICMP fixed header (8 bytes: type, code, checksum, rest-of-header).
#[repr(C)]
pub struct IcmpHdr {
    pub r#type: u8,
    pub code: u8,
    pub _checksum: u16,
    pub _rest: u32,
}

// ── Byte conversion helpers ─────────────────────────────────────────

/// Convert 4 big-endian bytes to a `u32`.
#[inline(always)]
pub fn u32_from_be_bytes(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
}

/// Convert 2 big-endian bytes to a `u16`.
#[inline(always)]
pub fn u16_from_be_bytes(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

/// Convert a 16-byte IPv6 address to `[u32; 4]` in network byte order.
#[inline(always)]
pub fn ipv6_addr_to_u32x4(addr: &[u8; 16]) -> [u32; 4] {
    [
        u32_from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32_from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
        u32_from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
        u32_from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
    ]
}

/// Convert `[u32; 4]` to 16 bytes in network byte order.
#[inline(always)]
pub fn u32x4_to_bytes(words: &[u32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let mut w = 0usize;
    while w < 4 {
        let b = words[w].to_be_bytes();
        bytes[w * 4] = b[0];
        bytes[w * 4 + 1] = b[1];
        bytes[w * 4 + 2] = b[2];
        bytes[w * 4 + 3] = b[3];
        w += 1;
    }
    bytes
}

/// Convert `[u32; 4]` to 16-byte IPv6 address (alias for [`u32x4_to_bytes`]).
#[inline(always)]
pub fn u32x4_to_ipv6_bytes(addr: &[u32; 4]) -> [u8; 16] {
    u32x4_to_bytes(addr)
}

/// Per-word masked comparison of IPv6 addresses.
///
/// Returns `true` if `(addr[i] & mask[i]) == match_addr[i]` for all words.
#[inline(always)]
pub fn ipv6_mask_match(addr: &[u32; 4], match_addr: &[u32; 4], mask: &[u32; 4]) -> bool {
    let mut w = 0usize;
    while w < 4 {
        if (addr[w] & mask[w]) != match_addr[w] {
            return false;
        }
        w += 1;
    }
    true
}

// ── NPTv6 helpers ─────────────────────────────────────────────────

/// Ones' complement addition of two 16-bit values (RFC 1071).
/// Used by NPTv6 prefix translation for checksum-neutral address mapping.
#[inline(always)]
pub fn ones_complement_add(a: u16, b: u16) -> u16 {
    let sum = a as u32 + b as u32;
    let folded = (sum & 0xFFFF) + (sum >> 16);
    folded as u16
}

/// Build an IPv6 prefix mask from `prefix_len` (0-128) as `[u32; 4]`.
/// Each u32 is in host byte order. Bounded loop (max 4 iterations).
#[inline(always)]
pub fn prefix_to_mask(prefix_len: u8) -> [u32; 4] {
    let mut mask = [0u32; 4];
    let mut remaining = prefix_len as u32;
    let mut i = 0usize;
    while i < 4 {
        if remaining >= 32 {
            mask[i] = 0xFFFF_FFFF;
            remaining -= 32;
        } else if remaining > 0 {
            mask[i] = !((1u32 << (32 - remaining)) - 1);
            remaining = 0;
        }
        i += 1;
    }
    mask
}
