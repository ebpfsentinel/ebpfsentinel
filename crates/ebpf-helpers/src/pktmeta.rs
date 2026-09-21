//! One parse per TCX chain.
//!
//! Every tc classifier on an interface runs on the same `sk_buff`, one after
//! the other, and until this module each of them walked the Ethernet header,
//! the VLAN tags, the IP header and its extension headers, and read the L4
//! ports, then resolved the tenant off the same three maps. Six programs on
//! the ingress chain meant six parses of one packet.
//!
//! The 20 bytes of `skb->cb` the classifier hook exposes survive from one
//! program of a chain to the next, so the first program to parse the packet
//! leaves what it found there and the ones after it read it back. The words
//! are guarded rather than trusted: a magic byte, and a check word folded
//! over the four payload words, the packet length, the interface it is on
//! and the interface it came in by. A locally originated skb carries the
//! transport's own control block in the same bytes, a forwarded one carries
//! what the ingress chain wrote on another device, and either fails the
//! check and is parsed again.
//!
//! A program that rewrites the packet - the two NAT classifiers - calls
//! [`invalidate`] afterwards, so the programs behind it parse the rewritten
//! packet rather than the one that arrived.
//!
//! Layout (each word host order):
//!
//! | word | content |
//! |---|---|
//! | 0 | `MAGIC << 24 \| vlan_id << 12 \| flags << 8 \| proto` |
//! | 1 | `l3_off << 16 \| l4_off` |
//! | 2 | `src_port << 16 \| dst_port` |
//! | 3 | `tenant_id` |
//! | 4 | check word |

use aya_ebpf::programs::TcContext;
use core::mem;
use ebpf_common::event::{FLAG_IPV6, FLAG_VLAN};
use ebpf_common::ipv6::walk_ipv6_ext_headers;
use ebpf_common::vlan::walk_vlan_tags;

use crate::net::{ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, PROTO_TCP, PROTO_UDP};
use crate::tc::ptr_at;

const MAGIC: u32 = 0xEB;
const CHECK_SALT: u32 = 0x5EB0_F5E1;

/// The parse found an IPv4 header.
pub const FLAG_IPV4: u8 = 0x04;
/// The tenant has been resolved by a program earlier in the chain.
pub const FLAG_TENANT: u8 = 0x08;

/// A header offset above this is not a packet this datapath classifies;
/// the mask also keeps the offsets the verifier sees inside the packet
/// pointer's reachable range.
const OFFSET_MASK: u32 = 0x07FF;

/// The four bits of `flags` carried in the control block.
const FLAG_MASK: u8 = FLAG_IPV6 | FLAG_VLAN | FLAG_IPV4 | FLAG_TENANT;

/// Ethernet header length.
const ETH_HLEN: usize = 14;
/// IPv4 fixed header length.
const IPV4_HDR_LEN: usize = 20;

/// What one parse of the packet established.
#[derive(Clone, Copy)]
pub struct PktMeta {
    /// Where the IP header starts.
    pub l3_off: u16,
    /// Where the transport header starts.
    pub l4_off: u16,
    /// Transport protocol (after IPv6 extension headers).
    pub proto: u8,
    /// [`FLAG_IPV4`], [`FLAG_IPV6`], [`FLAG_VLAN`], [`FLAG_TENANT`].
    pub flags: u8,
    /// Outer VLAN identifier, 0 when untagged.
    pub vlan_id: u16,
    /// TCP or UDP source port, 0 otherwise.
    pub src_port: u16,
    /// TCP or UDP destination port, 0 otherwise.
    pub dst_port: u16,
    /// Tenant, meaningful only with [`FLAG_TENANT`].
    pub tenant_id: u32,
}

impl PktMeta {
    #[inline(always)]
    #[must_use]
    pub const fn is_ipv4(&self) -> bool {
        self.flags & FLAG_IPV4 != 0
    }

    #[inline(always)]
    #[must_use]
    pub const fn is_ipv6(&self) -> bool {
        self.flags & FLAG_IPV6 != 0
    }

    /// The `PacketEvent` flag bits this parse decided: VLAN and IPv6.
    #[inline(always)]
    #[must_use]
    pub const fn event_flags(&self) -> u8 {
        self.flags & (FLAG_IPV6 | FLAG_VLAN)
    }

    /// The tenant a program earlier in the chain resolved, if any.
    #[inline(always)]
    #[must_use]
    pub const fn tenant(&self) -> Option<u32> {
        if self.flags & FLAG_TENANT != 0 {
            Some(self.tenant_id)
        } else {
            None
        }
    }

    /// Offsets as the packet helpers take them.
    #[inline(always)]
    #[must_use]
    pub const fn l3(&self) -> usize {
        self.l3_off as usize
    }

    #[inline(always)]
    #[must_use]
    pub const fn l4(&self) -> usize {
        self.l4_off as usize
    }
}

#[inline(always)]
fn check_word(ctx: &TcContext, w: [u32; 4]) -> u32 {
    let skb = ctx.skb.skb;
    // SAFETY: `skb` is the live `__sk_buff` of this invocation; the three
    // fields are readable by a classifier.
    let (len, ifindex, ingress) =
        unsafe { ((*skb).len, (*skb).ifindex, (*skb).ingress_ifindex) };
    w[0] ^ w[1] ^ w[2] ^ w[3] ^ len ^ ifindex.rotate_left(8) ^ ingress.rotate_left(16) ^ CHECK_SALT
}

#[inline(always)]
fn pack(meta: &PktMeta) -> [u32; 4] {
    [
        (MAGIC << 24)
            | (u32::from(meta.vlan_id & 0x0FFF) << 12)
            | (u32::from(meta.flags & FLAG_MASK) << 8)
            | u32::from(meta.proto),
        (u32::from(meta.l3_off) << 16) | u32::from(meta.l4_off),
        (u32::from(meta.src_port) << 16) | u32::from(meta.dst_port),
        meta.tenant_id,
    ]
}

/// Read back what a program earlier in the chain left, if the words pass
/// the check.
#[inline(always)]
#[must_use]
pub fn read_cb(ctx: &TcContext) -> Option<PktMeta> {
    let skb = ctx.skb.skb;
    // SAFETY: `cb` is a readable field of the classifier's `__sk_buff`.
    let w = unsafe { (*skb).cb };
    if w[0] >> 24 != MAGIC {
        return None;
    }
    if w[4] != check_word(ctx, [w[0], w[1], w[2], w[3]]) {
        return None;
    }
    Some(PktMeta {
        l3_off: ((w[1] >> 16) & OFFSET_MASK) as u16,
        l4_off: (w[1] & OFFSET_MASK) as u16,
        proto: (w[0] & 0xFF) as u8,
        flags: ((w[0] >> 8) & 0xFF) as u8 & FLAG_MASK,
        vlan_id: ((w[0] >> 12) & 0x0FFF) as u16,
        src_port: (w[2] >> 16) as u16,
        dst_port: (w[2] & 0xFFFF) as u16,
        tenant_id: w[3],
    })
}

/// Leave the parse in the control block for the programs behind this one.
#[inline(always)]
pub fn write_cb(ctx: &TcContext, meta: &PktMeta) {
    let w = pack(meta);
    let check = check_word(ctx, w);
    let skb = ctx.skb.skb;
    // SAFETY: `cb` is writable by a classifier, and nothing else in the
    // chain owns it.
    unsafe {
        (*skb).cb[0] = w[0];
        (*skb).cb[1] = w[1];
        (*skb).cb[2] = w[2];
        (*skb).cb[3] = w[3];
        (*skb).cb[4] = check;
    }
}

/// Drop what is in the control block, so the next program parses the
/// packet again. Called after a rewrite.
#[inline(always)]
pub fn invalidate(ctx: &TcContext) {
    let skb = ctx.skb.skb;
    // SAFETY: as in [`write_cb`].
    unsafe {
        (*skb).cb[0] = 0;
        (*skb).cb[4] = 0;
    }
}

/// Record the tenant this program resolved, for the programs behind it.
/// The tenant is keyed on the interface, the VLAN and the source address,
/// none of which a program in the chain changes without invalidating.
#[inline(always)]
pub fn write_tenant(ctx: &TcContext, tenant_id: u32) {
    let skb = ctx.skb.skb;
    // SAFETY: as in [`read_cb`] and [`write_cb`].
    let w = unsafe { (*skb).cb };
    if w[0] >> 24 != MAGIC {
        return;
    }
    let w0 = w[0] | (u32::from(FLAG_TENANT) << 8);
    let check = check_word(ctx, [w0, w[1], w[2], tenant_id]);
    unsafe {
        (*skb).cb[0] = w0;
        (*skb).cb[3] = tenant_id;
        (*skb).cb[4] = check;
    }
}

/// Parse the packet: Ethernet, up to two VLAN tags, IPv4 or IPv6 with its
/// extension headers, and the TCP or UDP ports. A frame that is neither
/// IPv4 nor IPv6 parses to a meta with neither flag, so the chain agrees
/// on it once. A truncated frame is `Err`, which every classifier treats
/// as a pass.
#[inline(always)]
pub fn parse(ctx: &TcContext) -> Result<PktMeta, ()> {
    let mut meta = PktMeta {
        l3_off: 0,
        l4_off: 0,
        proto: 0,
        flags: 0,
        vlan_id: 0,
        src_port: 0,
        dst_port: 0,
        tenant_id: 0,
    };

    // SAFETY: bounds-checked against the packet window.
    let ether_type_ptr: *const [u8; 2] = unsafe { ptr_at(ctx, 12)? };
    let ether_type = u16::from_be_bytes(unsafe { *ether_type_ptr });

    // SAFETY: `data()..data_end()` is the readable packet window.
    let walk = unsafe { walk_vlan_tags(ctx.data(), ctx.data_end(), ether_type, ETH_HLEN) }
        .ok_or(())?;
    if walk.tagged {
        meta.flags |= FLAG_VLAN;
        meta.vlan_id = walk.vlan_id;
    }
    let l3 = walk.l3_offset;
    meta.l3_off = l3 as u16;

    let l4 = if walk.ether_type == ETH_P_IP {
        // Version/IHL byte and the protocol byte of the IPv4 header.
        let vihl: *const u8 = unsafe { ptr_at(ctx, l3)? };
        let proto: *const u8 = unsafe { ptr_at(ctx, l3 + 9)? };
        let ihl = ((unsafe { *vihl } & 0x0F) as usize) << 2;
        if ihl < IPV4_HDR_LEN {
            return Err(());
        }
        meta.flags |= FLAG_IPV4;
        meta.proto = unsafe { *proto };
        l3 + ihl
    } else if walk.ether_type == ETH_P_IPV6 {
        let next_hdr: *const u8 = unsafe { ptr_at(ctx, l3 + 6)? };
        let (proto, l4) = unsafe {
            walk_ipv6_ext_headers(ctx.data(), ctx.data_end(), l3 + IPV6_HDR_LEN, *next_hdr)
        }
        .ok_or(())?;
        meta.flags |= FLAG_IPV6;
        meta.proto = proto;
        l4
    } else {
        return Ok(meta);
    };
    meta.l4_off = l4 as u16;

    if meta.proto == PROTO_TCP || meta.proto == PROTO_UDP {
        // Both headers start with the two ports; a frame cut before them
        // keeps 0/0, exactly what the classifiers read off a port-less
        // protocol.
        if let Ok(ports) = unsafe { ptr_at::<[u8; 4]>(ctx, l4) } {
            let p = unsafe { *ports };
            meta.src_port = u16::from_be_bytes([p[0], p[1]]);
            meta.dst_port = u16::from_be_bytes([p[2], p[3]]);
        }
    }
    Ok(meta)
}

/// What the chain knows about this packet: read back if a program before
/// this one parsed it, parsed and left for the next one otherwise.
#[inline(always)]
pub fn resolve(ctx: &TcContext) -> Result<PktMeta, ()> {
    if let Some(meta) = read_cb(ctx) {
        return Ok(meta);
    }
    let meta = parse(ctx)?;
    write_cb(ctx, &meta);
    Ok(meta)
}

const _: () = assert!(mem::size_of::<PktMeta>() == 16);
