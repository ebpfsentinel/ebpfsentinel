#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::{bpf_l3_csum_replace, bpf_l4_csum_replace, bpf_skb_store_bytes},
    macros::{classifier, map},
    maps::{Array, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use core::mem;
use ebpf_common::{
    conntrack::{
        ConnKey, ConnKeyV6, ConnValue, ConnValueV6, CT_FLAG_NAT_DST, CT_MAX_ENTRIES_V4,
        CT_MAX_ENTRIES_V6, normalize_key_v4, normalize_key_v6,
    },
    nat::{
        MAX_NAT_RULES, MAX_NAT_RULES_V6, NAT_MATCH_DST_IP, NAT_MATCH_DST_PORT, NAT_MATCH_PROTO,
        NAT_MATCH_SRC_IP, NAT_METRIC_COUNT, NAT_METRIC_DNAT_APPLIED, NAT_METRIC_ERRORS,
        NAT_TYPE_DNAT, NAT_TYPE_ONETOONE, NAT_TYPE_REDIRECT, NatRuleEntry, NatRuleEntryV6,
    },
};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const VLAN_HDR_LEN: usize = 4;
const IPV6_HDR_LEN: usize = 40;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// Offset of dst_addr within Ipv4Hdr (standard IP header).
const IPV4_DST_OFFSET: usize = 16;
/// Offset of IP header checksum within Ipv4Hdr.
const IPV4_CSUM_OFFSET: usize = 10;
/// Offset of dst_addr within IPv6 header.
const IPV6_DST_OFFSET: usize = 24;

/// BPF_F_RECOMPUTE_CSUM flag (unused for raw csum replace).
const BPF_F_RECOMPUTE_CSUM: u64 = 1;

// ── Inline header types ─────────────────────────────────────────────

#[repr(C)]
struct VlanHdr {
    tci: u16,
    ether_type: u16,
}

/// IPv6 fixed header (40 bytes).
#[repr(C)]
struct Ipv6Hdr {
    _vtcfl: u32,
    _payload_len: u16,
    next_hdr: u8,
    _hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

// ── Maps ────────────────────────────────────────────────────────────

/// DNAT rules (scanned linearly, priority order).
#[map]
static NAT_DNAT_RULES: Array<NatRuleEntry> = Array::with_max_entries(MAX_NAT_RULES, 0);

/// Number of active DNAT rules.
#[map]
static NAT_DNAT_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// IPv6 DNAT rules.
#[map]
static NAT_DNAT_RULES_V6: Array<NatRuleEntryV6> = Array::with_max_entries(MAX_NAT_RULES_V6, 0);

/// Number of active IPv6 DNAT rules.
#[map]
static NAT_DNAT_RULE_COUNT_V6: Array<u32> = Array::with_max_entries(1, 0);

/// Shared conntrack table (pinned, same as tc-conntrack).
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 0);

/// Shared IPv6 conntrack table.
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValueV6> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 0);

/// Per-CPU NAT metrics.
#[map]
static NAT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(NAT_METRIC_COUNT, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_nat_ingress(ctx: TcContext) -> i32 {
    match try_nat_ingress(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(NAT_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = NAT_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

#[inline(always)]
fn u32_from_be_bytes(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
}

#[inline(always)]
fn u16_from_be_bytes(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Convert 16 raw bytes to `[u32; 4]` (network byte order words).
#[inline(always)]
fn ipv6_addr_to_u32x4(bytes: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    ]
}

// ── Processing ──────────────────────────────────────────────────────

#[inline(always)]
fn try_nat_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
    }

    if ether_type == ETH_P_IP {
        process_dnat_v4(ctx, l3_offset)
    } else if ether_type == ETH_P_IPV6 {
        process_dnat_v6(ctx, l3_offset)
    } else {
        Ok(TC_ACT_OK)
    }
}

#[inline(always)]
fn process_dnat_v4(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto } as u8;

    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    let (src_port, dst_port) = match protocol {
        PROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
            )
        }
        PROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
            )
        }
        _ => return Ok(TC_ACT_OK),
    };

    // Check existing conntrack entry for cached NAT mapping.
    let ct_key = normalize_key_v4(src_ip, dst_ip, src_port, dst_port, protocol);
    if let Some(ct_entry) = unsafe { CT_TABLE_V4.get(&ct_key) } {
        if ct_entry.flags & CT_FLAG_NAT_DST != 0 && ct_entry.nat_addr != 0 {
            // Apply cached DNAT: rewrite destination IP (and port if set).
            rewrite_dst_ip(ctx, l3_offset, l4_offset, protocol, dst_ip, ct_entry.nat_addr)?;
            if ct_entry.nat_port != 0 {
                rewrite_dst_port(ctx, l4_offset, protocol, dst_port, ct_entry.nat_port)?;
            }
            increment_metric(NAT_METRIC_DNAT_APPLIED);
            return Ok(TC_ACT_OK);
        }
    }

    // Scan DNAT rules for new connections.
    let count = match NAT_DNAT_RULE_COUNT.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let max = if count > MAX_NAT_RULES { MAX_NAT_RULES } else { count };
    let mut i = 0u32;
    while i < max {
        if let Some(rule) = NAT_DNAT_RULES.get(i) {
            if match_nat_rule(rule, src_ip, dst_ip, dst_port, protocol) {
                let new_dst_ip = match rule.nat_type {
                    NAT_TYPE_DNAT | NAT_TYPE_ONETOONE => rule.nat_addr,
                    NAT_TYPE_REDIRECT => src_ip, // Redirect to self
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                let new_dst_port = if rule.nat_port_start != 0 {
                    rule.nat_port_start
                } else {
                    dst_port
                };

                // Rewrite packet
                rewrite_dst_ip(ctx, l3_offset, l4_offset, protocol, dst_ip, new_dst_ip)?;
                if new_dst_port != dst_port {
                    rewrite_dst_port(ctx, l4_offset, protocol, dst_port, new_dst_port)?;
                }

                // Update conntrack entry with NAT mapping so subsequent
                // packets of this connection use the cached path.
                if let Some(ct_entry) = CT_TABLE_V4.get_ptr_mut(&ct_key) {
                    unsafe {
                        (*ct_entry).nat_addr = new_dst_ip;
                        (*ct_entry).nat_port = new_dst_port;
                        (*ct_entry).flags |= CT_FLAG_NAT_DST;
                        (*ct_entry).nat_type = NAT_TYPE_DNAT;
                    }
                }

                increment_metric(NAT_METRIC_DNAT_APPLIED);
                return Ok(TC_ACT_OK);
            }
        }
        i += 1;
    }

    Ok(TC_ACT_OK)
}

/// IPv6 DNAT processing.
#[inline(never)]
fn process_dnat_v6(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let protocol = unsafe { (*ipv6hdr).next_hdr };

    let l4_offset = l3_offset + IPV6_HDR_LEN;

    let (src_port, dst_port) = match protocol {
        PROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
            )
        }
        PROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
            )
        }
        _ => return Ok(TC_ACT_OK),
    };

    // Check existing conntrack entry for cached NAT mapping.
    let ct_key = normalize_key_v6(&src_addr, &dst_addr, src_port, dst_port, protocol);
    // Pre-compute offsets for V6 rewriting (5-arg BPF limit).
    let ipv6_dst_off = (l3_offset + IPV6_DST_OFFSET) as u32;
    let l4_csum_off = match protocol {
        PROTO_TCP => (l4_offset + 16) as u32,
        PROTO_UDP => (l4_offset + 6) as u32,
        _ => 0u32,
    };

    if let Some(ct_entry) = unsafe { CT_TABLE_V6.get(&ct_key) } {
        if ct_entry.flags & CT_FLAG_NAT_DST != 0 && ct_entry.nat_addr != [0; 4] {
            rewrite_dst_ip_v6(ctx, ipv6_dst_off, l4_csum_off, &dst_addr, &ct_entry.nat_addr)?;
            if ct_entry.nat_port != 0 {
                rewrite_dst_port(ctx, l4_offset, protocol, dst_port, ct_entry.nat_port)?;
            }
            increment_metric(NAT_METRIC_DNAT_APPLIED);
            return Ok(TC_ACT_OK);
        }
    }

    // Scan IPv6 DNAT rules.
    let count = match NAT_DNAT_RULE_COUNT_V6.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let max = if count > MAX_NAT_RULES_V6 {
        MAX_NAT_RULES_V6
    } else {
        count
    };
    let mut i = 0u32;
    while i < max {
        if let Some(rule) = NAT_DNAT_RULES_V6.get(i) {
            if match_nat_rule_v6(rule, &src_addr, &dst_addr, dst_port, protocol) {
                let new_dst_addr = match rule.nat_type {
                    NAT_TYPE_DNAT | NAT_TYPE_ONETOONE => rule.nat_addr,
                    NAT_TYPE_REDIRECT => src_addr,
                    _ => {
                        i += 1;
                        continue;
                    }
                };
                let new_dst_port = if rule.nat_port_start != 0 {
                    rule.nat_port_start
                } else {
                    dst_port
                };

                rewrite_dst_ip_v6(ctx, ipv6_dst_off, l4_csum_off, &dst_addr, &new_dst_addr)?;
                if new_dst_port != dst_port {
                    rewrite_dst_port(ctx, l4_offset, protocol, dst_port, new_dst_port)?;
                }

                if let Some(ct_entry) = CT_TABLE_V6.get_ptr_mut(&ct_key) {
                    unsafe {
                        (*ct_entry).nat_addr = new_dst_addr;
                        (*ct_entry).nat_port = new_dst_port;
                        (*ct_entry).flags |= CT_FLAG_NAT_DST;
                        (*ct_entry).nat_type = NAT_TYPE_DNAT;
                    }
                }

                increment_metric(NAT_METRIC_DNAT_APPLIED);
                return Ok(TC_ACT_OK);
            }
        }
        i += 1;
    }

    Ok(TC_ACT_OK)
}

/// Rewrite the destination IP address in the IPv4 header and update checksums.
#[inline(always)]
fn rewrite_dst_ip(
    ctx: &TcContext,
    l3_offset: usize,
    l4_offset: usize,
    protocol: u8,
    old_ip: u32,
    new_ip: u32,
) -> Result<(), ()> {
    if old_ip == new_ip {
        return Ok(());
    }

    let old_be = old_ip.to_be_bytes();
    let new_be = new_ip.to_be_bytes();

    // Write new destination IP into the packet.
    let dst_off = (l3_offset + IPV4_DST_OFFSET) as u32;
    let ret = unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            dst_off,
            new_be.as_ptr() as *const _,
            4,
            BPF_F_RECOMPUTE_CSUM,
        )
    };
    if ret != 0 {
        return Err(());
    }

    // Update IP header checksum (incremental).
    let ip_csum_off = (l3_offset + IPV4_CSUM_OFFSET) as u32;
    let ret = unsafe {
        bpf_l3_csum_replace(
            ctx.skb.skb as *mut _,
            ip_csum_off,
            u32::from_be_bytes(old_be) as u64,
            u32::from_be_bytes(new_be) as u64,
            4,
        )
    };
    if ret != 0 {
        return Err(());
    }

    // Update L4 checksum (TCP/UDP pseudo-header includes IP addresses).
    let l4_csum_off = match protocol {
        PROTO_TCP => l4_offset + 16, // TCP checksum at offset 16
        PROTO_UDP => l4_offset + 6,  // UDP checksum at offset 6
        _ => return Ok(()),
    } as u32;

    let ret = unsafe {
        bpf_l4_csum_replace(
            ctx.skb.skb as *mut _,
            l4_csum_off,
            u32::from_be_bytes(old_be) as u64,
            u32::from_be_bytes(new_be) as u64,
            4,  // BPF_F_PSEUDO_HDR is 0x10, but 4 = size of the field
        )
    };
    if ret != 0 {
        return Err(());
    }

    Ok(())
}

/// Rewrite the destination IPv6 address and update L4 pseudo-header checksum.
/// IPv6 has no header checksum, so only L4 checksum needs updating.
///
/// `dst_off` = absolute offset of IPv6 dst addr in packet.
/// `l4_csum_off` = absolute offset of L4 checksum field (0 = skip L4 update).
#[inline(always)]
fn rewrite_dst_ip_v6(
    ctx: &TcContext,
    dst_off: u32,
    l4_csum_off: u32,
    old_addr: &[u32; 4],
    new_addr: &[u32; 4],
) -> Result<(), ()> {
    if old_addr == new_addr {
        return Ok(());
    }

    let new_bytes = u32x4_to_bytes(new_addr);
    let ret = unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            dst_off,
            new_bytes.as_ptr() as *const _,
            16,
            BPF_F_RECOMPUTE_CSUM,
        )
    };
    if ret != 0 {
        return Err(());
    }

    if l4_csum_off == 0 {
        return Ok(());
    }

    let mut w = 0usize;
    while w < 4 {
        let old_w = old_addr[w];
        let new_w = new_addr[w];
        if old_w != new_w {
            let ret = unsafe {
                bpf_l4_csum_replace(
                    ctx.skb.skb as *mut _,
                    l4_csum_off,
                    old_w as u64,
                    new_w as u64,
                    4,
                )
            };
            if ret != 0 {
                return Err(());
            }
        }
        w += 1;
    }

    Ok(())
}

/// Rewrite the destination port and update L4 checksum.
#[inline(always)]
fn rewrite_dst_port(
    ctx: &TcContext,
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    if old_port == new_port {
        return Ok(());
    }

    // Destination port offset within L4 header (TCP and UDP both at offset 2).
    let port_off = (l4_offset + 2) as u32;
    let new_be = new_port.to_be_bytes();
    let ret = unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            port_off,
            new_be.as_ptr() as *const _,
            2,
            BPF_F_RECOMPUTE_CSUM,
        )
    };
    if ret != 0 {
        return Err(());
    }

    // Update L4 checksum.
    let l4_csum_off = match protocol {
        PROTO_TCP => l4_offset + 16,
        PROTO_UDP => l4_offset + 6,
        _ => return Ok(()),
    } as u32;

    let ret = unsafe {
        bpf_l4_csum_replace(
            ctx.skb.skb as *mut _,
            l4_csum_off,
            old_port as u64,
            new_port as u64,
            2,
        )
    };
    if ret != 0 {
        return Err(());
    }

    Ok(())
}

/// Check if a NAT rule matches the packet (IPv4).
#[inline(always)]
fn match_nat_rule(
    rule: &NatRuleEntry,
    src_ip: u32,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) -> bool {
    let flags = rule.match_flags;

    if (flags & NAT_MATCH_PROTO) != 0 && rule.match_protocol != protocol {
        return false;
    }
    if (flags & NAT_MATCH_SRC_IP) != 0 && (src_ip & rule.match_src_mask) != rule.match_src_ip {
        return false;
    }
    if (flags & NAT_MATCH_DST_IP) != 0 && (dst_ip & rule.match_dst_mask) != rule.match_dst_ip {
        return false;
    }
    if (flags & NAT_MATCH_DST_PORT) != 0
        && (dst_port < rule.match_dst_port_start || dst_port > rule.match_dst_port_end)
    {
        return false;
    }

    true
}

/// Check if an IPv6 NAT rule matches the packet.
#[inline(never)]
fn match_nat_rule_v6(
    rule: &NatRuleEntryV6,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    dst_port: u16,
    protocol: u8,
) -> bool {
    let flags = rule.match_flags;

    if (flags & NAT_MATCH_PROTO) != 0 && rule.match_protocol != protocol {
        return false;
    }
    if (flags & NAT_MATCH_SRC_IP) != 0 && !ipv6_mask_match(src_addr, &rule.match_src_addr, &rule.match_src_mask) {
        return false;
    }
    if (flags & NAT_MATCH_DST_IP) != 0 && !ipv6_mask_match(dst_addr, &rule.match_dst_addr, &rule.match_dst_mask) {
        return false;
    }
    if (flags & NAT_MATCH_DST_PORT) != 0
        && (dst_port < rule.match_dst_port_start || dst_port > rule.match_dst_port_end)
    {
        return false;
    }

    true
}

/// Per-word masked comparison of IPv6 addresses.
#[inline(always)]
fn ipv6_mask_match(addr: &[u32; 4], match_addr: &[u32; 4], mask: &[u32; 4]) -> bool {
    let mut w = 0usize;
    while w < 4 {
        if (addr[w] & mask[w]) != match_addr[w] {
            return false;
        }
        w += 1;
    }
    true
}

/// Convert `[u32; 4]` to 16 bytes in network byte order.
#[inline(always)]
fn u32x4_to_bytes(words: &[u32; 4]) -> [u8; 16] {
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

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
