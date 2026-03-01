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
        ConnKey, ConnKeyV6, ConnValue, ConnValueV6, CT_FLAG_NAT_SRC, CT_MAX_ENTRIES_V4,
        CT_MAX_ENTRIES_V6, normalize_key_v4, normalize_key_v6,
    },
    nat::{
        MAX_NAT_PORT_ALLOC, MAX_NAT_RULES, MAX_NAT_RULES_V6, NAT_MATCH_DST_IP, NAT_MATCH_PROTO,
        NAT_MATCH_SRC_IP, NAT_METRIC_COUNT, NAT_METRIC_ERRORS, NAT_METRIC_MASQ_APPLIED,
        NAT_METRIC_SNAT_APPLIED, NAT_METRIC_TOTAL_SEEN, NAT_TYPE_MASQUERADE, NAT_TYPE_SNAT,
        NatPortAllocKey, NatPortAllocValue, NatRuleEntry, NatRuleEntryV6,
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

/// Offset of src_addr within Ipv4Hdr (standard IP header).
const IPV4_SRC_OFFSET: usize = 12;
/// Offset of IP header checksum within Ipv4Hdr.
const IPV4_CSUM_OFFSET: usize = 10;
/// Offset of src_addr within IPv6 header.
const IPV6_SRC_OFFSET: usize = 8;

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

/// SNAT rules (scanned linearly, priority order).
#[map]
static NAT_SNAT_RULES: Array<NatRuleEntry> = Array::with_max_entries(MAX_NAT_RULES, 0);

/// Number of active SNAT rules.
#[map]
static NAT_SNAT_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// IPv6 SNAT rules.
#[map]
static NAT_SNAT_RULES_V6: Array<NatRuleEntryV6> = Array::with_max_entries(MAX_NAT_RULES_V6, 0);

/// Number of active IPv6 SNAT rules.
#[map]
static NAT_SNAT_RULE_COUNT_V6: Array<u32> = Array::with_max_entries(1, 0);

/// Shared conntrack table (pinned, same as tc-conntrack).
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 0);

/// Shared IPv6 conntrack table.
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValueV6> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 0);

/// NAT port allocation table (LRU): tracks which translated port is
/// assigned for each original (addr, port) pair.
#[map]
static NAT_PORT_ALLOC: LruHashMap<NatPortAllocKey, NatPortAllocValue> =
    LruHashMap::with_max_entries(MAX_NAT_PORT_ALLOC, 0);

/// Per-CPU NAT metrics.
#[map]
static NAT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(NAT_METRIC_COUNT, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_nat_egress(ctx: TcContext) -> i32 {
    increment_metric(NAT_METRIC_TOTAL_SEEN);
    match try_nat_egress(&ctx) {
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
fn try_nat_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
    }

    if ether_type == ETH_P_IP {
        process_snat_v4(ctx, l3_offset)
    } else if ether_type == ETH_P_IPV6 {
        process_snat_v6(ctx, l3_offset)
    } else {
        Ok(TC_ACT_OK)
    }
}

#[inline(always)]
fn process_snat_v4(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
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

    // Check existing conntrack entry for cached SNAT mapping.
    let ct_key = normalize_key_v4(src_ip, dst_ip, src_port, dst_port, protocol);
    if let Some(ct_entry) = unsafe { CT_TABLE_V4.get(&ct_key) } {
        if ct_entry.flags & CT_FLAG_NAT_SRC != 0 && ct_entry.nat_addr != 0 {
            // Apply cached SNAT: rewrite source IP (and port if set).
            rewrite_src_ip(ctx, l3_offset, l4_offset, protocol, src_ip, ct_entry.nat_addr)?;
            if ct_entry.nat_port != 0 && ct_entry.nat_port != src_port {
                rewrite_src_port(ctx, l4_offset, protocol, src_port, ct_entry.nat_port)?;
            }
            increment_metric(NAT_METRIC_SNAT_APPLIED);
            return Ok(TC_ACT_OK);
        }
    }

    // Scan SNAT rules for new connections.
    let count = match NAT_SNAT_RULE_COUNT.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let max = if count > MAX_NAT_RULES { MAX_NAT_RULES } else { count };
    let mut i = 0u32;
    while i < max {
        if let Some(rule) = NAT_SNAT_RULES.get(i) {
            if match_snat_rule(rule, src_ip, dst_ip, protocol) {
                let new_src_ip = rule.nat_addr;
                if new_src_ip == 0 && rule.nat_type != NAT_TYPE_MASQUERADE {
                    // No translation address configured, skip.
                    i += 1;
                    continue;
                }

                // Allocate a translated port (or use original).
                let new_src_port = if rule.nat_port_start != 0 {
                    allocate_port(src_ip, src_port, rule.nat_port_start, rule.nat_port_end)
                } else {
                    src_port
                };

                // For masquerade, use the configured nat_addr (set by userspace
                // to the interface's IP). A full implementation would use
                // bpf_fib_lookup to discover the egress IP, but that requires
                // the full fib_lookup struct which is complex in eBPF.
                let translated_ip = if rule.nat_type == NAT_TYPE_MASQUERADE && new_src_ip == 0 {
                    // Masquerade fallback: userspace must pre-populate nat_addr
                    // with the interface IP. If not set, skip this rule.
                    i += 1;
                    continue;
                } else {
                    new_src_ip
                };

                // Rewrite packet.
                rewrite_src_ip(ctx, l3_offset, l4_offset, protocol, src_ip, translated_ip)?;
                if new_src_port != src_port {
                    rewrite_src_port(ctx, l4_offset, protocol, src_port, new_src_port)?;
                }

                // Store NAT mapping in conntrack.
                if let Some(ct_entry) = CT_TABLE_V4.get_ptr_mut(&ct_key) {
                    unsafe {
                        (*ct_entry).nat_addr = translated_ip;
                        (*ct_entry).nat_port = new_src_port;
                        (*ct_entry).flags |= CT_FLAG_NAT_SRC;
                        (*ct_entry).nat_type = NAT_TYPE_SNAT;
                    }
                }

                if rule.nat_type == NAT_TYPE_MASQUERADE {
                    increment_metric(NAT_METRIC_MASQ_APPLIED);
                } else {
                    increment_metric(NAT_METRIC_SNAT_APPLIED);
                }
                return Ok(TC_ACT_OK);
            }
        }
        i += 1;
    }

    Ok(TC_ACT_OK)
}

/// IPv6 SNAT processing.
#[inline(never)]
fn process_snat_v6(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
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

    // Pre-compute offsets for V6 rewriting (5-arg BPF limit).
    let ipv6_src_off = (l3_offset + IPV6_SRC_OFFSET) as u32;
    let l4_csum_off = match protocol {
        PROTO_TCP => (l4_offset + 16) as u32,
        PROTO_UDP => (l4_offset + 6) as u32,
        _ => 0u32,
    };

    // Check existing conntrack entry for cached SNAT mapping.
    let ct_key = normalize_key_v6(&src_addr, &dst_addr, src_port, dst_port, protocol);
    if let Some(ct_entry) = unsafe { CT_TABLE_V6.get(&ct_key) } {
        if ct_entry.flags & CT_FLAG_NAT_SRC != 0 && ct_entry.nat_addr != [0; 4] {
            rewrite_src_ip_v6(ctx, ipv6_src_off, l4_csum_off, &src_addr, &ct_entry.nat_addr)?;
            if ct_entry.nat_port != 0 && ct_entry.nat_port != src_port {
                rewrite_src_port(ctx, l4_offset, protocol, src_port, ct_entry.nat_port)?;
            }
            increment_metric(NAT_METRIC_SNAT_APPLIED);
            return Ok(TC_ACT_OK);
        }
    }

    // Scan IPv6 SNAT rules.
    let count = match NAT_SNAT_RULE_COUNT_V6.get(0) {
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
        if let Some(rule) = NAT_SNAT_RULES_V6.get(i) {
            if match_snat_rule_v6(rule, &src_addr, &dst_addr, protocol) {
                let new_src_addr = rule.nat_addr;
                if new_src_addr == [0; 4] && rule.nat_type != NAT_TYPE_MASQUERADE {
                    i += 1;
                    continue;
                }

                let new_src_port = if rule.nat_port_start != 0 {
                    allocate_port_v6(&src_addr, src_port, rule.nat_port_start, rule.nat_port_end)
                } else {
                    src_port
                };

                let translated_addr = if rule.nat_type == NAT_TYPE_MASQUERADE && new_src_addr == [0; 4] {
                    i += 1;
                    continue;
                } else {
                    new_src_addr
                };

                rewrite_src_ip_v6(ctx, ipv6_src_off, l4_csum_off, &src_addr, &translated_addr)?;
                if new_src_port != src_port {
                    rewrite_src_port(ctx, l4_offset, protocol, src_port, new_src_port)?;
                }

                if let Some(ct_entry) = CT_TABLE_V6.get_ptr_mut(&ct_key) {
                    unsafe {
                        (*ct_entry).nat_addr = translated_addr;
                        (*ct_entry).nat_port = new_src_port;
                        (*ct_entry).flags |= CT_FLAG_NAT_SRC;
                        (*ct_entry).nat_type = NAT_TYPE_SNAT;
                    }
                }

                if rule.nat_type == NAT_TYPE_MASQUERADE {
                    increment_metric(NAT_METRIC_MASQ_APPLIED);
                } else {
                    increment_metric(NAT_METRIC_SNAT_APPLIED);
                }
                return Ok(TC_ACT_OK);
            }
        }
        i += 1;
    }

    Ok(TC_ACT_OK)
}

/// Allocate a port from the rule's port range using a hash-based scheme.
#[inline(always)]
fn allocate_port(orig_addr: u32, orig_port: u16, range_start: u16, range_end: u16) -> u16 {
    if range_start == 0 || range_end < range_start {
        return orig_port;
    }
    let range_size = (range_end - range_start + 1) as u32;
    let hash = orig_addr.wrapping_mul(2654435761) ^ (orig_port as u32).wrapping_mul(2246822519);
    let offset = hash % range_size;
    range_start + offset as u16
}

/// Allocate a port for IPv6 SNAT. XOR-folds the 128-bit address to u32 before hashing.
#[inline(always)]
fn allocate_port_v6(orig_addr: &[u32; 4], orig_port: u16, range_start: u16, range_end: u16) -> u16 {
    if range_start == 0 || range_end < range_start {
        return orig_port;
    }
    let folded = orig_addr[0] ^ orig_addr[1] ^ orig_addr[2] ^ orig_addr[3];
    let range_size = (range_end - range_start + 1) as u32;
    let hash = folded.wrapping_mul(2654435761) ^ (orig_port as u32).wrapping_mul(2246822519);
    let offset = hash % range_size;
    range_start + offset as u16
}

/// Rewrite the source IP address in the IPv4 header and update checksums.
#[inline(always)]
fn rewrite_src_ip(
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

    // Write new source IP into the packet.
    let src_off = (l3_offset + IPV4_SRC_OFFSET) as u32;
    let ret = unsafe {
        bpf_skb_store_bytes(
            ctx.skb.skb as *mut _,
            src_off,
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
        PROTO_TCP => l4_offset + 16,
        PROTO_UDP => l4_offset + 6,
        _ => return Ok(()),
    } as u32;

    let ret = unsafe {
        bpf_l4_csum_replace(
            ctx.skb.skb as *mut _,
            l4_csum_off,
            u32::from_be_bytes(old_be) as u64,
            u32::from_be_bytes(new_be) as u64,
            4,
        )
    };
    if ret != 0 {
        return Err(());
    }

    Ok(())
}

/// Rewrite the source IPv6 address and update L4 pseudo-header checksum.
///
/// `src_off` = absolute offset of IPv6 src addr in packet.
/// `l4_csum_off` = absolute offset of L4 checksum field (0 = skip L4 update).
#[inline(always)]
fn rewrite_src_ip_v6(
    ctx: &TcContext,
    src_off: u32,
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
            src_off,
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

/// Rewrite the source port and update L4 checksum.
#[inline(always)]
fn rewrite_src_port(
    ctx: &TcContext,
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    if old_port == new_port {
        return Ok(());
    }

    // Source port is at offset 0 within both TCP and UDP headers.
    let port_off = l4_offset as u32;
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

/// Check if a SNAT rule matches the packet (IPv4).
#[inline(always)]
fn match_snat_rule(rule: &NatRuleEntry, src_ip: u32, dst_ip: u32, protocol: u8) -> bool {
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

    true
}

/// Check if an IPv6 SNAT rule matches the packet.
#[inline(never)]
fn match_snat_rule_v6(
    rule: &NatRuleEntryV6,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    protocol: u8,
) -> bool {
    let flags = rule.match_flags;

    if (flags & NAT_MATCH_PROTO) != 0 && rule.match_protocol != protocol {
        return false;
    }
    if (flags & NAT_MATCH_SRC_IP) != 0
        && !ipv6_mask_match(src_addr, &rule.match_src_addr, &rule.match_src_mask)
    {
        return false;
    }
    if (flags & NAT_MATCH_DST_IP) != 0
        && !ipv6_mask_match(dst_addr, &rule.match_dst_addr, &rule.match_dst_mask)
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
