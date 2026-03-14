#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    cty::c_void,
    helpers::{bpf_l3_csum_replace, bpf_l4_csum_replace, bpf_loop, bpf_skb_store_bytes},
    macros::{classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, ipv6_mask_match, u16_from_be_bytes,
    u32_from_be_bytes, u32x4_to_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::increment_metric;
use ebpf_common::{
    conntrack::{
        ConnKey, ConnKeyV6, ConnValue, ConnValueV6, CT_FLAG_NAT_SRC, CT_MAX_ENTRIES_V4,
        CT_MAX_ENTRIES_V6, normalize_key_v4, normalize_key_v6,
    },
    nat::{
        MAX_NAT_PORT_ALLOC, MAX_NAT_RULES, MAX_NAT_RULES_V6, MAX_NPTV6_RULES,
        NAT_MATCH_DST_IP, NAT_MATCH_PROTO,
        NAT_MATCH_SRC_IP, NAT_METRIC_COUNT, NAT_METRIC_ERRORS, NAT_METRIC_MASQ_APPLIED,
        NAT_METRIC_NPTV6_TRANSLATED, NAT_METRIC_SNAT_APPLIED, NAT_METRIC_TOTAL_SEEN,
        NAT_TYPE_MASQUERADE, NAT_TYPE_SNAT,
        NatPortAllocKey, NatPortAllocValue, NatRuleEntry, NatRuleEntryV6, NptV6RuleEntry,
    },
};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.

/// Offset of src_addr within Ipv4Hdr (standard IP header).
const IPV4_SRC_OFFSET: usize = 12;
/// Offset of IP header checksum within Ipv4Hdr.
const IPV4_CSUM_OFFSET: usize = 10;
/// Offset of src_addr within IPv6 header.
const IPV6_SRC_OFFSET: usize = 8;

const BPF_F_RECOMPUTE_CSUM: u64 = 1;

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

/// NPTv6 prefix translation rules (RFC 6296).
#[map]
static NPTV6_RULES: Array<NptV6RuleEntry> = Array::with_max_entries(MAX_NPTV6_RULES, 0);

/// Number of active NPTv6 rules.
#[map]
static NPTV6_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Per-CPU NAT metrics.
#[map]
static NAT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(NAT_METRIC_COUNT, 0);

/// Per-interface group membership bitmask. Key = ifindex (u32), Value = group bitmask (u32).
#[map]
static INTERFACE_GROUPS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

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

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(NAT_METRICS, index);
}

// ── Interface group helpers ──────────────────────────────────────────

/// Get the interface group membership for the current packet's ingress interface.
#[inline(always)]
fn get_iface_groups(ctx: &TcContext) -> u32 {
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    match unsafe { INTERFACE_GROUPS.get(&ifindex) } {
        Some(&groups) => groups,
        None => 0,
    }
}

/// Check if a rule's `group_mask` matches the interface's group membership.
#[inline(always)]
fn group_matches(rule_group_mask: u32, iface_groups: u32) -> bool {
    let mask = rule_group_mask & 0x7FFF_FFFF;
    if mask == 0 {
        return true;
    }
    let hit = (mask & iface_groups) != 0;
    let invert = (rule_group_mask & 0x8000_0000) != 0;
    hit != invert
}

// ── bpf_loop context structs ────────────────────────────────────────

/// Opaque context passed through `bpf_loop` to the IPv4 SNAT rule-scan callback.
/// Kept small (~44 bytes) to stay well within the 512-byte eBPF stack limit.
#[repr(C)]
struct SnatScanCtx {
    count: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    protocol: u8,
    /// Result: translated source IP (0 = no match).
    new_src_ip: u32,
    /// Result: translated source port.
    new_src_port: u16,
    /// Result: NAT type of the matched rule.
    nat_type: u8,
    /// 1 if a rule matched, 0 otherwise.
    matched: u8,
    /// Interface group membership bitmask for the ingress interface.
    iface_groups: u32,
}

/// Opaque context passed through `bpf_loop` to the IPv6 SNAT rule-scan callback.
/// ~60 bytes: src_addr(16) + dst_addr(16) + scalars + results.
#[repr(C)]
struct SnatScanCtxV6 {
    count: u32,
    src_addr: [u32; 4],
    dst_addr: [u32; 4],
    src_port: u16,
    protocol: u8,
    /// Result: translated source address.
    new_src_addr: [u32; 4],
    /// Result: translated source port.
    new_src_port: u16,
    /// Result: NAT type of the matched rule.
    nat_type: u8,
    /// 1 if a rule matched, 0 otherwise.
    matched: u8,
    /// Interface group membership bitmask for the ingress interface.
    iface_groups: u32,
}

// ── bpf_loop callbacks ─────────────────────────────────────────────

/// Callback for `bpf_loop`: scan one IPv4 SNAT rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
#[inline(never)]
unsafe extern "C" fn scan_snat_rule_v4(index: u32, ctx: *mut c_void) -> i64 {
    let lctx = unsafe { &mut *(ctx as *mut SnatScanCtx) };
    if index >= lctx.count {
        return 1;
    }
    if let Some(rule) = NAT_SNAT_RULES.get(index) {
        if !group_matches(rule.group_mask, lctx.iface_groups) {
            return 0;
        }
        if match_snat_rule(rule, lctx.src_ip, lctx.dst_ip, lctx.protocol) {
            let new_src_ip = rule.nat_addr;
            // Skip rules with no translation address (unless masquerade).
            if new_src_ip == 0 && rule.nat_type != NAT_TYPE_MASQUERADE {
                return 0;
            }
            // For masquerade, userspace must pre-populate nat_addr with
            // the interface IP. If not set, skip this rule.
            if rule.nat_type == NAT_TYPE_MASQUERADE && new_src_ip == 0 {
                return 0;
            }

            lctx.new_src_ip = new_src_ip;
            lctx.new_src_port = if rule.nat_port_start != 0 {
                allocate_port(lctx.src_ip, lctx.src_port, rule.nat_port_start, rule.nat_port_end)
            } else {
                lctx.src_port
            };
            lctx.nat_type = rule.nat_type;
            lctx.matched = 1;
            return 1;
        }
    }
    0
}

/// Callback for `bpf_loop`: scan one IPv6 SNAT rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
#[inline(never)]
unsafe extern "C" fn scan_snat_rule_v6(index: u32, ctx: *mut c_void) -> i64 {
    let lctx = unsafe { &mut *(ctx as *mut SnatScanCtxV6) };
    if index >= lctx.count {
        return 1;
    }
    if let Some(rule) = NAT_SNAT_RULES_V6.get(index) {
        if !group_matches(rule.group_mask, lctx.iface_groups) {
            return 0;
        }
        if match_snat_rule_v6(rule, &lctx.src_addr, &lctx.dst_addr, lctx.protocol) {
            let new_src_addr = rule.nat_addr;
            if new_src_addr == [0; 4] && rule.nat_type != NAT_TYPE_MASQUERADE {
                return 0;
            }
            if rule.nat_type == NAT_TYPE_MASQUERADE && new_src_addr == [0; 4] {
                return 0;
            }

            lctx.new_src_addr = new_src_addr;
            lctx.new_src_port = if rule.nat_port_start != 0 {
                allocate_port_v6(&lctx.src_addr, lctx.src_port, rule.nat_port_start, rule.nat_port_end)
            } else {
                lctx.src_port
            };
            lctx.nat_type = rule.nat_type;
            lctx.matched = 1;
            return 1;
        }
    }
    0
}

// ── Processing ──────────────────────────────────────────────────────

#[inline(always)]
fn try_nat_egress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
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

    // Scan SNAT rules for new connections via bpf_loop (kernel 5.17+).
    // The verifier analyzes the callback body only once, avoiding
    // complexity limits for large rule sets.
    let count = match NAT_SNAT_RULE_COUNT.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let iface_groups = get_iface_groups(ctx);

    let mut scan_ctx = SnatScanCtx {
        count: if count > MAX_NAT_RULES { MAX_NAT_RULES } else { count },
        src_ip,
        dst_ip,
        src_port,
        protocol,
        new_src_ip: 0,
        new_src_port: 0,
        nat_type: 0,
        matched: 0,
        iface_groups,
    };
    unsafe {
        bpf_loop(
            MAX_NAT_RULES,
            scan_snat_rule_v4 as *mut c_void,
            &mut scan_ctx as *mut SnatScanCtx as *mut c_void,
            0,
        );
    }

    if scan_ctx.matched != 0 {
        let translated_ip = scan_ctx.new_src_ip;
        let new_src_port = scan_ctx.new_src_port;

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

        if scan_ctx.nat_type == NAT_TYPE_MASQUERADE {
            increment_metric(NAT_METRIC_MASQ_APPLIED);
        } else {
            increment_metric(NAT_METRIC_SNAT_APPLIED);
        }
    }

    Ok(TC_ACT_OK)
}

/// IPv6 SNAT processing.
#[inline(never)]
fn process_snat_v6(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let raw_protocol = unsafe { (*ipv6hdr).next_hdr };

    // Check NPTv6 rules first (stateless, no conntrack needed).
    if try_nptv6_egress(ctx, l3_offset, &src_addr)? {
        return Ok(TC_ACT_OK);
    }

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (protocol, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_protocol)
        .ok_or(())?;

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

    // Scan IPv6 SNAT rules via bpf_loop.
    let count = match NAT_SNAT_RULE_COUNT_V6.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let iface_groups = get_iface_groups(ctx);

    let mut scan_ctx = SnatScanCtxV6 {
        count: if count > MAX_NAT_RULES_V6 { MAX_NAT_RULES_V6 } else { count },
        src_addr,
        dst_addr,
        src_port,
        protocol,
        new_src_addr: [0; 4],
        new_src_port: 0,
        nat_type: 0,
        matched: 0,
        iface_groups,
    };
    unsafe {
        bpf_loop(
            MAX_NAT_RULES_V6,
            scan_snat_rule_v6 as *mut c_void,
            &mut scan_ctx as *mut SnatScanCtxV6 as *mut c_void,
            0,
        );
    }

    if scan_ctx.matched != 0 {
        let translated_addr = scan_ctx.new_src_addr;
        let new_src_port = scan_ctx.new_src_port;

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

        if scan_ctx.nat_type == NAT_TYPE_MASQUERADE {
            increment_metric(NAT_METRIC_MASQ_APPLIED);
        } else {
            increment_metric(NAT_METRIC_SNAT_APPLIED);
        }
    }

    Ok(TC_ACT_OK)
}

// ── NPTv6 (RFC 6296) egress helpers ─────────────────────────────────

/// Ones-complement addition of two u16 values (with carry fold).
#[inline(always)]
fn ones_complement_add(a: u16, b: u16) -> u16 {
    let sum = a as u32 + b as u32;
    let folded = (sum & 0xFFFF) + (sum >> 16);
    folded as u16
}

/// Build an IPv6 prefix mask from `prefix_len` (0-128) as `[u32; 4]`.
#[inline(always)]
fn prefix_to_mask(prefix_len: u8) -> [u32; 4] {
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

/// Try NPTv6 prefix translation on egress (src rewrite: internal -> external).
/// Returns `true` if a rule matched and translation was applied.
#[inline(always)]
fn try_nptv6_egress(ctx: &TcContext, l3_offset: usize, src_addr: &[u32; 4]) -> Result<bool, ()> {
    let count = match NPTV6_RULE_COUNT.get(0) {
        Some(&c) if c > 0 => {
            if c > MAX_NPTV6_RULES { MAX_NPTV6_RULES } else { c }
        }
        _ => return Ok(false),
    };

    let mut i = 0u32;
    while i < count {
        if let Some(rule) = NPTV6_RULES.get(i) {
            if rule.enabled != 0 {
                let mask = prefix_to_mask(rule.prefix_len);
                // Check if src matches internal_prefix.
                let mut matches = true;
                let mut j = 0usize;
                while j < 4 {
                    if (src_addr[j] & mask[j]) != (rule.internal_prefix[j] & mask[j]) {
                        matches = false;
                        break;
                    }
                    j += 1;
                }
                if matches {
                    apply_nptv6_src(ctx, l3_offset, src_addr, rule)?;
                    increment_metric(NAT_METRIC_NPTV6_TRANSLATED);
                    return Ok(true);
                }
            }
        }
        i += 1;
    }
    Ok(false)
}

/// Apply NPTv6 source prefix translation (checksum-neutral per RFC 6296).
#[inline(always)]
fn apply_nptv6_src(
    ctx: &TcContext,
    l3_offset: usize,
    src_addr: &[u32; 4],
    rule: &NptV6RuleEntry,
) -> Result<(), ()> {
    let mask = prefix_to_mask(rule.prefix_len);

    // Build new address: external_prefix | (src_addr & ~mask).
    let mut new_addr = [0u32; 4];
    let mut k = 0usize;
    while k < 4 {
        new_addr[k] = (rule.external_prefix[k] & mask[k]) | (src_addr[k] & !mask[k]);
        k += 1;
    }

    // Apply checksum adjustment to the first 16-bit word after the prefix
    // (RFC 6296 section 3.1).
    let adj_word_idx = rule.prefix_len as usize / 16;
    if adj_word_idx < 8 {
        let u32_idx = adj_word_idx / 2;
        let high = (adj_word_idx % 2) == 0;
        let current_word = if high {
            (new_addr[u32_idx] >> 16) as u16
        } else {
            new_addr[u32_idx] as u16
        };
        let adjusted = ones_complement_add(current_word, rule.adjustment);
        if high {
            new_addr[u32_idx] = ((adjusted as u32) << 16) | (new_addr[u32_idx] & 0xFFFF);
        } else {
            new_addr[u32_idx] = (new_addr[u32_idx] & 0xFFFF_0000) | (adjusted as u32);
        }
    }

    // Write new source address (IPv6 src is at offset 8 from IPv6 header).
    let src_off = (l3_offset + IPV6_SRC_OFFSET) as u32;
    let new_bytes = u32x4_to_bytes(&new_addr);
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

    Ok(())
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

// ipv6_mask_match, u32x4_to_bytes imported from ebpf_helpers::net

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
