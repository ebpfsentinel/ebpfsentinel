#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    cty::c_void,
    helpers::{bpf_ktime_get_boot_ns, bpf_l3_csum_replace, bpf_l4_csum_replace, bpf_loop, bpf_skb_store_bytes},
    macros::{classifier, map},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, lpm_trie::Key},
    programs::TcContext,
};

use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, ipv6_mask_match, ones_complement_add,
    prefix_to_mask, u16_from_be_bytes, u32_from_be_bytes, u32x4_to_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::increment_metric;
use ebpf_common::{
    conntrack::{
        ConnKey, ConnKeyV6, ConnValue, ConnValueV6, CT_FLAG_NAT_DST, CT_MAX_ENTRIES_V4,
        CT_MAX_ENTRIES_V6, normalize_key_v4, normalize_key_v6,
    },
    nat::{
        HairpinConfig, HairpinCtValue, MAX_HAIRPIN_CT,
        MAX_NAT_HASH_EXACT, MAX_NAT_RULES, MAX_NAT_RULES_V6, MAX_NPTV6_RULES,
        NAT_MATCH_DST_IP, NAT_MATCH_DST_PORT, NAT_MATCH_PROTO,
        NAT_MATCH_SRC_IP, NAT_METRIC_COUNT, NAT_METRIC_DNAT_APPLIED, NAT_METRIC_ERRORS,
        NAT_METRIC_HAIRPIN_APPLIED, NAT_METRIC_NPTV6_TRANSLATED, NAT_METRIC_TOTAL_SEEN,
        NAT_TYPE_DNAT, NAT_TYPE_ONETOONE, NAT_TYPE_REDIRECT,
        NatHashKeyExact, NatHashValue, NatRuleEntry, NatRuleEntryV6, NptV6RuleEntry,
    },
    tenant::{MAX_TENANT_SUBNET_LPM_ENTRIES, MAX_TENANT_SUBNET_V6_LPM_ENTRIES},
};
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.

// NOTE: bpf_skb_change_proto (v4.8) enables IPv4↔IPv6 protocol translation
// (NAT64/NAT46). Not currently used — our NAT operates within the same
// address family. Available for future cross-AF NAT implementation.

/// Offset of src_addr within Ipv4Hdr (standard IP header).
const IPV4_SRC_OFFSET: usize = 12;
/// Offset of dst_addr within Ipv4Hdr (standard IP header).
const IPV4_DST_OFFSET: usize = 16;
/// Offset of IP header checksum within Ipv4Hdr.
const IPV4_CSUM_OFFSET: usize = 10;
/// Offset of dst_addr within IPv6 header.
const IPV6_DST_OFFSET: usize = 24;

/// BPF_F_RECOMPUTE_CSUM flag (unused for raw csum replace).
const BPF_F_RECOMPUTE_CSUM: u64 = 1;

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

/// Fast-path: exact-match DNAT HashMap (proto, dst_ip, dst_port) → NAT action.
/// Checked before the Array+bpf_loop scan for O(1) lookup.
#[map]
static NAT_HASH_DNAT: HashMap<NatHashKeyExact, NatHashValue> =
    HashMap::with_max_entries(MAX_NAT_HASH_EXACT, 0);

/// Shared conntrack table (pinned, same as tc-conntrack).
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 0);

/// Shared IPv6 conntrack table.
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValueV6> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 0);

/// NPTv6 prefix translation rules (RFC 6296).
#[map]
static NPTV6_RULES: Array<NptV6RuleEntry> = Array::with_max_entries(MAX_NPTV6_RULES, 0);

/// Number of active NPTv6 rules.
#[map]
static NPTV6_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// Hairpin NAT configuration (single-element array).
#[map]
static NAT_HAIRPIN_CONFIG: Array<HairpinConfig> = Array::with_max_entries(1, 0);

/// Hairpin NAT conntrack table (LRU): maps post-hairpin 5-tuple to original
/// client info so return traffic can be un-SNATed and un-DNATed.
#[map]
static NAT_HAIRPIN_CT: LruHashMap<ConnKey, HairpinCtValue> =
    LruHashMap::with_max_entries(MAX_HAIRPIN_CT, 0);

/// Per-CPU NAT metrics.
#[map]
static NAT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(NAT_METRIC_COUNT, 0);

/// Per-interface group membership bitmask. Key = ifindex (u32), Value = group bitmask (u32).
#[map]
static INTERFACE_GROUPS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// Tenant resolution: VLAN ID -> tenant_id.
#[map]
static TENANT_VLAN_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// LPM trie for subnet-based tenant resolution (IPv4).
#[map]
static TENANT_SUBNET_V4: LpmTrie<[u8; 4], u32> =
    LpmTrie::with_max_entries(MAX_TENANT_SUBNET_LPM_ENTRIES, 0);

/// LPM trie for subnet-based tenant resolution (IPv6).
#[map]
static TENANT_SUBNET_V6: LpmTrie<[u8; 16], u32> =
    LpmTrie::with_max_entries(MAX_TENANT_SUBNET_V6_LPM_ENTRIES, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_nat_ingress(ctx: TcContext) -> i32 {
    increment_metric(NAT_METRIC_TOTAL_SEEN);
    match try_nat_ingress(&ctx) {
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

/// Resolve the tenant ID for the current packet.
/// Priority: VLAN-based > interface-based > subnet (LPM) > default (0).
#[inline(always)]
unsafe fn resolve_tenant_id(ifindex: u32, vlan_id: u16, src_ip: u32) -> u32 {
    unsafe {
        // Priority 1: VLAN-based (if packet has VLAN tag)
        if vlan_id != 0 {
            let vlan_key = vlan_id as u32;
            if let Some(&tid) = TENANT_VLAN_MAP.get(&vlan_key) {
                return tid;
            }
        }
        // Priority 2: Interface-based
        if let Some(&tid) = INTERFACE_GROUPS.get(&ifindex) {
            return tid;
        }
        // Priority 3: Subnet-based (LPM trie on src_ip)
        if src_ip != 0 {
            let key = Key::new(32, src_ip.to_be_bytes());
            if let Some(&tid) = TENANT_SUBNET_V4.get(&key) {
                return tid;
            }
        }
        // Default tenant
        0
    }
}

/// Resolve the tenant ID for an IPv6 packet.
/// Priority: VLAN-based > interface-based > subnet V6 (LPM) > default (0).
#[inline(always)]
unsafe fn resolve_tenant_id_v6(ifindex: u32, vlan_id: u16, src_addr: &[u32; 4]) -> u32 {
    unsafe {
        // Priority 1: VLAN-based (if packet has VLAN tag)
        if vlan_id != 0 {
            let vlan_key = vlan_id as u32;
            if let Some(&tid) = TENANT_VLAN_MAP.get(&vlan_key) {
                return tid;
            }
        }
        // Priority 2: Interface-based
        if let Some(&tid) = INTERFACE_GROUPS.get(&ifindex) {
            return tid;
        }
        // Priority 3: Subnet-based (LPM trie on IPv6 src_addr)
        let addr_bytes: [u8; 16] = core::mem::transmute(*src_addr);
        let key = Key::new(128, addr_bytes);
        if let Some(&tid) = TENANT_SUBNET_V6.get(&key) {
            return tid;
        }
        // Default tenant
        0
    }
}

// ── bpf_loop context structs ────────────────────────────────────────

/// Opaque context passed through `bpf_loop` to the IPv4 DNAT rule-scan callback.
/// Kept small (~40 bytes) to stay well within the 512-byte eBPF stack limit.
#[repr(C)]
struct DnatScanCtx {
    count: u32,
    src_ip: u32,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
    /// Result: new destination IP (0 = no match).
    new_dst_ip: u32,
    /// Result: new destination port (0 = unchanged).
    new_dst_port: u16,
    /// Result: NAT type of the matched rule.
    nat_type: u8,
    /// 1 if a rule matched, 0 otherwise.
    matched: u8,
    /// Interface group membership bitmask for the ingress interface.
    iface_groups: u32,
    /// Resolved tenant ID for the current packet.
    tenant_id: u32,
}

/// Opaque context passed through `bpf_loop` to the IPv6 DNAT rule-scan callback.
/// ~56 bytes: src_addr(16) + dst_addr(16) + scalars.
#[repr(C)]
struct DnatScanCtxV6 {
    count: u32,
    src_addr: [u32; 4],
    dst_addr: [u32; 4],
    dst_port: u16,
    protocol: u8,
    /// Result: new destination address.
    new_dst_addr: [u32; 4],
    /// Result: new destination port (0 = unchanged).
    new_dst_port: u16,
    /// Result: NAT type of the matched rule.
    nat_type: u8,
    /// 1 if a rule matched, 0 otherwise.
    matched: u8,
    /// Interface group membership bitmask for the ingress interface.
    iface_groups: u32,
    /// Resolved tenant ID for the current packet.
    tenant_id: u32,
}

// ── bpf_loop callbacks ─────────────────────────────────────────────

/// Callback for `bpf_loop`: scan one IPv4 DNAT rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
#[inline(never)]
unsafe extern "C" fn scan_dnat_rule_v4(index: u32, ctx: *mut c_void) -> i64 {
    unsafe {
        let lctx = &mut *(ctx as *mut DnatScanCtx);
        if index >= lctx.count {
            return 1;
        }
        if let Some(rule) = NAT_DNAT_RULES.get(index) {
            if !group_matches(rule.group_mask, lctx.iface_groups) {
                return 0; // group mismatch, continue to next rule
            }
            if rule.tenant_id != 0 && rule.tenant_id != lctx.tenant_id {
                return 0; // tenant mismatch, continue to next rule
            }
            if match_nat_rule(rule, lctx.src_ip, lctx.dst_ip, lctx.dst_port, lctx.protocol) {
                let new_dst_ip = match rule.nat_type {
                    NAT_TYPE_DNAT | NAT_TYPE_ONETOONE => rule.nat_addr,
                    NAT_TYPE_REDIRECT => lctx.src_ip,
                    _ => return 0, // Unknown NAT type, continue scanning
                };
                lctx.new_dst_ip = new_dst_ip;
                lctx.new_dst_port = if rule.nat_port_start != 0 {
                    rule.nat_port_start
                } else {
                    lctx.dst_port
                };
                lctx.nat_type = rule.nat_type;
                lctx.matched = 1;
                return 1;
            }
        }
        0
    }
}

/// Callback for `bpf_loop`: scan one IPv6 DNAT rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
#[inline(never)]
unsafe extern "C" fn scan_dnat_rule_v6(index: u32, ctx: *mut c_void) -> i64 {
    unsafe {
        let lctx = &mut *(ctx as *mut DnatScanCtxV6);
        if index >= lctx.count {
            return 1;
        }
        if let Some(rule) = NAT_DNAT_RULES_V6.get(index) {
            if !group_matches(rule.group_mask, lctx.iface_groups) {
                return 0;
            }
            if rule.tenant_id != 0 && rule.tenant_id != lctx.tenant_id {
                return 0; // tenant mismatch, continue to next rule
            }
            if match_nat_rule_v6(rule, &lctx.src_addr, &lctx.dst_addr, lctx.dst_port, lctx.protocol) {
                let new_dst_addr = match rule.nat_type {
                    NAT_TYPE_DNAT | NAT_TYPE_ONETOONE => rule.nat_addr,
                    NAT_TYPE_REDIRECT => lctx.src_addr,
                    _ => return 0,
                };
                lctx.new_dst_addr = new_dst_addr;
                lctx.new_dst_port = if rule.nat_port_start != 0 {
                    rule.nat_port_start
                } else {
                    lctx.dst_port
                };
                lctx.nat_type = rule.nat_type;
                lctx.matched = 1;
                return 1;
            }
        }
        0
    }
}

// ── Processing ──────────────────────────────────────────────────────

#[inline(always)]
fn try_nat_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;
    let mut vlan_id: u16 = 0;

    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            vlan_id = u16::from_be(unsafe { (*vhdr2).tci }) & 0x0FFF;
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
    }

    if ether_type == ETH_P_IP {
        process_dnat_v4(ctx, l3_offset, vlan_id)
    } else if ether_type == ETH_P_IPV6 {
        process_dnat_v6(ctx, l3_offset, vlan_id)
    } else {
        Ok(TC_ACT_OK)
    }
}

// #[inline(never)] gives IPv4 its own stack frame, preventing the combined v4+v6
// stack from exceeding 512 bytes.
#[inline(never)]
fn process_dnat_v4(ctx: &TcContext, l3_offset: usize, vlan_id: u16) -> Result<i32, ()> {
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

    // Hairpin reverse path: check if this is return traffic from a
    // hairpinned connection. If so, un-SNAT the destination back to the
    // original client and un-DNAT the source back to the external IP.
    let hp_key = normalize_key_v4(src_ip, dst_ip, src_port, dst_port, protocol);
    if let Some(hp_val) = unsafe { NAT_HAIRPIN_CT.get(&hp_key) } {
        // Return traffic: dst is the firewall SNAT IP -> restore to original client
        rewrite_dst_ip(ctx, l3_offset, l4_offset, protocol, dst_ip, hp_val.orig_src_ip)?;
        // Return traffic: src is the internal server -> restore to external IP
        rewrite_src_ip(ctx, l3_offset, l4_offset, protocol, src_ip, hp_val.orig_dst_ip)?;
        increment_metric(NAT_METRIC_HAIRPIN_APPLIED);
        return Ok(TC_ACT_OK);
    }

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

    // Fast-path: exact-match DNAT HashMap lookup — O(1).
    let hash_key = NatHashKeyExact {
        dst_ip,
        dst_port,
        protocol,
        _pad: 0,
    };
    if let Some(val) = unsafe { NAT_HASH_DNAT.get(&hash_key) } {
        // Apply DNAT from HashMap hit
        rewrite_dst_ip(ctx, l3_offset, l4_offset, protocol, dst_ip, val.nat_addr)?;
        if val.nat_port_start != 0 {
            rewrite_dst_port(ctx, l4_offset, protocol, dst_port, val.nat_port_start)?;
        }
        // Store conntrack entry for return traffic
        let now = unsafe { bpf_ktime_get_boot_ns() };
        let ct_key = normalize_key_v4(src_ip, val.nat_addr, src_port, val.nat_port_start.max(dst_port), protocol);
        let ct_val = ConnValue {
            state: 1,
            flags: CT_FLAG_NAT_DST,
            nat_type: 2, // DNAT
            _pad: 0,
            packets_fwd: 1,
            packets_rev: 0,
            bytes_fwd: ctx.len() as u32,
            bytes_rev: 0,
            first_seen_ns: now,
            last_seen_ns: now,
            nat_addr: val.nat_addr,
            nat_port: val.nat_port_start,
            _pad2: [0; 2],
        };
        let _ = CT_TABLE_V4.insert(&ct_key, &ct_val, 0);
        increment_metric(NAT_METRIC_DNAT_APPLIED);
        return Ok(TC_ACT_OK);
    }

    // Scan DNAT rules for new connections via bpf_loop (kernel 5.17+).
    // The verifier analyzes the callback body only once, avoiding
    // complexity limits for large rule sets.
    let count = match NAT_DNAT_RULE_COUNT.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let iface_groups = get_iface_groups(ctx);
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let tenant_id = unsafe { resolve_tenant_id(ifindex, vlan_id, src_ip) };

    let mut scan_ctx = DnatScanCtx {
        count: if count > MAX_NAT_RULES { MAX_NAT_RULES } else { count },
        src_ip,
        dst_ip,
        dst_port,
        protocol,
        new_dst_ip: 0,
        new_dst_port: 0,
        nat_type: 0,
        matched: 0,
        iface_groups,
        tenant_id,
    };
    unsafe {
        bpf_loop(
            MAX_NAT_RULES,
            scan_dnat_rule_v4 as *mut c_void,
            &mut scan_ctx as *mut DnatScanCtx as *mut c_void,
            0,
        );
    }

    if scan_ctx.matched != 0 {
        let new_dst_ip = scan_ctx.new_dst_ip;
        let new_dst_port = scan_ctx.new_dst_port;

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

        // Hairpin forward path: if both the original source and the
        // post-DNAT destination are on the internal subnet, we must SNAT
        // the source to the firewall's internal IP. Otherwise the server
        // would reply directly to the client (asymmetric routing) and
        // the client would drop the unexpected source.
        if let Some(hcfg) = NAT_HAIRPIN_CONFIG.get(0) {
            if hcfg.enabled != 0 {
                // IPs are already in host byte order (u32_from_be_bytes above).
                // Config stores host-byte-order values, so compare directly.
                if (src_ip & hcfg.internal_mask) == hcfg.internal_subnet
                    && (new_dst_ip & hcfg.internal_mask) == hcfg.internal_subnet
                {
                    // SNAT: rewrite source to firewall internal IP.
                    rewrite_src_ip(
                        ctx, l3_offset, l4_offset, protocol,
                        src_ip, hcfg.hairpin_snat_ip,
                    )?;

                    // Store reverse mapping so return traffic can be restored.
                    // Key is the post-rewrite 5-tuple: (hairpin_snat_ip, new_dst_ip,
                    // src_port, new_dst_port, protocol).
                    let post_key = normalize_key_v4(
                        hcfg.hairpin_snat_ip, new_dst_ip,
                        src_port, new_dst_port, protocol,
                    );
                    let hp_val = HairpinCtValue {
                        orig_src_ip: src_ip,
                        orig_dst_ip: dst_ip, // pre-DNAT destination (external IP)
                        orig_src_port: src_port,
                        _pad: 0,
                    };
                    let _ = NAT_HAIRPIN_CT.insert(&post_key, &hp_val, 0);

                    increment_metric(NAT_METRIC_HAIRPIN_APPLIED);
                }
            }
        }
    }

    Ok(TC_ACT_OK)
}

/// IPv6 DNAT processing.
#[inline(never)]
fn process_dnat_v6(ctx: &TcContext, l3_offset: usize, vlan_id: u16) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let raw_protocol = unsafe { (*ipv6hdr).next_hdr };

    // Check NPTv6 rules first (stateless, no conntrack needed).
    if try_nptv6_ingress(ctx, l3_offset, &dst_addr)? {
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

    // Scan IPv6 DNAT rules via bpf_loop.
    let count = match NAT_DNAT_RULE_COUNT_V6.get(0) {
        Some(&c) => c,
        None => return Ok(TC_ACT_OK),
    };

    let iface_groups = get_iface_groups(ctx);
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let tenant_id = unsafe { resolve_tenant_id_v6(ifindex, vlan_id, &src_addr) };

    let mut scan_ctx = DnatScanCtxV6 {
        count: if count > MAX_NAT_RULES_V6 { MAX_NAT_RULES_V6 } else { count },
        src_addr,
        dst_addr,
        dst_port,
        protocol,
        new_dst_addr: [0; 4],
        new_dst_port: 0,
        nat_type: 0,
        matched: 0,
        iface_groups,
        tenant_id,
    };
    unsafe {
        bpf_loop(
            MAX_NAT_RULES_V6,
            scan_dnat_rule_v6 as *mut c_void,
            &mut scan_ctx as *mut DnatScanCtxV6 as *mut c_void,
            0,
        );
    }

    if scan_ctx.matched != 0 {
        let new_dst_addr = scan_ctx.new_dst_addr;
        let new_dst_port = scan_ctx.new_dst_port;

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
    }

    Ok(TC_ACT_OK)
}

// ── Checksum helpers ────────────────────────────────────────────────
// The rewrite functions below use `bpf_l3_csum_replace` (IP header) and
// `bpf_l4_csum_replace` (TCP/UDP pseudo-header) for incremental checksum
// updates after address/port changes.  These are the right helpers for
// single-field rewrites.
//

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

/// Rewrite the source IP address in the IPv4 header and update checksums.
///
/// Mirrors `rewrite_dst_ip` but operates on the source address field
/// (offset 12). Used by hairpin NAT to SNAT the client's source to the
/// firewall's internal IP.
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
            4,
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

// ── NPTv6 (RFC 6296) ingress helpers ────────────────────────────────

/// Try NPTv6 prefix translation on ingress (dst rewrite: external -> internal).
/// Returns `true` if a rule matched and translation was applied.
#[inline(always)]
fn try_nptv6_ingress(ctx: &TcContext, l3_offset: usize, dst_addr: &[u32; 4]) -> Result<bool, ()> {
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
                // Check if dst matches external_prefix.
                let mut matches = true;
                let mut j = 0usize;
                while j < 4 {
                    if (dst_addr[j] & mask[j]) != (rule.external_prefix[j] & mask[j]) {
                        matches = false;
                        break;
                    }
                    j += 1;
                }
                if matches {
                    apply_nptv6_dst(ctx, l3_offset, dst_addr, rule)?;
                    increment_metric(NAT_METRIC_NPTV6_TRANSLATED);
                    return Ok(true);
                }
            }
        }
        i += 1;
    }
    Ok(false)
}

/// Apply NPTv6 destination prefix translation (checksum-neutral per RFC 6296).
/// Reverse direction: external -> internal, uses `!adjustment` (ones-complement negation).
#[inline(always)]
fn apply_nptv6_dst(
    ctx: &TcContext,
    l3_offset: usize,
    dst_addr: &[u32; 4],
    rule: &NptV6RuleEntry,
) -> Result<(), ()> {
    let mask = prefix_to_mask(rule.prefix_len);

    // Build new address: internal_prefix | (dst_addr & ~mask).
    let mut new_addr = [0u32; 4];
    let mut k = 0usize;
    while k < 4 {
        new_addr[k] = (rule.internal_prefix[k] & mask[k]) | (dst_addr[k] & !mask[k]);
        k += 1;
    }

    // Apply reverse checksum adjustment (!adjustment = ones-complement negation)
    // to the first 16-bit word after the prefix (RFC 6296 section 3.1).
    let adj_word_idx = rule.prefix_len as usize / 16;
    if adj_word_idx < 8 {
        let u32_idx = adj_word_idx / 2;
        let high = (adj_word_idx % 2) == 0;
        let current_word = if high {
            (new_addr[u32_idx] >> 16) as u16
        } else {
            new_addr[u32_idx] as u16
        };
        let adjusted = ones_complement_add(current_word, !rule.adjustment);
        if high {
            new_addr[u32_idx] = ((adjusted as u32) << 16) | (new_addr[u32_idx] & 0xFFFF);
        } else {
            new_addr[u32_idx] = (new_addr[u32_idx] & 0xFFFF_0000) | (adjusted as u32);
        }
    }

    // Write new destination address (IPv6 dst is at offset 24 from IPv6 header).
    let dst_off = (l3_offset + IPV6_DST_OFFSET) as u32;
    let new_bytes = u32x4_to_bytes(&new_addr);
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

// ipv6_mask_match, u32x4_to_bytes imported from ebpf_helpers::net

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
