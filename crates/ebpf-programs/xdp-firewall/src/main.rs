#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::{
        bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_loop, bpf_xdp_adjust_meta,
    },
    macros::{map, xdp},
    maps::{
        Array, CpuMap, HashMap, LruHashMap, PerCpuArray, ProgramArray, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::XdpContext,
};
use core::mem;
use ebpf_common::{
    conntrack::{
        CT_MAX_ENTRIES_V4, CT_MAX_ENTRIES_V6, CT_SRC_COUNTER_MAX, CT_STATE_ESTABLISHED,
        CT_STATE_NEW, CT_STATE_RELATED, ConnKey, ConnKeyV6, ConnTrackConfig, ConnValue,
        ConnValueV6, OVERLOAD_SET_ID, SRC_COUNTER_FLAG_OVERLOADED, SrcStateCounter,
        normalize_key_v4, normalize_key_v6,
    },
    event::{
        EVENT_TYPE_FIREWALL, FLAG_IPV6, FLAG_VLAN, META_FLAG_PRESENT, PacketEvent, XdpMetadata,
    },
    firewall::{
        ACTION_DROP, ACTION_LOG, ACTION_PASS, ACTION_REJECT, CT_MATCH_ESTABLISHED,
        CT_MATCH_INVALID, CT_MATCH_NEW, CT_MATCH_RELATED, DEFAULT_POLICY_DROP, FirewallRuleEntry,
        FirewallRuleEntryV6, FwHashKey5Tuple, FwHashKeyPort, FwHashValue, ICMP_WILDCARD,
        IpSetKeyV4, LpmValue, MATCH_CT_STATE, MATCH_DST_IP, MATCH_DST_PORT, MATCH_DST_SET,
        MATCH_PROTO, MATCH_SRC_IP, MATCH_SRC_PORT, MATCH_SRC_SET, MATCH2_DSCP, MATCH2_DST_MAC,
        MATCH2_ICMP_CODE, MATCH2_ICMP_TYPE, MATCH2_NEGATE_DST, MATCH2_NEGATE_SRC, MATCH2_SRC_MAC,
        MATCH2_TCP_FLAGS, MAX_FIREWALL_RULES, MAX_FW_HASH_5TUPLE, MAX_FW_HASH_PORT,
        MAX_IPSET_ENTRIES_V4, MAX_LPM_RULES, PacketCtx,
    },
    tenant::{MAX_TENANT_SUBNET_LPM_ENTRIES, MAX_TENANT_SUBNET_V6_LPM_ENTRIES},
};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, IcmpHdr, Ipv6Hdr, PROTO_ICMPV6,
    PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes,
    u32_from_be_bytes,
};
use ebpf_helpers::xdp::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{copy_mac_asm, increment_metric, ringbuf_has_backpressure};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants / types from ebpf-helpers ─────────────────────────────
// Network constants, header structs, ptr_at, skip_ipv6_ext_headers,
// byte helpers, and metric/ringbuf macros are imported from ebpf_helpers.

// ── Per-user firewall capability note ───────────────────────────────
// `bpf_get_socket_uid()` is available in TC classifier context for per-user
// firewall rules.  In XDP context, socket metadata is not yet populated by
// the kernel.  For process-aware (UID-based) firewall enforcement, consider a
// TC classifier companion program that uses `bpf_get_socket_uid()` and writes
// the UID into the XDP metadata area via `bpf_xdp_adjust_meta`, which this
// program can then read after the TC pass.

// ── Multi-tenancy via HASH_OF_MAPS (kernel 4.12+) ──────────────────
//
// Current approach: single shared rule maps with tenant_id field per entry.
// Upgrade path: BPF_MAP_TYPE_HASH_OF_MAPS enables per-tenant rule tables.
//
// Architecture:
//   TENANT_RULE_MAPS: HashMap<tenant_id, inner_map_fd>
//   Each inner map is a complete rule table for one tenant.
//
// Benefits:
//   - Atomic per-tenant rule table swap (replace inner map FD)
//   - No cross-tenant interference during rule updates
//   - Natural isolation — one tenant's lookup never touches another's data
//
// aya-ebpf support: aya::maps::HashMap can be used as outer map.
// Inner maps are created by userspace and inserted as values.
//
// NOTE(future): HASH_OF_MAPS for per-tenant rule tables — requires aya map-in-map API.

// ── Maps ────────────────────────────────────────────────────────────

/// IPv4 firewall rules (array, indexed 0..count, priority order).
#[map]
static FIREWALL_RULES: Array<FirewallRuleEntry> = Array::with_max_entries(MAX_FIREWALL_RULES, 0);

/// Number of active IPv4 rules (single element at index 0).
#[map]
static FIREWALL_RULE_COUNT: Array<u32> = Array::with_max_entries(1, 0);

/// IPv6 firewall rules (array, indexed 0..count, priority order).
#[map]
static FIREWALL_RULES_V6: Array<FirewallRuleEntryV6> =
    Array::with_max_entries(MAX_FIREWALL_RULES, 0);

/// Number of active IPv6 rules (single element at index 0).
#[map]
static FIREWALL_RULE_COUNT_V6: Array<u32> = Array::with_max_entries(1, 0);

/// Default policy when no rule matches (0=pass, 1=drop).
#[map]
static FIREWALL_DEFAULT_POLICY: Array<u8> = Array::with_max_entries(1, 0);

/// Fast-path: 5-tuple exact-match HashMap (proto, src_ip, dst_ip, src_port, dst_port) → action.
/// Rules with exact values in all 5 fields (no wildcards, ranges, or extended flags) are
/// placed here by userspace for O(1) lookup before the Array+bpf_loop scan.
#[map]
static FW_HASH_5TUPLE: HashMap<FwHashKey5Tuple, FwHashValue> =
    HashMap::with_max_entries(MAX_FW_HASH_5TUPLE, 0);

/// Fast-path: protocol+port HashMap (proto, dst_port) → action.
/// Rules that match only on protocol and destination port (all other fields wildcard).
#[map]
static FW_HASH_PORT: HashMap<FwHashKeyPort, FwHashValue> =
    HashMap::with_max_entries(MAX_FW_HASH_PORT, 0);

// NOTE: User RingBuf (BPF_MAP_TYPE_USER_RINGBUF, type 31) is available since
// kernel 6.1, but aya 0.13.1 does not support loading this map type (returns
// "Unsupported map type found 31"). Removed until aya exposes UserRingBuf
// userspace API. Config push uses bpf_map_update_elem via map managers.
// See: known limitation "User RingBuf config push" in CHANGELOG.md.

/// Per-CPU packet counters. Index: 0=passed, 1=dropped, 2=errors, 3=events_dropped, 4=total_seen, 5=rejected.
#[map]
static FIREWALL_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(6, 0);

/// Per-CPU scratch buffer for packet context shared across action/event helpers.
/// Avoids passing 8+ arguments through inlined functions that would blow
/// the 512-byte BPF stack.
#[map]
static PKT_CTX: PerCpuArray<PacketCtx> = PerCpuArray::with_max_entries(1, 0);

/// Shared kernel->userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

/// Feature enable/disable flags (shared across programs).
#[map]
static CONFIG_FLAGS: Array<u32> = Array::with_max_entries(1, 0);

/// XDP program array for tail-call chaining (firewall → ratelimit).
/// Index 0: ratelimit program fd (set by userspace if ratelimit is enabled).
#[map]
static XDP_PROG_ARRAY: ProgramArray = ProgramArray::with_max_entries(4, 0);

/// Index of the ratelimit program in `XDP_PROG_ARRAY`.
const PROG_IDX_RATELIMIT: u32 = 0;
/// Index of the reject program in `XDP_PROG_ARRAY`.
const PROG_IDX_REJECT: u32 = 1;

/// Sentinel value returned by `apply_action` to signal the entry point
/// to tail-call into `xdp-firewall-reject`. Not a real XDP action.
const XDP_ACTION_REJECT: u32 = 0xFF;

/// Per-interface group membership bitmask. Key = ifindex (u32), Value = group bitmask (u32).
#[map]
static INTERFACE_GROUPS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// Tenant resolution: VLAN ID -> tenant_id.
#[map]
static TENANT_VLAN_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// LPM trie for subnet-based tenant resolution (IPv4).
/// Key = `[u8; 4]` (network byte order), Value = `tenant_id`.
#[map]
static TENANT_SUBNET_V4: LpmTrie<[u8; 4], u32> =
    LpmTrie::with_max_entries(MAX_TENANT_SUBNET_LPM_ENTRIES, 0);

/// LPM trie for subnet-based tenant resolution (IPv6).
/// Key = `[u8; 16]` (network byte order), Value = `tenant_id`.
#[map]
static TENANT_SUBNET_V6: LpmTrie<[u8; 16], u32> =
    LpmTrie::with_max_entries(MAX_TENANT_SUBNET_V6_LPM_ENTRIES, 0);

/// LPM Trie for O(log n) IPv4 source CIDR matching (CIDR-only rules).
#[map]
static FW_LPM_SRC_V4: LpmTrie<[u8; 4], LpmValue> = LpmTrie::with_max_entries(MAX_LPM_RULES, 0);

/// LPM Trie for O(log n) IPv4 destination CIDR matching.
#[map]
static FW_LPM_DST_V4: LpmTrie<[u8; 4], LpmValue> = LpmTrie::with_max_entries(MAX_LPM_RULES, 0);

/// LPM Trie for O(log n) IPv6 source CIDR matching.
#[map]
static FW_LPM_SRC_V6: LpmTrie<[u8; 16], LpmValue> = LpmTrie::with_max_entries(MAX_LPM_RULES, 0);

/// LPM Trie for O(log n) IPv6 destination CIDR matching.
#[map]
static FW_LPM_DST_V6: LpmTrie<[u8; 16], LpmValue> = LpmTrie::with_max_entries(MAX_LPM_RULES, 0);

// ── Conntrack fast-path maps (read-only, shared via pinning) ────────

/// Shared conntrack table for ESTABLISHED bypass (read-only in XDP).
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v4, written by tc-conntrack.
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 0);

/// Shared conntrack table for IPv6 ESTABLISHED bypass (read-only in XDP).
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v6, written by tc-conntrack.
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValueV6> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 0);

// ── IP Set maps ─────────────────────────────────────────────────────

/// IPv4 IP set HashMap for large alias matching (GeoIP, blocklists).
/// Key: (set_id, addr). Presence = membership.
#[map]
static FW_IPSET_V4: HashMap<IpSetKeyV4, u8> = HashMap::with_max_entries(MAX_IPSET_ENTRIES_V4, 0);

// ── Connection limit maps (Epic 25) ─────────────────────────────────

/// Per-source-IP state counter. Keyed by source IPv4 address (u32).
/// Tracks concurrent connections and connection rate for overload protection.
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_src_counters, shared with tc-conntrack.
#[map]
static CT_SRC_COUNTERS: HashMap<u32, SrcStateCounter> =
    HashMap::with_max_entries(CT_SRC_COUNTER_MAX, 0);

/// Global conntrack configuration (single element). Read by XDP for limit thresholds.
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_config.
#[map]
static CT_CONFIG: Array<ConnTrackConfig> = Array::with_max_entries(1, 0);

/// Per-rule state counter. Index = rule index in FIREWALL_RULES array.
/// Tracks how many active connections were admitted by each rule.
#[map]
static FW_RULE_STATE_COUNT: Array<u32> = Array::with_max_entries(MAX_FIREWALL_RULES, 0);

/// CpuMap for DDoS CPU steering. When populated by userspace, dropped
/// packets are redirected to dedicated CPUs for rate-limited analysis
/// instead of being silently discarded. Falls back to XDP_DROP when
/// the map is empty (default behavior, no userspace wiring needed).
#[map]
static DDOS_CPUMAP: CpuMap = CpuMap::with_max_entries(128, 0);

// ── Metric indices ──────────────────────────────────────────────────

const METRIC_PASSED: u32 = 0;
const METRIC_DROPPED: u32 = 1;
const METRIC_ERRORS: u32 = 2;
const METRIC_EVENTS_DROPPED: u32 = 3;
const METRIC_TOTAL_SEEN: u32 = 4;
const METRIC_REJECTED: u32 = 5;

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    ringbuf_has_backpressure!(EVENTS)
}


// ── Interface group helpers ──────────────────────────────────────────

/// Get the interface group membership for the current packet's ingress interface.
#[inline(always)]
fn get_iface_groups(ctx: &XdpContext) -> u32 {
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    match unsafe { INTERFACE_GROUPS.get(&ifindex) } {
        Some(&groups) => groups,
        None => 0, // no group membership = floating rules only
    }
}

/// Check if a rule's `group_mask` matches the interface's group membership.
#[inline(always)]
fn group_matches(rule_group_mask: u32, iface_groups: u32) -> bool {
    let mask = rule_group_mask & 0x7FFF_FFFF;
    if mask == 0 {
        return true; // floating rule
    }
    let hit = (mask & iface_groups) != 0;
    let invert = (rule_group_mask & 0x8000_0000) != 0;
    hit != invert
}

/// Resolve the tenant ID for the current packet.
/// Priority: VLAN-based > interface-based > subnet (LPM) > default (0).
///
/// # Network namespace cookie (future)
/// `bpf_get_netns_cookie` provides a stable per-namespace u64 identifier that
/// can serve as a kernel-level container boundary for tenant isolation, without
/// relying on VLAN tags or LPM subnet matching.  Available in XDP context since
/// kernel 5.14.  Wire it into tenant matching when namespace-based tenancy is
/// enabled:
///
/// ```ignore
/// // Network namespace cookie can be used for container-level tenant identification
/// // without relying on LPM subnet matching. Available via:
/// //   let ns_cookie = unsafe { bpf_get_netns_cookie(ctx.ctx as *mut _) };
/// // NOTE(future): Wire ns_cookie into tenant matching when namespace-based tenancy is enabled
/// ```
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

// ── bpf_loop context structs ─────────────────────────────────────────
//
// Stack budget analysis (eBPF limit: 512 bytes per stack frame):
//
// RuleScanCtx (IPv4):
//   count(4) + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) +
//   protocol(1) + vlan_id(2) + ct_state(1) + tcp_flags(1) + icmp_type(1) +
//   icmp_code(1) + dscp(1) + src_mac(6) + dst_mac(6) + matched_action(4) +
//   matched_rule_idx(4) + matched_max_states(2)
//   = ~46 bytes (with padding, ~48 bytes)
//
// RuleScanCtxV6 (IPv6):
//   count(4) + src_addr(16) + dst_addr(16) + src_port(2) + dst_port(2) +
//   protocol(1) + vlan_id(2) + ct_state(1) + tcp_flags(1) + icmp_type(1) +
//   icmp_code(1) + dscp(1) + src_mac(6) + dst_mac(6) + matched_action(4) +
//   matched_rule_idx(4) + matched_max_states(2)
//   = ~70 bytes (with padding, ~72 bytes)
//
// Both are well within the 512-byte limit. Crucially, process_firewall_v4
// and process_firewall_v6 are both #[inline(never)], so the V4 and V6
// scan contexts never coexist on the same stack frame. The compiler gives
// each function its own 512-byte budget:
//   - process_firewall_v4: RuleScanCtx (~48 bytes) + locals (~60 bytes)
//   - process_firewall_v6: RuleScanCtxV6 (~72 bytes) + locals (~80 bytes)
//
// The bpf_loop callbacks (scan_rule_v4, scan_rule_v6) are also
// #[inline(never)], so their stack usage (pointer casts, map lookups) does
// not accumulate with the caller's frame.

/// Opaque context passed through `bpf_loop` to the IPv4 rule-scan callback.
#[repr(C)]
struct RuleScanCtx {
    count: u32,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan_id: u16,
    /// Conntrack state for this packet (CT_STATE_* constant, 0xFF = unknown).
    ct_state: u8,
    /// Raw TCP flags byte from the TCP header (0 if not TCP).
    tcp_flags: u8,
    /// ICMP type (0xFF if not ICMP).
    icmp_type: u8,
    /// ICMP code (0xFF if not ICMP).
    icmp_code: u8,
    /// DSCP value extracted from IP TOS field (ip.tos >> 2).
    dscp: u8,
    /// Source MAC address from Ethernet header.
    src_mac: [u8; 6],
    /// Destination MAC address from Ethernet header.
    dst_mac: [u8; 6],
    /// -1 = no match yet, 0+ = matched rule action.
    matched_action: i32,
    /// Index of the matched rule (-1 = none).
    matched_rule_idx: i32,
    /// Max states for the matched rule (0 = unlimited).
    matched_max_states: u16,
    /// Interface group membership bitmask for the ingress interface.
    iface_groups: u32,
    /// Resolved tenant ID for the current packet.
    tenant_id: u32,
}

/// Opaque context passed through `bpf_loop` to the IPv6 rule-scan callback.
#[repr(C)]
struct RuleScanCtxV6 {
    count: u32,
    src_addr: [u32; 4],
    dst_addr: [u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan_id: u16,
    /// Conntrack state for this packet (CT_STATE_* constant, 0xFF = unknown).
    ct_state: u8,
    /// Raw TCP flags byte from the TCP header (0 if not TCP).
    tcp_flags: u8,
    /// ICMP type (0xFF if not `ICMPv6`).
    icmp_type: u8,
    /// ICMP code (0xFF if not `ICMPv6`).
    icmp_code: u8,
    /// DSCP value extracted from IPv6 traffic class (tc >> 2).
    dscp: u8,
    /// Source MAC address from Ethernet header.
    src_mac: [u8; 6],
    /// Destination MAC address from Ethernet header.
    dst_mac: [u8; 6],
    /// -1 = no match yet, 0+ = matched rule action.
    matched_action: i32,
    /// Index of the matched rule (-1 = none).
    matched_rule_idx: i32,
    /// Max states for the matched rule (0 = unlimited).
    matched_max_states: u16,
    /// Interface group membership bitmask for the ingress interface.
    iface_groups: u32,
    /// Resolved tenant ID for the current packet.
    tenant_id: u32,
}

// PacketCtx imported from ebpf_common::firewall (shared with xdp-firewall-reject).

// ── bpf_loop callbacks ──────────────────────────────────────────────

/// Callback for `bpf_loop`: scan one IPv4 firewall rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
unsafe extern "C" fn scan_rule_v4(index: u32, ctx: *mut c_void) -> i64 {
    unsafe {
        let lctx = &mut *(ctx as *mut RuleScanCtx);
        if index >= lctx.count {
            return 1;
        }
        if let Some(rule) = FIREWALL_RULES.get(index) {
            // Check interface group membership before evaluating rule fields.
            if !group_matches(rule.group_mask, lctx.iface_groups) {
                return 0; // group mismatch, continue to next rule
            }
            if rule.tenant_id != 0 && rule.tenant_id != lctx.tenant_id {
                return 0; // tenant mismatch, continue to next rule
            }
            if match_rule_v4(
                rule,
                lctx.src_ip,
                lctx.dst_ip,
                lctx.src_port,
                lctx.dst_port,
                lctx.protocol,
                lctx.vlan_id,
                lctx.ct_state,
                lctx.tcp_flags,
                lctx.icmp_type,
                lctx.icmp_code,
                lctx.dscp,
                &lctx.src_mac,
                &lctx.dst_mac,
            ) {
                lctx.matched_action = rule.action as i32;
                lctx.matched_rule_idx = index as i32;
                lctx.matched_max_states = rule.max_states;
                return 1;
            }
        }
        0
    }
}

/// Callback for `bpf_loop`: scan one IPv6 firewall rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
unsafe extern "C" fn scan_rule_v6(index: u32, ctx: *mut c_void) -> i64 {
    unsafe {
        let lctx = &mut *(ctx as *mut RuleScanCtxV6);
        if index >= lctx.count {
            return 1;
        }
        if let Some(rule) = FIREWALL_RULES_V6.get(index) {
            // Check interface group membership before evaluating rule fields.
            if !group_matches(rule.group_mask, lctx.iface_groups) {
                return 0; // group mismatch, continue to next rule
            }
            if rule.tenant_id != 0 && rule.tenant_id != lctx.tenant_id {
                return 0; // tenant mismatch, continue to next rule
            }
            if match_rule_v6(
                rule,
                &lctx.src_addr,
                &lctx.dst_addr,
                lctx.src_port,
                lctx.dst_port,
                lctx.protocol,
                lctx.vlan_id,
                lctx.ct_state,
                lctx.tcp_flags,
                lctx.icmp_type,
                lctx.icmp_code,
                lctx.dscp,
                &lctx.src_mac,
                &lctx.dst_mac,
            ) {
                lctx.matched_action = rule.action as i32;
                lctx.matched_rule_idx = index as i32;
                lctx.matched_max_states = rule.max_states;
                return 1;
            }
        }
        0
    }
}

// ── Entry point ─────────────────────────────────────────────────────

/// XDP entry point. Delegates to try_xdp_firewall; any error returns XDP_PASS
/// (NFR15: default-to-pass on internal error).
#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    increment_metric(METRIC_TOTAL_SEEN);
    let action = match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            xdp_action::XDP_PASS
        }
    };
    // Tail calls must happen in the XDP entry point (not subprogs) to
    // satisfy kernel 6.17+ verifier: "tail_call is only allowed in
    // functions that return 'int'".
    if action == XDP_ACTION_REJECT {
        // Reject via tail-call to xdp-firewall-reject (slot 1).
        // PKT_CTX is already populated by process_firewall_v4/v6.
        // Falls back to DROP if the reject program is not loaded.
        unsafe {
            let _ = XDP_PROG_ARRAY.tail_call(&ctx, PROG_IDX_REJECT);
        }
        return xdp_action::XDP_DROP;
    }
    if action == xdp_action::XDP_PASS {
        unsafe {
            let _ = XDP_PROG_ARRAY.tail_call(&ctx, PROG_IDX_RATELIMIT);
        }
    }
    action
}

/// Read the default policy from the map (0=pass, 1=drop).
#[inline(always)]
fn read_default_policy() -> u8 {
    match FIREWALL_DEFAULT_POLICY.get(0) {
        Some(&val) => val,
        None => 0, // default to pass if map read fails
    }
}

/// Apply the default policy action. Reads packet metadata from `PKT_CTX`.
#[inline(always)]
fn apply_default_policy(ctx: &XdpContext) -> Result<u32, ()> {
    let policy = read_default_policy();
    if policy == DEFAULT_POLICY_DROP {
        emit_event(ACTION_DROP);
        increment_metric(METRIC_DROPPED);
        Ok(xdp_action::XDP_DROP)
    } else {
        increment_metric(METRIC_PASSED);
        write_xdp_metadata(ctx, ACTION_PASS, 0);
        Ok(xdp_action::XDP_PASS)
    }
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;
    let mut vlan_id: u16 = 0;
    let mut flags: u8 = 0;

    // Check for 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        flags |= FLAG_VLAN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            vlan_id = u16::from_be(unsafe { (*vhdr2).tci }) & 0x0FFF;
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
    }

    // NOTE: Dynamic VLAN tagging (bpf_skb_vlan_push/pop) requires TC classifier
    // context. XDP only supports parsing existing VLAN tags. For VLAN quarantine
    // tagging, use the tc-threatintel program which has TC context.

    if ether_type == ETH_P_IP {
        process_firewall_v4(ctx, l3_offset, vlan_id, flags)
    } else if ether_type == ETH_P_IPV6 {
        process_firewall_v6(ctx, l3_offset, vlan_id, flags | FLAG_IPV6)
    } else {
        increment_metric(METRIC_PASSED);
        Ok(xdp_action::XDP_PASS)
    }
}

/// IPv4 firewall processing: linear scan of FIREWALL_RULES array.
///
/// `#[inline(never)]` ensures this function gets its own stack frame
/// (~48 bytes for `RuleScanCtx` + locals), separate from the IPv6 path.
#[inline(never)]
fn process_firewall_v4(
    ctx: &XdpContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<u32, ()> {
    // Read MACs via inline asm (u32+u16 loads). LLVM cannot outline these
    // into memcpy, and the bounds proof from ptr_at stays in this frame.
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(src_mac.as_mut_ptr(), p.add(6));
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };

    // Extract DSCP from TOS field (top 6 bits).
    let tos = unsafe { (*ipv4hdr).tos };
    let dscp = tos >> 2;

    // ihl() returns the header length in bytes (already multiplied by 4)
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Parse L4 ports + TCP flags + ICMP type/code
    let mut tcp_flags: u8 = 0;
    let mut icmp_type: u8 = ICMP_WILDCARD;
    let mut icmp_code: u8 = ICMP_WILDCARD;

    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            // Extract TCP flags byte (offset 13 in TCP header).
            // network_types TcpHdr stores flags in individual bitfields;
            // read the raw byte at offset 13 for the flags bitmask.
            // Read raw TCP flags byte at offset 13 in the TCP header.
            tcp_flags = unsafe { *(tcphdr as *const u8).add(13) };
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
            )
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
            )
        }
        IpProto::Icmp => {
            let icmphdr: *const IcmpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            icmp_type = unsafe { (*icmphdr).r#type };
            icmp_code = unsafe { (*icmphdr).code };
            (0u16, 0u16)
        }
        _ => (0u16, 0u16),
    };

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];

    // Populate per-CPU packet context for apply_action / emit_event.
    let pkt_ctx = PKT_CTX.get_ptr_mut(0).ok_or(())?;
    unsafe {
        (*pkt_ctx).src_addr = src_addr;
        (*pkt_ctx).dst_addr = dst_addr;
        (*pkt_ctx).src_port = src_port;
        (*pkt_ctx).dst_port = dst_port;
        (*pkt_ctx).protocol = protocol as u8;
        (*pkt_ctx).flags = flags;
        (*pkt_ctx).vlan_id = vlan_id;
        (*pkt_ctx).l3_offset = l3_offset as u16;
        (*pkt_ctx).l4_offset = l4_offset as u16;
    }

    // Phase 0: Overload blacklist fast-path check.
    // If source IP is in the overload set (set_id=255), drop immediately.
    let overload_key = IpSetKeyV4 {
        set_id: OVERLOAD_SET_ID as u16,
        _pad: [0; 2],
        addr: src_ip,
    };
    if unsafe { FW_IPSET_V4.get(&overload_key) }.is_some() {
        increment_metric(METRIC_DROPPED);
        return Ok(xdp_action::XDP_DROP);
    }

    // Phase 0: Conntrack lookup.
    // Look up the connection state once; used for fast-path bypass and
    // ct_state_mask matching during the rule scan.
    let ct_key = normalize_key_v4(src_ip, dst_ip, src_port, dst_port, protocol as u8);
    let ct_state: u8 = if let Some(ct) = unsafe { CT_TABLE_V4.get(&ct_key) } {
        // Fast-path bypass: ESTABLISHED/RELATED skip rule evaluation entirely.
        if ct.state == CT_STATE_ESTABLISHED || ct.state == CT_STATE_RELATED {
            increment_metric(METRIC_PASSED);
            write_xdp_metadata(ctx, ACTION_PASS, 0);
            return Ok(xdp_action::XDP_PASS);
        }
        ct.state
    } else {
        0xFF // No conntrack entry — treated as "unknown"
    };

    // Phase 1: LPM Trie lookup — O(log n) for CIDR-only rules.
    // Keys use network byte order for correct prefix matching.
    let src_key = Key::new(32, src_ip.to_be_bytes());
    if let Some(val) = FW_LPM_SRC_V4.get(&src_key) {
        return apply_action(ctx, val.action);
    }
    let dst_key = Key::new(32, dst_ip.to_be_bytes());
    if let Some(val) = FW_LPM_DST_V4.get(&dst_key) {
        return apply_action(ctx, val.action);
    }

    // Phase 1b: 5-tuple exact-match HashMap lookup — O(1).
    let hash_key_5t = FwHashKey5Tuple {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: protocol as u8,
        _pad: [0; 3],
    };
    if let Some(val) = unsafe { FW_HASH_5TUPLE.get(&hash_key_5t) } {
        return apply_action(ctx, val.action);
    }

    // Phase 1c: protocol+port HashMap lookup — O(1).
    let hash_key_port = FwHashKeyPort {
        dst_port,
        protocol: protocol as u8,
        _pad: 0,
    };
    if let Some(val) = unsafe { FW_HASH_PORT.get(&hash_key_port) } {
        return apply_action(ctx, val.action);
    }

    // Phase 2: Linear scan for complex rules (port ranges, VLAN, MAC, CT state).
    // Read rule count
    let count = match FIREWALL_RULE_COUNT.get(0) {
        Some(&c) => c,
        None => 0,
    };

    // Scan rules via bpf_loop (kernel 5.17+): verifier analyzes the callback
    // body only once, allowing up to 4096 rules without complexity limits.
    // The scan context is on the stack (not a PerCpuArray map value) because
    // kernel 6.17+ requires the bpf_loop callback_ctx (R3) to be a stack
    // frame pointer, not a map_value pointer.
    let iface_groups = get_iface_groups(ctx);
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let tenant_id = unsafe { resolve_tenant_id(ifindex, vlan_id, src_ip) };

    let mut scan_ctx = RuleScanCtx {
        count,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol: protocol as u8,
        vlan_id,
        ct_state,
        tcp_flags,
        icmp_type,
        icmp_code,
        dscp,
        src_mac: [0; 6],
        dst_mac: [0; 6],
        matched_action: -1,
        matched_rule_idx: -1,
        matched_max_states: 0,
        iface_groups,
        tenant_id,
    };
    scan_ctx.src_mac = src_mac;
    scan_ctx.dst_mac = dst_mac;
    unsafe {
        bpf_loop(
            MAX_FIREWALL_RULES,
            scan_rule_v4 as *mut c_void,
            &mut scan_ctx as *mut RuleScanCtx as *mut c_void,
            0,
        );
    }
    let matched_action = scan_ctx.matched_action;
    let matched_rule_idx = scan_ctx.matched_rule_idx;
    let matched_max_states = scan_ctx.matched_max_states;

    if matched_action >= 0 {
        let action = matched_action as u8;
        // For PASS/LOG on NEW connections, enforce connection limits.
        if (action == ACTION_PASS || action == ACTION_LOG)
            && (ct_state == CT_STATE_NEW || ct_state == 0xFF)
        {
            if !check_connection_limits(src_ip, matched_rule_idx, matched_max_states) {
                // Connection limit exceeded → DROP.
                emit_event(ACTION_DROP);
                increment_metric(METRIC_DROPPED);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        return apply_action(ctx, action);
    }

    // No rule matched — apply default policy
    apply_default_policy(ctx)
}

/// Check if an IPv4 rule matches the packet fields.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn match_rule_v4(
    rule: &FirewallRuleEntry,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan_id: u16,
    ct_state: u8,
    tcp_flags: u8,
    icmp_type: u8,
    icmp_code: u8,
    dscp: u8,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
) -> bool {
    let flags = rule.match_flags;
    let flags2 = rule.match_flags2;

    // Protocol check
    if (flags & MATCH_PROTO) != 0 && rule.protocol != protocol {
        return false;
    }

    // Source MAC check (L2, before IP parsing)
    if (flags2 & MATCH2_SRC_MAC) != 0 && !mac_eq(src_mac, &rule.src_mac) {
        return false;
    }

    // Destination MAC check (L2)
    if (flags2 & MATCH2_DST_MAC) != 0 && !mac_eq(dst_mac, &rule.dst_mac) {
        return false;
    }

    // Source IP (CIDR match: masked comparison), with optional negation
    if (flags & MATCH_SRC_IP) != 0 {
        let matched = (src_ip & rule.src_mask) == rule.src_ip;
        let negated = (flags2 & MATCH2_NEGATE_SRC) != 0;
        if matched == negated {
            return false;
        }
    }

    // Destination IP (CIDR match), with optional negation
    if (flags & MATCH_DST_IP) != 0 {
        let matched = (dst_ip & rule.dst_mask) == rule.dst_ip;
        let negated = (flags2 & MATCH2_NEGATE_DST) != 0;
        if matched == negated {
            return false;
        }
    }

    // Source port range
    if (flags & MATCH_SRC_PORT) != 0
        && (src_port < rule.src_port_start || src_port > rule.src_port_end)
    {
        return false;
    }

    // Destination port range
    if (flags & MATCH_DST_PORT) != 0
        && (dst_port < rule.dst_port_start || dst_port > rule.dst_port_end)
    {
        return false;
    }

    // VLAN check (0 = match any)
    if rule.vlan_id != 0 && rule.vlan_id != vlan_id {
        return false;
    }

    // Conntrack state check
    if (flags & MATCH_CT_STATE) != 0 {
        let ct_bit = ct_state_to_bitmask(ct_state);
        if (rule.ct_state_mask & ct_bit) == 0 {
            return false;
        }
    }

    // TCP flags check: (packet_flags & mask) == match_value
    if (flags2 & MATCH2_TCP_FLAGS) != 0 && (tcp_flags & rule.tcp_flags_mask) != rule.tcp_flags_match
    {
        return false;
    }

    // ICMP type check
    if (flags2 & MATCH2_ICMP_TYPE) != 0 && icmp_type != rule.icmp_type {
        return false;
    }

    // ICMP code check
    if (flags2 & MATCH2_ICMP_CODE) != 0 && icmp_code != rule.icmp_code {
        return false;
    }

    // DSCP check
    if (flags2 & MATCH2_DSCP) != 0 && dscp != rule.dscp_match {
        return false;
    }

    // Source IP set check
    if (flags & MATCH_SRC_SET) != 0 {
        let key = IpSetKeyV4 {
            set_id: rule.src_set_id as u16,
            _pad: [0; 2],
            addr: src_ip,
        };
        if unsafe { FW_IPSET_V4.get(&key) }.is_none() {
            return false;
        }
    }

    // Destination IP set check
    if (flags & MATCH_DST_SET) != 0 {
        let key = IpSetKeyV4 {
            set_id: rule.dst_set_id as u16,
            _pad: [0; 2],
            addr: dst_ip,
        };
        if unsafe { FW_IPSET_V4.get(&key) }.is_none() {
            return false;
        }
    }

    true
}

/// Compare two 6-byte MAC addresses for equality.
#[inline(always)]
fn mac_eq(a: &[u8; 6], b: &[u8; 6]) -> bool {
    // Compiler optimizes to 4+2 byte loads on x86.
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3] && a[4] == b[4] && a[5] == b[5]
}

/// Check per-source connection limits and per-rule state limits.
///
/// Returns `true` if the connection should be allowed, `false` if it
/// should be dropped due to exceeding limits.
///
/// Only called for NEW connections (ct_state == CT_STATE_NEW or 0xFF)
/// that matched an ALLOW rule.
#[inline(never)]
fn check_connection_limits(src_ip: u32, rule_idx: i32, max_rule_states: u16) -> bool {
    // Read conntrack config for global limits.
    let cfg = match CT_CONFIG.get(0) {
        Some(c) => c,
        None => return true, // No config → no limits
    };

    // Check per-source limits.
    if cfg.max_src_states > 0 || cfg.max_src_conn_rate > 0 {
        if let Some(counter) = unsafe { CT_SRC_COUNTERS.get(&src_ip) } {
            // Already overloaded → DROP immediately.
            if (counter.flags & SRC_COUNTER_FLAG_OVERLOADED) != 0 {
                return false;
            }
            // Check concurrent connection limit.
            if cfg.max_src_states > 0 && counter.conn_count >= cfg.max_src_states {
                return false;
            }
            // Check connection rate limit.
            if cfg.max_src_conn_rate > 0 {
                let now = unsafe { bpf_ktime_get_boot_ns() };
                let window_ns = (cfg.conn_rate_window_secs as u64) * 1_000_000_000;
                let elapsed = now.saturating_sub(counter.window_start_ns);
                // Within the current rate window.
                if elapsed < window_ns && counter.conn_rate >= cfg.max_src_conn_rate {
                    // Rate exceeded → mark as overloaded and add to blacklist.
                    let overloaded = SrcStateCounter {
                        conn_count: counter.conn_count,
                        conn_rate: counter.conn_rate,
                        window_start_ns: counter.window_start_ns,
                        flags: counter.flags | SRC_COUNTER_FLAG_OVERLOADED,
                        _pad: [0; 7],
                    };
                    let _ = CT_SRC_COUNTERS.insert(&src_ip, &overloaded, 0);
                    // Add to overload IP set for fast-path rejection.
                    let ipset_key = IpSetKeyV4 {
                        set_id: OVERLOAD_SET_ID as u16,
                        _pad: [0; 2],
                        addr: src_ip,
                    };
                    let _ = FW_IPSET_V4.insert(&ipset_key, &1u8, 0);
                    return false;
                }
            }
        }
        // Increment counters (insert new entry if absent).
        let now = unsafe { bpf_ktime_get_boot_ns() };
        let new_counter = if let Some(existing) = unsafe { CT_SRC_COUNTERS.get(&src_ip) } {
            let window_ns = (cfg.conn_rate_window_secs as u64) * 1_000_000_000;
            let elapsed = now.saturating_sub(existing.window_start_ns);
            if elapsed >= window_ns {
                // Rate window expired — reset rate counter.
                SrcStateCounter {
                    conn_count: existing.conn_count + 1,
                    conn_rate: 1,
                    window_start_ns: now,
                    flags: existing.flags,
                    _pad: [0; 7],
                }
            } else {
                SrcStateCounter {
                    conn_count: existing.conn_count + 1,
                    conn_rate: existing.conn_rate + 1,
                    window_start_ns: existing.window_start_ns,
                    flags: existing.flags,
                    _pad: [0; 7],
                }
            }
        } else {
            SrcStateCounter {
                conn_count: 1,
                conn_rate: 1,
                window_start_ns: now,
                flags: 0,
                _pad: [0; 7],
            }
        };
        let _ = CT_SRC_COUNTERS.insert(&src_ip, &new_counter, 0);
    }

    // Check per-rule state limit.
    if max_rule_states > 0 && rule_idx >= 0 {
        if let Some(count_ptr) = FW_RULE_STATE_COUNT.get_ptr_mut(rule_idx as u32) {
            let current = unsafe { *count_ptr };
            if current >= max_rule_states as u32 {
                return false;
            }
            // Increment atomically.
            unsafe {
                *count_ptr = current + 1;
            }
        }
    }

    true
}

/// Convert a conntrack state constant to the corresponding CT_MATCH_* bitmask.
#[inline(always)]
fn ct_state_to_bitmask(state: u8) -> u8 {
    use ebpf_common::conntrack::*;
    match state {
        CT_STATE_NEW => CT_MATCH_NEW,
        CT_STATE_ESTABLISHED => CT_MATCH_ESTABLISHED,
        CT_STATE_RELATED => CT_MATCH_RELATED,
        CT_STATE_INVALID => CT_MATCH_INVALID,
        // For sub-states (SYN_SENT, SYN_RECV, FIN_WAIT, etc.) treat as NEW
        CT_STATE_SYN_SENT | CT_STATE_SYN_RECV => CT_MATCH_NEW,
        CT_STATE_FIN_WAIT | CT_STATE_CLOSE_WAIT | CT_STATE_TIME_WAIT => CT_MATCH_ESTABLISHED,
        _ => 0, // Unknown / no entry — matches nothing
    }
}

/// Perform IPv6 conntrack lookup. Returns the connection state, or 0xFF if
/// no entry exists.
#[inline(never)]
fn conntrack_lookup_v6(
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    next_hdr: u8,
) -> u8 {
    let ct_key_v6 = normalize_key_v6(src_addr, dst_addr, src_port, dst_port, next_hdr);
    if let Some(ct) = unsafe { CT_TABLE_V6.get(&ct_key_v6) } {
        ct.state
    } else {
        0xFF
    }
}

/// Perform IPv6 LPM trie lookup for source and destination CIDRs.
/// Returns the matched action (>=0) or -1 if no LPM match.
/// Reads raw IPv6 bytes from the `PacketCtx` pointer.
#[inline(never)]
fn lpm_lookup_v6(pkt_ctx: *const PacketCtx) -> i32 {
    let src_bytes = unsafe { (*pkt_ctx).src_bytes_v6 };
    let src_key_v6 = Key::new(128, src_bytes);
    if let Some(val) = FW_LPM_SRC_V6.get(&src_key_v6) {
        return val.action as i32;
    }
    let dst_bytes = unsafe { (*pkt_ctx).dst_bytes_v6 };
    let dst_key_v6 = Key::new(128, dst_bytes);
    if let Some(val) = FW_LPM_DST_V6.get(&dst_key_v6) {
        return val.action as i32;
    }
    -1
}

/// IPv6 firewall processing: linear scan of FIREWALL_RULES_V6 array.
///
/// `#[inline(never)]` is critical here: it gives this function its own
/// 512-byte stack frame, preventing `RuleScanCtxV6` (~72 bytes) from
/// accumulating with `RuleScanCtx` (~48 bytes) in `process_firewall_v4`.
#[inline(never)]
fn process_firewall_v6(
    ctx: &XdpContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut dst_mac = [0u8; 6];
    let mut src_mac = [0u8; 6];
    unsafe {
        let p = ethhdr as *const u8;
        copy_mac_asm!(dst_mac.as_mut_ptr(), p);
        copy_mac_asm!(src_mac.as_mut_ptr(), p.add(6));
    }

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Extract DSCP from IPv6 traffic class. The _vtcfl field is:
    // [version(4b)][traffic_class(8b)][flow_label(20b)] in network byte order.
    let vtcfl = u32::from_be(unsafe { (*ipv6hdr)._vtcfl });
    let traffic_class = ((vtcfl >> 20) & 0xFF) as u8;
    let dscp = traffic_class >> 2;

    // NOTE: IPsec/XFRM state detection (bpf_skb_get_xfrm_state) requires TC
    // classifier context. The IPv6 extension header parser already handles ESP
    // (proto 50) as a terminal header — see the skip_ipv6_ext_headers fix.

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) =
        skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr).ok_or(())?;

    // Populate per-CPU packet context early so IPv6 addresses live off-stack.
    let pkt_ctx = PKT_CTX.get_ptr_mut(0).ok_or(())?;
    unsafe {
        (*pkt_ctx).src_bytes_v6 = (*ipv6hdr).src_addr;
        (*pkt_ctx).dst_bytes_v6 = (*ipv6hdr).dst_addr;
        (*pkt_ctx).src_addr = ipv6_addr_to_u32x4(&(*pkt_ctx).src_bytes_v6);
        (*pkt_ctx).dst_addr = ipv6_addr_to_u32x4(&(*pkt_ctx).dst_bytes_v6);
        (*pkt_ctx).flags = flags;
        (*pkt_ctx).vlan_id = vlan_id;
        (*pkt_ctx).protocol = next_hdr;
        (*pkt_ctx).l3_offset = l3_offset as u16;
        (*pkt_ctx).l4_offset = l4_offset as u16;
    }

    // Parse L4 ports + TCP flags + ICMPv6 type/code
    let mut tcp_flags: u8 = 0;
    let mut icmp_type: u8 = ICMP_WILDCARD;
    let mut icmp_code: u8 = ICMP_WILDCARD;

    let (src_port, dst_port) = if next_hdr == PROTO_TCP {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        let flags_ptr = unsafe { (tcphdr as *const u8).add(13) };
        tcp_flags = unsafe { *flags_ptr };
        (
            u16_from_be_bytes(unsafe { (*tcphdr).source }),
            u16_from_be_bytes(unsafe { (*tcphdr).dest }),
        )
    } else if next_hdr == PROTO_UDP {
        let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        (
            u16_from_be_bytes(unsafe { (*udphdr).src }),
            u16_from_be_bytes(unsafe { (*udphdr).dst }),
        )
    } else if next_hdr == PROTO_ICMPV6 {
        let icmphdr: *const IcmpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        icmp_type = unsafe { (*icmphdr).r#type };
        icmp_code = unsafe { (*icmphdr).code };
        (0u16, 0u16)
    } else {
        (0u16, 0u16)
    };

    // Store ports now that we have them.
    unsafe {
        (*pkt_ctx).src_port = src_port;
        (*pkt_ctx).dst_port = dst_port;
    }

    // Read addresses from the off-stack context for local use.
    let src_addr = unsafe { (*pkt_ctx).src_addr };
    let dst_addr = unsafe { (*pkt_ctx).dst_addr };

    // Phase 0: Conntrack lookup (IPv6).
    // Look up the connection state once; used for fast-path bypass and
    // ct_state_mask matching during the rule scan.
    let ct_state: u8 = conntrack_lookup_v6(&src_addr, &dst_addr, src_port, dst_port, next_hdr);
    if ct_state == CT_STATE_ESTABLISHED || ct_state == CT_STATE_RELATED {
        increment_metric(METRIC_PASSED);
        write_xdp_metadata(ctx, ACTION_PASS, 0);
        return Ok(xdp_action::XDP_PASS);
    }

    // Phase 1: LPM Trie lookup — O(log n) for CIDR-only rules.
    // Read raw bytes from off-stack PKT_CTX.
    let lpm_action = lpm_lookup_v6(pkt_ctx);
    if lpm_action >= 0 {
        return apply_action(ctx, lpm_action as u8);
    }

    // Phase 2: Linear scan for complex rules (port, protocol, VLAN).
    // Read V6 rule count
    let count = match FIREWALL_RULE_COUNT_V6.get(0) {
        Some(&c) => c,
        None => 0,
    };

    // Scan V6 rules via bpf_loop (kernel 5.17+).
    // Stack-allocated context (kernel 6.17+ requires bpf_loop callback_ctx
    // to be a stack frame pointer, not a map_value pointer).
    let iface_groups = get_iface_groups(ctx);
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let tenant_id = unsafe { resolve_tenant_id_v6(ifindex, vlan_id, &src_addr) };

    let mut scan_ctx = RuleScanCtxV6 {
        count,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol: next_hdr,
        vlan_id,
        ct_state,
        tcp_flags,
        icmp_type,
        icmp_code,
        dscp,
        src_mac: [0; 6],
        dst_mac: [0; 6],
        matched_action: -1,
        matched_rule_idx: -1,
        matched_max_states: 0,
        iface_groups,
        tenant_id,
    };
    scan_ctx.src_mac = src_mac;
    scan_ctx.dst_mac = dst_mac;
    unsafe {
        bpf_loop(
            MAX_FIREWALL_RULES,
            scan_rule_v6 as *mut c_void,
            &mut scan_ctx as *mut RuleScanCtxV6 as *mut c_void,
            0,
        );
    }
    let matched_action = scan_ctx.matched_action;
    let matched_rule_idx = scan_ctx.matched_rule_idx;
    let matched_max_states = scan_ctx.matched_max_states;

    if matched_action >= 0 {
        let action = matched_action as u8;
        // For PASS/LOG on NEW connections, enforce connection limits.
        // Use src_addr[0] as the source key for the IPv4-keyed counter map.
        if (action == ACTION_PASS || action == ACTION_LOG)
            && (ct_state == CT_STATE_NEW || ct_state == 0xFF)
        {
            if !check_connection_limits(src_addr[0], matched_rule_idx, matched_max_states) {
                emit_event(ACTION_DROP);
                increment_metric(METRIC_DROPPED);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        return apply_action(ctx, action);
    }

    // No rule matched — apply default policy
    apply_default_policy(ctx)
}

/// Check if an IPv6 rule matches the packet fields.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn match_rule_v6(
    rule: &FirewallRuleEntryV6,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan_id: u16,
    ct_state: u8,
    tcp_flags: u8,
    icmp_type: u8,
    icmp_code: u8,
    dscp: u8,
    src_mac: &[u8; 6],
    dst_mac: &[u8; 6],
) -> bool {
    let flags = rule.match_flags;
    let flags2 = rule.match_flags2;

    // Protocol check
    if (flags & MATCH_PROTO) != 0 && rule.protocol != protocol {
        return false;
    }

    // Source MAC check (L2)
    if (flags2 & MATCH2_SRC_MAC) != 0 && !mac_eq(src_mac, &rule.src_mac) {
        return false;
    }

    // Destination MAC check (L2)
    if (flags2 & MATCH2_DST_MAC) != 0 && !mac_eq(dst_mac, &rule.dst_mac) {
        return false;
    }

    // Source IPv6 (CIDR match: compare each u32 word masked), with optional negation
    if (flags & MATCH_SRC_IP) != 0 {
        let matched = (src_addr[0] & rule.src_mask[0]) == rule.src_addr[0]
            && (src_addr[1] & rule.src_mask[1]) == rule.src_addr[1]
            && (src_addr[2] & rule.src_mask[2]) == rule.src_addr[2]
            && (src_addr[3] & rule.src_mask[3]) == rule.src_addr[3];
        let negated = (flags2 & MATCH2_NEGATE_SRC) != 0;
        if matched == negated {
            return false;
        }
    }

    // Destination IPv6 (CIDR match), with optional negation
    if (flags & MATCH_DST_IP) != 0 {
        let matched = (dst_addr[0] & rule.dst_mask[0]) == rule.dst_addr[0]
            && (dst_addr[1] & rule.dst_mask[1]) == rule.dst_addr[1]
            && (dst_addr[2] & rule.dst_mask[2]) == rule.dst_addr[2]
            && (dst_addr[3] & rule.dst_mask[3]) == rule.dst_addr[3];
        let negated = (flags2 & MATCH2_NEGATE_DST) != 0;
        if matched == negated {
            return false;
        }
    }

    // Source port range
    if (flags & MATCH_SRC_PORT) != 0
        && (src_port < rule.src_port_start || src_port > rule.src_port_end)
    {
        return false;
    }

    // Destination port range
    if (flags & MATCH_DST_PORT) != 0
        && (dst_port < rule.dst_port_start || dst_port > rule.dst_port_end)
    {
        return false;
    }

    // VLAN check (0 = match any)
    if rule.vlan_id != 0 && rule.vlan_id != vlan_id {
        return false;
    }

    // Conntrack state check
    if (flags & MATCH_CT_STATE) != 0 {
        let ct_bit = ct_state_to_bitmask(ct_state);
        if (rule.ct_state_mask & ct_bit) == 0 {
            return false;
        }
    }

    // TCP flags check: (packet_flags & mask) == match_value
    if (flags2 & MATCH2_TCP_FLAGS) != 0 && (tcp_flags & rule.tcp_flags_mask) != rule.tcp_flags_match
    {
        return false;
    }

    // ICMP type check
    if (flags2 & MATCH2_ICMP_TYPE) != 0 && icmp_type != rule.icmp_type {
        return false;
    }

    // ICMP code check
    if (flags2 & MATCH2_ICMP_CODE) != 0 && icmp_code != rule.icmp_code {
        return false;
    }

    // DSCP check
    if (flags2 & MATCH2_DSCP) != 0 && dscp != rule.dscp_match {
        return false;
    }

    true
}

/// Apply firewall action (shared by IPv4 and IPv6 paths).
///
/// Reads packet metadata from the `PKT_CTX` per-CPU scratch buffer
/// (must be populated before calling).
///
/// Returns the XDP action. The tail_call to the ratelimit program is
/// performed by the entry point (`xdp_firewall`) when the result is
/// `XDP_PASS` — this satisfies the kernel 6.17+ verifier requirement
/// that tail_call only happens in functions returning `int`.
#[inline(always)]
fn apply_action(ctx: &XdpContext, action: u8) -> Result<u32, ()> {
    match action {
        ACTION_DROP => {
            emit_event(ACTION_DROP);
            increment_metric(METRIC_DROPPED);
            // Try CpuMap redirect for DDoS CPU steering. When userspace has
            // populated DDOS_CPUMAP, dropped packets are redirected to
            // dedicated CPUs for rate-limited analysis instead of being
            // discarded. Falls back to XDP_DROP when the map is empty.
            let cpu = unsafe { bpf_get_smp_processor_id() };
            if DDOS_CPUMAP.redirect(cpu, 0).is_ok() {
                return Ok(xdp_action::XDP_REDIRECT);
            }
            Ok(xdp_action::XDP_DROP)
        }
        ACTION_REJECT => {
            emit_event(ACTION_REJECT);
            increment_metric(METRIC_REJECTED);
            // Return sentinel — the entry point will tail-call to
            // xdp-firewall-reject which has its own 512B stack.
            Ok(XDP_ACTION_REJECT)
        }
        ACTION_LOG => {
            emit_event(ACTION_LOG);
            increment_metric(METRIC_PASSED);
            write_xdp_metadata(ctx, ACTION_LOG, 0);
            Ok(xdp_action::XDP_PASS)
        }
        ACTION_PASS | _ => {
            increment_metric(METRIC_PASSED);
            write_xdp_metadata(ctx, ACTION_PASS, 0);
            Ok(xdp_action::XDP_PASS)
        }
    }
}

// ── Reject logic moved to xdp-firewall-reject (tail-called, slot 1) ──
// Removed: send_reject, send_tcp_rst_v4/v6, send_icmp_unreachable_v4,
// send_icmpv6_unreachable, compute_*_csum (now in ebpf-helpers/checksum.rs).
// See crates/ebpf-programs/xdp-firewall-reject/src/main.rs.

// ── Reject helpers ──────────────────────────────────────────────────
// (moved to xdp-firewall-reject)

// ── Helpers ─────────────────────────────────────────────────────────
// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::xdp



// increment_metric! imported from ebpf_helpers

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(FIREWALL_METRICS, index);
}

/// Prepend `XdpMetadata` to the packet's data_meta area so that TC programs
/// can read the firewall verdict without re-parsing. Best-effort: if
/// `bpf_xdp_adjust_meta` fails (driver doesn't support it), silently skips.
///
/// After `bpf_xdp_adjust_meta`, we must re-read `data_meta` (via
/// `ctx.metadata()`) and `data` (via `ctx.data()`) from the XDP context
/// to satisfy the BPF verifier on kernel 6.17+.
#[inline(always)]
fn write_xdp_metadata(ctx: &XdpContext, action: u8, rule_id: u32) {
    let meta_size = mem::size_of::<XdpMetadata>() as i32;
    let ret = unsafe { bpf_xdp_adjust_meta(ctx.ctx, -meta_size) };
    if ret != 0 {
        return; // Driver doesn't support metadata — skip silently
    }
    // After adjust_meta, re-read pointers from the XDP context so the
    // verifier knows the metadata area is valid.
    let data_meta = ctx.metadata();
    let data = ctx.data();
    if data_meta + mem::size_of::<XdpMetadata>() > data {
        return; // Safety check — required by verifier
    }
    let meta_ptr = data_meta as *mut XdpMetadata;
    unsafe {
        (*meta_ptr).rule_id = rule_id;
        (*meta_ptr).action = action;
        (*meta_ptr).ratelimit_status = 0;
        (*meta_ptr).meta_flags = META_FLAG_PRESENT;
        (*meta_ptr)._pad = 0;
    }
}

/// Emit a `PacketEvent` to the EVENTS RingBuf. Reads packet metadata
/// from the `PKT_CTX` per-CPU scratch buffer (must be populated before
/// calling). Skips emission under backpressure (>75% full). If the
/// buffer is full, increment the events_dropped metric.
#[inline(always)]
fn emit_event(action: u8) {
    if ringbuf_has_backpressure() {
        increment_metric(METRIC_EVENTS_DROPPED);
        return;
    }
    let pkt = match PKT_CTX.get_ptr(0) {
        Some(p) => p,
        None => return,
    };
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).src_addr = (*pkt).src_addr;
            (*ptr).dst_addr = (*pkt).dst_addr;
            (*ptr).src_port = (*pkt).src_port;
            (*ptr).dst_port = (*pkt).dst_port;
            (*ptr).protocol = (*pkt).protocol;
            (*ptr).event_type = EVENT_TYPE_FIREWALL;
            (*ptr).action = action;
            (*ptr).flags = (*pkt).flags;
            (*ptr).rule_id = 0;
            (*ptr).vlan_id = (*pkt).vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0; // Not available in XDP context
        }
        entry.submit(0);
    } else {
        increment_metric(METRIC_EVENTS_DROPPED);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
