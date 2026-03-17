#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::{
        bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_loop, bpf_xdp_adjust_meta,
        bpf_xdp_adjust_tail,
    },
    macros::{map, xdp},
    maps::{
        Array, HashMap, LruHashMap, PerCpuArray, ProgramArray, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::XdpContext,
};
use core::mem;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, IcmpHdr, Ipv6Hdr,
    PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4,
    u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut, skip_ipv6_ext_headers};
use ebpf_helpers::{increment_metric, ringbuf_has_backpressure};
use ebpf_common::{
    conntrack::{
        CT_SRC_COUNTER_MAX, CT_STATE_NEW, ConnKey, ConnKeyV6, ConnTrackConfig, ConnValue,
        ConnValueV6, CT_MAX_ENTRIES_V4, CT_MAX_ENTRIES_V6, CT_STATE_ESTABLISHED, CT_STATE_RELATED,
        OVERLOAD_SET_ID, SRC_COUNTER_FLAG_OVERLOADED, SrcStateCounter, normalize_key_v4,
        normalize_key_v6,
    },
    event::{
        EVENT_TYPE_FIREWALL, FLAG_IPV6, FLAG_VLAN, META_FLAG_PRESENT, PacketEvent, XdpMetadata,
    },
    firewall::{
        ACTION_DROP, ACTION_LOG, ACTION_PASS, ACTION_REJECT, CT_MATCH_ESTABLISHED, CT_MATCH_INVALID,
        CT_MATCH_NEW, CT_MATCH_RELATED, DEFAULT_POLICY_DROP, FirewallRuleEntry,
        FirewallRuleEntryV6, FwHashKey5Tuple, FwHashKeyPort, FwHashValue,
        ICMP_WILDCARD, IpSetKeyV4, LpmValue, MATCH2_DSCP, MATCH2_DST_MAC, MATCH2_ICMP_CODE,
        MATCH2_ICMP_TYPE, MATCH2_NEGATE_DST, MATCH2_NEGATE_SRC, MATCH2_SRC_MAC,
        MATCH2_TCP_FLAGS, MATCH_CT_STATE, MATCH_DST_IP, MATCH_DST_PORT, MATCH_DST_SET,
        MATCH_PROTO, MATCH_SRC_IP, MATCH_SRC_PORT, MATCH_SRC_SET, MAX_FIREWALL_RULES,
        MAX_FW_HASH_5TUPLE, MAX_FW_HASH_PORT, MAX_IPSET_ENTRIES_V4, MAX_LPM_RULES,
    },
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants / types from ebpf-helpers ─────────────────────────────
// Network constants, header structs, ptr_at, skip_ipv6_ext_headers,
// byte helpers, and metric/ringbuf macros are imported from ebpf_helpers.

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

/// User RingBuf for receiving config commands from userspace.
/// Drained at program entry to apply pending rule changes atomically.
#[map]
static CONFIG_RINGBUF: ebpf_helpers::user_ringbuf::UserRingBuf =
    ebpf_helpers::user_ringbuf::UserRingBuf::with_byte_size(
        ebpf_common::config_cmd::CONFIG_RINGBUF_SIZE,
        0,
    );

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

/// Per-interface group membership bitmask. Key = ifindex (u32), Value = group bitmask (u32).
#[map]
static INTERFACE_GROUPS: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

/// Tenant resolution: VLAN ID -> tenant_id.
#[map]
static TENANT_VLAN_MAP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

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
static FW_IPSET_V4: HashMap<IpSetKeyV4, u8> =
    HashMap::with_max_entries(MAX_IPSET_ENTRIES_V4, 0);

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

/// Resolve the tenant ID for the current packet using VLAN and interface signals.
/// Priority: VLAN-based > interface-based > default (0).
#[inline(always)]
unsafe fn resolve_tenant_id(ifindex: u32, vlan_id: u16) -> u32 {
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

/// Per-packet context stored in a `PerCpuArray` to keep addresses and
/// metadata off the 512-byte BPF stack. Populated once per packet,
/// consumed by `apply_action`, `apply_default_policy`, and `emit_event`.
#[repr(C)]
struct PacketCtx {
    src_addr: [u32; 4],
    dst_addr: [u32; 4],
    /// Raw IPv6 source bytes (network order) for LPM trie lookup.
    /// Unused in the IPv4 path.
    src_bytes_v6: [u8; 16],
    /// Raw IPv6 destination bytes (network order) for LPM trie lookup.
    dst_bytes_v6: [u8; 16],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
    /// Byte offset of L3 header from start of packet (for reject).
    l3_offset: u16,
    /// Byte offset of L4 header from start of packet (for reject).
    l4_offset: u16,
}

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
    // Drain pending config commands from userspace (best-effort, non-blocking).
    // This applies any pending rule changes atomically before packet processing.
    CONFIG_RINGBUF.drain(
        drain_config_cmd as *mut core::ffi::c_void,
        core::ptr::null_mut(),
        0,
    );

    increment_metric(METRIC_TOTAL_SEEN);
    let action = match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            xdp_action::XDP_PASS
        }
    };
    // tail_call must happen in the XDP entry point (not subprogs) to
    // satisfy kernel 6.17+ verifier: "tail_call is only allowed in
    // functions that return 'int'".
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
    // Extract Ethernet MAC addresses (always available, parsed before L3).
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

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
    let tenant_id = unsafe { resolve_tenant_id(ifindex, vlan_id) };

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
        src_mac,
        dst_mac,
        matched_action: -1,
        matched_rule_idx: -1,
        matched_max_states: 0,
        iface_groups,
        tenant_id,
    };
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
            if !check_connection_limits(
                src_ip,
                matched_rule_idx,
                matched_max_states,
            ) {
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
    if (flags2 & MATCH2_TCP_FLAGS) != 0
        && (tcp_flags & rule.tcp_flags_mask) != rule.tcp_flags_match
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
fn check_connection_limits(
    src_ip: u32,
    rule_idx: i32,
    max_rule_states: u16,
) -> bool {
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
    // Extract Ethernet MAC addresses (always available, parsed before L3).
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let src_mac = unsafe { (*ethhdr).src_addr };
    let dst_mac = unsafe { (*ethhdr).dst_addr };

    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Extract DSCP from IPv6 traffic class. The _vtcfl field is:
    // [version(4b)][traffic_class(8b)][flow_label(20b)] in network byte order.
    let vtcfl = u32::from_be(unsafe { (*ipv6hdr)._vtcfl });
    let traffic_class = ((vtcfl >> 20) & 0xFF) as u8;
    let dscp = traffic_class >> 2;

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr)
        .ok_or(())?;

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
    let tenant_id = unsafe { resolve_tenant_id(ifindex, vlan_id) };

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
        src_mac,
        dst_mac,
        matched_action: -1,
        matched_rule_idx: -1,
        matched_max_states: 0,
        iface_groups,
        tenant_id,
    };
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
            if !check_connection_limits(
                src_addr[0],
                matched_rule_idx,
                matched_max_states,
            ) {
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
    if (flags2 & MATCH2_TCP_FLAGS) != 0
        && (tcp_flags & rule.tcp_flags_mask) != rule.tcp_flags_match
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
            Ok(xdp_action::XDP_DROP)
        }
        ACTION_REJECT => {
            emit_event(ACTION_REJECT);
            increment_metric(METRIC_REJECTED);
            // Read offsets/protocol from per-CPU context.
            let pkt = match PKT_CTX.get_ptr(0) {
                Some(p) => p,
                None => return Ok(xdp_action::XDP_DROP),
            };
            let protocol = unsafe { (*pkt).protocol };
            let is_ipv6 = unsafe { ((*pkt).flags & FLAG_IPV6) != 0 };
            let l3_off = unsafe { (*pkt).l3_offset as usize };
            let l4_off = unsafe { (*pkt).l4_offset as usize };
            // Try to send a reject response; fall back to DROP on failure.
            match send_reject(ctx, protocol, is_ipv6, l3_off, l4_off) {
                Ok(xdp_act) => Ok(xdp_act),
                Err(()) => Ok(xdp_action::XDP_DROP),
            }
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

// ── Reject helpers ──────────────────────────────────────────────────
//
// These functions construct and send TCP RST or ICMP/ICMPv6 Unreachable
// packets in response to ACTION_REJECT rules. Each function is
// #[inline(never)] to get its own 512-byte BPF stack frame.

/// Dispatch reject response based on protocol and address family.
#[inline(always)]
fn send_reject(
    ctx: &XdpContext,
    protocol: u8,
    is_ipv6: bool,
    l3_off: usize,
    l4_off: usize,
) -> Result<u32, ()> {
    if protocol == PROTO_TCP {
        if is_ipv6 {
            send_tcp_rst_v6(ctx, l3_off, l4_off)
        } else {
            send_tcp_rst_v4(ctx, l3_off, l4_off)
        }
    } else if is_ipv6 {
        send_icmpv6_unreachable(ctx, l3_off, l4_off)
    } else {
        send_icmp_unreachable_v4(ctx, l3_off, l4_off)
    }
}

/// Construct and send a TCP RST for an IPv4 packet.
///
/// Reads incoming TCP seq/ack/flags/ports, truncates the packet to
/// Eth+IP+TCP (no payload/options), swaps addresses, and returns `XDP_TX`.
#[inline(never)]
fn send_tcp_rst_v4(ctx: &XdpContext, l3_off: usize, l4_off: usize) -> Result<u32, ()> {
    // ── Step 1: Read incoming TCP fields BEFORE modifying anything ──
    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
    let in_src_port = unsafe { (*tcphdr).source };
    let in_dst_port = unsafe { (*tcphdr).dest };
    let in_seq = unsafe { (*tcphdr).seq };
    let in_ack_seq = unsafe { (*tcphdr).ack_seq };
    // Raw TCP flags byte at offset 13.
    let in_flags: u8 = unsafe { *(tcphdr as *const u8).add(13) };

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let in_src_addr = unsafe { (*ipv4hdr).src_addr };
    let in_dst_addr = unsafe { (*ipv4hdr).dst_addr };

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let in_src_mac = unsafe { (*ethhdr).src_addr };
    let in_dst_mac = unsafe { (*ethhdr).dst_addr };

    // ── Step 2: Truncate packet to Eth + IP(20) + TCP(20) ──
    // Target size: l3_off + 20 (IP, no options) + 20 (TCP, no options).
    let target_len = l3_off + 20 + 20;
    let current_len = ctx.data_end() - ctx.data();
    let delta = target_len as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }

    // ── Step 3: Re-read ALL pointers after truncation ──
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, l3_off)? };
    let tcp: *mut TcpHdr = unsafe { ptr_at_mut(ctx, l3_off + 20)? };

    // ── Step 4: Swap Ethernet MACs ──
    unsafe {
        (*eth).dst_addr = in_src_mac;
        (*eth).src_addr = in_dst_mac;
    }

    // ── Step 5: Build IPv4 header ──
    unsafe {
        (*ip).set_vihl(4, 20); // version=4, IHL=20 bytes (5 words)
        (*ip).tos = 0;
        (*ip).set_tot_len(40); // 20 IP + 20 TCP
        (*ip).set_id(0);
        (*ip).set_frags(0x02, 0); // DF bit set, no fragment offset
        (*ip).ttl = 64;
        (*ip).proto = IpProto::Tcp;
        // Swap src/dst
        (*ip).src_addr = in_dst_addr;
        (*ip).dst_addr = in_src_addr;
        // Zero checksum before computing
        (*ip).check = [0, 0];
        let csum = compute_ipv4_csum(ip as *const u8, 20);
        (*ip).set_checksum(csum);
    }

    // ── Step 6: Build TCP RST header ──
    let tcp_flags_ack = in_flags & 0x10; // ACK bit
    let tcp_flags_syn = in_flags & 0x02; // SYN bit
    unsafe {
        // Swap ports
        (*tcp).source = in_dst_port;
        (*tcp).dest = in_src_port;

        if tcp_flags_ack != 0 {
            // Incoming had ACK: RST only, seq = incoming ack_seq
            (*tcp).seq = in_ack_seq;
            (*tcp).ack_seq = [0, 0, 0, 0];
            // flags byte at offset 13: RST=0x04
            *(tcp as *mut u8).add(13) = 0x04;
        } else {
            // Incoming was SYN (no ACK): RST+ACK, seq=0, ack = seq+1
            (*tcp).seq = [0, 0, 0, 0];
            // Compute ack = in_seq + 1 (for SYN, payload_len = 0, SYN counts as 1)
            let seq_val = u32::from_be_bytes(in_seq).wrapping_add(
                if tcp_flags_syn != 0 { 1 } else { 0 },
            );
            (*tcp).ack_seq = seq_val.to_be_bytes();
            // flags byte at offset 13: RST+ACK = 0x14
            *(tcp as *mut u8).add(13) = 0x14;
        }

        // data offset = 5 (20 bytes), reserved bits = 0
        // Byte 12 of TCP header: high nibble = data offset
        *(tcp as *mut u8).add(12) = 0x50;
        (*tcp).window = [0, 0];
        (*tcp).urg_ptr = [0, 0];
        (*tcp).check = [0, 0];

        // Compute TCP checksum with pseudo-header.
        let csum = compute_tcp_csum_v4(
            &in_dst_addr, // new src (original dst)
            &in_src_addr, // new dst (original src)
            tcp as *const u8,
            20,
        );
        let csum_be = csum.to_be_bytes();
        (*tcp).check = csum_be;
    }

    Ok(xdp_action::XDP_TX)
}

/// Construct and send a TCP RST for an IPv6 packet.
#[inline(never)]
fn send_tcp_rst_v6(ctx: &XdpContext, l3_off: usize, l4_off: usize) -> Result<u32, ()> {
    // ── Step 1: Read incoming TCP fields ──
    let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_off)? };
    let in_src_port = unsafe { (*tcphdr).source };
    let in_dst_port = unsafe { (*tcphdr).dest };
    let in_seq = unsafe { (*tcphdr).seq };
    let in_ack_seq = unsafe { (*tcphdr).ack_seq };
    let in_flags: u8 = unsafe { *(tcphdr as *const u8).add(13) };

    // Read IPv6 addresses using the inline Ipv6Hdr from ebpf_helpers::net.
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let in_src_addr: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let in_dst_addr: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let in_src_mac = unsafe { (*ethhdr).src_addr };
    let in_dst_mac = unsafe { (*ethhdr).dst_addr };

    // ── Step 2: Truncate to Eth + IPv6(40) + TCP(20) ──
    let target_len = l3_off + IPV6_HDR_LEN + 20;
    let current_len = ctx.data_end() - ctx.data();
    let delta = target_len as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }

    // ── Step 3: Re-read pointers ──
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip6: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, l3_off)? };
    let tcp: *mut TcpHdr = unsafe { ptr_at_mut(ctx, l3_off + IPV6_HDR_LEN)? };

    // ── Step 4: Swap Ethernet MACs ──
    unsafe {
        (*eth).dst_addr = in_src_mac;
        (*eth).src_addr = in_dst_mac;
    }

    // ── Step 5: Build IPv6 header ──
    unsafe {
        // Version=6, traffic class=0, flow label=0
        (*ip6)._vtcfl = (6u32 << 28).to_be();
        // Payload length = 20 (TCP header, no options)
        (*ip6)._payload_len = 20u16.to_be();
        (*ip6).next_hdr = PROTO_TCP;
        (*ip6).hop_limit = 64;
        // Swap src/dst
        (*ip6).src_addr = in_dst_addr;
        (*ip6).dst_addr = in_src_addr;
    }

    // ── Step 6: Build TCP RST header ──
    let tcp_flags_ack = in_flags & 0x10;
    let tcp_flags_syn = in_flags & 0x02;
    unsafe {
        (*tcp).source = in_dst_port;
        (*tcp).dest = in_src_port;

        if tcp_flags_ack != 0 {
            (*tcp).seq = in_ack_seq;
            (*tcp).ack_seq = [0, 0, 0, 0];
            *(tcp as *mut u8).add(13) = 0x04; // RST
        } else {
            (*tcp).seq = [0, 0, 0, 0];
            let seq_val = u32::from_be_bytes(in_seq).wrapping_add(
                if tcp_flags_syn != 0 { 1 } else { 0 },
            );
            (*tcp).ack_seq = seq_val.to_be_bytes();
            *(tcp as *mut u8).add(13) = 0x14; // RST+ACK
        }

        *(tcp as *mut u8).add(12) = 0x50; // data offset = 5
        (*tcp).window = [0, 0];
        (*tcp).urg_ptr = [0, 0];
        (*tcp).check = [0, 0];

        let csum = compute_tcp_csum_v6(&in_dst_addr, &in_src_addr, tcp as *const u8, 20);
        (*tcp).check = csum.to_be_bytes();
    }

    Ok(xdp_action::XDP_TX)
}

/// Construct and send an ICMP Destination Unreachable (type=3, code=3)
/// for a non-TCP IPv4 packet.
///
/// The ICMP error payload contains the original IPv4 header + first 8 bytes
/// of the L4 header (as required by RFC 792).
#[inline(never)]
fn send_icmp_unreachable_v4(
    ctx: &XdpContext,
    l3_off: usize,
    _l4_off: usize,
) -> Result<u32, ()> {
    // ── Step 1: Save original IP header + first 8 bytes of L4 ──
    // We need 20 bytes of IP header + 8 bytes of L4 = 28 bytes total.
    // Read them byte-by-byte to a stack buffer.
    let mut saved: [u8; 28] = [0u8; 28];
    let mut i: usize = 0;
    while i < 28 {
        let byte_ptr: *const u8 = unsafe { ptr_at(ctx, l3_off + i)? };
        saved[i] = unsafe { *byte_ptr };
        i += 1;
    }

    // Read original src/dst IPs and Ethernet MACs for the response.
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let orig_src = unsafe { (*ipv4hdr).src_addr };
    let orig_dst = unsafe { (*ipv4hdr).dst_addr };

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let in_src_mac = unsafe { (*ethhdr).src_addr };
    let in_dst_mac = unsafe { (*ethhdr).dst_addr };

    // ── Step 2: Truncate/resize to: l3_off + 20 (new IP) + 8 (ICMP hdr) + 28 (payload) ──
    let target_len = l3_off + 20 + 8 + 28; // = l3_off + 56
    let current_len = ctx.data_end() - ctx.data();
    let delta = target_len as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }

    // ── Step 3: Re-read pointers ──
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, l3_off)? };
    // ICMP header starts right after the new IPv4 header.
    let icmp_off = l3_off + 20;
    let icmp: *mut u8 = unsafe { ptr_at_mut(ctx, icmp_off)? };
    // Verify we can write 36 bytes (8 ICMP header + 28 payload).
    let _end_check: *const u8 = unsafe { ptr_at(ctx, icmp_off + 35)? };

    // ── Step 4: Swap Ethernet MACs ──
    unsafe {
        (*eth).dst_addr = in_src_mac;
        (*eth).src_addr = in_dst_mac;
    }

    // ── Step 5: Build new IPv4 header ──
    unsafe {
        (*ip).set_vihl(4, 20);
        (*ip).tos = 0;
        (*ip).set_tot_len(56); // 20 IP + 8 ICMP header + 28 payload
        (*ip).set_id(0);
        (*ip).set_frags(0, 0);
        (*ip).ttl = 64;
        (*ip).proto = IpProto::Icmp;
        // Swap: our reply comes FROM original dst TO original src.
        (*ip).src_addr = orig_dst;
        (*ip).dst_addr = orig_src;
        (*ip).check = [0, 0];
        let csum = compute_ipv4_csum(ip as *const u8, 20);
        (*ip).set_checksum(csum);
    }

    // ── Step 6: Build ICMP header ──
    unsafe {
        // Type 3 = Destination Unreachable, Code 3 = Port Unreachable
        *icmp = 3;
        *icmp.add(1) = 3;
        // Checksum placeholder
        *icmp.add(2) = 0;
        *icmp.add(3) = 0;
        // "Unused" / "Next-hop MTU" — zero for code 3
        *icmp.add(4) = 0;
        *icmp.add(5) = 0;
        *icmp.add(6) = 0;
        *icmp.add(7) = 0;
    }

    // ── Step 7: Write saved 28 bytes as ICMP payload ──
    let payload: *mut u8 = unsafe { ptr_at_mut(ctx, icmp_off + 8)? };
    let mut j: usize = 0;
    while j < 28 {
        unsafe { *payload.add(j) = saved[j] };
        j += 1;
    }

    // ── Step 8: Compute ICMP checksum over 36 bytes ──
    unsafe {
        let csum = compute_icmp_csum(icmp, 36);
        let csum_be = csum.to_be_bytes();
        *icmp.add(2) = csum_be[0];
        *icmp.add(3) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

/// Construct and send an ICMPv6 Destination Unreachable (type=1, code=4)
/// for a non-TCP IPv6 packet.
///
/// The ICMPv6 error payload contains as much of the original packet as
/// possible: the 40-byte IPv6 header + first 8 bytes of L4 = 48 bytes.
#[inline(never)]
fn send_icmpv6_unreachable(
    ctx: &XdpContext,
    l3_off: usize,
    _l4_off: usize,
) -> Result<u32, ()> {
    // ── Step 1: Save original IPv6 header (40 bytes) + first 8 bytes of L4 ──
    let mut saved: [u8; 48] = [0u8; 48];
    let mut i: usize = 0;
    while i < 48 {
        let byte_ptr: *const u8 = unsafe { ptr_at(ctx, l3_off + i)? };
        saved[i] = unsafe { *byte_ptr };
        i += 1;
    }

    // Read original addresses and MACs.
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_off)? };
    let orig_src: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let orig_dst: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let in_src_mac = unsafe { (*ethhdr).src_addr };
    let in_dst_mac = unsafe { (*ethhdr).dst_addr };

    // ── Step 2: Truncate to: l3_off + 40 (IPv6) + 8 (ICMPv6 hdr) + 48 (payload) ──
    let target_len = l3_off + IPV6_HDR_LEN + 8 + 48; // = l3_off + 96
    let current_len = ctx.data_end() - ctx.data();
    let delta = target_len as i32 - current_len as i32;
    if delta != 0 {
        let ret = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };
        if ret != 0 {
            return Err(());
        }
    }

    // ── Step 3: Re-read pointers ──
    let eth: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let ip6: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, l3_off)? };
    let icmp6_off = l3_off + IPV6_HDR_LEN;
    let icmp6: *mut u8 = unsafe { ptr_at_mut(ctx, icmp6_off)? };
    // Verify we can write 56 bytes (8 ICMPv6 header + 48 payload).
    let _end_check: *const u8 = unsafe { ptr_at(ctx, icmp6_off + 55)? };

    // ── Step 4: Swap Ethernet MACs ──
    unsafe {
        (*eth).dst_addr = in_src_mac;
        (*eth).src_addr = in_dst_mac;
    }

    // ── Step 5: Build IPv6 header ──
    unsafe {
        (*ip6)._vtcfl = (6u32 << 28).to_be();
        // Payload = ICMPv6 header (8) + payload (48) = 56
        (*ip6)._payload_len = 56u16.to_be();
        (*ip6).next_hdr = PROTO_ICMPV6;
        (*ip6).hop_limit = 64;
        (*ip6).src_addr = orig_dst;
        (*ip6).dst_addr = orig_src;
    }

    // ── Step 6: Build ICMPv6 header ──
    unsafe {
        // Type 1 = Destination Unreachable, Code 4 = Port Unreachable
        *icmp6 = 1;
        *icmp6.add(1) = 4;
        // Checksum placeholder
        *icmp6.add(2) = 0;
        *icmp6.add(3) = 0;
        // Unused (must be zero)
        *icmp6.add(4) = 0;
        *icmp6.add(5) = 0;
        *icmp6.add(6) = 0;
        *icmp6.add(7) = 0;
    }

    // ── Step 7: Write saved 48 bytes as ICMPv6 payload ──
    let payload: *mut u8 = unsafe { ptr_at_mut(ctx, icmp6_off + 8)? };
    let mut j: usize = 0;
    while j < 48 {
        unsafe { *payload.add(j) = saved[j] };
        j += 1;
    }

    // ── Step 8: Compute ICMPv6 checksum (includes pseudo-header) ──
    unsafe {
        let csum = compute_icmpv6_csum(&orig_dst, &orig_src, icmp6, 56);
        let csum_be = csum.to_be_bytes();
        *icmp6.add(2) = csum_be[0];
        *icmp6.add(3) = csum_be[1];
    }

    Ok(xdp_action::XDP_TX)
}

// ── Checksum helpers ────────────────────────────────────────────────

/// Compute the IPv4 header checksum (ones' complement of the ones'
/// complement sum of the header u16 words).
///
/// The checksum field in the header must be zeroed before calling.
#[inline(always)]
unsafe fn compute_ipv4_csum(hdr: *const u8, len: usize) -> u16 {
    unsafe {
        let mut sum: u32 = 0;
        let mut i: usize = 0;
        while i + 1 < len {
            let word = ((*hdr.add(i) as u32) << 8) | (*hdr.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        // Fold 32-bit sum into 16 bits.
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Compute TCP checksum with IPv4 pseudo-header.
///
/// The checksum field in the TCP header must be zeroed before calling.
/// Returns the checksum in host byte order.
#[inline(always)]
unsafe fn compute_tcp_csum_v4(
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    tcp_hdr: *const u8,
    tcp_len: usize,
) -> u16 {
    unsafe {
        let mut sum: u32 = 0;

        // Pseudo-header: src_ip (4 bytes) + dst_ip (4 bytes) + zero + proto + tcp_len
        sum += ((src_ip[0] as u32) << 8) | (src_ip[1] as u32);
        sum += ((src_ip[2] as u32) << 8) | (src_ip[3] as u32);
        sum += ((dst_ip[0] as u32) << 8) | (dst_ip[1] as u32);
        sum += ((dst_ip[2] as u32) << 8) | (dst_ip[3] as u32);
        sum += PROTO_TCP as u32; // 0x0006
        sum += tcp_len as u32;

        // Sum TCP header bytes as 16-bit words.
        let mut i: usize = 0;
        while i + 1 < tcp_len {
            let word = ((*tcp_hdr.add(i) as u32) << 8) | (*tcp_hdr.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        // Handle odd byte (shouldn't happen for 20-byte TCP header).
        if i < tcp_len {
            sum += (*tcp_hdr.add(i) as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Compute TCP checksum with IPv6 pseudo-header.
///
/// Returns the checksum in host byte order.
#[inline(always)]
unsafe fn compute_tcp_csum_v6(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    tcp_hdr: *const u8,
    tcp_len: usize,
) -> u16 {
    unsafe {
        let mut sum: u32 = 0;

        // Pseudo-header: src (16) + dst (16) + upper-layer length (4) + zero(3) + next_hdr(1)
        let mut i: usize = 0;
        while i < 16 {
            sum += ((src_ip[i] as u32) << 8) | (src_ip[i + 1] as u32);
            i += 2;
        }
        i = 0;
        while i < 16 {
            sum += ((dst_ip[i] as u32) << 8) | (dst_ip[i + 1] as u32);
            i += 2;
        }
        sum += tcp_len as u32; // Upper-layer packet length
        sum += PROTO_TCP as u32; // Next header = 6

        // Sum TCP header/data.
        i = 0;
        while i + 1 < tcp_len {
            let word = ((*tcp_hdr.add(i) as u32) << 8) | (*tcp_hdr.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        if i < tcp_len {
            sum += (*tcp_hdr.add(i) as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Compute ICMP checksum (ones' complement sum over the ICMP message).
///
/// The checksum field must be zeroed before calling.
/// Returns the checksum in host byte order.
#[inline(always)]
unsafe fn compute_icmp_csum(data: *const u8, len: usize) -> u16 {
    unsafe {
        let mut sum: u32 = 0;
        let mut i: usize = 0;
        while i + 1 < len {
            let word = ((*data.add(i) as u32) << 8) | (*data.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        if i < len {
            sum += (*data.add(i) as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Compute ICMPv6 checksum with IPv6 pseudo-header.
///
/// Returns the checksum in host byte order.
#[inline(always)]
unsafe fn compute_icmpv6_csum(
    src_ip: &[u8; 16],
    dst_ip: &[u8; 16],
    icmpv6_data: *const u8,
    icmpv6_len: usize,
) -> u16 {
    unsafe {
        let mut sum: u32 = 0;

        // Pseudo-header: src (16) + dst (16) + upper-layer length (4) + zero(3) + next_hdr(1)
        let mut i: usize = 0;
        while i < 16 {
            sum += ((src_ip[i] as u32) << 8) | (src_ip[i + 1] as u32);
            i += 2;
        }
        i = 0;
        while i < 16 {
            sum += ((dst_ip[i] as u32) << 8) | (dst_ip[i + 1] as u32);
            i += 2;
        }
        sum += icmpv6_len as u32; // Upper-layer packet length
        sum += PROTO_ICMPV6 as u32; // Next header = 58

        // Sum ICMPv6 data.
        i = 0;
        while i + 1 < icmpv6_len {
            let word = ((*icmpv6_data.add(i) as u32) << 8) | (*icmpv6_data.add(i + 1) as u32);
            sum += word;
            i += 2;
        }
        if i < icmpv6_len {
            sum += (*icmpv6_data.add(i) as u32) << 8;
        }

        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

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

// ── User RingBuf config command drain callback ──────────────────────

/// Callback for `bpf_user_ringbuf_drain`: process one config command.
///
/// Dispatches on `cmd_type` to add/remove rules from fast-path HashMaps
/// or update the default policy. Returns 0 to continue draining.
///
/// # Safety
///
/// Called by the kernel with validated pointers.
unsafe extern "C" fn drain_config_cmd(
    _ctx: *mut core::ffi::c_void,
    data: *mut core::ffi::c_void,
    _data_sz: u64,
) -> i64 {
    use ebpf_common::config_cmd::*;

    unsafe {
        let cmd = &*(data as *const ConfigCommand);

        match cmd.cmd_type {
            CMD_ADD_FW_RULE_5TUPLE => {
                if cmd.payload_len >= 20 {
                    let key = &*(cmd.payload.as_ptr() as *const FwHashKey5Tuple);
                    let val = &*(cmd.payload.as_ptr().add(16) as *const FwHashValue);
                    let _ = FW_HASH_5TUPLE.insert(key, val, 0);
                }
            }
            CMD_DEL_FW_RULE_5TUPLE => {
                if cmd.payload_len >= 16 {
                    let key = &*(cmd.payload.as_ptr() as *const FwHashKey5Tuple);
                    let _ = FW_HASH_5TUPLE.remove(key);
                }
            }
            CMD_ADD_FW_RULE_PORT => {
                if cmd.payload_len >= 8 {
                    let key = &*(cmd.payload.as_ptr() as *const FwHashKeyPort);
                    let val = &*(cmd.payload.as_ptr().add(4) as *const FwHashValue);
                    let _ = FW_HASH_PORT.insert(key, val, 0);
                }
            }
            CMD_DEL_FW_RULE_PORT => {
                if cmd.payload_len >= 4 {
                    let key = &*(cmd.payload.as_ptr() as *const FwHashKeyPort);
                    let _ = FW_HASH_PORT.remove(key);
                }
            }
            _ => {}
        }
    }

    0 // continue draining
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
