#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    cty::c_void,
    helpers::{
        bpf_check_mtu, bpf_csum_diff, bpf_fib_lookup as bpf_fib_lookup_helper,
        bpf_get_smp_processor_id, bpf_ktime_get_boot_ns, bpf_loop, bpf_xdp_adjust_meta,
    },
    macros::{map, xdp},
    maps::{
        Array, CpuMap, DevMap, HashMap, LruHashMap, PerCpuArray, ProgramArray, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use ebpf_common::{
    conntrack::{
        CT_SRC_COUNTER_MAX, CT_STATE_NEW, ConnKey, ConnKeyV6, ConnTrackConfig, ConnValue,
        CT_MAX_ENTRIES_V4, CT_MAX_ENTRIES_V6, CT_STATE_ESTABLISHED, CT_STATE_RELATED,
        OVERLOAD_SET_ID, SRC_COUNTER_FLAG_OVERLOADED, SrcStateCounter, normalize_key_v4,
        normalize_key_v6,
    },
    event::{
        EVENT_TYPE_FIREWALL, FLAG_IPV6, FLAG_VLAN, META_FLAG_PRESENT, PacketEvent, XdpMetadata,
    },
    firewall::{
        ACTION_DROP, ACTION_LOG, ACTION_PASS, CT_MATCH_ESTABLISHED, CT_MATCH_INVALID,
        CT_MATCH_NEW, CT_MATCH_RELATED, DEFAULT_POLICY_DROP, FirewallRuleEntry,
        FirewallRuleEntryV6, ICMP_WILDCARD, IpSetKeyV4, LpmValue, MATCH2_DSCP, MATCH2_DST_MAC, MATCH2_ICMP_CODE,
        MATCH2_ICMP_TYPE, MATCH2_NEGATE_DST, MATCH2_NEGATE_SRC, MATCH2_SRC_MAC,
        MATCH2_TCP_FLAGS, MATCH_CT_STATE, MATCH_DST_IP, MATCH_DST_PORT, MATCH_DST_SET,
        MATCH_PROTO, MATCH_SRC_IP, MATCH_SRC_PORT, MATCH_SRC_SET, MAX_FIREWALL_RULES,
        MAX_IPSET_ENTRIES_V4, MAX_LPM_RULES,
    },
    zone::MAX_ZONE_ENTRIES,
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
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
const PROTO_ICMP: u8 = 1;
const PROTO_ICMPV6: u8 = 58;

// ── Inline ICMP header type ─────────────────────────────────────────

/// ICMP fixed header (8 bytes: type, code, checksum, rest-of-header).
/// We only need type + code for firewall matching.
#[repr(C)]
struct IcmpHdr {
    r#type: u8,
    code: u8,
    _checksum: u16,
    _rest: u32,
}

// ── Inline IPv6 / VLAN header types ─────────────────────────────────

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

/// 802.1Q VLAN tag (4 bytes after EthHdr when ether_type == 0x8100).
#[repr(C)]
struct VlanHdr {
    tci: u16,
    ether_type: u16,
}

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

/// Per-CPU packet counters. Index: 0=passed, 1=dropped, 2=errors, 3=events_dropped.
#[map]
static FIREWALL_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

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

/// DevMap for packet mirroring (F16). Userspace populates entries with
/// target interface indices. XDP programs can redirect a copy of the
/// packet to a mirror port for out-of-band inspection.
#[map]
#[allow(dead_code)]
static FW_MIRROR_DEVMAP: DevMap = DevMap::with_max_entries(64, 0);

/// CpuMap for CPU steering (F17). Userspace populates entries so the XDP
/// program can redirect packets to a specific CPU for processing, enabling
/// RSS-like distribution or dedicated-core offload.
#[map]
#[allow(dead_code)]
static FW_CPUMAP: CpuMap = CpuMap::with_max_entries(128, 0);

// ── Conntrack fast-path maps (read-only, shared via pinning) ────────

/// Shared conntrack table for ESTABLISHED bypass (read-only in XDP).
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v4, written by tc-conntrack.
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 0);

/// Shared conntrack table for IPv6 ESTABLISHED bypass (read-only in XDP).
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v6, written by tc-conntrack.
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 0);

// ── IP Set maps ─────────────────────────────────────────────────────

/// IPv4 IP set HashMap for large alias matching (GeoIP, blocklists).
/// Key: (set_id, addr). Presence = membership.
#[map]
static FW_IPSET_V4: HashMap<IpSetKeyV4, u8> =
    HashMap::with_max_entries(MAX_IPSET_ENTRIES_V4, 0);

// ── Zone maps ──────────────────────────────────────────────────────

/// Maps interface index (ifindex) to zone ID. Userspace populates this
/// based on zone configuration. Zone ID 0 = unzoned.
#[map]
#[allow(dead_code)]
static ZONE_MAP: HashMap<u32, u8> = HashMap::with_max_entries(MAX_ZONE_ENTRIES, 0);

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

/// RingBuf total size in bytes (must match EVENTS map declaration).
const EVENTS_RINGBUF_SIZE: u64 = 256 * 4096;

/// Backpressure threshold: skip emission when >75% of RingBuf is consumed.
const BACKPRESSURE_THRESHOLD: u64 = EVENTS_RINGBUF_SIZE * 3 / 4;

/// `BPF_RB_AVAIL_DATA` flag for `bpf_ringbuf_query`.
const BPF_RB_AVAIL_DATA: u64 = 0;

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    EVENTS.query(BPF_RB_AVAIL_DATA) > BACKPRESSURE_THRESHOLD
}

// ── bpf_loop context structs ─────────────────────────────────────────

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
}

// ── bpf_loop callbacks ──────────────────────────────────────────────

/// Callback for `bpf_loop`: scan one IPv4 firewall rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
unsafe extern "C" fn scan_rule_v4(index: u32, ctx: *mut c_void) -> i64 {
    let lctx = &mut *(ctx as *mut RuleScanCtx);
    if index >= lctx.count {
        return 1;
    }
    if let Some(rule) = FIREWALL_RULES.get(index) {
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

/// Callback for `bpf_loop`: scan one IPv6 firewall rule.
/// Returns 0 to continue, 1 to stop (match found or index >= count).
unsafe extern "C" fn scan_rule_v6(index: u32, ctx: *mut c_void) -> i64 {
    let lctx = &mut *(ctx as *mut RuleScanCtxV6);
    if index >= lctx.count {
        return 1;
    }
    if let Some(rule) = FIREWALL_RULES_V6.get(index) {
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

// ── Entry point ─────────────────────────────────────────────────────

/// XDP entry point. Delegates to try_xdp_firewall; any error returns XDP_PASS
/// (NFR15: default-to-pass on internal error).
#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            xdp_action::XDP_PASS
        }
    }
}

// ── Helpers: byte conversion ────────────────────────────────────────

#[inline(always)]
fn u32_from_be_bytes(b: [u8; 4]) -> u32 {
    u32::from_be_bytes(b)
}

#[inline(always)]
fn u16_from_be_bytes(b: [u8; 2]) -> u16 {
    u16::from_be_bytes(b)
}

/// Convert a 16-byte IPv6 address to `[u32; 4]` in network byte order.
#[inline(always)]
fn ipv6_addr_to_u32x4(addr: &[u8; 16]) -> [u32; 4] {
    [
        u32_from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32_from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
        u32_from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
        u32_from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
    ]
}

/// Read the default policy from the map (0=pass, 1=drop).
#[inline(always)]
fn read_default_policy() -> u8 {
    match FIREWALL_DEFAULT_POLICY.get(0) {
        Some(&val) => val,
        None => 0, // default to pass if map read fails
    }
}

/// Apply the default policy action.
#[inline(always)]
fn apply_default_policy(
    ctx: &XdpContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) -> Result<u32, ()> {
    let policy = read_default_policy();
    if policy == DEFAULT_POLICY_DROP {
        emit_event(
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            ACTION_DROP,
            flags,
            vlan_id,
        );
        info!(
            ctx,
            "DEFAULT_DROP {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
        );
        increment_metric(METRIC_DROPPED);
        Ok(xdp_action::XDP_DROP)
    } else {
        increment_metric(METRIC_PASSED);
        write_xdp_metadata(ctx, ACTION_PASS, 0);
        // Try chaining to ratelimit; if not loaded, fall through to PASS.
        unsafe {
            let _ = XDP_PROG_ARRAY.tail_call(ctx, PROG_IDX_RATELIMIT);
        }
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
    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        flags |= FLAG_VLAN;
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
#[inline(always)]
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
            unsafe {
                let _ = XDP_PROG_ARRAY.tail_call(ctx, PROG_IDX_RATELIMIT);
            }
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
        return apply_action(
            ctx,
            val.action,
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            protocol as u8,
            flags,
            vlan_id,
        );
    }
    let dst_key = Key::new(32, dst_ip.to_be_bytes());
    if let Some(val) = FW_LPM_DST_V4.get(&dst_key) {
        return apply_action(
            ctx,
            val.action,
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            protocol as u8,
            flags,
            vlan_id,
        );
    }

    // Phase 2: Linear scan for complex rules (port, protocol, VLAN).
    // Read rule count
    let count = match FIREWALL_RULE_COUNT.get(0) {
        Some(&c) => c,
        None => 0,
    };

    // Scan rules via bpf_loop (kernel 5.17+): verifier analyzes the callback
    // body only once, allowing up to 4096 rules without complexity limits.
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
    };
    unsafe {
        bpf_loop(
            MAX_FIREWALL_RULES,
            scan_rule_v4 as *mut c_void,
            &mut scan_ctx as *mut RuleScanCtx as *mut c_void,
            0,
        );
    }

    if scan_ctx.matched_action >= 0 {
        let action = scan_ctx.matched_action as u8;
        // For PASS/LOG on NEW connections, enforce connection limits.
        if (action == ACTION_PASS || action == ACTION_LOG)
            && (ct_state == CT_STATE_NEW || ct_state == 0xFF)
        {
            if !check_connection_limits(
                src_ip,
                scan_ctx.matched_rule_idx,
                scan_ctx.matched_max_states,
            ) {
                // Connection limit exceeded → DROP.
                emit_event(
                    &src_addr,
                    &dst_addr,
                    src_port,
                    dst_port,
                    protocol as u8,
                    ACTION_DROP,
                    flags,
                    vlan_id,
                );
                increment_metric(METRIC_DROPPED);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        return apply_action(
            ctx,
            action,
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            protocol as u8,
            flags,
            vlan_id,
        );
    }

    // No rule matched — apply default policy
    apply_default_policy(
        ctx,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        protocol as u8,
        flags,
        vlan_id,
    )
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
#[inline(always)]
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
                    let _ = unsafe { FW_IPSET_V4.insert(&ipset_key, &1u8, 0) };
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

/// IPv6 firewall processing: linear scan of FIREWALL_RULES_V6 array.
#[inline(always)]
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
    // Grab raw bytes (network byte order) for LPM trie lookup.
    let src_bytes_v6: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let dst_bytes_v6: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };
    let src_addr = ipv6_addr_to_u32x4(&src_bytes_v6);
    let dst_addr = ipv6_addr_to_u32x4(&dst_bytes_v6);
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Extract DSCP from IPv6 traffic class. The _vtcfl field is:
    // [version(4b)][traffic_class(8b)][flow_label(20b)] in network byte order.
    let vtcfl = u32::from_be(unsafe { (*ipv6hdr)._vtcfl });
    let traffic_class = ((vtcfl >> 20) & 0xFF) as u8;
    let dscp = traffic_class >> 2;

    let l4_offset = l3_offset + IPV6_HDR_LEN;

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

    // Phase 0: Conntrack lookup (IPv6).
    // Look up the connection state once; used for fast-path bypass and
    // ct_state_mask matching during the rule scan.
    let ct_key_v6 = normalize_key_v6(&src_addr, &dst_addr, src_port, dst_port, next_hdr);
    let ct_state: u8 = if let Some(ct) = unsafe { CT_TABLE_V6.get(&ct_key_v6) } {
        // Fast-path bypass: ESTABLISHED/RELATED skip rule evaluation entirely.
        if ct.state == CT_STATE_ESTABLISHED || ct.state == CT_STATE_RELATED {
            increment_metric(METRIC_PASSED);
            write_xdp_metadata(ctx, ACTION_PASS, 0);
            unsafe {
                let _ = XDP_PROG_ARRAY.tail_call(ctx, PROG_IDX_RATELIMIT);
            }
            return Ok(xdp_action::XDP_PASS);
        }
        ct.state
    } else {
        0xFF // No conntrack entry — treated as "unknown"
    };

    // Phase 1: LPM Trie lookup — O(log n) for CIDR-only rules.
    let src_key_v6 = Key::new(128, src_bytes_v6);
    if let Some(val) = FW_LPM_SRC_V6.get(&src_key_v6) {
        return apply_action(
            ctx, val.action, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
        );
    }
    let dst_key_v6 = Key::new(128, dst_bytes_v6);
    if let Some(val) = FW_LPM_DST_V6.get(&dst_key_v6) {
        return apply_action(
            ctx, val.action, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
        );
    }

    // Phase 2: Linear scan for complex rules (port, protocol, VLAN).
    // Read V6 rule count
    let count = match FIREWALL_RULE_COUNT_V6.get(0) {
        Some(&c) => c,
        None => 0,
    };

    // Scan V6 rules via bpf_loop (kernel 5.17+).
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
    };
    unsafe {
        bpf_loop(
            MAX_FIREWALL_RULES,
            scan_rule_v6 as *mut c_void,
            &mut scan_ctx as *mut RuleScanCtxV6 as *mut c_void,
            0,
        );
    }

    if scan_ctx.matched_action >= 0 {
        let action = scan_ctx.matched_action as u8;
        // For PASS/LOG on NEW connections, enforce connection limits.
        // Use src_addr[0] as the source key for the IPv4-keyed counter map.
        if (action == ACTION_PASS || action == ACTION_LOG)
            && (ct_state == CT_STATE_NEW || ct_state == 0xFF)
        {
            if !check_connection_limits(
                src_addr[0],
                scan_ctx.matched_rule_idx,
                scan_ctx.matched_max_states,
            ) {
                emit_event(
                    &src_addr,
                    &dst_addr,
                    src_port,
                    dst_port,
                    next_hdr,
                    ACTION_DROP,
                    flags,
                    vlan_id,
                );
                increment_metric(METRIC_DROPPED);
                return Ok(xdp_action::XDP_DROP);
            }
        }
        return apply_action(
            ctx,
            action,
            &src_addr,
            &dst_addr,
            src_port,
            dst_port,
            next_hdr,
            flags,
            vlan_id,
        );
    }

    // No rule matched — apply default policy
    apply_default_policy(
        ctx, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
    )
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
/// On `XDP_PASS`, attempts a tail_call to the ratelimit program (index 0
/// in `XDP_PROG_ARRAY`). If ratelimit isn't loaded, falls through to PASS.
#[inline(always)]
fn apply_action(
    ctx: &XdpContext,
    action: u8,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) -> Result<u32, ()> {
    match action {
        ACTION_DROP => {
            emit_event(
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
                ACTION_DROP,
                flags,
                vlan_id,
            );
            info!(
                ctx,
                "DROP {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
            );
            increment_metric(METRIC_DROPPED);
            Ok(xdp_action::XDP_DROP)
        }
        ACTION_LOG => {
            emit_event(
                src_addr, dst_addr, src_port, dst_port, protocol, ACTION_LOG, flags, vlan_id,
            );
            info!(
                ctx,
                "LOG {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
            );
            increment_metric(METRIC_PASSED);
            write_xdp_metadata(ctx, ACTION_LOG, 0);
            // Try chaining to ratelimit; if not loaded, fall through to PASS.
            unsafe {
                let _ = XDP_PROG_ARRAY.tail_call(ctx, PROG_IDX_RATELIMIT);
            }
            Ok(xdp_action::XDP_PASS)
        }
        ACTION_PASS | _ => {
            increment_metric(METRIC_PASSED);
            write_xdp_metadata(ctx, ACTION_PASS, 0);
            // Try chaining to ratelimit; if not loaded, fall through to PASS.
            unsafe {
                let _ = XDP_PROG_ARRAY.tail_call(ctx, PROG_IDX_RATELIMIT);
            }
            Ok(xdp_action::XDP_PASS)
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Bounds-checked pointer access. Critical for eBPF verifier compliance:
/// every memory access must be validated against data_end.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = FIREWALL_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

/// Prepend `XdpMetadata` to the packet's data_meta area so that TC programs
/// can read the firewall verdict without re-parsing. Best-effort: if
/// `bpf_xdp_adjust_meta` fails (driver doesn't support it), silently skips.
#[inline(always)]
fn write_xdp_metadata(ctx: &XdpContext, action: u8, rule_id: u32) {
    let meta_size = mem::size_of::<XdpMetadata>() as i32;
    let ret = unsafe { bpf_xdp_adjust_meta(ctx.ctx, -meta_size) };
    if ret != 0 {
        return; // Driver doesn't support metadata — skip silently
    }
    // After adjust_meta, data_meta has grown by meta_size bytes.
    // Write the metadata into the new space.
    let data_meta = ctx.data() - meta_size as usize;
    let data = ctx.data();
    if data_meta + mem::size_of::<XdpMetadata>() > data {
        return; // Safety check
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

/// Emit a PacketEvent to the EVENTS RingBuf. Skips emission under
/// backpressure (>75% full). If the buffer is full, increment the
/// events_dropped metric — never block the hot path.
#[inline(always)]
fn emit_event(
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
    flags: u8,
    vlan_id: u16,
) {
    if ringbuf_has_backpressure() {
        increment_metric(METRIC_EVENTS_DROPPED);
        return;
    }
    if let Some(mut entry) = EVENTS.reserve::<PacketEvent>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).src_addr = *src_addr;
            (*ptr).dst_addr = *dst_addr;
            (*ptr).src_port = src_port;
            (*ptr).dst_port = dst_port;
            (*ptr).protocol = protocol;
            (*ptr).event_type = EVENT_TYPE_FIREWALL;
            (*ptr).action = action;
            (*ptr).flags = flags;
            (*ptr).rule_id = 0;
            (*ptr).vlan_id = vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0; // Not available in XDP context
        }
        entry.submit(0);
    } else {
        increment_metric(METRIC_EVENTS_DROPPED);
    }
}

// ── FIB lookup for routing enrichment (F11) ─────────────────────────

/// Address family constants for `bpf_fib_lookup`.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

/// Perform a FIB (Forwarding Information Base) lookup to determine the
/// egress interface index for a given source/destination pair.
///
/// Returns `Some(ifindex)` on successful lookup, `None` otherwise.
/// This can be used for routing enrichment in packet events.
#[allow(dead_code)]
#[inline(always)]
fn fib_lookup_enrichment(
    ctx: &XdpContext,
    family: u8,
    src: &[u32; 4],
    dst: &[u32; 4],
) -> Option<u32> {
    let mut params: aya_ebpf::bindings::bpf_fib_lookup = unsafe { core::mem::zeroed() };
    params.family = family;

    if family == AF_INET {
        params.__bindgen_anon_3.ipv4_src = src[0].to_be();
        params.__bindgen_anon_4.ipv4_dst = dst[0].to_be();
    } else if family == AF_INET6 {
        params.__bindgen_anon_3.ipv6_src = *src;
        params.__bindgen_anon_4.ipv6_dst = *dst;
    }

    // ifindex must be set to the ingress interface for the lookup.
    params.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };

    let ret = unsafe {
        bpf_fib_lookup_helper(
            ctx.ctx as *mut c_void,
            &mut params,
            core::mem::size_of::<aya_ebpf::bindings::bpf_fib_lookup>() as i32,
            0,
        )
    };

    if ret == 0 { Some(params.ifindex) } else { None }
}

// Suppress unused constant warnings for infrastructure code.
const _: () = {
    _ = AF_INET;
    _ = AF_INET6;
};

// ── Checksum helpers (F18) ───────────────────────────────────────────

/// Compute incremental checksum difference using `bpf_csum_diff`.
///
/// Used for SYN cookie response injection and other packet rewriting
/// scenarios where the IP/TCP checksum must be updated incrementally.
/// `from` and `to` are slices of u32 words (network byte order) representing
/// the old and new header fields. Returns the checksum difference as an i64.
#[inline(always)]
#[allow(dead_code)]
fn csum_diff(from: &[u32], to: &[u32]) -> i64 {
    unsafe {
        bpf_csum_diff(
            from.as_ptr() as *mut u32,
            (from.len() * 4) as u32,
            to.as_ptr() as *mut u32,
            (to.len() * 4) as u32,
            0,
        )
    }
}

// ── Packet mirroring helper (F16) ───────────────────────────────────

/// Redirect the current packet to a mirror interface via `FW_MIRROR_DEVMAP`.
///
/// `key` is the index into the `DevMap` (populated by userspace with the
/// target ifindex). On success returns `XDP_REDIRECT`; on failure returns
/// `XDP_PASS` so the packet continues normal processing.
#[inline(always)]
#[allow(dead_code)]
fn mirror_packet(key: u32) -> u32 {
    FW_MIRROR_DEVMAP
        .redirect(key, 0)
        .unwrap_or(xdp_action::XDP_PASS)
}

// ── CPU steering helper (F17) ───────────────────────────────────────

/// Redirect the current packet to a specific CPU via `FW_CPUMAP`.
///
/// `cpu` is the index into the `CpuMap` (populated by userspace with the
/// target CPU core and queue size). On success returns `XDP_REDIRECT`;
/// on failure returns `XDP_PASS`.
#[inline(always)]
#[allow(dead_code)]
fn steer_to_cpu(cpu: u32) -> u32 {
    FW_CPUMAP.redirect(cpu, 0).unwrap_or(xdp_action::XDP_PASS)
}

// ── MTU validation helper (F19) ─────────────────────────────────────

/// Check whether the current packet fits within the MTU of the given
/// interface. Returns `true` if the packet size is within the MTU.
///
/// Uses `bpf_check_mtu` (kernel 5.12+). `ifindex` of 0 means use the
/// current interface. `len_diff` accounts for planned encapsulation overhead.
#[inline(always)]
#[allow(dead_code)]
fn check_mtu(ctx: &XdpContext, ifindex: u32, len_diff: i32) -> bool {
    let mut mtu_len: u32 = 0;
    let ret = unsafe {
        bpf_check_mtu(
            ctx.ctx as *mut c_void,
            ifindex,
            &mut mtu_len as *mut u32,
            len_diff,
            0,
        )
    };
    // bpf_check_mtu returns 0 (BPF_MTU_CHK_RET_SUCCESS) if within MTU.
    ret == 0
}

// ── SYN cookie generation (F10) ──────────────────────────────────────

/// SYN cookie algorithm constant for ratelimit config.
#[allow(dead_code)]
const RATELIMIT_ALG_SYNCOOKIE: u8 = 4;

/// Generate a SYN cookie for an incoming SYN packet using `bpf_tcp_gen_syncookie`.
///
/// `iph` points to the IP header (v4 or v6), `iph_len` is its byte length.
/// `th` points to the TCP header, `th_len` is its byte length (≥20).
///
/// Returns the generated cookie value on success, or `None` on failure.
/// The caller is responsible for crafting the SYN+ACK response packet
/// using `bpf_xdp_adjust_head` and the checksum helpers (F18).
///
/// Requires a listening TCP socket on the destination port. The `sk`
/// parameter can be obtained via `bpf_sk_lookup_tcp` from a TC program
/// or `bpf_skc_lookup_tcp` from an XDP program.
#[inline(always)]
#[allow(dead_code)]
fn gen_syncookie(
    sk: *mut c_void,
    iph: *mut c_void,
    iph_len: u32,
    th: *mut c_void,
    th_len: u32,
) -> Option<u32> {
    // bpf_tcp_gen_syncookie returns i64: cookie on success, negative on error.
    let ret = unsafe {
        aya_ebpf::helpers::r#gen::bpf_tcp_gen_syncookie(
            sk,
            iph,
            iph_len,
            th as *mut aya_ebpf::bindings::tcphdr,
            th_len,
        )
    };
    if ret >= 0 { Some(ret as u32) } else { None }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
