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
        Array, CpuMap, DevMap, PerCpuArray, ProgramArray, RingBuf,
        lpm_trie::{Key, LpmTrie},
    },
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use ebpf_common::{
    event::{
        EVENT_TYPE_FIREWALL, FLAG_IPV6, FLAG_VLAN, META_FLAG_PRESENT, PacketEvent, XdpMetadata,
    },
    firewall::{
        ACTION_DROP, ACTION_LOG, ACTION_PASS, DEFAULT_POLICY_DROP, FirewallRuleEntry,
        FirewallRuleEntryV6, LpmValue, MATCH_DST_IP, MATCH_DST_PORT, MATCH_PROTO, MATCH_SRC_IP,
        MATCH_SRC_PORT, MAX_FIREWALL_RULES, MAX_LPM_RULES,
    },
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
    /// -1 = no match yet, 0+ = matched rule action.
    matched_action: i32,
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
    /// -1 = no match yet, 0+ = matched rule action.
    matched_action: i32,
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
        ) {
            lctx.matched_action = rule.action as i32;
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
        ) {
            lctx.matched_action = rule.action as i32;
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
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };

    // ihl() returns the header length in bytes (already multiplied by 4)
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Parse L4 ports
    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
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
        _ => (0u16, 0u16),
    };

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];

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
        matched_action: -1,
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
        return apply_action(
            ctx,
            scan_ctx.matched_action as u8,
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
fn match_rule_v4(
    rule: &FirewallRuleEntry,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan_id: u16,
) -> bool {
    let flags = rule.match_flags;

    // Protocol check
    if (flags & MATCH_PROTO) != 0 && rule.protocol != protocol {
        return false;
    }

    // Source IP (CIDR match: masked comparison)
    if (flags & MATCH_SRC_IP) != 0 && (src_ip & rule.src_mask) != rule.src_ip {
        return false;
    }

    // Destination IP (CIDR match)
    if (flags & MATCH_DST_IP) != 0 && (dst_ip & rule.dst_mask) != rule.dst_ip {
        return false;
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

    true
}

/// IPv6 firewall processing: linear scan of FIREWALL_RULES_V6 array.
#[inline(always)]
fn process_firewall_v6(
    ctx: &XdpContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<u32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    // Grab raw bytes (network byte order) for LPM trie lookup.
    let src_bytes_v6: [u8; 16] = unsafe { (*ipv6hdr).src_addr };
    let dst_bytes_v6: [u8; 16] = unsafe { (*ipv6hdr).dst_addr };
    let src_addr = ipv6_addr_to_u32x4(&src_bytes_v6);
    let dst_addr = ipv6_addr_to_u32x4(&dst_bytes_v6);
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    let l4_offset = l3_offset + IPV6_HDR_LEN;

    // Parse L4 ports
    let (src_port, dst_port) = if next_hdr == PROTO_TCP {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
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
    } else {
        (0u16, 0u16)
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
        matched_action: -1,
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
        return apply_action(
            ctx,
            scan_ctx.matched_action as u8,
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
fn match_rule_v6(
    rule: &FirewallRuleEntryV6,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan_id: u16,
) -> bool {
    let flags = rule.match_flags;

    // Protocol check
    if (flags & MATCH_PROTO) != 0 && rule.protocol != protocol {
        return false;
    }

    // Source IPv6 (CIDR match: compare each u32 word masked)
    if (flags & MATCH_SRC_IP) != 0 {
        if (src_addr[0] & rule.src_mask[0]) != rule.src_addr[0]
            || (src_addr[1] & rule.src_mask[1]) != rule.src_addr[1]
            || (src_addr[2] & rule.src_mask[2]) != rule.src_addr[2]
            || (src_addr[3] & rule.src_mask[3]) != rule.src_addr[3]
        {
            return false;
        }
    }

    // Destination IPv6 (CIDR match)
    if (flags & MATCH_DST_IP) != 0 {
        if (dst_addr[0] & rule.dst_mask[0]) != rule.dst_addr[0]
            || (dst_addr[1] & rule.dst_mask[1]) != rule.dst_addr[1]
            || (dst_addr[2] & rule.dst_mask[2]) != rule.dst_addr[2]
            || (dst_addr[3] & rule.dst_mask[3]) != rule.dst_addr[3]
        {
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
