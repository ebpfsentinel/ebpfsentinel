#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_prandom_u32, bpf_get_smp_processor_id,
        bpf_ktime_get_boot_ns,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, LpmTrie, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::{bpf_clone_redirect, bpf_get_socket_cookie, bpf_skb_load_bytes};
#[cfg(debug_assertions)]
use aya_log_ebpf::info;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::kfuncs::{BpfCtOpts, CtTuple, SkbDynptr, kill_flow_via_skb_ct, skb_get_fou_encap};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{emit_packet_event, increment_metric, ringbuf_has_backpressure};
use ebpf_common::{
    event::{
        PacketEvent, EVENT_TYPE_IDS, EVENT_TYPE_L7, FLAG_IPV6, FLAG_VLAN,
        MAX_L7_PAYLOAD, MAX_L7_PORTS, SMALL_L7_PAYLOAD,
    },
    ids::{
        IdsSamplingConfig, IdsPatternKey, IdsPatternValue, IDS_ACTION_DROP, IDS_SAMPLING_RANDOM,
    },
    tenant::{MAX_TENANT_SUBNET_LPM_ENTRIES, MAX_TENANT_SUBNET_V6_LPM_ENTRIES},
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

// ── AF_XDP zero-copy DPI path via XSKMAP (kernel 4.18+) ────────────
//
// For packets requiring deep inspection that exceeds eBPF complexity limits
// (e.g., reassembled TCP streams, complex regex), forward to userspace via
// AF_XDP instead of copying through RingBuf.
//
// Architecture:
//   #[map]
//   static IDS_XSKMAP: aya_ebpf::maps::XskMap = XskMap::with_max_entries(64, 0);
//
// On suspicious packet detection:
//   1. Basic eBPF-side checks (port, flags, sampling)
//   2. If complex inspection needed → bpf_redirect_map(&IDS_XSKMAP, queue_id, 0)
//   3. Userspace AF_XDP socket receives packet at wire speed (zero-copy)
//   4. Full regex/DPI in userspace with complete TCP reassembly
//
// Benefits vs RingBuf:
//   - Zero-copy (no kernel→user memcpy)
//   - Full packet (not truncated like RingBuf events)
//   - Bidirectional (can re-inject modified packets)
//
// NOTE(future): XskMap for AF_XDP zero-copy DPI — requires kernel 4.18+ and aya XskMap wiring.

// ── Maps ────────────────────────────────────────────────────────────

/// IDS pattern lookup: port+protocol → action + rule metadata.
#[map]
static IDS_PATTERNS: HashMap<IdsPatternKey, IdsPatternValue> =
    HashMap::with_max_entries(10240, 0);

/// Per-CPU packet counters. Index: 0=matched, 1=dropped, 2=errors, 3=events_dropped, 4=total_seen, 5=cgroup_tenant_resolved.
#[map]
static IDS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(6, 0);

/// Shared kernel→userspace event ring buffer (4 MB).
///
/// Bumped from 1 MiB to 4 MiB alongside the L7 payload capture bump to
/// 2048 B — larger events would otherwise cause frequent backpressure
/// drops. The extra 3 MiB of kernel memory is acceptable on any
/// modern deployment.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 4096, 0);

/// Feature enable/disable flags (shared across programs).
#[map]
static CONFIG_FLAGS: Array<u32> = Array::with_max_entries(1, 0);

/// Kernel-side IDS sampling configuration (single entry).
/// Mode + rate_threshold control event emission probability.
#[map]
static IDS_SAMPLING_CONFIG: Array<IdsSamplingConfig> = Array::with_max_entries(1, 0);

/// Mirror interface config: index 0 = target ifindex, index 1 = enabled (1/0).
/// Populated by enterprise forensics module.
#[map]
static IDS_MIRROR_CONFIG: Array<u32> = Array::with_max_entries(2, 0);

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

/// Cgroup-based tenant resolution: cgroup v2 id → tenant_id.
/// Populated by userspace from the container resolver. Used as the
/// lowest-priority fallback (after VLAN, interface, subnet) — only
/// meaningful on egress where the current task owns the skb.
#[map]
static TENANT_CGROUP_MAP: HashMap<u64, u32> = HashMap::with_max_entries(4096, 0);

/// L7 port lookup: dst_port → enabled flag. When set, TCP packets to this
/// port have their payload captured and sent to userspace for L7 protocol
/// parsing. Capacity is `MAX_L7_PORTS` (256) — enough to cover databases,
/// message brokers, caches, and custom services concurrently.
#[map]
static L7_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(MAX_L7_PORTS, 0);

/// Small L7 event buffer: `PacketEvent` header + `SMALL_L7_PAYLOAD` bytes
/// of payload (512 B). Used when TCP payload ≤ 512 bytes — saves ~75%
/// RingBuf space vs the full buffer.
#[repr(C)]
struct L7EventSmall {
    header: PacketEvent,
    payload: [u8; SMALL_L7_PAYLOAD],
}

/// Full L7 event buffer: `PacketEvent` header + `MAX_L7_PAYLOAD` bytes
/// of payload (2 KiB). Used when TCP payload > `SMALL_L7_PAYLOAD`.
#[repr(C)]
struct L7EventBuf {
    header: PacketEvent,
    payload: [u8; MAX_L7_PAYLOAD],
}

// ── Metric indices ──────────────────────────────────────────────────

const METRIC_MATCHED: u32 = 0;
const METRIC_DROPPED: u32 = 1;
const METRIC_ERRORS: u32 = 2;
const METRIC_EVENTS_DROPPED: u32 = 3;
const METRIC_TOTAL_SEEN: u32 = 4;
/// Tenant resolved via cgroup_id → TENANT_CGROUP_MAP lookup.
const METRIC_CGROUP_TENANT_RESOLVED: u32 = 5;

/// 75% threshold for the 4 MiB EVENTS ring buffer. Must stay in sync
/// with the `RingBuf::with_byte_size` call above.
const IDS_EVENTS_BACKPRESSURE_THRESHOLD: u64 = (1024 * 4096) * 3 / 4;

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    ringbuf_has_backpressure!(EVENTS, IDS_EVENTS_BACKPRESSURE_THRESHOLD)
}

/// Returns `true` if the event should be sampled out (i.e., skipped).
/// When sampling mode is `IDS_SAMPLING_NONE` or the config map is empty,
/// all events pass through (no sampling).
#[inline(always)]
fn should_skip_by_sampling() -> bool {
    if let Some(cfg) = IDS_SAMPLING_CONFIG.get(0) {
        if cfg.mode == IDS_SAMPLING_RANDOM {
            let rand = unsafe { bpf_get_prandom_u32() };
            return rand > cfg.rate_threshold;
        }
    }
    false
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
        // Priority 4: Cgroup-based (egress only — cgroup_id is 0 in softirq)
        let cgroup_id = bpf_get_current_cgroup_id();
        if cgroup_id != 0 {
            if let Some(&tid) = TENANT_CGROUP_MAP.get(&cgroup_id) {
                increment_metric(METRIC_CGROUP_TENANT_RESOLVED);
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
        // Priority 4: Cgroup-based (egress only)
        let cgroup_id = bpf_get_current_cgroup_id();
        if cgroup_id != 0 {
            if let Some(&tid) = TENANT_CGROUP_MAP.get(&cgroup_id) {
                increment_metric(METRIC_CGROUP_TENANT_RESOLVED);
                return tid;
            }
        }
        // Default tenant
        0
    }
}

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Delegates to try_tc_ids; any error returns TC_ACT_OK
/// (NFR15: default-to-pass on internal error).
#[classifier]
pub fn tc_ids(ctx: TcContext) -> i32 {
    increment_metric(METRIC_TOTAL_SEEN);
    match try_tc_ids(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── XDP metadata reading ────────────────────────────────────────────

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_ids(ctx: &TcContext) -> Result<i32, ()> {
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
        process_ids_v4(ctx, l3_offset, vlan_id, flags)
    } else if ether_type == ETH_P_IPV6 {
        process_ids_v6(ctx, l3_offset, vlan_id, flags | FLAG_IPV6)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 IDS processing path.
#[inline(always)]
fn process_ids_v4(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };

    // ihl() returns the header length in bytes (already multiplied by 4)
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Parse L4 ports. For TCP, keep a reference to the header so we can
    // reuse it for doff() in the L7 path (avoids a duplicate ptr_at).
    let mut tcp_hdr_ptr: Option<*const TcpHdr> = None;
    let (src_port, dst_port) = match protocol {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            tcp_hdr_ptr = Some(tcphdr);
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

    // L7 payload capture (independent of IDS patterns).
    // Reuse the TCP header pointer from the port parse above.
    if let Some(tcphdr) = tcp_hdr_ptr {
        if unsafe { L7_PORTS.get(&dst_port) }.is_some() {
            let tcp_data_off = (unsafe { (*tcphdr).doff() } as usize) * 4;
            let l7_offset = l4_offset + tcp_data_off;
            // bpf_skb_load_bytes handles fragmented packets natively
            // (via skb_header_pointer), so linearization via
            // bpf_skb_pull_data is unnecessary and wastes ~1µs on
            // large packets. Removed in favour of direct load.
            emit_l7_event(ctx, &src_addr, &dst_addr, src_port, dst_port, flags, vlan_id, l7_offset);
        }
    }

    // IDS pattern matching (key is port+protocol, no IP in key)
    process_ids_pattern(ctx, &src_addr, &dst_addr, src_port, dst_port, protocol as u8, flags, vlan_id)
}

/// IPv6 IDS processing path.
#[inline(always)]
fn process_ids_v6(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr)
        .ok_or(())?;

    // Parse L4 ports. For TCP, keep a reference to the header so we can
    // reuse it for doff() in the L7 path (avoids a duplicate ptr_at).
    let mut tcp_hdr_ptr: Option<*const TcpHdr> = None;
    let (src_port, dst_port) = if next_hdr == PROTO_TCP {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        tcp_hdr_ptr = Some(tcphdr);
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

    // L7 payload capture for IPv6 TCP.
    // Reuse the TCP header pointer from the port parse above.
    if let Some(tcphdr) = tcp_hdr_ptr {
        if unsafe { L7_PORTS.get(&dst_port) }.is_some() {
            let tcp_data_off = (unsafe { (*tcphdr).doff() } as usize) * 4;
            let l7_offset = l4_offset + tcp_data_off;
            // bpf_skb_load_bytes handles fragments natively — no
            // linearization needed (see IPv4 path comment).
            emit_l7_event(ctx, &src_addr, &dst_addr, src_port, dst_port, flags, vlan_id, l7_offset);
        }
    }

    // IDS pattern matching (key is port+protocol, same map for v4/v6)
    process_ids_pattern(ctx, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id)
}

/// IDS pattern lookup and action (shared by v4/v6 — key is port+protocol only).
#[inline(always)]
fn process_ids_pattern(
    _ctx: &TcContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) -> Result<i32, ()> {
    let key = IdsPatternKey {
        dst_port,
        protocol,
        _padding: 0,
    };

    let pattern = match unsafe { IDS_PATTERNS.get(&key) } {
        Some(p) => p,
        None => return Ok(TC_ACT_OK),
    };

    // Check interface group membership before applying IDS action.
    let iface_groups = get_iface_groups(_ctx);
    if !group_matches(pattern.group_mask, iface_groups) {
        return Ok(TC_ACT_OK); // group mismatch -> pass
    }

    // Check tenant isolation.
    let ifindex = unsafe { (*_ctx.skb.skb).ifindex };
    let tenant_id = if (flags & FLAG_IPV6) != 0 {
        unsafe { resolve_tenant_id_v6(ifindex, vlan_id, src_addr) }
    } else {
        unsafe { resolve_tenant_id(ifindex, vlan_id, src_addr[0]) }
    };
    if pattern.tenant_id != 0 && pattern.tenant_id != tenant_id {
        return Ok(TC_ACT_OK); // tenant mismatch -> pass
    }

    increment_metric(METRIC_MATCHED);

    // Kernel-side sampling: skip event emission probabilistically,
    // but always enforce the drop action for IPS mode.
    if !should_skip_by_sampling() {
        (|| {
            emit_packet_event!(EVENTS, IDS_METRICS, METRIC_EVENTS_DROPPED,
                src_addr, dst_addr, src_port, dst_port, protocol,
                EVENT_TYPE_IDS, pattern.action, pattern.rule_id, flags, vlan_id; tc _ctx);
        })();

        // Packet mirroring for forensics (enterprise feature, controlled by config map)
        if let Some(mirror_enabled) = IDS_MIRROR_CONFIG.get(1) {
            if *mirror_enabled == 1 {
                if let Some(ifindex) = IDS_MIRROR_CONFIG.get(0) {
                    let target_ifindex = *ifindex;
                    if target_ifindex > 0 {
                        unsafe {
                            bpf_clone_redirect(
                                _ctx.skb.skb as *mut _,
                                target_ifindex,
                                0, // flags: 0 = redirect ingress
                            );
                        }
                    }
                }
            }
        }
    }

    if pattern.action == IDS_ACTION_DROP {
        #[cfg(debug_assertions)]
        info!(_ctx, "IDS DROP {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port);

        // Mark the kernel netfilter conntrack entry as DYING so the
        // next packet of this flow is dropped by netfilter without a
        // userspace round-trip. The userspace IdsAppService counter
        // (ids_ct_dying_total) is incremented by the packet pipeline.
        let tuple = if (flags & FLAG_IPV6) != 0 {
            CtTuple::v6(*src_addr, *dst_addr, src_port, dst_port)
        } else {
            CtTuple::v4(src_addr[0], dst_addr[0], src_port, dst_port)
        };
        let mut opts = if protocol == PROTO_TCP {
            BpfCtOpts::tcp()
        } else {
            BpfCtOpts::udp()
        };
        unsafe {
            kill_flow_via_skb_ct(_ctx.skb.skb as *mut _, tuple, &mut opts);
        }

        increment_metric(METRIC_DROPPED);
        Ok(TC_ACT_SHOT)
    } else {
        #[cfg(debug_assertions)]
        info!(_ctx, "IDS ALERT {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port);
        Ok(TC_ACT_OK)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(IDS_METRICS, index);
}

/// Emit an L7 event: `PacketEvent` header + raw payload bytes from the packet.
///
/// Uses tiered `RingBuf` reservation to minimize bandwidth:
/// - Packets with <= 128 bytes of TCP payload -> `L7EventSmall` (192 bytes, saves 67%)
/// - Packets with > 128 bytes -> `L7EventBuf` (576 bytes, full capture)
///
/// Both tiers use compile-time constant lengths for `bpf_skb_load_bytes`
/// (required by the eBPF verifier on kernel 6.1+).
///
/// Uses `SkbDynptr` (kernel 6.4+ kfunc) to query the full packet size
/// including fragments without linearization, then falls back to
/// `ctx.len()` if the dynptr creation fails (should not happen on 6.9+).
#[inline(always)]
fn emit_l7_event(
    ctx: &TcContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    vlan_id: u16,
    l7_offset: usize,
) {
    if ringbuf_has_backpressure() {
        increment_metric(METRIC_EVENTS_DROPPED);
        return;
    }

    // Detect incoming FOU/GUE overlay encapsulation. Non-None means
    // the packet arrived through a FOU/GUE tunnel — useful for
    // overlay-aware IDS rules in cloud environments.
    let _fou_encap = unsafe { skb_get_fou_encap(ctx.skb.skb as *mut _) };

    // Use SkbDynptr to get the full packet size and read the first
    // 4 bytes of the L7 payload via adjust + read. This validates
    // the dynptr adjust/read path in TC context and provides a
    // protocol magic number for pre-classification (e.g. 0x16030x
    // for TLS, "HTTP" for HTTP/1.x, 0x505249 for HTTP/2 preface).
    let (pkt_len, _l7_magic) = unsafe { SkbDynptr::from_skb(ctx.skb.skb as *mut _) }
        .map(|mut dp| {
            let total = dp.size() as usize;
            // Clone the dynptr before adjusting so a second cursor
            // can independently scan headers while the primary cursor
            // reads the body (dual-cursor for HTTP pipelining etc.).
            let _header_cursor = dp.clone_dynptr();
            let magic: u32 = if l7_offset < total {
                dp.adjust(l7_offset as u32, dp.size());
                unsafe { dp.read::<u32>(0) }.unwrap_or(0)
            } else {
                0
            };
            (total, magic)
        })
        .unwrap_or((ctx.len() as usize, 0));
    let payload_avail = pkt_len.saturating_sub(l7_offset);

    if payload_avail <= SMALL_L7_PAYLOAD {
        // Small tier: reserve 192 bytes instead of 576
        emit_l7_small(ctx, src_addr, dst_addr, src_port, dst_port, flags, vlan_id, l7_offset);
    } else {
        // Full tier: reserve 576 bytes
        emit_l7_full(ctx, src_addr, dst_addr, src_port, dst_port, flags, vlan_id, l7_offset);
    }
}

/// Small L7 event (192 bytes): for packets with ≤ 128 bytes TCP payload.
#[inline(always)]
fn emit_l7_small(
    ctx: &TcContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    vlan_id: u16,
    l7_offset: usize,
) {
    if let Some(mut entry) = EVENTS.reserve::<L7EventSmall>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            fill_l7_header(
                ctx,
                &mut (*ptr).header,
                src_addr, dst_addr, src_port, dst_port, flags, vlan_id,
            );
            core::ptr::write_bytes((*ptr).payload.as_mut_ptr(), 0, SMALL_L7_PAYLOAD);
            let _ = bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                l7_offset as u32,
                (*ptr).payload.as_mut_ptr() as *mut _,
                SMALL_L7_PAYLOAD as u32,
            );
        }
        entry.submit(0);
    } else {
        increment_metric(METRIC_EVENTS_DROPPED);
    }
}

/// Full L7 event (576 bytes): for packets with > 128 bytes TCP payload.
#[inline(always)]
fn emit_l7_full(
    ctx: &TcContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    vlan_id: u16,
    l7_offset: usize,
) {
    if let Some(mut entry) = EVENTS.reserve::<L7EventBuf>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            fill_l7_header(
                ctx,
                &mut (*ptr).header,
                src_addr, dst_addr, src_port, dst_port, flags, vlan_id,
            );
            core::ptr::write_bytes((*ptr).payload.as_mut_ptr(), 0, MAX_L7_PAYLOAD);
            let _ = bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                l7_offset as u32,
                (*ptr).payload.as_mut_ptr() as *mut _,
                MAX_L7_PAYLOAD as u32,
            );
        }
        entry.submit(0);
    } else {
        increment_metric(METRIC_EVENTS_DROPPED);
    }
}

/// Fill the L7 event header fields (shared by both tiers).
#[inline(always)]
unsafe fn fill_l7_header(
    ctx: &TcContext,
    header: &mut PacketEvent,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    flags: u8,
    vlan_id: u16,
) {
    unsafe {
        header.timestamp_ns = bpf_ktime_get_boot_ns();
        header.src_addr = *src_addr;
        header.dst_addr = *dst_addr;
        header.src_port = src_port;
        header.dst_port = dst_port;
        header.protocol = PROTO_TCP;
        header.event_type = EVENT_TYPE_L7;
        header.action = 0;
        header.flags = flags;
        header.rule_id = 0;
        header.vlan_id = vlan_id;
        header.cpu_id = bpf_get_smp_processor_id() as u16;
        // Populate socket cookie for TC context (not available in XDP).
        header.socket_cookie = bpf_get_socket_cookie(ctx.skb.skb as *mut _);
        // Valid on egress where current task owns skb; 0 on ingress
        // softirq, userspace falls back to /proc parsing.
        header.cgroup_id = bpf_get_current_cgroup_id();
        header.cgroup1_id = 0;
        // RSS hash + RX timestamp are XDP-only metadata, populated by
        // xdp-firewall on the ingress path. TC programs leave them at 0.
        header.rss_hash = 0;
        header.rss_hash_type = 0;
        header.rx_hw_timestamp_ns = 0;
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
