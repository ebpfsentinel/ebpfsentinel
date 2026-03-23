#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_boot_ns},
    macros::{classifier, map},
    maps::{Array, HashMap, LpmTrie, LruPerCpuHashMap, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::TcContext,
};
use aya_ebpf_bindings::bindings::_bindgen_ty_28::BPF_SKB_TSTAMP_DELIVERY_MONO;
use aya_ebpf_bindings::helpers::{bpf_skb_ecn_set_ce, bpf_skb_set_tstamp};
use ebpf_common::{
    event::{EVENT_TYPE_QOS, FLAG_IPV6, FLAG_VLAN},
    qos::{
        QOS_METRIC_COUNT, QOS_METRIC_DELAYED, QOS_METRIC_DROPPED_LOSS, QOS_METRIC_DROPPED_QUEUE,
        QOS_METRIC_ERRORS, QOS_METRIC_EVENTS_DROPPED, QOS_METRIC_SHAPED, QOS_METRIC_TOTAL_SEEN,
        QosClassifierKey, QosClassifierValue, QosFlowState, QosPipeConfig, QosQueueConfig,
    },
    tenant::{MAX_TENANT_SUBNET_LPM_ENTRIES, MAX_TENANT_SUBNET_V6_LPM_ENTRIES},
};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP, PROTO_UDP,
    VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{emit_packet_event, increment_metric};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// NOTE: BPF_MAP_TYPE_QUEUE with bpf_map_push/pop_elem (v4.20) enables
// proper packet queuing for QoS scheduling. Current implementation uses
// token bucket + EDT timestamps without explicit queuing.

// ── Maps ────────────────────────────────────────────────────────────

/// `QoS` pipe configuration (written by userspace). Index = pipe_id (0-63).
#[map]
static QOS_PIPE_CONFIG: Array<QosPipeConfig> = Array::with_max_entries(64, 0);

/// `QoS` queue configuration (written by userspace). Index = queue_id (0-255).
#[map]
static QOS_QUEUE_CONFIG: Array<QosQueueConfig> = Array::with_max_entries(256, 0);

/// `QoS` classifier lookup: 5-tuple+DSCP -> queue_id + priority.
#[map]
static QOS_CLASSIFIERS: HashMap<QosClassifierKey, QosClassifierValue> =
    HashMap::with_max_entries(1024, 0);

/// Per-flow `QoS` state (token bucket). Per-CPU LRU eliminates cross-CPU contention.
#[map]
static QOS_FLOW_STATE: LruPerCpuHashMap<u32, QosFlowState> =
    LruPerCpuHashMap::with_max_entries(65536, 0);

/// Per-CPU packet counters.
#[map]
static QOS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(QOS_METRIC_COUNT, 0);

/// Shared kernel->userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

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

// ── Constants ───────────────────────────────────────────────────────

/// Action code for "shaped" (delayed/rate-limited but passed).
const ACTION_SHAPED: u8 = 1;
/// Action code for "dropped" by `QoS` policy.
const ACTION_DROPPED: u8 = 2;

// ── Helper wrappers ─────────────────────────────────────────────────

#[inline(always)]
fn increment_qos_metric(index: u32) {
    increment_metric!(QOS_METRICS, index);
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

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point for egress QoS. Default-to-pass on error (NFR15).
#[classifier]
pub fn tc_qos(ctx: TcContext) -> i32 {
    increment_qos_metric(QOS_METRIC_TOTAL_SEEN);
    match try_tc_qos(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_qos_metric(QOS_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_qos(ctx: &TcContext) -> Result<i32, ()> {
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
        process_qos_v4(ctx, l3_offset, vlan_id, flags)
    } else if ether_type == ETH_P_IPV6 {
        process_qos_v6(ctx, l3_offset, vlan_id, flags | FLAG_IPV6)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 `QoS` processing path.
#[inline(always)]
fn process_qos_v4(ctx: &TcContext, l3_offset: usize, vlan_id: u16, flags: u8) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto };
    // Extract DSCP from TOS field (top 6 bits)
    let tos = unsafe { (*ipv4hdr).tos };
    let dscp = tos >> 2;

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

    apply_qos(
        ctx,
        &src_addr,
        &dst_addr,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol as u8,
        dscp,
        vlan_id,
        flags,
    )
}

/// IPv6 `QoS` processing path.
#[inline(always)]
fn process_qos_v6(ctx: &TcContext, l3_offset: usize, vlan_id: u16, flags: u8) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_raw = unsafe { (*ipv6hdr).src_addr };
    let dst_raw = unsafe { (*ipv6hdr).dst_addr };
    let src_addr = ipv6_addr_to_u32x4(&src_raw);
    let dst_addr = ipv6_addr_to_u32x4(&dst_raw);
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Extract DSCP from the version/traffic-class/flow-label u32.
    // Layout (network byte order): version(4) + traffic_class(8) + flow_label(20).
    // _vtcfl is stored in big-endian; convert to host order first.
    let vtcfl = u32::from_be(unsafe { (*ipv6hdr)._vtcfl });
    // traffic_class is bits 20-27 (after version nibble)
    let traffic_class = ((vtcfl >> 20) & 0xFF) as u8;
    let dscp = traffic_class >> 2;

    let mut l4_offset = l3_offset + IPV6_HDR_LEN;
    let protocol = match skip_ipv6_ext_headers(ctx, l4_offset, next_hdr) {
        Some((proto, new_offset)) => {
            l4_offset = new_offset;
            proto
        }
        None => next_hdr,
    };

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
        _ => (0u16, 0u16),
    };

    // For IPv6 classifier lookup, XOR-fold to u32 for flow hashing
    let src_ip_hash = src_addr[0] ^ src_addr[1] ^ src_addr[2] ^ src_addr[3];
    let dst_ip_hash = dst_addr[0] ^ dst_addr[1] ^ dst_addr[2] ^ dst_addr[3];

    apply_qos(
        ctx,
        &src_addr,
        &dst_addr,
        src_ip_hash,
        dst_ip_hash,
        src_port,
        dst_port,
        protocol,
        dscp,
        vlan_id,
        flags,
    )
}

// ── Classification ──────────────────────────────────────────────────

/// Classify a packet using progressive wildcard lookups (max 4 attempts).
/// Returns (queue_id, priority) on match, or None.
#[inline(always)]
fn classify(
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    dscp: u8,
) -> Option<QosClassifierValue> {
    // 1. Exact 5-tuple + DSCP
    let key = QosClassifierKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        dscp,
        _padding: [0; 2],
    };
    if let Some(val) = unsafe { QOS_CLASSIFIERS.get(&key) } {
        return Some(*val);
    }

    // 2. Wildcard src_port
    let key2 = QosClassifierKey {
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port,
        protocol,
        dscp,
        _padding: [0; 2],
    };
    if let Some(val) = unsafe { QOS_CLASSIFIERS.get(&key2) } {
        return Some(*val);
    }

    // 3. Wildcard both ports
    let key3 = QosClassifierKey {
        src_ip,
        dst_ip,
        src_port: 0,
        dst_port: 0,
        protocol,
        dscp,
        _padding: [0; 2],
    };
    if let Some(val) = unsafe { QOS_CLASSIFIERS.get(&key3) } {
        return Some(*val);
    }

    // 4. Wildcard all (catch-all rule)
    let key4 = QosClassifierKey {
        src_ip: 0,
        dst_ip: 0,
        src_port: 0,
        dst_port: 0,
        protocol: 0,
        dscp: 0xFF,
        _padding: [0; 2],
    };
    if let Some(val) = unsafe { QOS_CLASSIFIERS.get(&key4) } {
        return Some(*val);
    }

    None
}

// ── Flow hashing ────────────────────────────────────────────────────

/// Hash a 5-tuple to a u32 flow key for per-flow state.
#[inline(always)]
fn flow_hash(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> u32 {
    // Simple XOR+rotate hash for flow identification
    let mut h = src_ip;
    h ^= dst_ip.rotate_left(13);
    h ^= (u32::from(src_port) << 16) | u32::from(dst_port);
    h ^= u32::from(protocol).rotate_left(5);
    // Finalize with a mix step
    h ^= h >> 16;
    h = h.wrapping_mul(0x45d9_f3b);
    h ^= h >> 16;
    h
}

// ── Core QoS logic ──────────────────────────────────────────────────

/// Apply `QoS` policy to a classified packet.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn apply_qos(
    ctx: &TcContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    dscp: u8,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    // Step 1: Classify the packet
    let classifier_val = match classify(src_ip, dst_ip, src_port, dst_port, protocol, dscp) {
        Some(v) => v,
        None => return Ok(TC_ACT_OK), // No matching rule -> pass
    };

    // Check interface group membership for the classifier value.
    let iface_groups = get_iface_groups(ctx);
    if !group_matches(classifier_val.group_mask, iface_groups) {
        return Ok(TC_ACT_OK); // group mismatch -> pass
    }

    // Check tenant isolation for the classifier.
    let ifindex = unsafe { (*ctx.skb.skb).ifindex };
    let tenant_id = if (flags & FLAG_IPV6) != 0 {
        unsafe { resolve_tenant_id_v6(ifindex, vlan_id, src_addr) }
    } else {
        unsafe { resolve_tenant_id(ifindex, vlan_id, src_ip) }
    };
    if classifier_val.tenant_id != 0 && classifier_val.tenant_id != tenant_id {
        return Ok(TC_ACT_OK); // tenant mismatch -> pass
    }

    // Step 2: Get queue config -> pipe config
    let queue_id = classifier_val.queue_id as u32;
    let queue_cfg = match QOS_QUEUE_CONFIG.get(queue_id) {
        Some(q) => q,
        None => return Ok(TC_ACT_OK),
    };

    if queue_cfg.enabled == 0 {
        return Ok(TC_ACT_OK);
    }

    let pipe_id = queue_cfg.pipe_id as u32;
    let pipe_cfg = match QOS_PIPE_CONFIG.get(pipe_id) {
        Some(p) => p,
        None => return Ok(TC_ACT_OK),
    };

    if pipe_cfg.enabled == 0 {
        return Ok(TC_ACT_OK);
    }

    // Check interface group membership for the pipe.
    if !group_matches(pipe_cfg.group_mask, iface_groups) {
        return Ok(TC_ACT_OK);
    }

    // Check tenant isolation for the pipe.
    if pipe_cfg.tenant_id != 0 && pipe_cfg.tenant_id != tenant_id {
        return Ok(TC_ACT_OK); // tenant mismatch -> pass
    }

    // Step 3: Loss emulation — random drop
    if pipe_cfg.loss_rate > 0 {
        let rand = unsafe { bpf_get_prandom_u32() } % 10000;
        if rand < u32::from(pipe_cfg.loss_rate) {
            increment_qos_metric(QOS_METRIC_DROPPED_LOSS);
            (|| {
                emit_packet_event!(EVENTS, QOS_METRICS, QOS_METRIC_EVENTS_DROPPED,
                    src_addr, dst_addr, src_port, dst_port, protocol,
                    EVENT_TYPE_QOS, ACTION_DROPPED, pipe_id, flags, vlan_id; tc ctx);
            })();
            return Ok(TC_ACT_SHOT);
        }
    }

    // Step 4: Token bucket bandwidth enforcement
    if pipe_cfg.bytes_per_ns > 0 {
        let now_ns = unsafe { bpf_ktime_get_boot_ns() };
        let fh = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);
        let pkt_len = (ctx.data_end() - ctx.data()) as u64;

        let should_drop = match QOS_FLOW_STATE.get_ptr_mut(&fh) {
            Some(state_ptr) => {
                let state = unsafe { &mut *state_ptr };
                // Refill tokens — use division (supported) not multiplication
                // (u64*u64 triggers __multi3 which eBPF lacks).
                // bytes_per_ns is the rate. Compute ns_per_byte = 1/bytes_per_ns.
                // new_tokens = elapsed_ns / ns_per_byte (both u64, division is OK).
                let elapsed_ns = now_ns.saturating_sub(state.last_refill_ns);
                let ns_per_byte = if pipe_cfg.bytes_per_ns > 0 {
                    1_000_000_000 / pipe_cfg.bytes_per_ns
                } else {
                    u64::MAX
                };
                let new_tokens = if ns_per_byte > 0 {
                    elapsed_ns / ns_per_byte
                } else {
                    elapsed_ns // rate >= 1 byte/ns → get all elapsed as tokens
                };
                state.tokens = (state.tokens + new_tokens).min(pipe_cfg.burst_bytes);
                state.last_refill_ns = now_ns;

                // Check if we can consume tokens
                if state.tokens >= pkt_len {
                    state.tokens -= pkt_len;
                    // ECN Congestion Experienced: when token bucket is below 25% of burst,
                    // mark the packet with CE to signal the sender to slow down proactively.
                    // This provides early congestion signalling without dropping the packet,
                    // allowing TCP to reduce its window before the queue overflows.
                    if state.tokens < pipe_cfg.burst_bytes / 4 {
                        unsafe { bpf_skb_ecn_set_ce(ctx.skb.skb) };
                    }
                    false
                } else {
                    true // over bandwidth
                }
            }
            None => {
                // First packet for this flow — initialize state
                let new_state = QosFlowState {
                    tokens: pipe_cfg.burst_bytes.saturating_sub(pkt_len),
                    last_refill_ns: now_ns,
                    last_edt_ns: 0,
                    pipe_id: pipe_id as u8,
                    queue_id: queue_id as u8,
                    _padding: [0; 6],
                };
                let _ = QOS_FLOW_STATE.insert(&fh, &new_state, 0);
                false // First packet passes
            }
        };

        if should_drop {
            increment_qos_metric(QOS_METRIC_DROPPED_QUEUE);
            (|| {
                emit_packet_event!(EVENTS, QOS_METRICS, QOS_METRIC_EVENTS_DROPPED,
                    src_addr, dst_addr, src_port, dst_port, protocol,
                    EVENT_TYPE_QOS, ACTION_DROPPED, pipe_id, flags, vlan_id; tc ctx);
            })();
            return Ok(TC_ACT_SHOT);
        }
    }

    // Step 5: EDT (Earliest Departure Time) pacing via bpf_skb_set_tstamp.
    // Sets skb->tstamp = max(now, prev_edt) + delay_ns so the kernel queuing
    // discipline (fq) spaces packets according to the configured delay.
    if pipe_cfg.delay_ns > 0 {
        let now_ns_edt = unsafe { bpf_ktime_get_boot_ns() };
        let fh_edt = flow_hash(src_ip, dst_ip, src_port, dst_port, protocol);

        let edt = match QOS_FLOW_STATE.get_ptr_mut(&fh_edt) {
            Some(state_ptr) => {
                let state = unsafe { &mut *state_ptr };
                let base = if state.last_edt_ns > now_ns_edt {
                    state.last_edt_ns
                } else {
                    now_ns_edt
                };
                let departure = base.saturating_add(pipe_cfg.delay_ns);
                state.last_edt_ns = departure;
                departure
            }
            None => {
                // No flow state yet (delay-only pipe without bandwidth shaping).
                let departure = now_ns_edt.saturating_add(pipe_cfg.delay_ns);
                let new_state = QosFlowState {
                    tokens: 0,
                    last_refill_ns: now_ns_edt,
                    last_edt_ns: departure,
                    pipe_id: pipe_id as u8,
                    queue_id: queue_id as u8,
                    _padding: [0; 6],
                };
                let _ = QOS_FLOW_STATE.insert(&fh_edt, &new_state, 0);
                departure
            }
        };

        unsafe {
            bpf_skb_set_tstamp(
                ctx.skb.skb,
                edt,
                BPF_SKB_TSTAMP_DELIVERY_MONO,
            );
        }

        increment_qos_metric(QOS_METRIC_DELAYED);
        (|| {
            emit_packet_event!(EVENTS, QOS_METRICS, QOS_METRIC_EVENTS_DROPPED,
                src_addr, dst_addr, src_port, dst_port, protocol,
                EVENT_TYPE_QOS, ACTION_SHAPED, pipe_id, flags, vlan_id; tc ctx);
        })();
    }

    // Mark as shaped if any shaping was applied
    increment_qos_metric(QOS_METRIC_SHAPED);

    Ok(TC_ACT_OK)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
