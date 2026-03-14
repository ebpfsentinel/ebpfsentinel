#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    helpers::{bpf_get_prandom_u32, bpf_get_smp_processor_id, bpf_ktime_get_boot_ns},
    macros::{classifier, map},
    maps::{Array, HashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
#[cfg(debug_assertions)]
use aya_log_ebpf::info;
use ebpf_common::{
    event::{PacketEvent, EVENT_TYPE_QOS, FLAG_IPV6, FLAG_VLAN},
    qos::{
        QosClassifierKey, QosClassifierValue, QosFlowState, QosPipeConfig, QosQueueConfig,
        QOS_METRIC_COUNT, QOS_METRIC_DELAYED, QOS_METRIC_DROPPED_LOSS, QOS_METRIC_DROPPED_QUEUE,
        QOS_METRIC_ERRORS, QOS_METRIC_EVENTS_DROPPED, QOS_METRIC_SHAPED, QOS_METRIC_TOTAL_SEEN,
    },
};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{increment_metric, ringbuf_has_backpressure};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

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

// ── Constants ───────────────────────────────────────────────────────

/// Action code for "shaped" (delayed/rate-limited but passed).
#[allow(dead_code)]
const ACTION_SHAPED: u8 = 1;
/// Action code for "dropped" by `QoS` policy.
const ACTION_DROPPED: u8 = 2;

// ── Helper wrappers ─────────────────────────────────────────────────

#[inline(always)]
fn increment_qos_metric(index: u32) {
    increment_metric!(QOS_METRICS, index);
}

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_bp() -> bool {
    ringbuf_has_backpressure!(EVENTS)
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
fn process_qos_v4(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
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
fn process_qos_v6(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
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

    // Step 3: Loss emulation — random drop
    if pipe_cfg.loss_rate > 0 {
        let rand = unsafe { bpf_get_prandom_u32() } % 10000;
        if rand < u32::from(pipe_cfg.loss_rate) {
            increment_qos_metric(QOS_METRIC_DROPPED_LOSS);
            emit_event(
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
                ACTION_DROPPED,
                pipe_id,
                flags,
                vlan_id,
            );
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
            emit_event(
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                protocol,
                ACTION_DROPPED,
                pipe_id,
                flags,
                vlan_id,
            );
            return Ok(TC_ACT_SHOT);
        }
    }

    // Step 5: Delay / EDT pacing
    // TODO: Implement EDT (Earliest Departure Time) pacing via skb->tstamp.
    // aya-ebpf does not currently expose bpf_skb_set_tstamp or direct
    // skb->tstamp write access. When it becomes available, set:
    //   skb->tstamp = max(now_ns, prev_edt) + delay_ns + pkt_len / bytes_per_ns
    // For now, delay is accounted in metrics but not enforced in the datapath.
    if pipe_cfg.delay_ns > 0 {
        increment_qos_metric(QOS_METRIC_DELAYED);
    }

    // Mark as shaped if any shaping was applied
    increment_qos_metric(QOS_METRIC_SHAPED);

    Ok(TC_ACT_OK)
}

// ── Event emission ──────────────────────────────────────────────────

/// Emit a `PacketEvent` to the EVENTS RingBuf. Skips emission under
/// backpressure (>75% full). If the buffer is full, increments the
/// events-dropped metric.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn emit_event(
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
    rule_id: u32,
    flags: u8,
    vlan_id: u16,
) {
    if ringbuf_bp() {
        increment_qos_metric(QOS_METRIC_EVENTS_DROPPED);
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
            (*ptr).event_type = EVENT_TYPE_QOS;
            (*ptr).action = action;
            (*ptr).flags = flags;
            (*ptr).rule_id = rule_id;
            (*ptr).vlan_id = vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0;
        }
        entry.submit(0);
    } else {
        increment_qos_metric(QOS_METRIC_EVENTS_DROPPED);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
