#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    helpers::{
        bpf_get_prandom_u32, bpf_get_smp_processor_id,
        bpf_ktime_get_boot_ns,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::info;
use core::mem;
use ebpf_common::{
    event::{
        PacketEvent, EVENT_TYPE_IDS, EVENT_TYPE_L7, FLAG_IPV6, FLAG_VLAN,
        MAX_L7_PAYLOAD,
    },
    ids::{
        IdsSamplingConfig, IdsPatternKey, IdsPatternValue, IDS_ACTION_DROP, IDS_SAMPLING_RANDOM,
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

/// IDS pattern lookup: port+protocol → action + rule metadata.
#[map]
static IDS_PATTERNS: HashMap<IdsPatternKey, IdsPatternValue> =
    HashMap::with_max_entries(10240, 0);

/// Per-CPU packet counters. Index: 0=matched, 1=dropped, 2=errors, 3=events_dropped.
#[map]
static IDS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

/// Shared kernel→userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

/// Feature enable/disable flags (shared across programs).
#[map]
static CONFIG_FLAGS: Array<u32> = Array::with_max_entries(1, 0);

/// Kernel-side IDS sampling configuration (single entry).
/// Mode + rate_threshold control event emission probability.
#[map]
static IDS_SAMPLING_CONFIG: Array<IdsSamplingConfig> = Array::with_max_entries(1, 0);

/// L7 port lookup: dst_port → enabled flag. When set, TCP packets to this port
/// have their payload captured and sent to userspace for L7 protocol parsing.
#[map]
static L7_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

/// Fixed-size buffer for L7 events: PacketEvent header + raw payload.
/// Submitted as a single RingBuf entry; userspace extracts payload from
/// bytes[64..] (everything after the 64-byte PacketEvent header).
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

/// RingBuf total size in bytes (must match EVENTS map declaration).
const EVENTS_RINGBUF_SIZE: u64 = 256 * 4096;

/// Backpressure threshold: skip emission when >75% of RingBuf is consumed.
const BACKPRESSURE_THRESHOLD: u64 = EVENTS_RINGBUF_SIZE * 3 / 4;

/// BPF_RB_AVAIL_DATA flag for `bpf_ringbuf_query`.
const BPF_RB_AVAIL_DATA: u64 = 0;

/// Returns `true` if the EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    EVENTS.query(BPF_RB_AVAIL_DATA) > BACKPRESSURE_THRESHOLD
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

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Delegates to try_tc_ids; any error returns TC_ACT_OK
/// (NFR15: default-to-pass on internal error).
#[classifier]
pub fn tc_ids(ctx: TcContext) -> i32 {
    match try_tc_ids(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(METRIC_ERRORS);
            TC_ACT_OK
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
    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        flags |= FLAG_VLAN;
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

    // L7 payload capture (independent of IDS patterns)
    if matches!(protocol, IpProto::Tcp) {
        if unsafe { L7_PORTS.get(&dst_port) }.is_some() {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            let tcp_data_off = (unsafe { (*tcphdr).doff() } as usize) * 4;
            let l7_offset = l4_offset + tcp_data_off;
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

    // L7 payload capture for IPv6 TCP
    if next_hdr == PROTO_TCP {
        if unsafe { L7_PORTS.get(&dst_port) }.is_some() {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            let tcp_data_off = (unsafe { (*tcphdr).doff() } as usize) * 4;
            let l7_offset = l4_offset + tcp_data_off;
            emit_l7_event(ctx, &src_addr, &dst_addr, src_port, dst_port, flags, vlan_id, l7_offset);
        }
    }

    // IDS pattern matching (key is port+protocol, same map for v4/v6)
    process_ids_pattern(ctx, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id)
}

/// IDS pattern lookup and action (shared by v4/v6 — key is port+protocol only).
#[inline(always)]
fn process_ids_pattern(
    ctx: &TcContext,
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

    increment_metric(METRIC_MATCHED);

    // Kernel-side sampling: skip event emission probabilistically,
    // but always enforce the drop action for IPS mode.
    if !should_skip_by_sampling() {
        emit_event(
            src_addr, dst_addr, src_port, dst_port, protocol, pattern, flags, vlan_id,
        );
    }

    if pattern.action == IDS_ACTION_DROP {
        info!(ctx, "IDS DROP {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port);
        increment_metric(METRIC_DROPPED);
        Ok(TC_ACT_SHOT)
    } else {
        info!(ctx, "IDS ALERT {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port);
        Ok(TC_ACT_OK)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Bounds-checked pointer access. Critical for eBPF verifier compliance:
/// every memory access must be validated against data_end.
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

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = IDS_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
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
    pattern: &IdsPatternValue,
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
            (*ptr).event_type = EVENT_TYPE_IDS;
            (*ptr).action = pattern.action;
            (*ptr).flags = flags;
            (*ptr).rule_id = pattern.rule_id;
            (*ptr).vlan_id = vlan_id;
            (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).socket_cookie = 0;
        }
        entry.submit(0);
    } else {
        increment_metric(METRIC_EVENTS_DROPPED);
    }
}

/// Emit an L7 event: PacketEvent header + raw payload bytes from the packet.
/// Reserves a fixed-size L7EventBuf in the RingBuf, fills the header, and
/// copies up to MAX_L7_PAYLOAD bytes of TCP payload starting at `l7_offset`.
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
    if let Some(mut entry) = EVENTS.reserve::<L7EventBuf>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            // Fill header
            (*ptr).header.timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).header.src_addr = *src_addr;
            (*ptr).header.dst_addr = *dst_addr;
            (*ptr).header.src_port = src_port;
            (*ptr).header.dst_port = dst_port;
            (*ptr).header.protocol = PROTO_TCP;
            (*ptr).header.event_type = EVENT_TYPE_L7;
            (*ptr).header.action = 0;
            (*ptr).header.flags = flags;
            (*ptr).header.rule_id = 0;
            (*ptr).header.vlan_id = vlan_id;
            (*ptr).header.cpu_id = bpf_get_smp_processor_id() as u16;
            (*ptr).header.socket_cookie = 0;

            // Zero payload buffer, then copy available packet bytes.
            core::ptr::write_bytes((*ptr).payload.as_mut_ptr(), 0, MAX_L7_PAYLOAD);

            let pkt_start = ctx.data() + l7_offset;
            let pkt_end = ctx.data_end();

            if pkt_start < pkt_end {
                let available = pkt_end - pkt_start;
                let copy_len = if available > MAX_L7_PAYLOAD {
                    MAX_L7_PAYLOAD
                } else {
                    available
                };
                core::ptr::copy_nonoverlapping(
                    pkt_start as *const u8,
                    (*ptr).payload.as_mut_ptr(),
                    copy_len,
                );
            }
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
