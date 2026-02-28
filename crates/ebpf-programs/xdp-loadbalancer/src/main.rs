#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_boot_ns},
    macros::{map, xdp},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use core::mem;
use ebpf_common::{
    event::{PacketEvent, FLAG_IPV6, FLAG_VLAN},
    loadbalancer::{
        LbBackendEntry, LbServiceConfig, LbServiceKey, LB_ACTION_FORWARD, LB_ACTION_NO_BACKEND,
        LB_ALG_IP_HASH, LB_ALG_ROUND_ROBIN, LB_ALG_WEIGHTED, LB_MAX_BACKENDS,
        LB_METRIC_BYTES_FORWARDED, LB_METRIC_COUNT, LB_METRIC_EVENTS_DROPPED,
        LB_METRIC_PACKETS_FORWARDED, LB_METRIC_PACKETS_NO_BACKEND, EVENT_TYPE_LB,
    },
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr};

// ── Constants ───────────────────────────────────────────────────────

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const VLAN_HDR_LEN: usize = 4;
const IPV6_HDR_LEN: usize = 40;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

const EVENTS_RINGBUF_SIZE: u64 = 256 * 4096;
const BACKPRESSURE_THRESHOLD: u64 = EVENTS_RINGBUF_SIZE * 3 / 4;
const BPF_RB_AVAIL_DATA: u64 = 0;

/// Maximum services.
const MAX_SERVICES: u32 = 64;
/// Maximum backends.
const MAX_BACKENDS: u32 = 256;

// ── Inline header types ─────────────────────────────────────────────

#[repr(C)]
struct Ipv6Hdr {
    _vtcfl: u32,
    _payload_len: u16,
    next_hdr: u8,
    _hop_limit: u8,
    src_addr: [u8; 16],
    dst_addr: [u8; 16],
}

#[repr(C)]
struct VlanHdr {
    tci: u16,
    ether_type: u16,
}

#[repr(C)]
struct TcpUdpHdr {
    src_port: u16,
    dst_port: u16,
}

// ── eBPF Maps ───────────────────────────────────────────────────────

/// Service lookup: (protocol, port) → service config.
#[map]
static LB_SERVICES: HashMap<LbServiceKey, LbServiceConfig> =
    HashMap::with_max_entries(MAX_SERVICES, 0);

/// Backend pool: backend_id → backend entry.
#[map]
static LB_BACKENDS: HashMap<u32, LbBackendEntry> = HashMap::with_max_entries(MAX_BACKENDS, 0);

/// Per-service round-robin state (index 0..63).
#[map]
static LB_RR_STATE: PerCpuArray<u32> = PerCpuArray::with_max_entries(MAX_SERVICES, 0);

/// Per-CPU metrics.
#[map]
static LB_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(LB_METRIC_COUNT, 0);

/// Shared event ring buffer.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(EVENTS_RINGBUF_SIZE as u32, 0);

// ── Entry Point ─────────────────────────────────────────────────────

#[xdp]
pub fn xdp_loadbalancer(ctx: XdpContext) -> u32 {
    match try_xdp_loadbalancer(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_loadbalancer(ctx: &XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;
    let mut vlan_id: u16 = 0;

    // Handle 802.1Q VLAN
    if ether_type == ETH_P_8021Q {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        vlan_id = u16::from_be(unsafe { (*vhdr).tci }) & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
    }

    match ether_type {
        ETH_P_IP => process_v4(ctx, l3_offset, vlan_id),
        ETH_P_IPV6 => process_v6(ctx, l3_offset, vlan_id),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

// ── IPv4 Processing ─────────────────────────────────────────────────

#[inline(always)]
fn process_v4(ctx: &XdpContext, l3_offset: usize, vlan_id: u16) -> Result<u32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let protocol = unsafe { (*ipv4hdr).proto };
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize * 4;
    let l4_offset = l3_offset + ihl;

    if protocol != PROTO_TCP && protocol != PROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let l4hdr: *const TcpUdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let dst_port = u16::from_be(unsafe { (*l4hdr).dst_port });
    let src_port = u16::from_be(unsafe { (*l4hdr).src_port });

    // Lookup service
    let key = LbServiceKey {
        protocol,
        _pad: 0,
        port: dst_port,
    };
    let svc_config = match unsafe { LB_SERVICES.get(&key) } {
        Some(c) => c,
        None => return Ok(xdp_action::XDP_PASS), // Not a load-balanced service
    };

    let src_addr_raw = unsafe { (*ipv4hdr).src_addr };
    let dst_addr_raw = unsafe { (*ipv4hdr).dst_addr };
    let src_ip = u32::from_be_bytes(src_addr_raw.to_be_bytes());
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;

    let src_addr = [u32::from_ne_bytes(src_addr_raw.to_ne_bytes()), 0, 0, 0];
    let dst_addr = [u32::from_ne_bytes(dst_addr_raw.to_ne_bytes()), 0, 0, 0];

    // Select backend
    let backend = match select_backend(svc_config, src_ip) {
        Some(b) => b,
        None => {
            increment_metric(LB_METRIC_PACKETS_NO_BACKEND);
            emit_event(
                ctx,
                &src_addr,
                &dst_addr,
                src_port,
                dst_port,
                protocol,
                LB_ACTION_NO_BACKEND,
                0,
                vlan_id,
            );
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // ── DNAT rewrite ────────────────────────────────────────────
    let ipv4hdr_mut: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, l3_offset)? };
    let l4hdr_mut: *mut TcpUdpHdr = unsafe { ptr_at_mut(ctx, l4_offset)? };

    let old_dst_ip = unsafe { (*ipv4hdr_mut).dst_addr };
    let new_dst_ip = backend.addr_v4.to_be();
    let old_dst_port = unsafe { (*l4hdr_mut).dst_port };
    let new_dst_port = backend.port.to_be();

    // Update IP header
    unsafe {
        (*ipv4hdr_mut).dst_addr = new_dst_ip;
    }

    // Incremental IP checksum update
    update_ip_checksum(ipv4hdr_mut, old_dst_ip, new_dst_ip);

    // Update L4 port
    unsafe {
        (*l4hdr_mut).dst_port = new_dst_port;
    }

    // Incremental L4 checksum update
    update_l4_checksum_v4(
        ctx,
        l4_offset,
        protocol,
        old_dst_ip,
        new_dst_ip,
        old_dst_port,
        new_dst_port,
    );

    // Metrics + event
    increment_metric(LB_METRIC_PACKETS_FORWARDED);
    add_metric(LB_METRIC_BYTES_FORWARDED, pkt_len);

    emit_event(
        ctx,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        protocol,
        LB_ACTION_FORWARD,
        0,
        vlan_id,
    );

    Ok(xdp_action::XDP_TX)
}

// ── IPv6 Processing ─────────────────────────────────────────────────

#[inline(always)]
fn process_v6(ctx: &XdpContext, l3_offset: usize, vlan_id: u16) -> Result<u32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };
    let l4_offset = l3_offset + IPV6_HDR_LEN;

    if next_hdr != PROTO_TCP && next_hdr != PROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let l4hdr: *const TcpUdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let dst_port = u16::from_be(unsafe { (*l4hdr).dst_port });
    let src_port = u16::from_be(unsafe { (*l4hdr).src_port });

    let key = LbServiceKey {
        protocol: next_hdr,
        _pad: 0,
        port: dst_port,
    };
    let svc_config = match unsafe { LB_SERVICES.get(&key) } {
        Some(c) => c,
        None => return Ok(xdp_action::XDP_PASS),
    };

    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });

    // For IP hash, XOR-fold IPv6 src to u32
    let src_ip_folded = src_addr[0] ^ src_addr[1] ^ src_addr[2] ^ src_addr[3];
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;

    let backend = match select_backend(svc_config, src_ip_folded) {
        Some(b) => b,
        None => {
            increment_metric(LB_METRIC_PACKETS_NO_BACKEND);
            emit_event(
                ctx,
                &src_addr,
                &dst_addr,
                src_port,
                dst_port,
                next_hdr,
                LB_ACTION_NO_BACKEND,
                FLAG_IPV6,
                vlan_id,
            );
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // ── DNAT rewrite (IPv6) ─────────────────────────────────────
    let ipv6hdr_mut: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, l3_offset)? };
    let l4hdr_mut: *mut TcpUdpHdr = unsafe { ptr_at_mut(ctx, l4_offset)? };

    let old_dst_port = unsafe { (*l4hdr_mut).dst_port };
    let new_dst_port = backend.port.to_be();

    if backend.is_ipv6 == 1 {
        // Rewrite 128-bit destination address
        let new_addr = u32x4_to_ipv6_bytes(&backend.addr_v6);
        unsafe {
            (*ipv6hdr_mut).dst_addr = new_addr;
        }
    }

    unsafe {
        (*l4hdr_mut).dst_port = new_dst_port;
    }

    // IPv6 has no IP checksum, but L4 pseudo-header checksum needs update
    update_l4_checksum_port_only(ctx, l4_offset, next_hdr, old_dst_port, new_dst_port);

    increment_metric(LB_METRIC_PACKETS_FORWARDED);
    add_metric(LB_METRIC_BYTES_FORWARDED, pkt_len);

    emit_event(
        ctx,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        next_hdr,
        LB_ACTION_FORWARD,
        FLAG_IPV6,
        vlan_id,
    );

    Ok(xdp_action::XDP_TX)
}

// ── Backend Selection ───────────────────────────────────────────────

/// Select a healthy backend from the service config.
/// Returns `None` if no healthy backend is available.
#[inline(always)]
fn select_backend(svc: &LbServiceConfig, src_ip: u32) -> Option<&LbBackendEntry> {
    let count = svc.backend_count as usize;
    if count == 0 {
        return None;
    }

    // Clamp to avoid out-of-bounds
    let count = if count > LB_MAX_BACKENDS {
        LB_MAX_BACKENDS
    } else {
        count
    };

    let start_idx = match svc.algorithm {
        LB_ALG_ROUND_ROBIN => {
            // Use per-CPU round-robin state (index 0 as default)
            let rr_ptr = LB_RR_STATE.get_ptr_mut(0)?;
            let rr = unsafe { *rr_ptr };
            unsafe {
                *rr_ptr = rr.wrapping_add(1);
            }
            rr as usize
        }
        LB_ALG_IP_HASH => fnv1a(src_ip) as usize,
        LB_ALG_WEIGHTED => {
            let rr_ptr = LB_RR_STATE.get_ptr_mut(0)?;
            let rr = unsafe { *rr_ptr };
            unsafe {
                *rr_ptr = rr.wrapping_add(1);
            }
            (rr ^ src_ip) as usize
        }
        // LeastConn falls back to RoundRobin in eBPF
        _ => {
            let rr_ptr = LB_RR_STATE.get_ptr_mut(0)?;
            let rr = unsafe { *rr_ptr };
            unsafe {
                *rr_ptr = rr.wrapping_add(1);
            }
            rr as usize
        }
    };

    // Linear probe for a healthy backend (try all, starting from selected index)
    let mut i = 0;
    while i < count {
        let idx = (start_idx + i) % count;
        // Bounds check for verifier
        if idx >= LB_MAX_BACKENDS {
            i += 1;
            continue;
        }
        let backend_id = svc.backend_ids[idx];
        if let Some(be) = unsafe { LB_BACKENDS.get(&backend_id) } {
            if be.healthy == 1 {
                return Some(be);
            }
        }
        i += 1;
    }

    None
}

/// FNV-1a hash of a u32 value.
#[inline(always)]
fn fnv1a(val: u32) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    let bytes = val.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        i += 1;
    }
    hash
}

// ── Checksum Helpers ────────────────────────────────────────────────

/// Incremental IP header checksum update after dst_addr rewrite (RFC 1624).
#[inline(always)]
fn update_ip_checksum(ipv4hdr: *mut Ipv4Hdr, old_val: u32, new_val: u32) {
    unsafe {
        let mut csum = !u32::from(u16::from_be((*ipv4hdr).check));
        // Subtract old, add new (32-bit words, split into 16-bit halves)
        csum = csum.wrapping_sub(old_val & 0xFFFF);
        csum = csum.wrapping_sub(old_val >> 16);
        csum = csum.wrapping_add(new_val & 0xFFFF);
        csum = csum.wrapping_add(new_val >> 16);
        // Fold carry
        csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
        csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
        (*ipv4hdr).check = (!csum as u16).to_be();
    }
}

/// Incremental TCP/UDP checksum update after IPv4 dst_addr + dst_port rewrite.
#[inline(always)]
fn update_l4_checksum_v4(
    ctx: &XdpContext,
    l4_offset: usize,
    protocol: u8,
    old_ip: u32,
    new_ip: u32,
    old_port: u16,
    new_port: u16,
) {
    let csum_offset = if protocol == PROTO_TCP {
        l4_offset + 16 // TCP checksum at offset 16
    } else {
        l4_offset + 6 // UDP checksum at offset 6
    };

    if let Ok(csum_ptr) = unsafe { ptr_at_mut::<u16>(ctx, csum_offset) } {
        unsafe {
            let mut csum = !u32::from(u16::from_be(*csum_ptr));
            // IP diff
            csum = csum.wrapping_sub(old_ip & 0xFFFF);
            csum = csum.wrapping_sub(old_ip >> 16);
            csum = csum.wrapping_add(new_ip & 0xFFFF);
            csum = csum.wrapping_add(new_ip >> 16);
            // Port diff
            csum = csum.wrapping_sub(u32::from(u16::from_be(old_port)));
            csum = csum.wrapping_add(u32::from(u16::from_be(new_port)));
            // Fold
            csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
            csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
            *csum_ptr = (!csum as u16).to_be();
        }
    }
}

/// Incremental L4 checksum update for port-only change (IPv6 — no IP checksum).
#[inline(always)]
fn update_l4_checksum_port_only(
    ctx: &XdpContext,
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) {
    let csum_offset = if protocol == PROTO_TCP {
        l4_offset + 16
    } else {
        l4_offset + 6
    };

    if let Ok(csum_ptr) = unsafe { ptr_at_mut::<u16>(ctx, csum_offset) } {
        unsafe {
            let mut csum = !u32::from(u16::from_be(*csum_ptr));
            csum = csum.wrapping_sub(u32::from(u16::from_be(old_port)));
            csum = csum.wrapping_add(u32::from(u16::from_be(new_port)));
            csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
            csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
            *csum_ptr = (!csum as u16).to_be();
        }
    }
}

// ── Pointer Helpers ─────────────────────────────────────────────────

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

// ── IPv6 Address Helpers ────────────────────────────────────────────

#[inline(always)]
fn ipv6_addr_to_u32x4(addr: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
        u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
        u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
        u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
    ]
}

#[inline(always)]
fn u32x4_to_ipv6_bytes(addr: &[u32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let a = addr[0].to_be_bytes();
    let b = addr[1].to_be_bytes();
    let c = addr[2].to_be_bytes();
    let d = addr[3].to_be_bytes();
    bytes[0] = a[0]; bytes[1] = a[1]; bytes[2] = a[2]; bytes[3] = a[3];
    bytes[4] = b[0]; bytes[5] = b[1]; bytes[6] = b[2]; bytes[7] = b[3];
    bytes[8] = c[0]; bytes[9] = c[1]; bytes[10] = c[2]; bytes[11] = c[3];
    bytes[12] = d[0]; bytes[13] = d[1]; bytes[14] = d[2]; bytes[15] = d[3];
    bytes
}

// ── Metrics Helpers ─────────────────────────────────────────────────

#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = LB_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

#[inline(always)]
fn add_metric(index: u32, value: u64) {
    if let Some(counter) = LB_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += value;
        }
    }
}

// ── Event Emission ──────────────────────────────────────────────────

#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    EVENTS.query(BPF_RB_AVAIL_DATA) > BACKPRESSURE_THRESHOLD
}

#[inline(always)]
fn emit_event(
    ctx: &XdpContext,
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
        increment_metric(LB_METRIC_EVENTS_DROPPED);
        return;
    }

    let event = match EVENTS.reserve::<PacketEvent>(0) {
        Some(e) => e,
        None => {
            increment_metric(LB_METRIC_EVENTS_DROPPED);
            return;
        }
    };

    let vlan_flags = if vlan_id > 0 { flags | FLAG_VLAN } else { flags };

    unsafe {
        let ptr = event.as_mut_ptr();
        (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
        (*ptr).src_addr = *src_addr;
        (*ptr).dst_addr = *dst_addr;
        (*ptr).src_port = src_port;
        (*ptr).dst_port = dst_port;
        (*ptr).protocol = protocol;
        (*ptr).event_type = EVENT_TYPE_LB;
        (*ptr).action = action;
        (*ptr).flags = vlan_flags;
        (*ptr).rule_id = 0;
        (*ptr).vlan_id = vlan_id;
        (*ptr).cpu_id = bpf_get_smp_processor_id() as u16;
        (*ptr).socket_cookie = 0;
        event.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
