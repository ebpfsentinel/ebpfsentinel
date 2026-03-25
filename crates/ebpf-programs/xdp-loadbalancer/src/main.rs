#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    bindings::xdp_action,
    helpers::{bpf_check_mtu, bpf_get_smp_processor_id, bpf_ktime_get_boot_ns},
    macros::{map, xdp},
    maps::{DevMap, HashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u32x4_to_ipv6_bytes,
};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut, skip_ipv6_ext_headers};
use ebpf_helpers::{add_metric, copy_16b_asm, copy_mac_asm, increment_metric, ringbuf_has_backpressure};
use ebpf_common::{
    event::{PacketEvent, FLAG_IPV6, FLAG_VLAN},
    loadbalancer::{
        LbBackendEntry, LbServiceConfigV2, LbServiceKey, LB_ACTION_FORWARD,
        LB_ACTION_NO_BACKEND, LB_ALG_IP_HASH, LB_ALG_ROUND_ROBIN, LB_ALG_WEIGHTED,
        LB_MAX_BACKENDS_V2, MAX_LB_BACKENDS_TOTAL, MAX_LB_SERVICES, LB_METRIC_BYTES_FORWARDED,
        LB_METRIC_COUNT, LB_METRIC_EVENTS_DROPPED, LB_METRIC_MTU_EXCEEDED,
        LB_METRIC_PACKETS_FORWARDED, LB_METRIC_PACKETS_NO_BACKEND, LB_METRIC_TOTAL_SEEN,
        EVENT_TYPE_LB,
    },
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.

// NOTE: bpf_skb_get/set_tunnel_key (v4.3, TC context) enables tunnel
// encapsulation metadata for VXLAN/GRE backends. XDP-level tunneling
// requires bpf_skb_adjust_room + manual header construction.

// NOTE: bpf_sk_select_reuseport (v4.19) enables socket-level load
// balancing via SO_REUSEPORT. Alternative to XDP-level DNAT for
// localhost services. Requires BPF_PROG_TYPE_SK_REUSEPORT program.

/// Maximum backends per service (verifier bound for iteration).
const MAX_BACKENDS_PER_SVC: usize = LB_MAX_BACKENDS_V2 as usize;

// ── Inline program-specific header types ────────────────────────────

#[repr(C)]
struct TcpUdpHdr {
    src_port: u16,
    dst_port: u16,
}

// ── eBPF Maps ───────────────────────────────────────────────────────

/// Service lookup: (protocol, port) → compact service config (V2).
#[map]
static LB_SERVICES: HashMap<LbServiceKey, LbServiceConfigV2> =
    HashMap::with_max_entries(MAX_LB_SERVICES, 0);

/// Global backend pool: backend_id → backend entry.
#[map]
static LB_BACKENDS: HashMap<u32, LbBackendEntry> =
    HashMap::with_max_entries(MAX_LB_BACKENDS_TOTAL, 0);

/// Per-service round-robin state (index 0..4095).
#[map]
static LB_RR_STATE: PerCpuArray<u32> = PerCpuArray::with_max_entries(MAX_LB_SERVICES, 0);

/// Per-CPU metrics.
#[map]
static LB_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(LB_METRIC_COUNT, 0);

/// DevMap for high-performance XDP redirect to backend interfaces.
/// Userspace populates this with backend ifindex values. When an entry
/// exists for the selected backend, `redirect` is used instead of XDP_TX.
/// Falls back to MAC swap + XDP_TX when the DevMap entry is absent.
#[map]
static LB_DEVMAP: DevMap = DevMap::with_max_entries(256, 0);

/// Shared event ring buffer.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

// ── Entry Point ─────────────────────────────────────────────────────

#[xdp]
pub fn xdp_loadbalancer(ctx: XdpContext) -> u32 {
    increment_metric(LB_METRIC_TOTAL_SEEN);
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
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        vlan_id = u16::from_be(unsafe { (*vhdr).tci }) & 0x0FFF;
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
    let proto = unsafe { (*ipv4hdr).proto };
    let protocol = proto as u8;
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    if proto != IpProto::Tcp && proto != IpProto::Udp {
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
    let src_ip = u32::from_be_bytes(src_addr_raw);
    let pkt_len = ctx.data_end().saturating_sub(ctx.data()) as u64;

    let src_addr = [u32::from_ne_bytes(src_addr_raw), 0, 0, 0];
    let dst_addr = [u32::from_ne_bytes(dst_addr_raw), 0, 0, 0];

    // Select backend using per-service round-robin index
    let svc_idx = service_key_index(&key);
    let (backend_id, backend) = match select_backend(svc_config, src_ip, svc_idx) {
        Some(b) => b,
        None => {
            increment_metric(LB_METRIC_PACKETS_NO_BACKEND);
            emit_event(
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

    let old_dst_ip = u32::from_be_bytes(unsafe { (*ipv4hdr_mut).dst_addr });
    let new_dst_ip = backend.addr_v4;
    let old_dst_port = unsafe { (*l4hdr_mut).dst_port };
    let new_dst_port = backend.port.to_be();

    // Update IP header
    unsafe {
        (*ipv4hdr_mut).dst_addr = new_dst_ip.to_be_bytes();
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
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        protocol,
        LB_ACTION_FORWARD,
        0,
        vlan_id,
    );

    // Check MTU before forwarding to avoid silent fragmentation.
    let mut mtu: u32 = 0;
    let mtu_ret = unsafe {
        bpf_check_mtu(
            ctx.ctx as *mut _,
            0,
            &mut mtu as *mut u32,
            0,
            0,
        )
    };
    if mtu_ret != 0 {
        increment_metric(LB_METRIC_MTU_EXCEEDED);
        return Ok(xdp_action::XDP_DROP);
    }

    // Try DevMap redirect first (wire-speed forwarding to backend interface).
    // If userspace has populated LB_DEVMAP[backend_id] with the backend's
    // ifindex, redirect directly. Otherwise fall back to MAC swap + XDP_TX.
    if LB_DEVMAP.redirect(backend_id, 0).is_ok() {
        return Ok(xdp_action::XDP_REDIRECT);
    }

    // Fallback: MAC swap + XDP_TX (same-subnet backends behind a gateway).
    // Use copy_mac_asm! to prevent LLVM memcpy outlining with packet pointers.
    let ethhdr_mut: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let mut tmp_mac = [0u8; 6];
    unsafe {
        let p = ethhdr_mut as *mut u8;
        copy_mac_asm!(tmp_mac.as_mut_ptr(), p);       // tmp = dst
        copy_mac_asm!(p, p.add(6));                    // dst = src
        copy_mac_asm!(p.add(6), tmp_mac.as_ptr());    // src = tmp
    }

    Ok(xdp_action::XDP_TX)
}

// ── IPv6 Processing ─────────────────────────────────────────────────

#[inline(always)]
fn process_v6(ctx: &XdpContext, l3_offset: usize, vlan_id: u16) -> Result<u32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr)
        .ok_or(())?;

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
    let pkt_len = ctx.data_end().saturating_sub(ctx.data()) as u64;

    let svc_idx = service_key_index(&key);
    let (backend_id, backend) = match select_backend(svc_config, src_ip_folded, svc_idx) {
        Some(b) => b,
        None => {
            increment_metric(LB_METRIC_PACKETS_NO_BACKEND);
            emit_event(
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

    let mut old_dst_addr = [0u8; 16];
    unsafe {
        let src = (ipv6hdr_mut as *const u8).add(24);
        copy_16b_asm!(old_dst_addr.as_mut_ptr(), src);
    }
    let old_dst_port = unsafe { (*l4hdr_mut).dst_port };
    let new_dst_port = backend.port.to_be();

    if backend.is_ipv6 == 1 {
        // Rewrite 128-bit destination address via inline asm to avoid memcpy.
        let new_addr = u32x4_to_ipv6_bytes(&backend.addr_v6);
        unsafe {
            let dst = (ipv6hdr_mut as *mut u8).add(24); // dst_addr offset in Ipv6Hdr
            copy_16b_asm!(dst, new_addr.as_ptr());
        }

        unsafe {
            (*l4hdr_mut).dst_port = new_dst_port;
        }

        // IPv6 has no IP checksum, but L4 pseudo-header includes addresses.
        // Update L4 checksum for both address and port change.
        update_l4_checksum_v6_dnat(
            ctx,
            l4_offset,
            next_hdr,
            &old_dst_addr,
            &new_addr,
            old_dst_port,
            new_dst_port,
        );
    } else {
        // IPv4 backend with IPv6 packet: only port changes
        unsafe {
            (*l4hdr_mut).dst_port = new_dst_port;
        }

        // IPv6 has no IP checksum, but L4 pseudo-header checksum needs update
        update_l4_checksum_port_only(ctx, l4_offset, next_hdr, old_dst_port, new_dst_port);
    }

    increment_metric(LB_METRIC_PACKETS_FORWARDED);
    add_metric(LB_METRIC_BYTES_FORWARDED, pkt_len);

    emit_event(
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        next_hdr,
        LB_ACTION_FORWARD,
        FLAG_IPV6,
        vlan_id,
    );

    // Check MTU before forwarding
    let mut mtu: u32 = 0;
    let mtu_ret = unsafe {
        bpf_check_mtu(ctx.ctx as *mut _, 0, &mut mtu as *mut u32, 0, 0)
    };
    if mtu_ret != 0 {
        increment_metric(LB_METRIC_MTU_EXCEEDED);
        return Ok(xdp_action::XDP_DROP);
    }

    // DevMap redirect first, MAC swap + XDP_TX fallback
    if LB_DEVMAP.redirect(backend_id, 0).is_ok() {
        return Ok(xdp_action::XDP_REDIRECT);
    }

    let ethhdr_mut: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let mut tmp_mac = [0u8; 6];
    unsafe {
        let p = ethhdr_mut as *mut u8;
        copy_mac_asm!(tmp_mac.as_mut_ptr(), p);
        copy_mac_asm!(p, p.add(6));
        copy_mac_asm!(p.add(6), tmp_mac.as_ptr());
    }

    Ok(xdp_action::XDP_TX)
}

// ── Backend Selection ───────────────────────────────────────────────

/// Select a healthy backend from the V2 service config.
///
/// Backends are stored globally in `LB_BACKENDS` at IDs
/// `svc.backend_start_id..svc.backend_start_id + svc.backend_count`.
/// The algorithm selects a starting offset, then probes linearly for a healthy backend.
#[inline(always)]
fn select_backend(
    svc: &LbServiceConfigV2,
    src_ip: u32,
    svc_index: u32,
) -> Option<(u32, &LbBackendEntry)> {
    let count = svc.backend_count as usize;
    if count == 0 {
        return None;
    }

    // Clamp to verifier-friendly bound
    let count = if count > MAX_BACKENDS_PER_SVC {
        MAX_BACKENDS_PER_SVC
    } else {
        count
    };

    let start_idx = match svc.algorithm {
        LB_ALG_ROUND_ROBIN => {
            let rr_ptr = LB_RR_STATE.get_ptr_mut(svc_index)?;
            let rr = unsafe { *rr_ptr };
            unsafe {
                *rr_ptr = rr.wrapping_add(1);
            }
            rr as usize
        }
        LB_ALG_IP_HASH => fnv1a(src_ip) as usize,
        LB_ALG_WEIGHTED => {
            let rr_ptr = LB_RR_STATE.get_ptr_mut(svc_index)?;
            let rr = unsafe { *rr_ptr };
            unsafe {
                *rr_ptr = rr.wrapping_add(1);
            }
            (rr ^ src_ip) as usize
        }
        // LeastConn falls back to RoundRobin in eBPF
        _ => {
            let rr_ptr = LB_RR_STATE.get_ptr_mut(svc_index)?;
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
        if idx >= MAX_BACKENDS_PER_SVC {
            i += 1;
            continue;
        }
        let backend_id = svc.backend_start_id + idx as u32;
        if let Some(be) = unsafe { LB_BACKENDS.get(&backend_id) } {
            if be.healthy == 1 {
                return Some((backend_id, be));
            }
        }
        i += 1;
    }

    None
}

/// Derive a per-service index from a `LbServiceKey` for round-robin state lookup.
/// Maps the (protocol, port) pair to an index in `0..MAX_LB_SERVICES`.
#[inline(always)]
fn service_key_index(key: &LbServiceKey) -> u32 {
    let combined = (key.protocol as u32) << 16 | (key.port as u32);
    fnv1a(combined) % MAX_LB_SERVICES
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
        let mut csum = !u32::from(u16::from_be_bytes((*ipv4hdr).check));
        // Subtract old, add new (32-bit words, split into 16-bit halves)
        csum = csum.wrapping_sub(old_val & 0xFFFF);
        csum = csum.wrapping_sub(old_val >> 16);
        csum = csum.wrapping_add(new_val & 0xFFFF);
        csum = csum.wrapping_add(new_val >> 16);
        // Fold carry
        csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
        csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
        (*ipv4hdr).check = (!csum as u16).to_be_bytes();
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

/// Incremental TCP/UDP checksum update after IPv6 dst_addr + dst_port rewrite.
///
/// The L4 pseudo-header for IPv6 includes the full 128-bit source and destination
/// addresses. When DNAT rewrites the destination address, the checksum must account
/// for all 8 u16 words of the old and new address plus the port change.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn update_l4_checksum_v6_dnat(
    ctx: &XdpContext,
    l4_offset: usize,
    protocol: u8,
    old_addr: &[u8; 16],
    new_addr: &[u8; 16],
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

            // Address diff: 8 u16 words (128-bit address)
            let mut i = 0;
            while i < 16 {
                let old_word = u16::from_be_bytes([old_addr[i], old_addr[i + 1]]);
                let new_word = u16::from_be_bytes([new_addr[i], new_addr[i + 1]]);
                csum = csum.wrapping_sub(u32::from(old_word));
                csum = csum.wrapping_add(u32::from(new_word));
                i += 2;
            }

            // Port diff
            csum = csum.wrapping_sub(u32::from(u16::from_be(old_port)));
            csum = csum.wrapping_add(u32::from(u16::from_be(new_port)));

            // Fold carry
            csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
            csum = (csum & 0xFFFF).wrapping_add(csum >> 16);
            *csum_ptr = (!csum as u16).to_be();
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────
// ptr_at, ptr_at_mut, skip_ipv6_ext_headers imported from ebpf_helpers::xdp
// ipv6_addr_to_u32x4, u32x4_to_ipv6_bytes imported from ebpf_helpers::net

#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(LB_METRICS, index);
}

#[inline(always)]
fn add_metric(index: u32, value: u64) {
    add_metric!(LB_METRICS, index, value);
}

// ── Event Emission ──────────────────────────────────────────────────

#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    ringbuf_has_backpressure!(EVENTS)
}

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
        increment_metric(LB_METRIC_EVENTS_DROPPED);
        return;
    }

    let mut event = match EVENTS.reserve::<PacketEvent>(0) {
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
