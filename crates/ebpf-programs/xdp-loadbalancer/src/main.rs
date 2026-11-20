#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::bindings::{
    BPF_FIB_LKUP_RET_NO_NEIGH, BPF_FIB_LKUP_RET_SUCCESS, bpf_fib_lookup as BpfFibLookupParams,
};
use aya_ebpf::helpers::generated::{bpf_fib_lookup, bpf_loop, bpf_redirect};
use aya_ebpf::{
    bindings::xdp_action,
    btf_maps::{DevMap, HashMap, LruHashMap, PerCpuArray, RingBuf},
    helpers::{
        bpf_check_mtu, bpf_get_prandom_u32, bpf_get_smp_processor_id, bpf_ktime_get_boot_ns,
    },
    macros::{btf_map, xdp},
    programs::XdpContext,
};
use ebpf_common::{
    event::{FLAG_IPV6, FLAG_VLAN, PacketEvent},
    loadbalancer::{
        BackendMac, EVENT_TYPE_LB, LB_ACTION_FORWARD, LB_ACTION_NO_BACKEND, LB_ALG_IP_HASH,
        LB_ALG_LEAST_CONN, LB_ALG_MAGLEV, LB_ALG_ROUND_ROBIN, LB_ALG_WEIGHTED, LB_DEFAULT_FLOWS,
        LB_FAMILY_V4, LB_FAMILY_V6, LB_FLOW_COUNTED, LB_FLOW_UNCOUNTED, LB_MAX_BACKENDS_V2,
        LB_METRIC_BYTES_FORWARDED, LB_METRIC_COUNT, LB_METRIC_EVENTS_DROPPED,
        LB_METRIC_MTU_EXCEEDED, LB_METRIC_PACKETS_FORWARDED, LB_METRIC_PACKETS_NO_BACKEND,
        LB_METRIC_TOTAL_SEEN, LB_MODE_L2DSR, LbBackendEntry, LbFlow, LbFlowKey, LbServiceConfigV2,
        LbServiceKey, MAGLEV_EMPTY, MAGLEV_RING_SIZE, MAX_LB_BACKEND_MAC, MAX_LB_BACKENDS_TOTAL,
        MAX_LB_SERVICES, MAX_MAGLEV_SERVICES, MaglevLookup, lb_fnv1a_u32, lb_service_index,
    },
};
use ebpf_helpers::kfuncs::{xdp_rx_hash, xdp_rx_timestamp};
use ebpf_helpers::net::{
    ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP, PROTO_UDP, ipv6_addr_to_u32x4,
    u32x4_to_ipv6_bytes,
};
use ebpf_helpers::parse_vlan_tags;
use ebpf_helpers::ringbuf::{avail_data, submit_flags};
use ebpf_helpers::trace::{self, NO_RULE, reason, stage};
use ebpf_helpers::xdp::{ptr_at, ptr_at_mut, skip_ipv6_ext_headers};
use ebpf_helpers::{
    add_metric, copy_16b_asm, copy_mac_asm, opaque_usize, ringbuf_has_backpressure,
};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.

/// Address family for the FIB lookup.
const FIB_AF_INET: u8 = 2;
const FIB_AF_INET6: u8 = 10;

/// Maximum backends per service (verifier bound for iteration).
const MAX_BACKENDS_PER_SVC: usize = LB_MAX_BACKENDS_V2 as usize;

// ── Inline program-specific header types ────────────────────────────

#[repr(C)]
struct TcpUdpHdr {
    src_port: u16,
    dst_port: u16,
}

/// The first fourteen bytes of a TCP header: enough to reach the flags.
#[repr(C)]
struct TcpHead {
    ports: [u16; 2],
    seq: u32,
    ack: u32,
    data_offset: u8,
    flags: u8,
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

// ── eBPF Maps ───────────────────────────────────────────────────────

/// Service lookup: (protocol, port) → compact service config (V2).
#[btf_map]
static LB_SERVICES: HashMap<LbServiceKey, LbServiceConfigV2, { MAX_LB_SERVICES as usize }> =
    HashMap::new();

/// Global backend pool: backend_id → backend entry.
#[btf_map]
static LB_BACKENDS: HashMap<u32, LbBackendEntry, { MAX_LB_BACKENDS_TOTAL as usize }> =
    HashMap::new();

/// Per-service round-robin state (index 0..4095).
#[btf_map]
static LB_RR_STATE: PerCpuArray<u32, { MAX_LB_SERVICES as usize }> = PerCpuArray::new();

/// Per-service Maglev lookup ring: svc_index → precomputed permutation.
/// Written by userspace (pure domain table generator), rebuilt only on
/// healthy-backend-set change. Read with a single O(1) index - no
/// per-packet state write - giving consistent flow pinning across nodes.
#[btf_map]
static LB_MAGLEV: HashMap<u32, MaglevLookup, { MAX_MAGLEV_SERVICES as usize }> = HashMap::new();

/// Connections in flight through the load balancer: the backend each one
/// was balanced to on its first packet, so every later packet of the
/// connection reaches the same backend. Sized at load from
/// `loadbalancer.max_flows`; past it the kernel evicts the least recently
/// used flow, whose next packet is balanced afresh.
#[btf_map]
static LB_FLOWS: LruHashMap<LbFlowKey, LbFlow, { LB_DEFAULT_FLOWS as usize }> = LruHashMap::new();

/// Where a DNAT-forwarded flow's replies must appear to come from, keyed
/// by the reply's own 5-tuple (backend to client). A backend answers from
/// its own address and port; the client is waiting on the service's, so a
/// reply passing back through this node has its source put back before it
/// is routed on. Sized at load like `LB_FLOWS`, and like it an LRU.
#[btf_map]
static LB_REVERSE: LruHashMap<LbFlowKey, LbReverse, { LB_DEFAULT_FLOWS as usize }> =
    LruHashMap::new();

/// The address and port a client sent a load-balanced flow to.
#[repr(C)]
#[derive(Clone, Copy)]
struct LbReverse {
    /// The service address the client used, in the packet's word layout.
    addr: [u32; 4],
    /// The service port, host order.
    port: u16,
    _pad: [u8; 6],
}

/// Open TCP connections per backend, read by least-connections. Userspace
/// creates one entry per backend at zero and recounts every entry from
/// `LB_FLOWS` on a timer, which repairs what an evicted flow or a reload
/// left behind; the program only moves the count of an entry that exists.
/// Signed, so a close seen after a recount reset it can go below zero for
/// a moment without making the backend look full.
#[btf_map]
static LB_BACKEND_CONNS: HashMap<u32, i64, { MAX_LB_BACKENDS_TOTAL as usize }> = HashMap::new();

/// Per-CPU metrics.
#[btf_map]
static LB_METRICS: PerCpuArray<u64, { LB_METRIC_COUNT as usize }> = PerCpuArray::new();

/// DevMap for high-performance XDP redirect to backend interfaces.
/// Userspace populates this with backend ifindex values. A DNAT packet
/// whose next hop leaves by another interface is redirected through the
/// entry for its backend, or through `bpf_redirect` when none exists.
#[btf_map]
static LB_DEVMAP: DevMap<256> = DevMap::new();

/// Resolved backend MAC addresses for L2 DSR: backend_id → MAC.
/// Populated by userspace neighbor/ARP/ND resolution in the loader
/// adapter. Read only when a service is in `LB_MODE_L2DSR`; an absent
/// entry makes the data plane fall back to the DNAT path unchanged.
#[btf_map]
static LB_BACKEND_MAC: HashMap<u32, BackendMac, { MAX_LB_BACKEND_MAC as usize }> = HashMap::new();

/// Per-CPU scratch for the FIB lookup parameters. A 64-byte struct zeroed on
/// the stack costs the verifier an unrolled memset on every path; a scratch
/// map costs one lookup.
#[btf_map]
static FIB_PARAMS: PerCpuArray<BpfFibLookupParams, 1> = PerCpuArray::new();

/// Kernel->userspace event ring buffer, 1 MiB: about 7,500 packet events
/// before backpressure refuses new ones (sizing in `ebpf_helpers::ringbuf`).
#[btf_map]
static EVENTS: RingBuf<PacketEvent, { 256 * 4096 }> = RingBuf::new();

// ── Entry Point ─────────────────────────────────────────────────────

#[xdp]
pub fn xdp_loadbalancer(ctx: XdpContext) -> u32 {
    let traced = trace::xdp(&ctx);
    increment_metric(traced, LB_METRIC_TOTAL_SEEN);
    // Capture the trusted XDP context pointer by value in the entry frame so
    // the `KF_TRUSTED_ARGS` kfuncs (conntrack lookup, RX-metadata) keep their
    // trusted arg#0 across outlined bpf-to-bpf calls. Reloading it from a
    // `&XdpContext` in a subprogram drops the trusted flag and the verifier
    // rejects the call with "arg#0 ... got scalar".
    let ctx_raw: *mut core::ffi::c_void = ctx.ctx.cast();
    let action = match try_xdp_loadbalancer(&ctx, ctx_raw) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    };
    // A packet sent on to a backend leaves rewritten; one addressed to no
    // service, or to a service with no healthy backend, passes untouched.
    let why = match action {
        xdp_action::XDP_PASS => reason::DEFAULT,
        xdp_action::XDP_DROP => reason::MALFORMED,
        _ => reason::REWRITE,
    };
    trace::xdp_record(&ctx, stage::LOADBALANCER, action as u8, why, NO_RULE);
    action
}

/// Whether this invocation is a trace, read from the raw context the entry
/// captured.
#[inline(always)]
fn is_traced(ctx_raw: *mut core::ffi::c_void) -> bool {
    trace::xdp(&XdpContext::new(ctx_raw.cast()))
}

#[inline(always)]
fn try_xdp_loadbalancer(ctx: &XdpContext, ctx_raw: *mut core::ffi::c_void) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    // 802.1Q / 802.1ad tags. The outer tag is the one carried onward: on a
    // QinQ frame that is the service provider's tag, which is what a policy
    // is written against, and the inner customer tag is left in the frame.
    let (vlan_id, _) = parse_vlan_tags!(ctx, ether_type, l3_offset);

    match ether_type {
        ETH_P_IP => process_v4(ctx, ctx_raw, l3_offset, vlan_id),
        ETH_P_IPV6 => process_v6(ctx, ctx_raw, l3_offset, vlan_id),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

// ── IPv4 Processing ─────────────────────────────────────────────────

#[inline(always)]
fn process_v4(
    ctx: &XdpContext,
    ctx_raw: *mut core::ffi::c_void,
    l3_offset: usize,
    vlan_id: u16,
) -> Result<u32, ()> {
    let traced = is_traced(ctx_raw);
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let proto = unsafe { (*ipv4hdr).proto() }.unwrap_or(IpProto::Reserved);
    let protocol = proto as u8;
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    if proto != IpProto::Tcp && proto != IpProto::Udp {
        return Ok(xdp_action::XDP_PASS);
    }

    let l4hdr: *const TcpUdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let dst_port = u16::from_be(unsafe { (*l4hdr).dst_port });
    let src_port = u16::from_be(unsafe { (*l4hdr).src_port });

    let src_addr_raw = unsafe { (*ipv4hdr).src_addr };
    let dst_addr_raw = unsafe { (*ipv4hdr).dst_addr };

    // The service bound to this destination address first, then the one
    // bound to every address on this port.
    let key = LbServiceKey {
        protocol,
        family: LB_FAMILY_V4,
        port: dst_port,
        addr: [u32::from_be_bytes(dst_addr_raw), 0, 0, 0],
    };
    let Some((key, svc_config)) = lookup_service(key) else {
        // Not a load-balanced service: perhaps a backend's reply.
        let reply = LbFlowKey {
            src_addr: [u32::from_ne_bytes(src_addr_raw), 0, 0, 0],
            dst_addr: [u32::from_ne_bytes(dst_addr_raw), 0, 0, 0],
            src_port,
            dst_port,
            protocol,
            family: LB_FAMILY_V4,
            _pad: [0; 2],
        };
        return reverse_v4(ctx, l3_offset, l4_offset, &reply);
    };
    let src_ip = u32::from_be_bytes(src_addr_raw);
    let pkt_len = ctx.data_end().saturating_sub(ctx.data()) as u64;

    let src_addr = [u32::from_ne_bytes(src_addr_raw), 0, 0, 0];
    let dst_addr = [u32::from_ne_bytes(dst_addr_raw), 0, 0, 0];

    let flow = LbFlowKey {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        family: LB_FAMILY_V4,
        _pad: [0; 2],
    };
    let tcp_flags = tcp_flags(ctx, l4_offset, protocol);
    let svc_idx = service_key_index(&key);
    let (backend_id, backend) =
        match flow_backend(ctx_raw, svc_config, &flow, tcp_flags, src_ip, svc_idx) {
            Some(b) => b,
            None => {
                increment_metric(traced, LB_METRIC_PACKETS_NO_BACKEND);
                emit_event(
                    ctx_raw,
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

    // ── L2 DSR forwarding mode ──────────────────────────────────
    // Rewrite only the destination MAC; dst IP stays the VIP and the
    // L3/L4 checksums are untouched. The backend (VIP on loopback)
    // replies directly to the client. If the backend MAC is not yet
    // resolved, fall through to the DNAT path unchanged (no regression).
    if svc_config.mode == LB_MODE_L2DSR {
        if let Some(action) = try_dsr_forward(
            ctx, ctx_raw, backend_id, &src_addr, &dst_addr, src_port, dst_port, protocol, 0,
            vlan_id, pkt_len,
        ) {
            return Ok(action);
        }
    }

    // ── DNAT rewrite ────────────────────────────────────────────
    remember_reply(
        traced,
        &flow,
        [u32::from_ne_bytes(backend.addr_v4.to_be_bytes()), 0, 0, 0],
        backend.port,
    );
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
    increment_metric(traced, LB_METRIC_PACKETS_FORWARDED);
    add_metric(traced, LB_METRIC_BYTES_FORWARDED, pkt_len);

    emit_event(
        ctx_raw,
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
    let mtu_ret = unsafe { bpf_check_mtu(ctx.ctx as *mut _, 0, &mut mtu as *mut u32, 0, 0) };
    // Only drop on a genuine MTU violation (positive BPF_MTU_CHK_RET_*); a
    // negative return is a helper error → pass (NFR15), otherwise forwarded
    // IPv6 transit packets get silently blackholed.
    if mtu_ret > 0 {
        increment_metric(traced, LB_METRIC_MTU_EXCEEDED);
        return Ok(xdp_action::XDP_DROP);
    }

    // Route the rewritten packet: the next hop towards the backend decides
    // both MACs and the interface it leaves by.
    let dst = [u32::from_ne_bytes(new_dst_ip.to_be_bytes()), 0, 0, 0];
    forward_to_backend(ctx, backend_id, FIB_AF_INET, src_addr, dst, protocol)
}

// ── IPv6 Processing ─────────────────────────────────────────────────

#[inline(always)]
fn process_v6(
    ctx: &XdpContext,
    ctx_raw: *mut core::ffi::c_void,
    l3_offset: usize,
    vlan_id: u16,
) -> Result<u32, ()> {
    let traced = is_traced(ctx_raw);
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) =
        skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr).ok_or(())?;

    if next_hdr != PROTO_TCP && next_hdr != PROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let l4hdr: *const TcpUdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let dst_port = u16::from_be(unsafe { (*l4hdr).dst_port });
    let src_port = u16::from_be(unsafe { (*l4hdr).src_port });

    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });

    let key = LbServiceKey {
        protocol: next_hdr,
        family: LB_FAMILY_V6,
        port: dst_port,
        addr: dst_addr,
    };
    let Some((key, svc_config)) = lookup_service(key) else {
        // Not a load-balanced service: perhaps a backend's reply.
        let reply = LbFlowKey {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol: next_hdr,
            family: LB_FAMILY_V6,
            _pad: [0; 2],
        };
        return reverse_v6(ctx, l3_offset, l4_offset, &reply);
    };

    // For IP hash, XOR-fold IPv6 src to u32
    let src_ip_folded = src_addr[0] ^ src_addr[1] ^ src_addr[2] ^ src_addr[3];
    let pkt_len = ctx.data_end().saturating_sub(ctx.data()) as u64;

    let flow = LbFlowKey {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol: next_hdr,
        family: LB_FAMILY_V6,
        _pad: [0; 2],
    };
    let tcp_flags = tcp_flags(ctx, l4_offset, next_hdr);
    let svc_idx = service_key_index(&key);
    let (backend_id, backend) = match flow_backend(
        ctx_raw,
        svc_config,
        &flow,
        tcp_flags,
        src_ip_folded,
        svc_idx,
    ) {
        Some(b) => b,
        None => {
            increment_metric(traced, LB_METRIC_PACKETS_NO_BACKEND);
            emit_event(
                ctx_raw,
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

    // ── L2 DSR forwarding mode (IPv6) ───────────────────────────
    // Rewrite only the destination MAC; dst IP stays the VIP and the
    // L4 checksum is untouched. Fall through to DNAT if MAC unresolved.
    if svc_config.mode == LB_MODE_L2DSR {
        if let Some(action) = try_dsr_forward(
            ctx, ctx_raw, backend_id, &src_addr, &dst_addr, src_port, dst_port, next_hdr,
            FLAG_IPV6, vlan_id, pkt_len,
        ) {
            return Ok(action);
        }
    }

    // ── DNAT rewrite (IPv6) ─────────────────────────────────────
    // An IPv4 backend behind an IPv6 service keeps the packet's address and
    // only takes the port, so its replies come back from that address.
    let reply_from = if backend.is_ipv6 == 1 {
        backend.addr_v6
    } else {
        dst_addr
    };
    remember_reply(traced, &flow, reply_from, backend.port);
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

    increment_metric(traced, LB_METRIC_PACKETS_FORWARDED);
    add_metric(traced, LB_METRIC_BYTES_FORWARDED, pkt_len);

    emit_event(
        ctx_raw,
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
    let mtu_ret = unsafe { bpf_check_mtu(ctx.ctx as *mut _, 0, &mut mtu as *mut u32, 0, 0) };
    // Only drop on a genuine MTU violation (positive BPF_MTU_CHK_RET_*); a
    // negative return is a helper error → pass (NFR15), otherwise forwarded
    // IPv6 transit packets get silently blackholed.
    if mtu_ret > 0 {
        increment_metric(traced, LB_METRIC_MTU_EXCEEDED);
        return Ok(xdp_action::XDP_DROP);
    }

    // Route the rewritten packet from the addresses now in the header, so
    // the lookup sees the backend rather than the VIP.
    let ipv6hdr_now: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    unsafe {
        let base = ipv6hdr_now as *const u8;
        copy_16b_asm!(src_bytes.as_mut_ptr(), base.add(8));
        copy_16b_asm!(dst_bytes.as_mut_ptr(), base.add(24));
    }
    forward_to_backend(
        ctx,
        backend_id,
        FIB_AF_INET6,
        wire_words(&src_bytes),
        wire_words(&dst_bytes),
        next_hdr,
    )
}

// ── Replies to DNAT-forwarded flows ─────────────────────────────────

/// Record where the replies to a flow forwarded to `backend_addr`
/// (packet word layout) and `backend_port` (host order) will come from.
///
/// Written only when absent or stale, so a flow costs one lookup per
/// packet and one write when it starts or moves. A traced packet writes
/// nothing.
#[inline(always)]
fn remember_reply(traced: bool, flow: &LbFlowKey, backend_addr: [u32; 4], backend_port: u16) {
    if traced {
        return;
    }
    let reply = LbFlowKey {
        src_addr: backend_addr,
        dst_addr: flow.src_addr,
        src_port: backend_port,
        dst_port: flow.src_port,
        protocol: flow.protocol,
        family: flow.family,
        _pad: [0; 2],
    };
    if let Some(known) = unsafe { LB_REVERSE.get(&reply) } {
        if known.port == flow.dst_port && known.addr == flow.dst_addr {
            return;
        }
    }
    let original = LbReverse {
        addr: flow.dst_addr,
        port: flow.dst_port,
        _pad: [0; 6],
    };
    let _ = LB_REVERSE.insert(&reply, &original, 0);
}

/// Put a backend's IPv4 reply back in the service's name and route it on;
/// any other packet passes untouched.
#[inline(always)]
fn reverse_v4(
    ctx: &XdpContext,
    l3_offset: usize,
    l4_offset: usize,
    reply: &LbFlowKey,
) -> Result<u32, ()> {
    let Some(original) = (unsafe { LB_REVERSE.get(reply) }) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let ipv4hdr_mut: *mut Ipv4Hdr = unsafe { ptr_at_mut(ctx, l3_offset)? };
    let l4hdr_mut: *mut TcpUdpHdr = unsafe { ptr_at_mut(ctx, l4_offset)? };

    let old_src_ip = u32::from_be_bytes(unsafe { (*ipv4hdr_mut).src_addr });
    let new_src_ip = u32::from_be_bytes(original.addr[0].to_ne_bytes());
    let old_src_port = unsafe { (*l4hdr_mut).src_port };
    let new_src_port = original.port.to_be();

    unsafe {
        (*ipv4hdr_mut).src_addr = new_src_ip.to_be_bytes();
        (*l4hdr_mut).src_port = new_src_port;
    }
    update_ip_checksum(ipv4hdr_mut, old_src_ip, new_src_ip);
    update_l4_checksum_v4(
        ctx,
        l4_offset,
        reply.protocol,
        old_src_ip,
        new_src_ip,
        old_src_port,
        new_src_port,
    );
    forward_to_backend(
        ctx,
        NO_DEVMAP_SLOT,
        FIB_AF_INET,
        original.addr,
        reply.dst_addr,
        reply.protocol,
    )
}

/// Put a backend's IPv6 reply back in the service's name and route it on;
/// any other packet passes untouched.
#[inline(always)]
fn reverse_v6(
    ctx: &XdpContext,
    l3_offset: usize,
    l4_offset: usize,
    reply: &LbFlowKey,
) -> Result<u32, ()> {
    let Some(original) = (unsafe { LB_REVERSE.get(reply) }) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let ipv6hdr_mut: *mut Ipv6Hdr = unsafe { ptr_at_mut(ctx, l3_offset)? };
    let l4hdr_mut: *mut TcpUdpHdr = unsafe { ptr_at_mut(ctx, l4_offset)? };

    let mut old_src = [0u8; 16];
    unsafe {
        let base = ipv6hdr_mut as *mut u8;
        copy_16b_asm!(old_src.as_mut_ptr(), base.add(8));
    }
    let new_src = u32x4_to_ipv6_bytes(&original.addr);
    let old_src_port = unsafe { (*l4hdr_mut).src_port };
    let new_src_port = original.port.to_be();
    unsafe {
        let base = ipv6hdr_mut as *mut u8;
        copy_16b_asm!(base.add(8), new_src.as_ptr());
        (*l4hdr_mut).src_port = new_src_port;
    }
    update_l4_checksum_v6_dnat(
        ctx,
        l4_offset,
        reply.protocol,
        &old_src,
        &new_src,
        old_src_port,
        new_src_port,
    );
    forward_to_backend(
        ctx,
        NO_DEVMAP_SLOT,
        FIB_AF_INET6,
        wire_words(&new_src),
        wire_words(&u32x4_to_ipv6_bytes(&reply.dst_addr)),
        reply.protocol,
    )
}

// ── L2 DSR Forwarding ───────────────────────────────────────────────

/// L2 Direct Server Return: rewrite ONLY the destination Ethernet
/// address to the resolved backend MAC and L2-forward the packet. The
/// destination IP stays the VIP and no L3/L4 checksum is recomputed.
///
/// Returns `Some(action)` once the packet is handled (REDIRECT / TX, or
/// DROP on MTU overflow). Returns `None` when the backend MAC has not
/// been resolved yet, so the caller falls back to the DNAT path.
#[inline(always)]
#[allow(clippy::too_many_arguments)]
fn try_dsr_forward(
    ctx: &XdpContext,
    ctx_raw: *mut core::ffi::c_void,
    backend_id: u32,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
    pkt_len: u64,
) -> Option<u32> {
    let traced = is_traced(ctx_raw);
    // Resolve backend MAC; absent → caller falls back to DNAT.
    let mac = unsafe { LB_BACKEND_MAC.get(&backend_id) }?.mac;

    // Rewrite only the Ethernet header. dst IP = VIP, L3/L4 checksums
    // untouched. The frame was addressed to this interface, so its old
    // destination is our own MAC and becomes the source: leaving the
    // client router's MAC there would teach the switch that the router
    // sits behind this port. copy_mac_asm! prevents LLVM memcpy outlining
    // with packet pointers.
    let ethhdr_mut: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0).ok()? };
    unsafe {
        let p = ethhdr_mut as *mut u8;
        copy_mac_asm!(p.add(6), p);
        copy_mac_asm!(p, mac.as_ptr());
    }

    increment_metric(traced, LB_METRIC_PACKETS_FORWARDED);
    add_metric(traced, LB_METRIC_BYTES_FORWARDED, pkt_len);
    emit_event(
        ctx_raw,
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        LB_ACTION_FORWARD,
        flags,
        vlan_id,
    );

    // Check MTU before forwarding to avoid silent fragmentation.
    let mut mtu: u32 = 0;
    let mtu_ret = unsafe { bpf_check_mtu(ctx.ctx as *mut _, 0, &mut mtu as *mut u32, 0, 0) };
    // Only drop on a genuine MTU violation (positive BPF_MTU_CHK_RET_*); a
    // negative return is a helper error → pass (NFR15), otherwise forwarded
    // IPv6 transit packets get silently blackholed.
    if mtu_ret > 0 {
        increment_metric(traced, LB_METRIC_MTU_EXCEEDED);
        return Some(xdp_action::XDP_DROP);
    }

    // DevMap redirect first (wire-speed), MAC-rewrite + XDP_TX fallback.
    if LB_DEVMAP.redirect(backend_id, 0).is_ok() {
        return Some(xdp_action::XDP_REDIRECT);
    }
    Some(xdp_action::XDP_TX)
}

// ── DNAT Forwarding ─────────────────────────────────────────────────

/// A `forward_to_backend` key no backend holds: the packet leaves by the
/// interface the route names, not by a backend's `LB_DEVMAP` slot.
const NO_DEVMAP_SLOT: u32 = u32::MAX;

/// Send a DNAT-rewritten packet to its backend.
///
/// The destination IP now names the backend, but the Ethernet header
/// still carries the frame that reached us: our own MAC as destination
/// and the client-side router as source. `bpf_fib_lookup` with neighbour
/// resolution answers the three things the rewrite needs - the interface
/// the backend is reached by, the next hop's MAC and the MAC of that
/// interface - so both addresses are written before the packet leaves.
///
/// - Next hop on the ingress interface: `XDP_TX`.
/// - Next hop elsewhere: the backend's `LB_DEVMAP` entry, or
///   `bpf_redirect` to the interface the FIB named.
/// - Route known but neighbour not yet resolved: `XDP_PASS`, so the stack
///   forwards this packet and resolves the neighbour for the next one.
/// - No route: the frame is bounced back to the router it came from
///   (MAC swap + `XDP_TX`), which only reaches a backend that router can
///   route to.
///
/// `src`/`dst` carry the addresses in wire order: word 0 alone for IPv4,
/// all four for IPv6. The scratch buffer is per-CPU and reused, so every
/// field the kernel reads is written on each call.
#[inline(always)]
fn forward_to_backend(
    ctx: &XdpContext,
    backend_id: u32,
    family: u8,
    src: [u32; 4],
    dst: [u32; 4],
    l4_protocol: u8,
) -> Result<u32, ()> {
    let params = FIB_PARAMS.get_ptr_mut(0).ok_or(())?;
    let ingress = ctx.ingress_ifindex() as u32;

    unsafe {
        (*params).family = family;
        (*params).l4_protocol = l4_protocol;
        (*params).sport = 0;
        (*params).dport = 0;
        // tot_len 0: the MTU was already checked by bpf_check_mtu.
        (*params).__bindgen_anon_1.tot_len = 0;
        // The kernel writes rt_metric back into this union: clear all four
        // bytes so a stale metric is not read as this packet's tos/flowinfo.
        (*params).__bindgen_anon_2.flowinfo = 0;
        if family == FIB_AF_INET6 {
            (*params).__bindgen_anon_3.ipv6_src = src;
            (*params).__bindgen_anon_4.ipv6_dst = dst;
        } else {
            (*params).__bindgen_anon_3.ipv4_src = src[0];
            (*params).__bindgen_anon_4.ipv4_dst = dst[0];
        }
        (*params).ifindex = ingress;
    }

    let rc = unsafe {
        bpf_fib_lookup(
            ctx.ctx.cast::<core::ffi::c_void>(),
            params,
            core::mem::size_of::<BpfFibLookupParams>() as i32,
            0,
        )
    };

    let ethhdr_mut: *mut EthHdr = unsafe { ptr_at_mut(ctx, 0)? };
    let p = ethhdr_mut as *mut u8;

    if rc == BPF_FIB_LKUP_RET_SUCCESS as i64 {
        let egress = unsafe { (*params).ifindex };
        unsafe {
            copy_mac_asm!(p, (*params).__bindgen_anon_6.__bindgen_anon_2.dmac.as_ptr());
            copy_mac_asm!(
                p.add(6),
                (*params).__bindgen_anon_6.__bindgen_anon_2.smac.as_ptr()
            );
        }
        if egress == ingress {
            return Ok(xdp_action::XDP_TX);
        }
        if LB_DEVMAP.redirect(backend_id, 0).is_ok() {
            return Ok(xdp_action::XDP_REDIRECT);
        }
        return Ok(unsafe { bpf_redirect(egress, 0) } as u32);
    }

    if rc == BPF_FIB_LKUP_RET_NO_NEIGH as i64 {
        return Ok(xdp_action::XDP_PASS);
    }

    let mut tmp_mac = [0u8; 6];
    unsafe {
        copy_mac_asm!(tmp_mac.as_mut_ptr(), p); // tmp = dst
        copy_mac_asm!(p, p.add(6)); // dst = src
        copy_mac_asm!(p.add(6), tmp_mac.as_ptr()); // src = tmp
    }
    Ok(xdp_action::XDP_TX)
}

/// Reinterpret 16 header bytes as four words with their wire byte order
/// preserved - what `bpf_fib_lookup` expects for `ipv6_src`/`ipv6_dst`.
#[inline(always)]
fn wire_words(bytes: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    ]
}

// ── Backend Selection ───────────────────────────────────────────────

/// The TCP flags of a TCP packet, zero for anything else or a header too
/// short to carry them.
#[inline(always)]
fn tcp_flags(ctx: &XdpContext, l4_offset: usize, protocol: u8) -> u8 {
    if protocol != PROTO_TCP {
        return 0;
    }
    match unsafe { ptr_at::<TcpHead>(ctx, l4_offset) } {
        Ok(h) => unsafe { (*h).flags },
        Err(()) => 0,
    }
}

/// The backend a packet of this flow goes to.
///
/// A flow already in `LB_FLOWS` keeps its backend while that backend is
/// still one of the service's and healthy. A new flow, a flow whose
/// backend left or failed, and a TCP SYN on a connection seen closing (a
/// client reusing its port) are balanced by the service's algorithm and
/// recorded. A TCP connection counts against its backend from its first
/// packet until its first FIN or RST; UDP flows keep their backend but
/// count nowhere.
///
/// A traced packet is balanced like any other and changes nothing.
#[inline(always)]
fn flow_backend(
    ctx_raw: *mut core::ffi::c_void,
    svc: &LbServiceConfigV2,
    flow: &LbFlowKey,
    tcp_flags: u8,
    src_ip: u32,
    svc_index: u32,
) -> Option<(u32, &'static LbBackendEntry)> {
    let traced = is_traced(ctx_raw);
    let is_tcp = flow.protocol == PROTO_TCP;
    let closing = is_tcp && tcp_flags & (TCP_FIN | TCP_RST) != 0;
    let opening = is_tcp && tcp_flags & (TCP_SYN | TCP_ACK) == TCP_SYN;

    if let Some(entry) = LB_FLOWS.get_ptr_mut(flow) {
        let backend_id = unsafe { (*entry).backend_id };
        let state = unsafe { core::ptr::addr_of_mut!((*entry).state) };
        let counted = unsafe { core::ptr::read_volatile(state) } == LB_FLOW_COUNTED;
        if counted || !opening {
            if let Some(be) = service_backend(svc, backend_id) {
                if closing && !traced {
                    uncount(state, backend_id);
                }
                return Some((backend_id, be));
            }
        }
        // The flow leaves this backend: it stops counting there.
        if !traced {
            uncount(state, backend_id);
        }
    }

    let (backend_id, be) = select_backend(ctx_raw, svc, src_ip, svc_index)?;
    if traced {
        return Some((backend_id, be));
    }
    let counts = is_tcp && !closing;
    let entry = LbFlow {
        backend_id,
        _pad: 0,
        state: if counts {
            LB_FLOW_COUNTED
        } else {
            LB_FLOW_UNCOUNTED
        },
    };
    if LB_FLOWS.insert(flow, &entry, 0).is_ok() && counts {
        add_conns(backend_id, 1);
    }
    Some((backend_id, be))
}

/// Stop counting a flow against its backend, once however many CPUs see
/// it close at the same time.
#[inline(always)]
fn uncount(state: *mut u64, backend_id: u32) {
    // SAFETY: `state` is the state word of a live `LB_FLOWS` value.
    let was = unsafe { exchange(state, LB_FLOW_UNCOUNTED) };
    if was == LB_FLOW_COUNTED {
        add_conns(backend_id, -1);
    }
}

/// Move a backend's open-connection count, when userspace created its
/// entry.
#[inline(always)]
fn add_conns(backend_id: u32, delta: i64) {
    if let Some(n) = LB_BACKEND_CONNS.get_ptr_mut(&backend_id) {
        // SAFETY: `n` is a live, aligned map value.
        unsafe { atomic_add(n.cast::<u64>(), delta as u64) };
    }
}

/// Add `value` to the word at `at` with the instruction's own lock, so two
/// CPUs adding to one shared map value both land. `core`'s atomics offer no
/// read-modify-write on this target, the instruction itself does.
///
/// # Safety
/// `at` points at a live, aligned `u64` of a map value.
#[inline(always)]
unsafe fn atomic_add(at: *mut u64, value: u64) {
    #[cfg(target_arch = "bpf")]
    // SAFETY: the caller hands a live aligned word; the instruction reads
    // and writes only that word.
    unsafe {
        core::arch::asm!(
            "lock *(u64 *)({at} + 0) += {value}",
            at = in(reg) at,
            value = in(reg) value,
            options(nostack),
        );
    }
    #[cfg(not(target_arch = "bpf"))]
    // SAFETY: the caller hands a live aligned word.
    unsafe {
        *at = (*at).wrapping_add(value);
    }
}

/// Write `value` to the word at `at` and return what it held, in one
/// locked instruction.
///
/// # Safety
/// `at` points at a live, aligned `u64` of a map value.
#[inline(always)]
unsafe fn exchange(at: *mut u64, value: u64) -> u64 {
    #[cfg(target_arch = "bpf")]
    {
        let mut v = value;
        // SAFETY: the caller hands a live aligned word; the instruction
        // reads and writes only that word.
        unsafe {
            core::arch::asm!(
                "{v} = xchg_64({at} + 0, {v})",
                at = in(reg) at,
                v = inout(reg) v,
                options(nostack),
            );
        }
        v
    }
    #[cfg(not(target_arch = "bpf"))]
    // SAFETY: the caller hands a live aligned word.
    unsafe {
        core::ptr::replace(at, value)
    }
}

/// The backend at `backend_id` when it is one of this service's and
/// healthy.
#[inline(always)]
fn service_backend(svc: &LbServiceConfigV2, backend_id: u32) -> Option<&'static LbBackendEntry> {
    let first = svc.backend_start_id;
    if backend_id < first || backend_id - first >= u32::from(svc.backend_count) {
        return None;
    }
    let be = unsafe { LB_BACKENDS.get(&backend_id) }?;
    if be.healthy == 1 { Some(be) } else { None }
}

/// Select a healthy backend for a new flow.
///
/// Backends are stored globally in `LB_BACKENDS` at IDs
/// `svc.backend_start_id..svc.backend_start_id + svc.backend_count`.
/// Weighted and least-connections walk every healthy backend once; the
/// other algorithms pick a starting offset and probe linearly from it.
#[inline(always)]
fn select_backend(
    ctx_raw: *mut core::ffi::c_void,
    svc: &LbServiceConfigV2,
    src_ip: u32,
    svc_index: u32,
) -> Option<(u32, &'static LbBackendEntry)> {
    let traced = is_traced(ctx_raw);
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
        LB_ALG_ROUND_ROBIN => next_rr(traced, svc_index)? as usize,
        // Prefer NIC RSS hash when available (hardware-computed,
        // better distribution, zero CPU cost). Fall back to
        // software FNV-1a when the driver lacks RSS metadata.
        LB_ALG_IP_HASH => unsafe { xdp_rx_hash(ctx_raw.cast_const()) }
            .map(|(h, _)| h as usize)
            .unwrap_or_else(|| fnv1a(src_ip) as usize),
        LB_ALG_WEIGHTED => {
            let id = select_weighted(svc, count)?;
            return service_backend(svc, id).map(|be| (id, be));
        }
        LB_ALG_LEAST_CONN => {
            let offset = next_rr(traced, svc_index)? as usize;
            let id = select_least_conn(svc, count, offset)?;
            return service_backend(svc, id).map(|be| (id, be));
        }
        // Maglev: O(1) lookup into the precomputed permutation ring.
        // Deterministic software hash of the source IP (NOT the NIC RSS
        // hash) so every node maps a flow to the same slot - required
        // for L2 DSR / multi-node ECMP. The userspace table already
        // contains only healthy backend slots; the linear probe below
        // still covers a backend that went down between rebuilds.
        LB_ALG_MAGLEV => match unsafe { LB_MAGLEV.get(&svc_index) } {
            Some(tbl) => {
                // `% MAGLEV_RING_SIZE` provably yields a slot in
                // `[0, MAGLEV_RING_SIZE)`, but the ring size is prime so the
                // compiler proves the `if slot < MAGLEV_RING_SIZE` guard
                // redundant and elides it - leaving the verifier with the
                // unbounded modulo result and rejecting the `entries[slot]`
                // deref ("unbounded memory access"). Routing the slot through
                // a value barrier first turns the guard into a real runtime
                // branch the verifier uses to bound the index.
                let slot = opaque_usize((fnv1a(src_ip) as usize) % MAGLEV_RING_SIZE);
                if slot < MAGLEV_RING_SIZE {
                    let e = tbl.entries[slot];
                    if e == MAGLEV_EMPTY { 0 } else { e as usize }
                } else {
                    0
                }
            }
            // Table not synced yet - safe RR fallback.
            None => next_rr(traced, svc_index)? as usize,
        },
        _ => next_rr(traced, svc_index)? as usize,
    };

    // First healthy backend walking from the selected index.
    let id = Walk::new(svc, count, start_idx).run(first_healthy_step)?;
    service_backend(svc, id).map(|be| (id, be))
}

/// The service's round-robin position, moved on by one unless traced.
#[inline(always)]
fn next_rr(traced: bool, svc_index: u32) -> Option<u32> {
    let rr_ptr = LB_RR_STATE.get_ptr_mut(svc_index)?;
    let rr = unsafe { *rr_ptr };
    unsafe {
        *rr_ptr = rr.wrapping_add(live(traced));
    }
    Some(rr)
}

/// No backend picked yet.
const NONE_PICKED: u32 = u32::MAX;

/// What a selection walk carries from one backend to the next.
///
/// The weighted and least-connection walks keep a running total, a best
/// count and the backend picked so far, all different on every path; walked
/// inline over up to 256 backends the verifier could prune none of those paths
/// and gives up. Under `bpf_loop` it checks the step once, whatever the count.
#[repr(C)]
struct Walk {
    first: u32,
    count: u32,
    offset: u32,
    total: u32,
    picked: u32,
    fewest: i64,
}

impl Walk {
    fn new(svc: &LbServiceConfigV2, count: usize, offset: usize) -> Self {
        Self {
            first: svc.backend_start_id,
            count: count as u32,
            offset: offset as u32,
            total: 0,
            picked: NONE_PICKED,
            fewest: i64::MAX,
        }
    }

    fn run(mut self, step: extern "C" fn(u32, *mut core::ffi::c_void) -> i64) -> Option<u32> {
        // SAFETY: `step` is a static function of this program with the
        // callback signature `bpf_loop` expects, and the context is this walk,
        // on the stack for the whole call.
        unsafe {
            bpf_loop(
                self.count,
                step as *mut core::ffi::c_void,
                (&raw mut self).cast::<core::ffi::c_void>(),
                0,
            );
        }
        (self.picked != NONE_PICKED).then_some(self.picked)
    }
}

#[inline(never)]
extern "C" fn first_healthy_step(i: u32, walk: *mut core::ffi::c_void) -> i64 {
    // SAFETY: `bpf_loop` hands back the context `Walk::run` gave it.
    let walk = unsafe { &mut *walk.cast::<Walk>() };
    let Some(idx) = walk.offset.wrapping_add(i).checked_rem(walk.count) else {
        return 1;
    };
    let backend_id = walk.first.wrapping_add(idx);
    match unsafe { LB_BACKENDS.get(&backend_id) } {
        Some(be) if be.healthy == 1 => {
            walk.picked = backend_id;
            1
        }
        _ => 0,
    }
}

/// Weighted random pick in one pass: every healthy backend replaces the pick
/// so far with probability its weight over the running total.
#[inline(always)]
fn select_weighted(svc: &LbServiceConfigV2, count: usize) -> Option<u32> {
    Walk::new(svc, count, 0).run(weighted_step)
}

#[inline(never)]
extern "C" fn weighted_step(i: u32, walk: *mut core::ffi::c_void) -> i64 {
    // SAFETY: `bpf_loop` hands back the context `Walk::run` gave it.
    let walk = unsafe { &mut *walk.cast::<Walk>() };
    if i >= walk.count {
        return 1;
    }
    let backend_id = walk.first.wrapping_add(i);
    if let Some(be) = unsafe { LB_BACKENDS.get(&backend_id) } {
        let weight = u32::from(be.weight);
        if be.healthy == 1 && weight > 0 {
            walk.total = walk.total.wrapping_add(weight);
            // `checked_rem` rather than `%`: a `%` the compiler cannot prove
            // non-zero leaves a panic call the verifier refuses.
            let draw = unsafe { bpf_get_prandom_u32() }.checked_rem(walk.total);
            if matches!(draw, Some(d) if d < weight) {
                walk.picked = backend_id;
            }
        }
    }
    0
}

/// The healthy backend with the fewest open connections. Ties go to the
/// first one met walking from `offset`, which turns with every new flow so
/// equal backends share new connections in turn.
#[inline(always)]
fn select_least_conn(svc: &LbServiceConfigV2, count: usize, offset: usize) -> Option<u32> {
    Walk::new(svc, count, offset).run(least_conn_step)
}

#[inline(never)]
extern "C" fn least_conn_step(i: u32, walk: *mut core::ffi::c_void) -> i64 {
    // SAFETY: `bpf_loop` hands back the context `Walk::run` gave it.
    let walk = unsafe { &mut *walk.cast::<Walk>() };
    let Some(idx) = walk.offset.wrapping_add(i).checked_rem(walk.count) else {
        return 1;
    };
    let backend_id = walk.first.wrapping_add(idx);
    if let Some(be) = unsafe { LB_BACKENDS.get(&backend_id) } {
        if be.healthy == 1 {
            let open = match unsafe { LB_BACKEND_CONNS.get(&backend_id) } {
                Some(n) if *n > 0 => *n,
                _ => 0,
            };
            if open < walk.fewest {
                walk.fewest = open;
                walk.picked = backend_id;
            }
        }
    }
    0
}

/// The service a packet is addressed to: the one bound to its exact
/// destination address, else the one bound to every address on its port.
/// Returns the key that matched, since that is what the per-service state
/// is indexed by.
#[inline(always)]
fn lookup_service(exact: LbServiceKey) -> Option<(LbServiceKey, &'static LbServiceConfigV2)> {
    if let Some(config) = unsafe { LB_SERVICES.get(&exact) } {
        return Some((exact, config));
    }
    let any = LbServiceKey::any(exact.protocol, exact.port);
    unsafe { LB_SERVICES.get(&any) }.map(|config| (any, config))
}

/// Derive a per-service index from a `LbServiceKey` for round-robin state lookup,
/// in `0..MAX_LB_SERVICES`.
#[inline(always)]
fn service_key_index(key: &LbServiceKey) -> u32 {
    lb_service_index(key)
}

/// FNV-1a hash of a u32 value. Delegates to the shared `ebpf-common`
/// implementation so the data plane and userspace never drift.
#[inline(always)]
fn fnv1a(val: u32) -> u32 {
    lb_fnv1a_u32(val)
}

// ── Checksum Helpers ────────────────────────────────────────────────

/// One 16-bit word of a one's-complement sum replaced (RFC 1624, eqn. 3):
/// the old word is added in complement, never subtracted. Subtracting in
/// two's complement is off by one whenever it borrows, which is how one
/// rewritten packet in a few hundred reached the backend with a checksum it
/// dropped.
#[inline(always)]
fn csum_replace16(sum: u32, old: u16, new: u16) -> u32 {
    sum + u32::from(!old) + u32::from(new)
}

/// Both halves of a 32-bit value replaced.
#[inline(always)]
fn csum_replace32(sum: u32, old: u32, new: u32) -> u32 {
    let sum = csum_replace16(sum, (old & 0xFFFF) as u16, (new & 0xFFFF) as u16);
    csum_replace16(sum, (old >> 16) as u16, (new >> 16) as u16)
}

/// Fold an accumulator back to the 16-bit field value.
#[inline(always)]
fn csum_fold(mut sum: u32) -> u16 {
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    !(sum as u16)
}

/// Offset of the TCP or UDP checksum field.
#[inline(always)]
fn l4_csum_offset(l4_offset: usize, protocol: u8) -> usize {
    if protocol == PROTO_TCP {
        l4_offset + 16
    } else {
        l4_offset + 6
    }
}

/// Apply `edit` to the TCP or UDP checksum at `l4_offset`. A UDP datagram
/// sent without a checksum (zero) keeps none, and a UDP result of zero is
/// written as all ones, its equivalent.
#[inline(always)]
fn edit_l4_checksum(ctx: &XdpContext, l4_offset: usize, protocol: u8, edit: impl Fn(u32) -> u32) {
    if let Ok(csum_ptr) = unsafe { ptr_at_mut::<u16>(ctx, l4_csum_offset(l4_offset, protocol)) } {
        unsafe {
            let field = u16::from_be(*csum_ptr);
            if protocol != PROTO_TCP && field == 0 {
                return;
            }
            let mut out = csum_fold(edit(u32::from(!field)));
            if protocol != PROTO_TCP && out == 0 {
                out = 0xFFFF;
            }
            *csum_ptr = out.to_be();
        }
    }
}

/// Incremental IP header checksum update after an address rewrite.
#[inline(always)]
fn update_ip_checksum(ipv4hdr: *mut Ipv4Hdr, old_val: u32, new_val: u32) {
    unsafe {
        let field = u16::from_be_bytes((*ipv4hdr).check);
        let sum = csum_replace32(u32::from(!field), old_val, new_val);
        (*ipv4hdr).check = csum_fold(sum).to_be_bytes();
    }
}

/// Incremental TCP/UDP checksum update after an IPv4 address + port rewrite.
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
    edit_l4_checksum(ctx, l4_offset, protocol, |sum| {
        let sum = csum_replace32(sum, old_ip, new_ip);
        csum_replace16(sum, u16::from_be(old_port), u16::from_be(new_port))
    });
}

/// Incremental L4 checksum update for port-only change (IPv6 - no IP checksum).
#[inline(always)]
fn update_l4_checksum_port_only(
    ctx: &XdpContext,
    l4_offset: usize,
    protocol: u8,
    old_port: u16,
    new_port: u16,
) {
    edit_l4_checksum(ctx, l4_offset, protocol, |sum| {
        csum_replace16(sum, u16::from_be(old_port), u16::from_be(new_port))
    });
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
    edit_l4_checksum(ctx, l4_offset, protocol, |mut sum| {
        let mut i = 0;
        while i < 16 {
            let old_word = u16::from_be_bytes([old_addr[i], old_addr[i + 1]]);
            let new_word = u16::from_be_bytes([new_addr[i], new_addr[i + 1]]);
            sum = csum_replace16(sum, old_word, new_word);
            i += 2;
        }
        csum_replace16(sum, u16::from_be(old_port), u16::from_be(new_port))
    });
}

// ── Helpers ─────────────────────────────────────────────────────────
// ptr_at, ptr_at_mut, skip_ipv6_ext_headers imported from ebpf_helpers::xdp
// ipv6_addr_to_u32x4, u32x4_to_ipv6_bytes imported from ebpf_helpers::net

#[inline(always)]
fn increment_metric(traced: bool, index: u32) {
    add_metric!(LB_METRICS, index, u64::from(live(traced)));
}

#[inline(always)]
fn add_metric(traced: bool, index: u32, value: u64) {
    add_metric!(
        LB_METRICS,
        index,
        value & u64::from(live(traced)).wrapping_neg()
    );
}

/// 1 for live traffic and 0 for a trace, so a write adds nothing to a traced
/// packet's counters without a branch. A branch on the trace flag keeps the
/// verifier from merging the two paths that follow it, and across the
/// backend selection that is enough states to exhaust its budget.
#[inline(always)]
fn live(traced: bool) -> u32 {
    u32::from(!traced)
}

// ── Event Emission ──────────────────────────────────────────────────

#[inline(always)]
fn ringbuf_has_backpressure() -> bool {
    ringbuf_has_backpressure!(EVENTS)
}

#[inline(always)]
fn emit_event(
    ctx_raw: *mut core::ffi::c_void,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    action: u8,
    flags: u8,
    vlan_id: u16,
) {
    if is_traced(ctx_raw) {
        return;
    }
    if ringbuf_has_backpressure() {
        increment_metric(false, LB_METRIC_EVENTS_DROPPED);
        return;
    }

    let mut event = match EVENTS.reserve_untyped::<PacketEvent>(0) {
        Some(e) => e,
        None => {
            increment_metric(false, LB_METRIC_EVENTS_DROPPED);
            return;
        }
    };

    let vlan_flags = if vlan_id > 0 {
        flags | FLAG_VLAN
    } else {
        flags
    };

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
        (*ptr).cgroup_id = 0;
        (*ptr).cgroup1_id = 0;
        let (rss_h, rss_t) = xdp_rx_hash(ctx_raw.cast_const()).unwrap_or((0, 0));
        (*ptr).rss_hash = rss_h;
        (*ptr).rss_hash_type = rss_t;
        (*ptr).rx_hw_timestamp_ns = xdp_rx_timestamp(ctx_raw.cast_const()).unwrap_or(0);
        // The linear frame, which is what the forwarded-bytes counter reads.
        let frame = XdpContext::new(ctx_raw.cast());
        (*ptr).pkt_len = frame.data_end().saturating_sub(frame.data()) as u32;
        (*ptr)._pad = 0;
        event.submit(submit_flags(avail_data(&EVENTS)));
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
