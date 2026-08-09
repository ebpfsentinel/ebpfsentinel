#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    btf_maps::{PerCpuArray, RingBuf},
    helpers::{bpf_get_current_cgroup_id, bpf_ktime_get_boot_ns},
    macros::{btf_map, classifier},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;
use core::mem;
use ebpf_common::dns::{
    DNS_DIRECTION_QUERY, DNS_DIRECTION_RESPONSE, DNS_MAX_PAYLOAD, DNS_METRIC_ERRORS,
    DNS_METRIC_EVENTS_DROPPED, DNS_METRIC_EVENTS_EMITTED, DNS_METRIC_PACKETS_INSPECTED,
    DNS_METRIC_TOTAL_SEEN, DNS_SMALL_PAYLOAD, DnsEvent, DnsEventBuf, DnsEventSmall,
};
use ebpf_common::event::{FLAG_IPV6, FLAG_TCP, FLAG_VLAN};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP, PROTO_UDP,
    VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{increment_metric, opaque_usize};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.
const DNS_PORT: u16 = 53;

// ── Maps ────────────────────────────────────────────────────────────

/// Dedicated DNS kernel→userspace event ring buffer (256 KB).
/// Separate from the main EVENTS RingBuf to avoid DNS volume flooding
/// security events and to allow independent polling cadence.
#[btf_map]
static DNS_EVENTS: RingBuf<DnsEventBuf, { 64 * 4096 }> = RingBuf::new();

/// Per-CPU DNS counters. Index: 0=packets_inspected, 1=events_emitted,
/// 2=errors, 3=events_dropped, 4=total_seen.
#[btf_map]
static DNS_METRICS: PerCpuArray<u64, 5> = PerCpuArray::new();

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Captures DNS packets (UDP/TCP port 53) and
/// emits them to the DNS_EVENTS RingBuf. Always returns TC_ACT_OK
/// (passthrough — observation only, no blocking).
#[classifier]
pub fn tc_dns(ctx: TcContext) -> i32 {
    increment_metric(DNS_METRIC_TOTAL_SEEN);
    let action = match try_tc_dns(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(DNS_METRIC_ERRORS);
            TC_ACT_OK
        }
    };
    // Under TCX (kernel >= 6.6) a program returning TC_ACT_OK terminates the
    // program chain on this hook; translate a "pass" verdict to TCX_NEXT (-1)
    // so other tc programs attached to the same interface still run.
    if action == TC_ACT_OK { -1 } else { action }
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_dns(ctx: &TcContext) -> Result<i32, ()> {
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
        process_dns_v4(ctx, l3_offset, vlan_id, flags)
    } else if ether_type == ETH_P_IPV6 {
        process_dns_v6(ctx, l3_offset, vlan_id, flags | FLAG_IPV6)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 DNS processing path (UDP and TCP port 53).
#[inline(always)]
fn process_dns_v4(ctx: &TcContext, l3_offset: usize, vlan_id: u16, flags: u8) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let protocol = unsafe { (*ipv4hdr).proto() }.unwrap_or(IpProto::Reserved);

    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    let (src_port, dst_port, dns_offset, tcp_flag) = if protocol == IpProto::Udp {
        let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        let sp = u16_from_be_bytes(unsafe { (*udphdr).src });
        let dp = u16_from_be_bytes(unsafe { (*udphdr).dst });
        (sp, dp, l4_offset + mem::size_of::<UdpHdr>(), 0u8)
    } else if protocol == IpProto::Tcp {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        let sp = u16_from_be_bytes(unsafe { (*tcphdr).source });
        let dp = u16_from_be_bytes(unsafe { (*tcphdr).dest });
        // Compute TCP data offset from the already-validated tcphdr pointer.
        // Read byte 12 of the TCP header (data offset + reserved) directly
        // from the validated pointer to keep the verifier happy.
        let doff_byte = unsafe { *(tcphdr as *const u8).add(12) };
        let data_off = (doff_byte as usize >> 2) & 0x3C;
        // For TCP DNS, skip TCP header + 2-byte DNS length prefix.
        // Use a fixed maximum offset to satisfy the verifier's bounded arithmetic.
        // Max dns_off = l4_offset(82) + data_off(60) + 2 = 144
        if data_off < 20 {
            return Ok(TC_ACT_OK); // invalid TCP header
        }
        let dns_off = l4_offset + data_off + 2;
        if dns_off > 200 {
            return Ok(TC_ACT_OK); // sanity check
        }
        (sp, dp, dns_off, FLAG_TCP)
    } else {
        return Ok(TC_ACT_OK);
    };

    // Check if this is a DNS packet (port 53)
    let direction = if dst_port == DNS_PORT {
        DNS_DIRECTION_QUERY
    } else if src_port == DNS_PORT {
        DNS_DIRECTION_RESPONSE
    } else {
        return Ok(TC_ACT_OK);
    };

    increment_metric(DNS_METRIC_PACKETS_INSPECTED);

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];

    emit_dns_event(
        ctx,
        &src_addr,
        &dst_addr,
        flags | tcp_flag,
        vlan_id,
        direction,
        dns_offset,
    );

    Ok(TC_ACT_OK)
}

/// IPv6 DNS processing path (UDP and TCP port 53).
#[inline(always)]
fn process_dns_v6(ctx: &TcContext, l3_offset: usize, vlan_id: u16, flags: u8) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) =
        skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr).ok_or(())?;

    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });

    let (src_port, dst_port, dns_offset, tcp_flag) = if next_hdr == PROTO_UDP {
        let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        let sp = u16_from_be_bytes(unsafe { (*udphdr).src });
        let dp = u16_from_be_bytes(unsafe { (*udphdr).dst });
        (sp, dp, l4_offset + mem::size_of::<UdpHdr>(), 0u8)
    } else if next_hdr == PROTO_TCP {
        let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
        let sp = u16_from_be_bytes(unsafe { (*tcphdr).source });
        let dp = u16_from_be_bytes(unsafe { (*tcphdr).dest });
        let data_off = ((unsafe { (*tcphdr).doff() } as usize) << 2) & 0x3C;
        let dns_off = l4_offset + data_off + 2;
        let _: *const u8 = unsafe { ptr_at(ctx, dns_off)? };
        (sp, dp, dns_off, FLAG_TCP)
    } else {
        return Ok(TC_ACT_OK);
    };

    // Check if this is a DNS packet (port 53)
    let direction = if dst_port == DNS_PORT {
        DNS_DIRECTION_QUERY
    } else if src_port == DNS_PORT {
        DNS_DIRECTION_RESPONSE
    } else {
        return Ok(TC_ACT_OK);
    };

    increment_metric(DNS_METRIC_PACKETS_INSPECTED);

    emit_dns_event(
        ctx,
        &src_addr,
        &dst_addr,
        flags | tcp_flag,
        vlan_id,
        direction,
        dns_offset,
    );

    Ok(TC_ACT_OK)
}

// ── Helpers ─────────────────────────────────────────────────────────

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

/// Increment a per-CPU DNS metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(DNS_METRICS, index);
}

/// DNS backpressure threshold: 75% of 256 KB DNS ring buffer.
const DNS_BACKPRESSURE_THRESHOLD: u64 = 64 * 4096 * 3 / 4;

/// Returns `true` if the DNS_EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn dns_ringbuf_has_backpressure() -> bool {
    ebpf_helpers::ringbuf_has_backpressure!(DNS_EVENTS, DNS_BACKPRESSURE_THRESHOLD)
}

/// Header fields shared by both event tiers, gathered once so the two
/// reservation paths write the same header from the same values.
struct DnsHeaderFields {
    src_addr: [u32; 4],
    dst_addr: [u32; 4],
    payload_len: u16,
    direction: u8,
    flags: u8,
    vlan_id: u16,
}

/// Emit a DNS record to the DNS_EVENTS RingBuf. Skips emission under
/// backpressure (>75% full). Copies the DnsEvent header and up to
/// DNS_MAX_PAYLOAD bytes of raw DNS payload from the packet.
///
/// The reservation is tiered by captured length: a payload that fits in
/// `DNS_SMALL_PAYLOAD` takes a 192-byte record instead of 576, which is the
/// common case (a query carrying one name) and triples how many records the
/// 256 KB ring holds before it drops. The two tiers are separate `#[repr(C)]`
/// types rather than one runtime-sized reservation because `bpf_ringbuf_reserve`
/// demands a size the verifier can see as constant; a tier per type gives it
/// exactly that. Userspace is unaffected - the header is byte-identical and the
/// reader already bounds the payload by `dns_payload_len` against the record it
/// actually received.
///
/// `bpf_skb_load_bytes` is called directly rather than through aya's
/// `load_bytes()` wrapper, whose variable `[0, len]` range the kernel 6.17+
/// verifier rejects.
#[inline(always)]
fn emit_dns_event(
    ctx: &TcContext,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    flags: u8,
    vlan_id: u16,
    direction: u8,
    dns_offset: usize,
) {
    if dns_ringbuf_has_backpressure() {
        increment_metric(DNS_METRIC_EVENTS_DROPPED);
        return;
    }
    // Calculate DNS payload length using the full SKB length (ctx.len())
    // instead of the linear buffer (data_end - data). This ensures jumbo
    // frames and GRO-aggregated DNS responses are measured correctly.
    let total_len = ctx.len() as usize;

    // No DNS payload available — nothing to emit
    if dns_offset >= total_len {
        return;
    }

    let available = total_len - dns_offset;
    let payload_len: usize = if available > DNS_MAX_PAYLOAD {
        DNS_MAX_PAYLOAD
    } else {
        available
    };

    let fields = DnsHeaderFields {
        src_addr: *src_addr,
        dst_addr: *dst_addr,
        payload_len: payload_len as u16,
        direction,
        flags,
        vlan_id,
    };

    // bpf_skb_load_bytes handles fragmented packets natively (via
    // skb_header_pointer), so linearization is unnecessary.
    //
    // RingBuf path (copy-based). TC programs are not sleepable, so the
    // sleepable arena-alloc kfunc is unavailable here.
    let emitted = if payload_len <= DNS_SMALL_PAYLOAD {
        emit_dns_small(ctx, &fields, dns_offset, payload_len)
    } else {
        emit_dns_full(ctx, &fields, dns_offset, payload_len)
    };

    if emitted {
        increment_metric(DNS_METRIC_EVENTS_EMITTED);
    } else {
        increment_metric(DNS_METRIC_EVENTS_DROPPED);
    }
}

/// Write the tier-independent header into a reserved record.
///
/// # Safety
///
/// `ptr` must point at a live ring-buffer reservation of at least
/// `DnsEvent::HEADER_SIZE` bytes.
#[inline(always)]
unsafe fn write_dns_header(ptr: *mut DnsEvent, f: &DnsHeaderFields) {
    unsafe {
        (*ptr).timestamp_ns = bpf_ktime_get_boot_ns();
        (*ptr).src_addr = f.src_addr;
        (*ptr).dst_addr = f.dst_addr;
        (*ptr).dns_payload_len = f.payload_len;
        (*ptr).dns_payload_offset = DnsEvent::HEADER_SIZE;
        (*ptr).direction = f.direction;
        (*ptr).flags = f.flags;
        (*ptr).vlan_id = f.vlan_id;
        (*ptr)._padding = [0; 8];
        // Valid on egress queries where the current task owns the skb; 0 on
        // ingress softirq (DNS responses).
        (*ptr).cgroup_id = bpf_get_current_cgroup_id();
    }
}

/// Small tier (192 bytes): payloads up to `DNS_SMALL_PAYLOAD`.
///
/// `#[inline(never)]` gives each tier its own stack frame, which keeps the two
/// reservation sizes from compounding into one function's verifier state.
#[inline(never)]
fn emit_dns_small(
    ctx: &TcContext,
    fields: &DnsHeaderFields,
    dns_offset: usize,
    payload_len: usize,
) -> bool {
    let Some(mut entry) = DNS_EVENTS.reserve_untyped::<DnsEventSmall>(0) else {
        return false;
    };
    let ptr = entry.as_mut_ptr();
    let loaded = unsafe {
        write_dns_header(core::ptr::addr_of_mut!((*ptr).header), fields);
        load_dns_payload::<DNS_SMALL_PAYLOAD>(
            ctx,
            (*ptr).payload.as_mut_ptr(),
            dns_offset,
            payload_len,
        )
    };
    if !loaded {
        entry.discard(0);
        increment_metric(DNS_METRIC_ERRORS);
        return false;
    }
    entry.submit(0);
    true
}

/// Full tier (576 bytes): payloads above `DNS_SMALL_PAYLOAD`.
#[inline(never)]
fn emit_dns_full(
    ctx: &TcContext,
    fields: &DnsHeaderFields,
    dns_offset: usize,
    payload_len: usize,
) -> bool {
    let Some(mut entry) = DNS_EVENTS.reserve_untyped::<DnsEventBuf>(0) else {
        return false;
    };
    let ptr = entry.as_mut_ptr();
    let loaded = unsafe {
        write_dns_header(core::ptr::addr_of_mut!((*ptr).header), fields);
        load_dns_payload::<DNS_MAX_PAYLOAD>(
            ctx,
            (*ptr).payload.as_mut_ptr(),
            dns_offset,
            payload_len,
        )
    };
    if !loaded {
        entry.discard(0);
        increment_metric(DNS_METRIC_ERRORS);
        return false;
    }
    entry.submit(0);
    true
}

/// Zero a tier's payload buffer and load the captured bytes into it.
///
/// Returns whether the load succeeded. A failure leaves the zeroed buffer
/// behind, which the header would still advertise as `payload_len` bytes of
/// DNS, so the caller drops the record instead of publishing a blank one.
///
/// # Safety
///
/// `dst` must point at a live reservation with at least `CAP` writable bytes.
#[inline(always)]
unsafe fn load_dns_payload<const CAP: usize>(
    ctx: &TcContext,
    dst: *mut u8,
    dns_offset: usize,
    payload_len: usize,
) -> bool {
    unsafe {
        // Zero the payload buffer so bytes beyond the captured DNS payload are
        // deterministic rather than whatever the ring last held.
        core::ptr::write_bytes(dst, 0, CAP);

        // Load exactly the bytes the packet carries (clamped to the buffer),
        // not a fixed CAP. `bpf_skb_load_bytes` is all-or-nothing: a constant
        // full-buffer read fails whenever the remaining skb is shorter — the
        // common case for DNS — leaving the payload all-zero while
        // `dns_payload_len` still advertises the real length. Loading the real
        // length captures the query/answer.
        //
        // `payload_len` is already in `1..=CAP` (dns_offset < total_len, so
        // `available >= 1`, and the caller picked the tier by that length), but
        // the RingBuf reserve spills the register and the verifier loses the
        // lower bound, rejecting the zero case ("R4 invalid zero-sized read")
        // on kernel 6.17+. Route the value through a barrier then re-clamp so
        // the `[1, CAP]` bound survives the spill/reload. The load always fits
        // (dns_offset + load_len <= total_len = skb len), so it never fails on
        // bounds.
        let load_len = opaque_usize(payload_len).clamp(1, CAP);
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            dns_offset as u32,
            dst as *mut _,
            load_len as u32,
        ) >= 0
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
