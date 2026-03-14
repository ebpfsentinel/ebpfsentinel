#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
use aya_ebpf_bindings::helpers::bpf_skb_load_bytes;
use core::mem;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_UDP,
    VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::increment_metric;
use ebpf_common::dns::{
    DnsEvent, DnsEventBuf, DNS_DIRECTION_QUERY, DNS_DIRECTION_RESPONSE, DNS_MAX_PAYLOAD,
    DNS_METRIC_ERRORS, DNS_METRIC_EVENTS_DROPPED, DNS_METRIC_EVENTS_EMITTED,
    DNS_METRIC_PACKETS_INSPECTED, DNS_METRIC_TOTAL_SEEN,
};
use ebpf_common::event::{FLAG_IPV6, FLAG_VLAN};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────
// Network constants and header structs imported from ebpf_helpers.
const DNS_PORT: u16 = 53;

// ── Maps ────────────────────────────────────────────────────────────

/// Dedicated DNS kernel→userspace event ring buffer (256 KB).
/// Separate from the main EVENTS RingBuf to avoid DNS volume flooding
/// security events and to allow independent polling cadence.
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 4096, 0);

/// Per-CPU DNS counters. Index: 0=packets_inspected, 1=events_emitted,
/// 2=errors, 3=events_dropped, 4=total_seen.
#[map]
static DNS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Captures DNS packets (UDP port 53) and
/// emits them to the DNS_EVENTS RingBuf. Always returns TC_ACT_OK
/// (passthrough — observation only, no blocking).
#[classifier]
pub fn tc_dns(ctx: TcContext) -> i32 {
    increment_metric(DNS_METRIC_TOTAL_SEEN);
    match try_tc_dns(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(DNS_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
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

/// IPv4 DNS processing path.
#[inline(always)]
fn process_dns_v4(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let protocol = unsafe { (*ipv4hdr).proto };

    // DNS is UDP only (TCP DNS is out of scope for this story)
    if protocol != IpProto::Udp {
        return Ok(TC_ACT_OK);
    }

    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Parse UDP header
    let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let src_port = u16_from_be_bytes(unsafe { (*udphdr).src });
    let dst_port = u16_from_be_bytes(unsafe { (*udphdr).dst });

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
    let dns_offset = l4_offset + mem::size_of::<UdpHdr>();

    emit_dns_event(ctx, &src_addr, &dst_addr, flags, vlan_id, direction, dns_offset);

    Ok(TC_ACT_OK)
}

/// IPv6 DNS processing path.
#[inline(always)]
fn process_dns_v6(
    ctx: &TcContext,
    l3_offset: usize,
    vlan_id: u16,
    flags: u8,
) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let raw_next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (next_hdr, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_next_hdr)
        .ok_or(())?;

    // DNS is UDP only
    if next_hdr != PROTO_UDP {
        return Ok(TC_ACT_OK);
    }

    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });

    // Parse UDP header
    let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
    let src_port = u16_from_be_bytes(unsafe { (*udphdr).src });
    let dst_port = u16_from_be_bytes(unsafe { (*udphdr).dst });

    // Check if this is a DNS packet (port 53)
    let direction = if dst_port == DNS_PORT {
        DNS_DIRECTION_QUERY
    } else if src_port == DNS_PORT {
        DNS_DIRECTION_RESPONSE
    } else {
        return Ok(TC_ACT_OK);
    };

    increment_metric(DNS_METRIC_PACKETS_INSPECTED);

    let dns_offset = l4_offset + mem::size_of::<UdpHdr>();

    emit_dns_event(ctx, &src_addr, &dst_addr, flags, vlan_id, direction, dns_offset);

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

/// Emit a DnsEventBuf to the DNS_EVENTS RingBuf. Skips emission under
/// backpressure (>75% full). Copies the DnsEvent header and up to
/// DNS_MAX_PAYLOAD bytes of raw DNS payload from the packet.
///
/// Calls `bpf_skb_load_bytes` directly with a compile-time constant
/// length (`DNS_MAX_PAYLOAD`) so the kernel 6.17+ verifier sees a
/// fixed-size read instead of the variable `[0, 511]` range that
/// aya's `load_bytes()` wrapper produces.
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
    // Calculate DNS payload length before reserving ringbuf entry
    let pkt_start = ctx.data() + dns_offset;
    let pkt_end = ctx.data_end();

    // No DNS payload available — nothing to emit
    if pkt_start >= pkt_end {
        return;
    }

    let available = pkt_end - pkt_start;
    let payload_len: usize = if available > DNS_MAX_PAYLOAD {
        DNS_MAX_PAYLOAD
    } else {
        available
    };

    if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEventBuf>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            // Fill header
            (*ptr).header.timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).header.src_addr = *src_addr;
            (*ptr).header.dst_addr = *dst_addr;
            (*ptr).header.dns_payload_len = payload_len as u16;
            (*ptr).header.dns_payload_offset = DnsEvent::HEADER_SIZE;
            (*ptr).header.direction = direction;
            (*ptr).header.flags = flags;
            (*ptr).header.vlan_id = vlan_id;

            // Zero payload buffer so bytes beyond the actual DNS
            // payload are deterministic even if load_bytes copies less.
            core::ptr::write_bytes((*ptr).payload.as_mut_ptr(), 0, DNS_MAX_PAYLOAD);

            // Call bpf_skb_load_bytes directly with a compile-time
            // constant length (DNS_MAX_PAYLOAD = 512). The aya wrapper
            // `ctx.load_bytes()` computes min(skb_len - offset, dst.len())
            // which gives the verifier a variable range [0, 511] for R4,
            // rejected as "invalid zero-sized read" on kernel 6.17+.
            //
            // With a constant length the verifier sees R4=512 (fixed).
            // If the packet has fewer bytes, bpf_skb_load_bytes returns
            // an error and the pre-zeroed buffer remains intact — the
            // actual payload length is recorded in dns_payload_len.
            let _ = bpf_skb_load_bytes(
                ctx.skb.skb as *const _,
                dns_offset as u32,
                (*ptr).payload.as_mut_ptr() as *mut _,
                DNS_MAX_PAYLOAD as u32,
            );
        }
        entry.submit(0);
        increment_metric(DNS_METRIC_EVENTS_EMITTED);
    } else {
        increment_metric(DNS_METRIC_EVENTS_DROPPED);
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
