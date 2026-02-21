#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map},
    maps::{PerCpuArray, RingBuf},
    programs::TcContext,
};
use core::mem;
use ebpf_common::dns::{
    DnsEvent, DnsEventBuf, DNS_DIRECTION_QUERY, DNS_DIRECTION_RESPONSE, DNS_MAX_PAYLOAD,
    DNS_METRIC_ERRORS, DNS_METRIC_EVENTS_DROPPED, DNS_METRIC_EVENTS_EMITTED,
    DNS_METRIC_PACKETS_INSPECTED,
};
use ebpf_common::event::{FLAG_IPV6, FLAG_VLAN};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

// ── Constants ───────────────────────────────────────────────────────

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const VLAN_HDR_LEN: usize = 4;
const IPV6_HDR_LEN: usize = 40;
const PROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;

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

/// Dedicated DNS kernel→userspace event ring buffer (256 KB).
/// Separate from the main EVENTS RingBuf to avoid DNS volume flooding
/// security events and to allow independent polling cadence.
#[map]
static DNS_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 4096, 0);

/// Per-CPU DNS counters. Index: 0=packets_inspected, 1=events_emitted,
/// 2=errors, 3=events_dropped.
#[map]
static DNS_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Captures DNS packets (UDP port 53) and
/// emits them to the DNS_EVENTS RingBuf. Always returns TC_ACT_OK
/// (passthrough — observation only, no blocking).
#[classifier]
pub fn tc_dns(ctx: TcContext) -> i32 {
    match try_tc_dns(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(DNS_METRIC_ERRORS);
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

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_dns(ctx: &TcContext) -> Result<i32, ()> {
    increment_metric(DNS_METRIC_PACKETS_INSPECTED);

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
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // DNS is UDP only
    if next_hdr != PROTO_UDP {
        return Ok(TC_ACT_OK);
    }

    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let l4_offset = l3_offset + IPV6_HDR_LEN;

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

    let dns_offset = l4_offset + mem::size_of::<UdpHdr>();

    emit_dns_event(ctx, &src_addr, &dst_addr, flags, vlan_id, direction, dns_offset);

    Ok(TC_ACT_OK)
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

/// Increment a per-CPU DNS metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    if let Some(counter) = DNS_METRICS.get_ptr_mut(index) {
        unsafe {
            *counter += 1;
        }
    }
}

/// DNS_EVENTS RingBuf total size in bytes (must match map declaration).
const DNS_RINGBUF_SIZE: u64 = 64 * 4096;

/// Backpressure threshold: skip emission when >75% of DNS RingBuf is consumed.
const DNS_BACKPRESSURE_THRESHOLD: u64 = DNS_RINGBUF_SIZE * 3 / 4;

/// `BPF_RB_AVAIL_DATA` flag for `bpf_ringbuf_query`.
const BPF_RB_AVAIL_DATA: u64 = 0;

/// Returns `true` if the DNS_EVENTS RingBuf has backpressure (>75% full).
#[inline(always)]
fn dns_ringbuf_has_backpressure() -> bool {
    DNS_EVENTS.query(BPF_RB_AVAIL_DATA) > DNS_BACKPRESSURE_THRESHOLD
}

/// Emit a DnsEventBuf to the DNS_EVENTS RingBuf. Skips emission under
/// backpressure (>75% full). Copies the DnsEvent header and up to
/// DNS_MAX_PAYLOAD bytes of raw DNS payload from the packet.
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
    if let Some(mut entry) = DNS_EVENTS.reserve::<DnsEventBuf>(0) {
        let ptr = entry.as_mut_ptr();
        unsafe {
            // Calculate DNS payload length (bounded to DNS_MAX_PAYLOAD)
            let pkt_start = ctx.data() + dns_offset;
            let pkt_end = ctx.data_end();

            let payload_len = if pkt_start >= pkt_end {
                0usize
            } else {
                let available = pkt_end - pkt_start;
                if available > DNS_MAX_PAYLOAD {
                    DNS_MAX_PAYLOAD
                } else {
                    available
                }
            };

            // Fill header
            (*ptr).header.timestamp_ns = bpf_ktime_get_boot_ns();
            (*ptr).header.src_addr = *src_addr;
            (*ptr).header.dst_addr = *dst_addr;
            (*ptr).header.dns_payload_len = payload_len as u16;
            (*ptr).header.dns_payload_offset = DnsEvent::HEADER_SIZE;
            (*ptr).header.direction = direction;
            (*ptr).header.flags = flags;
            (*ptr).header.vlan_id = vlan_id;

            // Zero payload buffer, then copy available DNS bytes
            core::ptr::write_bytes((*ptr).payload.as_mut_ptr(), 0, DNS_MAX_PAYLOAD);

            if payload_len > 0 {
                core::ptr::copy_nonoverlapping(
                    pkt_start as *const u8,
                    (*ptr).payload.as_mut_ptr(),
                    payload_len,
                );
            }
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
