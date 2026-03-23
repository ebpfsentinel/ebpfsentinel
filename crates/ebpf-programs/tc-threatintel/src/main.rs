#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    bindings::TC_ACT_SHOT,
    macros::{classifier, map},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf, bloom_filter::BloomFilter},
    programs::TcContext,
};
#[cfg(debug_assertions)]
use aya_log_ebpf::info;
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_TCP,
    PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4, u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::{emit_packet_event, increment_metric};
use ebpf_common::{
    event::{
        EVENT_TYPE_THREATINTEL, FLAG_IPV6, FLAG_VLAN,
    },
    threatintel::{
        THREATINTEL_ACTION_DROP, THREATINTEL_MAX_ENTRIES, THREATINTEL_METRIC_DROPPED,
        THREATINTEL_METRIC_ERRORS, THREATINTEL_METRIC_EVENTS_DROPPED, THREATINTEL_METRIC_MATCHED,
        THREATINTEL_METRIC_TOTAL_SEEN,
        ThreatIntelKey, ThreatIntelKeyV6, ThreatIntelValue,
    },
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

// ── Maps ────────────────────────────────────────────────────────────

/// Threat intel IOC lookup: IPv4 address → action + feed metadata.
/// Supports 1M+ entries (NFR22). Uses `LruHashMap` so that when the map is
/// full the least-recently-used entry is evicted instead of silently
/// dropping new inserts.
#[map]
static THREATINTEL_IOCS: LruHashMap<ThreatIntelKey, ThreatIntelValue> =
    LruHashMap::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Threat intel IOC lookup: IPv6 address → action + feed metadata.
/// Uses `LruHashMap` for automatic LRU eviction on full maps.
#[map]
static THREATINTEL_IOCS_V6: LruHashMap<ThreatIntelKeyV6, ThreatIntelValue> =
    LruHashMap::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Bloom filter pre-check for IPv4 IOCs (kernel 5.16+).
/// Eliminates ~98% of HashMap lookups for non-matching packets.
#[map]
static mut THREATINTEL_BLOOM_V4: BloomFilter<ThreatIntelKey> =
    BloomFilter::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Bloom filter pre-check for IPv6 IOCs (kernel 5.16+).
#[map]
static mut THREATINTEL_BLOOM_V6: BloomFilter<ThreatIntelKeyV6> =
    BloomFilter::with_max_entries(THREATINTEL_MAX_ENTRIES, 0);

/// Per-CPU counters. Index: 0=matched, 1=dropped, 2=errors, 3=events_dropped, 4=total_seen.
#[map]
static THREATINTEL_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(5, 0);

/// Shared kernel→userspace event ring buffer (1 MB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 4096, 0);

/// Feature enable/disable flags (shared across programs).
#[map]
static CONFIG_FLAGS: Array<u32> = Array::with_max_entries(1, 0);

// ── Entry point ─────────────────────────────────────────────────────

/// TC classifier entry point. Delegates to try_tc_threatintel; any error
/// returns TC_ACT_OK (NFR15: default-to-pass on internal error).
#[classifier]
pub fn tc_threatintel(ctx: TcContext) -> i32 {
    increment_metric(THREATINTEL_METRIC_TOTAL_SEEN);
    match try_tc_threatintel(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(THREATINTEL_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_threatintel(ctx: &TcContext) -> Result<i32, ()> {
    // Check if threat intel is enabled via config flags (0 = disabled).
    if let Some(flags) = CONFIG_FLAGS.get(0) {
        if *flags == 0 {
            return Ok(TC_ACT_OK);
        }
    }

    // Parse Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;
    let mut vlan_id: u16 = 0;
    let mut pkt_flags: u8 = 0;

    // Check for 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        let tci = u16::from_be(unsafe { (*vhdr).tci });
        vlan_id = tci & 0x0FFF;
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;
        pkt_flags |= FLAG_VLAN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            vlan_id = u16::from_be(unsafe { (*vhdr2).tci }) & 0x0FFF;
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
    }

    if ether_type == ETH_P_IP {
        process_threatintel_v4(ctx, l3_offset, vlan_id, pkt_flags)
    } else if ether_type == ETH_P_IPV6 {
        process_threatintel_v6(ctx, l3_offset, vlan_id, pkt_flags | FLAG_IPV6)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 threat intel processing.
#[inline(always)]
fn process_threatintel_v4(
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

    // IOC lookup: bloom filter pre-check avoids HashMap lookups for
    // ~98% of non-matching packets (kernel 5.16+).
    let src_key = ThreatIntelKey { ip: src_ip };
    let dst_key = ThreatIntelKey { ip: dst_ip };

    let src_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V4))
            .contains(&src_key)
            .is_ok()
    };
    let dst_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V4))
            .contains(&dst_key)
            .is_ok()
    };

    if !src_maybe && !dst_maybe {
        return Ok(TC_ACT_OK); // guaranteed no match
    }

    let src_match = if src_maybe {
        unsafe { THREATINTEL_IOCS.get(&src_key) }
    } else {
        None
    };
    let dst_match = if dst_maybe {
        unsafe { THREATINTEL_IOCS.get(&dst_key) }
    } else {
        None
    };

    let matched = match (src_match, dst_match) {
        (None, None) => return Ok(TC_ACT_OK), // bloom false positive
        (Some(v), None) | (None, Some(v)) => v,
        (Some(s), Some(d)) => {
            if d.action > s.action {
                d
            } else {
                s
            }
        }
    };

    let src_addr = [src_ip, 0, 0, 0];
    let dst_addr = [dst_ip, 0, 0, 0];
    apply_threatintel_action(
        ctx,
        matched,
        &src_addr,
        &dst_addr,
        src_port,
        dst_port,
        protocol as u8,
        flags,
        vlan_id,
    )
}

/// IPv6 threat intel processing.
#[inline(always)]
fn process_threatintel_v6(
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

    // IOC lookup: bloom filter pre-check for IPv6.
    let src_key = ThreatIntelKeyV6 { ip: src_addr };
    let dst_key = ThreatIntelKeyV6 { ip: dst_addr };

    let src_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V6))
            .contains(&src_key)
            .is_ok()
    };
    let dst_maybe = unsafe {
        (*core::ptr::addr_of_mut!(THREATINTEL_BLOOM_V6))
            .contains(&dst_key)
            .is_ok()
    };

    if !src_maybe && !dst_maybe {
        return Ok(TC_ACT_OK); // guaranteed no match
    }

    let src_match = if src_maybe {
        unsafe { THREATINTEL_IOCS_V6.get(&src_key) }
    } else {
        None
    };
    let dst_match = if dst_maybe {
        unsafe { THREATINTEL_IOCS_V6.get(&dst_key) }
    } else {
        None
    };

    let matched = match (src_match, dst_match) {
        (None, None) => return Ok(TC_ACT_OK), // bloom false positive
        (Some(v), None) | (None, Some(v)) => v,
        (Some(s), Some(d)) => {
            if d.action > s.action {
                d
            } else {
                s
            }
        }
    };

    apply_threatintel_action(
        ctx, matched, &src_addr, &dst_addr, src_port, dst_port, next_hdr, flags, vlan_id,
    )
}

/// Apply threat intel action (shared by v4/v6 paths).
#[inline(always)]
fn apply_threatintel_action(
    _ctx: &TcContext,
    matched: &ThreatIntelValue,
    src_addr: &[u32; 4],
    dst_addr: &[u32; 4],
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    flags: u8,
    vlan_id: u16,
) -> Result<i32, ()> {
    increment_metric(THREATINTEL_METRIC_MATCHED);
    (|| {
        emit_packet_event!(EVENTS, THREATINTEL_METRICS, THREATINTEL_METRIC_EVENTS_DROPPED,
            src_addr, dst_addr, src_port, dst_port, protocol,
            EVENT_TYPE_THREATINTEL, matched.action, matched.feed_id as u32, flags, vlan_id; tc _ctx);
    })();

    if matched.action == THREATINTEL_ACTION_DROP {
        #[cfg(debug_assertions)]
        info!(
            _ctx,
            "THREATINTEL DROP {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
        );
        increment_metric(THREATINTEL_METRIC_DROPPED);
        Ok(TC_ACT_SHOT)
    } else {
        #[cfg(debug_assertions)]
        info!(
            _ctx,
            "THREATINTEL ALERT {:i} -> {:i}:{}", src_addr[0], dst_addr[0], dst_port
        );
        Ok(TC_ACT_OK)
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

/// Increment a per-CPU metric counter.
#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(THREATINTEL_METRICS, index);
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
