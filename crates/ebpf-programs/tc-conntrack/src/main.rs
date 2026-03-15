#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::bpf_ktime_get_boot_ns,
    macros::{classifier, map},
    maps::{Array, LruHashMap, PerCpuArray},
    programs::TcContext,
};
use ebpf_helpers::net::{
    ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, ETH_P_IPV6, IPV6_HDR_LEN, Ipv6Hdr, PROTO_ICMP,
    PROTO_ICMPV6, PROTO_TCP, PROTO_UDP, VLAN_HDR_LEN, VlanHdr, ipv6_addr_to_u32x4,
    u16_from_be_bytes, u32_from_be_bytes,
};
use ebpf_helpers::tc::{ptr_at, skip_ipv6_ext_headers};
use ebpf_helpers::increment_metric;
use ebpf_common::conntrack::{
    ConnKey, ConnKeyV6, ConnTrackConfig, ConnValue, ConnValueV6, CT_FLAG_ASSURED,
    CT_FLAG_SEEN_REPLY, CT_MAX_ENTRIES_V4, CT_MAX_ENTRIES_V6, CT_METRIC_COUNT, CT_METRIC_ERRORS,
    CT_METRIC_ESTABLISHED, CT_METRIC_HITS, CT_METRIC_INVALID, CT_METRIC_LOOKUPS, CT_METRIC_NEW,
    CT_METRIC_TOTAL_SEEN,
    CT_STATE_CLOSE_WAIT, CT_STATE_ESTABLISHED, CT_STATE_FIN_WAIT, CT_STATE_INVALID, CT_STATE_NEW,
    CT_STATE_SYN_RECV, CT_STATE_SYN_SENT, CT_STATE_TIME_WAIT, normalize_key_v4, normalize_key_v6,
};
use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

// ── Constants / types from ebpf-helpers ─────────────────────────────
// Network constants, header structs, ptr_at, skip_ipv6_ext_headers,
// byte helpers, and metric macros are imported from ebpf_helpers.

// TCP flags
const TCP_SYN: u8 = 0x02;
const TCP_ACK: u8 = 0x10;
const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

// ── Maps ────────────────────────────────────────────────────────────

/// IPv4 connection tracking table (LRU for automatic eviction).
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v4 for sharing.
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 0);

/// IPv6 connection tracking table.
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v6 for sharing.
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValueV6> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 0);

/// Conntrack configuration (timeouts, enable flag).
#[map]
static CT_CONFIG: Array<ConnTrackConfig> = Array::with_max_entries(1, 0);

/// Per-CPU conntrack metrics.
#[map]
static CT_METRICS: PerCpuArray<u64> = PerCpuArray::with_max_entries(CT_METRIC_COUNT, 0);

// ── Entry point ─────────────────────────────────────────────────────

#[classifier]
pub fn tc_conntrack(ctx: TcContext) -> i32 {
    increment_metric(CT_METRIC_TOTAL_SEEN);
    match try_tc_conntrack(&ctx) {
        Ok(action) => action,
        Err(()) => {
            increment_metric(CT_METRIC_ERRORS);
            TC_ACT_OK
        }
    }
}

// ── Helpers ─────────────────────────────────────────────────────────

#[inline(always)]
fn is_conntrack_enabled() -> bool {
    match CT_CONFIG.get(0) {
        Some(cfg) => cfg.enabled != 0,
        None => false,
    }
}

// ptr_at, skip_ipv6_ext_headers imported from ebpf_helpers::tc

#[inline(always)]
fn increment_metric(index: u32) {
    increment_metric!(CT_METRICS, index);
}

/// Extract TCP flags byte from TcpHdr.
#[inline(always)]
fn tcp_flags(th: &TcpHdr) -> u8 {
    // TCP flags are in the 14th byte of the header
    let bits = th._bitfield_1.get(0, 16);
    (bits >> 8) as u8
}

// ── Packet processing ───────────────────────────────────────────────

#[inline(always)]
fn try_tc_conntrack(ctx: &TcContext) -> Result<i32, ()> {
    if !is_conntrack_enabled() {
        return Ok(TC_ACT_OK);
    }

    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    let mut ether_type = u16::from_be(unsafe { (*ethhdr).ether_type });
    let mut l3_offset = EthHdr::LEN;

    // 802.1Q VLAN tag
    if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
        let vhdr: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
        ether_type = u16::from_be(unsafe { (*vhdr).ether_type });
        l3_offset += VLAN_HDR_LEN;

        // QinQ: parse second VLAN tag if present
        if ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD {
            let vhdr2: *const VlanHdr = unsafe { ptr_at(ctx, l3_offset)? };
            ether_type = u16::from_be(unsafe { (*vhdr2).ether_type });
            l3_offset += VLAN_HDR_LEN;
        }
    }

    if ether_type == ETH_P_IP {
        process_conntrack_v4(ctx, l3_offset)
    } else if ether_type == ETH_P_IPV6 {
        process_conntrack_v6(ctx, l3_offset)
    } else {
        Ok(TC_ACT_OK)
    }
}

/// IPv4 connection tracking: lookup/insert/update state machine.
#[inline(always)]
fn process_conntrack_v4(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto } as u8;

    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    let l4_offset = l3_offset + ihl;

    // Parse L4 ports and TCP flags
    let (src_port, dst_port, tcp_flag_bits) = match protocol {
        PROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            let flags = tcp_flags(unsafe { &*tcphdr });
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
                flags,
            )
        }
        PROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
                0u8,
            )
        }
        PROTO_ICMP => (0u16, 0u16, 0u8),
        _ => return Ok(TC_ACT_OK),
    };

    let ct_key = normalize_key_v4(src_ip, dst_ip, src_port, dst_port, protocol);
    let now = unsafe { bpf_ktime_get_boot_ns() };

    increment_metric(CT_METRIC_LOOKUPS);

    // Determine if this packet is in the "forward" direction (src is the
    // lower IP:port pair in the normalized key).
    let is_forward = ct_key.src_ip == src_ip && ct_key.src_port == src_port;
    let pkt_len = (ctx.data_end() - ctx.data()) as u32;

    if let Some(entry) = CT_TABLE_V4.get_ptr_mut(&ct_key) {
        // Existing connection — update
        increment_metric(CT_METRIC_HITS);
        unsafe {
            (*entry).last_seen_ns = now;

            // Update counters
            if is_forward {
                (*entry).packets_fwd = (*entry).packets_fwd.wrapping_add(1);
                (*entry).bytes_fwd = (*entry).bytes_fwd.wrapping_add(pkt_len);
            } else {
                (*entry).packets_rev = (*entry).packets_rev.wrapping_add(1);
                (*entry).bytes_rev = (*entry).bytes_rev.wrapping_add(pkt_len);
                (*entry).flags |= CT_FLAG_SEEN_REPLY;
            }

            // TCP state machine
            if protocol == PROTO_TCP {
                advance_tcp_state(entry, tcp_flag_bits, is_forward);
            } else if protocol == PROTO_UDP && (*entry).flags & CT_FLAG_SEEN_REPLY != 0 {
                // UDP "stream": bidirectional traffic seen
                (*entry).state = CT_STATE_ESTABLISHED;
                (*entry).flags |= CT_FLAG_ASSURED;
            }
        }
    } else {
        // New connection — insert
        let state = if protocol == PROTO_TCP {
            // Only create entry on SYN
            if tcp_flag_bits & TCP_SYN != 0 && tcp_flag_bits & TCP_ACK == 0 {
                CT_STATE_SYN_SENT
            } else {
                increment_metric(CT_METRIC_INVALID);
                return Ok(TC_ACT_OK);
            }
        } else {
            CT_STATE_NEW
        };

        let new_entry = ConnValue {
            state,
            flags: 0,
            nat_type: 0,
            _pad: 0,
            packets_fwd: 1,
            packets_rev: 0,
            bytes_fwd: pkt_len,
            bytes_rev: 0,
            first_seen_ns: now,
            last_seen_ns: now,
            nat_addr: 0,
            nat_port: 0,
            _pad2: [0; 2],
        };

        let _ = CT_TABLE_V4.insert(&ct_key, &new_entry, 0);
        increment_metric(CT_METRIC_NEW);
    }

    Ok(TC_ACT_OK)
}

/// IPv6 connection tracking: lookup/insert/update state machine.
#[inline(never)]
fn process_conntrack_v6(ctx: &TcContext, l3_offset: usize) -> Result<i32, ()> {
    let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).src_addr });
    let dst_addr = ipv6_addr_to_u32x4(unsafe { &(*ipv6hdr).dst_addr });
    let raw_protocol = unsafe { (*ipv6hdr).next_hdr };

    // Skip IPv6 extension headers to find the actual L4 protocol.
    let (protocol, l4_offset) = skip_ipv6_ext_headers(ctx, l3_offset + IPV6_HDR_LEN, raw_protocol)
        .ok_or(())?;

    let (src_port, dst_port, tcp_flag_bits) = match protocol {
        PROTO_TCP => {
            let tcphdr: *const TcpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            let flags = tcp_flags(unsafe { &*tcphdr });
            (
                u16_from_be_bytes(unsafe { (*tcphdr).source }),
                u16_from_be_bytes(unsafe { (*tcphdr).dest }),
                flags,
            )
        }
        PROTO_UDP => {
            let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, l4_offset)? };
            (
                u16_from_be_bytes(unsafe { (*udphdr).src }),
                u16_from_be_bytes(unsafe { (*udphdr).dst }),
                0u8,
            )
        }
        PROTO_ICMPV6 => (0u16, 0u16, 0u8),
        _ => return Ok(TC_ACT_OK),
    };

    let ct_key = normalize_key_v6(&src_addr, &dst_addr, src_port, dst_port, protocol);
    let now = unsafe { bpf_ktime_get_boot_ns() };

    increment_metric(CT_METRIC_LOOKUPS);

    let is_forward = ct_key.src_addr == src_addr && ct_key.src_port == src_port;
    let pkt_len = (ctx.data_end() - ctx.data()) as u32;

    if let Some(entry) = CT_TABLE_V6.get_ptr_mut(&ct_key) {
        increment_metric(CT_METRIC_HITS);
        unsafe {
            (*entry).last_seen_ns = now;

            if is_forward {
                (*entry).packets_fwd = (*entry).packets_fwd.wrapping_add(1);
                (*entry).bytes_fwd = (*entry).bytes_fwd.wrapping_add(pkt_len);
            } else {
                (*entry).packets_rev = (*entry).packets_rev.wrapping_add(1);
                (*entry).bytes_rev = (*entry).bytes_rev.wrapping_add(pkt_len);
                (*entry).flags |= CT_FLAG_SEEN_REPLY;
            }

            if protocol == PROTO_TCP {
                advance_tcp_state_v6(entry, tcp_flag_bits, is_forward);
            } else if protocol == PROTO_UDP && (*entry).flags & CT_FLAG_SEEN_REPLY != 0 {
                (*entry).state = CT_STATE_ESTABLISHED;
                (*entry).flags |= CT_FLAG_ASSURED;
            }
        }
    } else {
        let state = if protocol == PROTO_TCP {
            if tcp_flag_bits & TCP_SYN != 0 && tcp_flag_bits & TCP_ACK == 0 {
                CT_STATE_SYN_SENT
            } else {
                increment_metric(CT_METRIC_INVALID);
                return Ok(TC_ACT_OK);
            }
        } else {
            CT_STATE_NEW
        };

        let new_entry = ConnValueV6 {
            state,
            flags: 0,
            nat_type: 0,
            _pad: 0,
            packets_fwd: 1,
            packets_rev: 0,
            bytes_fwd: pkt_len,
            bytes_rev: 0,
            first_seen_ns: now,
            last_seen_ns: now,
            nat_addr: [0; 4],
            nat_port: 0,
            _pad2: [0; 2],
        };

        let _ = CT_TABLE_V6.insert(&ct_key, &new_entry, 0);
        increment_metric(CT_METRIC_NEW);
    }

    Ok(TC_ACT_OK)
}

/// Shared TCP state machine logic for both IPv4 and IPv6 connections.
///
/// Operates on raw pointers to `state` and `flags` fields, which are at the
/// same conceptual position in both `ConnValue` and `ConnValueV6`.
#[inline(always)]
unsafe fn advance_tcp_state_inner(state: *mut u8, flags: *mut u8, tcp_flags: u8, is_forward: bool) {
    unsafe {
        let current = *state;

        if tcp_flags & TCP_RST != 0 {
            *state = CT_STATE_INVALID;
            return;
        }

        match current {
            CT_STATE_SYN_SENT => {
                if !is_forward && tcp_flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) {
                    *state = CT_STATE_SYN_RECV;
                    *flags |= CT_FLAG_SEEN_REPLY;
                }
            }
            CT_STATE_SYN_RECV => {
                if is_forward && tcp_flags & TCP_ACK != 0 {
                    *state = CT_STATE_ESTABLISHED;
                    *flags |= CT_FLAG_ASSURED;
                    increment_metric(CT_METRIC_ESTABLISHED);
                }
            }
            CT_STATE_ESTABLISHED => {
                if tcp_flags & TCP_FIN != 0 {
                    if is_forward {
                        *state = CT_STATE_FIN_WAIT;
                    } else {
                        *state = CT_STATE_CLOSE_WAIT;
                    }
                }
            }
            CT_STATE_FIN_WAIT => {
                if !is_forward && tcp_flags & TCP_FIN != 0 {
                    *state = CT_STATE_TIME_WAIT;
                }
            }
            CT_STATE_CLOSE_WAIT => {
                if is_forward && tcp_flags & TCP_FIN != 0 {
                    *state = CT_STATE_TIME_WAIT;
                }
            }
            _ => {}
        }
    }
}

/// Advance the TCP state machine based on observed flags (IPv4).
#[inline(always)]
unsafe fn advance_tcp_state(entry: *mut ConnValue, tcp_flags: u8, is_forward: bool) {
    unsafe {
        advance_tcp_state_inner(
            &raw mut (*entry).state,
            &raw mut (*entry).flags,
            tcp_flags,
            is_forward,
        );
    }
}

/// Advance the TCP state machine for IPv6 connections.
#[inline(always)]
unsafe fn advance_tcp_state_v6(entry: *mut ConnValueV6, tcp_flags: u8, is_forward: bool) {
    unsafe {
        advance_tcp_state_inner(
            &raw mut (*entry).state,
            &raw mut (*entry).flags,
            tcp_flags,
            is_forward,
        );
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
