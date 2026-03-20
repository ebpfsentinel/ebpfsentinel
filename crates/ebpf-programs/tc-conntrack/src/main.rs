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
    CT_FLAG_SEEN_REPLY, CT_MAX_ENTRIES_V4, CT_MAX_ENTRIES_V6, CT_METRIC_CLOSED, CT_METRIC_COUNT,
    CT_METRIC_ERRORS, CT_METRIC_ESTABLISHED, CT_METRIC_HITS, CT_METRIC_INVALID, CT_METRIC_LOOKUPS,
    CT_METRIC_NEW, CT_METRIC_TOTAL_SEEN,
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
///
/// Flag `2` = `BPF_F_NO_COMMON_LRU`: enables per-CPU LRU lists instead of the
/// shared global LRU list. This eliminates cross-CPU spinlock contention on the
/// LRU eviction path at the cost of slightly less accurate LRU ordering across
/// CPUs — an acceptable trade-off for high-throughput per-flow workloads.
///
/// # Race conditions (F5)
/// LRU maps in eBPF are CPU-local in the kernel's per-CPU hash implementation.
/// On RSS-enabled NICs, all packets of a given 5-tuple are steered to the same
/// CPU queue, making per-flow entries effectively CPU-private and race-free in
/// the common case. Multi-queue rebalancing (rare, triggered by NIC reset or
/// `ethtool -X` reconfiguration) can cause two CPUs to operate on the same
/// logical flow simultaneously; byte/packet counters may then undercount by a
/// small amount. This trade-off is acceptable because the counters are used for
/// monitoring only — not for admission control or billing decisions. Userspace
/// GC reads are protected by the map's internal spinlock.
#[map]
static CT_TABLE_V4: LruHashMap<ConnKey, ConnValue> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V4, 2); // 2 = BPF_F_NO_COMMON_LRU

/// IPv6 connection tracking table.
/// Pinned at /sys/fs/bpf/ebpfsentinel/ct_table_v6 for sharing.
/// (See CT_TABLE_V4 for the race-condition and BPF_F_NO_COMMON_LRU rationale.)
#[map]
static CT_TABLE_V6: LruHashMap<ConnKeyV6, ConnValueV6> =
    LruHashMap::with_max_entries(CT_MAX_ENTRIES_V6, 2); // 2 = BPF_F_NO_COMMON_LRU

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

/// Select the appropriate timeout in nanoseconds based on protocol and
/// connection state.  Returns 0 if the config entry is missing (disabled).
#[inline(always)]
fn select_timeout(state: u8, protocol: u8, config: &ConnTrackConfig) -> u64 {
    match protocol {
        PROTO_UDP => config.udp_timeout_ns,
        PROTO_ICMP | PROTO_ICMPV6 => config.icmp_timeout_ns,
        PROTO_TCP => match state {
            CT_STATE_SYN_SENT | CT_STATE_SYN_RECV => config.tcp_syn_timeout_ns,
            CT_STATE_ESTABLISHED => config.tcp_established_timeout_ns,
            CT_STATE_FIN_WAIT | CT_STATE_CLOSE_WAIT | CT_STATE_TIME_WAIT => {
                config.tcp_fin_timeout_ns
            }
            _ => config.tcp_established_timeout_ns,
        },
        _ => config.tcp_established_timeout_ns,
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
    // Per-protocol handlers read the full config and check the enabled flag
    // themselves so they can also access timeout values in one map lookup.
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
    // Read the full config once — needed for timeout values.
    let ct_config = match CT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_OK),
    };

    if ct_config.enabled == 0 {
        return Ok(TC_ACT_OK);
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, l3_offset)? };
    let src_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).src_addr });
    let dst_ip = u32_from_be_bytes(unsafe { (*ipv4hdr).dst_addr });
    let protocol = unsafe { (*ipv4hdr).proto } as u8;

    let ihl = unsafe { (*ipv4hdr).ihl() } as usize;
    // F2: Reject crafted packets with IHL < 5 words (20 bytes); they would
    // cause the L4 header pointer to land inside the IP header itself.
    if ihl < 20 {
        return Ok(TC_ACT_OK);
    }
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
        // F6: Use ICMP type and code as pseudo-ports so distinct ICMP flows
        // (e.g. echo vs. unreachable) get separate conntrack entries instead
        // of collapsing onto a single (0,0) key.
        PROTO_ICMP => {
            let icmp_type_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset)? };
            let icmp_code_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset + 1)? };
            let icmp_type = unsafe { *icmp_type_ptr } as u16;
            let icmp_code = unsafe { *icmp_code_ptr } as u16;
            (icmp_type, icmp_code, 0u8)
        }
        _ => return Ok(TC_ACT_OK),
    };

    let ct_key = normalize_key_v4(src_ip, dst_ip, src_port, dst_port, protocol);
    let now = unsafe { bpf_ktime_get_boot_ns() };

    increment_metric(CT_METRIC_LOOKUPS);

    // Determine if this packet is in the "forward" direction (src is the
    // lower IP:port pair in the normalized key).
    let is_forward = ct_key.src_ip == src_ip && ct_key.src_port == src_port;
    let pkt_len = (ctx.data_end() - ctx.data()) as u32;

    // Whether we need to insert a fresh entry (set to true when a stale entry
    // is lazily evicted, causing the packet to be treated as a new connection).
    let mut insert_new = false;

    if let Some(entry) = CT_TABLE_V4.get_ptr_mut(&ct_key) {
        // Lazy timeout eviction: check whether this entry has expired before
        // updating it.  Stale entries are deleted on access so the LRU
        // backstop remains accurate and the next packet creates a fresh entry.
        let (entry_state, elapsed) = unsafe { ((*entry).state, now.saturating_sub((*entry).last_seen_ns)) };
        let timeout = select_timeout(entry_state, protocol, ct_config);

        if timeout > 0 && elapsed > timeout {
            // Entry is stale — evict and treat this packet as a new connection.
            let _ = CT_TABLE_V4.remove(&ct_key);
            increment_metric(CT_METRIC_CLOSED);
            insert_new = true;
        } else {
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
        }
    } else {
        insert_new = true;
    }

    if insert_new {
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
    // Read the full config once — needed for timeout values.
    let ct_config = match CT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return Ok(TC_ACT_OK),
    };

    if ct_config.enabled == 0 {
        return Ok(TC_ACT_OK);
    }

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
        // F6: Use ICMPv6 type and code as pseudo-ports (same rationale as IPv4 ICMP).
        PROTO_ICMPV6 => {
            let icmp_type_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset)? };
            let icmp_code_ptr: *const u8 = unsafe { ptr_at(ctx, l4_offset + 1)? };
            let icmp_type = unsafe { *icmp_type_ptr } as u16;
            let icmp_code = unsafe { *icmp_code_ptr } as u16;
            (icmp_type, icmp_code, 0u8)
        }
        _ => return Ok(TC_ACT_OK),
    };

    let ct_key = normalize_key_v6(&src_addr, &dst_addr, src_port, dst_port, protocol);
    let now = unsafe { bpf_ktime_get_boot_ns() };

    increment_metric(CT_METRIC_LOOKUPS);

    let is_forward = ct_key.src_addr == src_addr && ct_key.src_port == src_port;
    let pkt_len = (ctx.data_end() - ctx.data()) as u32;

    // Whether we need to insert a fresh entry (set to true when a stale entry
    // is lazily evicted, causing the packet to be treated as a new connection).
    let mut insert_new = false;

    if let Some(entry) = CT_TABLE_V6.get_ptr_mut(&ct_key) {
        // Lazy timeout eviction: check whether this entry has expired before
        // updating it.  Stale entries are deleted on access so the LRU
        // backstop remains accurate and the next packet creates a fresh entry.
        let (entry_state, elapsed) = unsafe { ((*entry).state, now.saturating_sub((*entry).last_seen_ns)) };
        let timeout = select_timeout(entry_state, protocol, ct_config);

        if timeout > 0 && elapsed > timeout {
            // Entry is stale — evict and treat this packet as a new connection.
            let _ = CT_TABLE_V6.remove(&ct_key);
            increment_metric(CT_METRIC_CLOSED);
            insert_new = true;
        } else {
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
        }
    } else {
        insert_new = true;
    }

    if insert_new {
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
///
/// # Timeout enforcement (F3 / Wave 3)
/// Lazy eviction is performed on every lookup: `process_conntrack_v4` and
/// `process_conntrack_v6` compare `last_seen_ns` against `now - timeout_ns`
/// (selected by `select_timeout`) before updating an existing entry.  Stale
/// entries are deleted via `CT_TABLE_V{4,6}.remove` and the arriving packet
/// is treated as a new connection.  The `LruHashMap` (with
/// `BPF_F_NO_COMMON_LRU`) still provides a hard backstop, evicting the
/// least-recently-used entry when the table fills.  Userspace GC remains as a
/// belt-and-suspenders cleanup pass for long-idle entries that never receive
/// another packet to trigger lazy eviction.
///
/// # Race conditions (F5)
/// All mutations of a conntrack entry happen via `get_ptr_mut`, which returns
/// a CPU-local pointer in eBPF's per-CPU hash model. On multi-queue NICs with
/// RSS, the kernel routes all packets of a given flow to the same CPU/queue,
/// so the same entry is effectively CPU-private for the lifetime of a flow.
/// Counters (`packets_fwd`, `bytes_fwd`, etc.) may undercount marginally if
/// RSS reassigns a flow mid-stream (e.g., after NIC reset or queue resize),
/// which is acceptable given the monitoring-only nature of these counters.
#[inline(always)]
unsafe fn advance_tcp_state_inner(state: *mut u8, flags: *mut u8, tcp_flags: u8, is_forward: bool) {
    unsafe {
        let current = *state;

        if tcp_flags & TCP_RST != 0 {
            // F7: RST resets the connection — count it as closed.
            *state = CT_STATE_INVALID;
            increment_metric(CT_METRIC_CLOSED);
            return;
        }

        match current {
            CT_STATE_SYN_SENT => {
                if !is_forward && tcp_flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) {
                    // Normal three-way handshake: server replied SYN+ACK.
                    *state = CT_STATE_SYN_RECV;
                    *flags |= CT_FLAG_SEEN_REPLY;
                }
                // F4: Simultaneous open — reverse SYN without ACK means the
                // peer also sent a SYN before receiving ours (RFC 793 §3.4).
                // Transition to SYN_RECV so the subsequent ACKs complete the
                // handshake through the normal CT_STATE_SYN_RECV arm.
                if !is_forward && (tcp_flags & TCP_SYN != 0) && (tcp_flags & TCP_ACK == 0) {
                    *state = CT_STATE_SYN_RECV;
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
                    // F7: Both sides have FINed — connection is closing.
                    *state = CT_STATE_TIME_WAIT;
                    increment_metric(CT_METRIC_CLOSED);
                }
            }
            CT_STATE_CLOSE_WAIT => {
                if is_forward && tcp_flags & TCP_FIN != 0 {
                    // F7: Both sides have FINed — connection is closing.
                    *state = CT_STATE_TIME_WAIT;
                    increment_metric(CT_METRIC_CLOSED);
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
