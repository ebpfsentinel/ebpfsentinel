//! Counting the health of TCP connections, per edge.
//!
//! Four raw tracepoints of the TCP stack, each adding one to a per-CPU
//! counter keyed by the edge the connection runs on: the two addresses, the
//! service port and the cgroup of the local socket. Nothing leaves the
//! kernel but the counters, so a retransmission storm or a reset flood costs
//! a hash update per event rather than a ring buffer the agent has to drain.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, PerCpuArray, PerCpuHashMap},
    helpers::bpf_probe_read_kernel,
    macros::{btf_map, raw_tracepoint},
    programs::RawTracePointContext,
};
use ebpf_common::tcp_health::{
    TCP_HEALTH_AF_INET, TCP_HEALTH_AF_INET6, TCP_HEALTH_IPPROTO_TCP, TCP_HEALTH_MAX_KEYS,
    TCP_HEALTH_METRIC_COUNT, TCP_HEALTH_METRIC_COUNTED, TCP_HEALTH_METRIC_KEYS_FULL,
    TCP_HEALTH_METRIC_UNCONFIGURED, TCP_HEALTH_METRIC_UNREADABLE, TCP_STATE_NEW_SYN_RECV,
    TCP_STATE_TIME_WAIT, TcpEdgeCounts, TcpEdgeKey, TcpHealthConfig, Transition, service_port,
    transition,
};
use ebpf_helpers::increment_metric;

/// `BPF_NOEXIST`: insert only when the key is absent.
const BPF_NOEXIST: u64 = 1;

/// The counter an event adds to.
#[derive(Clone, Copy)]
enum Counter {
    Retransmit,
    ResetSent,
    ResetReceived,
    Opened,
    Closed,
    Failed,
}

// ── Maps ────────────────────────────────────────────────────────────

/// Offsets of the running kernel, written by userspace from BTF before the
/// tracepoints are attached.
#[btf_map]
static TCP_HEALTH_CONFIG: Array<TcpHealthConfig, 1> = Array::new();

/// Counts per edge, summed over the CPUs by userspace.
///
/// A plain hash rather than an LRU: an eviction would make a counter go
/// backwards, which a reader takes for a restart. A full map is counted.
#[btf_map]
static TCP_EDGES: PerCpuHashMap<TcpEdgeKey, TcpEdgeCounts, { TCP_HEALTH_MAX_KEYS as usize }> =
    PerCpuHashMap::new();

/// Per-CPU counters. Index: 0=counted, 1=keys_full, 2=unconfigured,
/// 3=unreadable.
#[btf_map]
static TCP_HEALTH_METRICS: PerCpuArray<u64, { TCP_HEALTH_METRIC_COUNT as usize }> =
    PerCpuArray::new();

// ── Programs ────────────────────────────────────────────────────────

/// A segment is sent again. `TP_PROTO(sk, skb, err)`.
#[raw_tracepoint(tracepoint = "tcp_retransmit_skb")]
pub fn tcp_health_retransmit(ctx: RawTracePointContext) -> i32 {
    count_on_socket(ctx.arg::<u64>(0), Counter::Retransmit);
    0
}

/// This node sends a reset. `TP_PROTO(sk, skb, reason)`.
///
/// Without a socket the reset answers a segment nobody was there to take,
/// and the edge is read off that segment with no service port.
#[raw_tracepoint(tracepoint = "tcp_send_reset")]
pub fn tcp_health_send_reset(ctx: RawTracePointContext) -> i32 {
    let sk = ctx.arg::<u64>(0);
    if sk != 0 {
        count_on_socket(sk, Counter::ResetSent);
        return 0;
    }
    let Some(config) = config() else {
        return 0;
    };
    match key_of_segment(ctx.arg::<u64>(1), &config) {
        Ok(key) => add(&key, Counter::ResetSent),
        Err(()) => increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE),
    }
    0
}

/// This node receives a reset. `TP_PROTO(sk)`.
#[raw_tracepoint(tracepoint = "tcp_receive_reset")]
pub fn tcp_health_receive_reset(ctx: RawTracePointContext) -> i32 {
    count_on_socket(ctx.arg::<u64>(0), Counter::ResetReceived);
    0
}

/// A socket changes state. `TP_PROTO(sk, oldstate, newstate)`.
#[raw_tracepoint(tracepoint = "inet_sock_set_state")]
pub fn tcp_health_set_state(ctx: RawTracePointContext) -> i32 {
    let counter = match transition(ctx.arg::<u64>(1) as u32, ctx.arg::<u64>(2) as u32) {
        Transition::Opened => Counter::Opened,
        Transition::Closed => Counter::Closed,
        Transition::Failed => Counter::Failed,
        Transition::None => return 0,
    };
    let sk = ctx.arg::<u64>(0);
    let Some(config) = config() else {
        return 0;
    };
    // The tracepoint fires for every inet protocol that keeps a state.
    let protocol = read_u16(sk + u64::from(config.sk_protocol));
    if protocol != Ok(TCP_HEALTH_IPPROTO_TCP) {
        return 0;
    }
    match key_of_socket(sk, &config) {
        Ok(key) => add(&key, counter),
        Err(()) => increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE),
    }
    0
}

// ── Helpers ─────────────────────────────────────────────────────────

/// The configuration, or `None` after counting that it was not written.
#[inline(always)]
fn config() -> Option<TcpHealthConfig> {
    match TCP_HEALTH_CONFIG.get(0).copied() {
        Some(config) if config.ready != 0 => Some(config),
        _ => {
            increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNCONFIGURED);
            None
        }
    }
}

#[inline(always)]
fn count_on_socket(sk: u64, counter: Counter) {
    let Some(config) = config() else {
        return;
    };
    match key_of_socket(sk, &config) {
        Ok(key) => add(&key, counter),
        Err(()) => increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE),
    }
}

#[inline(always)]
fn add(key: &TcpEdgeKey, counter: Counter) {
    if let Some(counts) = TCP_EDGES.get_ptr_mut(key) {
        // Per-CPU value: no other CPU writes this slot.
        bump(unsafe { &mut *counts }, counter);
    } else {
        let mut first = TcpEdgeCounts::default();
        bump(&mut first, counter);
        if TCP_EDGES.insert(key, &first, BPF_NOEXIST).is_err() {
            // Another CPU may have inserted the edge between the lookup and
            // the insert, which leaves this CPU's slot zeroed and ready.
            match TCP_EDGES.get_ptr_mut(key) {
                Some(counts) => bump(unsafe { &mut *counts }, counter),
                None => {
                    increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_KEYS_FULL);
                    return;
                }
            }
        }
    }
    increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_COUNTED);
}

#[inline(always)]
fn bump(counts: &mut TcpEdgeCounts, counter: Counter) {
    match counter {
        Counter::Retransmit => counts.retransmits += 1,
        Counter::ResetSent => counts.resets_sent += 1,
        Counter::ResetReceived => counts.resets_received += 1,
        Counter::Opened => counts.opened += 1,
        Counter::Closed => counts.closed += 1,
        Counter::Failed => counts.failed += 1,
    }
}

/// The edge a socket runs on. A time-wait or request socket shares only
/// `sock_common` with a full one, so its cgroup is not read.
#[inline(always)]
fn key_of_socket(sk: u64, config: &TcpHealthConfig) -> Result<TcpEdgeKey, ()> {
    if sk == 0 {
        return Err(());
    }
    let common = sk + u64::from(config.sk_common);
    let family = read_u16(common + u64::from(config.skc_family))?;
    let state = u32::from(read_u8(common + u64::from(config.skc_state))?);
    let mut local_port = read_u16(common + u64::from(config.skc_num))?;
    // A full socket moving to `CLOSE` has had its port released already;
    // its source port is still there. A time-wait or request socket has no
    // `inet_sock` behind `sock_common`, and keeps its number.
    if local_port == 0 && state != TCP_STATE_TIME_WAIT && state != TCP_STATE_NEW_SYN_RECV {
        local_port = u16::from_be(read_u16(sk + u64::from(config.inet_sport))?);
    }
    let remote_port = u16::from_be(read_u16(common + u64::from(config.skc_dport))?);
    let (port, port_is_local) = service_port(local_port, remote_port);
    let mut key = TcpEdgeKey {
        port,
        port_is_local: u8::from(port_is_local),
        ..TcpEdgeKey::default()
    };
    if family == u16::from(TCP_HEALTH_AF_INET) {
        key.family = TCP_HEALTH_AF_INET;
        key.local[0] = host_order(read_u32(common + u64::from(config.skc_rcv_saddr))?);
        key.remote[0] = host_order(read_u32(common + u64::from(config.skc_daddr))?);
    } else if family == u16::from(TCP_HEALTH_AF_INET6) {
        key.family = TCP_HEALTH_AF_INET6;
        let local = common + u64::from(config.skc_v6_rcv_saddr);
        let remote = common + u64::from(config.skc_v6_daddr);
        let mut word = 0usize;
        while word < 4 {
            key.local[word] = host_order(read_u32(local + word as u64 * 4)?);
            key.remote[word] = host_order(read_u32(remote + word as u64 * 4)?);
            word += 1;
        }
    } else {
        return Err(());
    }
    if state != TCP_STATE_TIME_WAIT && state != TCP_STATE_NEW_SYN_RECV {
        key.cgroup = cgroup_of(sk, config);
    }
    Ok(key)
}

/// The cgroup v2 id of a full socket, 0 when any link of the chain is absent.
#[inline(always)]
fn cgroup_of(sk: u64, config: &TcpHealthConfig) -> u64 {
    let data = sk + u64::from(config.sk_cgrp_data);
    let Ok(cgroup) = read_u64(data + u64::from(config.cgrp_data_cgroup)) else {
        return 0;
    };
    if cgroup == 0 {
        return 0;
    }
    let Ok(kn) = read_u64(cgroup + u64::from(config.cgroup_kn)) else {
        return 0;
    };
    if kn == 0 {
        return 0;
    }
    read_u64(kn + u64::from(config.kn_id)).unwrap_or(0)
}

/// The edge of a segment that reached no socket: its destination is the
/// local end and its source the remote one, and there is no service port.
#[inline(always)]
fn key_of_segment(skb: u64, config: &TcpHealthConfig) -> Result<TcpEdgeKey, ()> {
    if skb == 0 {
        return Err(());
    }
    let head = read_u64(skb + u64::from(config.skb_head))?;
    let network = read_u16(skb + u64::from(config.skb_network_header))?;
    if head == 0 || network == u16::MAX {
        return Err(());
    }
    let ip = head + u64::from(network);
    let version = read_u8(ip)? >> 4;
    let mut key = TcpEdgeKey {
        port_is_local: 1,
        ..TcpEdgeKey::default()
    };
    if version == 4 {
        key.family = TCP_HEALTH_AF_INET;
        key.remote[0] = host_order(read_u32(ip + 12)?);
        key.local[0] = host_order(read_u32(ip + 16)?);
    } else if version == 6 {
        key.family = TCP_HEALTH_AF_INET6;
        let mut word = 0usize;
        while word < 4 {
            key.remote[word] = host_order(read_u32(ip + 8 + word as u64 * 4)?);
            key.local[word] = host_order(read_u32(ip + 24 + word as u64 * 4)?);
            word += 1;
        }
    } else {
        return Err(());
    }
    Ok(key)
}

/// The host-order value of a big-endian word, the convention every address
/// in the datapath's maps follows.
#[inline(always)]
fn host_order(raw: u32) -> u32 {
    u32::from_be_bytes(raw.to_ne_bytes())
}

#[inline(always)]
fn read_u8(at: u64) -> Result<u8, ()> {
    unsafe { bpf_probe_read_kernel(at as *const u8) }.map_err(|_| ())
}

#[inline(always)]
fn read_u16(at: u64) -> Result<u16, ()> {
    unsafe { bpf_probe_read_kernel(at as *const u16) }.map_err(|_| ())
}

#[inline(always)]
fn read_u32(at: u64) -> Result<u32, ()> {
    unsafe { bpf_probe_read_kernel(at as *const u32) }.map_err(|_| ())
}

#[inline(always)]
fn read_u64(at: u64) -> Result<u64, ()> {
    unsafe { bpf_probe_read_kernel(at as *const u64) }.map_err(|_| ())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
