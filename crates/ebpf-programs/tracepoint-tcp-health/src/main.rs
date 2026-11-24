//! Counting the health of TCP connections, per edge.
//!
//! Four raw tracepoints of the TCP stack, each adding one to a per-CPU
//! counter keyed by the edge the connection runs on: the two addresses, the
//! service port and the cgroup of the local socket. Nothing leaves the
//! kernel but the counters, so a retransmission storm or a reset flood costs
//! a hash update per event rather than a ring buffer the agent has to drain.
//! The same state changes sample the socket's smoothed round-trip time into a
//! histogram under the same edge, and a `sock_ops` program times each write
//! from the kernel's own timestamps where the host runs it.

#![no_std]
#![no_main]
#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]

use aya_ebpf::{
    btf_maps::{Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap},
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, generated},
    macros::{btf_map, raw_tracepoint, sock_ops},
    programs::{RawTracePointContext, SockOpsContext},
};
use ebpf_common::tcp_health::{
    BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
    BPF_SOCK_OPS_TSTAMP_SENDMSG_CB, SK_BPF_CB_FLAGS, SK_BPF_CB_TX_TIMESTAMPING,
    TCP_HEALTH_AF_INET, TCP_HEALTH_AF_INET6, TCP_HEALTH_IPPROTO_TCP, TCP_HEALTH_MAX_KEYS,
    TCP_HEALTH_METRIC_COUNT, TCP_HEALTH_METRIC_COUNTED, TCP_HEALTH_METRIC_KEYS_FULL,
    TCP_HEALTH_METRIC_SEND_REFUSED, TCP_HEALTH_METRIC_UNCONFIGURED, TCP_HEALTH_METRIC_UNREADABLE,
    TCP_HEALTH_SOL_SOCKET, TCP_RTT_BUCKETS, TCP_SEND_MAX_PENDING, TCP_SEND_STAGE_ACKED,
    TCP_SEND_STAGES, TCP_STATE_ESTABLISHED, TCP_STATE_NEW_SYN_RECV, TCP_STATE_TIME_WAIT,
    TcpEdgeCounts, TcpEdgeKey, TcpEdgeRtt, TcpEdgeSend, TcpHealthConfig, TcpSendPending,
    Transition, rtt_bucket, send_in_flight, send_stage, service_port, transition,
};
use ebpf_helpers::{
    increment_metric,
    kfuncs::{sock_ops_enable_tx_tstamp, sock_ops_kern_ctx},
};

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

/// Round-trip time samples per edge, shared by every CPU and added to
/// atomically. Keyed like `TCP_EDGES` and never evicted, for the same reason.
#[btf_map]
static TCP_RTT: HashMap<TcpEdgeKey, TcpEdgeRtt, { TCP_HEALTH_MAX_KEYS as usize }> = HashMap::new();

/// Timed writes per edge, one histogram per stage, shared by every CPU and
/// added to atomically. Keyed like `TCP_EDGES` and never evicted.
#[btf_map]
static TCP_SEND: HashMap<TcpEdgeKey, TcpEdgeSend, { TCP_HEALTH_MAX_KEYS as usize }> =
    HashMap::new();

/// One zeroed histogram set, never written: what a new edge in `TCP_SEND`
/// is inserted from, since 432 bytes do not fit on the program's stack.
#[btf_map]
static TCP_SEND_ZERO: Array<TcpEdgeSend, 1> = Array::new();

/// The write each socket has in flight, by socket cookie. An LRU: a socket
/// that closed with a write never acknowledged leaves nothing behind.
#[btf_map]
static TCP_SEND_PENDING: LruHashMap<u64, TcpSendPending, { TCP_SEND_MAX_PENDING as usize }> =
    LruHashMap::new();

/// Per-CPU counters. Index: 0=counted, 1=keys_full, 2=unconfigured,
/// 3=unreadable, 4=send_refused.
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
///
/// Reaching `ESTABLISHED` and leaving it are also the two moments the
/// round-trip time is sampled: the handshake's measure, and the estimate the
/// connection ended with.
#[raw_tracepoint(tracepoint = "inet_sock_set_state")]
pub fn tcp_health_set_state(ctx: RawTracePointContext) -> i32 {
    let old = ctx.arg::<u64>(1) as u32;
    let new = ctx.arg::<u64>(2) as u32;
    let counter = match transition(old, new) {
        Transition::Opened => Some(Counter::Opened),
        Transition::Closed => Some(Counter::Closed),
        Transition::Failed => Some(Counter::Failed),
        Transition::None => None,
    };
    let sample = old == TCP_STATE_ESTABLISHED || new == TCP_STATE_ESTABLISHED;
    if counter.is_none() && !sample {
        return 0;
    }
    let sk = ctx.arg::<u64>(0);
    let Some(config) = config() else {
        return 0;
    };
    // The tracepoint fires for every inet protocol that keeps a state.
    let protocol = read_u16(sk + u64::from(config.sk_protocol));
    if protocol != Ok(TCP_HEALTH_IPPROTO_TCP) {
        return 0;
    }
    let Ok(key) = key_of_socket(sk, &config) else {
        increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE);
        return 0;
    };
    if let Some(counter) = counter {
        add(&key, counter);
    }
    if sample {
        // Only a full socket is ever established, so `tcp_sock` is there.
        match read_u32(sk + u64::from(config.tcp_srtt_us)) {
            // Zero is a socket that has not measured anything yet.
            Ok(0) => {}
            Ok(srtt) => add_rtt(&key, u64::from(srtt >> 3)),
            Err(()) => increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE),
        }
    }
    0
}

/// Time writes with the kernel's own timestamps, attached to a cgroup.
///
/// An established connection opts in; each write the application hands over
/// while none is in flight on its socket is tagged, and the callbacks the tag
/// turns on add the time since to the edge's histograms. A write handed over
/// while another is in flight is not timed, so each socket costs one entry
/// and one tag at a time.
#[sock_ops]
pub fn tcp_health_send_timestamps(ctx: SockOpsContext) -> u32 {
    match ctx.op() {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => opt_in(&ctx),
        BPF_SOCK_OPS_TSTAMP_SENDMSG_CB => tag_write(&ctx),
        op => {
            if let Some(stage) = send_stage(op) {
                time_stage(&ctx, stage);
            }
        }
    }
    // One is what every attached `sock_ops` program answers when it lets the
    // socket through; none of the callbacks used here reads a reply.
    1
}

/// Turn the timestamp callbacks on for a connection that came up.
#[inline(always)]
fn opt_in(ctx: &SockOpsContext) {
    let mut flags: i32 = SK_BPF_CB_TX_TIMESTAMPING;
    // SAFETY: `ctx.ops` is the live context of this callback and `flags` a
    // stack word of the length given.
    let rc = unsafe {
        generated::bpf_setsockopt(
            ctx.ops.cast(),
            TCP_HEALTH_SOL_SOCKET,
            SK_BPF_CB_FLAGS,
            (&raw mut flags).cast(),
            4,
        )
    };
    if rc != 0 {
        increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_SEND_REFUSED);
    }
}

/// Tag the write being handed over, unless one is still in flight.
#[inline(always)]
fn tag_write(ctx: &SockOpsContext) {
    // SAFETY: `ctx.ops` is the live context of this callback.
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.ops.cast()) };
    if cookie == 0 {
        return;
    }
    // SAFETY: the helper takes no argument.
    let now = unsafe { bpf_ktime_get_ns() };
    if let Some(pending) = TCP_SEND_PENDING.get_ptr(&cookie) {
        // SAFETY: a map value pointer the lookup returned.
        if send_in_flight(unsafe { (*pending).since_ns }, now) {
            return;
        }
    }
    let Some(config) = config() else {
        return;
    };
    // SAFETY: the context of this `sock_ops` invocation.
    let kern = unsafe { sock_ops_kern_ctx(ctx.ops.cast()) };
    if kern.is_null() {
        return;
    }
    // The socket is the first word of `struct bpf_sock_ops_kern`.
    let Ok(sk) = read_u64(kern as u64) else {
        increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE);
        return;
    };
    let Ok(key) = key_of_socket(sk, &config) else {
        increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_UNREADABLE);
        return;
    };
    // SAFETY: `kern` came from this invocation's context.
    if unsafe { sock_ops_enable_tx_tstamp(kern) }.is_err() {
        increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_SEND_REFUSED);
        return;
    }
    let pending = TcpSendPending {
        since_ns: now,
        key,
        timed: 0,
        _pad: [0; 7],
    };
    if TCP_SEND_PENDING.insert(&cookie, &pending, 0).is_err() {
        increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_KEYS_FULL);
    }
}

/// Add the time since the write was handed over to the stage a callback
/// closes. A stage is timed once per write, a segment sent again passing the
/// same stages again; the acknowledgement ends the write.
#[inline(always)]
fn time_stage(ctx: &SockOpsContext, stage: usize) {
    if stage >= TCP_SEND_STAGES {
        return;
    }
    // SAFETY: `ctx.ops` is the live context of this callback.
    let cookie = unsafe { generated::bpf_get_socket_cookie(ctx.ops.cast()) };
    let Some(pending) = TCP_SEND_PENDING.get_ptr_mut(&cookie) else {
        return;
    };
    let bit = 1u8 << stage;
    // SAFETY: a map value pointer the lookup returned. A callback for the
    // same socket on another CPU can at worst time a stage twice.
    let (since, key, timed) = unsafe { ((*pending).since_ns, (*pending).key, (*pending).timed) };
    if timed & bit == 0 {
        // SAFETY: as above.
        unsafe { (*pending).timed = timed | bit };
        // SAFETY: the helper takes no argument.
        let now = unsafe { bpf_ktime_get_ns() };
        if now >= since {
            add_send(&key, stage, (now - since) / 1_000);
        }
    }
    if stage == TCP_SEND_STAGE_ACKED {
        let _ = TCP_SEND_PENDING.remove(&cookie);
    }
}

/// Add one sample of `us` microseconds to `stage` under `key`.
#[inline(always)]
fn add_send(key: &TcpEdgeKey, stage: usize, us: u64) {
    let send = match TCP_SEND.get_ptr_mut(key) {
        Some(send) => send,
        None => {
            let Some(zero) = TCP_SEND_ZERO.get(0) else {
                return;
            };
            let _ = TCP_SEND.insert(key, zero, BPF_NOEXIST);
            match TCP_SEND.get_ptr_mut(key) {
                Some(send) => send,
                None => {
                    increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_KEYS_FULL);
                    return;
                }
            }
        }
    };
    if stage >= TCP_SEND_STAGES {
        return;
    }
    // SAFETY: `send` is a live map value and `stage` is in bounds.
    record(unsafe { &raw mut (*send).stages[stage] }, us);
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

/// Add one round-trip time sample of `us` microseconds under `key`.
#[inline(always)]
fn add_rtt(key: &TcpEdgeKey, us: u64) {
    let rtt = match TCP_RTT.get_ptr_mut(key) {
        Some(rtt) => rtt,
        None => {
            // Inserted empty and then added to like any other, so two CPUs
            // racing on the first sample both land in the one entry.
            let _ = TCP_RTT.insert(key, &TcpEdgeRtt::default(), BPF_NOEXIST);
            match TCP_RTT.get_ptr_mut(key) {
                Some(rtt) => rtt,
                None => {
                    increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_KEYS_FULL);
                    return;
                }
            }
        }
    };
    record(rtt, us);
}

/// Add one sample of `us` microseconds to the histogram at `rtt`.
#[inline(always)]
fn record(rtt: *mut TcpEdgeRtt, us: u64) {
    let bucket = rtt_bucket(us);
    if bucket >= TCP_RTT_BUCKETS {
        return;
    }
    // SAFETY: the pointer is a live map value for the length of this
    // program, and every write to it goes through these atomic adds.
    unsafe {
        atomic_add(&raw mut (*rtt).buckets[bucket], 1);
        atomic_add(&raw mut (*rtt).sum_us, us);
        atomic_add(&raw mut (*rtt).count, 1);
    }
    increment_metric!(TCP_HEALTH_METRICS, TCP_HEALTH_METRIC_COUNTED);
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
