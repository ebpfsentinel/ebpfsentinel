//! Counting the packets the kernel drops, under the reason it gives.
//!
//! `kfree_skb` fires for every packet the stack frees without delivering it,
//! with the `skb_drop_reason` the freeing path named. This program adds one
//! to a per-CPU counter keyed by that reason and by the interface the packet
//! was on, and does nothing else: no event leaves the kernel, so the cost of
//! a drop storm is a hash update per packet rather than a ring buffer the
//! agent has to keep up with.
//!
//! Nothing here runs on a delivered packet. The tracepoint sits on the drop
//! path only, and a normal consumption below `first_drop` returns at the
//! first comparison.

#![no_std]
#![no_main]

use aya_ebpf::{
    btf_maps::{Array, HashMap, PerCpuArray, PerCpuHashMap},
    helpers::bpf_probe_read_kernel,
    macros::{btf_map, raw_tracepoint},
    programs::RawTracePointContext,
};
use ebpf_common::drop_reason::{
    DROP_IFNAME_LEN, DROP_METRIC_COUNT, DROP_METRIC_COUNTED, DROP_METRIC_KEYS_FULL,
    DROP_METRIC_UNCONFIGURED, DROP_REASON_MAX_KEYS, DROP_WATCH_MAX, DROP_WORKLOAD_MAX_KEYS,
    DropReasonConfig, DropReasonKey, DropWorkloadKey, counted_reason,
};
use ebpf_helpers::increment_metric;

/// `BPF_NOEXIST`: insert only when the key is absent.
const BPF_NOEXIST: u64 = 1;

// ── Maps ────────────────────────────────────────────────────────────

/// Offsets and the first drop value of the running kernel, written by
/// userspace from BTF before the tracepoint is attached.
#[btf_map]
static DROP_CONFIG: Array<DropReasonConfig, 1> = Array::new();

/// Drops per reason and interface, summed over the CPUs by userspace.
///
/// A plain hash rather than an LRU: an eviction would make a counter go
/// backwards, which a reader takes for a restart. A full map is counted.
#[btf_map]
static DROP_COUNTS: PerCpuHashMap<DropReasonKey, u64, { DROP_REASON_MAX_KEYS as usize }> =
    PerCpuHashMap::new();

/// How many workloads are watched. Read first, so a node investigating
/// nothing pays one array read per drop and no socket walk.
#[btf_map]
static DROP_WATCHING: Array<u32, 1> = Array::new();

/// The cgroups being watched, written by userspace for an investigation's
/// lifetime and removed at its end.
#[btf_map]
static DROP_WATCHED: HashMap<u64, u8, { DROP_WATCH_MAX as usize }> = HashMap::new();

/// Drops per watched workload and reason. Userspace removes a workload's
/// rows when it stops watching it, so the next investigation starts at zero.
#[btf_map]
static DROP_WORKLOADS: PerCpuHashMap<DropWorkloadKey, u64, { DROP_WORKLOAD_MAX_KEYS as usize }> =
    PerCpuHashMap::new();

/// Per-CPU counters. Index: 0=counted, 1=keys_full, 2=unconfigured.
#[btf_map]
static DROP_METRICS: PerCpuArray<u64, { DROP_METRIC_COUNT as usize }> = PerCpuArray::new();

// ── Program ─────────────────────────────────────────────────────────

/// A packet was freed. `TP_PROTO(skb, location, reason, rx_sk)`.
#[raw_tracepoint(tracepoint = "kfree_skb")]
pub fn drop_reason_kfree_skb(ctx: RawTracePointContext) -> i32 {
    let Some(config) = DROP_CONFIG.get(0).copied() else {
        return 0;
    };
    if config.first_drop == 0 {
        increment_metric!(DROP_METRICS, DROP_METRIC_UNCONFIGURED);
        return 0;
    }
    let reason = ctx.arg::<u64>(2) as u32;
    if reason < config.first_drop {
        return 0;
    }
    let reason = counted_reason(reason);
    let skb = ctx.arg::<u64>(0);
    if DROP_WATCHING.get(0).is_some_and(|n| *n != 0) {
        count_workload(reason, skb, ctx.arg::<u64>(3), &config);
    }
    let key = key_of(reason, skb, &config);
    if let Some(count) = DROP_COUNTS.get_ptr_mut(&key) {
        // Per-CPU value: no other CPU writes this slot.
        unsafe { *count += 1 };
    } else if DROP_COUNTS.insert(&key, &1, BPF_NOEXIST).is_err() {
        // Another CPU may have inserted the pair between the lookup and the
        // insert, which leaves this CPU's slot at zero and ready.
        match DROP_COUNTS.get_ptr_mut(&key) {
            Some(count) => unsafe { *count += 1 },
            None => {
                increment_metric!(DROP_METRICS, DROP_METRIC_KEYS_FULL);
                return 0;
            }
        }
    }
    increment_metric!(DROP_METRICS, DROP_METRIC_COUNTED);
    0
}

// ── Helpers ─────────────────────────────────────────────────────────

/// `TCP_TIME_WAIT` and `TCP_NEW_SYN_RECV`: sockets that carry only a
/// `sock_common`, so nothing past it may be read as a full socket.
const TCP_TIME_WAIT: u8 = 6;
const TCP_NEW_SYN_RECV: u8 = 12;

/// Count a drop under its workload when the socket behind it sits in a
/// watched cgroup: the socket the receive path found, else the sender's.
#[inline(always)]
fn count_workload(reason: u32, skb: u64, rx_sk: u64, config: &DropReasonConfig) {
    let sk = if rx_sk != 0 {
        rx_sk
    } else if skb != 0 {
        read_u64(skb + u64::from(config.skb_sk))
    } else {
        0
    };
    if sk == 0 {
        return;
    }
    let state_at = (sk + u64::from(config.sk_state)) as *const u8;
    match unsafe { bpf_probe_read_kernel(state_at) } {
        Ok(TCP_TIME_WAIT | TCP_NEW_SYN_RECV) | Err(_) => return,
        Ok(_) => {}
    }
    let data = sk + u64::from(config.sk_cgrp_data);
    let cgroup = read_u64(data + u64::from(config.cgrp_data_cgroup));
    if cgroup == 0 {
        return;
    }
    let kn = read_u64(cgroup + u64::from(config.cgroup_kn));
    if kn == 0 {
        return;
    }
    let id = read_u64(kn + u64::from(config.kn_id));
    if id == 0 || unsafe { DROP_WATCHED.get(&id) }.is_none() {
        return;
    }
    let key = DropWorkloadKey {
        cgroup: id,
        reason,
        _pad: 0,
    };
    if let Some(count) = DROP_WORKLOADS.get_ptr_mut(&key) {
        unsafe { *count += 1 };
    } else if DROP_WORKLOADS.insert(&key, &1, BPF_NOEXIST).is_err() {
        match DROP_WORKLOADS.get_ptr_mut(&key) {
            Some(count) => unsafe { *count += 1 },
            None => increment_metric!(DROP_METRICS, DROP_METRIC_KEYS_FULL),
        }
    }
}

/// A kernel pointer-sized read, 0 when it faults.
#[inline(always)]
fn read_u64(at: u64) -> u64 {
    unsafe { bpf_probe_read_kernel(at as *const u64) }.unwrap_or(0)
}

/// The pair a dropped packet is counted under: its device's index and name
/// when it still has a device, the index it arrived on otherwise, and 0 when
/// neither can be read.
#[inline(always)]
fn key_of(reason: u32, skb: u64, config: &DropReasonConfig) -> DropReasonKey {
    let mut key = DropReasonKey {
        reason,
        ifindex: 0,
        name: [0; DROP_IFNAME_LEN],
    };
    if skb == 0 {
        return key;
    }
    let dev_at = (skb + u64::from(config.skb_dev)) as *const u64;
    let dev = unsafe { bpf_probe_read_kernel(dev_at) }.unwrap_or(0);
    if dev != 0 {
        let ifindex_at = (dev + u64::from(config.dev_ifindex)) as *const i32;
        if let Ok(ifindex) = unsafe { bpf_probe_read_kernel(ifindex_at) } {
            key.ifindex = ifindex as u32;
            let name_at = (dev + u64::from(config.dev_name)) as *const [u8; DROP_IFNAME_LEN];
            if let Ok(name) = unsafe { bpf_probe_read_kernel(name_at) } {
                key.name = name;
            }
            return key;
        }
    }
    let iif_at = (skb + u64::from(config.skb_iif)) as *const i32;
    key.ifindex = unsafe { bpf_probe_read_kernel(iif_at) }.map_or(0, |iif| iif as u32);
    key
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
