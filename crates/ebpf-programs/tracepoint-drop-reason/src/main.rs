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
    btf_maps::{Array, PerCpuArray, PerCpuHashMap},
    helpers::bpf_probe_read_kernel,
    macros::{btf_map, raw_tracepoint},
    programs::RawTracePointContext,
};
use ebpf_common::drop_reason::{
    DROP_METRIC_COUNT, DROP_METRIC_COUNTED, DROP_METRIC_KEYS_FULL, DROP_METRIC_UNCONFIGURED,
    DROP_IFNAME_LEN, DROP_REASON_MAX_KEYS, DropReasonConfig, DropReasonKey, counted_reason,
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
    let key = key_of(counted_reason(reason), ctx.arg::<u64>(0), &config);
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
