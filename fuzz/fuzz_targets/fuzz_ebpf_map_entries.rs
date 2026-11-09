#![no_main]

//! Entries the agent reads back out of the maps the tracepoint and cgroup
//! programs fill, turned into domain values by the adapter's own functions
//! and then fed to the domain engines that consume them:
//!
//! - tracepoint-tcp-health: a per-CPU edge counter and its round-trip
//!   histogram, through `raw_edge`, the delta ledger and the reset scan;
//! - tracepoint-drop-reason: a device name off the counter key, through the
//!   reading fold and its delta ledger;
//! - cgroup-attribution: a listening socket entry, through `bound_socket`;
//! - cgroup-connect-redirect: the origin recorded for a redirected connect,
//!   through `origin_destination`.

use core::mem::size_of;

use adapters::ebpf::{connect_redirect, drop_reason, socket_identity_reader, tcp_health};
use domain::drops::{DropDeltas, DropReading, RawDrop};
use domain::tcp_health::TcpEdgeDeltas;
use domain::tcp_health::reset_scan::{ResetRates, observations};
use ebpf_common::attribution::ListeningSocket;
use ebpf_common::drop_reason::DropReasonKey;
use ebpf_common::redirect::RedirectOrigin;
use ebpf_common::tcp_health::{TcpEdgeCounts, TcpEdgeKey, TcpEdgeRtt};
use libfuzzer_sys::fuzz_target;

/// Take one `T` off the front of `bytes`.
fn take<T: Copy>(bytes: &mut &[u8]) -> Option<T> {
    if bytes.len() < size_of::<T>() {
        return None;
    }
    // SAFETY: the length is checked above and every type read here is
    // `#[repr(C)]` plain data valid for any bit pattern; the read is
    // unaligned because the input carries no alignment.
    let value = unsafe { bytes.as_ptr().cast::<T>().read_unaligned() };
    *bytes = &bytes[size_of::<T>()..];
    Some(value)
}

fuzz_target!(|data: &[u8]| {
    let mut bytes = data;

    // Two readings of up to four edges each, two CPUs per edge, so the
    // ledger sees counters move forwards, backwards and wrap.
    let mut deltas = TcpEdgeDeltas::default();
    let mut rates = ResetRates::new(60);
    for reading in 0..2_u64 {
        let mut edges = Vec::new();
        for _ in 0..4 {
            let (Some(key), Some(a), Some(b)) = (
                take::<TcpEdgeKey>(&mut bytes),
                take::<TcpEdgeCounts>(&mut bytes),
                take::<TcpEdgeCounts>(&mut bytes),
            ) else {
                break;
            };
            let rtt = take::<TcpEdgeRtt>(&mut bytes);
            edges.push(tcp_health::raw_edge(&key, &[a, b], rtt.as_ref()));
        }
        let uncounted = take::<u64>(&mut bytes).unwrap_or(0);
        let moved = deltas.advance(&edges, uncounted);
        let seen = observations(&moved.edges);
        for rate in rates.record(reading.saturating_mul(1_000_000_000), &seen) {
            let _ = format!("{rate:?}");
        }
        for edge in &edges {
            let _ = deltas.totals_of(edge.id.cgroup);
        }
    }

    // Two drop readings over the same keys.
    let mut drops = DropDeltas::default();
    let mut raw = Vec::new();
    while raw.len() < 8 {
        let (Some(key), Some(packets)) =
            (take::<DropReasonKey>(&mut bytes), take::<u64>(&mut bytes))
        else {
            break;
        };
        raw.push(RawDrop {
            reason: format!("R{}", key.reason % 4),
            ifindex: key.ifindex,
            name: drop_reason::key_name(&key.name),
            packets,
        });
    }
    let _ = drops.advance(&DropReading::from_raw(&raw, 0));
    for drop in &mut raw {
        drop.packets = drop.packets.rotate_left(7);
    }
    let reading = DropReading::from_raw(&raw, u64::MAX);
    let _ = reading.total();
    let _ = drops.advance(&reading);

    if let Some(listener) = take::<ListeningSocket>(&mut bytes) {
        let _ = format!("{:?}", socket_identity_reader::bound_socket(&listener));
    }
    if let Some(origin) = take::<RedirectOrigin>(&mut bytes) {
        let _ = connect_redirect::origin_destination(&origin);
    }
});
