use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use adapters::ebpf::MetricsReader;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Periodically read eBPF `PerCpuArray` metrics maps and record values
/// into the Prometheus-based `AgentMetrics` registry.
///
/// Each `MetricsReader` owns a single `*_METRICS` map. We read a fixed
/// set of indices per map and mirror them onto the
/// `ebpfsentinel_packets_total{interface="<MAP>",action="<label>"}`
/// counter family.
///
/// The eBPF maps hold **cumulative** per-CPU counters, so each poll the
/// loop computes the delta against the previous reading and adds only that
/// delta. The exposed counter therefore tracks the real kernel counter and
/// is independent of the poll cadence. A reading that drops below the
/// previous value (program reload zeroes the map) is treated as a counter
/// reset: the new absolute value is taken as the delta.
///
/// Accepts a shared `Arc<RwLock<Vec<MetricsReader>>>` so that readers
/// can be added/removed dynamically as eBPF programs are loaded/unloaded.
pub async fn run_kernel_metrics_loop(
    readers: Arc<RwLock<Vec<MetricsReader>>>,
    metrics: Arc<dyn MetricsPort>,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip first immediate tick — metrics are 0 at startup
    ticker.tick().await;

    // Last absolute value seen per (map name, index), to derive deltas.
    let mut last: HashMap<(String, u32), u64> = HashMap::new();

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        let readers_lock = readers.read().await;
        for reader in readers_lock.iter() {
            let map_name = reader.map_name();
            let labels = metric_labels(map_name);
            for (idx, action) in labels {
                match reader.read_metric(*idx) {
                    Ok(value) => {
                        let key = (map_name.to_string(), *idx);
                        let prev = last.get(&key).copied().unwrap_or(0);
                        // Counter reset (map recreated on reload) → the
                        // current absolute value is the delta.
                        let delta = if value >= prev { value - prev } else { value };
                        if delta > 0 {
                            metrics.record_packets_by(map_name, action, delta);
                        }
                        last.insert(key, value);
                    }
                    Err(e) => {
                        tracing::debug!(
                            map = map_name,
                            index = idx,
                            error = %e,
                            "kernel metric read failed"
                        );
                    }
                }
            }
        }
    }
}

/// Return (index, label) pairs for the standard metric indices of a given map.
#[allow(clippy::too_many_lines)]
fn metric_labels(map_name: &str) -> &'static [(u32, &'static str)] {
    match map_name {
        "FIREWALL_METRICS" => &[
            (0, "passed"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
            (5, "rejected"),
            (6, "mtu_exceeded"),
            (7, "reject_throttled"),
        ],
        "RATELIMIT_METRICS" => &[
            (0, "matched"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
            (5, "mtu_exceeded"),
        ],
        "IDS_METRICS" | "THREATINTEL_METRICS" => &[
            (0, "matched"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
            (5, "cgroup_resolved"),
        ],
        "DNS_METRICS" => &[
            (0, "inspected"),
            (1, "emitted"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
        ],
        "DLP_METRICS" => &[
            (0, "write_events"),
            (1, "read_events"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
        ],
        "CT_METRICS" => &[
            (0, "new"),
            (1, "established"),
            (2, "closed"),
            (3, "invalid"),
            (4, "evicted"),
            (5, "errors"),
            (6, "lookups"),
            (7, "hits"),
            (8, "total_seen"),
        ],
        "NAT_METRICS" => &[
            (0, "snat_applied"),
            (1, "dnat_applied"),
            (2, "masq_applied"),
            (3, "port_alloc_fail"),
            (4, "errors"),
            (5, "total_seen"),
            (6, "nptv6_translated"),
        ],
        "SCRUB_METRICS" => &[
            (0, "packets"),
            (1, "ttl_fixed"),
            (2, "mss_clamped"),
            (3, "df_cleared"),
            (4, "ipid_randomized"),
            (5, "errors"),
            (6, "hop_fixed"),
            (7, "total_seen"),
            (8, "tcp_flags_scrubbed"),
            (9, "ecn_stripped"),
            (10, "tos_normalized"),
            (11, "tcp_ts_stripped"),
            (12, "fragments_dropped"),
        ],
        "DDOS_METRICS" => &[
            (0, "syn_rcv"),
            (1, "syn_flood_drops"),
            (2, "icmp_pass"),
            (3, "icmp_drop"),
            (4, "amp_passed"),
            (5, "amp_dropped"),
            (14, "total_seen"),
            (15, "syncookie_sent"),
            (16, "syncookie_valid"),
            (17, "syncookie_invalid"),
        ],
        "LB_METRICS" => &[
            (0, "forwarded"),
            (1, "no_backend"),
            (2, "bytes_forwarded"),
            (3, "events_dropped"),
            (4, "total_seen"),
            (5, "mtu_exceeded"),
        ],
        "QOS_METRICS" => &[
            (0, "total_seen"),
            (1, "shaped"),
            (2, "dropped_loss"),
            (3, "dropped_queue"),
            (4, "delayed"),
            (5, "errors"),
            (6, "events_dropped"),
        ],
        _ => &[(0, "index_0"), (1, "index_1"), (2, "errors")],
    }
}
