use std::sync::Arc;
use std::time::Duration;

use adapters::ebpf::MetricsReader;
use ports::secondary::metrics_port::MetricsPort;
use tokio_util::sync::CancellationToken;

/// Periodically read eBPF `PerCpuArray` metrics maps and record values
/// into the Prometheus-based `AgentMetrics` registry.
///
/// Each `MetricsReader` owns a single `*_METRICS` map. We read a fixed
/// set of indices per map (4 by default: matched, dropped, errors, events dropped)
/// and expose them as Prometheus counters via `record_packet`.
pub async fn run_kernel_metrics_loop(
    readers: Vec<MetricsReader>,
    metrics: Arc<dyn MetricsPort>,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    // Skip first immediate tick — metrics are 0 at startup
    ticker.tick().await;

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        for reader in &readers {
            let map_name = reader.map_name();
            // Read common indices: 0=matched/passed, 1=dropped, 2=errors, 3=events_dropped
            // Each map may have more indices, but these 4 are universal.
            let labels = metric_labels(map_name);
            for (idx, action) in labels {
                match reader.read_metric(*idx) {
                    Ok(value) => {
                        // Use record_packet with (program_name, action) as a generic counter.
                        // The interface label carries the map name for identification.
                        metrics.record_packet(map_name, action);
                        // Also record as gauge-style observation for absolute kernel counters.
                        // We use bytes_processed as a vehicle for absolute counter values.
                        metrics.record_bytes_processed(map_name, action, value);
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
fn metric_labels(map_name: &str) -> &'static [(u32, &'static str)] {
    match map_name {
        "FIREWALL_METRICS" => &[
            (0, "passed"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
        ],
        "RATELIMIT_METRICS" | "IDS_METRICS" | "THREATINTEL_METRICS" => &[
            (0, "matched"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
        ],
        "DNS_METRICS" => &[
            (0, "inspected"),
            (1, "emitted"),
            (2, "errors"),
            (3, "events_dropped"),
        ],
        "DLP_METRICS" => &[
            (0, "write_events"),
            (1, "read_events"),
            (2, "errors"),
            (3, "events_dropped"),
        ],
        "CT_METRICS" => &[
            (0, "new"),
            (1, "established"),
            (2, "closed"),
            (3, "invalid"),
            (4, "evicted"),
            (5, "errors"),
        ],
        "NAT_METRICS" => &[
            (0, "snat_applied"),
            (1, "dnat_applied"),
            (2, "masq_applied"),
            (3, "port_alloc_fail"),
            (4, "errors"),
        ],
        "SCRUB_METRICS" => &[
            (0, "packets"),
            (1, "ttl_fixed"),
            (2, "mss_clamped"),
            (3, "df_cleared"),
            (4, "ipid_randomized"),
            (5, "errors"),
        ],
        "DDOS_METRICS" => &[
            (0, "syn_rcv"),
            (1, "syncookies"),
            (2, "icmp_pass"),
            (3, "icmp_drop"),
        ],
        _ => &[(0, "index_0"), (1, "index_1"), (2, "errors")],
    }
}
