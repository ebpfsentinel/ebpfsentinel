use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use adapters::ebpf::MetricsReader;
use application::zone_service_impl::ZoneAppService;
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
/// This loop is **not** a safety net for missed ring-buffer notifications and
/// must not be retired alongside one. A `PerCpuArray` has no notification
/// channel of any kind: nothing wakes userspace when the kernel bumps a slot,
/// so polling is the only way to read these maps, and the delta arithmetic
/// exists so the exported counter matches the kernel counter regardless of how
/// often the poll happens. The event path is a separate mechanism entirely -
/// the three ring-buffer readers are epoll-driven and observe a record as soon
/// as the kernel commits it, without waiting for a tick here.
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
        // tc-ids carries one index tc-threatintel does not: attribution to
        // the sending cgroup, which is counted separately from a tenant
        // resolved through the cgroup map.
        "IDS_METRICS" => &[
            (0, "matched"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
            (5, "cgroup_resolved"),
            (6, "cgroup_attributed"),
        ],
        "THREATINTEL_METRICS" => &[
            (0, "matched"),
            (1, "dropped"),
            (2, "errors"),
            (3, "events_dropped"),
            (4, "total_seen"),
        ],
        // Per-zone counters are indexed by zone id, not by a fixed action
        // list, so they are read by `zone_metric_labels` instead.
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
            (9, "kfunc_lookups"),
            (10, "kfunc_hits"),
            (11, "kfunc_misses"),
            (12, "kfunc_state_new"),
            (13, "kfunc_state_established"),
            (14, "kfunc_state_related"),
            (15, "kfunc_state_invalid"),
            (16, "kfunc_marked"),
            (17, "kfunc_read_errors"),
        ],
        "NAT_METRICS" => &[
            (0, "snat_applied"),
            (1, "dnat_applied"),
            (2, "masq_applied"),
            (3, "port_alloc_fail"),
            (4, "errors"),
            (5, "total_seen"),
            (6, "nptv6_translated"),
            (7, "hairpin_applied"),
            (8, "kfunc_delegated"),
            (9, "kfunc_fallback"),
            (10, "xfrm_steered"),
            (11, "fou_encap"),
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
            (6, "oversized_icmp"),
            (7, "errors"),
            (8, "events_dropped"),
            (9, "conn_tracked"),
            (10, "half_open_drops"),
            (11, "rst_flood_drops"),
            (12, "fin_flood_drops"),
            (13, "ack_flood_drops"),
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

// ── Per-zone counters ────────────────────────────────────────────────

/// Name of the counter slot that holds traffic on interfaces no zone claims.
const UNZONED: &str = "unzoned";

/// Poll the datapath's per-zone counters and mirror them into the metrics
/// port, labelled by zone name.
///
/// The zone maps are indexed by `zone_id`, an internal 1-based position in
/// the configuration that would mean nothing to an operator, so the names are
/// read from the zone service on every tick: it is the same source the maps
/// are programmed from, and reading it late is what keeps the labels right
/// after a zone is added or removed at runtime.
///
/// Slot 0 counts the packets that reached the default policy on an interface
/// no zone claims, which is exported under [`UNZONED`]: traffic escaping the
/// zoning entirely is exactly what an operator needs to see.
///
/// Deltas are derived exactly as in [`run_kernel_metrics_loop`]: the kernel
/// counter is absolute, so the exposed counter tracks it regardless of the
/// poll cadence, and a value that dropped (map recreated on reload) is taken
/// as the new delta.
pub async fn run_zone_metrics_loop(
    passed: MetricsReader,
    dropped: MetricsReader,
    zones: Arc<RwLock<ZoneAppService>>,
    metrics: Arc<dyn MetricsPort>,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // counters are 0 at startup

    let mut last: HashMap<(u32, &'static str), u64> = HashMap::new();

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        let mut zone_names = vec![(0u32, UNZONED.to_string())];
        {
            let svc = zones.read().await;
            zone_names.extend(
                svc.zones()
                    .iter()
                    .enumerate()
                    .map(|(idx, zone)| (u32::try_from(idx + 1).unwrap_or(0), zone.id.clone())),
            );
        }

        for (zone_id, zone_name) in &zone_names {
            for (reader, action) in [(&passed, "passed"), (&dropped, "dropped")] {
                match reader.read_metric(*zone_id) {
                    Ok(value) => {
                        let key = (*zone_id, action);
                        let prev = last.get(&key).copied().unwrap_or(0);
                        let delta = if value >= prev { value - prev } else { value };
                        if delta > 0 {
                            metrics.record_zone_packets_by(zone_name, action, delta);
                        }
                        last.insert(key, value);
                    }
                    Err(e) => {
                        tracing::debug!(
                            zone = %zone_name,
                            action,
                            error = %e,
                            "zone metric read failed"
                        );
                    }
                }
            }
        }
    }
}

/// Periodically export what the datapath actually achieved, as opposed to what
/// was asked of it.
///
/// Two facts, both states of the machine rather than counts, and both invisible
/// in every other metric this agent exports:
///
/// * how many programs loaded and were then refused an attachment, which leaves
///   a process running, answering its health check and reporting zeros while
///   watching nothing;
/// * which XDP mode each interface's program is running in, which is the
///   kernel's answer rather than the configured one - a driver that refused
///   native and a fallback that landed on generic look identical in the
///   configuration and cost an order of magnitude in the datapath.
///
/// Polled rather than recorded at attach time because neither fact is ours to
/// keep: an attachment can be replaced, an interface can go down, and a value
/// written once at startup would go on asserting a mode that stopped being true
/// hours ago. An interface the kernel will not answer for is cleared rather than
/// left standing, because the last known mode of an interface that no longer
/// carries a program is the one answer worse than none.
pub async fn run_datapath_state_loop(
    interfaces: Vec<String>,
    metrics: Arc<dyn MetricsPort>,
    interval: Duration,
    cancel: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        tokio::select! {
            () = cancel.cancelled() => break,
            _ = ticker.tick() => {}
        }

        let blocked = adapters::ebpf::blocked_attaches().len();
        metrics.set_ebpf_attach_blocked(u64::try_from(blocked).unwrap_or(u64::MAX));

        for interface in &interfaces {
            match xdp_mode_of(interface) {
                Some(mode) => metrics.set_xdp_attach_mode(interface, mode),
                None => metrics.clear_xdp_attach_mode(interface),
            }
        }
    }
}

/// The XDP mode the kernel reports for one interface, or nothing.
///
/// Nothing covers all three ways there is no answer - the name does not
/// resolve, the interface carries no XDP program, the question could not be
/// asked - because none of them is a mode and reporting one would be inventing
/// a measurement.
fn xdp_mode_of(interface: &str) -> Option<&'static str> {
    let ifindex = adapters::ebpf::kfunc_attach::iface_to_ifindex(interface).ok()?;
    match adapters::ebpf::xdp_attachment(ifindex) {
        Ok(Some(attachment)) => Some(attachment.mode.as_str()),
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(
                interface,
                error = %e,
                "XDP attachment could not be read"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{metric_labels, xdp_mode_of};

    #[test]
    fn an_interface_no_kernel_knows_reports_no_mode_rather_than_an_unknown_one() {
        // The three ways there is no answer are one answer here. A name that
        // does not resolve is not an interface running XDP in an unrecognised
        // mode, and reporting it as one would put a machine on a screen as
        // misconfigured rather than as unmeasured.
        assert_eq!(xdp_mode_of("no-such-interface-0"), None);
    }

    #[test]
    fn ids_metrics_expose_the_cgroup_tenant_counter() {
        // Index 5 of IDS_METRICS is where tc-ids counts tenants resolved from
        // the packet's cgroup. The kernel program owns the index, so a change
        // there without a change here would silently mislabel the counter.
        let labels = metric_labels("IDS_METRICS");
        assert_eq!(
            labels.iter().find(|(idx, _)| *idx == 5).map(|(_, l)| *l),
            Some("cgroup_resolved")
        );
    }

    #[test]
    fn ids_metrics_separate_attribution_from_tenant_resolution() {
        // The two events are unrelated: attribution happens for any packet
        // whose sending cgroup is visible, tenant resolution only for one
        // the cgroup map names. One shared index would report a tenant that
        // was never resolved.
        let labels = metric_labels("IDS_METRICS");
        assert_eq!(
            labels.iter().find(|(idx, _)| *idx == 6).map(|(_, l)| *l),
            Some("cgroup_attributed")
        );
        assert!(
            !metric_labels("THREATINTEL_METRICS")
                .iter()
                .any(|(idx, _)| *idx == 6)
        );
    }

    /// Every `*_METRICS` per-CPU array the metrics loop reads, with the
    /// `ebpf-common` constant the kernel program sizes it from.
    ///
    /// A map is here or its slots are exported under positional names like
    /// `metric_17`, which tells an operator nothing.
    const KERNEL_METRIC_MAPS: &[(&str, u32)] = &[
        (
            "FIREWALL_METRICS",
            ebpf_common::firewall::FIREWALL_METRIC_COUNT,
        ),
        (
            "RATELIMIT_METRICS",
            ebpf_common::ratelimit::RATELIMIT_METRIC_COUNT,
        ),
        ("IDS_METRICS", ebpf_common::ids::IDS_METRIC_COUNT),
        (
            "THREATINTEL_METRICS",
            ebpf_common::threatintel::THREATINTEL_METRIC_COUNT,
        ),
        ("DNS_METRICS", ebpf_common::dns::DNS_METRIC_COUNT),
        ("DLP_METRICS", ebpf_common::dlp::DLP_METRIC_COUNT),
        ("CT_METRICS", ebpf_common::conntrack::CT_METRIC_COUNT),
        ("NAT_METRICS", ebpf_common::nat::NAT_METRIC_COUNT),
        ("SCRUB_METRICS", ebpf_common::scrub::SCRUB_METRIC_COUNT),
        ("DDOS_METRICS", ebpf_common::ddos::DDOS_METRIC_COUNT),
        ("LB_METRICS", ebpf_common::loadbalancer::LB_METRIC_COUNT),
        ("QOS_METRICS", ebpf_common::qos::QOS_METRIC_COUNT),
    ];

    #[test]
    fn every_map_labels_every_index_the_kernel_writes() {
        // The kernel program sizes each map from its `*_METRIC_COUNT`
        // constant, so a slot added there and not here is a counter the
        // kernel increments and nobody can read. Reading the count rather
        // than a number written out here is what makes that a build failure
        // in this file rather than a gap somebody notices under attack.
        for (map, count) in KERNEL_METRIC_MAPS {
            let labels = metric_labels(map);
            for idx in 0..*count {
                assert!(
                    labels.iter().any(|(i, _)| *i == idx),
                    "{map} index {idx} has no label"
                );
            }
        }
    }

    #[test]
    fn no_map_labels_an_index_the_kernel_never_writes() {
        // A label past the end of the array is read back as an error on every
        // poll and exports nothing, so it reads as a counter that stays at
        // zero rather than as a table naming a slot that does not exist.
        for (map, count) in KERNEL_METRIC_MAPS {
            for (idx, label) in metric_labels(map) {
                assert!(
                    idx < count,
                    "{map} labels index {idx} as {label}, past the {count} slots the map holds"
                );
            }
        }
    }

    #[test]
    fn every_labelled_map_is_held_to_its_kernel_slot_count() {
        // Read the arms off the source rather than listing them here, so a
        // map added to the table without a slot count fails this test instead
        // of quietly escaping both assertions above.
        let source = include_str!("ebpf_metrics.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        let arms: Vec<&str> = production
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                let rest = trimmed.strip_prefix('"')?;
                let (name, tail) = rest.split_once('"')?;
                tail.trim_start().starts_with("=>").then_some(name)
            })
            .collect();
        assert!(
            !arms.is_empty(),
            "no map arm was read out of the label table"
        );

        for arm in arms {
            assert!(
                KERNEL_METRIC_MAPS.iter().any(|(map, _)| *map == arm),
                "{arm} is labelled but carries no kernel slot count"
            );
        }
    }

    #[test]
    fn every_map_the_agent_polls_carries_a_label_table() {
        // A map opened by the startup path and missing from the label table
        // falls through to the positional fallback, which exports every slot
        // as `index_0`, `index_1` and `errors` regardless of what the kernel
        // counts there. The per-zone maps are indexed by zone id rather than
        // by a fixed action list, so they are read by `zone_metric_labels`.
        let startup = include_str!("startup.rs");
        let mut polled: Vec<&str> = Vec::new();
        for (_, rest) in startup
            .match_indices("MetricsReader::new(")
            .map(|(i, _)| (i, &startup[i + "MetricsReader::new(".len()..]))
        {
            let Some(open) = rest.find('"') else { continue };
            let Some(len) = rest[open + 1..].find('"') else {
                continue;
            };
            let name = &rest[open + 1..open + 1 + len];
            if !name.starts_with("ZONE_METRICS") && !polled.contains(&name) {
                polled.push(name);
            }
        }
        assert!(
            !polled.is_empty(),
            "no polled map name was read out of the startup path"
        );

        for name in polled {
            assert!(
                KERNEL_METRIC_MAPS.iter().any(|(map, _)| *map == name),
                "{name} is polled but has no label table, so its slots export as positional names"
            );
        }
    }

    #[test]
    fn every_metric_index_is_declared_once() {
        for (map, _) in KERNEL_METRIC_MAPS {
            let labels = metric_labels(map);
            let mut indices: Vec<u32> = labels.iter().map(|(idx, _)| *idx).collect();
            indices.sort_unstable();
            let before = indices.len();
            indices.dedup();
            assert_eq!(indices.len(), before, "{map} declares an index twice");
        }
    }

    #[test]
    fn every_action_label_is_unique_within_its_map() {
        // Two slots sharing a label add together on the wire, so a flood
        // counter would be indistinguishable from the one beside it.
        for (map, _) in KERNEL_METRIC_MAPS {
            let mut labels: Vec<&str> = metric_labels(map).iter().map(|(_, l)| *l).collect();
            labels.sort_unstable();
            let before = labels.len();
            labels.dedup();
            assert_eq!(labels.len(), before, "{map} declares an action label twice");
        }
    }

    #[test]
    fn unknown_maps_fall_back_to_positional_labels() {
        let labels = metric_labels("SOMETHING_ELSE");
        assert_eq!(labels.len(), 3);
        assert_eq!(labels[2], (2, "errors"));
    }
}
