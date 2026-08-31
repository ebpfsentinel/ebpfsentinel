use crate::ebpf::XDP_ATTACH_MODES;
use ports::secondary::metrics_port::{
    AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
    DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics,
    RoutingMetrics, SystemMetrics, ThreatIntelMetrics, ZoneMetrics,
};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets_range};
use prometheus_client::registry::Registry;
use std::sync::atomic::AtomicU64;

// ── Label types ─────────────────────────────────────────────────────

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct PacketLabels {
    pub interface: String,
    pub action: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReasonLabels {
    pub reason: String,
}

/// Labels for the per-program ring-buffer counters. `source` is the eBPF
/// program that produced the record (`tc-ids`, `xdp-firewall`, …).
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RingBufLabels {
    pub source: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RingBufDropLabels {
    pub source: String,
    pub reason: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct GeoLookupLabels {
    /// `hit` when the IP resolved to a country, `miss` otherwise.
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ComponentLabels {
    pub component: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProgramLabels {
    pub program: String,
}

/// One interface and one of the XDP modes it could be running in.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct XdpModeLabels {
    pub interface: String,
    pub mode: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReloadLabels {
    pub component: String,
    pub result: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AlertLabels {
    pub component: String,
    pub severity: String,
    pub technique_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct DestinationLabels {
    pub destination: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RuleLabels {
    pub component: String,
    pub rule_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct RuleIdLabels {
    pub rule_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct BytesLabels {
    pub interface: String,
    pub direction: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct AttackTypeLabels {
    pub attack_type: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct GatewayLabels {
    pub gateway: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct WorkerLabels {
    pub worker_id: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ServiceLabels {
    pub service: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ZoneLabels {
    pub zone: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ZonePacketLabels {
    pub zone: String,
    pub action: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct FeedLabels {
    pub feed: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct VipLabels {
    pub vip: String,
}

// ── Agent metrics registry ──────────────────────────────────────────

/// Prometheus metrics registry for the agent.
///
/// All metric families use interior mutability (atomics), so recording
/// metrics only requires `&self`. The registry itself is NOT Clone -
/// wrap in `Arc` for multi-task sharing.
pub struct AgentMetrics {
    registry: Registry,
    pub packets_total: Family<PacketLabels, Counter>,
    pub events_dropped_total: Family<ReasonLabels, Counter>,
    pub rules_loaded: Family<ComponentLabels, Gauge>,
    pub ebpf_program_status: Family<ProgramLabels, Gauge>,
    /// A family with no labels rather than a bare gauge: a bare one is exported
    /// at zero from the moment the registry exists, and zero here is a
    /// measurement - a datapath that attached everything it loaded. A family
    /// exports nothing until something has actually looked.
    pub ebpf_attach_blocked: Family<Vec<(String, String)>, Gauge>,
    pub xdp_attach_mode: Family<XdpModeLabels, Gauge>,
    pub packet_processing_duration: Family<ProgramLabels, Histogram>,
    pub rules_reloads_total: Family<ReloadLabels, Counter>,
    pub alerts_total: Family<AlertLabels, Counter>,
    pub alerts_dropped_total: Family<ReasonLabels, Counter>,
    pub alerts_exported_total: Family<DestinationLabels, Counter>,
    pub threatintel_matches_total: Family<FeedLabels, Counter>,
    pub zone_interfaces: Family<ZoneLabels, Gauge>,
    pub zone_policies: Family<ZoneLabels, Gauge>,
    pub zone_packets_total: Family<ZonePacketLabels, Counter>,
    pub alert_sender_circuit_state: Family<DestinationLabels, Gauge>,
    /// Live SSE alert-stream subscriber count. Set by handler on
    /// connect / disconnect.
    pub alerts_sse_subscribers: Gauge,
    pub ips_blacklist_size: Gauge,
    pub ips_blocks_total: Counter,
    pub alerts_by_rule_total: Family<RuleLabels, Counter>,
    pub false_positives_total: Family<RuleLabels, Counter>,
    pub memory_usage_bytes: Gauge,
    pub cpu_usage_percent: Gauge<f64, AtomicU64>,
    pub open_fds: Gauge,
    pub thread_count: Gauge,
    pub bytes_processed_total: Family<BytesLabels, Counter>,
    pub dns_cache_entries: Gauge,
    pub dns_cache_hits_total: Counter,
    pub dns_cache_evictions_total: Counter,
    pub dns_blocked_domains_total: Counter,
    pub dns_injected_ips: Gauge,
    pub domain_reputation_high_risk: Gauge,
    pub domain_auto_blocked_total: Counter,
    pub geoip_lookups_total: Family<GeoLookupLabels, Counter>,
    pub ids_domain_matches_total: Family<RuleIdLabels, Counter>,
    pub dlp_scans_total: Counter,
    pub dlp_matches_total: Family<RuleIdLabels, Counter>,
    pub dlp_scan_duration_seconds: Histogram,
    pub ddos_attacks_detected_total: Family<AttackTypeLabels, Counter>,
    pub ddos_attacks_active: Gauge,
    pub ddos_mitigations_total: Family<AttackTypeLabels, Counter>,
    pub conntrack_active: Gauge,
    pub conntrack_expired_total: Counter,
    pub conntrack_kfunc_lookups: Gauge,
    pub conntrack_kfunc_hits: Gauge,
    pub conntrack_kfunc_misses: Gauge,
    pub routing_gateway_status: Family<GatewayLabels, Gauge>,
    pub routing_failovers_total: Counter,
    pub routing_gateways_total: Gauge,
    pub audit_events_total: Counter,
    pub audit_failures_total: Counter,
    pub lb_forwarded_total: Counter,
    pub lb_backends_healthy: Family<ServiceLabels, Gauge>,
    /// Cumulative forged ARP replies per VIP, mirrored from the kernel
    /// `VIP_ARP_REPLIES` map (gauge mirror of a kernel counter).
    pub lb_vip_arp_replies: Family<VipLabels, Gauge>,
    /// Speaker takeovers per VIP (userspace-incremented on promotion).
    pub lb_vip_takeovers_total: Family<VipLabels, Counter>,
    pub worker_events_total: Family<WorkerLabels, Counter>,
    pub worker_processing_duration: Family<WorkerLabels, Histogram>,
    /// Records drained from a datapath ring buffer, per producing program.
    /// Paired with the kernel-side `events_dropped` slot of the same
    /// program's metrics map, this separates what the kernel refused to
    /// emit from what userspace received.
    pub ringbuf_events_total: Family<RingBufLabels, Counter>,
    /// Drained records userspace threw away before the pipeline saw them.
    /// Without this a committed-then-discarded record is indistinguishable
    /// from one the kernel never emitted.
    pub ringbuf_events_dropped_total: Family<RingBufDropLabels, Counter>,
    /// Delay between the kernel committing a record and userspace draining
    /// it. Both ends read `CLOCK_BOOTTIME`, so the timestamps are comparable.
    pub ringbuf_latency_seconds: Family<RingBufLabels, Histogram>,
    pub container_resolver_cache_hits_total: Counter,
    pub container_resolver_cache_misses_total: Counter,
    pub container_resolver_errors_total: Counter,
    /// IDS flow-kill counter - times the IDS pipeline decided to
    /// mark a conntrack entry `IPS_DYING` to terminate a live flow
    /// following a block-mode rule match.
    pub ids_ct_dying_total: Counter,
    /// Whether eBPF is loaded through a BPF token: `1` when the agent
    /// loaded its programs via `BPF_TOKEN_CREATE` (the only supported
    /// path), `0` when running in API-only mode with no eBPF attached.
    pub bpf_token_used: Gauge,
}

impl AgentMetrics {
    /// Create a new metrics registry with all metrics registered under
    /// the `ebpfsentinel` prefix.
    #[allow(clippy::too_many_lines)]
    pub fn new() -> Self {
        let mut registry = Registry::with_prefix("ebpfsentinel");

        let packets_total = Family::<PacketLabels, Counter>::default();
        registry.register(
            "packets",
            "Total packets processed by the agent",
            packets_total.clone(),
        );

        let events_dropped_total = Family::<ReasonLabels, Counter>::default();
        registry.register(
            "events_dropped",
            "Events dropped due to backpressure or errors",
            events_dropped_total.clone(),
        );

        let rules_loaded = Family::<ComponentLabels, Gauge>::default();
        registry.register(
            "rules_loaded",
            "Number of active rules per component",
            rules_loaded.clone(),
        );

        let ebpf_program_status = Family::<ProgramLabels, Gauge>::default();
        registry.register(
            "ebpf_program_status",
            "eBPF program load status (1=loaded, 0=failed)",
            ebpf_program_status.clone(),
        );

        let ebpf_attach_blocked = Family::<Vec<(String, String)>, Gauge>::default();
        registry.register(
            "ebpf_attach_blocked",
            "eBPF programs that loaded but could not be attached",
            ebpf_attach_blocked.clone(),
        );

        let xdp_attach_mode = Family::<XdpModeLabels, Gauge>::default();
        registry.register(
            "xdp_attach_mode",
            "XDP mode an interface's program is running in (1=in force)",
            xdp_attach_mode.clone(),
        );

        let packet_processing_duration =
            Family::<ProgramLabels, Histogram>::new_with_constructor(|| {
                // Exponential buckets from 1μs to 10ms (10 buckets)
                Histogram::new(exponential_buckets_range(0.000_001, 0.01, 10))
            });
        registry.register(
            "packet_processing_duration_seconds",
            "Packet processing latency in seconds",
            packet_processing_duration.clone(),
        );

        let rules_reloads_total = Family::<ReloadLabels, Counter>::default();
        registry.register(
            "rules_reloads",
            "Configuration reload attempts",
            rules_reloads_total.clone(),
        );

        let alerts_total = Family::<AlertLabels, Counter>::default();
        registry.register(
            "alerts",
            "Total alerts produced by component and severity",
            alerts_total.clone(),
        );

        let alerts_dropped_total = Family::<ReasonLabels, Counter>::default();
        registry.register(
            "alerts_dropped",
            "Alerts dropped due to dedup, throttle, or backpressure",
            alerts_dropped_total.clone(),
        );

        let alerts_exported_total = Family::<DestinationLabels, Counter>::default();
        registry.register(
            "alerts_exported",
            "Alerts successfully handed off to an external sender, by destination",
            alerts_exported_total.clone(),
        );

        let threatintel_matches_total = Family::<FeedLabels, Counter>::default();
        registry.register(
            "threatintel_matches",
            "IOC matches resolved against a threat-intelligence feed, by feed",
            threatintel_matches_total.clone(),
        );

        let zone_interfaces = Family::<ZoneLabels, Gauge>::default();
        registry.register(
            "zone_interfaces",
            "Interfaces bound to each security zone",
            zone_interfaces.clone(),
        );

        let zone_policies = Family::<ZoneLabels, Gauge>::default();
        registry.register(
            "zone_policies",
            "Inter-zone policies whose source is this zone",
            zone_policies.clone(),
        );

        let zone_packets_total = Family::<ZonePacketLabels, Counter>::default();
        registry.register(
            "zone_packets",
            "Packets handled by zone posture, by zone and action",
            zone_packets_total.clone(),
        );

        let alert_sender_circuit_state = Family::<DestinationLabels, Gauge>::default();
        registry.register(
            "alert_sender_circuit_state",
            "Alert sender circuit breaker state (0=closed, 1=half-open, 2=open)",
            alert_sender_circuit_state.clone(),
        );

        let alerts_sse_subscribers = Gauge::default();
        registry.register(
            "alerts_sse_subscribers",
            "Current number of SSE alert-stream subscribers",
            alerts_sse_subscribers.clone(),
        );

        let ips_blacklist_size = Gauge::default();
        registry.register(
            "ips_blacklist_size",
            "Current number of IPs in the IPS blacklist",
            ips_blacklist_size.clone(),
        );

        let ips_blocks_total = Counter::default();
        registry.register(
            "ips_blocks",
            "Total IPS enforcement actions (blocks)",
            ips_blocks_total.clone(),
        );

        let alerts_by_rule_total = Family::<RuleLabels, Counter>::default();
        registry.register(
            "alerts_by_rule",
            "Total alerts per component and rule_id",
            alerts_by_rule_total.clone(),
        );

        let false_positives_total = Family::<RuleLabels, Counter>::default();
        registry.register(
            "false_positives",
            "Total false positive markings per component and rule_id",
            false_positives_total.clone(),
        );

        let memory_usage_bytes = Gauge::default();
        registry.register(
            "memory_usage_bytes",
            "Process resident set size (RSS) in bytes",
            memory_usage_bytes.clone(),
        );

        let cpu_usage_percent: Gauge<f64, AtomicU64> = Gauge::default();
        registry.register(
            "cpu_usage_percent",
            "Process CPU usage percentage",
            cpu_usage_percent.clone(),
        );

        let open_fds = Gauge::default();
        registry.register(
            "open_fds",
            "Number of open file descriptors for the process",
            open_fds.clone(),
        );

        let thread_count = Gauge::default();
        registry.register(
            "thread_count",
            "Number of threads in the process",
            thread_count.clone(),
        );

        let bytes_processed_total = Family::<BytesLabels, Counter>::default();
        registry.register(
            "bytes_processed",
            "Total bytes processed by interface and direction",
            bytes_processed_total.clone(),
        );

        let dns_cache_entries = Gauge::default();
        registry.register(
            "dns_cache_entries",
            "Current number of entries in the DNS resolution cache",
            dns_cache_entries.clone(),
        );

        let dns_cache_hits_total = Counter::default();
        registry.register(
            "dns_cache_hits",
            "Total DNS cache lookup hits",
            dns_cache_hits_total.clone(),
        );

        let dns_cache_evictions_total = Counter::default();
        registry.register(
            "dns_cache_evictions",
            "Total DNS cache evictions (LRU + TTL expiry)",
            dns_cache_evictions_total.clone(),
        );

        let dns_blocked_domains_total = Counter::default();
        registry.register(
            "dns_blocked_domains",
            "Total DNS domains matched by blocklist",
            dns_blocked_domains_total.clone(),
        );

        let dns_injected_ips = Gauge::default();
        registry.register(
            "dns_injected_ips",
            "Current number of IPs injected from DNS blocklist",
            dns_injected_ips.clone(),
        );

        let domain_reputation_high_risk = Gauge::default();
        registry.register(
            "domain_reputation_high_risk",
            "Number of high-risk domains tracked by the reputation engine",
            domain_reputation_high_risk.clone(),
        );

        let domain_auto_blocked_total = Counter::default();
        registry.register(
            "domain_auto_blocked",
            "Total domains auto-blocked by the reputation engine",
            domain_auto_blocked_total.clone(),
        );

        let geoip_lookups_total = Family::<GeoLookupLabels, Counter>::default();
        registry.register(
            "geoip_lookups",
            "Total GeoIP database lookups, labelled hit/miss",
            geoip_lookups_total.clone(),
        );

        let ids_domain_matches_total = Family::<RuleIdLabels, Counter>::default();
        registry.register(
            "ids_domain_matches",
            "Total IDS rule matches based on domain pattern",
            ids_domain_matches_total.clone(),
        );

        let dlp_scans_total = Counter::default();
        registry.register(
            "dlp_scans",
            "Total DLP data scans performed",
            dlp_scans_total.clone(),
        );

        let dlp_matches_total = Family::<RuleIdLabels, Counter>::default();
        registry.register(
            "dlp_matches",
            "Total DLP pattern matches by pattern_id",
            dlp_matches_total.clone(),
        );

        let dlp_scan_duration_seconds =
            Histogram::new(exponential_buckets_range(0.000_01, 0.1, 10));
        registry.register(
            "dlp_scan_duration_seconds",
            "DLP scan latency in seconds",
            dlp_scan_duration_seconds.clone(),
        );

        let ddos_attacks_detected_total = Family::<AttackTypeLabels, Counter>::default();
        registry.register(
            "ddos_attacks_detected",
            "Total DDoS attacks detected by type",
            ddos_attacks_detected_total.clone(),
        );

        let ddos_attacks_active = Gauge::default();
        registry.register(
            "ddos_attacks_active",
            "Current number of active DDoS attacks",
            ddos_attacks_active.clone(),
        );

        let ddos_mitigations_total = Family::<AttackTypeLabels, Counter>::default();
        registry.register(
            "ddos_mitigations",
            "Total DDoS mitigation actions by type",
            ddos_mitigations_total.clone(),
        );

        let conntrack_active = Gauge::default();
        registry.register(
            "conntrack_active",
            "Current number of active tracked connections",
            conntrack_active.clone(),
        );

        let conntrack_expired_total = Counter::default();
        registry.register(
            "conntrack_expired",
            "Total expired connection tracking entries",
            conntrack_expired_total.clone(),
        );

        let conntrack_kfunc_lookups = Gauge::default();
        registry.register(
            "conntrack_kfunc_lookups",
            "Kernel netfilter CT kfunc lookup attempts from BPF",
            conntrack_kfunc_lookups.clone(),
        );
        let conntrack_kfunc_hits = Gauge::default();
        registry.register(
            "conntrack_kfunc_hits",
            "Kernel netfilter CT kfunc lookup hits from BPF",
            conntrack_kfunc_hits.clone(),
        );
        let conntrack_kfunc_misses = Gauge::default();
        registry.register(
            "conntrack_kfunc_misses",
            "Kernel netfilter CT kfunc lookup misses from BPF",
            conntrack_kfunc_misses.clone(),
        );

        let routing_gateway_status = Family::<GatewayLabels, Gauge>::default();
        registry.register(
            "routing_gateway_status",
            "Gateway health status (1=healthy, 0=unhealthy)",
            routing_gateway_status.clone(),
        );

        let routing_failovers_total = Counter::default();
        registry.register(
            "routing_failovers",
            "Total gateway failover events",
            routing_failovers_total.clone(),
        );

        let routing_gateways_total = Gauge::default();
        registry.register(
            "routing_gateways",
            "Total number of configured gateways",
            routing_gateways_total.clone(),
        );

        let audit_events_total = Counter::default();
        registry.register(
            "audit_events",
            "Total audit events recorded",
            audit_events_total.clone(),
        );

        let audit_failures_total = Counter::default();
        registry.register(
            "audit_failures",
            "Total audit write failures",
            audit_failures_total.clone(),
        );

        let lb_forwarded_total = Counter::default();
        registry.register(
            "lb_forwarded",
            "Total load-balanced packets forwarded",
            lb_forwarded_total.clone(),
        );

        let lb_backends_healthy = Family::<ServiceLabels, Gauge>::default();
        registry.register(
            "lb_backends_healthy",
            "Number of healthy backends per service",
            lb_backends_healthy.clone(),
        );

        let lb_vip_arp_replies = Family::<VipLabels, Gauge>::default();
        registry.register(
            "lb_vip_arp_replies",
            "Forged ARP replies per announced VIP",
            lb_vip_arp_replies.clone(),
        );

        let lb_vip_takeovers_total = Family::<VipLabels, Counter>::default();
        registry.register(
            "lb_vip_takeovers",
            "Speaker takeovers per announced VIP",
            lb_vip_takeovers_total.clone(),
        );

        let worker_events_total = Family::<WorkerLabels, Counter>::default();
        registry.register(
            "worker_events",
            "Events processed per dispatch worker",
            worker_events_total.clone(),
        );

        let worker_processing_duration =
            Family::<WorkerLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets_range(0.000_001, 0.1, 16))
            });
        registry.register(
            "worker_processing_duration_seconds",
            "Event processing duration per dispatch worker",
            worker_processing_duration.clone(),
        );

        let ringbuf_events_total = Family::<RingBufLabels, Counter>::default();
        registry.register(
            "ringbuf_events",
            "Records drained from a datapath ring buffer, per producing program",
            ringbuf_events_total.clone(),
        );

        let ringbuf_events_dropped_total = Family::<RingBufDropLabels, Counter>::default();
        registry.register(
            "ringbuf_events_dropped",
            "Drained records discarded by userspace before the pipeline",
            ringbuf_events_dropped_total.clone(),
        );

        // A record that sat in the ring for a whole second is a different
        // failure from one drained in microseconds, so the range spans both.
        let ringbuf_latency_seconds =
            Family::<RingBufLabels, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets_range(0.000_001, 1.0, 16))
            });
        registry.register(
            "ringbuf_latency_seconds",
            "Delay between the kernel committing a ring-buffer record and userspace draining it",
            ringbuf_latency_seconds.clone(),
        );

        let container_resolver_cache_hits_total = Counter::default();
        registry.register(
            "container_resolver_cache_hits",
            "Container resolver cache hits",
            container_resolver_cache_hits_total.clone(),
        );

        let container_resolver_cache_misses_total = Counter::default();
        registry.register(
            "container_resolver_cache_misses",
            "Container resolver cache misses (proc reads)",
            container_resolver_cache_misses_total.clone(),
        );

        let container_resolver_errors_total = Counter::default();
        registry.register(
            "container_resolver_errors",
            "Container resolver read errors from /proc",
            container_resolver_errors_total.clone(),
        );

        let ids_ct_dying_total = Counter::default();
        registry.register(
            "ids_ct_dying",
            "IDS verdict pipeline marked a conntrack entry IPS_DYING (flow kill)",
            ids_ct_dying_total.clone(),
        );

        let bpf_token_used = Gauge::default();
        registry.register(
            "bpf_token_used",
            "eBPF loaded via BPF token (1=token-loaded, 0=API-only/no eBPF)",
            bpf_token_used.clone(),
        );

        Self {
            registry,
            packets_total,
            events_dropped_total,
            rules_loaded,
            ebpf_program_status,
            ebpf_attach_blocked,
            xdp_attach_mode,
            packet_processing_duration,
            rules_reloads_total,
            alerts_total,
            alerts_dropped_total,
            alerts_exported_total,
            threatintel_matches_total,
            zone_interfaces,
            zone_policies,
            zone_packets_total,
            alert_sender_circuit_state,
            alerts_sse_subscribers,
            ips_blacklist_size,
            ips_blocks_total,
            alerts_by_rule_total,
            false_positives_total,
            memory_usage_bytes,
            cpu_usage_percent,
            open_fds,
            thread_count,
            bytes_processed_total,
            dns_cache_entries,
            dns_cache_hits_total,
            dns_cache_evictions_total,
            dns_blocked_domains_total,
            dns_injected_ips,
            domain_reputation_high_risk,
            domain_auto_blocked_total,
            geoip_lookups_total,
            ids_domain_matches_total,
            dlp_scans_total,
            dlp_matches_total,
            dlp_scan_duration_seconds,
            ddos_attacks_detected_total,
            ddos_attacks_active,
            ddos_mitigations_total,
            conntrack_active,
            conntrack_expired_total,
            conntrack_kfunc_lookups,
            conntrack_kfunc_hits,
            conntrack_kfunc_misses,
            routing_gateway_status,
            routing_failovers_total,
            routing_gateways_total,
            audit_events_total,
            audit_failures_total,
            lb_forwarded_total,
            lb_backends_healthy,
            lb_vip_arp_replies,
            lb_vip_takeovers_total,
            worker_events_total,
            worker_processing_duration,
            ringbuf_events_total,
            ringbuf_events_dropped_total,
            ringbuf_latency_seconds,
            container_resolver_cache_hits_total,
            container_resolver_cache_misses_total,
            container_resolver_errors_total,
            ids_ct_dying_total,
            bpf_token_used,
        }
    }

    /// Record whether eBPF was loaded through a BPF token (`true`) or the
    /// agent is running in API-only mode with no eBPF (`false`).
    pub fn set_bpf_token_used(&self, token_loaded: bool) {
        self.bpf_token_used.set(i64::from(token_loaded));
    }

    /// Encode all registered metrics to `OpenMetrics` text format.
    pub fn encode(&self) -> String {
        let mut buffer = String::new();
        prometheus_client::encoding::text::encode(&mut buffer, &self.registry)
            .expect("encoding metrics to string should not fail");
        buffer
    }
}

impl Default for AgentMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── Sub-trait implementations ──────────────────────────────────────

impl PacketMetrics for AgentMetrics {
    fn record_packet(&self, interface: &str, action: &str) {
        self.packets_total
            .get_or_create(&PacketLabels {
                interface: interface.to_string(),
                action: action.to_string(),
            })
            .inc();
    }

    fn record_packets_by(&self, interface: &str, action: &str, count: u64) {
        self.packets_total
            .get_or_create(&PacketLabels {
                interface: interface.to_string(),
                action: action.to_string(),
            })
            .inc_by(count);
    }

    fn record_bytes_processed(&self, interface: &str, direction: &str, bytes: u64) {
        self.bytes_processed_total
            .get_or_create(&BytesLabels {
                interface: interface.to_string(),
                direction: direction.to_string(),
            })
            .inc_by(bytes);
    }

    fn observe_processing_duration(&self, program: &str, duration_seconds: f64) {
        self.packet_processing_duration
            .get_or_create(&ProgramLabels {
                program: program.to_string(),
            })
            .observe(duration_seconds);
    }
}

impl FirewallMetrics for AgentMetrics {
    fn set_rules_loaded(&self, component: &str, count: u64) {
        self.rules_loaded
            .get_or_create(&ComponentLabels {
                component: component.to_string(),
            })
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn set_ebpf_program_status(&self, program: &str, loaded: bool) {
        self.ebpf_program_status
            .get_or_create(&ProgramLabels {
                program: program.to_string(),
            })
            .set(i64::from(loaded));
    }

    fn set_ebpf_attach_blocked(&self, count: u64) {
        self.ebpf_attach_blocked
            .get_or_create(&Vec::new())
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn set_xdp_attach_mode(&self, interface: &str, mode: &str) {
        for known in XDP_ATTACH_MODES {
            self.xdp_attach_mode
                .get_or_create(&XdpModeLabels {
                    interface: interface.to_string(),
                    mode: (*known).to_string(),
                })
                .set(i64::from(*known == *mode));
        }
    }

    fn clear_xdp_attach_mode(&self, interface: &str) {
        for known in XDP_ATTACH_MODES {
            self.xdp_attach_mode
                .get_or_create(&XdpModeLabels {
                    interface: interface.to_string(),
                    mode: (*known).to_string(),
                })
                .set(0);
        }
    }
}

impl AlertMetrics for AgentMetrics {
    fn record_alert(&self, component: &str, severity: &str, technique_id: &str) {
        self.alerts_total
            .get_or_create(&AlertLabels {
                component: component.to_string(),
                severity: severity.to_string(),
                technique_id: technique_id.to_string(),
            })
            .inc();
    }

    fn record_alert_dropped(&self, reason: &str) {
        self.alerts_dropped_total
            .get_or_create(&ReasonLabels {
                reason: reason.to_string(),
            })
            .inc();
    }

    fn record_alert_exported(&self, destination: &str) {
        self.alerts_exported_total
            .get_or_create(&DestinationLabels {
                destination: destination.to_string(),
            })
            .inc();
    }

    fn record_alert_by_rule(&self, component: &str, rule_id: &str) {
        self.alerts_by_rule_total
            .get_or_create(&RuleLabels {
                component: component.to_string(),
                rule_id: rule_id.to_string(),
            })
            .inc();
    }

    fn record_false_positive(&self, component: &str, rule_id: &str) {
        self.false_positives_total
            .get_or_create(&RuleLabels {
                component: component.to_string(),
                rule_id: rule_id.to_string(),
            })
            .inc();
    }

    fn record_circuit_state(&self, destination: &str, state: u8) {
        self.alert_sender_circuit_state
            .get_or_create(&DestinationLabels {
                destination: destination.to_string(),
            })
            .set(i64::from(state));
    }

    fn record_ids_domain_match(&self, rule_id: &str) {
        self.ids_domain_matches_total
            .get_or_create(&RuleIdLabels {
                rule_id: rule_id.to_string(),
            })
            .inc();
    }

    fn set_alerts_sse_subscribers(&self, count: i64) {
        self.alerts_sse_subscribers.set(count);
    }
}

impl IpsMetrics for AgentMetrics {
    fn set_ips_blacklist_size(&self, size: u64) {
        self.ips_blacklist_size
            .set(size.try_into().unwrap_or(i64::MAX));
    }

    fn record_ips_block(&self) {
        self.ips_blocks_total.inc();
    }
}

impl ThreatIntelMetrics for AgentMetrics {
    fn record_threatintel_match(&self, feed_id: &str) {
        self.threatintel_matches_total
            .get_or_create(&FeedLabels {
                feed: feed_id.to_string(),
            })
            .inc();
    }
}

impl ZoneMetrics for AgentMetrics {
    fn set_zone_interfaces(&self, zone: &str, count: u64) {
        self.zone_interfaces
            .get_or_create(&ZoneLabels {
                zone: zone.to_string(),
            })
            .set(i64::try_from(count).unwrap_or(i64::MAX));
    }

    fn record_zone_packets_by(&self, zone: &str, action: &str, delta: u64) {
        self.zone_packets_total
            .get_or_create(&ZonePacketLabels {
                zone: zone.to_string(),
                action: action.to_string(),
            })
            .inc_by(delta);
    }

    fn set_zone_policies(&self, zone: &str, count: u64) {
        self.zone_policies
            .get_or_create(&ZoneLabels {
                zone: zone.to_string(),
            })
            .set(i64::try_from(count).unwrap_or(i64::MAX));
    }
}

impl DnsMetrics for AgentMetrics {
    fn set_dns_cache_entries(&self, count: u64) {
        self.dns_cache_entries
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn increment_dns_cache_hits(&self) {
        self.dns_cache_hits_total.inc();
    }

    fn increment_dns_cache_evictions(&self) {
        self.dns_cache_evictions_total.inc();
    }

    fn increment_dns_blocked_domains(&self) {
        self.dns_blocked_domains_total.inc();
    }

    fn set_dns_injected_ips(&self, count: u64) {
        self.dns_injected_ips
            .set(count.try_into().unwrap_or(i64::MAX));
    }
}

impl DomainMetrics for AgentMetrics {
    fn set_domain_reputation_high_risk(&self, count: u64) {
        self.domain_reputation_high_risk
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn increment_domain_auto_blocked(&self) {
        self.domain_auto_blocked_total.inc();
    }

    fn record_reputation_auto_block(&self, _domain: &str) {
        self.domain_auto_blocked_total.inc();
    }

    fn record_geoip_lookup(&self, found: bool) {
        self.geoip_lookups_total
            .get_or_create(&GeoLookupLabels {
                result: if found { "hit" } else { "miss" }.to_string(),
            })
            .inc();
    }
}

impl SystemMetrics for AgentMetrics {
    fn set_memory_usage_bytes(&self, bytes: u64) {
        self.memory_usage_bytes
            .set(bytes.try_into().unwrap_or(i64::MAX));
    }

    fn set_cpu_usage_percent(&self, percent: f64) {
        self.cpu_usage_percent.set(percent);
    }

    fn set_open_fds(&self, count: u64) {
        self.open_fds.set(count.try_into().unwrap_or(i64::MAX));
    }

    fn set_thread_count(&self, count: u64) {
        self.thread_count.set(count.try_into().unwrap_or(i64::MAX));
    }
}

impl ConfigMetrics for AgentMetrics {
    fn record_config_reload(&self, component: &str, result: &str) {
        self.rules_reloads_total
            .get_or_create(&ReloadLabels {
                component: component.to_string(),
                result: result.to_string(),
            })
            .inc();
    }
}

impl EventMetrics for AgentMetrics {
    fn record_event_dropped(&self, reason: &str) {
        self.events_dropped_total
            .get_or_create(&ReasonLabels {
                reason: reason.to_string(),
            })
            .inc();
    }

    fn record_worker_event(&self, worker_id: usize) {
        self.worker_events_total
            .get_or_create(&WorkerLabels {
                worker_id: worker_id.to_string(),
            })
            .inc();
    }

    fn observe_worker_duration(&self, worker_id: usize, duration_seconds: f64) {
        self.worker_processing_duration
            .get_or_create(&WorkerLabels {
                worker_id: worker_id.to_string(),
            })
            .observe(duration_seconds);
    }

    fn record_ringbuf_event(&self, source: &str) {
        self.ringbuf_events_total
            .get_or_create(&RingBufLabels {
                source: source.to_string(),
            })
            .inc();
    }

    fn record_ringbuf_event_dropped(&self, source: &str, reason: &str) {
        self.ringbuf_events_dropped_total
            .get_or_create(&RingBufDropLabels {
                source: source.to_string(),
                reason: reason.to_string(),
            })
            .inc();
    }

    fn observe_ringbuf_latency(&self, source: &str, seconds: f64) {
        self.ringbuf_latency_seconds
            .get_or_create(&RingBufLabels {
                source: source.to_string(),
            })
            .observe(seconds);
    }
}

impl DlpMetrics for AgentMetrics {
    fn record_dlp_scan(&self) {
        self.dlp_scans_total.inc();
    }

    fn record_dlp_match(&self, pattern_id: &str) {
        self.dlp_matches_total
            .get_or_create(&RuleIdLabels {
                rule_id: pattern_id.to_string(),
            })
            .inc();
    }

    fn observe_dlp_scan_duration(&self, duration_seconds: f64) {
        self.dlp_scan_duration_seconds.observe(duration_seconds);
    }
}

impl DdosMetrics for AgentMetrics {
    fn record_ddos_attack_detected(&self, attack_type: &str) {
        self.ddos_attacks_detected_total
            .get_or_create(&AttackTypeLabels {
                attack_type: attack_type.to_string(),
            })
            .inc();
    }

    fn set_ddos_attacks_active(&self, count: u64) {
        self.ddos_attacks_active
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn record_ddos_mitigation(&self, attack_type: &str) {
        self.ddos_mitigations_total
            .get_or_create(&AttackTypeLabels {
                attack_type: attack_type.to_string(),
            })
            .inc();
    }
}

impl ConntrackMetrics for AgentMetrics {
    fn set_conntrack_active(&self, count: u64) {
        self.conntrack_active
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn record_conntrack_expired(&self) {
        self.conntrack_expired_total.inc();
    }

    fn set_conntrack_kfunc_lookups(&self, count: u64) {
        self.conntrack_kfunc_lookups
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn set_conntrack_kfunc_hits(&self, count: u64) {
        self.conntrack_kfunc_hits
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn set_conntrack_kfunc_misses(&self, count: u64) {
        self.conntrack_kfunc_misses
            .set(count.try_into().unwrap_or(i64::MAX));
    }
}

impl RoutingMetrics for AgentMetrics {
    fn set_routing_gateway_status(&self, gateway: &str, healthy: bool) {
        self.routing_gateway_status
            .get_or_create(&GatewayLabels {
                gateway: gateway.to_string(),
            })
            .set(i64::from(healthy));
    }

    fn record_routing_failover(&self) {
        self.routing_failovers_total.inc();
    }

    fn set_routing_gateways_total(&self, count: u64) {
        self.routing_gateways_total
            .set(count.try_into().unwrap_or(i64::MAX));
    }
}

impl AuditMetrics for AgentMetrics {
    fn record_audit_event(&self) {
        self.audit_events_total.inc();
    }

    fn record_audit_failure(&self) {
        self.audit_failures_total.inc();
    }
}

impl LbMetrics for AgentMetrics {
    fn record_lb_forwarded(&self) {
        self.lb_forwarded_total.inc();
    }

    fn set_lb_backends_healthy(&self, service: &str, count: u64) {
        self.lb_backends_healthy
            .get_or_create(&ServiceLabels {
                service: service.to_string(),
            })
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn set_vip_arp_replies(&self, vip: &str, count: u64) {
        self.lb_vip_arp_replies
            .get_or_create(&VipLabels {
                vip: vip.to_string(),
            })
            .set(count.try_into().unwrap_or(i64::MAX));
    }

    fn record_vip_takeover(&self, vip: &str) {
        self.lb_vip_takeovers_total
            .get_or_create(&VipLabels {
                vip: vip.to_string(),
            })
            .inc();
    }
}

impl ports::secondary::metrics_port::FingerprintMetrics for AgentMetrics {}

impl ports::secondary::metrics_port::ContainerMetrics for AgentMetrics {
    fn record_container_cache_hit(&self) {
        self.container_resolver_cache_hits_total.inc();
    }

    fn record_container_cache_miss(&self) {
        self.container_resolver_cache_misses_total.inc();
    }

    fn record_container_resolver_error(&self) {
        self.container_resolver_errors_total.inc();
    }
}

impl ports::secondary::metrics_port::CtMetrics for AgentMetrics {
    fn record_ids_ct_dying(&self) {
        self.ids_ct_dying_total.inc();
    }
}

// MetricsPort is automatically implemented via the blanket impl
// since AgentMetrics implements all sub-traits.

#[cfg(test)]
mod tests {
    use super::*;
    use ports::secondary::metrics_port::MetricsPort;

    #[test]
    fn new_creates_valid_registry() {
        let metrics = AgentMetrics::new();
        let encoded = metrics.encode();
        // Should contain EOF marker (OpenMetrics format)
        assert!(encoded.contains("# EOF"));
    }

    #[test]
    fn counter_increment_appears_in_output() {
        let metrics = AgentMetrics::new();
        metrics.record_packet("eth0", "pass");
        metrics.record_packet("eth0", "pass");
        metrics.record_packet("eth0", "drop");

        let encoded = metrics.encode();
        // Named exactly rather than by substring: a substring of the right
        // name is still a substring of a wrong one.
        assert!(encoded.contains("# TYPE ebpfsentinel_packets counter"));
        assert!(
            encoded.contains("ebpfsentinel_packets_total{interface=\"eth0\",action=\"pass\"} 2")
        );
        assert!(
            encoded.contains("ebpfsentinel_packets_total{interface=\"eth0\",action=\"drop\"} 1")
        );
    }

    #[test]
    fn gauge_set_appears_in_output() {
        let metrics = AgentMetrics::new();
        metrics.set_rules_loaded("firewall", 42);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_rules_loaded"));
        assert!(encoded.contains("component=\"firewall\""));
        assert!(encoded.contains("42"));
    }

    #[test]
    fn ebpf_program_status_loaded() {
        let metrics = AgentMetrics::new();
        metrics.set_ebpf_program_status("xdp_firewall", true);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_ebpf_program_status"));
        assert!(encoded.contains("program=\"xdp_firewall\""));
    }

    #[test]
    fn a_build_that_never_looked_exports_no_blocked_count_at_all() {
        // Zero blocked is a datapath with nothing wrong, so it must not be what
        // a build with no eBPF at all reports by simply existing.
        let metrics = AgentMetrics::new();

        assert!(!metrics.encode().contains("ebpf_attach_blocked"));
    }

    #[test]
    fn attach_blocked_counts_programs_that_loaded_and_attached_nowhere() {
        let metrics = AgentMetrics::new();
        metrics.set_ebpf_attach_blocked(2);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_ebpf_attach_blocked{} 2"));
    }

    #[test]
    fn exactly_one_xdp_mode_is_in_force_for_an_interface() {
        let metrics = AgentMetrics::new();
        metrics.set_xdp_attach_mode("eth0", "generic");

        let encoded = metrics.encode();
        assert!(encoded.contains("interface=\"eth0\",mode=\"generic\"} 1"));
        assert!(encoded.contains("interface=\"eth0\",mode=\"native\"} 0"));
    }

    #[test]
    fn a_mode_that_stopped_being_true_is_taken_down_rather_than_left_standing() {
        // An interface that fell back from native to generic must not go on
        // reporting native: two modes at one would be read as two attachments.
        let metrics = AgentMetrics::new();
        metrics.set_xdp_attach_mode("eth0", "native");
        metrics.set_xdp_attach_mode("eth0", "generic");

        let encoded = metrics.encode();
        assert!(encoded.contains("interface=\"eth0\",mode=\"native\"} 0"));
        assert!(encoded.contains("interface=\"eth0\",mode=\"generic\"} 1"));
    }

    #[test]
    fn an_interface_carrying_nothing_reports_no_mode_at_all() {
        let metrics = AgentMetrics::new();
        metrics.set_xdp_attach_mode("eth0", "native");
        metrics.clear_xdp_attach_mode("eth0");

        let encoded = metrics.encode();
        for mode in XDP_ATTACH_MODES {
            assert!(encoded.contains(&format!("mode=\"{mode}\"}} 0")));
        }
    }

    #[test]
    fn histogram_observe_appears_in_output() {
        let metrics = AgentMetrics::new();
        metrics.observe_processing_duration("xdp_firewall", 0.000_050); // 50μs

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_packet_processing_duration_seconds"));
        assert!(encoded.contains("program=\"xdp_firewall\""));
    }

    #[test]
    fn events_dropped_counter() {
        let metrics = AgentMetrics::new();
        metrics.record_event_dropped("channel_full");

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_events_dropped"));
        assert!(encoded.contains("reason=\"channel_full\""));
    }

    #[test]
    fn worker_metrics() {
        let metrics = AgentMetrics::new();
        metrics.record_worker_event(0);
        metrics.record_worker_event(0);
        metrics.record_worker_event(1);
        metrics.observe_worker_duration(0, 0.000_042);
        metrics.observe_worker_duration(1, 0.000_078);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_worker_events"));
        assert!(encoded.contains("worker_id=\"0\""));
        assert!(encoded.contains("worker_id=\"1\""));
        assert!(encoded.contains("ebpfsentinel_worker_processing_duration_seconds"));
    }

    #[test]
    fn metrics_port_trait_impl() {
        // Verify AgentMetrics implements MetricsPort via trait object
        let metrics = AgentMetrics::new();
        let port: &dyn MetricsPort = &metrics;
        port.record_packet("lo", "pass");
        port.set_rules_loaded("firewall", 5);
        port.set_ebpf_program_status("xdp_firewall", true);
        port.record_event_dropped("parse_error");
        port.observe_processing_duration("xdp_firewall", 0.001);
        port.record_config_reload("firewall", "success");
        port.record_alert("ids", "high", "T1071");
        port.record_alert_dropped("dedup");
        port.record_circuit_state("webhook", 0);
        port.set_ips_blacklist_size(5);
        port.record_ips_block();
        port.record_alert_by_rule("ids", "ids-001");
        port.record_false_positive("ids", "ids-001");
        port.set_memory_usage_bytes(1024 * 1024);
        port.set_cpu_usage_percent(25.5);
        port.record_bytes_processed("eth0", "rx", 1500);
    }

    #[test]
    fn alert_counter_increments() {
        let metrics = AgentMetrics::new();
        metrics.record_alert("ids", "high", "T1071");
        metrics.record_alert("ids", "critical", "T1041");

        let encoded = metrics.encode();
        // `ebpfsentinel_alerts` is a substring of four other series, so the
        // whole name and its labels are asserted instead.
        assert!(encoded.contains("# TYPE ebpfsentinel_alerts counter"));
        assert!(encoded.contains(
            "ebpfsentinel_alerts_total{component=\"ids\",severity=\"high\",technique_id=\"T1071\"} 1"
        ));
        assert!(encoded.contains(
            "ebpfsentinel_alerts_total{component=\"ids\",severity=\"critical\",technique_id=\"T1041\"} 1"
        ));
    }

    #[test]
    fn alert_dropped_counter_increments() {
        let metrics = AgentMetrics::new();
        metrics.record_alert_dropped("dedup");
        metrics.record_alert_dropped("throttle");

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_alerts_dropped"));
        assert!(encoded.contains("reason=\"dedup\""));
        assert!(encoded.contains("reason=\"throttle\""));
    }

    #[test]
    fn alert_exported_counter_increments() {
        let metrics = AgentMetrics::new();
        metrics.record_alert_exported("otlp");

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_alerts_exported"));
        assert!(encoded.contains("destination=\"otlp\""));
        // It must NOT be recorded as a drop.
        assert!(!encoded.contains("reason=\"otlp_exported\""));
    }

    #[test]
    fn circuit_state_gauge() {
        let metrics = AgentMetrics::new();
        metrics.record_circuit_state("webhook-dest", 0);
        metrics.record_circuit_state("webhook-dest", 2);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_alert_sender_circuit_state"));
        assert!(encoded.contains("destination=\"webhook-dest\""));
    }

    #[test]
    fn ips_blacklist_size_gauge() {
        let metrics = AgentMetrics::new();
        metrics.set_ips_blacklist_size(42);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_ips_blacklist_size"));
        assert!(encoded.contains("42"));
    }

    #[test]
    fn ips_blocks_counter() {
        let metrics = AgentMetrics::new();
        metrics.record_ips_block();
        metrics.record_ips_block();

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_ips_blocks"));
    }

    #[test]
    fn alerts_by_rule_counter() {
        let metrics = AgentMetrics::new();
        metrics.record_alert_by_rule("ids", "ids-001");
        metrics.record_alert_by_rule("ids", "ids-001");
        metrics.record_alert_by_rule("dlp", "dlp-001");

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_alerts_by_rule"));
        assert!(encoded.contains("rule_id=\"ids-001\""));
        assert!(encoded.contains("rule_id=\"dlp-001\""));
    }

    #[test]
    fn false_positives_counter() {
        let metrics = AgentMetrics::new();
        metrics.record_false_positive("ids", "ids-001");

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_false_positives"));
        assert!(encoded.contains("rule_id=\"ids-001\""));
        assert!(encoded.contains("component=\"ids\""));
    }

    #[test]
    fn memory_usage_gauge() {
        let metrics = AgentMetrics::new();
        metrics.set_memory_usage_bytes(1_048_576);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_memory_usage_bytes"));
        assert!(encoded.contains("1048576"));
    }

    #[test]
    fn cpu_usage_gauge() {
        let metrics = AgentMetrics::new();
        metrics.set_cpu_usage_percent(42.5);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_cpu_usage_percent"));
    }

    #[test]
    fn bytes_processed_counter() {
        let metrics = AgentMetrics::new();
        metrics.record_bytes_processed("eth0", "rx", 1500);
        metrics.record_bytes_processed("eth0", "tx", 800);

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_bytes_processed"));
        assert!(encoded.contains("interface=\"eth0\""));
        assert!(encoded.contains("direction=\"rx\""));
        assert!(encoded.contains("direction=\"tx\""));
    }

    #[test]
    fn config_reload_counter() {
        let metrics = AgentMetrics::new();
        metrics.record_config_reload("firewall", "success");
        metrics.record_config_reload("firewall", "failure");

        let encoded = metrics.encode();
        assert!(encoded.contains("ebpfsentinel_rules_reloads"));
        assert!(encoded.contains("component=\"firewall\""));
        assert!(encoded.contains("result=\"success\""));
        assert!(encoded.contains("result=\"failure\""));
    }

    /// Every metric this registry holds, as the name it is registered under
    /// and the metric type it encodes as.
    ///
    /// The series an operator queries is derived from the pair rather than
    /// written here: the `ebpfsentinel_` prefix in front, and the `_total`
    /// suffix the text encoder appends to every counter and to nothing else.
    /// Deriving it is the whole point - a counter registered under a name
    /// that already ends in `_total` is exported as `_total_total`, which is
    /// a series no dashboard, alert rule or runbook naming the intended one
    /// will ever match.
    ///
    /// Adding, renaming or removing a metric means editing this list, and
    /// that is deliberate: the edit is where somebody notices that a query
    /// written against the old name has just stopped returning anything.
    const REGISTERED_METRICS: &[(&str, &str)] = &[
        ("alert_sender_circuit_state", "gauge"),
        ("alerts", "counter"),
        ("alerts_by_rule", "counter"),
        ("alerts_dropped", "counter"),
        ("alerts_exported", "counter"),
        ("alerts_sse_subscribers", "gauge"),
        ("audit_events", "counter"),
        ("audit_failures", "counter"),
        ("bpf_token_used", "gauge"),
        ("bytes_processed", "counter"),
        ("container_resolver_cache_hits", "counter"),
        ("container_resolver_cache_misses", "counter"),
        ("container_resolver_errors", "counter"),
        ("conntrack_active", "gauge"),
        ("conntrack_expired", "counter"),
        ("conntrack_kfunc_hits", "gauge"),
        ("conntrack_kfunc_lookups", "gauge"),
        ("conntrack_kfunc_misses", "gauge"),
        ("cpu_usage_percent", "gauge"),
        ("ddos_attacks_active", "gauge"),
        ("ddos_attacks_detected", "counter"),
        ("ddos_mitigations", "counter"),
        ("dlp_matches", "counter"),
        ("dlp_scan_duration_seconds", "histogram"),
        ("dlp_scans", "counter"),
        ("dns_blocked_domains", "counter"),
        ("dns_cache_entries", "gauge"),
        ("dns_cache_evictions", "counter"),
        ("dns_cache_hits", "counter"),
        ("dns_injected_ips", "gauge"),
        ("domain_auto_blocked", "counter"),
        ("domain_reputation_high_risk", "gauge"),
        ("ebpf_attach_blocked", "gauge"),
        ("ebpf_program_status", "gauge"),
        ("events_dropped", "counter"),
        ("false_positives", "counter"),
        ("geoip_lookups", "counter"),
        ("ids_ct_dying", "counter"),
        ("ids_domain_matches", "counter"),
        ("ips_blacklist_size", "gauge"),
        ("ips_blocks", "counter"),
        ("lb_backends_healthy", "gauge"),
        ("lb_forwarded", "counter"),
        ("lb_vip_arp_replies", "gauge"),
        ("lb_vip_takeovers", "counter"),
        ("memory_usage_bytes", "gauge"),
        ("open_fds", "gauge"),
        ("packet_processing_duration_seconds", "histogram"),
        ("packets", "counter"),
        ("ringbuf_events", "counter"),
        ("ringbuf_events_dropped", "counter"),
        ("ringbuf_latency_seconds", "histogram"),
        ("routing_failovers", "counter"),
        ("routing_gateway_status", "gauge"),
        ("routing_gateways", "gauge"),
        ("rules_loaded", "gauge"),
        ("rules_reloads", "counter"),
        ("thread_count", "gauge"),
        ("threatintel_matches", "counter"),
        ("worker_events", "counter"),
        ("worker_processing_duration_seconds", "histogram"),
        ("xdp_attach_mode", "gauge"),
        ("zone_interfaces", "gauge"),
        ("zone_packets", "counter"),
        ("zone_policies", "gauge"),
    ];

    /// The family name the `# TYPE` line carries: the prefix and nothing
    /// else, whatever the kind.
    fn family_name(registered: &str) -> String {
        format!("ebpfsentinel_{registered}")
    }

    /// The series name a query has to name, which is the family name plus the
    /// `_total` suffix the text encoder appends to a counter sample and to
    /// nothing else.
    fn queried_name(registered: &str, kind: &str) -> String {
        if kind == "counter" {
            format!("ebpfsentinel_{registered}_total")
        } else {
            format!("ebpfsentinel_{registered}")
        }
    }

    /// `# TYPE <name> <kind>` lines of an exposition, in encounter order.
    fn type_lines(encoded: &str) -> Vec<(String, String)> {
        encoded
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .filter_map(|rest| rest.split_once(' '))
            .map(|(name, kind)| (name.to_string(), kind.to_string()))
            .collect()
    }

    /// A registry with one child in every labelled family.
    ///
    /// A `Family` with no children is silent, so an empty registry exposes
    /// only the metrics that are not families and a name check over it would
    /// cover half the surface. Fields are touched directly rather than
    /// through the recording methods on purpose: what is being checked here
    /// is the name a metric is exported under, not whether the pipeline
    /// reaches it.
    fn populated_registry() -> AgentMetrics {
        let m = AgentMetrics::new();
        populate_datapath_counter_families(&m);
        populate_detection_counter_families(&m);
        populate_gauge_families(&m);
        populate_histograms(&m);
        m
    }

    /// One child in every labelled counter family on the packet path.
    fn populate_datapath_counter_families(m: &AgentMetrics) {
        m.packets_total
            .get_or_create(&PacketLabels {
                interface: "eth0".into(),
                action: "pass".into(),
            })
            .inc();
        m.events_dropped_total
            .get_or_create(&ReasonLabels {
                reason: "backpressure".into(),
            })
            .inc();
        m.rules_reloads_total
            .get_or_create(&ReloadLabels {
                component: "firewall".into(),
                result: "success".into(),
            })
            .inc();
        m.zone_packets_total
            .get_or_create(&ZonePacketLabels {
                zone: "wan".into(),
                action: "pass".into(),
            })
            .inc();
        m.bytes_processed_total
            .get_or_create(&BytesLabels {
                interface: "eth0".into(),
                direction: "rx".into(),
            })
            .inc_by(1500);
        m.geoip_lookups_total
            .get_or_create(&GeoLookupLabels {
                result: "hit".into(),
            })
            .inc();
        m.lb_vip_takeovers_total
            .get_or_create(&VipLabels {
                vip: "web-vip".into(),
            })
            .inc();
        m.worker_events_total
            .get_or_create(&WorkerLabels {
                worker_id: "0".into(),
            })
            .inc();
        m.ringbuf_events_total
            .get_or_create(&RingBufLabels {
                source: "tc-ids".into(),
            })
            .inc();
        m.ringbuf_events_dropped_total
            .get_or_create(&RingBufDropLabels {
                source: "tc-ids".into(),
                reason: "parse".into(),
            })
            .inc();
    }

    /// One child in every labelled counter family that counts a
    /// detection or its delivery.
    fn populate_detection_counter_families(m: &AgentMetrics) {
        m.alerts_total
            .get_or_create(&AlertLabels {
                component: "ids".into(),
                severity: "high".into(),
                technique_id: "T1071".into(),
            })
            .inc();
        m.alerts_dropped_total
            .get_or_create(&ReasonLabels {
                reason: "dedup".into(),
            })
            .inc();
        m.alerts_exported_total
            .get_or_create(&DestinationLabels {
                destination: "webhook".into(),
            })
            .inc();
        m.threatintel_matches_total
            .get_or_create(&FeedLabels {
                feed: "abuse-ch".into(),
            })
            .inc();
        m.alerts_by_rule_total
            .get_or_create(&RuleLabels {
                component: "ids".into(),
                rule_id: "ids-001".into(),
            })
            .inc();
        m.false_positives_total
            .get_or_create(&RuleLabels {
                component: "ids".into(),
                rule_id: "ids-001".into(),
            })
            .inc();
        m.ids_domain_matches_total
            .get_or_create(&RuleIdLabels {
                rule_id: "ids-002".into(),
            })
            .inc();
        m.dlp_matches_total
            .get_or_create(&RuleIdLabels {
                rule_id: "dlp-001".into(),
            })
            .inc();
        m.ddos_attacks_detected_total
            .get_or_create(&AttackTypeLabels {
                attack_type: "syn_flood".into(),
            })
            .inc();
        m.ddos_mitigations_total
            .get_or_create(&AttackTypeLabels {
                attack_type: "syn_flood".into(),
            })
            .inc();
    }

    /// One child in every labelled gauge family.
    fn populate_gauge_families(m: &AgentMetrics) {
        m.rules_loaded
            .get_or_create(&ComponentLabels {
                component: "firewall".into(),
            })
            .set(1);
        m.ebpf_program_status
            .get_or_create(&ProgramLabels {
                program: "xdp-firewall".into(),
            })
            .set(1);
        m.ebpf_attach_blocked.get_or_create(&Vec::new()).set(0);
        m.xdp_attach_mode
            .get_or_create(&XdpModeLabels {
                interface: "eth0".into(),
                mode: "native".into(),
            })
            .set(1);
        m.zone_interfaces
            .get_or_create(&ZoneLabels { zone: "wan".into() })
            .set(1);
        m.zone_policies
            .get_or_create(&ZoneLabels { zone: "wan".into() })
            .set(1);
        m.alert_sender_circuit_state
            .get_or_create(&DestinationLabels {
                destination: "webhook".into(),
            })
            .set(0);
        m.routing_gateway_status
            .get_or_create(&GatewayLabels {
                gateway: "gw0".into(),
            })
            .set(1);
        m.lb_backends_healthy
            .get_or_create(&ServiceLabels {
                service: "web".into(),
            })
            .set(2);
        m.lb_vip_arp_replies
            .get_or_create(&VipLabels {
                vip: "web-vip".into(),
            })
            .set(3);
    }

    /// One observation in every histogram, family or not: a histogram is
    /// sampled as `_bucket`, `_sum` and `_count`, and an unobserved family
    /// emits none of them.
    fn populate_histograms(m: &AgentMetrics) {
        m.packet_processing_duration
            .get_or_create(&ProgramLabels {
                program: "xdp-firewall".into(),
            })
            .observe(0.000_01);
        m.worker_processing_duration
            .get_or_create(&WorkerLabels {
                worker_id: "0".into(),
            })
            .observe(0.000_01);
        m.ringbuf_latency_seconds
            .get_or_create(&RingBufLabels {
                source: "tc-ids".into(),
            })
            .observe(0.000_01);
        m.dlp_scan_duration_seconds.observe(0.000_01);
    }

    #[test]
    fn the_exposition_carries_exactly_the_series_the_list_names() {
        let encoded = populated_registry().encode();

        let mut on_the_wire = type_lines(&encoded);
        on_the_wire.sort();

        let mut expected: Vec<(String, String)> = REGISTERED_METRICS
            .iter()
            .map(|(name, kind)| (family_name(name), (*kind).to_string()))
            .collect();
        expected.sort();

        assert_eq!(
            on_the_wire, expected,
            "the exposition and the checked-in list disagree; a metric was added, renamed or removed without updating the list"
        );

        // The `# TYPE` line names the family; a query names the sample, which
        // for a counter carries the suffix the encoder appends. Both are
        // checked, because it is the second one an alert rule is written
        // against.
        for (name, kind) in REGISTERED_METRICS {
            let queried = queried_name(name, kind);
            // A histogram is sampled as `_bucket`, `_sum` and `_count` rather
            // than under the family name, so the count line stands for it.
            let sampled = if *kind == "histogram" {
                format!("{queried}_count")
            } else {
                queried.clone()
            };
            assert!(
                encoded.contains(&format!("\n{sampled}{{"))
                    || encoded.contains(&format!("\n{sampled} ")),
                "{sampled} is on no sample line of the exposition"
            );
        }
    }

    #[test]
    fn the_list_names_every_metric_the_registry_registers() {
        // Read off the source rather than off an exposition, because a family
        // nothing has written is silent and would slip past a wire check.
        let source = include_str!("metrics.rs");
        let production = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);

        let mut registered: Vec<&str> = Vec::new();
        let mut lines = production.lines();
        while let Some(line) = lines.next() {
            if line.trim() != "registry.register(" {
                continue;
            }
            let name = lines
                .next()
                .expect("a register call is followed by its name")
                .trim()
                .trim_end_matches(',')
                .trim_matches('"');
            registered.push(name);
        }
        registered.sort_unstable();

        let mut listed: Vec<&str> = REGISTERED_METRICS.iter().map(|(name, _)| *name).collect();
        listed.sort_unstable();

        assert_eq!(
            registered, listed,
            "the checked-in list and the registrations in this file disagree"
        );
    }

    #[test]
    fn no_registered_name_carries_a_suffix_the_encoder_owns() {
        for (name, kind) in REGISTERED_METRICS {
            assert!(
                !name.ends_with("_total"),
                "{name} is registered with the `_total` suffix the text encoder appends to counters; a counter becomes `_total_total` and anything else claims to be a counter"
            );

            let queried = queried_name(name, kind);
            assert_eq!(
                *kind == "counter",
                queried.ends_with("_total"),
                "{queried} carries `_total` and is a {kind}, which is not valid OpenMetrics"
            );
        }
    }
}
