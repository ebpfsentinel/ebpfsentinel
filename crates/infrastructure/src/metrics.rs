use ports::secondary::metrics_port::{
    AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
    DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics,
    RoutingMetrics, SystemMetrics,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ComponentLabels {
    pub component: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ProgramLabels {
    pub program: String,
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
pub struct ServiceLabels {
    pub service: String,
}

// ── Agent metrics registry ──────────────────────────────────────────

/// Prometheus metrics registry for the agent.
///
/// All metric families use interior mutability (atomics), so recording
/// metrics only requires `&self`. The registry itself is NOT Clone —
/// wrap in `Arc` for multi-task sharing.
pub struct AgentMetrics {
    registry: Registry,
    pub packets_total: Family<PacketLabels, Counter>,
    pub events_dropped_total: Family<ReasonLabels, Counter>,
    pub rules_loaded: Family<ComponentLabels, Gauge>,
    pub ebpf_program_status: Family<ProgramLabels, Gauge>,
    pub packet_processing_duration: Family<ProgramLabels, Histogram>,
    pub rules_reloads_total: Family<ReloadLabels, Counter>,
    pub alerts_total: Family<AlertLabels, Counter>,
    pub alerts_dropped_total: Family<ReasonLabels, Counter>,
    pub alert_sender_circuit_state: Family<DestinationLabels, Gauge>,
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
    pub ids_domain_matches_total: Family<RuleIdLabels, Counter>,
    pub dlp_scans_total: Counter,
    pub dlp_matches_total: Family<RuleIdLabels, Counter>,
    pub dlp_scan_duration_seconds: Histogram,
    pub ddos_attacks_detected_total: Family<AttackTypeLabels, Counter>,
    pub ddos_attacks_active: Gauge,
    pub ddos_mitigations_total: Family<AttackTypeLabels, Counter>,
    pub conntrack_active: Gauge,
    pub conntrack_expired_total: Counter,
    pub routing_gateway_status: Family<GatewayLabels, Gauge>,
    pub routing_failovers_total: Counter,
    pub routing_gateways_total: Gauge,
    pub audit_events_total: Counter,
    pub audit_failures_total: Counter,
    pub lb_forwarded_total: Counter,
    pub lb_backends_healthy: Family<ServiceLabels, Gauge>,
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

        let alert_sender_circuit_state = Family::<DestinationLabels, Gauge>::default();
        registry.register(
            "alert_sender_circuit_state",
            "Alert sender circuit breaker state (0=closed, 1=half-open, 2=open)",
            alert_sender_circuit_state.clone(),
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

        Self {
            registry,
            packets_total,
            events_dropped_total,
            rules_loaded,
            ebpf_program_status,
            packet_processing_duration,
            rules_reloads_total,
            alerts_total,
            alerts_dropped_total,
            alert_sender_circuit_state,
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
            ids_domain_matches_total,
            dlp_scans_total,
            dlp_matches_total,
            dlp_scan_duration_seconds,
            ddos_attacks_detected_total,
            ddos_attacks_active,
            ddos_mitigations_total,
            conntrack_active,
            conntrack_expired_total,
            routing_gateway_status,
            routing_failovers_total,
            routing_gateways_total,
            audit_events_total,
            audit_failures_total,
            lb_forwarded_total,
            lb_backends_healthy,
        }
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
        assert!(encoded.contains("ebpfsentinel_packets"));
        assert!(encoded.contains("interface=\"eth0\""));
        assert!(encoded.contains("action=\"pass\""));
        assert!(encoded.contains("action=\"drop\""));
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
        assert!(encoded.contains("ebpfsentinel_alerts"));
        assert!(encoded.contains("component=\"ids\""));
        assert!(encoded.contains("severity=\"high\""));
        assert!(encoded.contains("severity=\"critical\""));
        assert!(encoded.contains("technique_id=\"T1071\""));
        assert!(encoded.contains("technique_id=\"T1041\""));
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
}
