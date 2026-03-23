// Focused sub-traits for recording Prometheus metrics, grouped by domain.
//
// All methods take `&self` because the underlying implementation uses
// atomic operations (interior mutability via `prometheus-client`).
//
// Default implementations are no-ops, allowing test mocks to implement
// only the sub-traits relevant to the service under test.

// ── Packet processing metrics ──────────────────────────────────────

pub trait PacketMetrics: Send + Sync {
    /// Record a processed packet with interface and action labels.
    fn record_packet(&self, _interface: &str, _action: &str) {}

    /// Record bytes processed on a given interface and direction (rx/tx).
    fn record_bytes_processed(&self, _interface: &str, _direction: &str, _bytes: u64) {}

    /// Observe a packet processing duration in seconds.
    fn observe_processing_duration(&self, _program: &str, _duration_seconds: f64) {}
}

// ── Firewall / eBPF program metrics ────────────────────────────────

pub trait FirewallMetrics: Send + Sync {
    /// Set the number of active rules for a given component.
    fn set_rules_loaded(&self, _component: &str, _count: u64) {}

    /// Set the load status of an eBPF program (true=loaded, false=failed).
    fn set_ebpf_program_status(&self, _program: &str, _loaded: bool) {}
}

// ── Alert pipeline metrics ─────────────────────────────────────────

pub trait AlertMetrics: Send + Sync {
    /// Record an alert produced by a component with given severity and ATT&CK technique.
    fn record_alert(&self, _component: &str, _severity: &str, _technique_id: &str) {}

    /// Record an alert dropped (dedup, throttle, backpressure, etc.).
    fn record_alert_dropped(&self, _reason: &str) {}

    /// Record an alert for per-rule counting (enables FP rate computation).
    fn record_alert_by_rule(&self, _component: &str, _rule_id: &str) {}

    /// Record a false positive marking for a given component and rule.
    fn record_false_positive(&self, _component: &str, _rule_id: &str) {}

    /// Record circuit breaker state for an alert sender destination.
    /// State values: 0=closed, 1=half-open, 2=open.
    fn record_circuit_state(&self, _destination: &str, _state: u8) {}

    /// Record an IDS rule match based on domain pattern (not just IP+port).
    fn record_ids_domain_match(&self, _rule_id: &str) {}
}

// ── IPS metrics ────────────────────────────────────────────────────

pub trait IpsMetrics: Send + Sync {
    /// Set the current IPS blacklist size gauge.
    fn set_ips_blacklist_size(&self, _size: u64) {}

    /// Increment the IPS blocks counter.
    fn record_ips_block(&self) {}

    /// Increment the auto-response counter for a given policy.
    fn record_auto_response(&self, _policy_name: &str) {}
}

// ── DNS metrics ────────────────────────────────────────────────────

pub trait DnsMetrics: Send + Sync {
    /// Set the current number of entries in the DNS resolution cache.
    fn set_dns_cache_entries(&self, _count: u64) {}

    /// Increment the DNS cache hit counter.
    fn increment_dns_cache_hits(&self) {}

    /// Increment the DNS cache eviction counter.
    fn increment_dns_cache_evictions(&self) {}

    /// Increment the DNS blocked domains counter.
    fn increment_dns_blocked_domains(&self) {}

    /// Set the number of IPs currently injected from DNS blocklist.
    fn set_dns_injected_ips(&self, _count: u64) {}

    /// Record an encrypted DNS detection (`DoH` or `DoT`).
    fn record_encrypted_dns(&self, _protocol: &str, _resolver: &str) {}
}

// ── Domain reputation metrics ──────────────────────────────────────

pub trait DomainMetrics: Send + Sync {
    /// Set the number of high-risk domains tracked by the reputation engine.
    fn set_domain_reputation_high_risk(&self, _count: u64) {}

    /// Increment the counter of domains auto-blocked by reputation engine.
    fn increment_domain_auto_blocked(&self) {}

    /// Record a reputation-driven auto-block event for the given domain.
    fn record_reputation_auto_block(&self, _domain: &str) {}
}

// ── System resource metrics ────────────────────────────────────────

pub trait SystemMetrics: Send + Sync {
    /// Set the current process memory usage (RSS) in bytes.
    fn set_memory_usage_bytes(&self, _bytes: u64) {}

    /// Set the current process CPU usage as a percentage (0.0–100.0+).
    fn set_cpu_usage_percent(&self, _percent: f64) {}

    /// Set the number of open file descriptors for the process.
    fn set_open_fds(&self, _count: u64) {}

    /// Set the number of threads in the process.
    fn set_thread_count(&self, _count: u64) {}
}

// ── Configuration metrics ──────────────────────────────────────────

pub trait ConfigMetrics: Send + Sync {
    /// Record a configuration reload attempt (success or failure).
    fn record_config_reload(&self, _component: &str, _result: &str) {}
}

// ── Event pipeline metrics ─────────────────────────────────────────

pub trait EventMetrics: Send + Sync {
    /// Record a dropped event with a reason label.
    fn record_event_dropped(&self, _reason: &str) {}
}

// ── DLP metrics ──────────────────────────────────────────────────

pub trait DlpMetrics: Send + Sync {
    fn record_dlp_scan(&self) {}
    fn record_dlp_match(&self, _pattern_id: &str) {}
    fn observe_dlp_scan_duration(&self, _duration_seconds: f64) {}
}

// ── DDoS metrics ─────────────────────────────────────────────────

pub trait DdosMetrics: Send + Sync {
    fn record_ddos_attack_detected(&self, _attack_type: &str) {}
    fn set_ddos_attacks_active(&self, _count: u64) {}
    fn record_ddos_mitigation(&self, _attack_type: &str) {}
}

// ── Connection tracking metrics ──────────────────────────────────

pub trait ConntrackMetrics: Send + Sync {
    fn set_conntrack_active(&self, _count: u64) {}
    fn record_conntrack_expired(&self) {}
}

// ── Routing metrics ──────────────────────────────────────────────

pub trait RoutingMetrics: Send + Sync {
    fn set_routing_gateway_status(&self, _gateway: &str, _healthy: bool) {}
    fn record_routing_failover(&self) {}
    fn set_routing_gateways_total(&self, _count: u64) {}
}

// ── Audit metrics ────────────────────────────────────────────────

pub trait AuditMetrics: Send + Sync {
    fn record_audit_event(&self) {}
    fn record_audit_failure(&self) {}
}

// ── Load balancer metrics ────────────────────────────────────────

pub trait LbMetrics: Send + Sync {
    fn record_lb_forwarded(&self) {}
    fn set_lb_backends_healthy(&self, _service: &str, _count: u64) {}
}

// ── Fingerprint metrics ──────────────────────────────────────────

pub trait FingerprintMetrics: Send + Sync {
    /// Record a JA4 fingerprint seen for a given hash.
    fn record_fingerprint_seen(&self, _ja4: &str) {}
}

// ── Composite super-trait ──────────────────────────────────────────

/// Unified metrics port composing all domain-specific sub-traits.
///
/// Services accept `Arc<dyn MetricsPort>` for full access. The sub-traits
/// provide default no-op implementations so that test mocks only need to
/// override the methods they care about.
pub trait MetricsPort:
    PacketMetrics
    + FirewallMetrics
    + AlertMetrics
    + IpsMetrics
    + DnsMetrics
    + DomainMetrics
    + SystemMetrics
    + ConfigMetrics
    + EventMetrics
    + DlpMetrics
    + DdosMetrics
    + ConntrackMetrics
    + RoutingMetrics
    + AuditMetrics
    + LbMetrics
    + FingerprintMetrics
{
}

/// Blanket implementation: any type implementing all sub-traits automatically
/// implements `MetricsPort`.
impl<T> MetricsPort for T where
    T: PacketMetrics
        + FirewallMetrics
        + AlertMetrics
        + IpsMetrics
        + DnsMetrics
        + DomainMetrics
        + SystemMetrics
        + ConfigMetrics
        + EventMetrics
        + DlpMetrics
        + DdosMetrics
        + ConntrackMetrics
        + RoutingMetrics
        + AuditMetrics
        + LbMetrics
        + FingerprintMetrics
{
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_port_is_object_safe() {
        // Compile-time check: MetricsPort must be usable as dyn trait.
        fn _check(port: &dyn MetricsPort) {
            port.record_packet("eth0", "pass");
            port.set_rules_loaded("firewall", 10);
            port.record_config_reload("firewall", "success");
            port.record_alert("ids", "high", "T1071");
            port.record_alert_dropped("dedup");
            port.record_circuit_state("webhook", 0);
            port.set_ips_blacklist_size(10);
            port.record_ips_block();
            port.record_alert_by_rule("ids", "ids-001");
            port.record_false_positive("ids", "ids-001");
            port.set_memory_usage_bytes(1024);
            port.set_cpu_usage_percent(12.5);
            port.record_bytes_processed("eth0", "rx", 1500);
            port.set_dns_cache_entries(42);
            port.increment_dns_cache_hits();
            port.increment_dns_cache_evictions();
            port.increment_dns_blocked_domains();
            port.set_dns_injected_ips(5);
            port.set_domain_reputation_high_risk(5);
            port.increment_domain_auto_blocked();
            port.record_dlp_scan();
            port.record_dlp_match("pci-001");
            port.observe_dlp_scan_duration(0.001);
            port.record_ddos_attack_detected("syn_flood");
            port.set_ddos_attacks_active(2);
            port.record_ddos_mitigation("syn_flood");
            port.set_conntrack_active(100);
            port.record_conntrack_expired();
            port.set_routing_gateway_status("gw-1", true);
            port.record_routing_failover();
            port.set_routing_gateways_total(3);
            port.record_audit_event();
            port.record_audit_failure();
            port.record_lb_forwarded();
            port.set_lb_backends_healthy("web", 3);
            port.record_fingerprint_seen("t13d0305h2_abc_def");
        }
    }

    /// Verify that a minimal mock only needs empty trait impls.
    #[test]
    fn minimal_mock_compiles() {
        struct MinimalMock;
        impl PacketMetrics for MinimalMock {}
        impl FirewallMetrics for MinimalMock {}
        impl AlertMetrics for MinimalMock {}
        impl IpsMetrics for MinimalMock {}
        impl DnsMetrics for MinimalMock {}
        impl DomainMetrics for MinimalMock {}
        impl SystemMetrics for MinimalMock {}
        impl ConfigMetrics for MinimalMock {}
        impl EventMetrics for MinimalMock {}
        impl DlpMetrics for MinimalMock {}
        impl DdosMetrics for MinimalMock {}
        impl ConntrackMetrics for MinimalMock {}
        impl RoutingMetrics for MinimalMock {}
        impl AuditMetrics for MinimalMock {}
        impl LbMetrics for MinimalMock {}
        impl FingerprintMetrics for MinimalMock {}

        let mock = MinimalMock;
        let port: &dyn MetricsPort = &mock;
        port.record_packet("eth0", "pass"); // no-op
    }
}
