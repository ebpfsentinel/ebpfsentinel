use std::sync::Arc;

use domain::audit::entity::{AuditAction, AuditComponent};
use domain::common::entity::DomainMode;
use domain::ddos::entity::{DdosAttackType, DdosEvent};
use domain::firewall::entity::FirewallAction;
use domain::ids::entity::IdsAlert;
use domain::l7::entity::DetectedProtocol;
use domain::l7::parser::{detect_protocol, parse_payload};
use domain::threatintel::entity::ThreatIntelAlert;
use ebpf_common::ddos::{
    EVENT_TYPE_DDOS_AMP, EVENT_TYPE_DDOS_CONNTRACK, EVENT_TYPE_DDOS_ICMP, EVENT_TYPE_DDOS_SYN,
};
use ebpf_common::dlp::DlpEvent;
use ebpf_common::dns::DnsEvent;
use ebpf_common::event::{
    EVENT_TYPE_FIREWALL, EVENT_TYPE_IDS, EVENT_TYPE_RATELIMIT, EVENT_TYPE_THREATINTEL, PacketEvent,
};
use ports::secondary::dns_cache_port::DnsCachePort;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::{RwLock, mpsc};
use tokio_util::sync::CancellationToken;

use crate::audit_service_impl::AuditAppService;
use crate::ddos_service_impl::DdosAppService;
use crate::dlp_service_impl::DlpAppService;
use crate::dns_cache_service_impl::DnsCacheAppService;
use crate::ids_service_impl::IdsAppService;
use crate::ips_service_impl::IpsAppService;
use crate::l7_service_impl::L7AppService;
use crate::threatintel_service_impl::ThreatIntelAppService;

/// Wrapper around events flowing from the eBPF event reader to the dispatcher.
///
/// `L4` carries the 32-byte `PacketEvent` as before. `L7` carries the same
/// header plus a variable-length payload extracted from the `RingBuf`.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    L4(PacketEvent),
    L7 {
        header: PacketEvent,
        payload: Vec<u8>,
    },
    Dns {
        header: DnsEvent,
        payload: Vec<u8>,
    },
    Dlp(Box<DlpEvent>),
}

/// Routes eBPF events by `event_type` to the correct domain engine.
///
/// Consumes `PacketEvent`s from the event channel, dispatches IDS events
/// to the IDS engine for evaluation, and forwards resulting alerts to the
/// alert channel. Uses `tokio::select!` for cancellation awareness.
pub struct EventDispatcher {
    ids_service: Arc<RwLock<IdsAppService>>,
    l7_service: Arc<RwLock<L7AppService>>,
    threatintel_service: Arc<RwLock<ThreatIntelAppService>>,
    audit_service: Arc<RwLock<AuditAppService>>,
    metrics: Arc<dyn MetricsPort>,
    alert_tx: mpsc::Sender<IdsAlert>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
    dns_cache_svc: Option<Arc<DnsCacheAppService>>,
    ips_service: Option<Arc<RwLock<IpsAppService>>>,
    dlp_service: Option<Arc<RwLock<DlpAppService>>>,
    ddos_service: Option<Arc<RwLock<DdosAppService>>>,
}

impl EventDispatcher {
    pub fn new(
        ids_service: Arc<RwLock<IdsAppService>>,
        l7_service: Arc<RwLock<L7AppService>>,
        threatintel_service: Arc<RwLock<ThreatIntelAppService>>,
        audit_service: Arc<RwLock<AuditAppService>>,
        metrics: Arc<dyn MetricsPort>,
        alert_tx: mpsc::Sender<IdsAlert>,
        dns_cache: Option<Arc<dyn DnsCachePort>>,
    ) -> Self {
        Self {
            ids_service,
            l7_service,
            threatintel_service,
            audit_service,
            metrics,
            alert_tx,
            dns_cache,
            dns_cache_svc: None,
            ips_service: None,
            dlp_service: None,
            ddos_service: None,
        }
    }

    /// Set the DNS cache service for processing DNS events.
    #[must_use]
    pub fn with_dns_cache_svc(mut self, svc: Arc<DnsCacheAppService>) -> Self {
        self.dns_cache_svc = Some(svc);
        self
    }

    /// Set the IPS service for auto-blacklisting on IDS detections.
    #[must_use]
    pub fn with_ips_service(mut self, svc: Arc<RwLock<IpsAppService>>) -> Self {
        self.ips_service = Some(svc);
        self
    }

    /// Set the DLP service for processing DLP events.
    #[must_use]
    pub fn with_dlp_service(mut self, svc: Arc<RwLock<DlpAppService>>) -> Self {
        self.dlp_service = Some(svc);
        self
    }

    /// Set the `DDoS` service for processing `DDoS` events.
    #[must_use]
    pub fn with_ddos_service(mut self, svc: Arc<RwLock<DdosAppService>>) -> Self {
        self.ddos_service = Some(svc);
        self
    }

    /// Main event loop. Receives events from the event channel, dispatches
    /// by type, and drains remaining events on cancellation.
    pub async fn run(self, mut rx: mpsc::Receiver<AgentEvent>, cancel_token: CancellationToken) {
        let mut count: u64 = 0;

        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    // Drain remaining events before exiting
                    while let Ok(event) = rx.try_recv() {
                        count += 1;
                        self.dispatch_agent_event(event).await;
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            count += 1;
                            self.dispatch_agent_event(event).await;
                        }
                        None => break, // channel closed
                    }
                }
            }
        }

        tracing::info!(total_events = count, "event dispatcher stopped");
    }

    async fn dispatch_agent_event(&self, event: AgentEvent) {
        match event {
            AgentEvent::L4(pkt) => self.dispatch_event(pkt).await,
            AgentEvent::L7 { header, payload } => self.process_l7_event(header, &payload).await,
            AgentEvent::Dns { header, payload } => self.process_dns_event(header, &payload),
            AgentEvent::Dlp(event) => self.process_dlp_event(&event).await,
        }
    }

    async fn dispatch_event(&self, event: PacketEvent) {
        match event.event_type {
            EVENT_TYPE_FIREWALL => {
                let action = action_label(event.action);
                self.metrics.record_packet("firewall", action);
                tracing::debug!(
                    src_ip = %event.src_ip(),
                    dst_ip = %event.dst_ip(),
                    src_port = event.src_port,
                    dst_port = event.dst_port,
                    protocol = event.protocol,
                    action = event.action,
                    rule_id = event.rule_id,
                    "firewall event"
                );

                let audit_action = if event.action == 1 {
                    AuditAction::Drop
                } else {
                    AuditAction::Pass
                };
                let detail = format!("firewall {action} rule_id={}", event.rule_id);
                self.audit_service.read().await.record_security_decision(
                    AuditComponent::Firewall,
                    audit_action,
                    event.timestamp_ns,
                    event.src_addr,
                    event.dst_addr,
                    event.is_ipv6(),
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                    &event.rule_id.to_string(),
                    &detail,
                );
            }
            EVENT_TYPE_IDS => {
                self.process_ids_event(event).await;
            }
            EVENT_TYPE_RATELIMIT => {
                let action = action_label(event.action);
                self.metrics.record_packet("ratelimit", action);
                tracing::debug!(
                    src_ip = %event.src_ip(),
                    dst_ip = %event.dst_ip(),
                    src_port = event.src_port,
                    dst_port = event.dst_port,
                    protocol = event.protocol,
                    action = event.action,
                    "ratelimit event"
                );

                let audit_action = if event.action == 1 {
                    AuditAction::RateExceeded
                } else {
                    AuditAction::Pass
                };
                let detail = format!("ratelimit {action}");
                self.audit_service.read().await.record_security_decision(
                    AuditComponent::Ratelimit,
                    audit_action,
                    event.timestamp_ns,
                    event.src_addr,
                    event.dst_addr,
                    event.is_ipv6(),
                    event.src_port,
                    event.dst_port,
                    event.protocol,
                    "",
                    &detail,
                );
            }
            EVENT_TYPE_THREATINTEL => {
                self.process_threatintel_event(event).await;
            }
            EVENT_TYPE_DDOS_SYN
            | EVENT_TYPE_DDOS_ICMP
            | EVENT_TYPE_DDOS_AMP
            | EVENT_TYPE_DDOS_CONNTRACK => {
                self.process_ddos_event(event).await;
            }
            other => {
                tracing::debug!(event_type = other, "unhandled event type");
                self.metrics.record_packet("unknown", "unknown");
            }
        }
    }

    async fn process_ids_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("ids", action);

        // Reverse DNS lookup for domain-aware rules (non-blocking, in-memory cache)
        let dst_domains = self
            .dns_cache
            .as_ref()
            .map(|cache| {
                let dst_ip = addr_to_ip(event.dst_addr, event.is_ipv6());
                cache.lookup_ip(&dst_ip)
            })
            .unwrap_or_default();

        // First pass: read-only evaluation (fast path, shared lock)
        let (rule_id, threshold, alert, detail) = {
            let svc = self.ids_service.read().await;

            if !svc.enabled() {
                return;
            }

            let Some((_idx, rule, matched_domain)) =
                svc.evaluate_event_with_context(&event, &dst_domains)
            else {
                return;
            };

            let detail = format!("IDS rule {} matched", rule.id);
            let mut alert = IdsAlert::from_event(&event, rule);
            if matched_domain.is_some() {
                self.metrics.record_ids_domain_match(&rule.id.0);
            }
            alert.matched_domain = matched_domain;
            let rule_id = rule.id.clone();
            let threshold = rule.threshold.clone();
            (rule_id, threshold, alert, detail)
        };

        // Second pass: threshold check (only if rule has threshold config)
        if let Some(ref thresh) = threshold {
            let mut svc = self.ids_service.write().await;
            if !svc.check_threshold(&rule_id, thresh, event.src_addr[0], event.dst_addr[0]) {
                return; // Suppressed by threshold
            }
        }

        self.audit_service.read().await.record_security_decision(
            AuditComponent::Ids,
            AuditAction::Alert,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            &alert.rule_id.0,
            &detail,
        );

        if self.alert_tx.try_send(alert).is_err() {
            self.metrics.record_event_dropped("alert_channel_full");
        }

        // Feed detection into IPS for auto-blacklisting
        if let Some(ref ips_svc) = self.ips_service {
            let src_ip = addr_to_ip(event.src_addr, event.is_ipv6());
            let mut svc = ips_svc.write().await;
            svc.record_detection(src_ip);
        }
    }

    async fn process_threatintel_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("threatintel", action);

        let svc = self.threatintel_service.read().await;

        if !svc.enabled() {
            return;
        }

        // The eBPF program already matched the IP — look up the IOC for context.
        // Try both src and dst IPs (the kernel fires one event per match direction).
        let src_ip = addr_to_ip(event.src_addr, event.is_ipv6());
        let dst_ip = addr_to_ip(event.dst_addr, event.is_ipv6());

        let ioc = svc.lookup(&src_ip).or_else(|| svc.lookup(&dst_ip)).cloned();
        let mode = svc.mode();
        drop(svc);

        let Some(ioc) = ioc else {
            // IOC was in eBPF map but not in userspace engine (race during reload)
            tracing::debug!(
                src_ip = %event.src_ip(),
                dst_ip = %event.dst_ip(),
                "threatintel event but no IOC found in engine"
            );
            return;
        };
        let (feed_id, confidence, threat_type) = (ioc.feed_id, ioc.confidence, ioc.threat_type);

        let ti_alert = ThreatIntelAlert {
            feed_id,
            confidence,
            threat_type,
            mode,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            is_ipv6: event.is_ipv6(),
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            timestamp_ns: event.timestamp_ns,
        };

        // Reuse the IDS alert channel — AlertPipeline handles both IDS and ThreatIntel.
        // Convert to IdsAlert for channel compatibility (same shape).
        let ids_alert = IdsAlert {
            rule_id: domain::common::entity::RuleId(format!("ti-{}", ti_alert.feed_id)),
            severity: domain::common::entity::Severity::High,
            mode: if mode == DomainMode::Block {
                DomainMode::Block
            } else {
                DomainMode::Alert
            },
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            is_ipv6: event.is_ipv6(),
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            rule_index: 0,
            timestamp_ns: event.timestamp_ns,
            matched_domain: None,
        };

        tracing::info!(
            src_ip = %event.src_ip(),
            dst_ip = %event.dst_ip(),
            feed_id = %ti_alert.feed_id,
            confidence = ti_alert.confidence,
            threat_type = %ti_alert.threat_type,
            action = action,
            "threat intel IOC matched"
        );

        let detail = format!(
            "threat intel IOC matched feed={} confidence={}",
            ti_alert.feed_id, ti_alert.confidence
        );
        self.audit_service.read().await.record_security_decision(
            AuditComponent::Threatintel,
            AuditAction::Alert,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            &ti_alert.feed_id,
            &detail,
        );

        if self.alert_tx.try_send(ids_alert).is_err() {
            self.metrics.record_event_dropped("alert_channel_full");
        }
    }

    async fn process_l7_event(&self, header: PacketEvent, payload: &[u8]) {
        let protocol = detect_protocol(payload);
        let protocol_label = match protocol {
            DetectedProtocol::Http => "http",
            DetectedProtocol::Tls => "tls",
            DetectedProtocol::Grpc => "grpc",
            DetectedProtocol::Smtp => "smtp",
            DetectedProtocol::Ftp => "ftp",
            DetectedProtocol::Smb => "smb",
            DetectedProtocol::Unknown => "unknown",
        };

        let parsed = parse_payload(payload);

        // Evaluate L7 rules against parsed content
        let l7_svc = self.l7_service.read().await;
        let l7_action = l7_svc.evaluate(&header, &parsed);
        drop(l7_svc);

        if let Some(action) = l7_action {
            let action_label = match action {
                FirewallAction::Allow => "allow",
                FirewallAction::Deny => "deny",
                FirewallAction::Log => "log",
            };

            if action == FirewallAction::Deny || action == FirewallAction::Log {
                tracing::info!(
                    src_ip = %header.src_ip(),
                    dst_ip = %header.dst_ip(),
                    src_port = header.src_port,
                    dst_port = header.dst_port,
                    l7_protocol = protocol_label,
                    action = action_label,
                    "L7 rule matched"
                );
            } else {
                tracing::debug!(
                    src_ip = %header.src_ip(),
                    dst_ip = %header.dst_ip(),
                    l7_protocol = protocol_label,
                    action = action_label,
                    "L7 rule matched"
                );
            }

            let audit_action = match action {
                FirewallAction::Deny => AuditAction::Drop,
                _ => AuditAction::Pass,
            };
            let detail = format!("L7 {protocol_label} {action_label}");
            self.audit_service.read().await.record_security_decision(
                AuditComponent::L7,
                audit_action,
                header.timestamp_ns,
                header.src_addr,
                header.dst_addr,
                header.is_ipv6(),
                header.src_port,
                header.dst_port,
                header.protocol,
                "",
                &detail,
            );

            self.metrics.record_packet("l7", action_label);
        } else {
            tracing::debug!(
                src_ip = %header.src_ip(),
                dst_ip = %header.dst_ip(),
                l7_protocol = protocol_label,
                "L7 event — no rule matched"
            );
            self.metrics.record_packet("l7", protocol_label);
        }
    }

    fn process_dns_event(&self, header: DnsEvent, _payload: &[u8]) {
        let direction = if header.direction == ebpf_common::dns::DNS_DIRECTION_RESPONSE {
            "response"
        } else {
            "query"
        };

        self.metrics.record_packet("dns", direction);

        tracing::debug!(
            dns_payload_len = header.dns_payload_len,
            direction,
            "DNS event received"
        );
    }

    async fn process_dlp_event(&self, event: &DlpEvent) {
        self.metrics.record_packet("dlp", "captured");

        let direction = if event.direction == ebpf_common::dlp::DLP_DIRECTION_READ {
            "read"
        } else {
            "write"
        };

        tracing::debug!(
            pid = event.pid,
            tgid = event.tgid,
            data_len = event.data_len,
            direction,
            "DLP event received"
        );

        if let Some(ref dlp_svc) = self.dlp_service {
            let svc = dlp_svc.read().await;
            if !svc.enabled() {
                return;
            }

            let actual_len = (event.data_len as usize).min(ebpf_common::dlp::DLP_MAX_EXCERPT);
            let matches = svc.scan_data(&event.data_excerpt[..actual_len]);
            if !matches.is_empty() {
                tracing::info!(
                    pid = event.pid,
                    match_count = matches.len(),
                    direction,
                    "DLP patterns matched in SSL traffic"
                );
                self.metrics.record_packet("dlp", "alert");
            }
        }
    }

    async fn process_ddos_event(&self, event: PacketEvent) {
        self.metrics.record_packet("ddos", "drop");

        let Some(ref ddos_service) = self.ddos_service else {
            return;
        };

        let Some(attack_type) = DdosAttackType::from_event_type(event.event_type) else {
            return;
        };

        let ddos_event = DdosEvent {
            timestamp_ns: event.timestamp_ns,
            attack_type,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            is_ipv6: event.is_ipv6(),
        };

        let changed = {
            let mut svc = ddos_service.write().await;
            svc.process_event(&ddos_event)
        };

        if changed {
            tracing::info!(
                attack_type = ?attack_type,
                src_ip = %event.src_ip(),
                dst_ip = %event.dst_ip(),
                "DDoS attack state changed"
            );
        }

        self.audit_service.read().await.record_security_decision(
            AuditComponent::Ratelimit,
            AuditAction::Drop,
            event.timestamp_ns,
            event.src_addr,
            event.dst_addr,
            event.is_ipv6(),
            event.src_port,
            event.dst_port,
            event.protocol,
            "",
            &format!("ddos {attack_type:?} drop"),
        );
    }
}

fn action_label(action: u8) -> &'static str {
    match action {
        0 => "pass",
        1 => "drop",
        2 => "log",
        _ => "unknown",
    }
}

/// Convert a `[u32; 4]` address to `IpAddr`.
///
/// IPv4 uses only the first element; IPv6 uses all four u32s in network order.
fn addr_to_ip(addr: [u32; 4], ipv6: bool) -> std::net::IpAddr {
    if ipv6 {
        let mut bytes = [0u8; 16];
        for (i, word) in addr.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(addr[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, Protocol, RuleId, Severity};
    use domain::firewall::entity::FirewallAction;
    use domain::ids::engine::IdsEngine;
    use domain::ids::entity::IdsRule;
    use domain::l7::engine::L7Engine;
    use domain::l7::entity::{L7Matcher, L7Rule};
    use domain::threatintel::engine::ThreatIntelEngine;
    use ebpf_common::event::{EVENT_TYPE_DLP, EVENT_TYPE_IDS, EVENT_TYPE_L7, EVENT_TYPE_RATELIMIT};
    use ports::secondary::metrics_port::{
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    use crate::audit_service_impl::AuditAppService;
    use crate::threatintel_service_impl::ThreatIntelAppService;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use ports::secondary::audit_sink::AuditSink;

    struct TestMetrics {
        packet_calls: AtomicU32,
        dropped_calls: AtomicU32,
        last_component: std::sync::Mutex<String>,
        last_action: std::sync::Mutex<String>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                packet_calls: AtomicU32::new(0),
                dropped_calls: AtomicU32::new(0),
                last_component: std::sync::Mutex::new(String::new()),
                last_action: std::sync::Mutex::new(String::new()),
            }
        }
    }

    impl PacketMetrics for TestMetrics {
        fn record_packet(&self, interface: &str, action: &str) {
            self.packet_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_component.lock().unwrap() = interface.to_string();
            *self.last_action.lock().unwrap() = action.to_string();
        }
    }
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {
        fn record_event_dropped(&self, _reason: &str) {
            self.dropped_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn make_ids_rule(id: &str) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: format!("Test rule {id}"),
            severity: Severity::High,
            mode: DomainMode::Alert,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
        }
    }

    fn make_event(event_type: u8, rule_id: u32) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A80001, 0, 0, 0],
            dst_addr: [0x0A000001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            event_type,
            action: 0,
            flags: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            rule_id,
        }
    }

    fn make_service_with_rules(rules: Vec<IdsRule>) -> Arc<RwLock<IdsAppService>> {
        let mut engine = IdsEngine::new();
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(RwLock::new(IdsAppService::new(engine, None, metrics)))
    }

    fn make_l7_service() -> Arc<RwLock<L7AppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(RwLock::new(L7AppService::new(L7Engine::new(), metrics)))
    }

    fn make_ti_service() -> Arc<RwLock<ThreatIntelAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(RwLock::new(ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            metrics,
            vec![],
        )))
    }

    struct NoopAuditSink;
    impl AuditSink for NoopAuditSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    fn make_audit_service() -> Arc<RwLock<AuditAppService>> {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        Arc::new(RwLock::new(AuditAppService::new(sink)))
    }

    fn make_l7_service_with_rules(rules: Vec<L7Rule>) -> Arc<RwLock<L7AppService>> {
        let mut engine = L7Engine::new();
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(RwLock::new(L7AppService::new(engine, metrics)))
    }

    fn make_dispatcher(
        ids_service: Arc<RwLock<IdsAppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<IdsAlert>,
    ) -> EventDispatcher {
        EventDispatcher::new(
            ids_service,
            make_l7_service(),
            make_ti_service(),
            make_audit_service(),
            metrics,
            alert_tx,
            None,
        )
    }

    fn make_dispatcher_with_l7(
        ids_service: Arc<RwLock<IdsAppService>>,
        l7_service: Arc<RwLock<L7AppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<IdsAlert>,
    ) -> EventDispatcher {
        EventDispatcher::new(
            ids_service,
            l7_service,
            make_ti_service(),
            make_audit_service(),
            metrics,
            alert_tx,
            None,
        )
    }

    #[tokio::test]
    async fn firewall_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_FIREWALL, 0))
            .await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "firewall");
        assert_eq!(*metrics.last_action.lock().unwrap(), "pass");
    }

    #[tokio::test]
    async fn ids_event_with_matching_rule_produces_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;

        let alert = alert_rx.try_recv().unwrap();
        assert_eq!(alert.rule_id.0, "ids-001");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ids");
    }

    #[tokio::test]
    async fn ids_event_with_no_matching_rule_produces_no_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // rule_id=99 → out of range
        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 99))
            .await;

        assert!(alert_rx.try_recv().is_err());
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ids_event_with_disabled_service_produces_no_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        ids.write().await.set_enabled(false);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;

        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unknown_event_type_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_DLP, 0))
            .await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "unknown");
    }

    #[tokio::test]
    async fn backpressure_drops_alert_on_full_channel() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        // Channel capacity of 1
        let (alert_tx, _alert_rx) = mpsc::channel(1);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // Fill the channel
        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;
        // This should trigger backpressure
        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;

        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn run_drains_on_cancellation() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(100);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(100);
        let cancel = CancellationToken::new();

        // Send events before starting the dispatcher
        event_tx
            .send(AgentEvent::L4(make_event(EVENT_TYPE_IDS, 0)))
            .await
            .unwrap();
        event_tx
            .send(AgentEvent::L4(make_event(EVENT_TYPE_FIREWALL, 0)))
            .await
            .unwrap();

        // Cancel immediately
        cancel.cancel();

        // Run the dispatcher — it should drain both events then exit
        dispatcher.run(event_rx, cancel).await;

        // The IDS event should have produced an alert
        assert!(alert_rx.try_recv().is_ok());
        // Both events should have been processed (2 metric calls)
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn run_exits_on_channel_close() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(10);
        let cancel = CancellationToken::new();

        // Drop sender to close channel
        drop(event_tx);

        // Should exit immediately since channel is closed
        dispatcher.run(event_rx, cancel).await;
    }

    #[tokio::test]
    async fn firewall_event_action_labels() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // action=1 (drop)
        let mut event = make_event(EVENT_TYPE_FIREWALL, 0);
        event.action = 1;
        dispatcher.dispatch_event(event).await;
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");

        // action=2 (log)
        event.action = 2;
        dispatcher.dispatch_event(event).await;
        assert_eq!(*metrics.last_action.lock().unwrap(), "log");
    }

    #[tokio::test]
    async fn ratelimit_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_RATELIMIT, 0);
        event.action = 1; // drop (throttled)
        dispatcher.dispatch_event(event).await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ratelimit");
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");
    }

    #[tokio::test]
    async fn ratelimit_event_pass_records_pass_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_RATELIMIT, 0); // action=0 (pass)
        dispatcher.dispatch_event(event).await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ratelimit");
        assert_eq!(*metrics.last_action.lock().unwrap(), "pass");
    }

    // ── L7 dispatch tests ──────────────────────────────────────────

    #[tokio::test]
    async fn l7_event_with_http_payload_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();

        dispatcher
            .dispatch_agent_event(AgentEvent::L7 { header, payload })
            .await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "http");
    }

    #[tokio::test]
    async fn l7_event_with_unknown_protocol_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = vec![0x01, 0x02, 0x03, 0x04];

        dispatcher
            .dispatch_agent_event(AgentEvent::L7 { header, payload })
            .await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "unknown");
    }

    #[tokio::test]
    async fn l7_event_via_run_loop() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let (event_tx, event_rx) = mpsc::channel::<AgentEvent>(10);
        let cancel = CancellationToken::new();

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n".to_vec();
        event_tx
            .send(AgentEvent::L7 { header, payload })
            .await
            .unwrap();

        cancel.cancel();
        dispatcher.run(event_rx, cancel).await;

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
    }

    // ── L7 rule evaluation tests ──────────────────────────────────

    #[tokio::test]
    async fn l7_matching_deny_rule_records_deny_metric() {
        let ids = make_service_with_rules(vec![]);
        let l7 = make_l7_service_with_rules(vec![L7Rule {
            id: RuleId("l7-deny-delete".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: Some("DELETE".to_string()),
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        }]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"DELETE /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec();
        dispatcher
            .dispatch_agent_event(AgentEvent::L7 { header, payload })
            .await;

        // The L7 service records "deny" metric internally
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "deny");
    }

    #[tokio::test]
    async fn l7_no_matching_rule_records_protocol_metric() {
        let ids = make_service_with_rules(vec![]);
        let l7 = make_l7_service();
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"GET /safe HTTP/1.1\r\nHost: ok.com\r\n\r\n".to_vec();
        dispatcher
            .dispatch_agent_event(AgentEvent::L7 { header, payload })
            .await;

        // No rule matched → dispatcher records protocol label
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "http");
    }

    #[tokio::test]
    async fn l7_disabled_service_records_protocol_metric() {
        let ids = make_service_with_rules(vec![]);
        let l7 = make_l7_service_with_rules(vec![L7Rule {
            id: RuleId("l7-deny".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Http {
                method: Some("DELETE".to_string()),
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        }]);
        l7.write().await.set_enabled(false);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"DELETE /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec();
        dispatcher
            .dispatch_agent_event(AgentEvent::L7 { header, payload })
            .await;

        // Service disabled → no deny, just protocol metric
        assert_eq!(*metrics.last_component.lock().unwrap(), "l7");
        assert_eq!(*metrics.last_action.lock().unwrap(), "http");
    }

    // ── DNS-aware IDS pipeline tests ──────────────────────────────

    use domain::dns::entity::{DnsCacheEntry, DnsCacheStats};
    use domain::ids::entity::DomainMatchMode;
    use std::collections::HashMap;
    use std::net::IpAddr;

    /// Mock DNS cache that returns pre-configured domain→IP mappings.
    struct MockDnsCache {
        ip_to_domains: std::sync::Mutex<HashMap<IpAddr, Vec<String>>>,
    }

    impl MockDnsCache {
        fn new() -> Self {
            Self {
                ip_to_domains: std::sync::Mutex::new(HashMap::new()),
            }
        }

        fn with_mapping(ip: IpAddr, domains: Vec<String>) -> Self {
            let mut map = HashMap::new();
            map.insert(ip, domains);
            Self {
                ip_to_domains: std::sync::Mutex::new(map),
            }
        }
    }

    impl DnsCachePort for MockDnsCache {
        fn lookup_domain(&self, _domain: &str) -> Option<DnsCacheEntry> {
            None
        }

        fn lookup_ip(&self, ip: &IpAddr) -> Vec<String> {
            self.ip_to_domains
                .lock()
                .unwrap()
                .get(ip)
                .cloned()
                .unwrap_or_default()
        }

        fn lookup_all(&self, _page: usize, _page_size: usize) -> Vec<(String, DnsCacheEntry)> {
            vec![]
        }

        fn insert(&self, _domain: String, _ips: Vec<IpAddr>, _ttl_secs: u64, _timestamp_ns: u64) {}

        fn stats(&self) -> DnsCacheStats {
            DnsCacheStats::default()
        }

        fn flush(&self) {}
    }

    fn make_domain_ids_rule(id: &str, pattern: &str, mode: DomainMatchMode) -> IdsRule {
        IdsRule {
            domain_pattern: Some(pattern.to_string()),
            domain_match_mode: Some(mode),
            ..make_ids_rule(id)
        }
    }

    fn make_dispatcher_with_dns(
        ids_service: Arc<RwLock<IdsAppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<IdsAlert>,
        dns_cache: Arc<dyn DnsCachePort>,
    ) -> EventDispatcher {
        EventDispatcher::new(
            ids_service,
            make_l7_service(),
            make_ti_service(),
            make_audit_service(),
            metrics,
            alert_tx,
            Some(dns_cache),
        )
    }

    #[tokio::test]
    async fn ids_domain_rule_matches_with_dns_cache() {
        let ids = make_service_with_rules(vec![make_domain_ids_rule(
            "ids-dom-1",
            "evil.com",
            DomainMatchMode::Exact,
        )]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // dst_addr[0] = 0x0A000001 → 10.0.0.1
        let dst_ip: IpAddr = "10.0.0.1".parse().unwrap();
        let dns = Arc::new(MockDnsCache::with_mapping(
            dst_ip,
            vec!["evil.com".to_string()],
        ));

        let dispatcher =
            make_dispatcher_with_dns(Arc::clone(&ids), Arc::clone(&metrics), alert_tx, dns);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;

        let alert = alert_rx.try_recv().unwrap();
        assert_eq!(alert.rule_id.0, "ids-dom-1");
        assert_eq!(alert.matched_domain, Some("evil.com".to_string()));
    }

    #[tokio::test]
    async fn ids_domain_rule_no_match_without_dns_entry() {
        let ids = make_service_with_rules(vec![make_domain_ids_rule(
            "ids-dom-1",
            "evil.com",
            DomainMatchMode::Exact,
        )]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // Empty DNS cache — no domains resolved for this IP
        let dns: Arc<dyn DnsCachePort> = Arc::new(MockDnsCache::new());

        let dispatcher =
            make_dispatcher_with_dns(Arc::clone(&ids), Arc::clone(&metrics), alert_tx, dns);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;

        // Domain rule should not match — no alert
        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn ids_ip_only_rule_works_without_dns() {
        // IP-only rule (no domain pattern) should still match even without DNS cache
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // DNS cache present but no entry for this IP
        let dns: Arc<dyn DnsCachePort> = Arc::new(MockDnsCache::new());

        let dispatcher =
            make_dispatcher_with_dns(Arc::clone(&ids), Arc::clone(&metrics), alert_tx, dns);

        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;

        let alert = alert_rx.try_recv().unwrap();
        assert_eq!(alert.rule_id.0, "ids-001");
        assert!(alert.matched_domain.is_none());
    }

    #[tokio::test]
    async fn ids_dns_disabled_domain_rules_silently_skipped() {
        // DNS disabled (None) → domain rules can't match, IP rules still work
        let ids = make_service_with_rules(vec![
            make_domain_ids_rule("ids-dom-1", "evil.com", DomainMatchMode::Exact),
            make_ids_rule("ids-002"),
        ]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        // No DNS cache (dns_cache = None)
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        // Event for rule index 0 (domain rule) — should NOT match
        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 0))
            .await;
        assert!(alert_rx.try_recv().is_err());

        // Event for rule index 1 (IP-only rule) — should match
        dispatcher
            .dispatch_event(make_event(EVENT_TYPE_IDS, 1))
            .await;
        let alert = alert_rx.try_recv().unwrap();
        assert_eq!(alert.rule_id.0, "ids-002");
    }
}
