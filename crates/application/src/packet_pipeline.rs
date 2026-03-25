use std::sync::Arc;

use domain::audit::entity::{AuditAction, AuditComponent};
use domain::common::entity::DomainMode;
use domain::ddos::entity::{DdosAttackType, DdosEvent};
use domain::dlp::entity::DlpAlert;
use domain::firewall::entity::FirewallAction;
use domain::ids::entity::IdsAlert;

use crate::alert_event::AlertEvent;
use arc_swap::ArcSwap;
use domain::dns::encrypted_dns::EncryptedDnsDetector;
use domain::l7::entity::{DetectedProtocol, ParsedProtocol};
use domain::l7::ja4::{self, FingerprintCache, FlowKey};
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
use ebpf_common::loadbalancer::{EVENT_TYPE_LB, LB_ACTION_FORWARD, LB_ACTION_NO_BACKEND};
use ports::secondary::dns_cache_port::DnsCachePort;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::audit_service_impl::AuditAppService;
use crate::ddos_service_impl::DdosAppService;
use crate::dlp_service_impl::DlpAppService;
use crate::dns_blocklist_service_impl::DnsBlocklistAppService;
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
///
/// Supports parallel dispatch via [`run_parallel`](Self::run_parallel):
/// a distributor task hashes each event's source address and routes it to
/// one of N worker tasks, preserving per-source ordering while scaling
/// across cores.
#[derive(Clone)]
pub struct EventDispatcher {
    ids_service: Arc<ArcSwap<IdsAppService>>,
    l7_service: Arc<ArcSwap<L7AppService>>,
    threatintel_service: Arc<ArcSwap<ThreatIntelAppService>>,
    audit_service: Arc<AuditAppService>,
    metrics: Arc<dyn MetricsPort>,
    alert_tx: mpsc::Sender<AlertEvent>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
    dns_cache_svc: Option<Arc<DnsCacheAppService>>,
    ips_service: Option<Arc<ArcSwap<IpsAppService>>>,
    dlp_service: Option<Arc<ArcSwap<DlpAppService>>>,
    ddos_service: Option<Arc<ArcSwap<DdosAppService>>>,
    dns_blocklist_svc: Option<Arc<DnsBlocklistAppService>>,
    fingerprint_cache: Arc<FingerprintCache>,
    encrypted_dns_detector: EncryptedDnsDetector,
}

impl EventDispatcher {
    pub fn new(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        l7_service: Arc<ArcSwap<L7AppService>>,
        threatintel_service: Arc<ArcSwap<ThreatIntelAppService>>,
        audit_service: Arc<AuditAppService>,
        metrics: Arc<dyn MetricsPort>,
        alert_tx: mpsc::Sender<AlertEvent>,
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
            dns_blocklist_svc: None,
            fingerprint_cache: Arc::new(FingerprintCache::new(
                10_000,
                std::time::Duration::from_secs(300),
            )),
            encrypted_dns_detector: EncryptedDnsDetector::default(),
        }
    }

    /// Return a shared reference to the JA4 fingerprint cache.
    pub fn fingerprint_cache(&self) -> Arc<FingerprintCache> {
        Arc::clone(&self.fingerprint_cache)
    }

    /// Set the DNS cache service for processing DNS events.
    #[must_use]
    pub fn with_dns_cache_svc(mut self, svc: Arc<DnsCacheAppService>) -> Self {
        self.dns_cache_svc = Some(svc);
        self
    }

    /// Set the IPS service for auto-blacklisting on IDS detections.
    #[must_use]
    pub fn with_ips_service(mut self, svc: Arc<ArcSwap<IpsAppService>>) -> Self {
        self.ips_service = Some(svc);
        self
    }

    /// Add custom `DoH` resolver domains for encrypted DNS detection.
    #[must_use]
    pub fn with_doh_resolvers(mut self, resolvers: &[String]) -> Self {
        self.encrypted_dns_detector.add_custom_resolvers(resolvers);
        self
    }

    /// Set the DLP service for processing DLP events.
    #[must_use]
    pub fn with_dlp_service(mut self, svc: Arc<ArcSwap<DlpAppService>>) -> Self {
        self.dlp_service = Some(svc);
        self
    }

    /// Set the `DDoS` service for processing `DDoS` events.
    #[must_use]
    pub fn with_ddos_service(mut self, svc: Arc<ArcSwap<DdosAppService>>) -> Self {
        self.ddos_service = Some(svc);
        self
    }

    /// Set the DNS blocklist service for evaluating DNS responses.
    #[must_use]
    pub fn with_dns_blocklist_svc(mut self, svc: Arc<DnsBlocklistAppService>) -> Self {
        self.dns_blocklist_svc = Some(svc);
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
                        self.dispatch_agent_event(event);
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            count += 1;
                            self.dispatch_agent_event(event);
                        }
                        None => break, // channel closed
                    }
                }
            }
        }

        tracing::info!(total_events = count, "event dispatcher stopped");
    }

    /// Parallel event loop. Spawns `num_workers` worker tasks and a
    /// distributor that hashes each event's source address to a worker
    /// channel, preserving per-source ordering.
    ///
    /// Falls back to single-threaded [`run`](Self::run) when `num_workers <= 1`.
    pub async fn run_parallel(
        self,
        num_workers: usize,
        rx: mpsc::Receiver<AgentEvent>,
        cancel_token: CancellationToken,
    ) {
        if num_workers <= 1 {
            return self.run(rx, cancel_token).await;
        }

        let channel_size = 4096;
        let mut worker_txs = Vec::with_capacity(num_workers);
        let mut handles = Vec::with_capacity(num_workers);

        for id in 0..num_workers {
            let (tx, worker_rx) = mpsc::channel::<AgentEvent>(channel_size);
            worker_txs.push(tx);

            let worker = self.clone();
            let token = cancel_token.clone();
            handles.push(tokio::spawn(async move {
                worker.run_worker(id, worker_rx, token).await;
            }));
        }

        // Distributor: read from main channel, hash src_addr, send to worker
        Self::distribute(rx, worker_txs, num_workers, cancel_token.clone()).await;

        // Wait for all workers to finish draining
        for handle in handles {
            let _ = handle.await;
        }

        tracing::info!(num_workers, "parallel event dispatcher stopped");
    }

    async fn distribute(
        mut rx: mpsc::Receiver<AgentEvent>,
        worker_txs: Vec<mpsc::Sender<AgentEvent>>,
        num_workers: usize,
        cancel_token: CancellationToken,
    ) {
        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    // Drain remaining events
                    while let Ok(event) = rx.try_recv() {
                        let idx = Self::worker_index(&event, num_workers);
                        let _ = worker_txs[idx].send(event).await;
                    }
                    // Drop senders to signal workers to finish
                    drop(worker_txs);
                    break;
                }
                msg = rx.recv() => {
                    if let Some(event) = msg {
                        let idx = Self::worker_index(&event, num_workers);
                        if worker_txs[idx].send(event).await.is_err() {
                            break; // worker gone
                        }
                    } else {
                        drop(worker_txs);
                        break;
                    }
                }
            }
        }
    }

    async fn run_worker(
        self,
        id: usize,
        mut rx: mpsc::Receiver<AgentEvent>,
        cancel_token: CancellationToken,
    ) {
        let mut count: u64 = 0;

        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    while let Ok(event) = rx.try_recv() {
                        count += 1;
                        self.dispatch_agent_event(event);
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            count += 1;
                            self.dispatch_agent_event(event);
                        }
                        None => break,
                    }
                }
            }
        }

        tracing::debug!(worker_id = id, total_events = count, "event worker stopped");
    }

    /// Deterministic worker selection based on source address.
    /// Events from the same source always go to the same worker,
    /// preserving per-source ordering. XOR-folds all 4 address words
    /// for good distribution across both IPv4 and IPv6.
    fn worker_index(event: &AgentEvent, num_workers: usize) -> usize {
        let hash = match event {
            AgentEvent::L4(pkt) => {
                pkt.src_addr[0] ^ pkt.src_addr[1] ^ pkt.src_addr[2] ^ pkt.src_addr[3]
            }
            AgentEvent::L7 { header, .. } => {
                header.src_addr[0] ^ header.src_addr[1] ^ header.src_addr[2] ^ header.src_addr[3]
            }
            AgentEvent::Dns { header, .. } => {
                header.src_addr[0] ^ header.src_addr[1] ^ header.src_addr[2] ^ header.src_addr[3]
            }
            AgentEvent::Dlp(ev) => ev.pid ^ ev.tgid,
        };
        hash as usize % num_workers
    }

    fn dispatch_agent_event(&self, event: AgentEvent) {
        let start = std::time::Instant::now();
        let program = match &event {
            AgentEvent::L4(pkt) => event_type_label(pkt.event_type),
            AgentEvent::L7 { .. } => "l7",
            AgentEvent::Dns { .. } => "dns",
            AgentEvent::Dlp(_) => "dlp",
        };
        match event {
            AgentEvent::L4(pkt) => self.dispatch_event(pkt),
            AgentEvent::L7 { header, payload } => self.process_l7_event(header, &payload),
            AgentEvent::Dns { header, payload } => self.process_dns_event(header, &payload),
            AgentEvent::Dlp(event) => self.process_dlp_event(&event),
        }
        self.metrics
            .observe_processing_duration(program, start.elapsed().as_secs_f64());
    }

    fn dispatch_event(&self, event: PacketEvent) {
        match event.event_type {
            EVENT_TYPE_FIREWALL => self.process_firewall_event(event),
            EVENT_TYPE_IDS => self.process_ids_event(event),
            EVENT_TYPE_RATELIMIT => self.process_ratelimit_event(event),
            EVENT_TYPE_THREATINTEL => {
                self.process_threatintel_event(event);
            }
            EVENT_TYPE_DDOS_SYN
            | EVENT_TYPE_DDOS_ICMP
            | EVENT_TYPE_DDOS_AMP
            | EVENT_TYPE_DDOS_CONNTRACK => {
                self.process_ddos_event(event);
            }
            EVENT_TYPE_LB => {
                self.process_lb_event(&event);
            }
            other => {
                tracing::debug!(event_type = other, "unhandled event type");
                self.metrics.record_packet("unknown", "unknown");
            }
        }
    }

    fn process_firewall_event(&self, event: PacketEvent) {
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
        self.audit_service.record_security_decision(
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

        if event.action == 1 {
            self.emit_packet_security_alert(
                domain::alert::entity::PacketAlertComponent::Firewall,
                &event,
                &event.rule_id.to_string(),
                action,
                &detail,
            );
        }
    }

    fn process_ratelimit_event(&self, event: PacketEvent) {
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
        self.audit_service.record_security_decision(
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

        if event.action == 1 {
            self.emit_packet_security_alert(
                domain::alert::entity::PacketAlertComponent::Ratelimit,
                &event,
                "",
                action,
                &detail,
            );
        }
    }

    fn process_ids_event(&self, event: PacketEvent) {
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

        // Evaluate and threshold check (all methods are now &self via interior mutability)
        let (_rule_clone, alert, detail, _src_country) = {
            let svc = self.ids_service.load();

            if !svc.enabled() {
                return;
            }

            // Resolve source country for country-aware sampling and thresholds
            let src_country = svc.resolve_country(event.src_addr, event.is_ipv6());

            let Some((_idx, rule, matched_domain)) =
                svc.evaluate_event_with_context(&event, &dst_domains, src_country.as_deref())
            else {
                return;
            };

            let detail = format!("IDS rule {} matched", rule.id);
            let mut alert = IdsAlert::from_event(&event, rule);
            if matched_domain.is_some() {
                self.metrics.record_ids_domain_match(&rule.id.0);
            }
            alert.matched_domain = matched_domain;
            let rule_clone = rule.clone();
            let threshold = rule.threshold.clone();

            // Threshold check with country-aware overrides (now &self, no write lock needed)
            if threshold.is_some()
                && !svc.check_threshold_with_country(
                    &rule_clone,
                    event.src_addr[0],
                    event.dst_addr[0],
                    src_country.as_deref(),
                )
            {
                return; // Suppressed by threshold
            }

            (rule_clone, alert, detail, src_country)
        };

        self.audit_service.record_security_decision(
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

        if self.alert_tx.try_send(AlertEvent::Ids(alert)).is_err() {
            self.metrics.record_event_dropped("alert_channel_full");
        }

        // Feed detection into IPS for auto-blacklisting
        if let Some(ref ips_svc) = self.ips_service {
            let src_ip = addr_to_ip(event.src_addr, event.is_ipv6());
            let svc = ips_svc.load();
            let actions = svc.record_detection(src_ip);

            // Emit alert when IPS auto-blacklists an IP
            if !actions.is_empty() {
                let detail = format!("IPS auto-blacklist: {src_ip}");
                self.emit_packet_security_alert(
                    domain::alert::entity::PacketAlertComponent::Ips,
                    &event,
                    &format!("ips-blacklist:{src_ip}"),
                    "blacklist",
                    &detail,
                );
            }
        }
    }

    fn process_threatintel_event(&self, event: PacketEvent) {
        let action = action_label(event.action);
        self.metrics.record_packet("threatintel", action);

        let svc = self.threatintel_service.load();

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
        self.audit_service.record_security_decision(
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

        if self.alert_tx.try_send(AlertEvent::Ids(ids_alert)).is_err() {
            self.metrics.record_event_dropped("alert_channel_full");
        }
    }

    fn process_l7_event(&self, header: PacketEvent, payload: &[u8]) {
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

        // Compute and cache JA4 fingerprint for TLS connections
        if let ParsedProtocol::Tls(ref tls_hello) = parsed {
            let fp = ja4::compute_ja4(tls_hello);
            self.metrics.record_fingerprint_seen(&fp.ja4);
            let flow_key = FlowKey {
                src_addr: header.src_addr,
                src_port: header.src_port,
                dst_addr: header.dst_addr,
                dst_port: header.dst_port,
            };
            self.fingerprint_cache.insert(flow_key, fp);

            // Detect encrypted DNS (DoH/DoT)
            self.check_encrypted_dns(tls_hello, &header);
        }

        // Evaluate L7 rules against parsed content
        let l7_svc = self.l7_service.load();
        let l7_result = l7_svc.evaluate(&header, &parsed);
        drop(l7_svc);

        if let Some((action, rule_id)) = l7_result {
            let action_label = match action {
                FirewallAction::Allow => "allow",
                FirewallAction::Deny => "deny",
                FirewallAction::Log => "log",
                FirewallAction::Reject => "reject",
            };

            if action == FirewallAction::Deny
                || action == FirewallAction::Log
                || action == FirewallAction::Reject
            {
                tracing::info!(
                    src_ip = %header.src_ip(),
                    dst_ip = %header.dst_ip(),
                    src_port = header.src_port,
                    dst_port = header.dst_port,
                    l7_protocol = protocol_label,
                    action = action_label,
                    rule_id = %rule_id,
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
                FirewallAction::Deny | FirewallAction::Reject => AuditAction::Drop,
                _ => AuditAction::Pass,
            };
            let detail = format!("L7 {protocol_label} {action_label} rule={rule_id}");
            self.audit_service.record_security_decision(
                AuditComponent::L7,
                audit_action,
                header.timestamp_ns,
                header.src_addr,
                header.dst_addr,
                header.is_ipv6(),
                header.src_port,
                header.dst_port,
                header.protocol,
                &rule_id.0,
                &detail,
            );

            // Emit alert for L7 deny/reject
            if action == FirewallAction::Deny || action == FirewallAction::Reject {
                self.emit_packet_security_alert(
                    domain::alert::entity::PacketAlertComponent::L7,
                    &header,
                    &rule_id.0,
                    action_label,
                    &detail,
                );
            }

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

    fn emit_packet_security_alert(
        &self,
        component: domain::alert::entity::PacketAlertComponent,
        event: &PacketEvent,
        rule_id: &str,
        action_label: &str,
        detail: &str,
    ) {
        let severity = match component {
            domain::alert::entity::PacketAlertComponent::Ips => {
                domain::common::entity::Severity::High
            }
            _ => domain::common::entity::Severity::Medium,
        };
        let psa = domain::alert::entity::PacketSecurityAlert {
            component,
            src_addr: event.src_addr,
            dst_addr: event.dst_addr,
            src_port: event.src_port,
            dst_port: event.dst_port,
            protocol: event.protocol,
            is_ipv6: event.is_ipv6(),
            timestamp_ns: event.timestamp_ns,
            rule_id: rule_id.to_string(),
            action_label: action_label.to_string(),
            severity,
            detail: detail.to_string(),
        };
        let _ = self.alert_tx.try_send(AlertEvent::PacketSecurity(psa));
    }

    fn check_encrypted_dns(
        &self,
        tls_hello: &domain::l7::entity::TlsClientHello,
        header: &PacketEvent,
    ) {
        if let Some(detection) = self.encrypted_dns_detector.detect(
            tls_hello.sni.as_deref(),
            header.dst_port,
            header.src_addr,
            header.dst_addr,
        ) {
            let proto_label = match detection.protocol {
                domain::dns::encrypted_dns::EncryptedDnsProtocol::Doh => "doh",
                domain::dns::encrypted_dns::EncryptedDnsProtocol::Dot => "dot",
            };
            self.metrics
                .record_encrypted_dns(proto_label, &detection.resolver);
            tracing::info!(
                protocol = proto_label,
                resolver = %detection.resolver,
                src_ip = %header.src_ip(),
                dst_port = header.dst_port,
                "encrypted DNS detected"
            );

            // Emit DNS alert for encrypted DNS detection
            let dns_alert = domain::dns::entity::DnsAlert {
                domain: detection.resolver.clone(),
                resolved_ips: Vec::new(),
                reason: domain::dns::entity::DnsAlertReason::EncryptedDns {
                    protocol: proto_label.to_string(),
                    resolver: detection.resolver,
                },
                severity: domain::common::entity::Severity::Medium,
                timestamp_ns: header.timestamp_ns,
            };
            let _ = self.alert_tx.try_send(AlertEvent::Dns(dns_alert));
        }
    }

    fn process_dns_event(&self, header: DnsEvent, payload: &[u8]) {
        let is_tcp = ebpf_common::event::is_tcp(header.flags);
        let direction = if header.direction == ebpf_common::dns::DNS_DIRECTION_RESPONSE {
            "response"
        } else {
            "query"
        };
        let transport = if is_tcp { "tcp" } else { "udp" };

        self.metrics.record_packet("dns", direction);

        tracing::debug!(
            dns_payload_len = header.dns_payload_len,
            direction,
            transport,
            "DNS event received"
        );

        // Only process responses (which contain resolved IPs)
        if header.direction != ebpf_common::dns::DNS_DIRECTION_RESPONSE {
            return;
        }

        let is_ipv6 = (header.flags & ebpf_common::event::FLAG_IPV6) != 0;
        let src_ip = addr_to_ip(header.src_addr, is_ipv6);
        let parsed =
            match domain::dns::parser::parse_dns_packet(payload, src_ip, header.timestamp_ns) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(error = %e, "DNS packet parse error");
                    return;
                }
            };

        let domain::dns::entity::DnsPacket::Response(response) = parsed else {
            return;
        };

        // Insert each answer record into DNS cache
        if let Some(ref cache_svc) = self.dns_cache_svc {
            for record in &response.answers {
                if !record.resolved_ips.is_empty() {
                    cache_svc.insert(
                        record.domain.clone(),
                        record.resolved_ips.clone(),
                        u64::from(record.ttl),
                        header.timestamp_ns,
                    );
                }
            }
        }

        // Check DNS blocklist for each answered domain
        if let Some(ref blocklist_svc) = self.dns_blocklist_svc {
            for record in &response.answers {
                if !record.resolved_ips.is_empty() {
                    blocklist_svc.on_dns_response(
                        &record.domain,
                        &record.resolved_ips,
                        record.ttl,
                        header.timestamp_ns,
                    );
                }
            }
        }
    }

    fn process_dlp_event(&self, event: &DlpEvent) {
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
            let svc = dlp_svc.load();
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

                let patterns = svc.list_patterns();
                for m in &matches {
                    if let Some(pattern) = patterns.get(m.pattern_index) {
                        let dlp_alert = DlpAlert::from_event(event, pattern);
                        if self.alert_tx.try_send(AlertEvent::Dlp(dlp_alert)).is_err() {
                            self.metrics.record_event_dropped("alert_channel_full");
                        }
                    }
                }
            }
        }
    }

    fn process_ddos_event(&self, event: PacketEvent) {
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

        let svc = ddos_service.load();
        let changed = svc.process_event(&ddos_event);

        if changed {
            tracing::info!(
                attack_type = ?attack_type,
                src_ip = %event.src_ip(),
                dst_ip = %event.dst_ip(),
                "DDoS attack state changed"
            );

            // Find the most recent matching attack and send an alert
            if let Some(attack) = svc
                .active_attacks()
                .iter()
                .rev()
                .find(|a| a.attack_type == attack_type)
            {
                let alert = AlertEvent::Ddos {
                    attack: attack.clone(),
                    src_addr: event.src_addr,
                    dst_addr: event.dst_addr,
                    is_ipv6: event.is_ipv6(),
                    src_port: event.src_port,
                    dst_port: event.dst_port,
                    protocol: event.protocol,
                };
                if self.alert_tx.try_send(alert).is_err() {
                    self.metrics.record_event_dropped("alert_channel_full");
                }
            }
        }

        self.audit_service.record_security_decision(
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

    fn process_lb_event(&self, event: &PacketEvent) {
        let action_label = match event.action {
            LB_ACTION_FORWARD => "forward",
            LB_ACTION_NO_BACKEND => "no_backend",
            _ => "unknown",
        };
        self.metrics.record_packet("loadbalancer", action_label);

        tracing::debug!(
            src_ip = %event.src_ip(),
            dst_ip = %event.dst_ip(),
            src_port = event.src_port,
            dst_port = event.dst_port,
            protocol = event.protocol,
            action = action_label,
            "load balancer event"
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

fn event_type_label(event_type: u8) -> &'static str {
    match event_type {
        EVENT_TYPE_FIREWALL => "firewall",
        EVENT_TYPE_IDS => "ids",
        EVENT_TYPE_RATELIMIT => "ratelimit",
        EVENT_TYPE_THREATINTEL => "threatintel",
        EVENT_TYPE_DDOS_SYN
        | EVENT_TYPE_DDOS_ICMP
        | EVENT_TYPE_DDOS_AMP
        | EVENT_TYPE_DDOS_CONNTRACK => "ddos",
        EVENT_TYPE_LB => "lb",
        _ => "unknown",
    }
}

use crate::addr_to_ip;

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
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
        DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics, FirewallMetrics, IpsMetrics,
        LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
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
    impl DlpMetrics for TestMetrics {}
    impl DdosMetrics for TestMetrics {}
    impl ConntrackMetrics for TestMetrics {}
    impl RoutingMetrics for TestMetrics {}
    impl AuditMetrics for TestMetrics {}
    impl LbMetrics for TestMetrics {}
    impl FingerprintMetrics for TestMetrics {}

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
            country_thresholds: None,
            group_mask: 0,
        }
    }

    fn make_event(event_type: u8, rule_id: u32) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
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

    fn make_service_with_rules(rules: Vec<IdsRule>) -> Arc<ArcSwap<IdsAppService>> {
        let mut engine = IdsEngine::new();
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(IdsAppService::new(
            engine, None, metrics,
        )))
    }

    fn make_l7_service() -> Arc<ArcSwap<L7AppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(L7AppService::new(
            L7Engine::new(),
            metrics,
        )))
    }

    fn make_ti_service() -> Arc<ArcSwap<ThreatIntelAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(ThreatIntelAppService::new(
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

    fn make_audit_service() -> Arc<AuditAppService> {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        Arc::new(AuditAppService::new(sink))
    }

    fn make_l7_service_with_rules(rules: Vec<L7Rule>) -> Arc<ArcSwap<L7AppService>> {
        let mut engine = L7Engine::new();
        for rule in rules {
            engine.add_rule(rule).unwrap();
        }
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(L7AppService::new(engine, metrics)))
    }

    fn make_dispatcher(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<AlertEvent>,
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

    /// Unwrap an `AlertEvent::Ids` variant for test assertions.
    fn unwrap_ids_alert(event: AlertEvent) -> IdsAlert {
        match event {
            AlertEvent::Ids(a) => a,
            _ => panic!("expected AlertEvent::Ids"),
        }
    }

    fn make_dispatcher_with_l7(
        ids_service: Arc<ArcSwap<IdsAppService>>,
        l7_service: Arc<ArcSwap<L7AppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<AlertEvent>,
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

        dispatcher.dispatch_event(make_event(EVENT_TYPE_FIREWALL, 0));

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

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
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
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 99));

        assert!(alert_rx.try_recv().is_err());
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ids_event_with_disabled_service_produces_no_alert() {
        let ids = make_service_with_rules(vec![make_ids_rule("ids-001")]);
        {
            let mut svc = (**ids.load()).clone();
            svc.set_enabled(false);
            ids.store(Arc::new(svc));
        }
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        assert!(alert_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn unknown_event_type_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        dispatcher.dispatch_event(make_event(EVENT_TYPE_DLP, 0));

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
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));
        // This should trigger backpressure
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

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
        dispatcher.dispatch_event(event);
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");

        // action=2 (log)
        event.action = 2;
        dispatcher.dispatch_event(event);
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
        dispatcher.dispatch_event(event);

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
        dispatcher.dispatch_event(event);

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

        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

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

        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

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
            src_country_codes: None,
            dst_country_codes: None,
            src_ip_alias: None,
            dst_ip_alias: None,
            dst_port_alias: None,
        }]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"DELETE /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec();
        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

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
        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

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
            src_country_codes: None,
            dst_country_codes: None,
            src_ip_alias: None,
            dst_ip_alias: None,
            dst_port_alias: None,
        }]);
        {
            let mut svc = (**l7.load()).clone();
            svc.set_enabled(false);
            l7.store(Arc::new(svc));
        }
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher =
            make_dispatcher_with_l7(Arc::clone(&ids), l7, Arc::clone(&metrics), alert_tx);

        let header = make_event(EVENT_TYPE_L7, 0);
        let payload = b"DELETE /admin HTTP/1.1\r\nHost: evil.com\r\n\r\n".to_vec();
        dispatcher.dispatch_agent_event(AgentEvent::L7 { header, payload });

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
        ids_service: Arc<ArcSwap<IdsAppService>>,
        metrics: Arc<TestMetrics>,
        alert_tx: mpsc::Sender<AlertEvent>,
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

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
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

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

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

        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));

        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
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
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 0));
        assert!(alert_rx.try_recv().is_err());

        // Event for rule index 1 (IP-only rule) — should match
        dispatcher.dispatch_event(make_event(EVENT_TYPE_IDS, 1));
        let alert = unwrap_ids_alert(alert_rx.try_recv().unwrap());
        assert_eq!(alert.rule_id.0, "ids-002");
    }

    // ── Load Balancer dispatch tests ────────────────────────────────

    #[tokio::test]
    async fn lb_forward_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_LB, 0);
        event.action = LB_ACTION_FORWARD;
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "loadbalancer");
        assert_eq!(*metrics.last_action.lock().unwrap(), "forward");
    }

    #[tokio::test]
    async fn lb_no_backend_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_LB, 0);
        event.action = LB_ACTION_NO_BACKEND;
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "loadbalancer");
        assert_eq!(*metrics.last_action.lock().unwrap(), "no_backend");
    }

    // ── DDoS dispatch tests ──────────────────────────────────────

    use crate::ddos_service_impl::DdosAppService;
    use domain::ddos::engine::DdosEngine;

    fn make_ddos_service() -> Arc<ArcSwap<DdosAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        Arc::new(ArcSwap::from_pointee(DdosAppService::new(
            DdosEngine::new(),
            metrics,
        )))
    }

    #[tokio::test]
    async fn ddos_syn_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_DDOS_SYN, 0);
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
        assert_eq!(*metrics.last_action.lock().unwrap(), "drop");
    }

    #[tokio::test]
    async fn ddos_event_without_service_does_nothing() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        // No ddos_service attached (default make_dispatcher sets it to None)
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_DDOS_ICMP, 0);
        dispatcher.dispatch_event(event);

        // Metric is still recorded even without a service
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
    }

    #[tokio::test]
    async fn ddos_event_with_service_processes() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let ddos = make_ddos_service();
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_ddos_service(Arc::clone(&ddos));

        let event = make_event(EVENT_TYPE_DDOS_SYN, 0);
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
    }

    // ── Threatintel dispatch tests ───────────────────────────────

    use domain::threatintel::entity::{Ioc, ThreatType};

    #[tokio::test]
    async fn threatintel_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let event = make_event(EVENT_TYPE_THREATINTEL, 0);
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "threatintel");
        assert_eq!(*metrics.last_action.lock().unwrap(), "pass");
    }

    #[tokio::test]
    async fn threatintel_event_disabled_service_no_alert() {
        let ids = make_service_with_rules(vec![]);
        let ti = make_ti_service();
        {
            let mut svc = (**ti.load()).clone();
            svc.set_enabled(false);
            ti.store(Arc::new(svc));
        }
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        let dispatcher = EventDispatcher::new(
            ids,
            make_l7_service(),
            Arc::clone(&ti),
            make_audit_service(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            alert_tx,
            None,
        );

        let event = make_event(EVENT_TYPE_THREATINTEL, 0);
        dispatcher.dispatch_event(event);

        assert!(alert_rx.try_recv().is_err());
        // Metric is still recorded before the enabled check returns
        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn threatintel_event_with_matching_ioc_produces_alert() {
        let ids = make_service_with_rules(vec![]);
        let ti = make_ti_service();

        // The src_addr in make_event is 0xC0A8_0001 = 192.168.0.1
        let src_ip: IpAddr = "192.168.0.1".parse().unwrap();
        {
            let mut svc = (**ti.load()).clone();
            svc.add_ioc(Ioc {
                ip: src_ip,
                feed_id: "test-feed".to_string(),
                confidence: 90,
                threat_type: ThreatType::Malware,
                last_seen: 0,
                source_feed: "test".to_string(),
            })
            .unwrap();
            ti.store(Arc::new(svc));
        }

        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);

        let dispatcher = EventDispatcher::new(
            ids,
            make_l7_service(),
            Arc::clone(&ti),
            make_audit_service(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            alert_tx,
            None,
        );

        let event = make_event(EVENT_TYPE_THREATINTEL, 0);
        dispatcher.dispatch_event(event);

        let alert = alert_rx.try_recv().unwrap();
        match alert {
            AlertEvent::Ids(a) => {
                assert!(a.rule_id.0.starts_with("ti-"));
            }
            _ => panic!("expected AlertEvent::Ids from threatintel"),
        }
    }

    // ── DLP dispatch tests ───────────────────────────────────────

    use crate::dlp_service_impl::DlpAppService;
    use domain::dlp::engine::DlpEngine;
    use domain::dlp::entity::DlpPattern;
    use ebpf_common::dlp::DLP_MAX_EXCERPT;

    fn make_dlp_event_with_data(data: &[u8]) -> DlpEvent {
        let mut event = DlpEvent {
            pid: 1000,
            tgid: 2000,
            timestamp_ns: 0,
            #[allow(clippy::cast_possible_truncation)]
            data_len: data.len() as u32, // DLP_MAX_EXCERPT is small, no truncation possible
            direction: 0,
            _padding: [0; 3],
            data_excerpt: [0u8; DLP_MAX_EXCERPT],
        };
        let copy_len = data.len().min(DLP_MAX_EXCERPT);
        event.data_excerpt[..copy_len].copy_from_slice(&data[..copy_len]);
        event
    }

    fn make_dlp_service_with_pattern() -> Arc<ArcSwap<DlpAppService>> {
        let metrics: Arc<dyn MetricsPort> = Arc::new(TestMetrics::new());
        let mut engine = DlpEngine::new();
        engine
            .add_pattern(DlpPattern {
                id: RuleId("dlp-pci-001".to_string()),
                name: "Credit Card".to_string(),
                regex: r"\d{4}".to_string(),
                severity: Severity::High,
                mode: DomainMode::Alert,
                data_type: "pci".to_string(),
                description: String::new(),
                enabled: true,
            })
            .unwrap();
        Arc::new(ArcSwap::from_pointee(DlpAppService::new(engine, metrics)))
    }

    #[tokio::test]
    async fn dlp_event_records_metric() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let dlp_event = make_dlp_event_with_data(b"hello world");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        // record_packet is called twice: once for "dlp"/"captured" in process_dlp_event,
        // and once for observe_processing_duration via dispatch_agent_event.
        // But record_packet records the last call which is "dlp"/"captured".
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
        assert_eq!(*metrics.last_action.lock().unwrap(), "captured");
    }

    #[tokio::test]
    async fn dlp_event_without_service_no_panic() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        // No dlp_service attached (default make_dispatcher sets it to None)
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let dlp_event = make_dlp_event_with_data(b"some data 1234");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        // Metric recorded, no panic
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
        assert_eq!(*metrics.last_action.lock().unwrap(), "captured");
    }

    #[tokio::test]
    async fn dlp_event_with_match_produces_alert() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, mut alert_rx) = mpsc::channel(10);
        let dlp = make_dlp_service_with_pattern();
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx)
            .with_dlp_service(Arc::clone(&dlp));

        // Data containing 4 consecutive digits should match the \d{4} pattern
        let dlp_event = make_dlp_event_with_data(b"card number 1234 here");
        dispatcher.dispatch_agent_event(AgentEvent::Dlp(Box::new(dlp_event)));

        let alert = alert_rx.try_recv().unwrap();
        match alert {
            AlertEvent::Dlp(a) => {
                assert_eq!(a.pattern_id.0, "dlp-pci-001");
                assert_eq!(a.pattern_name, "Credit Card");
            }
            _ => panic!("expected AlertEvent::Dlp"),
        }
    }

    // ── LB unknown action test ───────────────────────────────────

    #[tokio::test]
    async fn lb_unknown_action_records_unknown() {
        let ids = make_service_with_rules(vec![]);
        let metrics = Arc::new(TestMetrics::new());
        let (alert_tx, _alert_rx) = mpsc::channel(10);
        let dispatcher = make_dispatcher(Arc::clone(&ids), Arc::clone(&metrics), alert_tx);

        let mut event = make_event(EVENT_TYPE_LB, 0);
        event.action = 255;
        dispatcher.dispatch_event(event);

        assert_eq!(metrics.packet_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "loadbalancer");
        assert_eq!(*metrics.last_action.lock().unwrap(), "unknown");
    }

    // ── Helper function tests ────────────────────────────────────

    #[test]
    fn action_label_all_values() {
        assert_eq!(action_label(0), "pass");
        assert_eq!(action_label(1), "drop");
        assert_eq!(action_label(2), "log");
        assert_eq!(action_label(99), "unknown");
    }

    #[test]
    fn event_type_label_all_values() {
        assert_eq!(event_type_label(EVENT_TYPE_FIREWALL), "firewall");
        assert_eq!(event_type_label(EVENT_TYPE_IDS), "ids");
        assert_eq!(event_type_label(EVENT_TYPE_RATELIMIT), "ratelimit");
        assert_eq!(event_type_label(EVENT_TYPE_THREATINTEL), "threatintel");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_SYN), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_ICMP), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_AMP), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_DDOS_CONNTRACK), "ddos");
        assert_eq!(event_type_label(EVENT_TYPE_LB), "lb");
        assert_eq!(event_type_label(254), "unknown");
    }
}
