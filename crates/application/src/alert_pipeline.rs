use std::sync::Arc;

use domain::alert::engine::AlertRouter;
use domain::alert::entity::PacketSecurityAlert;
use domain::alert::entity::{Alert, AlertDestination};
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::ddos::entity::DdosAttack;
use domain::dlp::entity::DlpAlert;
use domain::dns::entity::{DnsAlert, DnsAlertReason};
use domain::ids::entity::IdsAlert;
use ports::secondary::alert_enrichment_port::AlertEnrichmentPort;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::alert_store::AlertStore;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::alert_event::AlertEvent;
use crate::audit_service_impl::AuditAppService;
use crate::ips_service_impl::IpsAppService;

/// Alert pipeline application service.
///
/// Converts `IdsAlert`s into full-context `Alert`s, passes them through
/// the `AlertRouter` for dedup/throttle/route matching, records metrics,
/// and dispatches matched alerts to the appropriate senders.
pub struct AlertPipeline {
    router: AlertRouter,
    metrics: Arc<dyn MetricsPort>,
    audit_service: Arc<RwLock<AuditAppService>>,
    log_sender: Option<Arc<dyn AlertSender>>,
    webhook_sender: Option<Arc<dyn AlertSender>>,
    email_sender: Option<Arc<dyn AlertSender>>,
    otlp_sender: Option<Arc<dyn AlertSender>>,
    /// Optional broadcast sender for gRPC alert streaming.
    /// Non-blocking: sends are best-effort (dropped if no receivers or lagged).
    stream_tx: Option<broadcast::Sender<Alert>>,
    /// Optional persistent alert store for query and false-positive marking.
    alert_store: Option<Arc<dyn AlertStore>>,
    /// Optional enricher for adding domain context to alerts.
    enricher: Option<Arc<dyn AlertEnrichmentPort>>,
    /// Optional simple auto-response evaluator (OSS).
    auto_response: Option<AutoResponseHandler>,
    /// Optional auto-capture trigger (OSS).
    auto_capture: Option<AutoCaptureHandler>,
}

/// Auto-capture trigger: starts a PCAP capture when a high-severity alert fires.
pub struct AutoCaptureHandler {
    policy: domain::capture::entity::AutoCapturePolicy,
    capture_engine: Arc<RwLock<domain::capture::engine::CaptureEngine>>,
    /// Channel to send capture requests to the spawner (adapters layer).
    capture_tx: mpsc::Sender<domain::capture::entity::AutoCaptureRequest>,
}

/// Simple auto-response: evaluates alerts against severity-based policies
/// and enforces block/throttle via the IPS blacklist.
pub struct AutoResponseHandler {
    policies: Vec<domain::response::entity::SimpleResponsePolicy>,
    ips_service: Arc<RwLock<IpsAppService>>,
}

impl AlertPipeline {
    pub fn new(
        router: AlertRouter,
        metrics: Arc<dyn MetricsPort>,
        audit_service: Arc<RwLock<AuditAppService>>,
    ) -> Self {
        Self {
            router,
            metrics,
            audit_service,
            log_sender: None,
            webhook_sender: None,
            email_sender: None,
            otlp_sender: None,
            stream_tx: None,
            alert_store: None,
            enricher: None,
            auto_response: None,
            auto_capture: None,
        }
    }

    /// Attach a broadcast sender for real-time gRPC alert streaming.
    #[must_use]
    pub fn with_stream_sender(mut self, tx: broadcast::Sender<Alert>) -> Self {
        self.stream_tx = Some(tx);
        self
    }

    /// Attach a persistent alert store for query and false-positive marking.
    #[must_use]
    pub fn with_alert_store(mut self, store: Arc<dyn AlertStore>) -> Self {
        self.alert_store = Some(store);
        self
    }

    /// Attach an alert enricher for adding domain context (reverse DNS, reputation).
    #[must_use]
    pub fn with_enricher(mut self, enricher: Arc<dyn AlertEnrichmentPort>) -> Self {
        self.enricher = Some(enricher);
        self
    }

    /// Attach an auto-capture handler (OSS).
    /// Captures are triggered via an `mpsc` channel — the receiver spawns the
    /// actual pcap task in the adapters layer.
    #[must_use]
    pub fn with_auto_capture(
        mut self,
        policy: domain::capture::entity::AutoCapturePolicy,
        capture_engine: Arc<RwLock<domain::capture::engine::CaptureEngine>>,
        capture_tx: mpsc::Sender<domain::capture::entity::AutoCaptureRequest>,
    ) -> Self {
        tracing::info!(
            policy = %policy.name,
            min_severity = ?policy.min_severity,
            duration_secs = policy.duration_secs,
            "auto-capture enabled (OSS)"
        );
        self.auto_capture = Some(AutoCaptureHandler {
            policy,
            capture_engine,
            capture_tx,
        });
        self
    }

    /// Attach a simple auto-response handler (OSS).
    #[must_use]
    pub fn with_auto_response(
        mut self,
        policies: Vec<domain::response::entity::SimpleResponsePolicy>,
        ips_service: Arc<RwLock<IpsAppService>>,
    ) -> Self {
        if !policies.is_empty() {
            tracing::info!(
                policy_count = policies.len(),
                "auto-response enabled (OSS simple mode)"
            );
            self.auto_response = Some(AutoResponseHandler {
                policies,
                ips_service,
            });
        }
        self
    }

    #[must_use]
    pub fn with_log_sender(mut self, sender: Arc<dyn AlertSender>) -> Self {
        self.log_sender = Some(sender);
        self
    }

    #[must_use]
    pub fn with_webhook_sender(mut self, sender: Arc<dyn AlertSender>) -> Self {
        self.webhook_sender = Some(sender);
        self
    }

    #[must_use]
    pub fn with_email_sender(mut self, sender: Arc<dyn AlertSender>) -> Self {
        self.email_sender = Some(sender);
        self
    }

    #[must_use]
    pub fn with_otlp_sender(mut self, sender: Arc<dyn AlertSender>) -> Self {
        self.otlp_sender = Some(sender);
        self
    }

    /// Process a single IDS alert: convert to domain Alert, record metric,
    /// pass through router, and dispatch to matching senders.
    pub async fn process_alert(&mut self, ids_alert: &IdsAlert) {
        let description = format!(
            "IDS rule {} matched: {}:{} -> {}:{}",
            ids_alert.rule_id,
            ids_alert.src_ip(),
            ids_alert.src_port,
            ids_alert.dst_ip(),
            ids_alert.dst_port,
        );
        let mut alert = Alert::from_ids_alert(ids_alert, &description);

        // Enrich with domain context (best-effort)
        if let Some(ref enricher) = self.enricher {
            enricher.enrich_alert(&mut alert);
        }

        // Record alert metrics
        let severity_str = severity_label(alert.severity);
        let technique_id = alert
            .mitre_attack
            .as_ref()
            .map_or("", |m| m.technique_id.as_str());
        self.metrics
            .record_alert(&alert.component, severity_str, technique_id);
        self.metrics
            .record_alert_by_rule(&alert.component, &alert.rule_id.0);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Pass through router (dedup, throttle, route matching)
        let matched_routes: Vec<_> = self
            .router
            .process_alert(&alert)
            .into_iter()
            .map(|(i, r)| (i, r.clone()))
            .collect();

        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            tracing::debug!(
                rule_id = %alert.rule_id,
                severity = severity_str,
                "alert dropped: no matching route or dedup/throttle"
            );
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Process a single DLP alert: convert to domain Alert, record metric,
    /// pass through router, and dispatch to matching senders.
    pub async fn process_dlp_alert(&mut self, dlp_alert: &DlpAlert) {
        let description = format!(
            "DLP pattern {} ({}) matched on pid {} ({})",
            dlp_alert.pattern_name, dlp_alert.data_type, dlp_alert.pid, dlp_alert.redacted_excerpt,
        );
        let mut alert = Alert::from_dlp_alert(dlp_alert, &description);

        // Enrich with domain context (best-effort)
        if let Some(ref enricher) = self.enricher {
            enricher.enrich_alert(&mut alert);
        }

        // Record audit entry for DLP violation
        let audit_detail = format!(
            "DLP {} ({}) pid={}",
            dlp_alert.pattern_name, dlp_alert.data_type, dlp_alert.pid,
        );
        self.audit_service.read().await.record_security_decision(
            AuditComponent::Dlp,
            AuditAction::PolicyViolation,
            dlp_alert.timestamp_ns,
            [0; 4],
            [0; 4],
            false,
            0,
            0,
            0,
            &dlp_alert.pattern_id.0,
            &audit_detail,
        );

        // Record alert metrics
        let severity_str = severity_label(alert.severity);
        let technique_id = alert
            .mitre_attack
            .as_ref()
            .map_or("", |m| m.technique_id.as_str());
        self.metrics
            .record_alert(&alert.component, severity_str, technique_id);
        self.metrics
            .record_alert_by_rule(&alert.component, &alert.rule_id.0);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store DLP alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Pass through router (dedup, throttle, route matching)
        let matched_routes: Vec<_> = self
            .router
            .process_alert(&alert)
            .into_iter()
            .map(|(i, r)| (i, r.clone()))
            .collect();

        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            tracing::debug!(
                pattern_id = %alert.rule_id,
                severity = severity_str,
                "DLP alert dropped: no matching route or dedup/throttle"
            );
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Process a `DDoS` attack state change: convert to domain Alert, record metric,
    /// pass through router, and dispatch to matching senders.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_ddos_alert(
        &mut self,
        attack: &DdosAttack,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        is_ipv6: bool,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) {
        let description = format!(
            "DDoS {:?} attack {} — status: {:?}, peak: {} pps, current: {} pps",
            attack.attack_type,
            attack.id,
            attack.mitigation_status,
            attack.peak_pps,
            attack.current_pps,
        );
        let mut alert = Alert::from_ddos_attack(
            attack,
            src_addr,
            dst_addr,
            is_ipv6,
            src_port,
            dst_port,
            protocol,
            &description,
        );

        // Enrich with domain context (best-effort)
        if let Some(ref enricher) = self.enricher {
            enricher.enrich_alert(&mut alert);
        }

        // Record alert metrics
        let severity_str = severity_label(alert.severity);
        let technique_id = alert
            .mitre_attack
            .as_ref()
            .map_or("", |m| m.technique_id.as_str());
        self.metrics
            .record_alert(&alert.component, severity_str, technique_id);
        self.metrics
            .record_alert_by_rule(&alert.component, &alert.rule_id.0);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store DDoS alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Pass through router (dedup, throttle, route matching)
        let matched_routes: Vec<_> = self
            .router
            .process_alert(&alert)
            .into_iter()
            .map(|(i, r)| (i, r.clone()))
            .collect();

        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            tracing::debug!(
                attack_id = %alert.rule_id,
                severity = severity_str,
                "DDoS alert dropped: no matching route or dedup/throttle"
            );
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Process a packet-level security alert (firewall, ratelimit, L7, IPS).
    pub async fn process_packet_security_alert(&mut self, psa: &PacketSecurityAlert) {
        let mut alert = Alert::from_packet_security_alert(psa);

        if let Some(ref enricher) = self.enricher {
            enricher.enrich_alert(&mut alert);
        }

        let severity_str = severity_label(alert.severity);
        let technique_id = alert
            .mitre_attack
            .as_ref()
            .map_or("", |m| m.technique_id.as_str());
        self.metrics
            .record_alert(&alert.component, severity_str, technique_id);
        self.metrics
            .record_alert_by_rule(&alert.component, &alert.rule_id.0);

        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store {} alert", alert.component);
        }

        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        let matched_routes: Vec<_> = self
            .router
            .process_alert(&alert)
            .into_iter()
            .map(|(i, r)| (i, r.clone()))
            .collect();
        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Process a single DNS alert: convert to domain Alert, record metric,
    /// pass through router, and dispatch to matching senders.
    pub async fn process_dns_alert(&mut self, dns_alert: &DnsAlert) {
        let description = match &dns_alert.reason {
            DnsAlertReason::Blocklist { pattern } => {
                format!(
                    "DNS blocklist match: domain {} matched pattern {}",
                    dns_alert.domain, pattern,
                )
            }
            DnsAlertReason::Reputation { score } => {
                format!(
                    "DNS reputation auto-block: domain {} score {score:.2}",
                    dns_alert.domain,
                )
            }
            DnsAlertReason::EncryptedDns { protocol, resolver } => {
                format!("Encrypted DNS detected: {protocol} to resolver {resolver}",)
            }
        };
        let mut alert = Alert::from_dns_alert(dns_alert, &description);

        // Enrich with domain context (best-effort)
        if let Some(ref enricher) = self.enricher {
            enricher.enrich_alert(&mut alert);
        }

        // Record alert metrics
        let severity_str = severity_label(alert.severity);
        let technique_id = alert
            .mitre_attack
            .as_ref()
            .map_or("", |m| m.technique_id.as_str());
        self.metrics
            .record_alert(&alert.component, severity_str, technique_id);
        self.metrics
            .record_alert_by_rule(&alert.component, &alert.rule_id.0);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store DNS alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Pass through router (dedup, throttle, route matching)
        let matched_routes: Vec<_> = self
            .router
            .process_alert(&alert)
            .into_iter()
            .map(|(i, r)| (i, r.clone()))
            .collect();

        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            tracing::debug!(
                rule_id = %alert.rule_id,
                severity = severity_str,
                "DNS alert dropped: no matching route or dedup/throttle"
            );
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Async run loop: consumes alert events from the channel,
    /// dispatches each one to the appropriate handler, and drains on cancellation.
    pub async fn run(
        mut self,
        mut rx: mpsc::Receiver<AlertEvent>,
        cancel_token: CancellationToken,
    ) {
        let mut count: u64 = 0;

        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    // Drain remaining alerts before exiting
                    while let Ok(event) = rx.try_recv() {
                        count += 1;
                        self.dispatch_alert(event).await;
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(event) => {
                            count += 1;
                            self.dispatch_alert(event).await;
                        }
                        None => break, // channel closed
                    }
                }
            }
        }

        tracing::info!(total_alerts = count, "alert pipeline stopped");
    }

    async fn dispatch_alert(&mut self, event: AlertEvent) {
        match event {
            AlertEvent::Ids(ids_alert) => self.process_alert(&ids_alert).await,
            AlertEvent::Dlp(dlp_alert) => self.process_dlp_alert(&dlp_alert).await,
            AlertEvent::Ddos {
                attack,
                src_addr,
                dst_addr,
                is_ipv6,
                src_port,
                dst_port,
                protocol,
            } => {
                self.process_ddos_alert(
                    &attack, src_addr, dst_addr, is_ipv6, src_port, dst_port, protocol,
                )
                .await;
            }
            AlertEvent::Dns(dns_alert) => self.process_dns_alert(&dns_alert).await,
            AlertEvent::PacketSecurity(psa) => {
                self.process_packet_security_alert(&psa).await;
            }
        }
    }

    /// Evaluate an alert against simple auto-response policies.
    /// If a policy matches, enforce block/throttle via IPS blacklist.
    async fn evaluate_auto_response(&self, alert: &domain::alert::entity::Alert) {
        let Some(ref handler) = self.auto_response else {
            return;
        };

        for policy in &handler.policies {
            // Check severity
            if alert.severity.to_u8() < policy.min_severity.to_u8() {
                continue;
            }
            // Check component filter
            if !policy.components.is_empty()
                && !policy
                    .components
                    .iter()
                    .any(|c| alert.component.eq_ignore_ascii_case(c))
            {
                continue;
            }
            // Extract source IP
            let src_ip = if alert.is_ipv6 {
                let bytes: [u8; 16] = {
                    let mut b = [0u8; 16];
                    for (i, &word) in alert.src_addr.iter().enumerate() {
                        b[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
                    }
                    b
                };
                std::net::IpAddr::from(bytes)
            } else {
                std::net::IpAddr::from(std::net::Ipv4Addr::from(alert.src_addr[0]))
            };

            let reason = format!("auto-response:{} alert={}", policy.name, alert.id);
            let ttl = std::time::Duration::from_secs(policy.ttl_secs);

            let mut ips = handler.ips_service.write().await;
            match ips.add_to_blacklist(src_ip, reason.clone(), ttl) {
                Ok(()) => {
                    tracing::info!(
                        policy = %policy.name,
                        alert_id = %alert.id,
                        src_ip = %src_ip,
                        action = ?policy.action,
                        ttl_secs = policy.ttl_secs,
                        severity = ?alert.severity,
                        component = %alert.component,
                        "auto-response: enforced"
                    );
                    self.metrics.record_auto_response(&policy.name);
                }
                Err(e) => {
                    tracing::warn!(
                        policy = %policy.name,
                        alert_id = %alert.id,
                        src_ip = %src_ip,
                        error = %e,
                        "auto-response: enforcement failed"
                    );
                }
            }
            // Only first matching policy applies (no stacking)
            break;
        }
    }

    /// Evaluate an alert against auto-capture policy.
    /// If it matches and no capture is running, start one with a BPF filter
    /// derived from the alert's source/destination IPs.
    async fn evaluate_auto_capture(&self, alert: &domain::alert::entity::Alert) {
        let Some(ref handler) = self.auto_capture else {
            return;
        };
        let policy = &handler.policy;

        // Check severity
        if alert.severity.to_u8() < policy.min_severity.to_u8() {
            return;
        }
        // Check component filter
        if !policy.components.is_empty()
            && !policy
                .components
                .iter()
                .any(|c| alert.component.eq_ignore_ascii_case(c))
        {
            return;
        }
        // Check if a capture is already running
        if handler.capture_engine.read().await.has_active() {
            tracing::debug!(
                alert_id = %alert.id,
                "auto-capture: skipped (another capture is active)"
            );
            return;
        }

        // Build BPF filter from alert context
        let src_ip = if alert.is_ipv6 {
            let bytes: [u8; 16] = {
                let mut b = [0u8; 16];
                for (i, &word) in alert.src_addr.iter().enumerate() {
                    b[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
                }
                b
            };
            std::net::IpAddr::from(bytes).to_string()
        } else {
            std::net::IpAddr::from(std::net::Ipv4Addr::from(alert.src_addr[0])).to_string()
        };
        let filter = format!("host {src_ip}");

        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let cap_id = format!("auto-{}", now_ns / 1_000_000);
        let output_path = format!("/var/lib/ebpfsentinel/captures/{cap_id}.pcap");

        let session = domain::capture::entity::CaptureSession {
            id: cap_id.clone(),
            filter: filter.clone(),
            duration_secs: policy.duration_secs,
            snap_length: policy.snap_length,
            output_path,
            interface: policy.interface.clone(),
            status: domain::capture::entity::CaptureStatus::Running,
            started_at_ns: now_ns,
            file_size_bytes: 0,
            packets_captured: 0,
        };

        // Register in engine
        {
            let mut engine = handler.capture_engine.write().await;
            if let Err(e) = engine.start(session.clone()) {
                tracing::debug!(alert_id = %alert.id, error = %e, "auto-capture: registration failed");
                return;
            }
        }

        // Send to capture spawner (adapters layer)
        let req = domain::capture::entity::AutoCaptureRequest { session };
        if let Err(e) = handler.capture_tx.try_send(req) {
            tracing::warn!(
                capture_id = %cap_id,
                error = %e,
                "auto-capture: failed to send to spawner"
            );
            handler.capture_engine.write().await.fail(&cap_id);
            return;
        }

        tracing::info!(
            capture_id = %cap_id,
            alert_id = %alert.id,
            severity = ?alert.severity,
            component = %alert.component,
            filter = %filter,
            duration_secs = policy.duration_secs,
            "auto-capture: started"
        );
    }

    /// Hot-reload alert routes without resetting dedup/throttle state.
    pub fn reload_routes(&mut self, routes: Vec<domain::alert::entity::AlertRoute>) {
        self.router.reload_routes(routes);
    }

    /// Resolve the sender for a given destination type.
    fn sender_for(&self, dest: &AlertDestination) -> Option<&Arc<dyn AlertSender>> {
        match dest {
            AlertDestination::Log => self.log_sender.as_ref(),
            AlertDestination::Webhook { .. } => self.webhook_sender.as_ref(),
            AlertDestination::Email { .. } => self.email_sender.as_ref(),
            AlertDestination::Otlp => self.otlp_sender.as_ref(),
        }
    }

    /// Dispatch an alert to all matched route senders **concurrently**.
    ///
    /// Routes are cloned from the router result so that the mutable borrow
    /// on `self.router` (for dedup/throttle state) is released before we
    /// access the immutable senders.
    async fn send_to_destinations(
        &self,
        alert: &Alert,
        matched_routes: Vec<(usize, domain::alert::entity::AlertRoute)>,
    ) {
        let futures: Vec<_> = matched_routes
            .iter()
            .filter_map(|(idx, route)| {
                self.sender_for(&route.destination).map(|sender| {
                    let idx = *idx;
                    let route_name = route.name.clone();
                    async move {
                        if let Err(e) = sender.send(alert, route).await {
                            tracing::warn!(
                                alert_id = %alert.id,
                                route_name = %route_name,
                                route_index = idx,
                                error = %e,
                                "alert send failed"
                            );
                        }
                    }
                })
            })
            .collect();

        futures_util::future::join_all(futures).await;
    }
}

fn severity_label(severity: domain::common::entity::Severity) -> &'static str {
    match severity {
        domain::common::entity::Severity::Low => "low",
        domain::common::entity::Severity::Medium => "medium",
        domain::common::entity::Severity::High => "high",
        domain::common::entity::Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::alert::entity::AlertRoute;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use domain::common::error::DomainError;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
        DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics, FirewallMetrics, IpsMetrics,
        LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    struct TestMetrics {
        alert_calls: AtomicU32,
        dropped_calls: AtomicU32,
        last_component: std::sync::Mutex<String>,
        last_severity: std::sync::Mutex<String>,
        last_drop_reason: std::sync::Mutex<String>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                alert_calls: AtomicU32::new(0),
                dropped_calls: AtomicU32::new(0),
                last_component: std::sync::Mutex::new(String::new()),
                last_severity: std::sync::Mutex::new(String::new()),
                last_drop_reason: std::sync::Mutex::new(String::new()),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {
        fn record_alert(&self, component: &str, severity: &str, _technique_id: &str) {
            self.alert_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_component.lock().unwrap() = component.to_string();
            *self.last_severity.lock().unwrap() = severity.to_string();
        }
        fn record_alert_dropped(&self, reason: &str) {
            self.dropped_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_drop_reason.lock().unwrap() = reason.to_string();
        }
    }
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {}
    impl DlpMetrics for TestMetrics {}
    impl DdosMetrics for TestMetrics {}
    impl ConntrackMetrics for TestMetrics {}
    impl RoutingMetrics for TestMetrics {}
    impl AuditMetrics for TestMetrics {}
    impl LbMetrics for TestMetrics {}
    impl FingerprintMetrics for TestMetrics {}

    fn make_ids_alert(rule_id: &str, severity: Severity) -> IdsAlert {
        IdsAlert {
            rule_id: RuleId(rule_id.to_string()),
            severity,
            mode: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            is_ipv6: false,
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            rule_index: 0,
            timestamp_ns: 1_000_000_000,
            matched_domain: None,
        }
    }

    fn make_route(name: &str, min_severity: Severity) -> AlertRoute {
        AlertRoute {
            name: name.to_string(),
            destination: AlertDestination::Log,
            min_severity,
            event_types: None,
        }
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

    #[allow(clippy::similar_names)]
    fn make_pipeline(routes: Vec<AlertRoute>, metrics: Arc<TestMetrics>) -> AlertPipeline {
        let router = AlertRouter::new(
            routes,
            Duration::from_secs(0), // no dedup for tests
            Duration::from_secs(300),
            100,
        );
        AlertPipeline::new(
            router,
            metrics as Arc<dyn MetricsPort>,
            make_audit_service(),
        )
    }

    #[tokio::test]
    async fn alert_processed_and_metric_recorded() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ids");
        assert_eq!(*metrics.last_severity.lock().unwrap(), "high");
    }

    #[tokio::test]
    async fn dedup_skips_duplicate() {
        let metrics = Arc::new(TestMetrics::new());
        let router = AlertRouter::new(
            vec![make_route("all", Severity::Low)],
            Duration::from_secs(60), // dedup enabled
            Duration::from_secs(300),
            100,
        );
        let mut pipeline = AlertPipeline::new(
            router,
            metrics as Arc<dyn MetricsPort>,
            make_audit_service(),
        );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;
        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        // Both alerts are recorded as alerts_total, but second has no route match (dedup)
    }

    #[tokio::test]
    async fn throttle_excess_dropped() {
        let metrics = Arc::new(TestMetrics::new());
        let router = AlertRouter::new(
            vec![make_route("all", Severity::Low)],
            Duration::from_secs(0),
            Duration::from_secs(300),
            1, // throttle max = 1
        );
        let mut pipeline = AlertPipeline::new(
            router,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            make_audit_service(),
        );

        // First alert passes
        let mut alert1 = make_ids_alert("ids-001", Severity::High);
        alert1.src_addr = [1, 0, 0, 0];
        pipeline.process_alert(&alert1).await;
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 0);

        // Second alert from same rule throttled
        let mut alert2 = make_ids_alert("ids-001", Severity::High);
        alert2.src_addr = [2, 0, 0, 0];
        pipeline.process_alert(&alert2).await;
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn matching_route_dispatches() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline = make_pipeline(
            vec![
                make_route("all", Severity::Low),
                make_route("high-only", Severity::High),
            ],
            Arc::clone(&metrics),
        );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn no_matching_route_logged_as_dropped() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline = make_pipeline(
            vec![make_route("critical-only", Severity::Critical)],
            Arc::clone(&metrics),
        );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::Low))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_drop_reason.lock().unwrap(), "no_route");
    }

    #[tokio::test]
    async fn run_drains_on_cancellation() {
        let metrics = Arc::new(TestMetrics::new());
        let pipeline = make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        let (tx, rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        // Send an alert before starting
        tx.send(AlertEvent::Ids(make_ids_alert("ids-001", Severity::High)))
            .await
            .unwrap();

        // Cancel immediately
        cancel.cancel();

        pipeline.run(rx, cancel).await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn run_exits_on_channel_close() {
        let metrics = Arc::new(TestMetrics::new());
        let pipeline = make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        let (tx, rx) = mpsc::channel::<AlertEvent>(10);
        let cancel = CancellationToken::new();

        // Drop sender to close channel
        drop(tx);

        // Should exit immediately
        pipeline.run(rx, cancel).await;
    }

    #[test]
    fn severity_label_mapping() {
        assert_eq!(severity_label(Severity::Low), "low");
        assert_eq!(severity_label(Severity::Medium), "medium");
        assert_eq!(severity_label(Severity::High), "high");
        assert_eq!(severity_label(Severity::Critical), "critical");
    }

    // ── Sender dispatch tests ──────────────────────────────────────

    struct MockSender {
        send_calls: AtomicU32,
    }

    impl MockSender {
        fn new() -> Self {
            Self {
                send_calls: AtomicU32::new(0),
            }
        }
    }

    impl AlertSender for MockSender {
        fn send<'a>(
            &'a self,
            _alert: &'a Alert,
            _route: &'a AlertRoute,
        ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
            self.send_calls.fetch_add(1, Ordering::Relaxed);
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn sender_called_for_matching_route() {
        let metrics = Arc::new(TestMetrics::new());
        let sender = Arc::new(MockSender::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_log_sender(Arc::clone(&sender) as Arc<dyn AlertSender>);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(sender.send_calls.load(Ordering::Relaxed), 1);
    }

    struct FailingSender;

    impl AlertSender for FailingSender {
        fn send<'a>(
            &'a self,
            _alert: &'a Alert,
            _route: &'a AlertRoute,
        ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
            Box::pin(async { Err(DomainError::EngineError("send failed".to_string())) })
        }
    }

    #[tokio::test]
    async fn sender_error_does_not_fail_pipeline() {
        let metrics = Arc::new(TestMetrics::new());
        let sender: Arc<dyn AlertSender> = Arc::new(FailingSender);
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_log_sender(sender);

        // Should not panic despite sender error
        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn no_sender_defaults_to_log_only() {
        let metrics = Arc::new(TestMetrics::new());
        // Pipeline without any senders configured
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        // Alert processed and metric recorded, but no sender called
        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 0);
    }

    // ── DLP alert tests ────────────────────────────────────────────

    fn make_dlp_alert(pattern_id: &str, severity: Severity) -> DlpAlert {
        DlpAlert {
            pattern_id: RuleId(pattern_id.to_string()),
            pattern_name: "Test Pattern".to_string(),
            severity,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            pid: 1234,
            tgid: 5678,
            direction: 0,
            redacted_excerpt: "[REDACTED:pci]".to_string(),
            timestamp_ns: 2_000_000_000,
        }
    }

    #[tokio::test]
    async fn dlp_alert_processed_and_metric_recorded() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        pipeline
            .process_dlp_alert(&make_dlp_alert("dlp-pci-visa", Severity::Critical))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
        assert_eq!(*metrics.last_severity.lock().unwrap(), "critical");
    }

    #[tokio::test]
    async fn dlp_alert_no_route_dropped() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline = make_pipeline(
            vec![make_route("critical-only", Severity::Critical)],
            Arc::clone(&metrics),
        );

        pipeline
            .process_dlp_alert(&make_dlp_alert("dlp-pii-email", Severity::Low))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dlp_alert_dispatches_to_sender() {
        let metrics = Arc::new(TestMetrics::new());
        let sender = Arc::new(MockSender::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_log_sender(Arc::clone(&sender) as Arc<dyn AlertSender>);

        pipeline
            .process_dlp_alert(&make_dlp_alert("dlp-pci-visa", Severity::Critical))
            .await;

        assert_eq!(sender.send_calls.load(Ordering::Relaxed), 1);
    }

    // ── DDoS alert tests ───────────────────────────────────────────

    fn make_ddos_attack() -> DdosAttack {
        use domain::ddos::entity::DdosAttackType;
        DdosAttack::new(
            "atk-test-1".to_string(),
            DdosAttackType::SynFlood,
            1_000_000_000,
        )
    }

    #[tokio::test]
    async fn ddos_alert_processed_and_metric_recorded() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        pipeline
            .process_ddos_alert(
                &make_ddos_attack(),
                [1, 0, 0, 0],
                [2, 0, 0, 0],
                false,
                0,
                80,
                6,
            )
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
    }

    #[tokio::test]
    async fn ddos_alert_dispatches_to_sender() {
        let metrics = Arc::new(TestMetrics::new());
        let sender = Arc::new(MockSender::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_log_sender(Arc::clone(&sender) as Arc<dyn AlertSender>);

        pipeline
            .process_ddos_alert(
                &make_ddos_attack(),
                [1, 0, 0, 0],
                [2, 0, 0, 0],
                false,
                0,
                80,
                6,
            )
            .await;

        assert_eq!(sender.send_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ddos_alert_no_route_dropped() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline = make_pipeline(
            vec![make_route("critical-only", Severity::Critical)],
            Arc::clone(&metrics),
        );

        // IcmpFlood maps to Medium severity, which is below Critical
        let attack = {
            use domain::ddos::entity::DdosAttackType;
            DdosAttack::new(
                "atk-low".to_string(),
                DdosAttackType::IcmpFlood,
                1_000_000_000,
            )
        };

        pipeline
            .process_ddos_alert(&attack, [1, 0, 0, 0], [2, 0, 0, 0], false, 0, 80, 6)
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_drop_reason.lock().unwrap(), "no_route");
    }

    // ── Alert store tests ─────────────────────────────────────────

    struct MockAlertStore {
        store_calls: AtomicU32,
        fail: bool,
    }

    impl MockAlertStore {
        fn new() -> Self {
            Self {
                store_calls: AtomicU32::new(0),
                fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                store_calls: AtomicU32::new(0),
                fail: true,
            }
        }
    }

    impl AlertStore for MockAlertStore {
        fn store_alert(&self, _alert: &Alert) -> Result<(), domain::alert::error::AlertError> {
            self.store_calls.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                Err(domain::alert::error::AlertError::RoutingError(
                    "store error".to_string(),
                ))
            } else {
                Ok(())
            }
        }

        fn get_alert(&self, _id: &str) -> Result<Option<Alert>, domain::alert::error::AlertError> {
            Ok(None)
        }

        fn mark_false_positive(&self, _id: &str) -> Result<bool, domain::alert::error::AlertError> {
            Ok(false)
        }

        fn query_alerts(
            &self,
            _query: &domain::alert::query::AlertQuery,
        ) -> Result<Vec<Alert>, domain::alert::error::AlertError> {
            Ok(vec![])
        }

        fn alert_count(&self) -> Result<usize, domain::alert::error::AlertError> {
            Ok(0)
        }
    }

    #[tokio::test]
    async fn alert_stored_when_store_configured() {
        let metrics = Arc::new(TestMetrics::new());
        let store = Arc::new(MockAlertStore::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_alert_store(Arc::clone(&store) as Arc<dyn AlertStore>);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(store.store_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn alert_store_error_does_not_fail_pipeline() {
        let metrics = Arc::new(TestMetrics::new());
        let store = Arc::new(MockAlertStore::failing());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_alert_store(Arc::clone(&store) as Arc<dyn AlertStore>);

        // Should not panic despite store error
        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(store.store_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
    }

    // ── gRPC broadcast tests ──────────────────────────────────────

    #[tokio::test]
    async fn alert_broadcast_to_stream() {
        let metrics = Arc::new(TestMetrics::new());
        let (tx, mut rx) = broadcast::channel::<Alert>(16);
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_stream_sender(tx);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        let received = rx.try_recv();
        assert!(received.is_ok(), "should have received broadcast alert");
        assert_eq!(received.unwrap().component, "ids");
    }

    #[tokio::test]
    async fn alert_broadcast_no_receiver_ok() {
        let metrics = Arc::new(TestMetrics::new());
        let (tx, _) = broadcast::channel::<Alert>(16);
        // Drop all receivers — send should not panic
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_stream_sender(tx);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
    }

    // ── Enricher tests ────────────────────────────────────────────

    struct MockEnricher {
        enrich_calls: AtomicU32,
    }

    impl MockEnricher {
        fn new() -> Self {
            Self {
                enrich_calls: AtomicU32::new(0),
            }
        }
    }

    impl AlertEnrichmentPort for MockEnricher {
        fn enrich_alert(&self, _alert: &mut Alert) {
            self.enrich_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn alert_enriched_when_enricher_configured() {
        let metrics = Arc::new(TestMetrics::new());
        let enricher = Arc::new(MockEnricher::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_enricher(Arc::clone(&enricher) as Arc<dyn AlertEnrichmentPort>);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(enricher.enrich_calls.load(Ordering::Relaxed), 1);
    }

    // ── reload_routes tests ───────────────────────────────────────

    #[tokio::test]
    async fn reload_routes_updates_routing() {
        let metrics = Arc::new(TestMetrics::new());
        // Start with no routes matching Low severity
        let mut pipeline = make_pipeline(
            vec![make_route("critical-only", Severity::Critical)],
            Arc::clone(&metrics),
        );

        // Low alert should be dropped
        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::Low))
            .await;
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);

        // Reload with a route that accepts Low severity
        pipeline.reload_routes(vec![make_route("all", Severity::Low)]);

        // Now the same alert should not be dropped
        pipeline
            .process_alert(&make_ids_alert("ids-002", Severity::Low))
            .await;
        assert_eq!(
            metrics.dropped_calls.load(Ordering::Relaxed),
            1,
            "drop count should not increase after reload"
        );
    }

    // ── Run loop dispatch tests ───────────────────────────────────

    #[tokio::test]
    async fn run_dispatches_dlp_alert() {
        let metrics = Arc::new(TestMetrics::new());
        let pipeline = make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        let (tx, rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        tx.send(AlertEvent::Dlp(make_dlp_alert(
            "dlp-pci-visa",
            Severity::Critical,
        )))
        .await
        .unwrap();

        // Cancel so `run` drains and exits
        cancel.cancel();

        pipeline.run(rx, cancel).await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "dlp");
    }

    #[tokio::test]
    async fn run_dispatches_ddos_alert() {
        let metrics = Arc::new(TestMetrics::new());
        let pipeline = make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        let (tx, rx) = mpsc::channel(100);
        let cancel = CancellationToken::new();

        tx.send(AlertEvent::Ddos {
            attack: make_ddos_attack(),
            src_addr: [1, 0, 0, 0],
            dst_addr: [2, 0, 0, 0],
            is_ipv6: false,
            src_port: 0,
            dst_port: 80,
            protocol: 6,
        })
        .await
        .unwrap();

        cancel.cancel();

        pipeline.run(rx, cancel).await;

        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_component.lock().unwrap(), "ddos");
    }

    #[tokio::test]
    async fn multiple_routes_dispatch_to_senders() {
        let metrics = Arc::new(TestMetrics::new());
        let log_sender = Arc::new(MockSender::new());
        let webhook_sender = Arc::new(MockSender::new());

        let routes = vec![
            make_route("log-all", Severity::Low),
            AlertRoute {
                name: "webhook-high".to_string(),
                destination: AlertDestination::Webhook {
                    url: "https://example.com/alerts".to_string(),
                },
                min_severity: Severity::Low,
                event_types: None,
            },
        ];

        let mut pipeline = make_pipeline(routes, Arc::clone(&metrics))
            .with_log_sender(Arc::clone(&log_sender) as Arc<dyn AlertSender>)
            .with_webhook_sender(Arc::clone(&webhook_sender) as Arc<dyn AlertSender>);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(log_sender.send_calls.load(Ordering::Relaxed), 1);
        assert_eq!(webhook_sender.send_calls.load(Ordering::Relaxed), 1);
    }
}
