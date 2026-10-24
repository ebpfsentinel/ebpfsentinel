use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use domain::alert::engine::AlertRouter;
use domain::alert::entity::PacketSecurityAlert;
use domain::alert::entity::{Alert, AlertDestination};
use domain::alias::entity::UNKNOWN_COUNTRY;
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::common::entity::RuleId;
use domain::ddos::entity::DdosAttack;
use domain::dlp::entity::DlpAlert;
use domain::dns::entity::{DnsAlert, DnsAlertReason};
use domain::firewall::entity::IpCidr;
use domain::ids::entity::IdsAlert;
use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitPolicy};
use domain::threatintel::entity::ThreatIntelAlert;
use ports::secondary::alert_enrichment_port::{AlertEnrichmentPort, Enrichment};
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::alert_store::AlertStore;
use ports::secondary::metadata_enricher_port::MetadataEnricher;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::socket_identity_port::FlowEndpoints;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::alert_event::AlertEvent;
use crate::alert_replay::AlertReplayBuffer;
use crate::audit_service_impl::AuditAppService;
use crate::ips_service_impl::IpsAppService;
use crate::process_signal_service::ProcessSignalService;
use crate::ratelimit_service_impl::RateLimitAppService;
use crate::workload_resolver::WorkloadResolver;

/// Alert pipeline application service.
///
/// Converts `IdsAlert`s into full-context `Alert`s, passes them through
/// the `AlertRouter` for dedup/throttle/route matching, records metrics,
/// and dispatches matched alerts to the appropriate senders.
pub struct AlertPipeline {
    router: AlertRouter,
    metrics: Arc<dyn MetricsPort>,
    audit_service: Arc<AuditAppService>,
    log_sender: Option<Arc<dyn AlertSender>>,
    webhook_sender: Option<Arc<dyn AlertSender>>,
    email_sender: Option<Arc<dyn AlertSender>>,
    otlp_sender: Option<Arc<dyn AlertSender>>,
    /// Optional broadcast sender for gRPC alert streaming.
    /// Non-blocking: sends are best-effort (dropped if no receivers or lagged).
    stream_tx: Option<broadcast::Sender<Alert>>,
    /// Optional replay buffer feeding the SSE alerts stream's
    /// `Last-Event-ID` resume contract. Pushed in lock-step with the
    /// `stream_tx` broadcast so subscribers can backfill missed events.
    replay_buffer: Option<Arc<AlertReplayBuffer>>,
    /// Optional persistent alert store for query and false-positive marking.
    alert_store: Option<Arc<dyn AlertStore>>,
    /// Optional enricher for adding domain context to alerts.
    enricher: Option<Arc<dyn AlertEnrichmentPort>>,
    /// Optional metadata enrichers (Docker, Kubernetes...) evaluated in order.
    metadata_enrichers: Vec<Arc<dyn MetadataEnricher>>,
    /// Optional simple auto-response evaluator (OSS).
    auto_response: Option<AutoResponseHandler>,
    /// Optional auto-capture trigger (OSS).
    auto_capture: Option<AutoCaptureHandler>,
    /// Names the workload behind an alert's flow. Unwired by default, and
    /// unwired for good on a host whose kernel refused the attribution
    /// hooks, which is why every alert's block is optional.
    workloads: WorkloadResolver,
    /// Stops the process behind a flow a prevention rule blocked, when the
    /// rule asks for it. Absent unless the agent's process kill is enabled
    /// and its kernel program attached.
    process_kill: Option<Arc<ProcessSignalService>>,
}

/// Auto-capture trigger: starts a PCAP capture when a high-severity alert fires.
pub struct AutoCaptureHandler {
    policy: domain::capture::entity::AutoCapturePolicy,
    capture_engine: Arc<RwLock<domain::capture::engine::CaptureEngine>>,
    /// Channel to send capture requests to the spawner (adapters layer).
    capture_tx: mpsc::Sender<domain::capture::entity::AutoCaptureRequest>,
}

/// Simple auto-response: evaluates alerts against severity-based policies
/// and enforces the matching one - a block through the IPS blacklist, a
/// throttle through the XDP rate limiter.
pub struct AutoResponseHandler {
    policies: Vec<domain::response::entity::SimpleResponsePolicy>,
    ips_service: Arc<ArcSwap<IpsAppService>>,
    rate_limit_service: Arc<RwLock<RateLimitAppService>>,
}

impl AutoResponseHandler {
    /// Blacklist the source for `ttl`, which the IPS service expires itself.
    fn block(&self, src_ip: IpAddr, reason: String, ttl: Duration) -> Result<(), String> {
        self.ips_service
            .load()
            .add_to_blacklist(src_ip, reason, ttl)
            .map_err(|e| e.to_string())
    }

    /// Install a per-source token bucket in the XDP rate limiter and schedule
    /// its removal. Unlike a blacklist entry the rate limiter holds no expiry
    /// of its own, so the caller's TTL has to be honoured here.
    ///
    /// The rate limiter's config map is keyed by a 32-bit source address, so
    /// an IPv6 source is refused by the policy's own validation and reported
    /// to the caller. Blacklisting is the response that covers IPv6.
    async fn throttle(
        &self,
        src_ip: IpAddr,
        policy: &domain::response::entity::SimpleResponsePolicy,
        ttl: Duration,
    ) -> Result<(), String> {
        if src_ip.is_ipv6() {
            return Err(
                "the rate limiter matches IPv4 sources; contain an IPv6 source with a block \
                 policy instead"
                    .to_string(),
            );
        }

        // A bucket the size of one second of traffic: a burst above the rate
        // is metered rather than waved through on the first packet. A policy
        // that states no rate leaves this at zero, which the policy's own
        // validation rejects below rather than silently picking a rate the
        // operator never asked for.
        let rate = policy.rate_pps.unwrap_or(0);
        let rule_id = auto_response_rule_id(&policy.name, src_ip);
        let entry = RateLimitPolicy {
            id: rule_id.clone(),
            rate,
            burst: rate,
            action: RateLimitAction::Drop,
            src_ip: host_cidr(src_ip),
            enabled: true,
            algorithm: RateLimitAlgorithm::TokenBucket,
            group_mask: 0,
            tenant_id: 0,
        };

        {
            let mut rl = self.rate_limit_service.write().await;
            // Re-arming an existing throttle: drop it first so the source gets
            // one bucket with a fresh TTL instead of two policies on one IP.
            let _ = rl.remove_policy(&rule_id);
            rl.add_policy(entry).map_err(|e| e.to_string())?;
        }

        // Scheduled unconditionally, so a zero TTL lapses at once the way a
        // zero-TTL blacklist entry does rather than becoming permanent.
        let service = Arc::clone(&self.rate_limit_service);
        tokio::spawn(async move {
            tokio::time::sleep(ttl).await;
            match service.write().await.remove_policy(&rule_id) {
                Ok(()) => tracing::info!(%src_ip, "auto-response: throttle expired"),
                Err(e) => {
                    tracing::warn!(%src_ip, error = %e, "auto-response: expired throttle not removed");
                }
            }
        });
        Ok(())
    }
}

/// The source address an alert names, or `None` when it names none.
///
/// Process-level alerts (DLP, ML anomalies) have no packet behind them and
/// zero their address fields, and an unspecified address is not a host any
/// response could contain.
fn alert_source_ip(alert: &domain::alert::entity::Alert) -> Option<IpAddr> {
    let ip = if alert.is_ipv6 {
        let mut bytes = [0u8; 16];
        for (i, &word) in alert.src_addr.iter().enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        IpAddr::from(bytes)
    } else {
        IpAddr::from(std::net::Ipv4Addr::from(alert.src_addr[0]))
    };
    (!ip.is_unspecified()).then_some(ip)
}

/// Single-host CIDR (/32 or /128) for the source an alert names.
/// The alert's own five-tuple, where it is about a flow at all.
///
/// A system alert, a `DDoS` summary on a zeroed tuple and an alert whose
/// addresses were never filled have nothing to look up, and asking the socket
/// tables for 0.0.0.0:0 would at best waste a lookup and at worst match a
/// row that has nothing to do with it.
fn alert_flow(alert: &Alert) -> Option<FlowEndpoints> {
    if alert.src_addr == [0; 4] && alert.dst_addr == [0; 4] {
        return None;
    }
    Some(FlowEndpoints {
        local_addr: crate::addr_to_ip(alert.src_addr, alert.is_ipv6),
        remote_addr: crate::addr_to_ip(alert.dst_addr, alert.is_ipv6),
        local_port: alert.src_port,
        remote_port: alert.dst_port,
        protocol: alert.protocol,
    })
}

fn host_cidr(ip: IpAddr) -> IpCidr {
    match ip {
        IpAddr::V4(v4) => IpCidr::V4 {
            addr: v4.to_bits(),
            prefix_len: 32,
        },
        IpAddr::V6(v6) => IpCidr::V6 {
            addr: v6.octets(),
            prefix_len: 128,
        },
    }
}

/// Rule ID for a throttle, keyed by policy and source so re-arming replaces
/// the entry. Policy names come from the config file and rule IDs accept only
/// alphanumerics, dashes and underscores, so anything else is folded away.
fn auto_response_rule_id(policy_name: &str, src_ip: IpAddr) -> RuleId {
    let raw = format!("auto-response-{policy_name}-{src_ip}");
    RuleId(
        raw.chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect(),
    )
}

impl AlertPipeline {
    pub fn new(
        router: AlertRouter,
        metrics: Arc<dyn MetricsPort>,
        audit_service: Arc<AuditAppService>,
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
            replay_buffer: None,
            alert_store: None,
            enricher: None,
            metadata_enrichers: Vec::new(),
            auto_response: None,
            auto_capture: None,
            workloads: WorkloadResolver::new(),
            process_kill: None,
        }
    }

    /// Stop the process behind a flow through `svc` when a blocking
    /// prevention rule asks for it.
    #[must_use]
    pub fn with_process_kill(mut self, svc: Arc<ProcessSignalService>) -> Self {
        self.process_kill = Some(svc);
        self
    }

    /// Name the workload behind every alert through `resolver`.
    #[must_use]
    pub fn with_workload_resolver(mut self, resolver: WorkloadResolver) -> Self {
        self.workloads = resolver;
        self
    }

    /// Register a [`MetadataEnricher`]. Enrichers are consulted in registration
    /// order; the first one that returns `Some(..)` wins.
    #[must_use]
    pub fn with_metadata_enricher(mut self, enricher: Arc<dyn MetadataEnricher>) -> Self {
        tracing::info!(enricher = enricher.name(), "metadata enricher registered");
        self.metadata_enrichers.push(enricher);
        self
    }

    /// Run the enricher, when there is one, and keep what it learned that
    /// the counters need.
    fn enrich(&self, alert: &mut Alert) -> Enrichment {
        self.attribute(alert);
        self.enricher
            .as_ref()
            .map(|enricher| enricher.enrich_alert(alert))
            .unwrap_or_default()
    }

    /// Name the workload behind the alert's flow, for every family at once.
    ///
    /// This sits on the one path every alert takes rather than in each
    /// `process_*`, because an attribution that six call sites each had to
    /// remember is an attribution that one of them eventually forgets. A
    /// pipeline with no resolver, a flow the kernel no longer holds and an
    /// alert that is about no flow at all each leave the block absent.
    fn attribute(&self, alert: &mut Alert) {
        if !self.workloads.is_wired() || alert.workload.is_some() {
            return;
        }
        // A DLP alert already names its own thread: the uprobe fired in the
        // process doing the writing, which is a reading rather than a match.
        if let Some(pid) = alert.tgid.or(alert.pid)
            && let Some(workload) = self.workloads.by_pid(pid)
        {
            alert.workload = Some(workload);
            return;
        }
        if let Some(flow) = alert_flow(alert) {
            alert.workload = self.workloads.by_flow(&flow);
        }
    }

    /// Count one alert in every family that counts alerts, so the totals by
    /// component, by rule and by country of origin always agree.
    fn record_alert_metrics(&self, alert: &Alert, enrichment: &Enrichment) {
        let severity_str = severity_label(alert.severity);
        let technique_id = alert
            .mitre_attack
            .as_ref()
            .map_or("", |m| m.technique_id.as_str());
        self.metrics
            .record_alert(&alert.component, severity_str, technique_id);
        self.metrics
            .record_alert_by_rule(&alert.component, &alert.rule_id.0);
        self.metrics.record_alert_source_country(
            enrichment
                .source_country
                .as_deref()
                .unwrap_or(UNKNOWN_COUNTRY),
        );
    }

    async fn apply_metadata_enrichers(&self, alert: &mut Alert) {
        if self.metadata_enrichers.is_empty() {
            return;
        }
        let Some(info) = alert.container.as_ref() else {
            return;
        };
        for enricher in &self.metadata_enrichers {
            match enricher.enrich(info).await {
                Ok(Some(metadata)) => {
                    alert.container_metadata = Some(metadata);
                    return;
                }
                Ok(None) => {}
                Err(err) => {
                    tracing::debug!(
                        enricher = enricher.name(),
                        error = %err,
                        "metadata enricher failed"
                    );
                }
            }
        }
    }

    /// Attach a broadcast sender for real-time gRPC alert streaming.
    #[must_use]
    pub fn with_stream_sender(mut self, tx: broadcast::Sender<Alert>) -> Self {
        self.stream_tx = Some(tx);
        self
    }

    /// Attach a replay buffer fed in lock-step with the broadcast sender.
    /// Used by the SSE alerts handler to fulfil `Last-Event-ID` resume.
    #[must_use]
    pub fn with_replay_buffer(mut self, buffer: Arc<AlertReplayBuffer>) -> Self {
        self.replay_buffer = Some(buffer);
        self
    }

    /// Push an alert onto the replay buffer (no-op when no buffer is wired).
    fn push_replay(&self, alert: &Alert) {
        if let Some(ref buf) = self.replay_buffer {
            buf.push(alert.clone());
        }
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
    /// Captures are triggered via an `mpsc` channel - the receiver spawns the
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
        ips_service: Arc<ArcSwap<IpsAppService>>,
        rate_limit_service: Arc<RwLock<RateLimitAppService>>,
    ) -> Self {
        if !policies.is_empty() {
            tracing::info!(
                policy_count = policies.len(),
                "auto-response enabled (OSS simple mode)"
            );
            self.auto_response = Some(AutoResponseHandler {
                policies,
                ips_service,
                rate_limit_service,
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
        let enrichment = self.enrich(&mut alert);

        self.apply_metadata_enrichers(&mut alert).await;

        // Record alert metrics
        self.record_alert_metrics(&alert, &enrichment);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Dedup, throttle, route matching. Suppression here only stops
        // delivery - the alert is already stored and streamed above.
        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Process a single threat intel match: convert to domain Alert, record
    /// metric, pass through router, and dispatch to matching senders.
    ///
    /// Kept apart from [`process_alert`](Self::process_alert) because an IOC
    /// match is not a signature match: the alert it becomes names the feed
    /// that resolved it, carries the confidence and the threat type, and is
    /// filed under the component an operator writes in a policy or a filter.
    pub async fn process_threatintel_alert(&mut self, ti_alert: &ThreatIntelAlert) {
        let description = format!(
            "Threat intel IOC matched: feed {} confidence {} type {}",
            ti_alert.feed_id, ti_alert.confidence, ti_alert.threat_type,
        );
        let mut alert = Alert::from_threatintel_alert(ti_alert, &description);

        // Enrich with domain context (best-effort)
        let enrichment = self.enrich(&mut alert);

        self.apply_metadata_enrichers(&mut alert).await;

        // Record alert metrics
        self.record_alert_metrics(&alert, &enrichment);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
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
        let enrichment = self.enrich(&mut alert);

        self.apply_metadata_enrichers(&mut alert).await;

        // Record audit entry for DLP violation
        let audit_detail = format!(
            "DLP {} ({}) pid={}",
            dlp_alert.pattern_name, dlp_alert.data_type, dlp_alert.pid,
        );
        self.audit_service.record_security_decision(
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
        self.record_alert_metrics(&alert, &enrichment);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store DLP alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Dedup, throttle, route matching. Suppression here only stops
        // delivery - the alert is already stored and streamed above.
        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
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
            "DDoS {:?} attack {} - status: {:?}, peak: {} pps, current: {} pps",
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
        let enrichment = self.enrich(&mut alert);

        self.apply_metadata_enrichers(&mut alert).await;

        // Record alert metrics
        self.record_alert_metrics(&alert, &enrichment);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store DDoS alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Auto-response: evaluate and enforce if policies match
        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Dedup, throttle, route matching. Suppression here only stops
        // delivery - the alert is already stored and streamed above.
        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Process a packet-level security alert (firewall, ratelimit, L7, IPS).
    pub async fn process_packet_security_alert(&mut self, psa: &PacketSecurityAlert) {
        let mut alert = Alert::from_packet_security_alert(psa);

        let enrichment = self.enrich(&mut alert);
        if psa.kill_process {
            self.kill_flow_process(&alert);
        }

        self.apply_metadata_enrichers(&mut alert).await;

        self.record_alert_metrics(&alert, &enrichment);

        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store {} alert", alert.component);
        }

        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        self.evaluate_auto_response(&alert).await;
        self.evaluate_auto_capture(&alert).await;

        // Dedup, throttle, route matching. Suppression here only stops
        // delivery - the alert is already stored and streamed above.
        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
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
                format!("Encrypted DNS detected: {protocol} to resolver {resolver}")
            }
            DnsAlertReason::AllowList { container, source } => {
                format!(
                    "DNS allow-list refusal: container {container} ({source}) asked for {}, \
                     which its list does not carry",
                    dns_alert.domain,
                )
            }
        };
        let mut alert = Alert::from_dns_alert(dns_alert, &description);

        // Enrich with domain context (best-effort)
        let enrichment = self.enrich(&mut alert);

        self.apply_metadata_enrichers(&mut alert).await;

        // Record alert metrics
        self.record_alert_metrics(&alert, &enrichment);

        // Persist alert to store (best-effort)
        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store DNS alert");
        }

        // Broadcast to gRPC stream subscribers (best-effort, non-blocking)
        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Dedup, throttle, route matching. Suppression here only stops
        // delivery - the alert is already stored and streamed above.
        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
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
            AlertEvent::ThreatIntel(ti_alert) => self.process_threatintel_alert(&ti_alert).await,
            AlertEvent::PacketSecurity(psa) => {
                self.process_packet_security_alert(&psa).await;
            }
            AlertEvent::WorkloadDenial(alert) => self.process_workload_denial(*alert).await,
            AlertEvent::System(alert) => self.process_system_alert(*alert).await,
        }
    }

    /// Emit a workload firewall refusal, naming the task that was refused.
    ///
    /// The refusal already carries the rule and the destination; what it
    /// cannot carry out of a socket hook is who the task was, so the
    /// attribution happens here, off the thread group id the kernel
    /// reported, before the alert takes the system path like any other.
    pub async fn process_workload_denial(&mut self, mut alert: Alert) {
        self.attribute(&mut alert);
        self.process_system_alert(alert).await;
    }

    /// Emit a pre-built system alert (multi-WAN failure, etc.) through the same
    /// metrics → store → broadcast → route path the kernel-event handlers use.
    pub async fn process_system_alert(&mut self, mut alert: Alert) {
        self.apply_metadata_enrichers(&mut alert).await;

        self.record_alert_metrics(&alert, &Enrichment::default());

        if let Some(ref store) = self.alert_store
            && let Err(e) = store.store_alert(&alert)
        {
            tracing::warn!(alert_id = %alert.id, error = %e, "failed to store system alert");
        }

        self.push_replay(&alert);
        if let Some(ref tx) = self.stream_tx {
            let _ = tx.send(alert.clone());
        }

        // Dedup, throttle, route matching. Suppression here only stops
        // delivery - the alert is already stored and streamed above.
        let matched_routes = self.resolve_routes(&alert);
        if matched_routes.is_empty() {
            return;
        }

        self.send_to_destinations(&alert, matched_routes).await;
    }

    /// Evaluate an alert against simple auto-response policies.
    ///
    /// The first policy that matches is the one that applies and evaluation
    /// stops there, so list order is precedence. A `block` sends the source to
    /// the IPS blacklist; a `throttle` gives it a token bucket at the policy's
    /// rate instead, which shapes the source rather than cutting it off.
    ///
    /// Both responses act on the address the alert names, so an alert that
    /// names none - DLP and ML anomalies are process-level and zero their
    /// address fields - is left alone rather than contained at 0.0.0.0.
    async fn evaluate_auto_response(&self, alert: &domain::alert::entity::Alert) {
        let Some(ref handler) = self.auto_response else {
            return;
        };

        let Some(src_ip) = alert_source_ip(alert) else {
            tracing::debug!(
                alert_id = %alert.id,
                component = %alert.component,
                "auto-response: skipped (the alert names no source address)"
            );
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
            let reason = format!("auto-response:{} alert={}", policy.name, alert.id);
            let ttl = std::time::Duration::from_secs(policy.ttl_secs);

            let enforced = match policy.action {
                domain::response::entity::ResponseActionType::BlockIp => {
                    handler.block(src_ip, reason, ttl)
                }
                domain::response::entity::ResponseActionType::ThrottleIp => {
                    handler.throttle(src_ip, policy, ttl).await
                }
            };
            match enforced {
                Ok(()) => {
                    tracing::info!(
                        policy = %policy.name,
                        alert_id = %alert.id,
                        src_ip = %src_ip,
                        action = policy.action.as_str(),
                        ttl_secs = policy.ttl_secs,
                        severity = ?alert.severity,
                        component = %alert.component,
                        "auto-response: enforced"
                    );
                    self.metrics.record_auto_response(&policy.name);
                    // The same trail a manual response leaves, so a source cut
                    // off by a policy is answerable from the audit log alone.
                    self.audit_service.record_response_action(
                        AuditAction::RuleAdded,
                        &src_ip.to_string(),
                        &policy.name,
                        &format!(
                            "auto-response {} on {src_ip} for alert {} (ttl {}s)",
                            policy.action.as_str(),
                            alert.id,
                            policy.ttl_secs
                        ),
                    );
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

    /// Stop the process that opened the flow a blocking rule matched.
    ///
    /// The process is the one attribution named, so a transited flow, a
    /// socket opened before the agent started and a host whose kernel
    /// refused the attribution hooks stop nothing: there is no process to
    /// name, and none is guessed. The kill runs on its own task because it
    /// waits for the kernel to catch the target, and the outcome, refusal
    /// included, is written to the audit log by the service.
    fn kill_flow_process(&self, alert: &Alert) {
        let Some(pid) = alert.workload.as_ref().map(|w| w.pid) else {
            tracing::info!(
                alert_id = %alert.id,
                rule_id = %alert.rule_id,
                "process kill: skipped (no process is attributed to the flow)"
            );
            return;
        };
        let Some(svc) = self.process_kill.as_ref().map(Arc::clone) else {
            tracing::warn!(
                alert_id = %alert.id,
                rule_id = %alert.rule_id,
                pid,
                "process kill: skipped (process kill is not running on this agent)"
            );
            return;
        };
        let rule_id = alert.rule_id.0.clone();
        let alert_id = alert.id.clone();
        tokio::spawn(async move {
            match svc.kill(pid, &rule_id).await {
                Ok(outcome) => tracing::info!(
                    alert_id = %alert_id,
                    rule_id = %rule_id,
                    pid,
                    outcome = %outcome.as_sentence(),
                    "process kill: decided"
                ),
                Err(e) => tracing::warn!(
                    alert_id = %alert_id,
                    rule_id = %rule_id,
                    pid,
                    error = %e,
                    "process kill: the signal maps refused"
                ),
            }
        });
    }

    /// Evaluate an alert against auto-capture policy.
    ///
    /// If it matches and no capture is running, start one filtered on the
    /// address the alert names. An alert that names none - DLP and ML
    /// anomalies are process-level and zero their address fields - starts no
    /// capture: `host 0.0.0.0` records nothing while holding the single
    /// capture slot for the whole policy duration, which is exactly when the
    /// next alert would have deserved it.
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
        let Some(src_ip) = alert_source_ip(alert) else {
            tracing::debug!(
                alert_id = %alert.id,
                component = %alert.component,
                "auto-capture: skipped (the alert names no source address)"
            );
            return;
        };

        // Check if a capture is already running
        if handler.capture_engine.read().await.has_active() {
            tracing::debug!(
                alert_id = %alert.id,
                "auto-capture: skipped (another capture is active)"
            );
            return;
        }

        let filter = format!("host {src_ip}");

        #[allow(clippy::cast_possible_truncation)]
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
        let stop = {
            let mut engine = handler.capture_engine.write().await;
            match engine.start(session.clone()) {
                Ok(stop) => stop,
                Err(e) => {
                    tracing::debug!(alert_id = %alert.id, error = %e, "auto-capture: registration failed");
                    return;
                }
            }
        };

        // Send to capture spawner (adapters layer), carrying the flag the
        // engine registered so the reader can be stopped like any other.
        let req = domain::capture::entity::AutoCaptureRequest { session, stop };
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

    /// Run an alert through the router and clone the routes it matched.
    ///
    /// Returns an empty vec when nothing is to be delivered, after recording
    /// *why*: a duplicate, a throttled rule and an alert no route wants are
    /// three different operational situations, and reporting them all as
    /// `no_route` made the drop counter useless for telling them apart.
    fn resolve_routes(&mut self, alert: &Alert) -> Vec<(usize, domain::alert::entity::AlertRoute)> {
        let decision = self.router.process_alert(alert);
        if let Some(reason) = decision.drop_reason() {
            self.metrics.record_alert_dropped(reason);
            tracing::debug!(
                component = %alert.component,
                rule_id = %alert.rule_id,
                severity = severity_label(alert.severity),
                reason,
                "alert not delivered to any destination"
            );
            return Vec::new();
        }
        decision
            .routes()
            .iter()
            .map(|(i, r)| (*i, (*r).clone()))
            .collect()
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
                let Some(sender) = self.sender_for(&route.destination) else {
                    // A route naming a destination nothing was built for sends
                    // nowhere. Counting it as its own reason keeps it apart
                    // from a duplicate, a throttle and an alert no route
                    // wanted, which are the three the drop counter already
                    // tells apart.
                    self.metrics.record_alert_dropped("no_sender");
                    tracing::warn!(
                        alert_id = %alert.id,
                        route_name = %route.name,
                        route_index = *idx,
                        "alert route has no sender configured"
                    );
                    return None;
                };
                Some({
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
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    struct TestMetrics {
        alert_calls: AtomicU32,
        dropped_calls: AtomicU32,
        auto_response_calls: AtomicU32,
        last_component: std::sync::Mutex<String>,
        last_severity: std::sync::Mutex<String>,
        last_drop_reason: std::sync::Mutex<String>,
        last_auto_response_policy: std::sync::Mutex<String>,
        countries: std::sync::Mutex<Vec<String>>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                alert_calls: AtomicU32::new(0),
                dropped_calls: AtomicU32::new(0),
                auto_response_calls: AtomicU32::new(0),
                last_component: std::sync::Mutex::new(String::new()),
                last_severity: std::sync::Mutex::new(String::new()),
                last_drop_reason: std::sync::Mutex::new(String::new()),
                last_auto_response_policy: std::sync::Mutex::new(String::new()),
                countries: std::sync::Mutex::new(Vec::new()),
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
        fn record_alert_source_country(&self, country: &str) {
            self.countries.lock().unwrap().push(country.to_string());
        }
    }
    impl IpsMetrics for TestMetrics {
        fn record_auto_response(&self, policy_name: &str) {
            self.auto_response_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_auto_response_policy.lock().unwrap() = policy_name.to_string();
        }
    }
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
    impl ContainerMetrics for TestMetrics {}
    impl CtMetrics for TestMetrics {}
    impl ThreatIntelMetrics for TestMetrics {}
    impl ZoneMetrics for TestMetrics {}

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
            container: None,
            rate_based: false,
        }
    }

    fn make_ti_alert() -> ThreatIntelAlert {
        ThreatIntelAlert {
            feed_id: "abuse-ch".to_string(),
            confidence: 90,
            threat_type: domain::threatintel::entity::ThreatType::C2,
            mode: DomainMode::Block,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            timestamp_ns: 1_000_000_000,
            container: None,
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

    fn make_audit_service() -> Arc<AuditAppService> {
        let sink: Arc<dyn AuditSink> = Arc::new(NoopAuditSink);
        Arc::new(AuditAppService::new(sink))
    }

    #[allow(clippy::similar_names)]
    fn make_pipeline_without_senders(
        routes: Vec<AlertRoute>,
        metrics: Arc<TestMetrics>,
    ) -> AlertPipeline {
        let router = AlertRouter::new(
            routes,
            Duration::from_secs(0), // no dedup for tests
            Duration::from_mins(5),
            100,
        );
        AlertPipeline::new(
            router,
            metrics as Arc<dyn MetricsPort>,
            make_audit_service(),
        )
    }

    /// Routing tests want a pipeline that can actually deliver, since a route
    /// whose destination was never built is itself a counted drop.
    fn make_pipeline(routes: Vec<AlertRoute>, metrics: Arc<TestMetrics>) -> AlertPipeline {
        make_pipeline_without_senders(routes, metrics)
            .with_log_sender(Arc::new(MockSender::new()) as Arc<dyn AlertSender>)
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

    struct FixedOwner(Option<ports::secondary::socket_identity_port::SocketOwner>);

    impl ports::secondary::socket_identity_port::SocketIdentityReader for FixedOwner {
        fn by_cookie(
            &self,
            _cookie: u64,
        ) -> Option<ports::secondary::socket_identity_port::SocketOwner> {
            self.0
        }
        fn by_flow(
            &self,
            _flow: &FlowEndpoints,
        ) -> Option<ports::secondary::socket_identity_port::SocketOwner> {
            self.0
        }
        fn by_originated_flow(
            &self,
            _flow: &FlowEndpoints,
        ) -> Option<ports::secondary::socket_identity_port::SocketOwner> {
            self.0
        }
    }

    fn resolver_naming(pid: u32) -> WorkloadResolver {
        WorkloadResolver::new().with_sockets(Box::new(FixedOwner(Some(
            ports::secondary::socket_identity_port::SocketOwner {
                pid,
                tgid: pid,
                uid: 1_000,
                cgroup_id: 77,
                source: domain::workload::entity::WorkloadSource::Flow,
            },
        ))))
    }

    #[tokio::test]
    async fn an_alert_on_an_attributed_flow_names_its_workload() {
        let metrics = Arc::new(TestMetrics::new());
        let (tx, mut rx) = broadcast::channel(4);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_stream_sender(tx)
            .with_workload_resolver(resolver_naming(4_242));

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        let alert = rx.recv().await.unwrap();
        let workload = alert.workload.unwrap();
        assert_eq!(workload.pid, 4_242);
        assert_eq!(workload.uid, Some(1_000));
    }

    #[tokio::test]
    async fn an_alert_the_tables_cannot_name_carries_no_block() {
        let metrics = Arc::new(TestMetrics::new());
        let (tx, mut rx) = broadcast::channel(4);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_stream_sender(tx)
            .with_workload_resolver(
                WorkloadResolver::new().with_sockets(Box::new(FixedOwner(None))),
            );

        pipeline
            .process_alert(&make_ids_alert("ids-002", Severity::High))
            .await;

        let alert = rx.recv().await.unwrap();
        assert!(domain::workload::entity::is_absent(&alert.workload));
        assert!(!serde_json::to_string(&alert).unwrap().contains("workload"));
    }

    /// Signal maps that record what was armed and report every target as
    /// signalled, so the service settles at once.
    struct RecordingSignalMaps {
        armed: Arc<std::sync::Mutex<Vec<u32>>>,
        pending: Vec<ebpf_common::signal::SignalEvent>,
    }

    impl ports::secondary::process_signal_map_port::ProcessSignalMapPort for RecordingSignalMaps {
        fn set_protected(
            &mut self,
            _tgids: &[u32],
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }
        fn arm(
            &mut self,
            tgid: u32,
            _signal: u32,
            _window_ns: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            self.armed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(tgid);
            self.pending.push(ebpf_common::signal::SignalEvent {
                tgid,
                outcome: ebpf_common::signal::SIGNAL_OUTCOME_SENT,
                ..Default::default()
            });
            Ok(())
        }
        fn disarm(&mut self, _tgid: u32) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }
        fn drain_events(
            &mut self,
        ) -> Result<Vec<ebpf_common::signal::SignalEvent>, domain::common::error::DomainError>
        {
            Ok(std::mem::take(&mut self.pending))
        }
    }

    /// A target that runs an unprotected binary until it is signalled, then
    /// is gone.
    struct UntilSignalled(std::sync::atomic::AtomicBool);

    impl ports::secondary::process_executable_port::ProcessExecutableReader for UntilSignalled {
        fn read_executable(&self, _pid: u32) -> Option<domain::dlp::entity::DlpExecutable> {
            self.0
                .swap(false, Ordering::Relaxed)
                .then(|| domain::dlp::entity::DlpExecutable {
                    path: "/tmp/implant".to_string(),
                    dev: 0,
                    inode: 0,
                    source: domain::dlp::entity::DlpIdentitySource::ProcessAtAlertTime,
                })
        }
    }

    async fn recording_kill() -> (Arc<ProcessSignalService>, Arc<std::sync::Mutex<Vec<u32>>>) {
        let armed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let maps = RecordingSignalMaps {
            armed: Arc::clone(&armed),
            pending: Vec::new(),
        };
        let svc = ProcessSignalService::new(
            Arc::new(tokio::sync::Mutex::new(maps))
                as Arc<
                    tokio::sync::Mutex<
                        dyn ports::secondary::process_signal_map_port::ProcessSignalMapPort,
                    >,
                >,
            Arc::new(UntilSignalled(std::sync::atomic::AtomicBool::new(true))),
            None,
            domain::response::signal::ProcessSignalGuard::new(1, &[], &[]),
            crate::process_signal_service::ProcessSignalSettings {
                signal: 9,
                window: Duration::from_millis(50),
                poll_interval: Duration::from_millis(5),
            },
        )
        .await
        .unwrap();
        (Arc::new(svc), armed)
    }

    fn ips_block(kill_process: bool) -> PacketSecurityAlert {
        PacketSecurityAlert {
            component: domain::alert::entity::PacketAlertComponent::Ips,
            src_addr: [0x0A00_0002, 0, 0, 0],
            dst_addr: [0xC633_6401, 0, 0, 0],
            src_port: 40_000,
            dst_port: 4_444,
            protocol: 6,
            is_ipv6: false,
            timestamp_ns: 1_000,
            rule_id: "ips-c2".to_string(),
            action_label: "block".to_string(),
            severity: Severity::Critical,
            detail: "IPS rule ips-c2 matched".to_string(),
            ja4_fingerprint: None,
            container: None,
            kill_process,
        }
    }

    async fn armed_after(psa: &PacketSecurityAlert, resolver: WorkloadResolver) -> Vec<u32> {
        let (svc, armed) = recording_kill().await;
        let mut pipeline = make_pipeline_without_senders(Vec::new(), Arc::new(TestMetrics::new()))
            .with_workload_resolver(resolver)
            .with_process_kill(svc);
        pipeline.process_packet_security_alert(psa).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        armed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[tokio::test]
    async fn a_blocking_rule_asking_for_the_process_stops_the_one_attribution_named() {
        assert_eq!(
            armed_after(&ips_block(true), resolver_naming(4_242)).await,
            vec![4_242]
        );
    }

    #[tokio::test]
    async fn no_process_is_stopped_unless_the_rule_asks_and_attribution_names_one() {
        assert!(
            armed_after(&ips_block(false), resolver_naming(4_242))
                .await
                .is_empty()
        );
        let unattributed = WorkloadResolver::new().with_sockets(Box::new(FixedOwner(None)));
        assert!(armed_after(&ips_block(true), unattributed).await.is_empty());
    }

    #[tokio::test]
    async fn an_alert_about_no_flow_asks_the_tables_nothing() {
        // A system alert carries zeroed addresses by construction, and a
        // lookup on 0.0.0.0:0 could only match the wrong socket.
        let metrics = Arc::new(TestMetrics::new());
        let (tx, mut rx) = broadcast::channel(4);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_stream_sender(tx)
            .with_workload_resolver(resolver_naming(4_242));

        pipeline
            .process_system_alert(Alert::wan_all_down(&["gw0".to_string()], 1_000))
            .await;

        let alert = rx.recv().await.unwrap();
        assert!(alert.workload.is_none());
    }

    #[tokio::test]
    async fn dedup_skips_duplicate() {
        let metrics = Arc::new(TestMetrics::new());
        let router = AlertRouter::new(
            vec![make_route("all", Severity::Low)],
            Duration::from_mins(1), // dedup enabled
            Duration::from_mins(5),
            100,
        );
        let mut pipeline = AlertPipeline::new(
            router,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            make_audit_service(),
        )
        .with_log_sender(Arc::new(MockSender::new()) as Arc<dyn AlertSender>);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;
        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        // Dedup gates delivery, not observation: both alerts are counted, and
        // the second is dropped under its own reason rather than "no_route".
        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_drop_reason.lock().unwrap(), "dedup");
    }

    #[tokio::test]
    async fn throttle_excess_dropped() {
        let metrics = Arc::new(TestMetrics::new());
        let router = AlertRouter::new(
            vec![make_route("all", Severity::Low)],
            Duration::from_secs(0),
            Duration::from_mins(5),
            1, // throttle max = 1
        );
        let mut pipeline = AlertPipeline::new(
            router,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            make_audit_service(),
        )
        .with_log_sender(Arc::new(MockSender::new()) as Arc<dyn AlertSender>);

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
        assert_eq!(*metrics.last_drop_reason.lock().unwrap(), "throttle");
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

    /// A route the router matched and nothing was built for delivers nothing,
    /// which is a drop with a reason of its own rather than a silent success.
    #[tokio::test]
    async fn a_route_with_no_sender_is_counted_under_its_own_reason() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline = make_pipeline_without_senders(
            vec![make_route("all", Severity::Low)],
            Arc::clone(&metrics),
        );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        // The alert is still observed - the drop is about delivery only.
        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dropped_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_drop_reason.lock().unwrap(), "no_sender");
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
            container: None,
            executable: None,
            flow: None,
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
        // Drop all receivers - send should not panic
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
        fn enrich_alert(&self, _alert: &mut Alert) -> Enrichment {
            self.enrich_calls.fetch_add(1, Ordering::Relaxed);
            Enrichment {
                source_country: Some("KP".to_string()),
            }
        }
    }

    #[tokio::test]
    async fn every_alert_is_counted_once_against_the_country_of_its_source() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_enricher(Arc::new(MockEnricher::new()) as Arc<dyn AlertEnrichmentPort>);

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;
        pipeline.process_threatintel_alert(&make_ti_alert()).await;
        // A system alert has no source address to resolve, and is still
        // counted, so the countries add up to the alerts.
        let system = Alert::from_ids_alert(&make_ids_alert("sys-001", Severity::Low), "system");
        pipeline.process_system_alert(system).await;

        assert_eq!(
            *metrics.countries.lock().unwrap(),
            ["KP", "KP", UNKNOWN_COUNTRY]
        );
        assert_eq!(metrics.alert_calls.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn an_alert_with_no_enricher_is_counted_under_unknown() {
        let metrics = Arc::new(TestMetrics::new());
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics));

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(*metrics.countries.lock().unwrap(), [UNKNOWN_COUNTRY]);
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
                    headers: std::collections::BTreeMap::new(),
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

    // ── Auto-capture ───────────────────────────────────────────────

    fn make_auto_capture(
        pipeline: AlertPipeline,
    ) -> (
        AlertPipeline,
        Arc<RwLock<domain::capture::engine::CaptureEngine>>,
        mpsc::Receiver<domain::capture::entity::AutoCaptureRequest>,
    ) {
        let engine = Arc::new(RwLock::new(domain::capture::engine::CaptureEngine::new(
            300,
            domain::capture::retention::RetentionPolicy::new(7, 1024),
        )));
        let (tx, rx) = mpsc::channel(4);
        let policy = domain::capture::entity::AutoCapturePolicy {
            name: "auto".to_string(),
            min_severity: Severity::High,
            components: Vec::new(),
            duration_secs: 30,
            snap_length: 262_144,
            interface: "eth0".to_string(),
        };
        (
            pipeline.with_auto_capture(policy, Arc::clone(&engine), tx),
            engine,
            rx,
        )
    }

    #[tokio::test]
    async fn a_matching_alert_captures_the_source_it_names() {
        let metrics = Arc::new(TestMetrics::new());
        let (mut pipeline, engine, mut rx) = make_auto_capture(make_pipeline(
            vec![make_route("all", Severity::Low)],
            metrics,
        ));

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        let req = rx.try_recv().expect("a capture was requested");
        assert_eq!(req.session.filter, "host 192.168.0.1");
        assert!(engine.read().await.has_active());
    }

    /// A capture filtered on 0.0.0.0 records nothing and holds the single
    /// capture slot for the policy duration, so the alert that names no
    /// source starts none at all.
    #[tokio::test]
    async fn an_alert_naming_no_source_starts_no_capture() {
        let metrics = Arc::new(TestMetrics::new());
        let (mut pipeline, engine, mut rx) = make_auto_capture(make_pipeline(
            vec![make_route("all", Severity::Low)],
            metrics,
        ));

        let mut alert = make_ids_alert("ids-001", Severity::High);
        alert.src_addr = [0; 4];
        pipeline.process_alert(&alert).await;

        assert!(rx.try_recv().is_err(), "no capture should be requested");
        assert!(!engine.read().await.has_active());
    }

    // ── Auto-response enforcement ──────────────────────────────────

    fn make_auto_response_services(
        metrics: &Arc<TestMetrics>,
    ) -> (
        Arc<ArcSwap<IpsAppService>>,
        Arc<RwLock<RateLimitAppService>>,
    ) {
        let ips = IpsAppService::new(
            domain::ips::engine::IpsEngine::new(domain::ips::entity::IpsPolicy::default()),
            Arc::clone(metrics) as Arc<dyn MetricsPort>,
        );
        let rl = RateLimitAppService::new(
            domain::ratelimit::engine::RateLimitEngine::new(),
            Arc::clone(metrics) as Arc<dyn MetricsPort>,
        );
        (
            Arc::new(ArcSwap::from_pointee(ips)),
            Arc::new(RwLock::new(rl)),
        )
    }

    fn make_auto_response_policy(
        action: domain::response::entity::ResponseActionType,
        rate_pps: Option<u64>,
    ) -> domain::response::entity::SimpleResponsePolicy {
        domain::response::entity::SimpleResponsePolicy {
            name: "auto".to_string(),
            min_severity: Severity::High,
            components: Vec::new(),
            action,
            // Long enough that the removal task a throttle schedules cannot
            // race the assertions below.
            ttl_secs: 3600,
            rate_pps,
        }
    }

    #[tokio::test]
    async fn an_enforced_policy_records_the_auto_response_metric() {
        // The enforcement itself is covered below. What is asserted here is
        // that the call site reaches the metrics port, since the port gives
        // every method a default empty body and a call that reaches nothing
        // still compiles.
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_auto_response(
                    vec![make_auto_response_policy(
                        domain::response::entity::ResponseActionType::BlockIp,
                        None,
                    )],
                    Arc::clone(&ips),
                    Arc::clone(&rl),
                );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert_eq!(metrics.auto_response_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*metrics.last_auto_response_policy.lock().unwrap(), "auto");
    }

    #[tokio::test]
    async fn an_ioc_match_is_filed_under_the_component_a_policy_names() {
        // A policy naming a component that no alert ever carries validates at
        // boot and enforces nothing, so what is asserted here is that the word
        // the configuration admits is the word the alert arrives with.
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut policy =
            make_auto_response_policy(domain::response::entity::ResponseActionType::BlockIp, None);
        policy.components = vec!["threatintel".to_string()];
        let mut pipeline =
            make_pipeline(vec![make_route("all", Severity::Low)], Arc::clone(&metrics))
                .with_auto_response(vec![policy], Arc::clone(&ips), Arc::clone(&rl));

        pipeline.process_threatintel_alert(&make_ti_alert()).await;

        assert_eq!(*metrics.last_component.lock().unwrap(), "threatintel");
        assert_eq!(metrics.auto_response_calls.load(Ordering::Relaxed), 1);
        assert!(ips.load().is_blacklisted(IpAddr::from([192, 168, 0, 1])));
    }

    #[tokio::test]
    async fn throttle_policy_installs_a_rate_limit_on_the_source() {
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_auto_response(
                vec![make_auto_response_policy(
                    domain::response::entity::ResponseActionType::ThrottleIp,
                    Some(500),
                )],
                Arc::clone(&ips),
                Arc::clone(&rl),
            );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        let installed = rl.read().await;
        let policies = installed.policies();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].rate, 500);
        assert_eq!(
            policies[0].src_ip,
            IpCidr::V4 {
                addr: 0xC0A8_0001,
                prefix_len: 32,
            }
        );
        // Throttling shapes the source; blacklisting it would cut it off.
        assert!(!ips.load().is_blacklisted(IpAddr::from([192, 168, 0, 1])));
    }

    #[tokio::test]
    async fn block_policy_blacklists_without_touching_the_rate_limiter() {
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_auto_response(
                vec![make_auto_response_policy(
                    domain::response::entity::ResponseActionType::BlockIp,
                    None,
                )],
                Arc::clone(&ips),
                Arc::clone(&rl),
            );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;

        assert!(ips.load().is_blacklisted(IpAddr::from([192, 168, 0, 1])));
        assert_eq!(rl.read().await.policies().len(), 0);
    }

    struct RecordingAuditSink(std::sync::Mutex<Vec<AuditEntry>>);
    impl AuditSink for RecordingAuditSink {
        fn write_entry(&self, entry: &AuditEntry) -> Result<(), AuditError> {
            self.0.lock().unwrap().push(entry.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn an_enforced_response_is_audited_under_the_policy_name() {
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let sink = Arc::new(RecordingAuditSink(std::sync::Mutex::new(Vec::new())));
        let router = AlertRouter::new(
            vec![make_route("all", Severity::Low)],
            Duration::from_secs(0),
            Duration::from_mins(5),
            100,
        );
        let mut pipeline = AlertPipeline::new(
            router,
            metrics as Arc<dyn MetricsPort>,
            Arc::new(AuditAppService::new(Arc::clone(&sink) as Arc<dyn AuditSink>)),
        )
        .with_auto_response(
            vec![make_auto_response_policy(
                domain::response::entity::ResponseActionType::BlockIp,
                None,
            )],
            ips,
            rl,
        );

        let alert = make_ids_alert("ids-001", Severity::High);
        pipeline.process_alert(&alert).await;

        let entries = sink.0.lock().unwrap();
        let response = entries
            .iter()
            .find(|e| e.component == AuditComponent::Responses)
            .expect("the enforced response is in the audit log");
        assert_eq!(response.action, AuditAction::RuleAdded);
        assert_eq!(
            response.src_addr[0],
            u32::from(std::net::Ipv4Addr::new(192, 168, 0, 1))
        );
        assert_eq!(response.rule_id, "auto");
        assert!(
            response.detail.contains("for alert "),
            "{}",
            response.detail
        );
        assert!(response.detail.contains("block_ip"), "{}", response.detail);
    }

    /// Process-level alerts carry no packet and zero their address fields.
    /// Containing 0.0.0.0 would hold nothing while reporting a response.
    #[tokio::test]
    async fn an_alert_naming_no_source_is_left_alone() {
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_auto_response(
                vec![make_auto_response_policy(
                    domain::response::entity::ResponseActionType::BlockIp,
                    None,
                )],
                Arc::clone(&ips),
                Arc::clone(&rl),
            );

        let mut alert = make_ids_alert("ids-001", Severity::High);
        alert.src_addr = [0; 4];
        pipeline.process_alert(&alert).await;

        assert!(!ips.load().is_blacklisted(IpAddr::from([0, 0, 0, 0])));
        assert_eq!(rl.read().await.policies().len(), 0);
    }

    /// The rate limiter's config map is keyed by a 32-bit address, so an IPv6
    /// source has no bucket to install and the throttle reports the failure
    /// instead of writing one somewhere else.
    #[tokio::test]
    async fn a_throttle_installs_nothing_for_an_ipv6_source() {
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_auto_response(
                vec![make_auto_response_policy(
                    domain::response::entity::ResponseActionType::ThrottleIp,
                    Some(500),
                )],
                ips,
                Arc::clone(&rl),
            );

        let mut alert = make_ids_alert("ids-001", Severity::High);
        alert.is_ipv6 = true;
        alert.src_addr = [0x2001_0DB8, 0, 0, 1];
        pipeline.process_alert(&alert).await;

        assert_eq!(rl.read().await.policies().len(), 0);
    }

    #[tokio::test]
    async fn a_second_alert_re_arms_one_throttle_rather_than_stacking() {
        let metrics = Arc::new(TestMetrics::new());
        let (ips, rl) = make_auto_response_services(&metrics);
        let mut pipeline = make_pipeline(vec![make_route("all", Severity::Low)], metrics)
            .with_auto_response(
                vec![make_auto_response_policy(
                    domain::response::entity::ResponseActionType::ThrottleIp,
                    Some(500),
                )],
                ips,
                Arc::clone(&rl),
            );

        pipeline
            .process_alert(&make_ids_alert("ids-001", Severity::High))
            .await;
        pipeline
            .process_alert(&make_ids_alert("ids-002", Severity::High))
            .await;

        assert_eq!(rl.read().await.policies().len(), 1);
    }
}
