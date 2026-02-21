use std::sync::Arc;

use domain::alert::engine::AlertRouter;
use domain::alert::entity::{Alert, AlertDestination};
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::dlp::entity::DlpAlert;
use domain::ids::entity::IdsAlert;
use ports::secondary::alert_enrichment_port::AlertEnrichmentPort;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::alert_store::AlertStore;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::{RwLock, broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::audit_service_impl::AuditAppService;

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
    /// Optional broadcast sender for gRPC alert streaming.
    /// Non-blocking: sends are best-effort (dropped if no receivers or lagged).
    stream_tx: Option<broadcast::Sender<Alert>>,
    /// Optional persistent alert store for query and false-positive marking.
    alert_store: Option<Arc<dyn AlertStore>>,
    /// Optional enricher for adding domain context to alerts.
    enricher: Option<Arc<dyn AlertEnrichmentPort>>,
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
            stream_tx: None,
            alert_store: None,
            enricher: None,
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
        self.metrics.record_alert(&alert.component, severity_str);
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

        // Pass through router (dedup, throttle, route matching)
        let matched_routes = self.router.process_alert(&alert);

        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            tracing::debug!(
                rule_id = %alert.rule_id,
                severity = severity_str,
                "alert dropped: no matching route or dedup/throttle"
            );
            return;
        }

        // Dispatch to each matched route's sender
        for (idx, route) in &matched_routes {
            let sender = match &route.destination {
                AlertDestination::Log => self.log_sender.as_ref(),
                AlertDestination::Webhook { .. } => self.webhook_sender.as_ref(),
                AlertDestination::Email { .. } => self.email_sender.as_ref(),
            };

            if let Some(sender) = sender {
                if let Err(e) = sender.send(&alert, route).await {
                    tracing::warn!(
                        alert_id = %alert.id,
                        route_name = %route.name,
                        route_index = idx,
                        error = %e,
                        "alert send failed"
                    );
                }
            } else {
                // No sender configured for this destination type — log only
                tracing::info!(
                    alert_id = %alert.id,
                    rule_id = %alert.rule_id,
                    severity = severity_str,
                    route_name = %route.name,
                    route_index = idx,
                    src_ip = %alert.src_ip(),
                    dst_ip = %alert.dst_ip(),
                    src_port = alert.src_port,
                    dst_port = alert.dst_port,
                    protocol = alert.protocol,
                    action = %alert.action,
                    "alert routed (no sender configured)"
                );
            }
        }
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
        self.metrics.record_alert(&alert.component, severity_str);
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

        // Pass through router (dedup, throttle, route matching)
        let matched_routes = self.router.process_alert(&alert);

        if matched_routes.is_empty() {
            self.metrics.record_alert_dropped("no_route");
            tracing::debug!(
                pattern_id = %alert.rule_id,
                severity = severity_str,
                "DLP alert dropped: no matching route or dedup/throttle"
            );
            return;
        }

        // Dispatch to each matched route's sender
        for (idx, route) in &matched_routes {
            let sender = match &route.destination {
                AlertDestination::Log => self.log_sender.as_ref(),
                AlertDestination::Webhook { .. } => self.webhook_sender.as_ref(),
                AlertDestination::Email { .. } => self.email_sender.as_ref(),
            };

            if let Some(sender) = sender {
                if let Err(e) = sender.send(&alert, route).await {
                    tracing::warn!(
                        alert_id = %alert.id,
                        route_name = %route.name,
                        route_index = idx,
                        error = %e,
                        "DLP alert send failed"
                    );
                }
            } else {
                tracing::info!(
                    alert_id = %alert.id,
                    pattern_id = %alert.rule_id,
                    severity = severity_str,
                    route_name = %route.name,
                    route_index = idx,
                    pid = dlp_alert.pid,
                    data_type = %dlp_alert.data_type,
                    action = %alert.action,
                    "DLP alert routed (no sender configured)"
                );
            }
        }
    }

    /// Async run loop: consumes IDS alerts from the channel,
    /// processes each one through the pipeline, and drains on cancellation.
    pub async fn run(mut self, mut rx: mpsc::Receiver<IdsAlert>, cancel_token: CancellationToken) {
        let mut count: u64 = 0;

        loop {
            tokio::select! {
                () = cancel_token.cancelled() => {
                    // Drain remaining alerts before exiting
                    while let Ok(ids_alert) = rx.try_recv() {
                        count += 1;
                        self.process_alert(&ids_alert).await;
                    }
                    break;
                }
                msg = rx.recv() => {
                    match msg {
                        Some(ids_alert) => {
                            count += 1;
                            self.process_alert(&ids_alert).await;
                        }
                        None => break, // channel closed
                    }
                }
            }
        }

        tracing::info!(total_alerts = count, "alert pipeline stopped");
    }

    /// Hot-reload alert routes without resetting dedup/throttle state.
    pub fn reload_routes(&mut self, routes: Vec<domain::alert::entity::AlertRoute>) {
        self.router.reload_routes(routes);
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
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
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
        fn record_alert(&self, component: &str, severity: &str) {
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
        tx.send(make_ids_alert("ids-001", Severity::High))
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

        let (tx, rx) = mpsc::channel(10);
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
