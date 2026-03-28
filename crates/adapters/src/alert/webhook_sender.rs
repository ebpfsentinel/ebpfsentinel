use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use application::retry::{RetryConfig, retry_with_backoff};
use domain::alert::circuit_breaker::CircuitBreaker;
use domain::alert::entity::{Alert, AlertDestination, AlertRoute};
use domain::common::error::DomainError;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::Mutex;

/// Alert sender that POSTs alert JSON to a webhook URL.
///
/// Validates webhook URLs against SSRF (rejects private/loopback/link-local IPs).
pub struct WebhookAlertSender {
    client: reqwest::Client,
    circuit_breaker: Mutex<CircuitBreaker>,
    retry_config: RetryConfig,
    metrics: Arc<dyn MetricsPort>,
    destination_name: String,
    /// Skip SSRF validation (test-only).
    #[cfg(test)]
    skip_url_validation: bool,
}

impl WebhookAlertSender {
    pub fn new(
        circuit_breaker: CircuitBreaker,
        retry_config: RetryConfig,
        metrics: Arc<dyn MetricsPort>,
        destination_name: String,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            circuit_breaker: Mutex::new(circuit_breaker),
            retry_config,
            metrics,
            destination_name,
            #[cfg(test)]
            skip_url_validation: false,
        }
    }
}

/// Validate webhook URL: must be http(s), must not target private/loopback/link-local addresses.
fn validate_webhook_url(url: &str) -> Result<(), DomainError> {
    let rest = if let Some(r) = url.strip_prefix("https://") {
        r
    } else if let Some(r) = url.strip_prefix("http://") {
        r
    } else {
        return Err(DomainError::EngineError(
            "webhook URL must use http:// or https:// scheme".to_string(),
        ));
    };

    // Extract host (strip path, query, userinfo, port)
    let host_port = rest.split('/').next().unwrap_or(rest);
    let host_port = host_port.split('?').next().unwrap_or(host_port);
    let host_port = host_port.rsplit_once('@').map_or(host_port, |(_, hp)| hp);

    let host = if let Some(bracketed) = host_port.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or(bracketed)
    } else {
        host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
    };

    if host.is_empty() {
        return Err(DomainError::EngineError(
            "webhook URL has empty host".to_string(),
        ));
    }

    let host_lower = host.to_ascii_lowercase();
    if host_lower == "localhost"
        || host_lower == "metadata.google.internal"
        || host_lower.ends_with(".internal")
    {
        return Err(DomainError::EngineError(
            "webhook URL must not target localhost or metadata endpoints".to_string(),
        ));
    }

    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
            return Err(DomainError::EngineError(
                "webhook URL must not target loopback, unspecified, or multicast addresses"
                    .to_string(),
            ));
        }
        match ip {
            std::net::IpAddr::V4(v4) => {
                if v4.is_private()
                    || v4.is_link_local()
                    || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
                {
                    return Err(DomainError::EngineError(
                        "webhook URL must not target private or link-local addresses".to_string(),
                    ));
                }
            }
            std::net::IpAddr::V6(v6) => {
                let first = v6.segments()[0];
                if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
                    return Err(DomainError::EngineError(
                        "webhook URL must not target private or link-local addresses".to_string(),
                    ));
                }
            }
        }
    }

    Ok(())
}

impl AlertSender for WebhookAlertSender {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
        route: &'a AlertRoute,
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
        Box::pin(async move {
            // 1. Check circuit breaker
            {
                let mut cb = self.circuit_breaker.lock().await;
                if !cb.can_attempt() {
                    self.metrics
                        .record_circuit_state(&self.destination_name, cb.state().as_u8());
                    return Err(DomainError::EngineError(format!(
                        "circuit breaker open for destination '{}'",
                        self.destination_name
                    )));
                }
            }

            // 2. Extract and validate webhook URL from route destination
            let url = match &route.destination {
                AlertDestination::Webhook { url } => {
                    #[cfg(test)]
                    if !self.skip_url_validation {
                        validate_webhook_url(url)?;
                    }
                    #[cfg(not(test))]
                    validate_webhook_url(url)?;
                    url.clone()
                }
                _ => {
                    return Err(DomainError::EngineError(
                        "webhook sender received non-webhook route".to_string(),
                    ));
                }
            };

            // 3. Serialize alert to JSON
            let body = serde_json::to_string(alert)
                .map_err(|e| DomainError::EngineError(format!("failed to serialize alert: {e}")))?;

            // 4. Retry with backoff: POST to webhook URL
            let client = &self.client;
            let result = retry_with_backoff(&self.retry_config, || {
                let url = url.clone();
                let body = body.clone();
                async move {
                    let response = client
                        .post(&url)
                        .header("Content-Type", "application/json")
                        .body(body)
                        .send()
                        .await
                        .map_err(|e| {
                            DomainError::EngineError(format!("webhook POST failed: {e}"))
                        })?;

                    if response.status().is_success() {
                        Ok(())
                    } else {
                        Err(DomainError::EngineError(format!(
                            "webhook returned HTTP {}",
                            response.status()
                        )))
                    }
                }
            })
            .await;

            // 5. Record success/failure in circuit breaker and update metric
            let mut cb = self.circuit_breaker.lock().await;
            match &result {
                Ok(()) => cb.record_success(),
                Err(_) => cb.record_failure(),
            }
            self.metrics
                .record_circuit_state(&self.destination_name, cb.state().as_u8());

            result
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
        DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics, FirewallMetrics, IpsMetrics,
        LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
    };
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::Duration;

    fn sample_alert() -> Alert {
        Alert {
            id: "1000000000-ids-001".to_string(),
            timestamp_ns: 1_000_000_000,
            component: "ids".to_string(),
            severity: Severity::High,
            rule_id: RuleId("ids-001".to_string()),
            action: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            is_ipv6: false,
            message: "SSH bruteforce detected".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: None,
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
        }
    }

    fn webhook_route(url: &str) -> AlertRoute {
        AlertRoute {
            name: "webhook-test".to_string(),
            destination: AlertDestination::Webhook {
                url: url.to_string(),
            },
            min_severity: Severity::Low,
            event_types: None,
        }
    }

    struct TestMetrics {
        circuit_state_calls: AtomicU32,
        last_state: std::sync::Mutex<u8>,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                circuit_state_calls: AtomicU32::new(0),
                last_state: std::sync::Mutex::new(0),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {
        fn record_circuit_state(&self, _: &str, state: u8) {
            self.circuit_state_calls.fetch_add(1, Ordering::Relaxed);
            *self.last_state.lock().unwrap() = state;
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

    fn fast_retry() -> RetryConfig {
        RetryConfig {
            max_retries: 1,
            backoff_schedule: vec![Duration::from_millis(1)],
            timeout: Duration::from_secs(2),
        }
    }

    #[tokio::test]
    async fn circuit_breaker_opens_after_threshold() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(2, Duration::from_secs(60));
        let mut sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );
        sender.skip_url_validation = true;

        let alert = sample_alert();
        let route = webhook_route("http://127.0.0.1:1/unreachable");

        // First attempt: will fail (connection refused)
        let _ = sender.send(&alert, &route).await;
        // Second attempt: will fail — opens circuit
        let _ = sender.send(&alert, &route).await;

        let cb_guard = sender.circuit_breaker.lock().await;
        assert_eq!(
            cb_guard.state(),
            domain::alert::circuit_breaker::CircuitState::Open
        );
    }

    #[tokio::test]
    async fn circuit_blocks_when_open() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(1, Duration::from_secs(60));
        let mut sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );
        sender.skip_url_validation = true;

        let alert = sample_alert();
        let route = webhook_route("http://127.0.0.1:1/unreachable");

        // First attempt fails, opens circuit
        let _ = sender.send(&alert, &route).await;

        // Second attempt should be blocked by circuit breaker
        let result = sender.send(&alert, &route).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("circuit breaker open"), "got: {err}");
    }

    #[tokio::test]
    async fn metric_updated_on_send() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let mut sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );
        sender.skip_url_validation = true;

        let alert = sample_alert();
        let route = webhook_route("http://127.0.0.1:1/unreachable");

        let _ = sender.send(&alert, &route).await;

        assert!(metrics.circuit_state_calls.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn non_webhook_route_returns_error() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test".to_string(),
        );

        let alert = sample_alert();
        let route = AlertRoute {
            name: "log-route".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::Low,
            event_types: None,
        };

        let result = sender.send(&alert, &route).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn successful_post_returns_ok() {
        use axum::{Router, http::StatusCode, routing::post};

        async fn handler_ok() -> StatusCode {
            StatusCode::OK
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/webhook", post(handler_ok));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/webhook");
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let mut sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );
        sender.skip_url_validation = true;

        let alert = sample_alert();
        let route = webhook_route(&url);

        let result = sender.send(&alert, &route).await;
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[tokio::test]
    async fn json_payload_contains_alert_fields() {
        use axum::body::Bytes;
        use axum::extract::State;
        use axum::http::StatusCode;
        use axum::{Router, routing::post};
        use tokio::sync::Mutex as TokioMutex;

        type SharedBody = Arc<TokioMutex<Option<Bytes>>>;

        async fn capture_handler(State(store): State<SharedBody>, body: Bytes) -> StatusCode {
            *store.lock().await = Some(body);
            StatusCode::OK
        }

        let store: SharedBody = Arc::new(TokioMutex::new(None));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/webhook", post(capture_handler))
            .with_state(Arc::clone(&store));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/webhook");
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let mut sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );
        sender.skip_url_validation = true;

        let alert = sample_alert();
        let route = webhook_route(&url);

        let result = sender.send(&alert, &route).await;
        assert!(result.is_ok(), "send failed: {result:?}");

        let captured = store.lock().await;
        let body = captured.as_ref().expect("no body captured");
        let json: serde_json::Value = serde_json::from_slice(body).expect("body is not valid JSON");

        assert_eq!(json["id"], "1000000000-ids-001");
        assert_eq!(json["severity"], "High");
        assert_eq!(json["rule_id"], "ids-001");
        assert_eq!(json["component"], "ids");
        assert_eq!(json["message"], "SSH bruteforce detected");
        assert_eq!(json["src_port"], 12345);
        assert_eq!(json["dst_port"], 22);
        assert_eq!(json["protocol"], 6);
    }

    #[tokio::test]
    async fn http_5xx_returns_error() {
        use axum::http::StatusCode;
        use axum::{Router, routing::post};

        async fn handler_500() -> StatusCode {
            StatusCode::INTERNAL_SERVER_ERROR
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/webhook", post(handler_500));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/webhook");
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let no_retry = RetryConfig {
            max_retries: 0,
            backoff_schedule: vec![],
            timeout: Duration::from_secs(2),
        };
        let mut sender = WebhookAlertSender::new(
            cb,
            no_retry,
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );
        sender.skip_url_validation = true;

        let alert = sample_alert();
        let route = webhook_route(&url);

        let result = sender.send(&alert, &route).await;
        assert!(result.is_err(), "expected Err for HTTP 500");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("500"), "error should mention 500, got: {err}");
    }

    #[test]
    fn alert_serialization_round_trip() {
        let alert = sample_alert();

        let json = serde_json::to_string(&alert).expect("serialize failed");
        let deserialized: Alert = serde_json::from_str(&json).expect("deserialize failed");

        assert_eq!(alert.id, deserialized.id);
        assert_eq!(alert.component, deserialized.component);
        assert_eq!(alert.message, deserialized.message);
        assert_eq!(alert.src_port, deserialized.src_port);
        assert_eq!(alert.dst_port, deserialized.dst_port);
        assert_eq!(alert.protocol, deserialized.protocol);
        assert_eq!(alert.timestamp_ns, deserialized.timestamp_ns);
        assert_eq!(alert.is_ipv6, deserialized.is_ipv6);
    }

    // ── Webhook URL SSRF validation ──────────────────────────────────

    #[test]
    fn webhook_url_accepts_public_https() {
        assert!(validate_webhook_url("https://hooks.slack.com/services/abc").is_ok());
    }

    #[test]
    fn webhook_url_rejects_loopback() {
        assert!(validate_webhook_url("http://127.0.0.1/hook").is_err());
    }

    #[test]
    fn webhook_url_rejects_private_rfc1918() {
        assert!(validate_webhook_url("http://10.0.0.1/hook").is_err());
        assert!(validate_webhook_url("http://172.16.0.1/hook").is_err());
        assert!(validate_webhook_url("http://192.168.1.1/hook").is_err());
    }

    #[test]
    fn webhook_url_rejects_link_local() {
        assert!(validate_webhook_url("http://169.254.169.254/latest/meta-data/").is_err());
    }

    #[test]
    fn webhook_url_rejects_localhost() {
        assert!(validate_webhook_url("http://localhost/hook").is_err());
    }

    #[test]
    fn webhook_url_rejects_ftp_scheme() {
        assert!(validate_webhook_url("ftp://example.com/hook").is_err());
    }
}
