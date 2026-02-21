use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use application::retry::{RetryConfig, retry_with_backoff};
use domain::alert::circuit_breaker::CircuitBreaker;
use domain::alert::entity::{Alert, AlertDestination, AlertRoute};
use domain::common::error::DomainError;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::metrics_port::MetricsPort;

/// Alert sender that POSTs alert JSON to a webhook URL.
pub struct WebhookAlertSender {
    client: reqwest::Client,
    circuit_breaker: Mutex<CircuitBreaker>,
    retry_config: RetryConfig,
    metrics: Arc<dyn MetricsPort>,
    destination_name: String,
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
        }
    }
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
                let mut cb = self.circuit_breaker.lock().unwrap();
                if !cb.can_attempt() {
                    self.metrics
                        .record_circuit_state(&self.destination_name, cb.state().as_u8());
                    return Err(DomainError::EngineError(format!(
                        "circuit breaker open for destination '{}'",
                        self.destination_name
                    )));
                }
            }

            // 2. Extract webhook URL from route destination
            let url = match &route.destination {
                AlertDestination::Webhook { url } => url.clone(),
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
            let mut cb = self.circuit_breaker.lock().unwrap();
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
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
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
        let sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );

        let alert = sample_alert();
        let route = webhook_route("http://127.0.0.1:1/unreachable");

        // First attempt: will fail (connection refused)
        let _ = sender.send(&alert, &route).await;
        // Second attempt: will fail — opens circuit
        let _ = sender.send(&alert, &route).await;

        let cb_guard = sender.circuit_breaker.lock().unwrap();
        assert_eq!(
            cb_guard.state(),
            domain::alert::circuit_breaker::CircuitState::Open
        );
    }

    #[tokio::test]
    async fn circuit_blocks_when_open() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(1, Duration::from_secs(60));
        let sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );

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
        let sender = WebhookAlertSender::new(
            cb,
            fast_retry(),
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "test-webhook".to_string(),
        );

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
}
