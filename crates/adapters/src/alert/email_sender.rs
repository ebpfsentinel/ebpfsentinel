use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use application::retry::{RetryConfig, retry_with_backoff};
use domain::alert::circuit_breaker::CircuitBreaker;
use domain::alert::entity::{Alert, AlertDestination, AlertRoute};
use domain::common::error::DomainError;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::metrics_port::MetricsPort;

/// Alert sender that sends alert JSON via SMTP email.
pub struct EmailAlertSender {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: String,
    circuit_breaker: Mutex<CircuitBreaker>,
    retry_config: RetryConfig,
    metrics: Arc<dyn MetricsPort>,
    destination_name: String,
}

impl EmailAlertSender {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        smtp_host: &str,
        smtp_port: u16,
        username: Option<&str>,
        password: Option<&str>,
        tls: bool,
        from: String,
        circuit_breaker: CircuitBreaker,
        retry_config: RetryConfig,
        metrics: Arc<dyn MetricsPort>,
        destination_name: String,
    ) -> Result<Self, DomainError> {
        let mut builder = if tls {
            AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)
                .map_err(|e| DomainError::EngineError(format!("SMTP relay error: {e}")))?
                .port(smtp_port)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_host).port(smtp_port)
        };

        if let (Some(user), Some(pass)) = (username, password) {
            builder = builder.credentials(Credentials::new(user.to_string(), pass.to_string()));
        }

        let transport = builder.build();

        Ok(Self {
            transport,
            from,
            circuit_breaker: Mutex::new(circuit_breaker),
            retry_config,
            metrics,
            destination_name,
        })
    }
}

impl AlertSender for EmailAlertSender {
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

            // 2. Extract email address from route destination
            let to_addr = match &route.destination {
                AlertDestination::Email { to } => to.clone(),
                _ => {
                    return Err(DomainError::EngineError(
                        "email sender received non-email route".to_string(),
                    ));
                }
            };

            // 3. Build email with JSON body
            let body = serde_json::to_string_pretty(alert)
                .map_err(|e| DomainError::EngineError(format!("failed to serialize alert: {e}")))?;

            let subject = format!(
                "[eBPFsentinel] {:?} alert: {} ({})",
                alert.severity, alert.rule_id, alert.component,
            );

            let email =
                Message::builder()
                    .from(self.from.parse().map_err(|e| {
                        DomainError::EngineError(format!("invalid from address: {e}"))
                    })?)
                    .to(to_addr.parse().map_err(|e| {
                        DomainError::EngineError(format!("invalid to address: {e}"))
                    })?)
                    .subject(subject)
                    .header(ContentType::TEXT_PLAIN)
                    .body(body)
                    .map_err(|e| DomainError::EngineError(format!("failed to build email: {e}")))?;

            // 4. Retry with backoff: send SMTP email
            let transport = &self.transport;
            let result = retry_with_backoff(&self.retry_config, || {
                let email = email.clone();
                async move {
                    transport
                        .send(email)
                        .await
                        .map_err(|e| DomainError::EngineError(format!("SMTP send failed: {e}")))?;
                    Ok(())
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

    fn email_route() -> AlertRoute {
        AlertRoute {
            name: "email-test".to_string(),
            destination: AlertDestination::Email {
                to: "admin@example.com".to_string(),
            },
            min_severity: Severity::Low,
            event_types: None,
        }
    }

    struct TestMetrics {
        circuit_state_calls: AtomicU32,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                circuit_state_calls: AtomicU32::new(0),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {
        fn record_circuit_state(&self, _: &str, _: u8) {
            self.circuit_state_calls.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {}
    impl EventMetrics for TestMetrics {}

    #[tokio::test]
    async fn email_sender_construction() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let result = EmailAlertSender::new(
            "127.0.0.1",
            25,
            None,
            None,
            false,
            "alerts@example.com".to_string(),
            cb,
            RetryConfig::default(),
            metrics as Arc<dyn MetricsPort>,
            "email-test".to_string(),
        );
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn email_circuit_breaker_blocks_when_open() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(1, Duration::from_secs(60));
        let sender = EmailAlertSender::new(
            "127.0.0.1",
            25,
            None,
            None,
            false,
            "alerts@example.com".to_string(),
            cb,
            RetryConfig {
                max_retries: 0,
                backoff_schedule: vec![Duration::from_millis(1)],
                timeout: Duration::from_millis(100),
            },
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "email-test".to_string(),
        )
        .unwrap();

        let alert = sample_alert();
        let route = email_route();

        // First attempt fails (no SMTP server), opens circuit
        let _ = sender.send(&alert, &route).await;

        // Second attempt should be blocked by circuit breaker
        let result = sender.send(&alert, &route).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("circuit breaker open"), "got: {err}");
    }

    #[tokio::test]
    async fn email_metric_updated() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let sender = EmailAlertSender::new(
            "127.0.0.1",
            25,
            None,
            None,
            false,
            "alerts@example.com".to_string(),
            cb,
            RetryConfig {
                max_retries: 0,
                backoff_schedule: vec![Duration::from_millis(1)],
                timeout: Duration::from_millis(100),
            },
            Arc::clone(&metrics) as Arc<dyn MetricsPort>,
            "email-test".to_string(),
        )
        .unwrap();

        let _ = sender.send(&sample_alert(), &email_route()).await;

        assert!(metrics.circuit_state_calls.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn email_non_email_route_returns_error() {
        let metrics = Arc::new(TestMetrics::new());
        let cb = CircuitBreaker::new(5, Duration::from_secs(60));
        let sender = EmailAlertSender::new(
            "127.0.0.1",
            25,
            None,
            None,
            false,
            "alerts@example.com".to_string(),
            cb,
            RetryConfig::default(),
            metrics as Arc<dyn MetricsPort>,
            "email-test".to_string(),
        )
        .unwrap();

        let route = AlertRoute {
            name: "log-route".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::Low,
            event_types: None,
        };

        let result = sender.send(&sample_alert(), &route).await;
        assert!(result.is_err());
    }
}
