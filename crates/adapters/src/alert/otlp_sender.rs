use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use domain::alert::entity::{Alert, AlertRoute};
use domain::common::error::DomainError;
use opentelemetry::InstrumentationScope;
use opentelemetry::logs::{LogRecord as _, Logger, LoggerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::metrics_port::MetricsPort;

/// Alert sender that exports alerts as OTLP Logs (fire-and-forget).
pub struct OtlpAlertSender {
    logger_provider: SdkLoggerProvider,
    metrics: Arc<dyn MetricsPort>,
}

impl OtlpAlertSender {
    /// Create a new OTLP sender. `protocol` is `"grpc"` or `"http"`.
    pub fn new(
        endpoint: &str,
        protocol: &str,
        timeout: Duration,
        metrics: Arc<dyn MetricsPort>,
    ) -> Result<Self, DomainError> {
        let exporter = match protocol {
            "http" => opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(endpoint)
                .with_timeout(timeout)
                .build()
                .map_err(|e| {
                    DomainError::EngineError(format!("OTLP HTTP exporter init failed: {e}"))
                })?,
            _ => opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(endpoint)
                .with_timeout(timeout)
                .build()
                .map_err(|e| {
                    DomainError::EngineError(format!("OTLP gRPC exporter init failed: {e}"))
                })?,
        };

        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter)
            .build();

        Ok(Self {
            logger_provider,
            metrics,
        })
    }
}

impl AlertSender for OtlpAlertSender {
    fn send<'a>(
        &'a self,
        alert: &'a Alert,
        _route: &'a AlertRoute,
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
        Box::pin(async move {
            let scope = InstrumentationScope::builder("ebpfsentinel")
                .with_version(env!("CARGO_PKG_VERSION"))
                .build();
            let logger = self.logger_provider.logger_with_scope(scope);

            let body = serde_json::to_string(alert).unwrap_or_default();

            let mut record = logger.create_log_record();
            record.set_body(body.into());
            record.set_severity_number(alert_severity_to_otel(alert.severity));
            record.set_severity_text(severity_label(alert.severity));

            record.add_attribute(
                "mitre.technique.id",
                alert
                    .mitre_attack
                    .as_ref()
                    .map_or(String::new(), |m| m.technique_id.clone()),
            );
            record.add_attribute("alert.component", alert.component.clone());
            record.add_attribute("alert.rule_id", alert.rule_id.0.clone());

            logger.emit(record);

            // Fire-and-forget: metric only, no retry
            self.metrics.record_alert_dropped("otlp_exported");

            Ok(())
        })
    }
}

impl Drop for OtlpAlertSender {
    fn drop(&mut self) {
        if let Err(e) = self.logger_provider.shutdown() {
            tracing::warn!(error = %e, "OTLP logger provider shutdown failed");
        }
    }
}

fn alert_severity_to_otel(
    severity: domain::common::entity::Severity,
) -> opentelemetry::logs::Severity {
    match severity {
        domain::common::entity::Severity::Low => opentelemetry::logs::Severity::Info,
        domain::common::entity::Severity::Medium => opentelemetry::logs::Severity::Warn,
        domain::common::entity::Severity::High => opentelemetry::logs::Severity::Error,
        domain::common::entity::Severity::Critical => opentelemetry::logs::Severity::Fatal,
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

    #[test]
    fn severity_mapping() {
        use domain::common::entity::Severity;
        assert!(matches!(
            alert_severity_to_otel(Severity::Low),
            opentelemetry::logs::Severity::Info
        ));
        assert!(matches!(
            alert_severity_to_otel(Severity::Critical),
            opentelemetry::logs::Severity::Fatal
        ));
    }

    #[test]
    fn severity_label_values() {
        use domain::common::entity::Severity;
        assert_eq!(severity_label(Severity::Low), "low");
        assert_eq!(severity_label(Severity::High), "high");
    }
}
