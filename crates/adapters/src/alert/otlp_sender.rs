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
                .with_endpoint(http_logs_endpoint(endpoint))
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

/// Resolve the OTLP/HTTP logs URL from a configured endpoint.
///
/// The SDK only appends the signal path (`/v1/logs`) when the endpoint comes
/// from the generic `OTEL_EXPORTER_OTLP_ENDPOINT` variable; an endpoint passed
/// programmatically is used verbatim. Configuration here names a collector
/// (`http://otel-collector:4318`), so without this the exporter would POST to
/// `/` and every spec-compliant collector would reject it. An endpoint that
/// already carries a path is left untouched, so a full signal URL still works.
fn http_logs_endpoint(endpoint: &str) -> String {
    let trimmed = endpoint.trim_end_matches('/');
    // Everything after the scheme; a remaining '/' means a path was given.
    let after_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    if after_scheme.contains('/') {
        endpoint.to_string()
    } else {
        format!("{trimmed}/v1/logs")
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

            // Fire-and-forget: count the hand-off to the OTLP batch exporter.
            // No retry and no delivery confirmation (batched export).
            self.metrics.record_alert_exported("otlp");

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

#[cfg(test)]
mod endpoint_tests {
    use super::http_logs_endpoint;

    #[test]
    fn bare_collector_endpoint_gains_the_signal_path() {
        assert_eq!(
            http_logs_endpoint("http://otel-collector:4318"),
            "http://otel-collector:4318/v1/logs"
        );
    }

    #[test]
    fn trailing_slash_does_not_double_up() {
        assert_eq!(
            http_logs_endpoint("http://otel-collector:4318/"),
            "http://otel-collector:4318/v1/logs"
        );
    }

    #[test]
    fn explicit_signal_url_is_left_alone() {
        assert_eq!(
            http_logs_endpoint("http://otel-collector:4318/v1/logs"),
            "http://otel-collector:4318/v1/logs"
        );
    }

    #[test]
    fn custom_path_is_left_alone() {
        assert_eq!(
            http_logs_endpoint("https://gateway.example.com/otlp/v1/logs"),
            "https://gateway.example.com/otlp/v1/logs"
        );
    }

    #[test]
    fn host_without_scheme_still_resolves() {
        assert_eq!(
            http_logs_endpoint("collector:4318"),
            "collector:4318/v1/logs"
        );
    }
}
