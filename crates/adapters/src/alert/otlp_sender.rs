use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use domain::alert::entity::{Alert, AlertRoute};
use domain::common::error::DomainError;
use opentelemetry::InstrumentationScope;
use opentelemetry::logs::{Logger, LoggerProvider as _};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use ports::secondary::alert_sender::AlertSender;
use ports::secondary::metrics_port::MetricsPort;

use crate::alert::otlp_record::{OtlpLogRecord, now_unix_nano};

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

            let mapped = OtlpLogRecord::from_alert(alert, now_unix_nano())?;

            let mut record = logger.create_log_record();
            mapped.apply(&mut record);

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

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use opentelemetry::logs::Severity as OtelSeverity;

    /// A log record the sender can write onto without an SDK behind it.
    #[derive(Default)]
    struct RecordedLog {
        timestamp: Option<std::time::SystemTime>,
        observed: Option<std::time::SystemTime>,
        body: Option<String>,
        severity_number: Option<OtelSeverity>,
        severity_text: Option<String>,
        attributes: Vec<(String, String)>,
    }

    impl opentelemetry::logs::LogRecord for RecordedLog {
        fn set_event_name(&mut self, _name: &'static str) {}

        fn set_timestamp(&mut self, timestamp: std::time::SystemTime) {
            self.timestamp = Some(timestamp);
        }

        fn set_observed_timestamp(&mut self, timestamp: std::time::SystemTime) {
            self.observed = Some(timestamp);
        }

        fn set_severity_text(&mut self, text: &'static str) {
            self.severity_text = Some(text.to_string());
        }

        fn set_severity_number(&mut self, number: OtelSeverity) {
            self.severity_number = Some(number);
        }

        fn set_body(&mut self, body: opentelemetry::logs::AnyValue) {
            if let opentelemetry::logs::AnyValue::String(s) = body {
                self.body = Some(s.to_string());
            }
        }

        fn add_attributes<I, K, V>(&mut self, attributes: I)
        where
            I: IntoIterator<Item = (K, V)>,
            K: Into<opentelemetry::Key>,
            V: Into<opentelemetry::logs::AnyValue>,
        {
            for (key, value) in attributes {
                self.add_attribute(key, value);
            }
        }

        fn set_target<T>(&mut self, _target: T)
        where
            T: Into<std::borrow::Cow<'static, str>>,
        {
        }

        fn add_attribute<K, V>(&mut self, key: K, value: V)
        where
            K: Into<opentelemetry::Key>,
            V: Into<opentelemetry::logs::AnyValue>,
        {
            let value = match value.into() {
                opentelemetry::logs::AnyValue::String(s) => s.to_string(),
                other => format!("{other:?}"),
            };
            self.attributes.push((key.into().to_string(), value));
        }

        fn set_trace_context(
            &mut self,
            _trace_id: opentelemetry::trace::TraceId,
            _span_id: opentelemetry::trace::SpanId,
            _trace_flags: Option<opentelemetry::trace::TraceFlags>,
        ) {
        }
    }

    fn sample_alert() -> Alert {
        Alert {
            id: "1000000000-ids-001".to_string(),
            timestamp_ns: 1_709_913_600_123_000_000,
            component: "ids".to_string(),
            severity: Severity::Critical,
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
            container: None,
            container_metadata: None,
        }
    }

    #[test]
    fn the_sender_writes_the_shared_record_onto_the_sdk() {
        let alert = sample_alert();
        let mapped = OtlpLogRecord::from_alert(&alert, 1_709_913_601_000_000_000)
            .expect("the alert serialises");

        let mut record = RecordedLog::default();
        mapped.apply(&mut record);

        assert_eq!(record.severity_text.as_deref(), Some("critical"));
        assert!(matches!(record.severity_number, Some(OtelSeverity::Fatal)));
        assert_eq!(record.body.as_deref(), Some(mapped.body.as_str()));
        assert_eq!(record.attributes, mapped.attributes);
        assert_eq!(
            record
                .timestamp
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| u64::try_from(d.as_nanos()).ok()),
            Some(alert.timestamp_ns)
        );
        assert_eq!(
            record
                .observed
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .and_then(|d| u64::try_from(d.as_nanos()).ok()),
            Some(1_709_913_601_000_000_000)
        );
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
