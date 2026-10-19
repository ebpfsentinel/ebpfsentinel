//! The one OTLP transport this agent exports through.
//!
//! Alerts and flow records are two signals on one wire: an estate running a
//! collector configures it once, and both reach it with the same protocol,
//! the same credential and the same trust decision. That is why the exporter,
//! the resource and the scope are built here rather than once per sender -
//! two copies of this would be two places for an endpoint, a certificate
//! authority or a timeout to drift apart, and the drift would only show on
//! the signal nobody was watching.

use std::time::Duration;

use domain::common::error::DomainError;
use infrastructure::config::{OtlpExportConfig, OtlpProtocol};
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig, WithTonicConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::{LogExporter, SdkLoggerProvider};
use tonic::metadata::{MetadataKey, MetadataMap, MetadataValue};
use tonic::transport::{Certificate, ClientTlsConfig};

use crate::alert::otlp_record::{OtlpResourceEnv, resource_attributes};

/// A logger provider on the collector the configuration names.
///
/// The block is taken whole rather than field by field because what the
/// exporter needs is the protocol, the credential and the trust decision
/// together: which of them applies depends on the other two. `destination` is
/// the label the caller counts under, and is used here only to say which
/// signal an unverified collector is being accepted for.
///
/// # Errors
///
/// Returns [`DomainError::EngineError`] when the protocol is not one of the
/// two accepted words, when a configured certificate authority cannot be
/// read, or when the exporter itself refuses to start.
pub fn build_logger_provider(
    config: &OtlpExportConfig,
    destination: &str,
) -> Result<SdkLoggerProvider, DomainError> {
    let protocol = config
        .protocol()
        .map_err(|e| DomainError::EngineError(e.to_string()))?;
    let timeout = Duration::from_millis(config.timeout_ms);
    let headers: Vec<(String, String)> = config
        .headers
        .iter()
        .flatten()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();

    let exporter = match protocol {
        OtlpProtocol::Http => {
            let mut builder = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(http_logs_endpoint(&config.endpoint))
                .with_timeout(timeout)
                .with_headers(headers.into_iter().collect());
            if let Some(client) = http_client(config, timeout, destination)? {
                builder = builder.with_http_client(client);
            }
            builder.build().map_err(|e| {
                DomainError::EngineError(format!("OTLP HTTP exporter init failed: {e}"))
            })?
        }
        OtlpProtocol::Grpc => {
            let mut builder = opentelemetry_otlp::LogExporter::builder()
                .with_tonic()
                .with_endpoint(&config.endpoint)
                .with_timeout(timeout)
                .with_metadata(metadata(&headers)?);
            if let Some(tls) = grpc_tls(config)? {
                builder = builder.with_tls_config(tls);
            }
            builder.build().map_err(|e| {
                DomainError::EngineError(format!("OTLP gRPC exporter init failed: {e}"))
            })?
        }
    };

    Ok(build_provider(exporter))
}

/// The configured headers as gRPC metadata, since a header on this transport
/// is a metadata entry rather than an HTTP header.
pub(crate) fn metadata(headers: &[(String, String)]) -> Result<MetadataMap, DomainError> {
    let mut map = MetadataMap::with_capacity(headers.len());
    for (name, value) in headers {
        let key = MetadataKey::from_bytes(name.to_ascii_lowercase().as_bytes()).map_err(|_| {
            DomainError::EngineError(format!(
                "OTLP header name '{name}' is not a valid gRPC metadata key"
            ))
        })?;
        let value = MetadataValue::try_from(value.as_str()).map_err(|_| {
            DomainError::EngineError(format!("value of OTLP header '{name}' is not sendable"))
        })?;
        map.insert(key, value);
    }
    Ok(map)
}

/// The TLS settings for the gRPC transport, or `None` where the endpoint is
/// plain HTTP and nothing about trust was configured.
///
/// Verification cannot be turned off here, which is why the configuration
/// refuses that pair before this is reached: tonic offers no way to accept a
/// certificate it could not verify, and pretending otherwise would export to
/// a verified collector an operator believed was not one.
fn grpc_tls(config: &OtlpExportConfig) -> Result<Option<ClientTlsConfig>, DomainError> {
    let secure = config.endpoint.trim().starts_with("https://");
    let Some(ca_cert) = config.ca_cert.as_deref() else {
        return Ok(secure.then(|| ClientTlsConfig::new().with_enabled_roots()));
    };
    let pem = std::fs::read(ca_cert).map_err(|e| {
        DomainError::EngineError(format!(
            "OTLP certificate authority '{ca_cert}' could not be read: {e}"
        ))
    })?;
    Ok(Some(
        ClientTlsConfig::new()
            .with_enabled_roots()
            .ca_certificate(Certificate::from_pem(pem)),
    ))
}

/// The HTTP client the exporter posts through, or `None` where the built-in
/// one already does what the configuration asked for.
///
/// It is a blocking client on purpose. The batch processor exports from a
/// dedicated thread of its own, which carries no Tokio reactor, so an async
/// client would reach the connector and find nothing to register the socket
/// with. A blocking client owns the runtime it drives, so it answers from any
/// thread, and the export is already off the path that produced the record.
fn http_client(
    config: &OtlpExportConfig,
    timeout: Duration,
    destination: &str,
) -> Result<Option<reqwest::blocking::Client>, DomainError> {
    if config.verify_tls && config.ca_cert.is_none() {
        return Ok(None);
    }

    let mut builder = reqwest::blocking::Client::builder().timeout(timeout);
    if let Some(ca_cert) = config.ca_cert.as_deref() {
        let pem = std::fs::read(ca_cert).map_err(|e| {
            DomainError::EngineError(format!(
                "OTLP certificate authority '{ca_cert}' could not be read: {e}"
            ))
        })?;
        let certificate = reqwest::Certificate::from_pem(&pem).map_err(|e| {
            DomainError::EngineError(format!(
                "OTLP certificate authority '{ca_cert}' is not a PEM certificate: {e}"
            ))
        })?;
        builder = builder.add_root_certificate(certificate);
    }
    if !config.verify_tls {
        tracing::warn!(
            destination,
            "TLS certificate verification disabled, the collector is not authenticated"
        );
        builder = builder.danger_accept_invalid_certs(true);
    }

    builder
        .build()
        .map_err(|e| DomainError::EngineError(format!("OTLP HTTP client init failed: {e}")))
        .map(Some)
}

/// The scope every record this agent exports is written under.
pub(crate) fn scope() -> InstrumentationScope {
    InstrumentationScope::builder("ebpfsentinel")
        .with_version(env!("CARGO_PKG_VERSION"))
        .build()
}

/// Build the provider with the resource that says which agent a record came
/// from, so a collector holding a fleet can tell two of them apart.
pub(crate) fn build_provider<E: LogExporter + 'static>(exporter: E) -> SdkLoggerProvider {
    let attributes = resource_attributes(&OtlpResourceEnv::from_process());
    let resource = Resource::builder_empty()
        .with_attributes(
            attributes
                .into_iter()
                .map(|(key, value)| KeyValue::new(key, value)),
        )
        .build();

    SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build()
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
            http_logs_endpoint("https://gateway.example/otlp/v1/logs"),
            "https://gateway.example/otlp/v1/logs"
        );
    }

    #[test]
    fn host_without_scheme_still_resolves() {
        assert_eq!(
            http_logs_endpoint("otel-collector:4318"),
            "otel-collector:4318/v1/logs"
        );
    }
}
