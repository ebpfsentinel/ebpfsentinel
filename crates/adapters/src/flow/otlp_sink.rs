//! Flow records as OTLP logs, on the collector the agent already exports its
//! alerts to.
//!
//! There is no endpoint, no credential and no trust decision here: all three
//! come from the alerting section through `otlp_transport`, because an estate
//! that configured one collector should not have to configure it twice. The
//! sink is one switch, and what it adds over IPFIX is a destination a SIEM
//! already holds open and a field vocabulary it already indexes.
//!
//! Delivery is batched by the SDK on a thread of its own, so an emit says
//! nothing about whether a collector took the record. What says so is the
//! flush, which is why one is asked for on a timer rather than per batch: a
//! flush per batch would block the drain for the exporter's whole timeout
//! every tick a collector was down, and never flushing at all would leave the
//! health endpoint claiming a sink was fine while every record was lost. A
//! failed flush counts the records it lost, backs the sink off, and shows up
//! in the health as the reason nothing is arriving.

use std::sync::Arc;
use std::time::{Duration, Instant};

use domain::common::error::DomainError;
use domain::flow::entity::FlowRecord;
use domain::flow::otlp::{EVENT_NAME, FLOW_SAMPLING, attributes, summary};
use infrastructure::config::{FlowExportConfig, OtlpExportConfig};
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider as _, Severity};
use ports::secondary::flow_sink_port::{FlowSink, FlowSinkHealth};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::otlp_transport::{build_logger_provider, scope};

/// The sink name both export series carry, and the name an operator reads in
/// the health endpoint.
const SINK_NAME: &str = "otlp";

/// How often delivery is confirmed. Half a minute is short enough that a
/// collector going down is visible in the health endpoint within one scrape
/// interval, and long enough that the drain is not waiting on a round trip
/// every tick.
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);

/// The first wait before a collector that refused a flush is flushed to
/// again, doubling up to the ceiling.
const BACKOFF_FLOOR: Duration = Duration::from_secs(5);
/// The longest wait between two attempts: a collector that comes back is
/// noticed in the same minute rather than the same hour.
const BACKOFF_CEILING: Duration = Duration::from_secs(60);

/// How long to wait before the next attempt, doubling with each failure.
fn backoff_for(consecutive_failures: u32) -> Duration {
    let shift = consecutive_failures.saturating_sub(1).min(4);
    let seconds = BACKOFF_FLOOR.as_secs().saturating_mul(1 << shift);
    Duration::from_secs(seconds).min(BACKOFF_CEILING)
}

/// Everything the sink mutates.
struct SinkState {
    /// Records emitted since the last confirmed flush, which is what a failed
    /// flush costs.
    pending: u64,
    flushed_at: Option<Instant>,
    retry_at: Option<Instant>,
    records_sent: u64,
    records_failed: u64,
    consecutive_failures: u32,
    detail: Option<String>,
}

/// The OTLP flow sink.
pub struct OtlpFlowSink {
    provider: opentelemetry_sdk::logs::SdkLoggerProvider,
    /// Built once: the scope and the logger are the same two values for every
    /// record, and building them per batch was work on the export path for a
    /// result that never differed.
    logger: opentelemetry_sdk::logs::SdkLogger,
    /// The rate the table samples at, written onto every record because no
    /// OTLP convention expresses it and a collector cannot scale a count back
    /// up without being told.
    sampling: u32,
    flush_interval: Duration,
    state: Mutex<SinkState>,
}

impl OtlpFlowSink {
    /// A sink on the collector `collector` names.
    ///
    /// Nothing is opened here: the SDK connects when the first batch is
    /// exported, so a collector that is not yet listening when the agent
    /// starts does not have to be.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EngineError`] when the exporter refuses to
    /// start: a protocol word with no transport behind it, a certificate
    /// authority that cannot be read, or a client that will not build.
    pub fn new(
        flow_export: &FlowExportConfig,
        collector: &OtlpExportConfig,
    ) -> Result<Self, DomainError> {
        let provider = build_logger_provider(collector, SINK_NAME)?;
        let logger = provider.logger_with_scope(scope());
        Ok(Self {
            provider,
            logger,
            sampling: flow_export.sampling,
            flush_interval: FLUSH_INTERVAL,
            state: Mutex::new(SinkState {
                pending: 0,
                flushed_at: None,
                retry_at: None,
                records_sent: 0,
                records_failed: 0,
                consecutive_failures: 0,
                detail: None,
            }),
        })
    }

    /// The sink a configured section asks for, or nothing where it is off.
    ///
    /// The collector block is the alerting one and is not optional here: the
    /// configuration refuses the pair before this is reached, so arriving
    /// with `None` is a wiring mistake rather than an operator's, and it is
    /// said out loud rather than returning a sink that sends nowhere.
    #[must_use]
    pub fn from_config(
        flow_export: &FlowExportConfig,
        collector: Option<&OtlpExportConfig>,
    ) -> Option<Arc<Self>> {
        if !flow_export.otlp.enabled {
            return None;
        }
        let Some(collector) = collector else {
            warn!("OTLP flow export is on with no collector configured: no flow sink built");
            return None;
        };
        match Self::new(flow_export, collector) {
            Ok(sink) => Some(Arc::new(sink)),
            Err(error) => {
                warn!(%error, "OTLP flow sink could not be built");
                None
            }
        }
    }

    /// Write one record onto the SDK.
    fn emit(&self, record: &FlowRecord) {
        let mut log = self.logger.create_log_record();
        log.set_event_name(EVENT_NAME);
        log.set_severity_number(Severity::Info);
        log.set_severity_text("INFO");
        log.set_body(AnyValue::String(summary(record).into()));
        log.add_attributes(
            attributes(record)
                .into_iter()
                .map(|(key, value)| (key, AnyValue::String(value.into()))),
        );
        if self.sampling > 1 {
            log.add_attribute(
                FLOW_SAMPLING,
                AnyValue::String(self.sampling.to_string().into()),
            );
        }
        self.logger.emit(log);
    }

    /// Ask the batch processor to deliver, off this thread: `force_flush`
    /// blocks until the exporter answers, and the exporter is a client with a
    /// timeout of its own.
    async fn flush(&self) -> Result<(), DomainError> {
        let provider = self.provider.clone();
        match tokio::task::spawn_blocking(move || provider.force_flush()).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(DomainError::EngineError(format!(
                "OTLP flush failed: {error}"
            ))),
            Err(error) => Err(DomainError::EngineError(format!(
                "OTLP flush did not run: {error}"
            ))),
        }
    }

    /// True where delivery is owed: never confirmed, or the interval has run
    /// out.
    fn flush_due(&self, state: &SinkState) -> bool {
        state
            .flushed_at
            .is_none_or(|flushed| flushed.elapsed() >= self.flush_interval)
    }
}

impl FlowSink for OtlpFlowSink {
    fn name(&self) -> &str {
        SINK_NAME
    }

    fn send<'a>(
        &'a self,
        records: &'a [FlowRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DomainError>> + Send + 'a>>
    {
        Box::pin(async move {
            if records.is_empty() {
                return Ok(());
            }
            let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
            let mut state = self.state.lock().await;

            if let Some(retry_at) = state.retry_at {
                if Instant::now() < retry_at {
                    state.records_failed = state.records_failed.saturating_add(count);
                    return Err(DomainError::EngineError(
                        "collector refused the last flush, backing off".to_string(),
                    ));
                }
                state.retry_at = None;
            }

            for record in records {
                self.emit(record);
            }
            state.records_sent = state.records_sent.saturating_add(count);
            state.pending = state.pending.saturating_add(count);

            if !self.flush_due(&state) {
                return Ok(());
            }

            let lost = state.pending;
            let result = self.flush().await;
            state.flushed_at = Some(Instant::now());
            state.pending = 0;
            match result {
                Ok(()) => {
                    state.consecutive_failures = 0;
                    state.detail = None;
                    debug!(
                        sink = SINK_NAME,
                        records = lost,
                        "flow sink delivery confirmed"
                    );
                    Ok(())
                }
                Err(error) => {
                    state.records_failed = state.records_failed.saturating_add(lost);
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    state.detail = Some(error.to_string());
                    state.retry_at = Some(Instant::now() + backoff_for(state.consecutive_failures));
                    warn!(sink = SINK_NAME, %error, "flow sink lost a batch");
                    Err(error)
                }
            }
        })
    }

    fn health<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = FlowSinkHealth> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            FlowSinkHealth {
                healthy: state.consecutive_failures == 0,
                detail: state.detail.clone(),
                records_sent: state.records_sent,
                records_failed: state.records_failed,
                consecutive_failures: state.consecutive_failures,
                ..FlowSinkHealth::new(SINK_NAME.to_string())
            }
        })
    }

    fn close<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DomainError>> + Send + 'a>>
    {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let lost = state.pending;
            let flushed = self.flush().await;
            state.pending = 0;
            if let Err(error) = flushed {
                state.records_failed = state.records_failed.saturating_add(lost);
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                state.detail = Some(error.to_string());
                warn!(sink = SINK_NAME, %error, "flow sink lost its last batch");
            }
            if let Err(error) = self.provider.shutdown() {
                warn!(sink = SINK_NAME, %error, "OTLP logger provider shutdown failed");
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use domain::flow::entity::FlowEndReason;
    use domain::flow::otlp::{FLOW_PACKETS, SOURCE_ADDRESS};
    use infrastructure::config::OtlpFlowSinkConfig;
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::logs::{LogBatch, LogExporter};

    use super::*;
    use crate::otlp_transport::build_provider;

    fn record(port: u16) -> FlowRecord {
        FlowRecord {
            src: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            dst: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            src_port: port,
            dst_port: 443,
            protocol: 6,
            packets: 12,
            bytes: 2_048,
            packets_rev: 9,
            bytes_rev: 8_192,
            start_ms: 1_760_000_000_000,
            end_ms: 1_760_000_012_500,
            reason: FlowEndReason::EndOfFlow,
            workload: None,
        }
    }

    fn flow_config(sampling: u32, enabled: bool) -> FlowExportConfig {
        FlowExportConfig {
            enabled: true,
            sampling,
            otlp: OtlpFlowSinkConfig { enabled },
            ..FlowExportConfig::default()
        }
    }

    fn collector(endpoint: &str) -> OtlpExportConfig {
        OtlpExportConfig {
            endpoint: endpoint.to_string(),
            protocol: "http".to_string(),
            timeout_ms: 200,
            headers: None,
            ca_cert: None,
            verify_tls: true,
        }
    }

    /// One exported record's attributes, as the names and the debug spelling
    /// of the values the exporter was handed.
    type SeenAttributes = Arc<std::sync::Mutex<Vec<Vec<(String, String)>>>>;

    /// An exporter that records what the batch processor handed it, and can
    /// be told to refuse.
    #[derive(Debug, Clone, Default)]
    struct CapturingExporter {
        records: SeenAttributes,
        bodies: Arc<std::sync::Mutex<Vec<String>>>,
        refusals: Arc<AtomicUsize>,
        refuse: bool,
    }

    impl LogExporter for CapturingExporter {
        fn export(&self, batch: LogBatch<'_>) -> impl Future<Output = OTelSdkResult> {
            if self.refuse {
                self.refusals.fetch_add(1, Ordering::SeqCst);
                return std::future::ready(Err(OTelSdkError::InternalFailure(
                    "the collector is not there".to_string(),
                )));
            }
            let mut held = self.records.lock().expect("no test holds this poisoned");
            let mut bodies = self.bodies.lock().expect("no test holds this poisoned");
            for (record, _scope) in batch.iter() {
                held.push(
                    record
                        .attributes_iter()
                        .map(|(key, value)| (key.to_string(), format!("{value:?}")))
                        .collect(),
                );
                if let Some(AnyValue::String(body)) = record.body() {
                    bodies.push(body.to_string());
                }
            }
            std::future::ready(Ok(()))
        }
    }

    /// A sink around an exporter a test holds, which is the only way to see
    /// what reached the wire without a collector.
    fn sink_on(exporter: CapturingExporter, flow_export: &FlowExportConfig) -> OtlpFlowSink {
        let provider = build_provider(exporter);
        let logger = provider.logger_with_scope(scope());
        OtlpFlowSink {
            provider,
            logger,
            sampling: flow_export.sampling,
            flush_interval: Duration::from_millis(0),
            state: Mutex::new(SinkState {
                pending: 0,
                flushed_at: None,
                retry_at: None,
                records_sent: 0,
                records_failed: 0,
                consecutive_failures: 0,
                detail: None,
            }),
        }
    }

    #[tokio::test]
    async fn a_batch_reaches_the_collector_as_one_log_per_record() {
        let exporter = CapturingExporter::default();
        let seen = exporter.records.clone();
        let bodies = exporter.bodies.clone();
        let sink = sink_on(exporter, &flow_config(1, true));

        sink.send(&[record(51_234), record(51_235)])
            .await
            .expect("the exporter accepts");

        let seen = seen.lock().expect("no test holds this poisoned");
        assert_eq!(seen.len(), 2, "two records are two logs, not one");
        let first = &seen[0];
        assert!(
            first.iter().any(|(key, _)| key == SOURCE_ADDRESS),
            "the five-tuple did not reach the collector: {first:?}"
        );
        assert!(first.iter().any(|(key, _)| key == FLOW_PACKETS));
        assert!(
            !first.iter().any(|(key, _)| key == FLOW_SAMPLING),
            "an unsampled table writes no sampling attribute: {first:?}"
        );
        let bodies = bodies.lock().expect("no test holds this poisoned");
        assert!(
            bodies[0].contains("10.0.0.7:51234 -> 93.184.216.34:443"),
            "the body is not the five-tuple a reader recognises: {bodies:?}"
        );
    }

    #[tokio::test]
    async fn a_sampled_table_says_at_what_rate() {
        let exporter = CapturingExporter::default();
        let seen = exporter.records.clone();
        let sink = sink_on(exporter, &flow_config(100, true));

        sink.send(&[record(51_234)]).await.expect("accepted");

        let seen = seen.lock().expect("no test holds this poisoned");
        let sampling = seen[0]
            .iter()
            .find(|(key, _)| key == FLOW_SAMPLING)
            .map(|(_, value)| value.clone())
            .expect("a sampled table writes the rate it sampled at");
        assert!(sampling.contains("100"), "{sampling}");
    }

    #[tokio::test]
    async fn a_collector_refusing_the_flush_is_counted_and_backed_off() {
        let exporter = CapturingExporter {
            refuse: true,
            ..CapturingExporter::default()
        };
        let refusals = exporter.refusals.clone();
        let sink = sink_on(exporter, &flow_config(1, true));

        let first = sink.send(&[record(51_234)]).await;
        assert!(first.is_err(), "a refused flush is not a delivery");

        let health = sink.health().await;
        assert!(!health.healthy, "a sink losing every record is not healthy");
        assert_eq!(health.records_failed, 1);
        assert_eq!(health.consecutive_failures, 1);
        assert!(
            health
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("flush failed")),
            "the health does not say why: {:?}",
            health.detail
        );

        let second = sink.send(&[record(51_235)]).await;
        assert!(second.is_err(), "the backoff refuses the batch");
        assert_eq!(
            refusals.load(Ordering::SeqCst),
            1,
            "the backoff tried the collector again inside its own window"
        );
        assert_eq!(sink.health().await.records_failed, 2);
    }

    #[tokio::test]
    async fn an_empty_batch_touches_nothing() {
        let exporter = CapturingExporter::default();
        let seen = exporter.records.clone();
        let sink = sink_on(exporter, &flow_config(1, true));

        sink.send(&[])
            .await
            .expect("nothing to send is not a failure");

        assert!(seen.lock().expect("no test holds this poisoned").is_empty());
        assert_eq!(sink.health().await.records_sent, 0);
    }

    #[test]
    fn the_sink_is_not_built_where_the_section_is_off() {
        let config = flow_config(1, false);
        assert!(
            OtlpFlowSink::from_config(&config, Some(&collector("http://127.0.0.1:1"))).is_none()
        );
    }

    #[test]
    fn the_sink_is_not_built_where_no_collector_is_named() {
        let config = flow_config(1, true);
        assert!(
            OtlpFlowSink::from_config(&config, None).is_none(),
            "a sink with nowhere to send is not a sink"
        );
    }

    #[test]
    fn a_configured_collector_builds_a_sink_without_reaching_it() {
        let config = flow_config(1, true);
        let sink = OtlpFlowSink::from_config(&config, Some(&collector("http://127.0.0.1:1")))
            .expect("the exporter builds without a collector listening");
        assert_eq!(sink.name(), "otlp");
    }
}
