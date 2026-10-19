//! Flow export status.
//!
//! One route, and it answers the two questions an operator has when a
//! collector shows nothing: is the exporter running and what did it do with
//! the flows it saw. The counters are the table's own, so a figure here is
//! the same figure the metrics endpoint carries under `flows_exported` and
//! `flows_dropped` rather than a second accounting of it.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

/// What one sink says about itself.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowSinkStatusResponse {
    /// Transport and target, as configured.
    pub name: String,
    /// False once a write failed and before the next one succeeds.
    pub healthy: bool,
    /// Why it is unhealthy, in the words the transport used. Absent while it
    /// is healthy, and it names no address beyond the sink's own name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub records_sent: u64,
    pub records_failed: u64,
    pub consecutive_failures: u32,
}

/// The exporter, its table and its sinks.
#[derive(Debug, Serialize, ToSchema)]
pub struct FlowExportStatusResponse {
    /// False when no sink is configured, in which case every counter below
    /// is zero because nothing was ever collected, not because nothing
    /// happened.
    pub enabled: bool,
    /// Readings the table took in.
    pub observed: u64,
    /// Records handed to the queue.
    pub exported: u64,
    /// Flows the sampling rate left out. Zero at the default rate of one.
    pub sampled_out: u64,
    /// Flows written out early because the table was full.
    pub evicted: u64,
    /// Flows whose counters went backwards, which is a five-tuple the kernel
    /// handed to a new connection rather than a negative.
    pub restarted: u64,
    /// Records built and then dropped because the queue to the sinks was
    /// full. A number here is a collector that cannot keep up, and it is why
    /// a missing flow is never a silence.
    pub queue_drops: u64,
    pub active_timeout_secs: u64,
    pub idle_timeout_secs: u64,
    /// One flow in this many is exported. The collector cannot infer it, so
    /// it has to be configured on both sides.
    pub sampling: u32,
    pub table_capacity: usize,
    pub queue_depth: usize,
    pub batch_size: usize,
    pub sinks: Vec<FlowSinkStatusResponse>,
}

// ── Handler ───────────────────────────────────────────────────────

/// `GET /api/v1/flows/export` - flow export status.
#[utoipa::path(
    get, path = "/api/v1/flows/export",
    tag = "Flows",
    responses((status = 200, description = "Flow export status", body = FlowExportStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Flow export not enabled", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn flow_export_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<FlowExportStatusResponse>, ApiError> {
    let handle = state.flow_export.load_full().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Flow export not enabled".to_string(),
    })?;
    let stats = handle.table_stats();
    let settings = handle.settings();
    let sinks = handle
        .sinks()
        .await
        .into_iter()
        .map(|health| FlowSinkStatusResponse {
            name: health.name,
            healthy: health.healthy,
            detail: health.detail,
            records_sent: health.records_sent,
            records_failed: health.records_failed,
            consecutive_failures: health.consecutive_failures,
        })
        .collect();
    Ok(Json(FlowExportStatusResponse {
        enabled: true,
        observed: stats.observed,
        exported: stats.exported,
        sampled_out: stats.sampled_out,
        evicted: stats.evicted,
        restarted: stats.restarted,
        queue_drops: handle.queue_drops(),
        active_timeout_secs: settings.limits.active_timeout_ms / 1_000,
        idle_timeout_secs: settings.limits.idle_timeout_ms / 1_000,
        sampling: settings.limits.sampling,
        table_capacity: settings.limits.capacity,
        queue_depth: settings.queue_depth,
        batch_size: settings.batch_size,
        sinks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapters::metrics::AgentMetrics;
    use application::flow_export_service::{FlowExportSettings, spawn_flow_export};
    use application::workload_resolver::WorkloadResolver;
    use domain::flow::ipfix::IpfixOptions;
    use infrastructure::config::{FlowTargetConfig, IpfixSinkConfig};
    use ports::secondary::flow_sink_port::FlowSink;
    use ports::secondary::metrics_port::MetricsPort;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    struct NoopSink;
    impl ports::secondary::audit_sink::AuditSink for NoopSink {
        fn write_entry(
            &self,
            _entry: &domain::audit::entity::AuditEntry,
        ) -> Result<(), domain::audit::error::AuditError> {
            Ok(())
        }
    }

    fn state() -> AppState {
        let noop: Arc<dyn MetricsPort> = Arc::new(ports::test_utils::NoopMetrics);
        let firewall = application::firewall_service_impl::FirewallAppService::new(
            domain::firewall::engine::FirewallEngine::new(),
            None,
            Arc::clone(&noop),
        );
        let ips = application::ips_service_impl::IpsAppService::new(
            domain::ips::engine::IpsEngine::default(),
            Arc::clone(&noop),
        );
        let l7 = application::l7_service_impl::L7AppService::new(
            domain::l7::engine::L7Engine::new(),
            Arc::clone(&noop),
        );
        let ratelimit = application::ratelimit_service_impl::RateLimitAppService::new(
            domain::ratelimit::engine::RateLimitEngine::new(),
            Arc::clone(&noop),
        );
        let threatintel = application::threatintel_service_impl::ThreatIntelAppService::new(
            domain::threatintel::engine::ThreatIntelEngine::new(1_000_000),
            Arc::clone(&noop),
            vec![],
        );
        let audit = application::audit_service_impl::AuditAppService::new(
            Arc::new(NoopSink) as Arc<dyn ports::secondary::audit_sink::AuditSink>
        );
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(std::sync::atomic::AtomicBool::new(true)),
            Arc::new(tokio::sync::RwLock::new(firewall)),
            Arc::new(arc_swap::ArcSwap::from_pointee(ips)),
            Arc::new(arc_swap::ArcSwap::from_pointee(l7)),
            Arc::new(tokio::sync::RwLock::new(ratelimit)),
            Arc::new(arc_swap::ArcSwap::from_pointee(threatintel)),
            Arc::new(audit),
            Arc::new(tokio::sync::RwLock::new(
                infrastructure::config::AgentConfig::from_yaml("agent:\n  interfaces: [eth0]")
                    .expect("a minimal configuration"),
            )),
            reload_tx,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        )
    }

    #[tokio::test]
    async fn a_node_without_an_exporter_answers_not_found() {
        let error = flow_export_status(State(Arc::new(state())))
            .await
            .expect_err("no exporter is a 404, not a zeroed reading");
        assert!(matches!(error, ApiError::NotFound { .. }));
    }

    #[tokio::test]
    async fn the_status_names_the_sinks_and_the_configured_bounds() {
        let target = FlowTargetConfig {
            address: "127.0.0.1:1".to_string(),
            transport: "udp".to_string(),
        };
        let sink = Arc::new(adapters::flow::ipfix_sink::IpfixSink::new(
            &target,
            IpfixOptions::default(),
            Duration::from_secs(600),
        )) as Arc<dyn FlowSink>;
        let (events_tx, events_rx) = tokio::sync::broadcast::channel(4);
        let cancel = CancellationToken::new();
        let settings = FlowExportSettings::default();
        let handle = spawn_flow_export(
            settings,
            WorkloadResolver::new(),
            vec![sink],
            Arc::new(AgentMetrics::new()) as Arc<dyn MetricsPort>,
            events_rx,
            cancel.clone(),
        )
        .expect("one sink");
        let state = Arc::new(state());
        state.flow_export.store(Some(Arc::new(handle)));

        let Json(body) = flow_export_status(State(state)).await.expect("a reading");
        assert!(body.enabled);
        assert_eq!(body.observed, 0);
        assert_eq!(body.queue_drops, 0);
        assert_eq!(body.sampling, 1);
        assert_eq!(body.active_timeout_secs, 60);
        assert_eq!(body.idle_timeout_secs, 15);
        assert_eq!(body.sinks.len(), 1);
        assert_eq!(body.sinks[0].name, "ipfix-udp-127.0.0.1:1");
        assert!(body.sinks[0].healthy);
        assert!(body.sinks[0].detail.is_none());
        cancel.cancel();
        drop(events_tx);
    }

    #[test]
    fn a_disabled_ipfix_section_yields_no_sink_to_report() {
        assert!(
            adapters::flow::ipfix_sink::IpfixSink::from_config(&IpfixSinkConfig::default())
                .is_empty()
        );
    }
}
