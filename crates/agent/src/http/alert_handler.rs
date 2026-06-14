use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use serde::{Deserialize, Serialize};
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use utoipa::{IntoParams, ToSchema};

use domain::alert::entity::Alert;
use domain::alert::filter::{AlertFilter, FilterError, parse_severity as parse_severity_domain};
use domain::alert::query::AlertQuery;
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::auth::entity::JwtClaims;
use domain::common::entity::Severity;
use ports::secondary::metrics_port::{AlertMetrics, MetricsPort};

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Query parameters DTO ────────────────────────────────────────────

#[derive(Debug, Deserialize, IntoParams)]
pub struct AlertQueryParams {
    /// Filter by component (e.g. "ids", "dlp", "threatintel").
    pub component: Option<String>,
    /// Filter by minimum severity ("low", "medium", "high", "critical").
    pub min_severity: Option<String>,
    /// Filter by rule ID (exact match).
    pub rule_id: Option<String>,
    /// Filter by false-positive flag.
    pub false_positive: Option<bool>,
    /// Start of time range (nanoseconds since epoch, inclusive).
    pub from: Option<u64>,
    /// End of time range (nanoseconds since epoch, inclusive).
    pub to: Option<u64>,
    /// Filter by MITRE ATT&CK tactic (e.g. "exfiltration", "impact").
    pub tactic: Option<String>,
    /// Filter by MITRE ATT&CK technique ID (e.g. "T1041").
    pub technique: Option<String>,
    /// Maximum entries to return (default 100, max 1000).
    pub limit: Option<usize>,
    /// Number of entries to skip (default 0).
    pub offset: Option<usize>,
}

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct AlertListResponse {
    pub alerts: Vec<AlertResponse>,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Serialize, ToSchema)]
pub struct AlertResponse {
    pub id: String,
    pub timestamp_ns: u64,
    pub component: String,
    pub severity: String,
    pub rule_id: String,
    pub action: String,
    /// Source address as four big-endian u32 words.
    /// IPv4: `[v4, 0, 0, 0]`. IPv6: full 128-bit address.
    pub src_addr: Vec<u32>,
    /// Destination address (same encoding as `src_addr`).
    pub dst_addr: Vec<u32>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub message: String,
    pub false_positive: bool,
    /// Reverse-DNS domain for source IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_domain: Option<String>,
    /// Reverse-DNS domain for destination IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_domain: Option<String>,
    /// Reputation score for source domain (0.0=clean, 1.0=malicious).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_domain_score: Option<f64>,
    /// Reputation score for destination domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_domain_score: Option<f64>,
    /// `GeoIP` location for source IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_geo: Option<String>,
    /// `GeoIP` location for destination IP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_geo: Option<String>,
    /// Threat intel: IOC confidence score (0-100).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// Threat intel: threat category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    /// DLP: data category (pci, pii, credentials, custom).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    /// DLP: process ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// DLP: thread group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    /// DLP: direction (0=write, 1=read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<u8>,
    /// IDS: matched domain name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_domain: Option<String>,
    /// `DDoS`: attack type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_type: Option<String>,
    /// `DDoS`: peak packets per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peak_pps: Option<u64>,
    /// `DDoS`: current smoothed packets per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_pps: Option<u64>,
    /// `DDoS`: mitigation status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigation_status: Option<String>,
    /// `DDoS`: total packets in attack.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_packets: Option<u64>,
    /// MITRE ATT&CK technique ID (e.g. "T1071").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique_id: Option<String>,
    /// MITRE ATT&CK technique name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique_name: Option<String>,
    /// MITRE ATT&CK tactic in kebab-case.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_tactic: Option<String>,
    /// JA4 TLS `ClientHello` fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja4_fingerprint: Option<String>,
    /// Container identity resolved from the event's `cgroup_id` (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerIdentity>,
}

/// Container provenance surfaced on an alert. `kind` is `container` for a
/// resolved container and `host` for a host-namespace process; the Docker /
/// Kubernetes fields are populated only when an enricher attached metadata.
#[derive(Serialize, ToSchema)]
pub struct ContainerIdentity {
    /// `container` or `host`.
    pub kind: String,
    /// Detected runtime (docker, containerd, crio, podman, unknown).
    pub runtime: String,
    /// Container ID (empty for host).
    pub id: String,
    /// cgroup path the resolver matched.
    pub cgroup_path: String,
    /// Kubernetes namespace (only when a k8s enricher attached metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Kubernetes pod name (only when a k8s enricher attached metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// Kubernetes container name (only when a k8s enricher attached metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct FalsePositiveResponse {
    pub alert_id: String,
    pub marked: bool,
}

// ── Constants ───────────────────────────────────────────────────────

const DEFAULT_LIMIT: usize = 100;
const MAX_LIMIT: usize = 1000;
/// Cadence of the `:keepalive` SSE comment. Conservative enough to keep
/// idle proxies (NGINX `proxy_read_timeout` defaults to 60 s) from closing
/// the connection while still leaving headroom for a missed tick.
const SSE_KEEPALIVE_SECS: u64 = 15;

// ── Helpers ─────────────────────────────────────────────────────────

fn parse_severity(s: &str) -> Option<Severity> {
    parse_severity_domain(s)
}

fn severity_label(s: Severity) -> &'static str {
    match s {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// Build the alert's [`ContainerIdentity`] DTO from the domain container
/// context. Returns `None` for a host-namespace process (nothing to surface)
/// and folds any Kubernetes enricher metadata into the namespace/pod fields.
fn container_identity(
    info: Option<&domain::container::entity::ContainerInfo>,
    metadata: Option<&domain::container::entity::ContainerMetadata>,
) -> Option<ContainerIdentity> {
    use domain::container::entity::{ContainerInfo, ContainerMetadata};

    let info = info?;
    let ContainerInfo::Container {
        container_id,
        runtime,
        cgroup_path,
        ..
    } = info
    else {
        return None;
    };

    let (namespace, pod, container_name) = match metadata {
        Some(ContainerMetadata::Kubernetes(k)) => (
            Some(k.namespace.clone()),
            Some(k.pod_name.clone()),
            Some(k.container_name.clone()),
        ),
        _ => (None, None, None),
    };

    Some(ContainerIdentity {
        kind: "container".to_string(),
        runtime: runtime.to_string(),
        id: container_id.clone(),
        cgroup_path: cgroup_path.clone(),
        namespace,
        pod,
        container_name,
    })
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/alerts` — query stored alerts with optional filters.
#[utoipa::path(
    get, path = "/api/v1/alerts",
    tag = "Alerts",
    params(AlertQueryParams),
    responses(
        (status = 200, description = "Paginated alerts", body = AlertListResponse),
        (status = 503, description = "Alert store not configured", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AlertQueryParams>,
) -> Result<Json<AlertListResponse>, ApiError> {
    let store = state
        .alert_store
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert store not configured".to_string(),
        })?;

    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);

    let min_severity = params.min_severity.as_deref().and_then(parse_severity);

    let query = AlertQuery {
        from_ns: params.from,
        to_ns: params.to,
        component: params.component,
        min_severity,
        rule_id: params.rule_id,
        false_positive: params.false_positive,
        tactic: params.tactic,
        technique: params.technique,
        limit,
        offset,
    };

    let total = store.alert_count().map_err(|e| ApiError::Internal {
        message: format!("alert count failed: {e}"),
    })?;

    let alerts = store.query_alerts(&query).map_err(|e| ApiError::Internal {
        message: format!("alert query failed: {e}"),
    })?;

    let response_alerts: Vec<AlertResponse> = alerts
        .into_iter()
        .map(|a| AlertResponse {
            id: a.id,
            timestamp_ns: a.timestamp_ns,
            component: a.component,
            severity: severity_label(a.severity).to_string(),
            rule_id: a.rule_id.0,
            action: a.action.as_str().to_string(),
            src_addr: a.src_addr.to_vec(),
            dst_addr: a.dst_addr.to_vec(),
            src_port: a.src_port,
            dst_port: a.dst_port,
            protocol: a.protocol,
            is_ipv6: a.is_ipv6,
            message: a.message,
            false_positive: a.false_positive,
            src_domain: a.src_domain,
            dst_domain: a.dst_domain,
            src_domain_score: a.src_domain_score,
            dst_domain_score: a.dst_domain_score,
            src_geo: a.src_geo,
            dst_geo: a.dst_geo,
            confidence: a.confidence,
            threat_type: a.threat_type,
            data_type: a.data_type,
            pid: a.pid,
            tgid: a.tgid,
            direction: a.direction,
            matched_domain: a.matched_domain,
            attack_type: a.attack_type,
            peak_pps: a.peak_pps,
            current_pps: a.current_pps,
            mitigation_status: a.mitigation_status,
            total_packets: a.total_packets,
            mitre_technique_id: a.mitre_attack.as_ref().map(|m| m.technique_id.clone()),
            mitre_technique_name: a.mitre_attack.as_ref().map(|m| m.technique_name.clone()),
            mitre_tactic: a.mitre_attack.map(|m| m.tactic),
            ja4_fingerprint: a.ja4_fingerprint,
            container: container_identity(a.container.as_ref(), a.container_metadata.as_ref()),
        })
        .collect();

    Ok(Json(AlertListResponse {
        alerts: response_alerts,
        total,
        limit,
        offset,
    }))
}

/// `POST /api/v1/alerts/{id}/false-positive` — mark an alert as false positive.
#[utoipa::path(
    post, path = "/api/v1/alerts/{id}/false-positive",
    tag = "Alerts",
    params(("id" = String, Path, description = "Alert identifier")),
    responses(
        (status = 200, description = "Alert marked as false positive", body = FalsePositiveResponse),
        (status = 404, description = "Alert not found", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn mark_false_positive(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<Json<FalsePositiveResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let store = state
        .alert_store
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert store not configured".to_string(),
        })?;

    // Fetch the alert first to get component and rule_id for the metric.
    let alert = store.get_alert(&id).map_err(|e| ApiError::Internal {
        message: format!("alert lookup failed: {e}"),
    })?;

    let alert = alert.ok_or(ApiError::NotFound {
        code: "ALERT_NOT_FOUND",
        message: format!("alert {id} not found"),
    })?;

    if alert.false_positive {
        // Already marked — return idempotent success.
        return Ok(Json(FalsePositiveResponse {
            alert_id: id,
            marked: true,
        }));
    }

    let marked = store
        .mark_false_positive(&id)
        .map_err(|e| ApiError::Internal {
            message: format!("mark false positive failed: {e}"),
        })?;

    if marked {
        // Increment FP metric.
        state
            .metrics
            .record_false_positive(&alert.component, &alert.rule_id.0);

        // Record audit entry for the FP marking.
        state.audit_service.record_security_decision(
            AuditComponent::parse_name(&alert.component),
            AuditAction::FalsePositive,
            alert.timestamp_ns,
            alert.src_addr,
            alert.dst_addr,
            alert.is_ipv6,
            alert.src_port,
            alert.dst_port,
            alert.protocol,
            &alert.rule_id.0,
            &format!("alert {id} marked as false positive"),
        );
    }

    Ok(Json(FalsePositiveResponse {
        alert_id: id,
        marked,
    }))
}

// ── SSE stream contract ─────────────────────────────────────────────

/// Query-string filters accepted by `GET /api/v1/alerts/stream`.
///
/// All fields are optional. A missing field means "do not filter on
/// this dimension". Tenant scoping is an Enterprise-only concern and
/// is not exposed by the OSS endpoint.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct StreamFilters {
    /// Minimum severity to receive (`low`, `medium`, `high`, `critical`).
    pub severity_min: Option<String>,
    /// Component to receive (case-insensitive exact match).
    pub component: Option<String>,
    /// MITRE ATT&CK tactic (kebab-case, case-insensitive).
    pub mitre_tactic: Option<String>,
}

impl StreamFilters {
    fn into_filter(self) -> Result<AlertFilter, ApiError> {
        AlertFilter::compile(
            self.severity_min.as_deref(),
            self.component,
            self.mitre_tactic,
        )
        .map_err(|e| match e {
            FilterError::InvalidSeverity { value } => ApiError::BadRequest {
                code: "INVALID_SEVERITY",
                message: format!(
                    "severity_min must be one of low|medium|high|critical, got {value:?}"
                ),
            },
        })
    }
}

/// RAII guard that bumps the `alerts_sse_subscribers` gauge on
/// construction and decrements it on drop.
struct SubscriberGuard {
    metrics: Arc<dyn MetricsPort>,
    counter: Arc<AtomicI64>,
}

impl SubscriberGuard {
    fn new(metrics: Arc<dyn MetricsPort>, counter: Arc<AtomicI64>) -> Self {
        let new = counter.fetch_add(1, Ordering::Relaxed) + 1;
        metrics.set_alerts_sse_subscribers(new);
        Self { metrics, counter }
    }
}

impl Drop for SubscriberGuard {
    fn drop(&mut self) {
        let new = self.counter.fetch_sub(1, Ordering::Relaxed) - 1;
        self.metrics.set_alerts_sse_subscribers(new.max(0));
    }
}

/// Stream wrapper that ties a [`SubscriberGuard`] to the underlying SSE
/// stream lifetime: the guard drops when the client disconnects.
struct GuardedSseStream<S> {
    inner: S,
    _guard: SubscriberGuard,
}

impl<S: Stream<Item = Result<Event, Infallible>> + Unpin> Stream for GuardedSseStream<S> {
    type Item = Result<Event, Infallible>;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }
}

/// Process-wide live subscriber counter, surfaced via the
/// `ebpfsentinel_alerts_sse_subscribers` Prometheus gauge.
fn subscriber_counter() -> Arc<AtomicI64> {
    use std::sync::OnceLock;
    static COUNTER: OnceLock<Arc<AtomicI64>> = OnceLock::new();
    Arc::clone(COUNTER.get_or_init(|| Arc::new(AtomicI64::new(0))))
}

/// Render an alert as an SSE event (`id:`, `event: alert`, `data: <json>`).
fn alert_to_event(alert: &Alert) -> Event {
    let json = serde_json::to_string(alert).unwrap_or_else(|_| "{}".to_string());
    Event::default()
        .id(alert.id.clone())
        .event("alert")
        .data(json)
}

/// Read the `Last-Event-ID` HTTP header per the SSE reconnection
/// contract. Empty values are treated as absent.
fn last_event_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

/// `GET /api/v1/alerts/stream` — Server-Sent Events live alert feed.
///
/// Server-side filtering happens on every alert before it is forwarded.
/// Reconnects can pass `Last-Event-ID` to backfill missed alerts from
/// the in-memory replay buffer (≤ 5 000 events). Lagged subscribers
/// silently skip the gap; clients should refetch via
/// `GET /api/v1/alerts` to backfill in that case.
#[utoipa::path(
    get, path = "/api/v1/alerts/stream",
    tag = "Alerts",
    params(StreamFilters),
    responses(
        (
            status = 200,
            description = "SSE stream of `event: alert` frames; `:keepalive` every 15 s",
            content_type = "text/event-stream",
        ),
        (status = 400, description = "Invalid filter parameter", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 503, description = "Alert stream not enabled", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn stream_alerts(
    State(state): State<Arc<AppState>>,
    Query(filters): Query<StreamFilters>,
    headers: HeaderMap,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let tx = state
        .alert_stream_tx
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert stream not enabled".to_string(),
        })?;
    let filter = filters.into_filter()?;
    let resume_from = last_event_id(&headers);

    // Snapshot first, then subscribe: events between the snapshot and the
    // subscribe instant are still delivered because the broadcast channel
    // is fed AFTER the replay buffer (see `AlertPipeline::push_replay`).
    let replay = state
        .alert_replay_buffer
        .as_ref()
        .map(|buf| buf.snapshot_after(resume_from.as_deref()))
        .unwrap_or_default();
    let rx = tx.subscribe();

    let metrics: Arc<dyn MetricsPort> = Arc::clone(&state.metrics) as Arc<dyn MetricsPort>;
    let guard = SubscriberGuard::new(metrics, subscriber_counter());

    let replay_filter = filter.clone();
    let replay_stream = tokio_stream::iter(
        replay
            .into_iter()
            .filter(move |a| replay_filter.matches(a))
            .map(|a| Ok::<_, Infallible>(alert_to_event(&a))),
    );

    let live_filter = filter;
    let live_stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(alert) if live_filter.matches(&alert) => Some(Ok(alert_to_event(&alert))),
        Ok(_) | Err(_) => None,
    });

    let combined = replay_stream.chain(live_stream);

    let stream = GuardedSseStream {
        inner: combined,
        _guard: guard,
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(SSE_KEEPALIVE_SECS))
            .text("keepalive"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_response_serialization() {
        let resp = AlertResponse {
            id: "test-001".to_string(),
            timestamp_ns: 1_000_000_000,
            component: "ids".to_string(),
            severity: "high".to_string(),
            rule_id: "ids-001".to_string(),
            action: "alert".to_string(),
            src_addr: vec![0xC0A8_0001, 0, 0, 0],
            dst_addr: vec![0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            is_ipv6: false,
            message: "test alert".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: Some("evil.com".to_string()),
            src_domain_score: None,
            dst_domain_score: Some(0.85),
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
            mitre_technique_id: None,
            mitre_technique_name: None,
            mitre_tactic: None,
            ja4_fingerprint: None,
            container: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "test-001");
        assert_eq!(json["component"], "ids");
        assert_eq!(json["severity"], "high");
        assert!(!json["is_ipv6"].as_bool().unwrap());
        assert_eq!(json["src_addr"][0], 0xC0A8_0001u32);
        assert!(!json["false_positive"].as_bool().unwrap());
        // Domain fields: None → absent (skip_serializing_if), Some → present
        assert!(json.get("src_domain").is_none());
        assert_eq!(json["dst_domain"], "evil.com");
        assert!((json["dst_domain_score"].as_f64().unwrap() - 0.85).abs() < 0.01);
        // Domain-specific fields absent when None
        assert!(json.get("confidence").is_none());
        assert!(json.get("attack_type").is_none());
    }

    #[test]
    fn false_positive_response_serialization() {
        let resp = FalsePositiveResponse {
            alert_id: "test-001".to_string(),
            marked: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["alert_id"], "test-001");
        assert!(json["marked"].as_bool().unwrap());
    }

    #[test]
    fn alert_list_response_serialization() {
        let resp = AlertListResponse {
            alerts: vec![],
            total: 42,
            limit: 100,
            offset: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 42);
        assert_eq!(json["limit"], 100);
        assert!(json["alerts"].as_array().unwrap().is_empty());
    }

    #[test]
    fn query_params_deserialize_defaults() {
        let params: AlertQueryParams = serde_json::from_str("{}").unwrap();
        assert!(params.component.is_none());
        assert!(params.min_severity.is_none());
        assert!(params.rule_id.is_none());
        assert!(params.false_positive.is_none());
        assert!(params.limit.is_none());
        assert!(params.offset.is_none());
    }

    #[test]
    fn query_params_deserialize_with_values() {
        let json = r#"{
            "component": "ids",
            "min_severity": "high",
            "rule_id": "ids-001",
            "false_positive": true,
            "limit": 50,
            "offset": 10
        }"#;
        let params: AlertQueryParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.component.as_deref(), Some("ids"));
        assert_eq!(params.min_severity.as_deref(), Some("high"));
        assert_eq!(params.rule_id.as_deref(), Some("ids-001"));
        assert_eq!(params.false_positive, Some(true));
        assert_eq!(params.limit, Some(50));
        assert_eq!(params.offset, Some(10));
    }

    #[test]
    fn parse_severity_values() {
        assert_eq!(parse_severity("low"), Some(Severity::Low));
        assert_eq!(parse_severity("medium"), Some(Severity::Medium));
        assert_eq!(parse_severity("HIGH"), Some(Severity::High));
        assert_eq!(parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("unknown"), None);
        assert_eq!(parse_severity(""), None);
    }
}
