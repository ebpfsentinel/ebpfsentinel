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
use domain::alert::triage::{
    AlertNote, AlertStatus, AlertTriage, AssigneeChange, MAX_BULK, TriageChange,
};
use domain::audit::entity::{AuditAction, AuditComponent};
use domain::auth::entity::JwtClaims;
use domain::common::entity::Severity;
use ports::secondary::alert_store::AlertTriageStore;
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
    /// Filter by triage status ("open", "acknowledged", "investigating",
    /// "resolved"). An alert nobody touched is open.
    pub status: Option<String>,
    /// Filter by assignee (exact match).
    pub assignee: Option<String>,
    /// `true` keeps only alerts nobody holds.
    pub unassigned: Option<bool>,
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
    /// Where the alert stands in the queue; `open` until somebody moves it.
    pub status: String,
    /// Who holds it, if anybody.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// What people wrote on it, oldest first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<AlertNoteResponse>,
    /// When the triage last changed (nanoseconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triage_updated_ns: Option<u64>,
}

/// One note on an alert as the API writes it.
#[derive(Serialize, ToSchema)]
pub struct AlertNoteResponse {
    /// Who the caller said wrote it.
    pub author: String,
    /// The identity the agent authenticated the write under.
    pub via: String,
    pub at_ns: u64,
    pub text: String,
}

/// `PATCH /api/v1/alerts/{id}/triage` body. A field left out stays as it
/// was; `assignee: null` takes the alert off whoever held it.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct TriageRequest {
    /// "open", "acknowledged", "investigating" or "resolved".
    pub status: Option<String>,
    #[serde(default, deserialize_with = "present_or_null")]
    #[schema(value_type = Option<String>, nullable)]
    pub assignee: AssigneeChange,
    /// A note to append.
    pub note: Option<String>,
    /// Who is writing, when a console writes on a person's behalf.
    /// Defaults to the authenticated identity.
    pub author: Option<String>,
}

/// `POST /api/v1/alerts/triage` body: one change applied to many alerts.
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct BulkTriageRequest {
    pub ids: Vec<String>,
    pub status: Option<String>,
    #[serde(default, deserialize_with = "present_or_null")]
    #[schema(value_type = Option<String>, nullable)]
    pub assignee: AssigneeChange,
    pub note: Option<String>,
    pub author: Option<String>,
}

/// The triage of one alert after a change.
#[derive(Serialize, ToSchema)]
pub struct TriageResponse {
    pub alert_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    pub notes: Vec<AlertNoteResponse>,
    pub updated_ns: u64,
}

/// What a bulk change did.
#[derive(Serialize, ToSchema)]
pub struct BulkTriageResponse {
    /// Alerts the change was applied to.
    pub updated: Vec<String>,
    /// Alerts the store no longer holds.
    pub missing: Vec<String>,
}

/// Tell a field sent as `null` apart from a field left out: absent keeps
/// (the `default`), `null` clears, a name hands the alert over.
fn present_or_null<'de, D>(de: D) -> Result<AssigneeChange, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(de)?.map_or(AssigneeChange::Clear, AssigneeChange::Set))
}

/// Container provenance surfaced on an alert.
///
/// The field is absent altogether for a host-namespace process, so `kind` is
/// always `container` where the object exists at all. It is kept because a
/// reader that has to tell a container apart from a host should be told so by
/// a value rather than by an absence it has to interpret.
///
/// The Kubernetes and the Docker halves are filled by whichever enricher
/// attached metadata, and never both, since the pipeline keeps the first
/// enricher that answered.
#[derive(Serialize, ToSchema)]
pub struct ContainerIdentity {
    /// Always `container`: a host-namespace process carries no identity.
    pub kind: String,
    /// Detected runtime (docker, containerd, crio, podman, unknown).
    pub runtime: String,
    /// Container ID.
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
    /// Container name (only when the Docker enricher attached metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Image tag (only when the Docker enricher attached metadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
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
/// and folds whichever enricher answered into the fields that enricher fills.
///
/// Both halves are carried, because a Docker host pays a daemon round-trip per
/// container and had nothing to show for it here: an alert naming a cgroup id
/// the operator has to look up elsewhere is a worse reading than one naming
/// the image it came from.
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
    let (name, image) = match metadata {
        Some(ContainerMetadata::Docker(d)) => (Some(d.name.clone()), Some(d.image.clone())),
        _ => (None, None),
    };

    Some(ContainerIdentity {
        kind: "container".to_string(),
        runtime: runtime.to_string(),
        id: container_id.clone(),
        cgroup_path: cgroup_path.clone(),
        namespace,
        pod,
        container_name,
        name,
        image,
    })
}

// ── Handlers ────────────────────────────────────────────────────────

/// One stored alert as the API writes it.
///
/// Shared by the list and the single-alert reading so the two can never
/// describe the same alert differently: a console opening a row out of the
/// queue has to be shown the queue's own fields. It is public because the
/// enterprise agent serves this same route off the same store, and a second
/// mapping there would answer `Severity::High` where this one answers
/// `"high"` - one queue reading two ways depending on which edition
/// answered.
pub fn alert_response(a: Alert) -> AlertResponse {
    triaged_response(a, None)
}

fn note_response(n: &AlertNote) -> AlertNoteResponse {
    AlertNoteResponse {
        author: n.author.clone(),
        via: n.via.clone(),
        at_ns: n.at_ns,
        text: n.text.clone(),
    }
}

/// One stored alert with what operators decided about it.
pub fn triaged_response(a: Alert, triage: Option<&AlertTriage>) -> AlertResponse {
    let triage = triage.filter(|t| !t.is_untouched());
    AlertResponse {
        status: triage
            .map_or(AlertStatus::Open, |t| t.status)
            .as_str()
            .to_string(),
        assignee: triage.and_then(|t| t.assignee.clone()),
        notes: triage.map_or_else(Vec::new, |t| t.notes.iter().map(note_response).collect()),
        triage_updated_ns: triage.map(|t| t.updated_ns),
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
    }
}

/// `GET /api/v1/alerts` - query stored alerts with optional filters.
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
    let filter = TriageFilter::from_params(
        params.status.as_deref(),
        params.assignee.clone(),
        params.unassigned,
    )?;
    let triage_filtered = filter.is_some();

    let triage = match state.alert_triage.as_ref() {
        Some(t) => t.triage_all().map_err(|e| ApiError::Internal {
            message: format!("alert triage read failed: {e}"),
        })?,
        None => std::collections::HashMap::new(),
    };

    let query = AlertQuery {
        from_ns: params.from,
        to_ns: params.to,
        component: params.component,
        min_severity,
        rule_id: params.rule_id,
        false_positive: params.false_positive,
        tactic: params.tactic,
        technique: params.technique,
        // The triage lives beside the alerts, so a filter on it is applied
        // here over every match and paged afterwards.
        limit: if triage_filtered { usize::MAX } else { limit },
        offset: if triage_filtered { 0 } else { offset },
    };

    let total = store.alert_count().map_err(|e| ApiError::Internal {
        message: format!("alert count failed: {e}"),
    })?;

    let mut alerts = store.query_alerts(&query).map_err(|e| ApiError::Internal {
        message: format!("alert query failed: {e}"),
    })?;

    if let Some(filter) = &filter {
        alerts = filter.page(alerts, &triage, offset, limit);
    }

    let response_alerts: Vec<AlertResponse> = alerts
        .into_iter()
        .map(|a| {
            let t = triage.get(&a.id);
            triaged_response(a, t)
        })
        .collect();

    Ok(Json(AlertListResponse {
        alerts: response_alerts,
        total,
        limit,
        offset,
    }))
}

/// `GET /api/v1/alerts/{id}` - one stored alert by identifier.
#[utoipa::path(
    get, path = "/api/v1/alerts/{id}",
    tag = "Alerts",
    params(("id" = String, Path, description = "Alert identifier")),
    responses(
        (status = 200, description = "The stored alert", body = AlertResponse),
        (status = 404, description = "Alert not found", body = ErrorBody),
        (status = 503, description = "Alert store not configured", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_alert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<AlertResponse>, ApiError> {
    let store = state
        .alert_store
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert store not configured".to_string(),
        })?;

    let alert = store.get_alert(&id).map_err(|e| ApiError::Internal {
        message: format!("alert lookup failed: {e}"),
    })?;

    let alert = alert.ok_or(ApiError::NotFound {
        code: "ALERT_NOT_FOUND",
        message: format!("alert {id} not found"),
    })?;

    let triage = match state.alert_triage.as_ref() {
        Some(t) => t
            .triage_all()
            .map_err(|e| ApiError::Internal {
                message: format!("alert triage read failed: {e}"),
            })?
            .remove(&id),
        None => None,
    };

    Ok(Json(triaged_response(alert, triage.as_ref())))
}

/// The triage half of an alert query: which alerts a status, an assignee or
/// "nobody holds it" keeps. Shared by both editions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriageFilter {
    status: Option<AlertStatus>,
    assignee: Option<String>,
    unassigned: Option<bool>,
}

impl TriageFilter {
    /// Read the three query parameters; `None` when none was given, so a
    /// caller pages in the store as before. An unknown status is refused.
    pub fn from_params(
        status: Option<&str>,
        assignee: Option<String>,
        unassigned: Option<bool>,
    ) -> Result<Option<Self>, ApiError> {
        let status = match status {
            None => None,
            Some(word) => Some(
                AlertStatus::parse(word).ok_or_else(|| ApiError::BadRequest {
                    code: "INVALID_STATUS",
                    message: format!("unknown status {word}"),
                })?,
            ),
        };
        if status.is_none() && assignee.is_none() && unassigned.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            status,
            assignee,
            unassigned,
        }))
    }

    /// Whether an alert with this triage (none: nobody touched it) is kept.
    pub fn keeps(&self, triage: Option<&AlertTriage>) -> bool {
        let held_by = triage.and_then(|t| t.assignee.as_deref());
        self.status
            .is_none_or(|s| triage.map_or(AlertStatus::Open, |t| t.status) == s)
            && self
                .assignee
                .as_deref()
                .is_none_or(|name| held_by == Some(name))
            && self.unassigned.is_none_or(|want| held_by.is_none() == want)
    }

    /// Keep what the filter keeps out of every match, then page it: the
    /// triage lives beside the alerts, so the store cannot page for it.
    pub fn page(
        &self,
        alerts: Vec<Alert>,
        triage: &std::collections::HashMap<String, AlertTriage>,
        offset: usize,
        limit: usize,
    ) -> Vec<Alert> {
        alerts
            .into_iter()
            .filter(|a| self.keeps(triage.get(&a.id)))
            .skip(offset)
            .take(limit)
            .collect()
    }
}

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// Turn a request into a change, naming who wrote it.
fn triage_change(
    status: Option<&str>,
    assignee: AssigneeChange,
    note: Option<String>,
    author: Option<String>,
    via: &str,
) -> Result<TriageChange, ApiError> {
    let status = match status {
        None => None,
        Some(word) => Some(
            AlertStatus::parse(word).ok_or_else(|| ApiError::BadRequest {
                code: "INVALID_STATUS",
                message: format!("unknown status {word}"),
            })?,
        ),
    };
    let author = author
        .map(|a| a.trim().to_string())
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| via.to_string());
    let change = TriageChange {
        status,
        assignee,
        note: note.map(|text| AlertNote {
            author,
            via: via.to_string(),
            at_ns: 0,
            text,
        }),
    };
    change.validate().map_err(|e| ApiError::BadRequest {
        code: "INVALID_TRIAGE",
        message: e.to_string(),
    })?;
    Ok(change)
}

/// The identity a write is recorded under; `local` when the agent runs
/// without authentication.
fn principal(claims: Option<&Extension<JwtClaims>>) -> String {
    claims.map_or_else(|| "local".to_string(), |Extension(c)| c.sub.clone())
}

fn triage_detail(id: &str, change: &TriageChange) -> String {
    let mut parts = vec![format!("alert {id}")];
    if let Some(s) = change.status {
        parts.push(format!("status {}", s.as_str()));
    }
    match &change.assignee {
        AssigneeChange::Set(name) => parts.push(format!("assigned to {}", name.trim())),
        AssigneeChange::Clear => parts.push("unassigned".to_string()),
        AssigneeChange::Keep => {}
    }
    if let Some(n) = &change.note {
        parts.push(format!("note by {} via {}", n.author, n.via));
    }
    parts.join(", ")
}

fn triage_store(state: &AppState) -> Result<&Arc<dyn AlertTriageStore>, ApiError> {
    state
        .alert_triage
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "alert store not configured".to_string(),
        })
}

/// `PATCH /api/v1/alerts/{id}/triage` - change one alert's status or
/// assignee, or append a note to it.
#[utoipa::path(
    patch, path = "/api/v1/alerts/{id}/triage",
    tag = "Alerts",
    params(("id" = String, Path, description = "Alert identifier")),
    request_body = TriageRequest,
    responses(
        (status = 200, description = "The alert's triage after the change", body = TriageResponse),
        (status = 400, description = "Unknown status, empty change, or a value past its ceiling", body = ErrorBody),
        (status = 404, description = "Alert not found", body = ErrorBody),
        (status = 503, description = "Alert store not configured", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn triage_alert(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
    Json(body): Json<TriageRequest>,
) -> Result<Json<TriageResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let store = triage_store(&state)?;
    let via = principal(claims.as_ref());
    let (answer, detail) = apply_triage(store.as_ref(), id, body, &via)?;
    state
        .audit_service
        .record_config_change(AuditAction::AlertTriaged, &detail);
    Ok(Json(answer))
}

/// Apply one change to one alert, handing back the answer and the line an
/// audit trail records it under. Shared by both editions, which serve the
/// route off the same store.
pub fn apply_triage(
    store: &dyn AlertTriageStore,
    id: String,
    body: TriageRequest,
    via: &str,
) -> Result<(TriageResponse, String), ApiError> {
    let change = triage_change(
        body.status.as_deref(),
        body.assignee,
        body.note,
        body.author,
        via,
    )?;
    let triage = store
        .update_triage(&id, &change, now_ns())
        .map_err(|e| ApiError::Internal {
            message: format!("alert triage failed: {e}"),
        })?
        .ok_or(ApiError::NotFound {
            code: "ALERT_NOT_FOUND",
            message: format!("alert {id} not found"),
        })?;
    let detail = triage_detail(&id, &change);
    Ok((
        TriageResponse {
            alert_id: id,
            status: triage.status.as_str().to_string(),
            assignee: triage.assignee.clone(),
            notes: triage.notes.iter().map(note_response).collect(),
            updated_ns: triage.updated_ns,
        },
        detail,
    ))
}

/// `POST /api/v1/alerts/triage` - apply one change to many alerts.
#[utoipa::path(
    post, path = "/api/v1/alerts/triage",
    tag = "Alerts",
    request_body = BulkTriageRequest,
    responses(
        (status = 200, description = "Which alerts changed and which the store no longer holds", body = BulkTriageResponse),
        (status = 400, description = "No IDs, too many IDs, or an invalid change", body = ErrorBody),
        (status = 503, description = "Alert store not configured", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn triage_alerts(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(body): Json<BulkTriageRequest>,
) -> Result<Json<BulkTriageResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let store = triage_store(&state)?;
    let via = principal(claims.as_ref());
    let (answer, details) = apply_bulk_triage(store.as_ref(), body, &via)?;
    for detail in &details {
        state
            .audit_service
            .record_config_change(AuditAction::AlertTriaged, detail);
    }
    Ok(Json(answer))
}

/// Apply one change to many alerts, handing back the answer and one audit
/// line per alert that changed.
pub fn apply_bulk_triage(
    store: &dyn AlertTriageStore,
    body: BulkTriageRequest,
    via: &str,
) -> Result<(BulkTriageResponse, Vec<String>), ApiError> {
    if body.ids.is_empty() || body.ids.len() > MAX_BULK {
        return Err(ApiError::BadRequest {
            code: "INVALID_TRIAGE",
            message: format!("name between 1 and {MAX_BULK} alerts"),
        });
    }
    let change = triage_change(
        body.status.as_deref(),
        body.assignee,
        body.note,
        body.author,
        via,
    )?;

    let now = now_ns();
    let mut updated = Vec::new();
    let mut missing = Vec::new();
    let mut details = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for id in body.ids {
        if !seen.insert(id.clone()) {
            continue;
        }
        match store
            .update_triage(&id, &change, now)
            .map_err(|e| ApiError::Internal {
                message: format!("alert triage failed: {e}"),
            })? {
            Some(_) => {
                details.push(triage_detail(&id, &change));
                updated.push(id);
            }
            None => missing.push(id),
        }
    }
    Ok((BulkTriageResponse { updated, missing }, details))
}

/// `POST /api/v1/alerts/{id}/false-positive` - mark an alert as false positive.
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
        // Already marked - return idempotent success.
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
///
/// The frame carries the same fields the query answers, because the live
/// feed and the backlog fill one queue: serialising the entity here instead
/// writes `High` where the query writes `high`, `Block` where it writes
/// `block`, and the MITRE mapping as a nested object rather than as three
/// flat fields - so an alert that arrived live and the same alert read back
/// after a refresh would be two different rows.
fn alert_to_event(alert: &Alert) -> Event {
    let json = alert_frame_json(alert);
    Event::default()
        .id(alert.id.clone())
        .event("alert")
        .data(json)
}

/// The body of one SSE frame.
///
/// Split out of [`alert_to_event`] because `Event` hands its data back to
/// nobody, so this is the only shape a test can hold the feed to.
fn alert_frame_json(alert: &Alert) -> String {
    serde_json::to_string(&alert_response(alert.clone())).unwrap_or_else(|_| "{}".to_string())
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

/// `GET /api/v1/alerts/stream` - Server-Sent Events live alert feed.
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

    // An alert is pushed to the replay buffer *before* it is broadcast, so
    // one that lands between the snapshot above and this subscribe is
    // delivered twice: once from the replay, once live. Remember what the
    // replay already carried and drop those ids from the live stream. The
    // set is bounded by the replay buffer's capacity.
    let replayed_ids: std::collections::HashSet<String> =
        replay.iter().map(|a| a.id.clone()).collect();

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
        Ok(alert) if replayed_ids.contains(&alert.id) => None,
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

    use domain::common::entity::{DomainMode, RuleId};

    /// A row opened out of the queue is the row the queue showed: the two
    /// readings share one mapping, so a field can never be written on the
    /// list and left off the single alert.
    #[test]
    fn a_stored_alert_maps_to_what_the_queue_prints() {
        let stored = {
            let id = "alert-1";
            let component = "ids";
            Alert {
                id: id.to_string(),
                timestamp_ns: 1_000_000_000,
                component: component.to_string(),
                severity: Severity::High,
                rule_id: RuleId(format!("{component}-001")),
                action: DomainMode::Alert,
                src_addr: [0xC0A8_0001, 0, 0, 0],
                dst_addr: [0x0A00_0001, 0, 0, 0],
                src_port: 12345,
                dst_port: 80,
                protocol: 6,
                is_ipv6: false,
                message: "test alert".to_string(),
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
        };

        let resp = alert_response(stored);

        assert_eq!(resp.id, "alert-1");
        assert_eq!(resp.component, "ids");
        assert_eq!(resp.severity, "high");
        assert_eq!(resp.rule_id, "ids-001");
        assert!(!resp.false_positive);
    }

    /// The live feed carries the query's own words. Serialising the entity
    /// into the frame instead writes `High`, `Block` and a nested MITRE
    /// object, so an alert seen arriving and the same alert read back after
    /// a refresh would disagree on every one of them.
    #[test]
    fn a_frame_carries_what_the_query_carries() {
        use domain::alert::entity::{PacketAlertComponent, PacketSecurityAlert};

        let alert = Alert::from_packet_security_alert(&PacketSecurityAlert {
            component: PacketAlertComponent::Firewall,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            timestamp_ns: 1_000_000_000,
            rule_id: "fw-deny-egress".to_string(),
            action_label: "deny".to_string(),
            severity: Severity::High,
            detail: "denied by policy".to_string(),
            ja4_fingerprint: None,
            container: None,
        });

        let frame: serde_json::Value =
            serde_json::from_str(&alert_frame_json(&alert)).expect("a frame is JSON");
        let object = frame.as_object().expect("a frame is an object");

        assert_eq!(frame["severity"], "high");
        assert_eq!(frame["action"], "block");
        assert_eq!(frame["component"], "firewall");
        assert!(!object.contains_key("mitre_attack"));
        assert!(object.contains_key("mitre_technique_id"));
        // The entity's enterprise context has no room on this shape, so it
        // is absent rather than arriving as a null the screen must ignore.
        assert!(!object.contains_key("ml_anomaly_score"));
        assert!(!object.contains_key("container_metadata"));
    }

    /// A Docker host pays a daemon round-trip per container, and until this
    /// reading carried the two fields it produced, every consumer got a
    /// cgroup id and had to go and look the workload up by hand.
    #[test]
    fn a_docker_enriched_alert_names_the_image_it_came_from() {
        use domain::container::entity::{
            ContainerInfo, ContainerMetadata, ContainerRuntime, DockerMetadata,
        };

        let info = ContainerInfo::Container {
            container_id: "abcdef1234567890".to_string(),
            runtime: ContainerRuntime::Docker,
            cgroup_path: "/docker/abcdef".to_string(),
            pid: 4242,
        };
        let metadata = ContainerMetadata::Docker(DockerMetadata {
            name: "web".to_string(),
            image: "nginx:1.25".to_string(),
            labels: vec![],
            created_at: String::new(),
            status: "running".to_string(),
        });

        let identity =
            container_identity(Some(&info), Some(&metadata)).expect("a container has an identity");

        assert_eq!(identity.name.as_deref(), Some("web"));
        assert_eq!(identity.image.as_deref(), Some("nginx:1.25"));
        // The Kubernetes half stays absent rather than arriving empty: only
        // one enricher ever answers for a given alert.
        assert_eq!(identity.namespace, None);
        assert_eq!(identity.pod, None);
    }

    #[test]
    fn a_kubernetes_enriched_alert_names_the_pod_and_no_image() {
        use domain::container::entity::{
            ContainerInfo, ContainerMetadata, ContainerRuntime, KubernetesMetadata,
        };

        let info = ContainerInfo::Container {
            container_id: "abcdef1234567890".to_string(),
            runtime: ContainerRuntime::Containerd,
            cgroup_path: "/kubepods/cri-containerd-abcdef.scope".to_string(),
            pid: 4242,
        };
        let metadata = ContainerMetadata::Kubernetes(KubernetesMetadata {
            pod_name: "my-app-7b8f9".to_string(),
            namespace: "production".to_string(),
            container_name: "app".to_string(),
            labels: vec![],
            annotations: vec![],
            service_account: String::new(),
            owner_kind: None,
            owner_name: None,
            node_name: String::new(),
        });

        let identity =
            container_identity(Some(&info), Some(&metadata)).expect("a container has an identity");

        assert_eq!(identity.namespace.as_deref(), Some("production"));
        assert_eq!(identity.pod.as_deref(), Some("my-app-7b8f9"));
        assert_eq!(identity.name, None);
        assert_eq!(identity.image, None);
    }

    /// `kind` never reads `host`, because a host process produces no object
    /// at all. A reader told otherwise would write a branch nothing reaches.
    #[test]
    fn a_host_process_carries_no_container_identity() {
        use domain::container::entity::ContainerInfo;

        assert!(container_identity(Some(&ContainerInfo::Host), None).is_none());
        assert!(container_identity(None, None).is_none());
    }

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
            status: "open".to_string(),
            assignee: None,
            notes: Vec::new(),
            triage_updated_ns: None,
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
