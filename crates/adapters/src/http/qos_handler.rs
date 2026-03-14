use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::qos::entity::{QosClassifier, QosDirection, QosMatchRule, QosPipe, QosQueue};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;
use super::validation::{MAX_ID_LENGTH, MAX_SHORT_STRING_LENGTH, validate_string_length};

// ── Request / Response DTOs ─────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct QosStatusResponse {
    pub enabled: bool,
    pub scheduler: String,
    pub pipe_count: usize,
    pub queue_count: usize,
    pub classifier_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct QosPipeResponse {
    pub id: String,
    pub rate_bps: u64,
    pub burst_bytes: u64,
}

#[derive(Serialize, ToSchema)]
pub struct QosQueueResponse {
    pub id: String,
    pub pipe_id: String,
    pub weight: u32,
}

#[derive(Serialize, ToSchema)]
pub struct QosClassifierResponse {
    pub id: String,
    pub queue_id: String,
    pub direction: String,
    pub priority: u32,
    pub match_rule: QosMatchRuleResponse,
}

#[derive(Serialize, ToSchema)]
pub struct QosMatchRuleResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub dscp: u8,
    pub vlan_id: u16,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateQosPipeRequest {
    pub id: String,
    pub rate_bps: u64,
    #[serde(default)]
    pub burst_bytes: u64,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateQosQueueRequest {
    pub id: String,
    pub pipe_id: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    50
}

#[derive(Deserialize, ToSchema)]
pub struct CreateQosClassifierRequest {
    pub id: String,
    pub queue_id: String,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default = "default_direction")]
    pub direction: String,
    #[serde(default)]
    pub match_rule: Option<CreateQosMatchRuleRequest>,
}

fn default_priority() -> u32 {
    100
}

fn default_direction() -> String {
    "egress".to_string()
}

#[derive(Deserialize, ToSchema)]
pub struct CreateQosMatchRuleRequest {
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub protocol: u8,
    #[serde(default)]
    pub dscp: u8,
    #[serde(default)]
    pub vlan_id: u16,
}

// ── Response builders ───────────────────────────────────────────────

impl QosPipeResponse {
    fn from_domain(pipe: &QosPipe) -> Self {
        Self {
            id: pipe.id.clone(),
            rate_bps: pipe.rate_bps,
            burst_bytes: pipe.burst_bytes,
        }
    }
}

impl QosQueueResponse {
    fn from_domain(queue: &QosQueue) -> Self {
        Self {
            id: queue.id.clone(),
            pipe_id: queue.pipe_id.clone(),
            weight: u32::from(queue.weight),
        }
    }
}

impl QosClassifierResponse {
    fn from_domain(cls: &QosClassifier) -> Self {
        Self {
            id: cls.id.clone(),
            queue_id: cls.queue_id.clone(),
            direction: cls.direction.as_str().to_string(),
            priority: cls.priority,
            match_rule: QosMatchRuleResponse {
                src_ip: cls.match_rule.src_ip.clone(),
                dst_ip: cls.match_rule.dst_ip.clone(),
                src_port: cls.match_rule.src_port,
                dst_port: cls.match_rule.dst_port,
                protocol: cls.match_rule.protocol,
                dscp: cls.match_rule.dscp,
                vlan_id: cls.match_rule.vlan_id,
            },
        }
    }
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/qos/status` -- `QoS` service status.
#[utoipa::path(
    get, path = "/api/v1/qos/status",
    tag = "QoS",
    responses((status = 200, description = "QoS status", body = QosStatusResponse))
)]
pub async fn get_qos_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<QosStatusResponse>, ApiError> {
    let svc = state.qos_service()?;
    let svc = svc.read().await;
    Ok(Json(QosStatusResponse {
        enabled: svc.enabled(),
        scheduler: svc.scheduler().as_str().to_string(),
        pipe_count: svc.pipes().len(),
        queue_count: svc.queues().len(),
        classifier_count: svc.classifiers().len(),
    }))
}

/// `GET /api/v1/qos/pipes` -- list all `QoS` pipes.
#[utoipa::path(
    get, path = "/api/v1/qos/pipes",
    tag = "QoS",
    responses((status = 200, description = "List of QoS pipes", body = Vec<QosPipeResponse>))
)]
pub async fn list_qos_pipes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<QosPipeResponse>>, ApiError> {
    let svc = state.qos_service()?;
    let svc = svc.read().await;
    let pipes: Vec<QosPipeResponse> = svc
        .pipes()
        .iter()
        .map(QosPipeResponse::from_domain)
        .collect();
    Ok(Json(pipes))
}

/// `POST /api/v1/qos/pipes` -- create a new `QoS` pipe.
#[utoipa::path(
    post, path = "/api/v1/qos/pipes",
    tag = "QoS",
    request_body = CreateQosPipeRequest,
    responses(
        (status = 201, description = "Pipe created", body = QosPipeResponse),
        (status = 400, description = "Validation error", body = ErrorBody),
        (status = 409, description = "Duplicate pipe", body = ErrorBody),
    )
)]
pub async fn create_qos_pipe(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateQosPipeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    validate_string_length("id", &req.id, MAX_ID_LENGTH)?;

    let pipe = QosPipe {
        id: req.id,
        rate_bps: req.rate_bps,
        burst_bytes: req.burst_bytes,
        delay_ms: 0,
        loss_pct: 0.0,
        priority: 0,
        direction: QosDirection::Egress,
        enabled: true,
        group_mask: 0,
    };

    let svc = state.qos_service()?;
    let mut svc = svc.write().await;
    svc.add_pipe(pipe.clone())?;
    drop(svc);

    tracing::info!(pipe_id = %pipe.id, "qos pipe created via API");

    Ok((
        StatusCode::CREATED,
        Json(QosPipeResponse::from_domain(&pipe)),
    ))
}

/// `DELETE /api/v1/qos/pipes/{id}` -- delete a `QoS` pipe.
#[utoipa::path(
    delete, path = "/api/v1/qos/pipes/{id}",
    tag = "QoS",
    params(("id" = String, Path, description = "Pipe identifier")),
    responses(
        (status = 204, description = "Pipe deleted"),
        (status = 404, description = "Pipe not found", body = ErrorBody),
    )
)]
pub async fn delete_qos_pipe(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let svc = state.qos_service()?;
    let mut svc = svc.write().await;
    svc.remove_pipe(&id)?;
    drop(svc);

    tracing::info!(pipe_id = %id, "qos pipe deleted via API");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/qos/queues` -- list all `QoS` queues.
#[utoipa::path(
    get, path = "/api/v1/qos/queues",
    tag = "QoS",
    responses((status = 200, description = "List of QoS queues", body = Vec<QosQueueResponse>))
)]
pub async fn list_qos_queues(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<QosQueueResponse>>, ApiError> {
    let svc = state.qos_service()?;
    let svc = svc.read().await;
    let queues: Vec<QosQueueResponse> = svc
        .queues()
        .iter()
        .map(QosQueueResponse::from_domain)
        .collect();
    Ok(Json(queues))
}

/// `POST /api/v1/qos/queues` -- create a new `QoS` queue.
#[utoipa::path(
    post, path = "/api/v1/qos/queues",
    tag = "QoS",
    request_body = CreateQosQueueRequest,
    responses(
        (status = 201, description = "Queue created", body = QosQueueResponse),
        (status = 400, description = "Validation error", body = ErrorBody),
        (status = 409, description = "Duplicate queue", body = ErrorBody),
    )
)]
pub async fn create_qos_queue(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateQosQueueRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    validate_string_length("id", &req.id, MAX_ID_LENGTH)?;
    validate_string_length("pipe_id", &req.pipe_id, MAX_ID_LENGTH)?;

    let queue = QosQueue {
        id: req.id,
        pipe_id: req.pipe_id,
        weight: u16::try_from(req.weight.min(u32::from(u16::MAX))).unwrap_or(u16::MAX),
        enabled: true,
    };

    let svc = state.qos_service()?;
    let mut svc = svc.write().await;
    svc.add_queue(queue.clone())?;
    drop(svc);

    tracing::info!(queue_id = %queue.id, "qos queue created via API");

    Ok((
        StatusCode::CREATED,
        Json(QosQueueResponse::from_domain(&queue)),
    ))
}

/// `DELETE /api/v1/qos/queues/{id}` -- delete a `QoS` queue.
#[utoipa::path(
    delete, path = "/api/v1/qos/queues/{id}",
    tag = "QoS",
    params(("id" = String, Path, description = "Queue identifier")),
    responses(
        (status = 204, description = "Queue deleted"),
        (status = 404, description = "Queue not found", body = ErrorBody),
    )
)]
pub async fn delete_qos_queue(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let svc = state.qos_service()?;
    let mut svc = svc.write().await;
    svc.remove_queue(&id)?;
    drop(svc);

    tracing::info!(queue_id = %id, "qos queue deleted via API");
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /api/v1/qos/classifiers` -- list all `QoS` classifiers.
#[utoipa::path(
    get, path = "/api/v1/qos/classifiers",
    tag = "QoS",
    responses((status = 200, description = "List of QoS classifiers", body = Vec<QosClassifierResponse>))
)]
pub async fn list_qos_classifiers(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<QosClassifierResponse>>, ApiError> {
    let svc = state.qos_service()?;
    let svc = svc.read().await;
    let classifiers: Vec<QosClassifierResponse> = svc
        .classifiers()
        .iter()
        .map(QosClassifierResponse::from_domain)
        .collect();
    Ok(Json(classifiers))
}

/// `POST /api/v1/qos/classifiers` -- create a new `QoS` classifier.
#[utoipa::path(
    post, path = "/api/v1/qos/classifiers",
    tag = "QoS",
    request_body = CreateQosClassifierRequest,
    responses(
        (status = 201, description = "Classifier created", body = QosClassifierResponse),
        (status = 400, description = "Validation error", body = ErrorBody),
        (status = 409, description = "Duplicate classifier", body = ErrorBody),
    )
)]
pub async fn create_qos_classifier(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateQosClassifierRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    validate_string_length("id", &req.id, MAX_ID_LENGTH)?;
    validate_string_length("queue_id", &req.queue_id, MAX_ID_LENGTH)?;
    validate_string_length("direction", &req.direction, MAX_SHORT_STRING_LENGTH)?;

    let direction = match req.direction.to_lowercase().as_str() {
        "ingress" | "in" => QosDirection::Ingress,
        "egress" | "out" => QosDirection::Egress,
        "both" | "all" => QosDirection::Both,
        _ => {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!(
                    "invalid direction '{}': expected ingress, egress, or both",
                    req.direction
                ),
            });
        }
    };

    let match_rule = if let Some(mr) = req.match_rule {
        QosMatchRule {
            src_ip: mr.src_ip,
            dst_ip: mr.dst_ip,
            src_port: mr.src_port,
            dst_port: mr.dst_port,
            protocol: mr.protocol,
            dscp: mr.dscp,
            vlan_id: mr.vlan_id,
        }
    } else {
        QosMatchRule::default()
    };

    let classifier = QosClassifier {
        id: req.id,
        queue_id: req.queue_id,
        direction,
        match_rule,
        priority: req.priority,
        group_mask: 0,
    };

    let svc = state.qos_service()?;
    let mut svc = svc.write().await;
    svc.add_classifier(classifier.clone())?;
    drop(svc);

    tracing::info!(classifier_id = %classifier.id, "qos classifier created via API");

    Ok((
        StatusCode::CREATED,
        Json(QosClassifierResponse::from_domain(&classifier)),
    ))
}

/// `DELETE /api/v1/qos/classifiers/{id}` -- delete a `QoS` classifier.
#[utoipa::path(
    delete, path = "/api/v1/qos/classifiers/{id}",
    tag = "QoS",
    params(("id" = String, Path, description = "Classifier identifier")),
    responses(
        (status = 204, description = "Classifier deleted"),
        (status = 404, description = "Classifier not found", body = ErrorBody),
    )
)]
pub async fn delete_qos_classifier(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let svc = state.qos_service()?;
    let mut svc = svc.write().await;
    svc.remove_classifier(&id)?;
    drop(svc);

    tracing::info!(classifier_id = %id, "qos classifier deleted via API");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_response_from_domain() {
        let pipe = QosPipe {
            id: "p-1".to_string(),
            rate_bps: 1_000_000,
            burst_bytes: 125_000,
            delay_ms: 0,
            loss_pct: 0.0,
            priority: 0,
            direction: QosDirection::Egress,
            enabled: true,
            group_mask: 0,
        };
        let resp = QosPipeResponse::from_domain(&pipe);
        assert_eq!(resp.id, "p-1");
        assert_eq!(resp.rate_bps, 1_000_000);
        assert_eq!(resp.burst_bytes, 125_000);
    }

    #[test]
    fn queue_response_from_domain() {
        let queue = QosQueue {
            id: "q-1".to_string(),
            pipe_id: "p-1".to_string(),
            weight: 50,
            enabled: true,
        };
        let resp = QosQueueResponse::from_domain(&queue);
        assert_eq!(resp.id, "q-1");
        assert_eq!(resp.pipe_id, "p-1");
        assert_eq!(resp.weight, 50);
    }

    #[test]
    fn classifier_response_from_domain() {
        let cls = QosClassifier {
            id: "c-1".to_string(),
            queue_id: "q-1".to_string(),
            direction: QosDirection::Egress,
            match_rule: QosMatchRule {
                src_ip: Some("10.0.0.0/8".to_string()),
                dst_ip: None,
                src_port: 0,
                dst_port: 80,
                protocol: 6,
                dscp: 0,
                vlan_id: 0,
            },
            priority: 100,
            group_mask: 0,
        };
        let resp = QosClassifierResponse::from_domain(&cls);
        assert_eq!(resp.id, "c-1");
        assert_eq!(resp.queue_id, "q-1");
        assert_eq!(resp.direction, "egress");
        assert_eq!(resp.priority, 100);
        assert_eq!(resp.match_rule.src_ip.as_deref(), Some("10.0.0.0/8"));
        assert!(resp.match_rule.dst_ip.is_none());
        assert_eq!(resp.match_rule.dst_port, 80);
        assert_eq!(resp.match_rule.protocol, 6);
    }

    #[test]
    fn pipe_response_serialization() {
        let resp = QosPipeResponse {
            id: "p-1".to_string(),
            rate_bps: 1_000_000,
            burst_bytes: 125_000,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "p-1");
        assert_eq!(json["rate_bps"], 1_000_000);
    }

    #[test]
    fn queue_response_serialization() {
        let resp = QosQueueResponse {
            id: "q-1".to_string(),
            pipe_id: "p-1".to_string(),
            weight: 50,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "q-1");
        assert_eq!(json["pipe_id"], "p-1");
        assert_eq!(json["weight"], 50);
    }

    #[test]
    fn classifier_response_serialization() {
        let resp = QosClassifierResponse {
            id: "c-1".to_string(),
            queue_id: "q-1".to_string(),
            direction: "egress".to_string(),
            priority: 100,
            match_rule: QosMatchRuleResponse {
                src_ip: None,
                dst_ip: None,
                src_port: 0,
                dst_port: 0,
                protocol: 0,
                dscp: 0,
                vlan_id: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "c-1");
        assert_eq!(json["direction"], "egress");
        // src_ip/dst_ip should be absent (skip_serializing_if)
        assert!(json.get("match_rule").unwrap().get("src_ip").is_none());
    }

    #[test]
    fn status_response_serialization() {
        let resp = QosStatusResponse {
            enabled: true,
            scheduler: "fifo".to_string(),
            pipe_count: 2,
            queue_count: 4,
            classifier_count: 8,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["scheduler"], "fifo");
        assert_eq!(json["pipe_count"], 2);
        assert_eq!(json["queue_count"], 4);
        assert_eq!(json["classifier_count"], 8);
    }
}
