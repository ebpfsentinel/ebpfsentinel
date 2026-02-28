use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::loadbalancer::entity::{LbAlgorithm, LbBackend, LbProtocol, LbService};
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::middleware::rbac::require_write_access;
use super::state::AppState;
use super::validation::{MAX_ID_LENGTH, MAX_SHORT_STRING_LENGTH, validate_string_length};

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct LbStatusResponse {
    pub enabled: bool,
    pub service_count: usize,
}

#[derive(Serialize)]
pub struct LbServiceResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub listen_port: u16,
    pub algorithm: String,
    pub backend_count: usize,
    pub enabled: bool,
}

impl LbServiceResponse {
    fn from_service(s: &LbService) -> Self {
        Self {
            id: s.id.0.clone(),
            name: s.name.clone(),
            protocol: s.protocol.as_str().to_string(),
            listen_port: s.listen_port,
            algorithm: s.algorithm.as_str().to_string(),
            backend_count: s.backends.len(),
            enabled: s.enabled,
        }
    }
}

#[derive(Serialize)]
pub struct LbServiceDetailResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub listen_port: u16,
    pub algorithm: String,
    pub enabled: bool,
    pub backends: Vec<LbBackendResponse>,
}

#[derive(Serialize)]
pub struct LbBackendResponse {
    pub id: String,
    pub addr: String,
    pub port: u16,
    pub weight: u32,
    pub enabled: bool,
    pub status: String,
    pub active_connections: u64,
}

// ── Request DTOs ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateLbServiceRequest {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub listen_port: u16,
    #[serde(default = "default_algorithm")]
    pub algorithm: String,
    pub backends: Vec<CreateLbBackendRequest>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct CreateLbBackendRequest {
    pub id: String,
    pub addr: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_algorithm() -> String {
    "round_robin".to_string()
}
fn default_weight() -> u32 {
    1
}
fn default_enabled() -> bool {
    true
}

// ── Handlers ──────────────────────────────────────────────────────

pub async fn lb_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<LbStatusResponse>, ApiError> {
    let lb = state
        .loadbalancer_service
        .as_ref()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "Load balancer not enabled".to_string(),
        })?;
    let svc = lb.read().await;
    Ok(Json(LbStatusResponse {
        enabled: svc.enabled(),
        service_count: svc.service_count(),
    }))
}

pub async fn list_lb_services(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<LbServiceResponse>>, ApiError> {
    let lb = state
        .loadbalancer_service
        .as_ref()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "Load balancer not enabled".to_string(),
        })?;
    let svc = lb.read().await;
    let services: Vec<LbServiceResponse> = svc
        .services()
        .iter()
        .map(|s| LbServiceResponse::from_service(s))
        .collect();
    Ok(Json(services))
}

pub async fn get_lb_service(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<LbServiceDetailResponse>, ApiError> {
    let lb = state
        .loadbalancer_service
        .as_ref()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "Load balancer not enabled".to_string(),
        })?;
    let svc = lb.read().await;
    let services = svc.services();
    let service = services
        .iter()
        .find(|s| s.id.0 == id)
        .ok_or(ApiError::NotFound {
            code: "NOT_FOUND",
            message: format!("service '{id}' not found"),
        })?;

    let backends: Vec<LbBackendResponse> = match svc.backend_states(&id) {
        Some(states) => states
            .iter()
            .map(|bs| LbBackendResponse {
                id: bs.backend.id.clone(),
                addr: bs.backend.addr.to_string(),
                port: bs.backend.port,
                weight: bs.backend.weight,
                enabled: bs.backend.enabled,
                status: bs.status.as_str().to_string(),
                active_connections: bs.active_connections,
            })
            .collect(),
        None => service
            .backends
            .iter()
            .map(|b| LbBackendResponse {
                id: b.id.clone(),
                addr: b.addr.to_string(),
                port: b.port,
                weight: b.weight,
                enabled: b.enabled,
                status: "healthy".to_string(),
                active_connections: 0,
            })
            .collect(),
    };

    Ok(Json(LbServiceDetailResponse {
        id: service.id.0.clone(),
        name: service.name.clone(),
        protocol: service.protocol.as_str().to_string(),
        listen_port: service.listen_port,
        algorithm: service.algorithm.as_str().to_string(),
        enabled: service.enabled,
        backends,
    }))
}

pub async fn create_lb_service(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateLbServiceRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }

    let service = parse_create_request(req)?;
    let rule_id = service.id.0.clone();
    let after_json = serde_json::to_string(&service).ok();

    let lb = state
        .loadbalancer_service
        .as_ref()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "Load balancer not enabled".to_string(),
        })?;
    let mut svc = lb.write().await;
    svc.add_service(service.clone())?;
    drop(svc);

    tracing::info!(rule_id = %rule_id, "LB service created via API");

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Loadbalancer,
        domain::audit::entity::AuditAction::RuleAdded,
        domain::audit::rule_change::ChangeActor::Api,
        &rule_id,
        None,
        after_json,
    );

    Ok((
        StatusCode::CREATED,
        Json(LbServiceResponse::from_service(&service)),
    ))
}

pub async fn delete_lb_service(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }

    let lb = state
        .loadbalancer_service
        .as_ref()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "Load balancer not enabled".to_string(),
        })?;

    let before_json = {
        let svc = lb.read().await;
        svc.services()
            .iter()
            .find(|s| s.id.0 == id)
            .and_then(|s| serde_json::to_string(s).ok())
    };

    let mut svc = lb.write().await;
    svc.remove_service(&domain::common::entity::RuleId(id.clone()))?;
    drop(svc);

    tracing::info!(rule_id = %id, "LB service deleted via API");

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Loadbalancer,
        domain::audit::entity::AuditAction::RuleRemoved,
        domain::audit::rule_change::ChangeActor::Api,
        &id,
        before_json,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ───────────────────────────────────────────────────────

fn parse_protocol(s: &str) -> Result<LbProtocol, ApiError> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(LbProtocol::Tcp),
        "udp" => Ok(LbProtocol::Udp),
        "tls_passthrough" | "tls" => Ok(LbProtocol::TlsPassthrough),
        _ => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid protocol '{s}': expected tcp, udp, or tls_passthrough"),
        }),
    }
}

fn parse_algorithm(s: &str) -> Result<LbAlgorithm, ApiError> {
    match s.to_lowercase().as_str() {
        "round_robin" | "roundrobin" => Ok(LbAlgorithm::RoundRobin),
        "weighted" => Ok(LbAlgorithm::Weighted),
        "ip_hash" | "iphash" => Ok(LbAlgorithm::IpHash),
        "least_conn" | "leastconn" => Ok(LbAlgorithm::LeastConn),
        _ => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!(
                "invalid algorithm '{s}': expected round_robin, weighted, ip_hash, or least_conn"
            ),
        }),
    }
}

fn parse_create_request(req: CreateLbServiceRequest) -> Result<LbService, ApiError> {
    validate_string_length("id", &req.id, MAX_ID_LENGTH)?;
    validate_string_length("name", &req.name, MAX_SHORT_STRING_LENGTH)?;
    validate_string_length("protocol", &req.protocol, MAX_SHORT_STRING_LENGTH)?;
    validate_string_length("algorithm", &req.algorithm, MAX_SHORT_STRING_LENGTH)?;

    let protocol = parse_protocol(&req.protocol)?;
    let algorithm = parse_algorithm(&req.algorithm)?;

    if req.listen_port == 0 {
        return Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: "listen_port must be > 0".to_string(),
        });
    }

    if req.backends.is_empty() {
        return Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: "at least one backend is required".to_string(),
        });
    }

    let mut backends = Vec::with_capacity(req.backends.len());
    for be in req.backends {
        validate_string_length("backend.id", &be.id, MAX_ID_LENGTH)?;
        validate_string_length("backend.addr", &be.addr, MAX_SHORT_STRING_LENGTH)?;

        let addr: std::net::IpAddr = be.addr.parse().map_err(|_| ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid backend address '{}'", be.addr),
        })?;

        if be.port == 0 {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("backend '{}' port must be > 0", be.id),
            });
        }
        if be.weight == 0 {
            return Err(ApiError::BadRequest {
                code: "VALIDATION_ERROR",
                message: format!("backend '{}' weight must be > 0", be.id),
            });
        }

        backends.push(LbBackend {
            id: be.id,
            addr,
            port: be.port,
            weight: be.weight,
            enabled: be.enabled,
        });
    }

    Ok(LbService {
        id: domain::common::entity::RuleId(req.id),
        name: req.name,
        protocol,
        listen_port: req.listen_port,
        algorithm,
        backends,
        enabled: req.enabled,
        health_check: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_create_request() {
        let req = CreateLbServiceRequest {
            id: "lb-001".to_string(),
            name: "web-service".to_string(),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            backends: vec![CreateLbBackendRequest {
                id: "be-1".to_string(),
                addr: "10.0.0.1".to_string(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
            enabled: true,
        };
        let svc = parse_create_request(req).unwrap();
        assert_eq!(svc.id.0, "lb-001");
        assert_eq!(svc.protocol, LbProtocol::Tcp);
        assert_eq!(svc.algorithm, LbAlgorithm::RoundRobin);
        assert_eq!(svc.backends.len(), 1);
    }

    #[test]
    fn parse_invalid_protocol() {
        let req = CreateLbServiceRequest {
            id: "lb-002".to_string(),
            name: "test".to_string(),
            protocol: "invalid".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            backends: vec![CreateLbBackendRequest {
                id: "be-1".to_string(),
                addr: "10.0.0.1".to_string(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_invalid_algorithm() {
        let req = CreateLbServiceRequest {
            id: "lb-003".to_string(),
            name: "test".to_string(),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "unknown".to_string(),
            backends: vec![CreateLbBackendRequest {
                id: "be-1".to_string(),
                addr: "10.0.0.1".to_string(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_zero_listen_port() {
        let req = CreateLbServiceRequest {
            id: "lb-004".to_string(),
            name: "test".to_string(),
            protocol: "tcp".to_string(),
            listen_port: 0,
            algorithm: "round_robin".to_string(),
            backends: vec![CreateLbBackendRequest {
                id: "be-1".to_string(),
                addr: "10.0.0.1".to_string(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_empty_backends() {
        let req = CreateLbServiceRequest {
            id: "lb-005".to_string(),
            name: "test".to_string(),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            backends: vec![],
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_invalid_backend_addr() {
        let req = CreateLbServiceRequest {
            id: "lb-006".to_string(),
            name: "test".to_string(),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            backends: vec![CreateLbBackendRequest {
                id: "be-1".to_string(),
                addr: "not-an-ip".to_string(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_all_protocols() {
        for p in &["tcp", "udp", "tls_passthrough", "tls"] {
            assert!(parse_protocol(p).is_ok(), "failed for {p}");
        }
    }

    #[test]
    fn parse_all_algorithms() {
        for a in &[
            "round_robin",
            "weighted",
            "ip_hash",
            "least_conn",
            "roundrobin",
            "iphash",
            "leastconn",
        ] {
            assert!(parse_algorithm(a).is_ok(), "failed for {a}");
        }
    }

    #[test]
    fn service_response_from_domain() {
        let svc = LbService {
            id: domain::common::entity::RuleId("lb-001".to_string()),
            name: "web".to_string(),
            protocol: LbProtocol::Tcp,
            listen_port: 443,
            algorithm: LbAlgorithm::RoundRobin,
            backends: vec![LbBackend {
                id: "be-1".to_string(),
                addr: "10.0.0.1".parse().unwrap(),
                port: 8080,
                weight: 1,
                enabled: true,
            }],
            enabled: true,
            health_check: None,
        };
        let resp = LbServiceResponse::from_service(&svc);
        assert_eq!(resp.id, "lb-001");
        assert_eq!(resp.protocol, "tcp");
        assert_eq!(resp.algorithm, "round_robin");
        assert_eq!(resp.backend_count, 1);
    }

    #[test]
    fn parse_zero_backend_weight() {
        let req = CreateLbServiceRequest {
            id: "lb-007".to_string(),
            name: "test".to_string(),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            backends: vec![CreateLbBackendRequest {
                id: "be-1".to_string(),
                addr: "10.0.0.1".to_string(),
                port: 8080,
                weight: 0,
                enabled: true,
            }],
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }
}
