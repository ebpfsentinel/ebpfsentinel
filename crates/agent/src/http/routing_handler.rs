use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use domain::auth::entity::JwtClaims;
use domain::routing::entity::{Gateway, GatewayState, HealthCheck};
use domain::routing::error::RoutingError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct RoutingStatusResponse {
    pub enabled: bool,
    pub gateway_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct GatewayResponse {
    /// Gateway identifier, rendered as a string for stable API addressing.
    pub id: String,
    pub name: String,
    pub interface: String,
    pub gateway_ip: String,
    /// Failover priority (lower = preferred).
    pub priority: u32,
    /// Alias of `priority`, exposed as a routing weight.
    pub weight: u32,
    pub enabled: bool,
    /// Health-check observed status (`healthy` / `degraded` / `down`).
    pub status: String,
    /// Alias of `status` for clients expecting a `health_status` field.
    pub health_status: String,
}

impl GatewayResponse {
    fn from_state(gs: &GatewayState) -> Self {
        let status = format!("{:?}", gs.status).to_lowercase();
        Self {
            id: gs.gateway.id.to_string(),
            name: gs.gateway.name.clone(),
            interface: gs.gateway.interface.clone(),
            gateway_ip: gs.gateway.gateway_ip.clone(),
            priority: gs.gateway.priority,
            weight: gs.gateway.priority,
            enabled: gs.gateway.enabled,
            health_status: status.clone(),
            status,
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateGatewayRequest {
    pub name: String,
    /// Gateway IPv4 address.
    pub ip: String,
    /// Egress interface; defaults to empty (inherits the agent's primary).
    #[serde(default)]
    pub interface: Option<String>,
    /// Routing weight; maps to failover priority (lower = preferred).
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Health-check probe interval in seconds. When set, an ICMP probe is configured.
    #[serde(default)]
    pub health_check_interval_secs: Option<u32>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_weight() -> u32 {
    100
}

fn default_true() -> bool {
    true
}

/// A resolved default route derived from the active gateway selection.
#[derive(Serialize, ToSchema)]
pub struct RouteResponse {
    /// Destination CIDR served by this route.
    pub destination: String,
    /// Identifier of the gateway this route egresses through.
    pub gateway_id: String,
    pub gateway_ip: String,
}

fn map_routing_error(err: &RoutingError) -> ApiError {
    match err {
        RoutingError::GatewayNotFound { id } => ApiError::NotFound {
            code: "GATEWAY_NOT_FOUND",
            message: format!("gateway {id} not found"),
        },
        RoutingError::DuplicateGateway { .. } | RoutingError::Full { .. } => ApiError::Conflict {
            code: "GATEWAY_CONFLICT",
            message: err.to_string(),
        },
        RoutingError::NoHealthyGateway => ApiError::ServiceUnavailable {
            message: err.to_string(),
        },
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/routing/status` — routing status.
#[utoipa::path(
    get, path = "/api/v1/routing/status",
    tag = "Routing",
    responses((status = 200, description = "Routing status", body = RoutingStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn routing_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<RoutingStatusResponse>, ApiError> {
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let svc = routing.read().await;
    Ok(Json(RoutingStatusResponse {
        enabled: svc.enabled(),
        gateway_count: svc.gateway_count(),
    }))
}

/// `GET /api/v1/routing/gateways` — list routing gateways.
#[utoipa::path(
    get, path = "/api/v1/routing/gateways",
    tag = "Routing",
    responses((status = 200, description = "Gateway list", body = Vec<GatewayResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_gateways(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<GatewayResponse>>, ApiError> {
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let svc = routing.read().await;
    let gateways: Vec<GatewayResponse> = svc
        .list_gateways()
        .iter()
        .map(|gs| GatewayResponse::from_state(gs))
        .collect();
    Ok(Json(gateways))
}

/// `POST /api/v1/routing/gateways` — add a routing gateway.
#[utoipa::path(
    post, path = "/api/v1/routing/gateways",
    tag = "Routing",
    request_body = CreateGatewayRequest,
    responses((status = 201, description = "Gateway created", body = GatewayResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 409, description = "Gateway conflict", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn create_gateway(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateGatewayRequest>,
) -> Result<(axum::http::StatusCode, Json<GatewayResponse>), ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let gateway = Gateway {
        id: 0, // reassigned by the service
        name: req.name,
        interface: req.interface.unwrap_or_default(),
        gateway_ip: req.ip,
        priority: req.weight,
        enabled: req.enabled,
        health_check: req
            .health_check_interval_secs
            .map(|interval_secs| HealthCheck {
                interval_secs,
                ..HealthCheck::default()
            }),
        preferred_for_countries: None,
    };
    let mut svc = routing.write().await;
    let id = svc
        .add_gateway(gateway)
        .map_err(|e| map_routing_error(&e))?;
    let resp = svc
        .list_gateways()
        .iter()
        .find(|gs| gs.gateway.id == id)
        .map(|gs| GatewayResponse::from_state(gs))
        .ok_or(ApiError::Internal {
            message: "gateway vanished after insert".to_string(),
        })?;
    Ok((axum::http::StatusCode::CREATED, Json(resp)))
}

/// `DELETE /api/v1/routing/gateways/{id}` — remove a routing gateway.
#[utoipa::path(
    delete, path = "/api/v1/routing/gateways/{id}",
    tag = "Routing",
    params(("id" = String, Path, description = "Gateway identifier")),
    responses((status = 204, description = "Gateway deleted"),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Gateway not found", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn delete_gateway(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let gateway_id: u8 = id.parse().map_err(|_| ApiError::BadRequest {
        code: "INVALID_GATEWAY_ID",
        message: format!("invalid gateway id: {id}"),
    })?;
    let mut svc = routing.write().await;
    svc.remove_gateway(gateway_id)
        .map_err(|e| map_routing_error(&e))?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// `GET /api/v1/routing/routes` — effective default route(s) from gateway selection.
#[utoipa::path(
    get, path = "/api/v1/routing/routes",
    tag = "Routing",
    responses((status = 200, description = "Active routes", body = Vec<RouteResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_routes(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RouteResponse>>, ApiError> {
    let routing = state.routing_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Routing not enabled".to_string(),
    })?;
    let svc = routing.read().await;
    // The effective routing table is the default route via the currently
    // selected (lowest-priority usable) gateway; empty when none is usable.
    let routes: Vec<RouteResponse> = svc
        .select_gateway()
        .map(|gs| RouteResponse {
            destination: "0.0.0.0/0".to_string(),
            gateway_id: gs.gateway.id.to_string(),
            gateway_ip: gs.gateway.gateway_ip.clone(),
        })
        .into_iter()
        .collect();
    Ok(Json(routes))
}
