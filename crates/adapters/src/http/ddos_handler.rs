use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use domain::common::entity::RuleId;
use domain::ddos::entity::{
    DdosAttackType, DdosMitigationAction, DdosMitigationStatus, DdosPolicy,
};
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::middleware::rbac::require_write_access;
use super::state::AppState;
use super::validation::{MAX_ID_LENGTH, MAX_SHORT_STRING_LENGTH, validate_string_length};

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DdosStatusResponse {
    pub enabled: bool,
    pub active_attacks: usize,
    pub total_mitigated: u64,
    pub policy_count: usize,
}

#[derive(Serialize)]
pub struct DdosAttackResponse {
    pub id: String,
    pub attack_type: String,
    pub status: String,
    pub start_time_ns: u64,
    pub peak_pps: u64,
    pub current_pps: u64,
    pub total_packets: u64,
    pub source_count: u64,
}

#[derive(Serialize)]
pub struct DdosPolicyResponse {
    pub id: String,
    pub attack_type: String,
    pub detection_threshold_pps: u64,
    pub mitigation_action: String,
    pub auto_block_duration_secs: u64,
    pub enabled: bool,
}

impl DdosPolicyResponse {
    fn from_policy(p: &DdosPolicy) -> Self {
        Self {
            id: p.id.0.clone(),
            attack_type: format!("{:?}", p.attack_type).to_lowercase(),
            detection_threshold_pps: p.detection_threshold_pps,
            mitigation_action: format!("{:?}", p.mitigation_action).to_lowercase(),
            auto_block_duration_secs: p.auto_block_duration_secs,
            enabled: p.enabled,
        }
    }
}

// ── Request DTOs ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateDdosPolicyRequest {
    pub id: String,
    pub attack_type: String,
    pub detection_threshold_pps: u64,
    #[serde(default = "default_mitigation_action")]
    pub mitigation_action: String,
    #[serde(default)]
    pub auto_block_duration_secs: u64,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_mitigation_action() -> String {
    "alert".to_string()
}
fn default_enabled() -> bool {
    true
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
}

fn default_limit() -> usize {
    100
}

// ── Handlers ──────────────────────────────────────────────────────

pub async fn ddos_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DdosStatusResponse>, ApiError> {
    let ddos = state.ddos_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DDoS protection not enabled".to_string(),
    })?;
    let svc = ddos.read().await;
    Ok(Json(DdosStatusResponse {
        enabled: svc.enabled(),
        active_attacks: svc.active_attack_count(),
        total_mitigated: svc.total_mitigated(),
        policy_count: svc.policy_count(),
    }))
}

pub async fn ddos_attacks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DdosAttackResponse>>, ApiError> {
    let ddos = state.ddos_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DDoS protection not enabled".to_string(),
    })?;
    let svc = ddos.read().await;
    let attacks: Vec<DdosAttackResponse> = svc
        .active_attacks()
        .iter()
        .map(|a| DdosAttackResponse {
            id: a.id.clone(),
            attack_type: format!("{:?}", a.attack_type).to_lowercase(),
            status: format_status(a.mitigation_status),
            start_time_ns: a.start_time_ns,
            peak_pps: a.peak_pps,
            current_pps: a.current_pps,
            total_packets: a.total_packets,
            source_count: a.source_count,
        })
        .collect();
    Ok(Json(attacks))
}

pub async fn ddos_history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<DdosAttackResponse>>, ApiError> {
    let ddos = state.ddos_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DDoS protection not enabled".to_string(),
    })?;
    let svc = ddos.read().await;
    let attacks: Vec<DdosAttackResponse> = svc
        .attack_history(query.limit)
        .iter()
        .map(|a| DdosAttackResponse {
            id: a.id.clone(),
            attack_type: format!("{:?}", a.attack_type).to_lowercase(),
            status: format_status(a.mitigation_status),
            start_time_ns: a.start_time_ns,
            peak_pps: a.peak_pps,
            current_pps: a.current_pps,
            total_packets: a.total_packets,
            source_count: a.source_count,
        })
        .collect();
    Ok(Json(attacks))
}

pub async fn list_ddos_policies(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DdosPolicyResponse>>, ApiError> {
    let ddos = state.ddos_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DDoS protection not enabled".to_string(),
    })?;
    let svc = ddos.read().await;
    let policies: Vec<DdosPolicyResponse> = svc
        .policies()
        .iter()
        .map(DdosPolicyResponse::from_policy)
        .collect();
    Ok(Json(policies))
}

pub async fn create_ddos_policy(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateDdosPolicyRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }

    let policy = parse_create_request(req)?;
    let rule_id = policy.id.0.clone();
    let after_json = serde_json::to_string(&policy).ok();

    let ddos = state.ddos_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DDoS protection not enabled".to_string(),
    })?;
    let mut svc = ddos.write().await;
    svc.add_policy(policy.clone())?;
    drop(svc);

    tracing::info!(rule_id = %rule_id, "DDoS policy created via API");

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Ddos,
        domain::audit::entity::AuditAction::RuleAdded,
        domain::audit::rule_change::ChangeActor::Api,
        &rule_id,
        None,
        after_json,
    );

    Ok((
        StatusCode::CREATED,
        Json(DdosPolicyResponse::from_policy(&policy)),
    ))
}

pub async fn delete_ddos_policy(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }

    let ddos = state.ddos_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DDoS protection not enabled".to_string(),
    })?;

    let before_json = {
        let svc = ddos.read().await;
        svc.policies()
            .iter()
            .find(|p| p.id.0 == id)
            .and_then(|p| serde_json::to_string(p).ok())
    };

    let mut svc = ddos.write().await;
    svc.remove_policy(&RuleId(id.clone()))?;
    drop(svc);

    tracing::info!(rule_id = %id, "DDoS policy deleted via API");

    state.audit_service.read().await.record_rule_change(
        domain::audit::entity::AuditComponent::Ddos,
        domain::audit::entity::AuditAction::RuleRemoved,
        domain::audit::rule_change::ChangeActor::Api,
        &id,
        before_json,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ───────────────────────────────────────────────────────

fn format_status(status: DdosMitigationStatus) -> String {
    match status {
        DdosMitigationStatus::Detecting => "detecting".to_string(),
        DdosMitigationStatus::Active => "active".to_string(),
        DdosMitigationStatus::Mitigated => "mitigated".to_string(),
        DdosMitigationStatus::Expired => "expired".to_string(),
    }
}

fn parse_attack_type(s: &str) -> Result<DdosAttackType, ApiError> {
    match s.to_lowercase().as_str() {
        "syn_flood" | "synflood" => Ok(DdosAttackType::SynFlood),
        "udp_amplification" | "udpamplification" => Ok(DdosAttackType::UdpAmplification),
        "icmp_flood" | "icmpflood" => Ok(DdosAttackType::IcmpFlood),
        "rst_flood" | "rstflood" => Ok(DdosAttackType::RstFlood),
        "fin_flood" | "finflood" => Ok(DdosAttackType::FinFlood),
        "ack_flood" | "ackflood" => Ok(DdosAttackType::AckFlood),
        "volumetric" => Ok(DdosAttackType::Volumetric),
        _ => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!(
                "invalid attack_type '{s}': expected syn_flood, udp_amplification, icmp_flood, \
                 rst_flood, fin_flood, ack_flood, or volumetric"
            ),
        }),
    }
}

fn parse_mitigation_action(s: &str) -> Result<DdosMitigationAction, ApiError> {
    match s.to_lowercase().as_str() {
        "alert" => Ok(DdosMitigationAction::Alert),
        "throttle" => Ok(DdosMitigationAction::Throttle),
        "block" => Ok(DdosMitigationAction::Block),
        _ => Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid mitigation_action '{s}': expected alert, throttle, or block"),
        }),
    }
}

fn parse_create_request(req: CreateDdosPolicyRequest) -> Result<DdosPolicy, ApiError> {
    validate_string_length("id", &req.id, MAX_ID_LENGTH)?;
    validate_string_length("attack_type", &req.attack_type, MAX_SHORT_STRING_LENGTH)?;
    validate_string_length(
        "mitigation_action",
        &req.mitigation_action,
        MAX_SHORT_STRING_LENGTH,
    )?;

    let attack_type = parse_attack_type(&req.attack_type)?;
    let mitigation_action = parse_mitigation_action(&req.mitigation_action)?;

    if req.detection_threshold_pps == 0 {
        return Err(ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: "detection_threshold_pps must be > 0".to_string(),
        });
    }

    Ok(DdosPolicy {
        id: RuleId(req.id),
        attack_type,
        detection_threshold_pps: req.detection_threshold_pps,
        mitigation_action,
        auto_block_duration_secs: req.auto_block_duration_secs,
        enabled: req.enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_create_request() {
        let req = CreateDdosPolicyRequest {
            id: "ddos-001".to_string(),
            attack_type: "syn_flood".to_string(),
            detection_threshold_pps: 5000,
            mitigation_action: "block".to_string(),
            auto_block_duration_secs: 300,
            enabled: true,
        };
        let policy = parse_create_request(req).unwrap();
        assert_eq!(policy.id.0, "ddos-001");
        assert_eq!(policy.attack_type, DdosAttackType::SynFlood);
        assert_eq!(policy.detection_threshold_pps, 5000);
        assert_eq!(policy.mitigation_action, DdosMitigationAction::Block);
    }

    #[test]
    fn parse_invalid_attack_type() {
        let req = CreateDdosPolicyRequest {
            id: "ddos-002".to_string(),
            attack_type: "invalid".to_string(),
            detection_threshold_pps: 5000,
            mitigation_action: "alert".to_string(),
            auto_block_duration_secs: 0,
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_zero_threshold() {
        let req = CreateDdosPolicyRequest {
            id: "ddos-003".to_string(),
            attack_type: "icmp_flood".to_string(),
            detection_threshold_pps: 0,
            mitigation_action: "alert".to_string(),
            auto_block_duration_secs: 0,
            enabled: true,
        };
        assert!(parse_create_request(req).is_err());
    }

    #[test]
    fn parse_all_attack_types() {
        for ty in &[
            "syn_flood",
            "udp_amplification",
            "icmp_flood",
            "rst_flood",
            "fin_flood",
            "ack_flood",
            "volumetric",
        ] {
            assert!(parse_attack_type(ty).is_ok(), "failed for {ty}");
        }
    }

    #[test]
    fn parse_all_mitigation_actions() {
        for action in &["alert", "throttle", "block"] {
            assert!(
                parse_mitigation_action(action).is_ok(),
                "failed for {action}"
            );
        }
    }

    #[test]
    fn policy_response_from_domain() {
        let policy = DdosPolicy {
            id: RuleId("ddos-001".to_string()),
            attack_type: DdosAttackType::SynFlood,
            detection_threshold_pps: 5000,
            mitigation_action: DdosMitigationAction::Block,
            auto_block_duration_secs: 300,
            enabled: true,
        };
        let resp = DdosPolicyResponse::from_policy(&policy);
        assert_eq!(resp.id, "ddos-001");
        assert_eq!(resp.detection_threshold_pps, 5000);
        assert!(resp.enabled);
    }
}
