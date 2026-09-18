use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct DlpStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub pattern_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct DlpPatternResponse {
    pub id: String,
    pub name: String,
    /// What the pattern is for, as the configuration file wrote it. Empty
    /// where none was written.
    pub description: String,
    pub regex: String,
    /// `low`, `medium`, `high` or `critical`.
    pub severity: String,
    /// `pci`, `pii`, `credentials` or `custom`.
    pub data_type: String,
    /// `alert` or `block`, this pattern's own. A pattern may block while the
    /// service default alerts, so a listing carrying only the service mode
    /// reads as a set of patterns that all merely report.
    pub mode: String,
    pub enabled: bool,
}

// ── Handlers ──────────────────────────────────────────────────────

/// One pattern, as the listing route answers it.
fn response_for(p: &domain::dlp::entity::DlpPattern) -> DlpPatternResponse {
    DlpPatternResponse {
        id: p.id.0.clone(),
        name: p.name.clone(),
        description: p.description.clone(),
        regex: p.regex.clone(),
        severity: format!("{:?}", p.severity).to_lowercase(),
        data_type: p.data_type.clone(),
        mode: p.mode.as_str().to_string(),
        enabled: p.enabled,
    }
}

/// `GET /api/v1/dlp/status` - DLP status.
#[utoipa::path(
    get, path = "/api/v1/dlp/status",
    tag = "DLP",
    responses((status = 200, description = "DLP status", body = DlpStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn dlp_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<DlpStatusResponse>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let svc = dlp.load();
    Ok(Json(DlpStatusResponse {
        enabled: svc.enabled(),
        mode: svc.mode().as_str().to_string(),
        pattern_count: svc.pattern_count(),
    }))
}

/// `GET /api/v1/dlp/patterns` - list DLP patterns.
#[utoipa::path(
    get, path = "/api/v1/dlp/patterns",
    tag = "DLP",
    responses((status = 200, description = "DLP patterns", body = Vec<DlpPatternResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_dlp_patterns(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<DlpPatternResponse>>, ApiError> {
    let dlp = state.dlp_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "DLP not enabled".to_string(),
    })?;
    let svc = dlp.load();
    let patterns: Vec<DlpPatternResponse> = svc.list_patterns().iter().map(response_for).collect();
    Ok(Json(patterns))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::{DomainMode, RuleId, Severity};
    use domain::dlp::entity::DlpPattern;

    fn pattern(mode: DomainMode) -> DlpPattern {
        DlpPattern {
            id: RuleId("dlp-cred-aws".to_string()),
            name: "AWS access key".to_string(),
            regex: "AKIA[0-9A-Z]{16}".to_string(),
            severity: Severity::Critical,
            mode,
            data_type: "credentials".to_string(),
            description: "Long-lived AWS access key identifier".to_string(),
            enabled: true,
        }
    }

    /// A pattern that stops a transfer while the service default only
    /// records one is the difference between a leak reported and a leak
    /// prevented, and the listing is where somebody checks which they have.
    #[test]
    fn a_pattern_carries_the_mode_it_is_enforced_at() {
        let p = pattern(DomainMode::Block);
        let body = serde_json::to_value(response_for(&p)).expect("serialise");

        assert_eq!(body["mode"], "block");
        assert_eq!(
            serde_json::to_value(response_for(&pattern(DomainMode::Alert))).expect("serialise")["mode"],
            "alert"
        );
    }

    #[test]
    fn a_pattern_carries_what_it_was_written_for() {
        let body =
            serde_json::to_value(response_for(&pattern(DomainMode::Alert))).expect("serialise");

        assert_eq!(body["description"], "Long-lived AWS access key identifier");
        assert_eq!(body["data_type"], "credentials");
        assert_eq!(body["severity"], "critical");
    }
}
