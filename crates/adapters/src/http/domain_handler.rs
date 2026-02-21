use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use domain::auth::entity::JwtClaims;
use ports::secondary::domain_reputation_port::DomainReputationPort;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;
use super::validation::{MAX_PATTERN_LENGTH, validate_string_length};

// ── Query parameters ────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
pub struct ReputationQueryParams {
    /// Filter by domain (exact match).
    pub domain: Option<String>,
    /// Minimum reputation score (0.0–1.0).
    pub min_score: Option<f64>,
    /// Page number (0-indexed).
    #[serde(default)]
    pub page: usize,
    /// Page size (max 500).
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_page_size() -> usize {
    50
}

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct DomainReputationResponse {
    pub domain: String,
    pub score: f64,
    pub factors: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub is_blocked: bool,
}

#[derive(Serialize, ToSchema)]
pub struct DomainReputationListResponse {
    pub entries: Vec<DomainReputationResponse>,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Deserialize, ToSchema)]
pub struct BlocklistAddRequest {
    pub domain: String,
}

#[derive(Serialize, ToSchema)]
pub struct BlocklistAddResponse {
    pub domain: String,
    pub added: bool,
}

#[derive(Serialize, ToSchema)]
pub struct BlocklistRemoveResponse {
    pub domain: String,
    pub removed: bool,
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/domains/reputation` — query domain reputations.
#[utoipa::path(
    get, path = "/api/v1/domains/reputation",
    tag = "Domain Intelligence",
    params(ReputationQueryParams),
    responses(
        (status = 200, description = "Domain reputations", body = DomainReputationListResponse),
        (status = 503, description = "Domain reputation not enabled", body = ErrorBody),
    )
)]
pub async fn list_domain_reputations(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ReputationQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    let rep_svc = state
        .domain_reputation_service
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "domain reputation is not enabled".to_string(),
        })?;

    let blocklist = state.dns_blocklist_service.as_ref();
    let page_size = params.page_size.min(500);

    let entries: Vec<DomainReputationResponse> = if let Some(ref domain) = params.domain {
        // Single domain lookup
        rep_svc
            .get_reputation(domain)
            .into_iter()
            .map(|rep| to_response(&rep, domain, blocklist))
            .collect()
    } else if let Some(min_score) = params.min_score {
        // Filter by min_score
        let high_risk = rep_svc.list_high_risk(min_score);
        high_risk
            .into_iter()
            .skip(params.page * page_size)
            .take(page_size)
            .map(|(rep, score)| {
                let is_blocked = check_blocked(blocklist, &rep.domain);
                DomainReputationResponse {
                    domain: rep.domain.clone(),
                    score,
                    factors: rep.factors.iter().map(|f| format!("{f:?}")).collect(),
                    first_seen: rep.first_seen,
                    last_seen: rep.last_seen,
                    is_blocked,
                }
            })
            .collect()
    } else {
        // Paginated listing
        let all = rep_svc.list_all(params.page, page_size);
        all.into_iter()
            .map(|(rep, score)| {
                let is_blocked = check_blocked(blocklist, &rep.domain);
                DomainReputationResponse {
                    domain: rep.domain.clone(),
                    score,
                    factors: rep.factors.iter().map(|f| format!("{f:?}")).collect(),
                    first_seen: rep.first_seen,
                    last_seen: rep.last_seen,
                    is_blocked,
                }
            })
            .collect()
    };

    Ok(Json(DomainReputationListResponse {
        entries,
        page: params.page,
        page_size,
    }))
}

/// `POST /api/v1/domains/blocklist` — add a domain to the runtime blocklist.
#[utoipa::path(
    post, path = "/api/v1/domains/blocklist",
    tag = "Domain Intelligence",
    request_body = BlocklistAddRequest,
    responses(
        (status = 200, description = "Domain added to blocklist", body = BlocklistAddResponse),
        (status = 400, description = "Invalid domain pattern", body = ErrorBody),
        (status = 503, description = "DNS blocklist not enabled", body = ErrorBody),
    )
)]
pub async fn add_to_blocklist(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(body): Json<BlocklistAddRequest>,
) -> Result<Json<BlocklistAddResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    validate_string_length("domain", &body.domain, MAX_PATTERN_LENGTH)?;

    let blocklist = state
        .dns_blocklist_service
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "DNS blocklist is not enabled".to_string(),
        })?;

    blocklist
        .add_pattern(&body.domain)
        .map_err(|e| ApiError::BadRequest {
            code: "INVALID_PATTERN",
            message: e,
        })?;

    Ok(Json(BlocklistAddResponse {
        domain: body.domain,
        added: true,
    }))
}

/// `DELETE /api/v1/domains/blocklist/{domain}` — remove a domain from the runtime blocklist.
#[utoipa::path(
    delete, path = "/api/v1/domains/blocklist/{domain}",
    tag = "Domain Intelligence",
    params(("domain" = String, Path, description = "Domain pattern to remove")),
    responses(
        (status = 200, description = "Domain removed from blocklist", body = BlocklistRemoveResponse),
        (status = 404, description = "Domain not found in blocklist", body = ErrorBody),
        (status = 503, description = "DNS blocklist not enabled", body = ErrorBody),
    )
)]
pub async fn remove_from_blocklist(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(domain): Path<String>,
) -> Result<Json<BlocklistRemoveResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let blocklist = state
        .dns_blocklist_service
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "DNS blocklist is not enabled".to_string(),
        })?;

    blocklist
        .remove_pattern(&domain)
        .map_err(|e| ApiError::NotFound {
            code: "PATTERN_NOT_FOUND",
            message: e,
        })?;

    Ok(Json(BlocklistRemoveResponse {
        domain,
        removed: true,
    }))
}

// ── Helpers ─────────────────────────────────────────────────────────

fn to_response(
    rep: &domain::dns::entity::DomainReputation,
    domain: &str,
    blocklist: Option<&Arc<application::dns_blocklist_service_impl::DnsBlocklistAppService>>,
) -> DomainReputationResponse {
    let is_blocked = check_blocked(blocklist, domain);
    DomainReputationResponse {
        domain: rep.domain.clone(),
        score: rep.compute_score(),
        factors: rep.factors.iter().map(|f| format!("{f:?}")).collect(),
        first_seen: rep.first_seen,
        last_seen: rep.last_seen,
        is_blocked,
    }
}

fn check_blocked(
    blocklist: Option<&Arc<application::dns_blocklist_service_impl::DnsBlocklistAppService>>,
    domain: &str,
) -> bool {
    blocklist.is_some_and(|bl| {
        bl.list_patterns_with_counts().iter().any(|(p, _)| {
            domain::dns::entity::DomainPattern::parse(p).is_ok_and(|pat| pat.matches(domain))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reputation_response_serialization() {
        let resp = DomainReputationResponse {
            domain: "evil.com".to_string(),
            score: 0.85,
            factors: vec!["HighEntropy".to_string()],
            first_seen: 1_000_000_000,
            last_seen: 2_000_000_000,
            is_blocked: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["domain"], "evil.com");
        assert!((json["score"].as_f64().unwrap() - 0.85).abs() < 0.01);
        assert!(json["is_blocked"].as_bool().unwrap());
    }

    #[test]
    fn reputation_list_response_serialization() {
        let resp = DomainReputationListResponse {
            entries: vec![],
            page: 0,
            page_size: 50,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["entries"].as_array().unwrap().is_empty());
        assert_eq!(json["page"], 0);
        assert_eq!(json["page_size"], 50);
    }

    #[test]
    fn blocklist_add_request_deserialize() {
        let json = r#"{"domain": "*.malware.com"}"#;
        let req: BlocklistAddRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.domain, "*.malware.com");
    }

    #[test]
    fn blocklist_add_response_serialization() {
        let resp = BlocklistAddResponse {
            domain: "evil.com".to_string(),
            added: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["domain"], "evil.com");
        assert!(json["added"].as_bool().unwrap());
    }

    #[test]
    fn blocklist_remove_response_serialization() {
        let resp = BlocklistRemoveResponse {
            domain: "evil.com".to_string(),
            removed: true,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["domain"], "evil.com");
        assert!(json["removed"].as_bool().unwrap());
    }
}
