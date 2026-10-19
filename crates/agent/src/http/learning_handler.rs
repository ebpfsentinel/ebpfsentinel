use std::sync::Arc;

use application::learning_service::now_ns;
use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use domain::auth::entity::JwtClaims;
use domain::firewall::workload::WorkloadSelector;
use domain::learning::entity::{LearningProgress, LearningScope};
use domain::learning::error::LearningError;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

/// One of the selectors a scope is written with, in the shape a workload
/// rule already uses.
#[derive(Debug, Clone, Default, Deserialize, Serialize, ToSchema)]
pub struct WorkloadSelectorBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
}

/// What the window is asked to watch.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeBody {
    /// Every workload on the node a flow can be attributed to.
    Node,
    /// One cgroup v2 subtree, by absolute path.
    Cgroup { path: String },
    /// A set of workloads, named the way a rule names them.
    Workloads {
        selectors: Vec<WorkloadSelectorBody>,
    },
}

impl TryFrom<ScopeBody> for LearningScope {
    type Error = ApiError;

    fn try_from(body: ScopeBody) -> Result<Self, Self::Error> {
        match body {
            ScopeBody::Node => Ok(Self::Node),
            ScopeBody::Cgroup { path } => Ok(Self::Cgroup { path }),
            ScopeBody::Workloads { selectors } => {
                let selectors = selectors
                    .into_iter()
                    .map(|s| {
                        WorkloadSelector::new(s.exe, s.unit, s.cgroup, s.container).map_err(|e| {
                            ApiError::BadRequest {
                                code: "INVALID_SCOPE",
                                message: e.to_string(),
                            }
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Workloads { selectors })
            }
        }
    }
}

/// Open a window.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct StartLearningRequest {
    /// What to watch. Omitted means the whole node.
    #[serde(default = "default_scope")]
    pub scope: ScopeBody,
    /// How long to watch for, in seconds.
    pub duration_secs: u64,
}

fn default_scope() -> ScopeBody {
    ScopeBody::Node
}

/// A window, as it stands.
///
/// Everything a reader needs to decide whether the document it would
/// produce is worth applying: how long it has really been watching, whether
/// the agent was up for all of it, how many destinations it holds, how many
/// it had to refuse, and how long since it last found a new one.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LearningSessionResponse {
    pub id: String,
    pub status: String,
    pub scope: ScopeBody,
    /// The scope in one line, as the generated document states it.
    pub scope_description: String,
    pub requested_duration_secs: u64,
    pub started_at_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ns: Option<u64>,
    pub elapsed_secs: u64,
    /// Seconds of the window the agent was not running for.
    pub gap_secs: u64,
    pub remaining_secs: u64,
    pub edges: usize,
    pub capacity: usize,
    /// Destinations refused because the window was full. Anything but zero
    /// means the document it produces is incomplete, and it says so.
    pub dropped_edges: u64,
    pub observations: u64,
    pub unattributed: u64,
    pub out_of_scope: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_new_edge_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secs_since_new_edge: Option<u64>,
    /// False once the agent has been down for part of the window.
    pub continuous: bool,
}

fn scope_body(scope: LearningScope) -> ScopeBody {
    match scope {
        LearningScope::Node => ScopeBody::Node,
        LearningScope::Cgroup { path } => ScopeBody::Cgroup { path },
        LearningScope::Workloads { selectors } => ScopeBody::Workloads {
            selectors: selectors
                .into_iter()
                .map(|s| WorkloadSelectorBody {
                    exe: s.exe,
                    unit: s.unit,
                    cgroup: s.cgroup,
                    container: s.container,
                })
                .collect(),
        },
    }
}

#[must_use]
pub fn session_response(progress: LearningProgress) -> LearningSessionResponse {
    LearningSessionResponse {
        id: progress.id,
        status: progress.status.as_str().to_string(),
        scope: scope_body(progress.scope),
        scope_description: progress.scope_description,
        requested_duration_secs: progress.requested_duration_secs,
        started_at_ns: progress.started_at_ns,
        ended_at_ns: progress.ended_at_ns,
        elapsed_secs: progress.elapsed_secs,
        gap_secs: progress.gap_secs,
        remaining_secs: progress.remaining_secs,
        edges: progress.edges,
        capacity: progress.capacity,
        dropped_edges: progress.dropped_edges,
        observations: progress.observations,
        unattributed: progress.unattributed,
        out_of_scope: progress.out_of_scope,
        last_new_edge_ns: progress.last_new_edge_ns,
        secs_since_new_edge: progress.secs_since_new_edge,
        continuous: progress.continuous,
    }
}

fn learning(
    state: &AppState,
) -> Result<Arc<application::learning_service::LearningAppService>, ApiError> {
    state
        .learning_service
        .load_full()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "learning mode is turned off on this node".to_string(),
        })
}

fn learning_error(err: &LearningError) -> ApiError {
    match err {
        LearningError::AlreadyRunning { .. } => ApiError::Conflict {
            code: "LEARNING_ALREADY_RUNNING",
            message: err.to_string(),
        },
        LearningError::Unknown { .. } | LearningError::NotRunning => ApiError::NotFound {
            code: "LEARNING_NOT_FOUND",
            message: err.to_string(),
        },
        _ => ApiError::BadRequest {
            code: "INVALID_LEARNING_REQUEST",
            message: err.to_string(),
        },
    }
}

/// `POST /api/v1/learning/sessions` - open a window.
#[utoipa::path(
    post, path = "/api/v1/learning/sessions",
    tag = "Learning",
    request_body = StartLearningRequest,
    responses(
        (status = 200, description = "The window that is now open", body = LearningSessionResponse),
        (status = 400, description = "A scope or a duration the node cannot honour", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Learning mode is turned off on this node", body = ErrorBody),
        (status = 409, description = "A window is already open", body = ErrorBody),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn start_learning(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(request): Json<StartLearningRequest>,
) -> Result<Json<LearningSessionResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let service = learning(&state)?;
    let scope = LearningScope::try_from(request.scope)?;
    let progress = service
        .start(scope, request.duration_secs, now_ns())
        .map_err(|e| learning_error(&e))?;
    tracing::info!(
        session = %progress.id,
        duration_secs = progress.requested_duration_secs,
        scope = %progress.scope_description,
        "learning window opened"
    );
    Ok(Json(session_response(progress)))
}

/// `GET /api/v1/learning/sessions` - every window this node remembers.
#[utoipa::path(
    get, path = "/api/v1/learning/sessions",
    tag = "Learning",
    responses(
        (status = 200, description = "The windows, newest first", body = Vec<LearningSessionResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Learning mode is turned off on this node", body = ErrorBody),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_learning(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<LearningSessionResponse>>, ApiError> {
    let service = learning(&state)?;
    let sessions = service
        .list(now_ns())
        .into_iter()
        .map(session_response)
        .collect();
    Ok(Json(sessions))
}

/// `GET /api/v1/learning/sessions/{id}` - one window, as it stands.
#[utoipa::path(
    get, path = "/api/v1/learning/sessions/{id}",
    tag = "Learning",
    params(("id" = String, Path, description = "The window's id")),
    responses(
        (status = 200, description = "The window", body = LearningSessionResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "No such window, or learning mode is off", body = ErrorBody),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_learning(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<LearningSessionResponse>, ApiError> {
    let service = learning(&state)?;
    let progress = service
        .progress(Some(&id), now_ns())
        .ok_or(ApiError::NotFound {
            code: "LEARNING_NOT_FOUND",
            message: format!("no learning window with id '{id}'"),
        })?;
    Ok(Json(session_response(progress)))
}

/// `POST /api/v1/learning/sessions/{id}/stop` - close a window early.
#[utoipa::path(
    post, path = "/api/v1/learning/sessions/{id}/stop",
    tag = "Learning",
    params(("id" = String, Path, description = "The window's id")),
    responses(
        (status = 200, description = "The window, now closed", body = LearningSessionResponse),
        (status = 400, description = "The window was already closed", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "No such window, or learning mode is off", body = ErrorBody),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn stop_learning(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<Json<LearningSessionResponse>, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let service = learning(&state)?;
    let progress = service
        .stop(Some(&id), now_ns())
        .map_err(|e| learning_error(&e))?;
    tracing::info!(
        session = %progress.id,
        edges = progress.edges,
        elapsed_secs = progress.elapsed_secs,
        "learning window closed"
    );
    Ok(Json(session_response(progress)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_with_no_scope_watches_the_whole_node() {
        let request: StartLearningRequest =
            serde_json::from_str(r#"{"duration_secs": 3600}"#).expect("the body parses");
        assert!(matches!(request.scope, ScopeBody::Node));
        assert_eq!(request.duration_secs, 3_600);
    }

    #[test]
    fn a_scope_naming_a_workload_becomes_the_selector_a_rule_uses() {
        let request: StartLearningRequest = serde_json::from_str(
            r#"{"duration_secs": 600, "scope": {"kind": "workloads",
                "selectors": [{"unit": "nginx.service"}]}}"#,
        )
        .expect("the body parses");
        let scope = LearningScope::try_from(request.scope).expect("the selector is one");
        match scope {
            LearningScope::Workloads { selectors } => {
                assert_eq!(selectors[0].unit.as_deref(), Some("nginx.service"));
            }
            other => panic!("expected a workload scope, got {other:?}"),
        }
    }

    #[test]
    fn a_scope_naming_nothing_is_refused_before_a_window_opens() {
        let request: StartLearningRequest = serde_json::from_str(
            r#"{"duration_secs": 600, "scope": {"kind": "workloads", "selectors": [{}]}}"#,
        )
        .expect("the body parses");
        let err = LearningScope::try_from(request.scope).expect_err("a selector names something");
        assert!(matches!(err, ApiError::BadRequest { code, .. } if code == "INVALID_SCOPE"));
    }

    #[test]
    fn a_window_that_was_never_opened_is_a_404_and_an_open_one_a_409() {
        assert!(matches!(
            learning_error(&LearningError::Unknown {
                id: "l-1".to_string()
            }),
            ApiError::NotFound { .. }
        ));
        assert!(matches!(
            learning_error(&LearningError::AlreadyRunning {
                id: "l-1".to_string()
            }),
            ApiError::Conflict { .. }
        ));
    }
}
