use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::netpol::{Direction, ReplayReport};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::brokered::brokered;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

/// How many connections a replay reads when the request names no limit.
const DEFAULT_REPLAY_FLOWS: usize = 10_000;

/// The most a replay reads, whatever the request asks.
const MAX_REPLAY_FLOWS: usize = 100_000;

// ── Request / response DTOs ───────────────────────────────────────

#[derive(Deserialize, ToSchema)]
pub struct NetpolReplayRequest {
    /// One or more `networking.k8s.io/v1` `NetworkPolicy` manifests, as a
    /// YAML stream. A `List` is read item by item. A policy with the
    /// namespace and name of one in force replaces it; any other is added.
    pub manifests: String,
    /// How many tracked connections to replay, at most 100000.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Serialize, ToSchema)]
pub struct NetpolRefusedFlow {
    /// `ingress` or `egress`, seen from the pod that would refuse.
    pub direction: String,
    /// The address at the other end, as the deciding hook sees it: the
    /// destination the pod connected to, a Service address included, or
    /// the source the pod was reached from.
    pub peer: String,
    pub protocol: u8,
    pub port: u16,
    /// The policies in force refuse it already.
    pub already_refused: bool,
    /// How many tracked connections had this shape.
    pub flows: usize,
}

#[derive(Serialize, ToSchema)]
pub struct NetpolWorkloadReplay {
    pub namespace: String,
    pub pod: String,
    pub refused: Vec<NetpolRefusedFlow>,
}

#[derive(Serialize, ToSchema)]
pub struct NetpolReplayResponse {
    /// Tracked connections read.
    pub flows: usize,
    /// Connections with a known pod at one end at least, the only ones a
    /// policy can decide.
    pub judged: usize,
    /// Connections the proposal refuses that the policies in force let
    /// through.
    pub newly_refused: usize,
    /// Connections the proposal refuses that are refused already.
    pub still_refused: usize,
    pub workloads: Vec<NetpolWorkloadReplay>,
}

fn replay_response(report: ReplayReport) -> NetpolReplayResponse {
    NetpolReplayResponse {
        flows: report.flows,
        judged: report.judged,
        newly_refused: report.newly_refused,
        still_refused: report.still_refused,
        workloads: report
            .workloads
            .into_iter()
            .map(|workload| NetpolWorkloadReplay {
                namespace: workload.namespace,
                pod: workload.pod,
                refused: workload
                    .refused
                    .into_iter()
                    .map(|flow| NetpolRefusedFlow {
                        direction: match flow.direction {
                            Direction::Ingress => "ingress",
                            Direction::Egress => "egress",
                        }
                        .to_string(),
                        peer: flow.peer.to_string(),
                        protocol: flow.protocol,
                        port: flow.port,
                        already_refused: flow.already_refused,
                        flows: flow.flows,
                    })
                    .collect(),
            })
            .collect(),
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `POST /api/v1/netpol/replay` - what proposed policies would have refused.
///
/// Changes nothing: the proposal is compiled beside the policies in force
/// and the connections this node tracks are put to both.
#[utoipa::path(
    post, path = "/api/v1/netpol/replay",
    tag = "NetworkPolicy",
    request_body = NetpolReplayRequest,
    responses((status = 200, description = "What the proposal would have refused, by pod", body = NetpolReplayResponse),
        (status = 400, description = "The manifests are not namespaced NetworkPolicy objects", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "Network policy or connection tracking is off on this node", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn replay_netpol(
    State(state): State<Arc<AppState>>,
    Json(body): Json<NetpolReplayRequest>,
) -> Result<Json<NetpolReplayResponse>, ApiError> {
    let replay = state.netpol_replay.load_full().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "network policy is not read on this node: it is off, its hooks did not \
                  attach, or the agent was built without Kubernetes support"
            .to_string(),
    })?;
    let ct = state.conntrack_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "Conntrack not enabled".to_string(),
    })?;
    if !ct.read().await.enabled() {
        return Err(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "connection tracking is off, so there are no flows to replay".to_string(),
        });
    }
    let limit = body
        .limit
        .unwrap_or(DEFAULT_REPLAY_FLOWS)
        .min(MAX_REPLAY_FLOWS);
    // The table is read and both policy sets compiled off the async worker:
    // the read blocks and the compile is proportional to the cluster.
    let ct = Arc::clone(ct);
    let manifests = body.manifests;
    let report = brokered("network policy replay", move || {
        let connections =
            ct.blocking_read()
                .get_connections(limit)
                .map_err(|e| ApiError::Internal {
                    message: format!("conntrack query failed: {e}"),
                })?;
        replay
            .replay(&manifests, &connections)
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_MANIFESTS",
                message: e.to_string(),
            })
    })
    .await
    .map_err(|message| ApiError::Internal { message })??;
    Ok(Json(replay_response(report)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::netpol::{RefusedFlow, WorkloadReplay};

    #[test]
    fn the_report_reads_as_the_dashboard_and_cli_show_it() {
        let response = replay_response(ReplayReport {
            flows: 3,
            judged: 2,
            newly_refused: 1,
            still_refused: 0,
            workloads: vec![WorkloadReplay {
                namespace: "shop".into(),
                pod: "api-1".into(),
                refused: vec![RefusedFlow {
                    direction: Direction::Egress,
                    peer: "10.96.0.20"
                        .parse()
                        .unwrap_or(std::net::Ipv4Addr::LOCALHOST.into()),
                    protocol: 6,
                    port: 80,
                    already_refused: false,
                    flows: 1,
                }],
            }],
        });
        let flow = &response.workloads[0].refused[0];
        assert_eq!(flow.direction, "egress");
        assert_eq!(flow.peer, "10.96.0.20");
        assert_eq!(response.newly_refused, 1);
    }
}
