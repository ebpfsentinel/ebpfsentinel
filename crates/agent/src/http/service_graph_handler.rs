use std::sync::Arc;

use adapters::ebpf::ringbuf_observer::boottime_now_ns;
use axum::Json;
use axum::extract::{Query, State};
use domain::l7::service_graph::{
    DEFAULT_MAX_EDGES_PER_MINUTE, EdgeCounts, EdgeKey, GRAPH_MINUTES, GraphEnd, GraphReading,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

/// The window a reading covers when none is asked for.
const DEFAULT_MINUTES: u64 = 15;

#[derive(Debug, Deserialize, IntoParams)]
pub struct ServiceGraphParams {
    /// How many minutes back the reading covers, the current one included,
    /// from 1 to 60. Defaults to 15.
    pub minutes: Option<u64>,
}

/// One end of a call.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceEndBody {
    /// The service this node named the end as. Absent when the process at
    /// that end does not run on this node, so only its address is known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    pub address: String,
}

/// Who called whom over the window, and how it went.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceEdgeBody {
    pub client: ServiceEndBody,
    pub server: ServiceEndBody,
    pub server_port: u16,
    /// `http`, `redis`, `postgres`, `mysql` or `dns-tcp`.
    pub protocol: String,
    /// The side of the connection this node was on: `server` when the
    /// server process runs here, `client` when only the client does,
    /// `transit` when neither does. A request whose two ends both run here
    /// is counted once, from the server side.
    pub observed_from: String,
    pub requests: u64,
    /// Answered with a failure the protocol states.
    pub errors: u64,
    /// Never answered within the timeout.
    pub unanswered: u64,
    /// Requests answered, which are the ones timed.
    pub answered: u64,
    /// Sum of the answered requests' durations, request to first answer
    /// byte, in nanoseconds. Divided by `answered` it is the mean.
    pub duration_ns_sum: u64,
}

/// The service graph seen from this node.
#[derive(Debug, Serialize, ToSchema)]
pub struct ServiceGraphResponse {
    pub minutes: u64,
    /// Requests left out because their minute already held as many edges
    /// as `max_edges_per_minute`.
    pub dropped: u64,
    pub max_edges_per_minute: usize,
    pub edges: Vec<ServiceEdgeBody>,
}

fn end(end: GraphEnd) -> ServiceEndBody {
    ServiceEndBody {
        service: end.service,
        address: end.address.to_string(),
    }
}

fn edge((key, counts): (EdgeKey, EdgeCounts)) -> ServiceEdgeBody {
    ServiceEdgeBody {
        protocol: key.protocol.as_str().to_string(),
        observed_from: key.observer.as_str().to_string(),
        server_port: key.server_port,
        client: end(key.client),
        server: end(key.server),
        requests: counts.requests,
        errors: counts.errors,
        unanswered: counts.unanswered,
        answered: counts.answered,
        duration_ns_sum: counts.duration_ns_sum,
    }
}

fn response(reading: GraphReading) -> ServiceGraphResponse {
    ServiceGraphResponse {
        minutes: reading.minutes,
        dropped: reading.dropped,
        max_edges_per_minute: DEFAULT_MAX_EDGES_PER_MINUTE,
        edges: reading.edges.into_iter().map(edge).collect(),
    }
}

/// `GET /api/v1/services/graph` - who called whom over the last minutes.
#[utoipa::path(
    get, path = "/api/v1/services/graph",
    tag = "Services",
    params(ServiceGraphParams),
    responses((status = 200, description = "Service graph", body = ServiceGraphResponse),
        (status = 400, description = "Window out of range", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "The L7 dispatcher is not running", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn service_graph(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ServiceGraphParams>,
) -> Result<Json<ServiceGraphResponse>, ApiError> {
    let minutes = params.minutes.unwrap_or(DEFAULT_MINUTES);
    if !(1..=GRAPH_MINUTES).contains(&minutes) {
        return Err(ApiError::BadRequest {
            code: "INVALID_WINDOW",
            message: format!("minutes must be between 1 and {GRAPH_MINUTES}"),
        });
    }
    let meter = state.service_graph.load_full().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "the L7 dispatcher is not running on this node".to_string(),
    })?;
    Ok(Json(response(meter.graph(boottime_now_ns(), minutes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::red::{RedOutcome, RedProtocol};
    use domain::l7::service_graph::{Observer, ServiceGraph};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn a_reading_maps_onto_the_wire_shape() {
        let mut graph = ServiceGraph::default();
        let key = EdgeKey {
            client: GraphEnd {
                service: None,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            },
            server: GraphEnd {
                service: Some("shop/api".into()),
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
            server_port: 8080,
            protocol: RedProtocol::Postgres,
            observer: Observer::Server,
        };
        graph.record(5, key, RedOutcome::Error, Some(40));
        let body = response(graph.read(5, 1));
        assert_eq!(body.minutes, 1);
        assert_eq!(body.max_edges_per_minute, DEFAULT_MAX_EDGES_PER_MINUTE);
        let json = serde_json::to_value(&body.edges[0]).unwrap_or_default();
        assert_eq!(json["protocol"], "postgres");
        assert_eq!(json["observed_from"], "server");
        assert_eq!(json["server"]["service"], "shop/api");
        assert_eq!(json["server"]["address"], "10.0.0.1");
        assert!(json["client"].get("service").is_none());
        assert_eq!(json["errors"], 1);
        assert_eq!(json["duration_ns_sum"], 40);
    }
}
