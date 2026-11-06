use std::collections::HashMap;
use std::sync::Arc;

use adapters::ebpf::ringbuf_observer::{boottime_now_ns, boottime_to_epoch_ns};
use axum::Json;
use axum::extract::{Query, State};
use domain::l7::service_graph::{
    DEFAULT_MAX_EDGES_PER_MINUTE, EdgeCounts, EdgeKey, GRAPH_MINUTES, GraphEnd, GraphReading,
    Observer,
};
use domain::tcp_health::{RTT_FIRST_BOUND_US, RttPair, RttSide, TcpRtt};
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

/// The smoothed TCP round-trip times sampled on an edge's connections over
/// the window: once when each was established and once when it left that
/// state.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoundTripBody {
    /// Samples per bucket, not cumulative. Bucket `i` closes at
    /// `first_bound_us` times two to the power `i`; the last one has no
    /// bound. Two readings add bucket by bucket.
    pub buckets: Vec<u64>,
    /// Upper bound of the first bucket, in microseconds.
    pub first_bound_us: u64,
    /// Sum of every sample, in microseconds.
    pub sum_us: u64,
    pub count: u64,
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
    /// The TCP round-trip time between the two ends, read off the socket on
    /// the side this node observed from. Absent when TCP health is off, on
    /// a transit edge, or when no connection of the pair was sampled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub round_trip: Option<RoundTripBody>,
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

/// The round-trip samples a service map edge carries, found by its two
/// addresses, its port and the side it was observed from.
fn round_trip(key: &EdgeKey, round_trips: &HashMap<RttPair, TcpRtt>) -> Option<RoundTripBody> {
    let measured_from = match key.observer {
        Observer::Server => RttSide::Server,
        Observer::Client => RttSide::Client,
        Observer::Transit => return None,
    };
    let rtt = round_trips.get(&RttPair {
        client: key.client.address,
        server: key.server.address,
        server_port: key.server_port,
        measured_from,
    })?;
    Some(RoundTripBody {
        buckets: rtt.buckets.to_vec(),
        first_bound_us: RTT_FIRST_BOUND_US,
        sum_us: rtt.sum_us,
        count: rtt.count,
    })
}

fn edge(
    (key, counts): (EdgeKey, EdgeCounts),
    round_trips: &HashMap<RttPair, TcpRtt>,
) -> ServiceEdgeBody {
    ServiceEdgeBody {
        round_trip: round_trip(&key, round_trips),
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

fn response(reading: GraphReading, round_trips: &HashMap<RttPair, TcpRtt>) -> ServiceGraphResponse {
    ServiceGraphResponse {
        minutes: reading.minutes,
        dropped: reading.dropped,
        max_edges_per_minute: DEFAULT_MAX_EDGES_PER_MINUTE,
        edges: reading
            .edges
            .into_iter()
            .map(|e| edge(e, round_trips))
            .collect(),
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
    // The round trips are polled on the boot clock, while an L7 event has its
    // kernel stamp moved onto the wall clock when it is drained, so each
    // reading is asked on the clock it was recorded on.
    let boot_now = boottime_now_ns();
    let round_trips = state
        .tcp_health
        .load_full()
        .map(|tcp| tcp.round_trips(boot_now, minutes))
        .unwrap_or_default();
    let graph = meter.graph(boottime_to_epoch_ns(boot_now), minutes);
    Ok(Json(response(graph, &round_trips)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::l7::red::{RedOutcome, RedProtocol};
    use domain::l7::service_graph::ServiceGraph;
    use domain::tcp_health::RTT_BUCKETS;
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
        graph.record(5, key.clone(), RedOutcome::Error, Some(40));
        let mut rtt = TcpRtt {
            buckets: [0; RTT_BUCKETS],
            sum_us: 300,
            count: 2,
        };
        rtt.buckets[2] = 2;
        let pair = |measured_from| RttPair {
            client: key.client.address,
            server: key.server.address,
            server_port: 8080,
            measured_from,
        };
        // The client side's sample of the same connection is not this
        // edge's: it was observed from the server.
        let round_trips = HashMap::from([
            (pair(RttSide::Server), rtt),
            (pair(RttSide::Client), TcpRtt::default()),
        ]);
        let body = response(graph.read(5, 1), &round_trips);
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
        assert_eq!(json["round_trip"]["count"], 2);
        assert_eq!(json["round_trip"]["sum_us"], 300);
        assert_eq!(json["round_trip"]["first_bound_us"], 64);
        assert_eq!(json["round_trip"]["buckets"][2], 2);
        assert_eq!(
            json["round_trip"]["buckets"].as_array().map(Vec::len),
            Some(16)
        );
    }

    #[test]
    fn a_transit_edge_or_an_unsampled_pair_carries_no_round_trip() {
        let mut graph = ServiceGraph::default();
        let key = |observer| EdgeKey {
            client: GraphEnd {
                service: None,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            },
            server: GraphEnd {
                service: None,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            },
            server_port: 80,
            protocol: RedProtocol::Http,
            observer,
        };
        graph.record(5, key(Observer::Transit), RedOutcome::Ok, Some(1));
        graph.record(5, key(Observer::Client), RedOutcome::Ok, Some(1));
        let rtt = TcpRtt {
            count: 1,
            ..TcpRtt::default()
        };
        let round_trips = HashMap::from([(
            RttPair {
                client: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                server_port: 80,
                measured_from: RttSide::Server,
            },
            rtt,
        )]);
        let body = response(graph.read(5, 1), &round_trips);
        assert_eq!(body.edges.len(), 2);
        for edge in &body.edges {
            assert!(edge.round_trip.is_none(), "{}", edge.observed_from);
        }
    }
}
