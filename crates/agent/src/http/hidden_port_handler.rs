use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::hidden::{HiddenPort, PortSweepCounts};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// One port the kernel holds and no listing shows.
#[derive(Debug, Serialize, ToSchema)]
pub struct HiddenPortBody {
    /// The network namespace, as an inode number.
    pub netns: u64,
    /// Whether that namespace is the host's.
    pub host_netns: bool,
    /// `tcp` or `udp`.
    pub transport: &'static str,
    /// The wildcard the refused bind was made on: `0.0.0.0` or `::`.
    pub address: &'static str,
    pub port: u16,
}

/// A namespace that could not be entered, so nothing in it was asked.
#[derive(Debug, Serialize, ToSchema)]
pub struct UnreachableNamespaceBody {
    pub netns: u64,
    pub reason: String,
}

/// How the last sweep reached its result.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct HiddenPortCountsBody {
    /// Network namespaces found.
    pub namespaces: u32,
    /// Namespaces that could not be entered.
    pub unreachable_namespaces: u32,
    /// Binds attempted in the first pass.
    pub probed: u32,
    /// Binds refused for another reason than the port being in use, so the
    /// port was not asked.
    pub unprobed: u32,
    /// Binds refused because the port is in use.
    pub refused: u32,
    /// Refusals a listed listener explains, every member of a
    /// `SO_REUSEPORT` group included.
    pub explained_by_listener: u32,
    /// Refusals only a TCP socket in `TIME_WAIT` explains.
    pub explained_by_time_wait: u32,
    /// Refusals only another bound socket explains, such as an outgoing
    /// connection.
    pub explained_by_other_socket: u32,
    /// Refusals the second reading did not confirm: a socket that came or
    /// went between the two.
    pub unconfirmed: u32,
    /// Ports reported hidden.
    pub hidden: u32,
}

impl From<PortSweepCounts> for HiddenPortCountsBody {
    fn from(c: PortSweepCounts) -> Self {
        Self {
            namespaces: c.namespaces,
            unreachable_namespaces: c.unreachable_namespaces,
            probed: c.probed,
            unprobed: c.unprobed,
            refused: c.refused,
            explained_by_listener: c.explained_by_listener,
            explained_by_time_wait: c.explained_by_time_wait,
            explained_by_other_socket: c.explained_by_other_socket,
            unconfirmed: c.unconfirmed,
            hidden: c.hidden,
        }
    }
}

/// The last comparison of the socket listings with a bind probe.
#[derive(Debug, Serialize, ToSchema)]
pub struct HiddenPortsResponse {
    /// Whether the sweep runs.
    pub reading: bool,
    /// Where the readings come from: `warden` or `local`. Absent when the
    /// sweep is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    /// How many ports each namespace is probed on.
    pub probed_ports: usize,
    /// When the last sweep was made, in nanoseconds since the epoch, `0`
    /// before the first.
    pub scanned_at_ns: u64,
    /// Why the last sweep failed. The result is then the sweep before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub counts: HiddenPortCountsBody,
    pub hidden: Vec<HiddenPortBody>,
    pub unreachable: Vec<UnreachableNamespaceBody>,
}

fn body(port: &HiddenPort) -> HiddenPortBody {
    HiddenPortBody {
        netns: port.netns,
        host_netns: port.host_netns,
        transport: port.transport.as_str(),
        address: port.family.wildcard(),
        port: port.port,
    }
}

/// `GET /api/v1/ebpf/hidden-ports` - ports that refuse a bind and appear in
/// no socket listing.
#[utoipa::path(
    get, path = "/api/v1/ebpf/hidden-ports",
    tag = "Operations",
    responses((status = 200, description = "The last comparison of the socket listings with a bind probe, with what explained each refusal", body = HiddenPortsResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_hidden_ports(State(state): State<Arc<AppState>>) -> Json<HiddenPortsResponse> {
    let Some(watcher) = state.hidden_ports.load_full() else {
        return Json(HiddenPortsResponse {
            reading: false,
            source: None,
            probed_ports: 0,
            scanned_at_ns: 0,
            last_error: None,
            counts: HiddenPortCountsBody::default(),
            hidden: Vec::new(),
            unreachable: Vec::new(),
        });
    };
    let report = watcher.report();
    Json(HiddenPortsResponse {
        reading: true,
        source: Some(watcher.source()),
        probed_ports: watcher.probed_ports(),
        scanned_at_ns: report.scanned_at_ns,
        last_error: report.error.clone(),
        counts: report.sweep.counts.into(),
        hidden: report.sweep.hidden.iter().map(body).collect(),
        unreachable: report
            .sweep
            .unreachable
            .iter()
            .map(|(netns, reason)| UnreachableNamespaceBody {
                netns: *netns,
                reason: reason.clone(),
            })
            .collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::hidden::{PortFamily, Transport};

    #[test]
    fn a_hidden_port_names_its_transport_and_wildcard() {
        let b = body(&HiddenPort {
            netns: 4_026_531_840,
            host_netns: true,
            transport: Transport::Udp,
            family: PortFamily::V6,
            port: 31337,
        });
        assert_eq!((b.transport, b.address, b.port), ("udp", "::", 31337));
    }

    #[test]
    fn the_counts_carry_over_one_for_one() {
        let counts = PortSweepCounts {
            namespaces: 3,
            refused: 9,
            explained_by_time_wait: 2,
            hidden: 1,
            ..PortSweepCounts::default()
        };
        let b = HiddenPortCountsBody::from(counts);
        assert_eq!(
            (b.namespaces, b.refused, b.explained_by_time_wait, b.hidden),
            (3, 9, 2, 1)
        );
    }
}
