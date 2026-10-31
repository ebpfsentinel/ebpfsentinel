use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::raw_socket::FilterState;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// One packet socket open on the node.
#[derive(Debug, Serialize, ToSchema)]
pub struct RawSocketBody {
    /// The socket's inode, unique within its network namespace.
    pub inode: u64,
    /// `raw` when the holder sees link-layer headers, `dgram` when the
    /// kernel strips them.
    pub kind: &'static str,
    /// The protocol the socket receives, `all` for every one.
    pub protocol: String,
    /// The interface it is bound to, `any` when it is bound to none.
    pub interface: String,
    /// The user that opened it.
    pub uid: u32,
    /// The network namespace it lives in, as an inode number.
    pub netns: u64,
    /// Whether that namespace is the host's.
    pub host_netns: bool,
    /// A process holding it, absent when none could be found.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// That process's executable, where it resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// The container holding it, where it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// The pod holding it, as `namespace/name`, where it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// `absent` when no filter is attached, `classic` when one is, and
    /// `unknown` when the kernel withheld the answer.
    pub filter: &'static str,
    /// The length of the attached classic filter, in instructions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter_instructions: Option<u32>,
}

/// The packet sockets on this node.
#[derive(Debug, Serialize, ToSchema)]
pub struct RawSocketsResponse {
    /// Whether the inventory is being read.
    pub reading: bool,
    /// Where the readings come from: `warden` or `local`. Absent when the
    /// inventory is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    /// When the last reading was made, in nanoseconds since the epoch, `0`
    /// before the first.
    pub scanned_at_ns: u64,
    /// Why the last reading failed. The sockets are then those of the
    /// reading before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub sockets: Vec<RawSocketBody>,
}

/// `GET /api/v1/ebpf/raw-sockets` - who else reads the node's traffic.
#[utoipa::path(
    get, path = "/api/v1/ebpf/raw-sockets",
    tag = "Operations",
    responses((status = 200, description = "Packet sockets open on the node, their holder and their filter", body = RawSocketsResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_raw_sockets(State(state): State<Arc<AppState>>) -> Json<RawSocketsResponse> {
    let Some(watcher) = state.raw_sockets.load_full() else {
        return Json(RawSocketsResponse {
            reading: false,
            source: None,
            scanned_at_ns: 0,
            last_error: None,
            sockets: Vec::new(),
        });
    };
    let inventory = watcher.inventory();
    Json(RawSocketsResponse {
        reading: true,
        source: Some(watcher.source()),
        scanned_at_ns: inventory.scanned_at_ns,
        last_error: inventory.error.clone(),
        sockets: inventory
            .sockets
            .iter()
            .map(|entry| body(&entry.socket, entry.workload.as_ref()))
            .collect(),
    })
}

fn body(
    socket: &domain::raw_socket::RawSocket,
    workload: Option<&domain::workload::entity::Workload>,
) -> RawSocketBody {
    let (filter, filter_instructions) = match socket.filter {
        FilterState::Unknown => ("unknown", None),
        FilterState::Absent => ("absent", None),
        FilterState::Classic { instructions } => ("classic", Some(instructions)),
    };
    RawSocketBody {
        inode: socket.inode,
        kind: socket.kind.as_str(),
        protocol: socket.protocol_name(),
        interface: socket.interface_label(),
        uid: socket.uid,
        netns: socket.netns,
        host_netns: socket.host_netns,
        pid: workload.map(|w| w.pid).or(socket.pid),
        executable: workload.and_then(|w| w.exe.clone()),
        container: workload.and_then(|w| w.container.clone()),
        pod: workload.and_then(|w| match (&w.namespace, &w.pod) {
            (Some(ns), Some(pod)) => Some(format!("{ns}/{pod}")),
            (None, Some(pod)) => Some(pod.clone()),
            _ => None,
        }),
        filter,
        filter_instructions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::raw_socket::{RawSocket, RawSocketKind};

    fn socket(filter: FilterState) -> RawSocket {
        RawSocket {
            inode: 7,
            kind: RawSocketKind::Raw,
            protocol: 0x0003,
            ifindex: 0,
            interface: None,
            uid: 0,
            netns: 1,
            host_netns: true,
            pid: Some(42),
            filter,
        }
    }

    #[test]
    fn a_classic_filter_carries_its_length_and_an_absent_one_does_not() {
        let json = serde_json::to_value(body(
            &socket(FilterState::Classic { instructions: 12 }),
            None,
        ))
        .unwrap_or_default();
        assert_eq!(json["filter"], "classic");
        assert_eq!(json["filter_instructions"], 12);
        assert_eq!(json["pid"], 42);
        let json =
            serde_json::to_value(body(&socket(FilterState::Absent), None)).unwrap_or_default();
        assert_eq!(json["filter"], "absent");
        assert!(json.get("filter_instructions").is_none());
        assert!(json.get("executable").is_none());
    }
}
