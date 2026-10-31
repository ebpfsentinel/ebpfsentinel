use std::sync::Arc;

use application::exposure_service::Listener;
use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// One address and port a process accepts traffic on.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListenerBody {
    /// The bound address, `0.0.0.0` or `::` for every address.
    pub address: String,
    pub port: u16,
    /// `tcp` or `udp`.
    pub protocol: &'static str,
    /// `all_addresses` when bound on every address of the namespace,
    /// `address` for one interface address, `loopback` when nothing off the
    /// node reaches it.
    pub scope: &'static str,
    /// Sockets the process holds on this address and port, more than one
    /// for a server spread over `SO_REUSEPORT`.
    pub sockets: u32,
    /// The process that bound it.
    pub pid: u32,
    /// The user it bound as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// Its executable, where the process table holds it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// The container holding it, where it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// The pod holding it, as `namespace/name`, where it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// The systemd unit holding it, for a host process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// When the first of its sockets was bound, in nanoseconds since boot.
    pub bound_at_boot_ns: u64,
}

/// The sockets this node accepts traffic on, and who bound them.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListenersResponse {
    /// Whether the socket hooks are attached. When they are not, the node's
    /// listeners are unknown rather than absent.
    pub reading: bool,
    /// Widest scope first: every address, then one address, then loopback.
    pub listeners: Vec<ListenerBody>,
}

/// `GET /api/v1/exposure/listeners` - what this node listens on, and who for.
#[utoipa::path(
    get, path = "/api/v1/exposure/listeners",
    tag = "Operations",
    responses((status = 200, description = "Sockets accepting traffic on the node, with the workload that bound each", body = ListenersResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_listeners(State(state): State<Arc<AppState>>) -> Json<ListenersResponse> {
    let listeners = state
        .exposure
        .load_full()
        .and_then(|service| service.listeners());
    Json(response(listeners))
}

fn response(listeners: Option<Vec<Listener>>) -> ListenersResponse {
    let Some(listeners) = listeners else {
        return ListenersResponse {
            reading: false,
            listeners: Vec::new(),
        };
    };
    ListenersResponse {
        reading: true,
        listeners: listeners.iter().map(body).collect(),
    }
}

fn body(listener: &Listener) -> ListenerBody {
    let w = &listener.workload;
    ListenerBody {
        address: listener.address.to_string(),
        port: listener.port,
        protocol: listener.protocol.as_str(),
        scope: listener.scope.as_str(),
        sockets: listener.sockets,
        pid: w.pid,
        uid: w.uid,
        executable: w.exe.clone(),
        container: w.container.clone(),
        pod: match (&w.namespace, &w.pod) {
            (Some(ns), Some(pod)) => Some(format!("{ns}/{pod}")),
            (None, Some(pod)) => Some(pod.clone()),
            _ => None,
        },
        unit: w.unit.clone(),
        bound_at_boot_ns: listener.bound_at_ns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::exposure::entity::{ListenerProtocol, ListenerScope};
    use domain::workload::entity::{Workload, WorkloadSource};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn hooks_not_attached_read_as_unknown_and_a_listener_names_its_scope_and_owner() {
        let json = serde_json::to_value(response(None)).unwrap();
        assert_eq!(json["reading"], false);

        let mut workload = Workload::new(42, WorkloadSource::Socket).unwrap();
        workload.exe = Some("/usr/bin/redis-server".into());
        workload.namespace = Some("cache".into());
        workload.pod = Some("redis-0".into());
        let json = serde_json::to_value(response(Some(vec![Listener {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 6379,
            protocol: ListenerProtocol::Tcp,
            scope: ListenerScope::AllAddresses,
            sockets: 1,
            bound_at_ns: 7,
            workload,
        }])))
        .unwrap();
        assert_eq!(json["reading"], true);
        let row = &json["listeners"][0];
        assert_eq!(row["address"], "0.0.0.0");
        assert_eq!(row["scope"], "all_addresses");
        assert_eq!(row["protocol"], "tcp");
        assert_eq!(row["pod"], "cache/redis-0");
        assert_eq!(row["executable"], "/usr/bin/redis-server");
        assert!(row.get("unit").is_none());
    }
}
