use std::sync::Arc;

use application::exposure_service::Listener;
use axum::Json;
use axum::extract::State;
use domain::exposure::reach::ReachDecision;
use domain::firewall::entity::FirewallAction;
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
    /// `exposed_used`, `exposed_unused`, `exposed_unmeasured` (UDP, whose use
    /// is not counted), `closed_by_policy` or `loopback_only`.
    pub class: &'static str,
    /// Whether the packet firewall lets anything off the node through to it.
    pub reachable: bool,
    /// The sources let through, when only some are. Absent means every
    /// source when `reachable`, and none when not.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_from: Vec<String>,
    /// What decided `reachable`: `rule`, `default_policy`,
    /// `firewall_not_enforcing` (disabled or in alert mode) or `loopback`.
    pub decided_by: &'static str,
    /// The deciding rule, when `decided_by` is `rule`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// TCP connections accepted on it since the hooks attached. Absent for
    /// UDP, which has no handshake to count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<u64>,
    /// When the last of them was accepted, in nanoseconds since boot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_accepted_boot_ns: Option<u64>,
}

/// The sockets this node accepts traffic on, who bound them, who may reach
/// them and whether anybody did.
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
    responses((status = 200, description = "Sockets accepting traffic on the node, with the workload that bound each, the sources the firewall lets through and the connections accepted", body = ListenersResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_listeners(State(state): State<Arc<AppState>>) -> Json<ListenersResponse> {
    let Some(service) = state.exposure.load_full() else {
        return Json(listeners_response(None));
    };
    let posture = state.firewall_service.read().await.posture();
    Json(listeners_response(service.listeners(&posture)))
}

/// The body of the route from a reading of the listeners, `None` when the
/// socket hooks are not attached. Shared with the enterprise agent, so one
/// query answers in the same words whichever edition serves it.
#[must_use]
pub fn listeners_response(listeners: Option<Vec<Listener>>) -> ListenersResponse {
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
        class: listener.class.as_str(),
        reachable: listener.reach.open,
        allowed_from: listener.reach.allowed_from.clone(),
        decided_by: match listener.reach.decided_by {
            ReachDecision::Rule { .. } => "rule",
            ReachDecision::DefaultPolicy { .. } => "default_policy",
            ReachDecision::NotEnforcing => "firewall_not_enforcing",
            ReachDecision::Loopback => "loopback",
        },
        rule: match &listener.reach.decided_by {
            ReachDecision::Rule { id, action } => Some(format!("{id} ({})", action_name(*action))),
            _ => None,
        },
        accepted: listener.accepted,
        last_accepted_boot_ns: listener.last_accepted_at_ns,
    }
}

fn action_name(action: FirewallAction) -> &'static str {
    match action {
        FirewallAction::Allow => "allow",
        FirewallAction::Deny => "deny",
        FirewallAction::Log => "log",
        FirewallAction::Reject => "reject",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::RuleId;
    use domain::exposure::entity::{ExposureClass, ListenerProtocol, ListenerScope};
    use domain::exposure::reach::Reach;
    use domain::workload::entity::{Workload, WorkloadSource};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn hooks_not_attached_read_as_unknown_and_a_listener_names_its_scope_and_owner() {
        let json = serde_json::to_value(listeners_response(None)).unwrap();
        assert_eq!(json["reading"], false);

        let mut workload = Workload::new(42, WorkloadSource::Socket).unwrap();
        workload.exe = Some("/usr/bin/redis-server".into());
        workload.namespace = Some("cache".into());
        workload.pod = Some("redis-0".into());
        let json = serde_json::to_value(listeners_response(Some(vec![Listener {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: 6379,
            protocol: ListenerProtocol::Tcp,
            scope: ListenerScope::AllAddresses,
            sockets: 1,
            bound_at_ns: 7,
            workload,
            reach: Reach {
                open: true,
                allowed_from: vec!["10.0.0.0/8".into()],
                decided_by: ReachDecision::Rule {
                    id: RuleId("drop-rest".into()),
                    action: FirewallAction::Deny,
                },
            },
            accepted: Some(0),
            last_accepted_at_ns: None,
            class: ExposureClass::ExposedUnused,
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
        assert_eq!(row["class"], "exposed_unused");
        assert_eq!(row["reachable"], true);
        assert_eq!(row["allowed_from"][0], "10.0.0.0/8");
        assert_eq!(row["decided_by"], "rule");
        assert_eq!(row["rule"], "drop-rest (deny)");
        assert_eq!(row["accepted"], 0);
        assert!(row.get("last_accepted_boot_ns").is_none());
    }
}
