use std::sync::Arc;

use application::exposure_service::Listener;
use application::package_inventory_service::PackageInventoryReport;
use axum::Json;
use axum::extract::State;
use domain::inventory::{Origin, behind};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::package_inventory_handler::{OwnerBody, owner_body};
use super::state::AppState;

/// One listener and the packages behind it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListeningBody {
    pub address: String,
    pub port: u16,
    /// `tcp` or `udp`.
    pub protocol: &'static str,
    /// `all_addresses`, `address` or `loopback`.
    pub scope: &'static str,
    /// The process that bound it.
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// The pod holding it, as `namespace/name`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// `exposed_used`, `exposed_unused`, `exposed_unmeasured`,
    /// `closed_by_policy` or `loopback_only`, as on the listeners route.
    pub class: &'static str,
    /// Who the policy lets reach it: `anywhere`, `private_only` when every
    /// source let through lies in a private or link-local range,
    /// `blocked` or `loopback`.
    pub origin: &'static str,
    /// The sources let through, when only some are.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub allowed_from: Vec<String>,
    /// TCP connections accepted on it since the hooks attached; absent for
    /// UDP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted: Option<u64>,
    /// Whether the files its process maps were read. When not, the two
    /// lists below are unknown rather than empty.
    pub mapped_read: bool,
    /// The packages owning a file its process maps, each once.
    pub packages: Vec<OwnerBody>,
    /// Files its process maps that no package in its root owns.
    pub unowned: Vec<String>,
}

/// Every listener with the packages its process maps.
#[derive(Debug, Serialize, ToSchema)]
pub struct ListeningResponse {
    /// Whether the socket hooks are attached.
    pub listeners_read: bool,
    /// Whether the package inventory is read.
    pub inventory_read: bool,
    /// When the mapped files were last read, nanoseconds since the epoch,
    /// `0` before the first.
    pub scanned_at_ns: u64,
    pub listeners: Vec<ListeningBody>,
}

#[utoipa::path(
    get, path = "/api/v1/surface/listening",
    tag = "Operations",
    responses((status = 200, description = "Every listener on the node with the packages its process maps, whether it took traffic and who the policy lets reach it", body = ListeningResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_listening(State(state): State<Arc<AppState>>) -> Json<ListeningResponse> {
    let listeners = match state.exposure.load_full() {
        Some(service) => {
            let posture = state.firewall_service.read().await.posture();
            service.listeners(&posture)
        }
        None => None,
    };
    let report = state.package_inventory.load_full().map(|s| s.report());
    Json(listening_response(listeners, report.as_deref()))
}

/// The body of the route from a reading of the listeners and of the
/// inventory, each `None` when it is not read.
#[must_use]
pub fn listening_response(
    listeners: Option<Vec<Listener>>,
    report: Option<&PackageInventoryReport>,
) -> ListeningResponse {
    ListeningResponse {
        listeners_read: listeners.is_some(),
        inventory_read: report.is_some(),
        scanned_at_ns: report.map_or(0, |r| r.scanned_at_ns),
        listeners: listeners
            .unwrap_or_default()
            .iter()
            .map(|l| listening(l, report))
            .collect(),
    }
}

fn listening(listener: &Listener, report: Option<&PackageInventoryReport>) -> ListeningBody {
    let w = &listener.workload;
    let found = report
        .map(|r| behind(&r.sweep.loaded, w.pid))
        .unwrap_or_default();
    ListeningBody {
        address: listener.address.to_string(),
        port: listener.port,
        protocol: listener.protocol.as_str(),
        scope: listener.scope.as_str(),
        pid: w.pid,
        executable: w.exe.clone(),
        container: w.container.clone(),
        pod: match (&w.namespace, &w.pod) {
            (Some(ns), Some(pod)) => Some(format!("{ns}/{pod}")),
            (None, Some(pod)) => Some(pod.clone()),
            _ => None,
        },
        class: listener.class.as_str(),
        origin: Origin::of(listener.scope, &listener.reach).as_str(),
        allowed_from: listener.reach.allowed_from.clone(),
        accepted: listener.accepted,
        mapped_read: found.read,
        packages: found.packages.iter().map(owner_body).collect(),
        unowned: found.unowned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::exposure::entity::{ExposureClass, ListenerProtocol, ListenerScope};
    use domain::exposure::reach::{Reach, ReachDecision};
    use domain::inventory::{
        DatabaseOutcome, DatabaseReading, InventorySweep, MappedObject, Package, PackageManager,
        PackageState, ProcessObjects, RootInventory, RootScope, loaded_objects,
    };
    use domain::workload::entity::{Workload, WorkloadSource};
    use std::net::{IpAddr, Ipv4Addr};

    fn listener(pid: u32, port: u16, allowed_from: &[&str], accepted: u64) -> Listener {
        let mut workload = Workload::new(pid, WorkloadSource::Socket).unwrap();
        workload.exe = Some("/usr/sbin/nginx".into());
        Listener {
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port,
            protocol: ListenerProtocol::Tcp,
            scope: ListenerScope::AllAddresses,
            sockets: 1,
            bound_at_ns: 1,
            workload,
            reach: Reach {
                open: true,
                allowed_from: allowed_from.iter().map(ToString::to_string).collect(),
                decided_by: ReachDecision::DefaultPolicy { drop: true },
            },
            accepted: Some(accepted),
            last_accepted_at_ns: None,
            class: ExposureClass::of(ListenerScope::AllAddresses, true, Some(accepted)),
        }
    }

    fn report() -> PackageInventoryReport {
        let roots = vec![RootInventory {
            scope: RootScope::Host,
            pid: 1,
            databases: vec![DatabaseReading {
                manager: PackageManager::Dpkg,
                path: "/var/lib/dpkg/status".into(),
                outcome: DatabaseOutcome::Read {
                    packages: vec![Package {
                        manager: PackageManager::Dpkg,
                        name: "nginx-core".into(),
                        version: "1.26.3-3".into(),
                        arch: None,
                        state: PackageState::Installed,
                        files: Some(vec!["/usr/sbin/nginx".into()]),
                    }],
                },
            }],
            error: None,
        }];
        let processes = [ProcessObjects {
            pid: 80,
            root_pid: Some(1),
            objects: vec![
                Arc::new(MappedObject {
                    dev: 1,
                    ino: 1,
                    path: "/usr/sbin/nginx".into(),
                    deleted: false,
                }),
                Arc::new(MappedObject {
                    dev: 1,
                    ino: 2,
                    path: "/opt/lua/module.so".into(),
                    deleted: false,
                }),
            ],
        }];
        let loaded = loaded_objects(&roots, &processes);
        PackageInventoryReport {
            sweep: InventorySweep {
                roots,
                loaded,
                ..InventorySweep::default()
            },
            scanned_at_ns: 5,
            error: None,
        }
    }

    #[test]
    fn a_listener_names_the_packages_behind_it_and_who_may_reach_it() {
        let report = report();
        let json = serde_json::to_value(listening_response(
            Some(vec![
                listener(80, 443, &[], 12),
                listener(90, 8080, &["10.0.0.0/8"], 0),
            ]),
            Some(&report),
        ))
        .unwrap();
        assert_eq!(json["listeners_read"], true);
        assert_eq!(json["inventory_read"], true);
        let web = &json["listeners"][0];
        assert_eq!(web["origin"], "anywhere");
        assert_eq!(web["class"], "exposed_used");
        assert_eq!(web["mapped_read"], true);
        assert_eq!(web["packages"][0]["name"], "nginx-core");
        assert_eq!(web["unowned"][0], "/opt/lua/module.so");
        let internal = &json["listeners"][1];
        assert_eq!(internal["origin"], "private_only");
        assert_eq!(internal["class"], "exposed_unused");
        assert_eq!(internal["mapped_read"], false);
        assert_eq!(internal["packages"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn nothing_read_says_so_on_both_halves() {
        let json = serde_json::to_value(listening_response(None, None)).unwrap();
        assert_eq!(json["listeners_read"], false);
        assert_eq!(json["inventory_read"], false);
        let json = serde_json::to_value(listening_response(
            Some(vec![listener(80, 443, &[], 1)]),
            None,
        ))
        .unwrap();
        assert_eq!(json["listeners"][0]["mapped_read"], false);
    }
}
