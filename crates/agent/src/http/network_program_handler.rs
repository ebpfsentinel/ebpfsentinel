use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::error::ErrorBody;
use super::state::AppState;

/// One process holding a program or the link attaching it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProgramHolderBody {
    pub pid: u32,
    /// Its executable, where it resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    /// The container it runs in, where it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// The pod it runs in, as `namespace/name`, where it runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
}

/// One eBPF program on the network path that the agent did not load.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkProgramBody {
    pub prog_id: u32,
    /// The program type, as the kernel names it.
    pub prog_type: String,
    /// The name its loader gave it, at most fifteen bytes.
    pub name: String,
    /// The hash of its instructions, in hex.
    pub tag: String,
    /// `xdp`, `tc_ingress`, `tc_egress`, `tcx_ingress`, `tcx_egress`,
    /// `netkit_primary`, `netkit_peer`, `cgroup`, `netfilter`, `netns`, or
    /// `unplaced` for a program of a network type found on none of them.
    pub hook: &'static str,
    /// Where it runs, as a person reads it.
    pub place: String,
    /// The link attaching it, absent for a legacy attachment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_id: Option<u32>,
    /// The interface index the attachment names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ifindex: Option<u32>,
    /// The host interface carrying it. Absent with an index set, the index
    /// belongs to another network namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// The cgroup a cgroup link sits on, by id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_id: Option<u64>,
    /// The cgroup attach point, the netfilter hook, or the namespace hook.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The uid that loaded it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_by_uid: Option<u32>,
    /// The processes holding it. Empty when only a pin or an attachment
    /// keeps it alive.
    pub holders: Vec<ProgramHolderBody>,
}

/// The eBPF programs on this node's network path, the agent's own set apart.
#[derive(Debug, Serialize, ToSchema)]
pub struct NetworkProgramsResponse {
    /// Whether the inventory is being read.
    pub reading: bool,
    /// Where the readings come from: `warden` or `local`. Absent when the
    /// inventory is off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    /// When the last reading was made, in nanoseconds since the epoch, `0`
    /// before the first.
    pub scanned_at_ns: u64,
    /// Why the last reading failed. The programs are then those of the
    /// reading before.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// How many programs on the network path are the agent's own.
    pub own_programs: usize,
    /// Every other program on the network path.
    pub programs: Vec<NetworkProgramBody>,
}

/// `GET /api/v1/ebpf/foreign-programs` - who else has a program on the
/// network path.
#[utoipa::path(
    get, path = "/api/v1/ebpf/foreign-programs",
    tag = "Operations",
    responses((status = 200, description = "eBPF programs on the network path that the agent did not load, where they run and who holds them", body = NetworkProgramsResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_foreign_programs(
    State(state): State<Arc<AppState>>,
) -> Json<NetworkProgramsResponse> {
    let Some(watcher) = state.network_programs.load_full() else {
        return Json(NetworkProgramsResponse {
            reading: false,
            source: None,
            scanned_at_ns: 0,
            last_error: None,
            own_programs: 0,
            programs: Vec::new(),
        });
    };
    let inventory = watcher.inventory();
    Json(NetworkProgramsResponse {
        reading: true,
        source: Some(watcher.source()),
        scanned_at_ns: inventory.scanned_at_ns,
        last_error: inventory.error.clone(),
        own_programs: inventory.own_programs,
        programs: inventory.programs.iter().map(body).collect(),
    })
}

fn body(entry: &application::network_program_service::NetworkProgramEntry) -> NetworkProgramBody {
    let program = &entry.program;
    NetworkProgramBody {
        prog_id: program.prog_id,
        prog_type: program.prog_type.clone(),
        name: program.name.clone(),
        tag: program.tag.clone(),
        hook: program.hook.as_str(),
        place: program.place(),
        link_id: program.link_id,
        ifindex: program.ifindex,
        interface: program.interface.clone(),
        cgroup_id: program.cgroup_id,
        detail: program.detail.clone(),
        created_by_uid: program.created_by_uid,
        holders: entry
            .holders
            .iter()
            .map(|holder| {
                let workload = holder.workload.as_ref();
                ProgramHolderBody {
                    pid: holder.pid,
                    executable: workload.and_then(|w| w.exe.clone()),
                    container: workload.and_then(|w| w.container.clone()),
                    pod: workload.and_then(|w| match (&w.namespace, &w.pod) {
                        (Some(ns), Some(pod)) => Some(format!("{ns}/{pod}")),
                        (None, Some(pod)) => Some(pod.clone()),
                        _ => None,
                    }),
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use application::network_program_service::{NetworkProgramEntry, ProgramHolder};
    use domain::network_program::{NetworkHook, NetworkProgram};

    #[test]
    fn a_program_in_another_namespace_carries_its_index_and_no_name() {
        let entry = NetworkProgramEntry {
            program: NetworkProgram {
                prog_id: 812,
                prog_type: "sched_cls".to_string(),
                name: "cil_from_container".to_string(),
                tag: "0a1b".to_string(),
                link_id: Some(14),
                hook: NetworkHook::NetkitPeer,
                ifindex: Some(14),
                interface: None,
                cgroup_id: None,
                detail: None,
                created_by_uid: Some(0),
                holders: vec![1312],
            },
            holders: vec![ProgramHolder {
                pid: 1312,
                workload: None,
            }],
        };
        let json = serde_json::to_value(body(&entry)).unwrap_or_default();
        assert_eq!(json["hook"], "netkit_peer");
        assert_eq!(json["ifindex"], 14);
        assert!(json.get("interface").is_none());
        assert_eq!(json["place"], "netkit_peer on #14 (another namespace)");
        assert_eq!(json["holders"][0]["pid"], 1312);
        assert!(json["holders"][0].get("executable").is_none());
    }
}
