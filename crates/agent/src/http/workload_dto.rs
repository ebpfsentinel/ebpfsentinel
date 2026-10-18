//! The workload block as the HTTP API writes it.
//!
//! One DTO, shared by every route that can name a process behind a flow, for
//! the same reason the domain holds one `Workload`: an alert and a connection
//! describing the same process in two spellings is a difference a reader
//! would have to learn rather than read.
//!
//! Absence is carried through unchanged. A transited flow, a socket opened
//! before the hooks attached and a host whose kernel refused them all produce
//! no block at all, so the key is missing from the document instead of
//! holding a pid of zero.

use domain::workload::entity::Workload;
use serde::Serialize;
use utoipa::ToSchema;

/// The process a flow belongs to, where the agent could name one.
#[derive(Serialize, ToSchema)]
pub struct WorkloadResponse {
    /// The process that owns the socket. Never zero: a block exists only
    /// when there is a process to name.
    pub pid: u32,
    /// How the process was reached - `socket` when the kernel's own handle
    /// on the socket answered, `flow` when the five-tuple was matched
    /// against the index of established connections, `process` when the
    /// event already named the task. The first and the third are read, the
    /// second is correlated.
    pub source: String,
    /// The executable path the process table recorded. Forgeable by the
    /// process itself, which is why it is a path and not an identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The real uid of the task when the socket was opened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// cgroup v2 id, as the kernel numbers it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<u64>,
    /// Container id, where the process runs in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Container image, where the runtime enricher read one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Pod name, on a Kubernetes node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// Namespace, on a Kubernetes node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service account the pod runs as, where the enricher read one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    /// systemd unit, for a host process the agent could place in one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// Map a resolved workload onto the wire, or nothing where there was none.
pub fn workload_response(workload: Option<Workload>) -> Option<WorkloadResponse> {
    let w = workload.filter(|w| w.pid != 0)?;
    Some(WorkloadResponse {
        pid: w.pid,
        source: w.source.as_str().to_string(),
        exe: w.exe,
        uid: w.uid,
        cgroup: w.cgroup,
        container: w.container,
        image: w.image,
        pod: w.pod,
        namespace: w.namespace,
        service_account: w.service_account,
        unit: w.unit,
    })
}

#[cfg(test)]
mod tests {
    use domain::workload::entity::WorkloadSource;

    use super::*;

    #[test]
    fn an_unresolved_flow_carries_no_block() {
        assert!(workload_response(None).is_none());
    }

    #[test]
    fn a_block_naming_no_process_never_reaches_the_wire() {
        let mut w = Workload::new(4242, WorkloadSource::Socket).expect("a pid builds a block");
        w.pid = 0;
        assert!(workload_response(Some(w)).is_none());
    }

    #[test]
    fn what_the_node_could_not_add_is_missing_rather_than_empty() {
        let w = Workload::new(4242, WorkloadSource::Flow).expect("a pid builds a block");
        let json = serde_json::to_string(&workload_response(Some(w)).expect("a block"))
            .expect("the block serialises");
        assert_eq!(json, r#"{"pid":4242,"source":"flow"}"#);
    }
}
