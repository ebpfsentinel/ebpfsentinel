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

use domain::workload::entity::{PeerWorkload, Workload, WorkloadAncestry};
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
    /// Digest of the executable, which is what names the bytes rather than
    /// the place: `fsverity-sha256:<hex>` where the kernel measured a file
    /// with fs-verity on, `sha256:<hex>` where the agent read its contents.
    /// Absent where the agent could not open the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe_hash: Option<String>,
    /// The command line, where the operator turned its capture on. The
    /// secret-bearing shapes were removed where argv was read, before it was
    /// stored, so what is here is what every reader of the process table saw.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
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
    /// The processes above this one, where the process table holds any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ancestry: Option<WorkloadAncestryResponse>,
    /// The workload at the other end of the flow, where its address is on
    /// another node of the fleet. Named from the list the console hands this
    /// node, never read off the wire.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerWorkloadResponse>,
}

/// The other end of a flow, as the node holding its address published it.
#[derive(Serialize, ToSchema)]
pub struct PeerWorkloadResponse {
    /// The remote address the name belongs to.
    pub address: String,
    /// Always `remote_list`: a corroboration from the list of remote
    /// identities, never a kernel reading. A list older than a pod's move
    /// names the pod that left.
    pub source: String,
    /// The node holding the address, as the console knows it.
    pub node: String,
    /// What sits behind the address: `host`, `container`, `pod` or `guest`.
    pub kind: String,
    /// The version of the list the name was read from.
    pub list_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<String>,
}

fn peer_response(peer: PeerWorkload) -> PeerWorkloadResponse {
    PeerWorkloadResponse {
        address: peer.address.to_string(),
        source: peer.source.as_str().to_string(),
        node: peer.node,
        kind: peer.kind.as_str().to_string(),
        list_version: peer.list_version,
        container: peer.container,
        image: peer.image,
        pod: peer.pod,
        namespace: peer.namespace,
        service_account: peer.service_account,
        guest: peer.guest,
    }
}

/// One process above the one behind a flow.
#[derive(Serialize, ToSchema)]
pub struct WorkloadAncestorResponse {
    /// The ancestor's pid when it ran.
    pub pid: u32,
    /// The executable path, where the process table read one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The kernel's 16-byte command name.
    pub name: String,
    /// The uid it execed as.
    pub uid: u32,
    /// Kernel monotonic start time in nanoseconds, where the kernel read it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<u64>,
    /// It has exited and is kept because this process descends from it.
    pub exited: bool,
}

/// The chain above the process behind a flow, parent first, at most eight.
#[derive(Serialize, ToSchema)]
pub struct WorkloadAncestryResponse {
    /// Parent first.
    pub ancestors: Vec<WorkloadAncestorResponse>,
    /// The chain goes on past the last ancestor listed.
    pub truncated: bool,
    /// The chain stops at an ancestor that was named and that the table does
    /// not hold, rather than at the root.
    pub incomplete: bool,
}

fn ancestry_response(ancestry: WorkloadAncestry) -> WorkloadAncestryResponse {
    WorkloadAncestryResponse {
        ancestors: ancestry
            .ancestors
            .into_iter()
            .map(|a| WorkloadAncestorResponse {
                pid: a.pid,
                exe: a.exe,
                name: a.name,
                uid: a.uid,
                start_ns: a.start_ns,
                exited: a.exited,
            })
            .collect(),
        truncated: ancestry.truncated,
        incomplete: ancestry.incomplete,
    }
}

/// Map a resolved workload onto the wire, or nothing where there was none.
pub fn workload_response(workload: Option<Workload>) -> Option<WorkloadResponse> {
    let w = workload.filter(|w| w.pid != 0)?;
    Some(WorkloadResponse {
        pid: w.pid,
        source: w.source.as_str().to_string(),
        exe: w.exe,
        exe_hash: w.exe_hash.map(|h| h.to_string()),
        command_line: w.command_line,
        uid: w.uid,
        cgroup: w.cgroup,
        container: w.container,
        image: w.image,
        pod: w.pod,
        namespace: w.namespace,
        service_account: w.service_account,
        unit: w.unit,
        ancestry: w.ancestry.map(ancestry_response),
        peer: w.peer.map(peer_response),
    })
}

#[cfg(test)]
mod tests {
    use domain::workload::entity::WorkloadSource;

    use super::*;

    #[test]
    fn the_peer_half_says_it_came_from_the_list() {
        use domain::identity::IdentityKind;
        use domain::workload::entity::PeerSource;

        let mut w = Workload::new(4242, WorkloadSource::Socket).expect("a pid builds a block");
        w.peer = Some(PeerWorkload {
            address: "10.1.2.3".parse().expect("an address"),
            source: PeerSource::RemoteList,
            node: "node-b".to_string(),
            kind: IdentityKind::Pod,
            list_version: "v7".to_string(),
            container: None,
            image: None,
            pod: Some("db-0".to_string()),
            namespace: Some("shop".to_string()),
            service_account: None,
            guest: None,
        });
        let json = serde_json::to_value(workload_response(Some(w)).expect("a block"))
            .expect("the block serialises");
        assert_eq!(json["source"], "socket");
        assert_eq!(json["peer"]["source"], "remote_list");
        assert_eq!(json["peer"]["node"], "node-b");
        assert_eq!(json["peer"]["kind"], "pod");
        assert_eq!(json["peer"]["address"], "10.1.2.3");
        assert!(json["peer"].get("image").is_none());
    }

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

    #[test]
    fn the_digest_travels_in_its_written_form() {
        use domain::process::digest::ExeHash;

        let written =
            "fsverity-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let mut w = Workload::new(4242, WorkloadSource::Socket).expect("a pid builds a block");
        w.exe_hash = Some(ExeHash::parse(written).expect("a digest"));
        let json = serde_json::to_value(workload_response(Some(w)).expect("a block"))
            .expect("the block serialises");
        assert_eq!(json["exe_hash"], written);
    }

    #[test]
    fn an_ancestry_carries_both_flags_whatever_their_value() {
        use domain::workload::entity::WorkloadAncestor;

        let mut w = Workload::new(4242, WorkloadSource::Socket).expect("a pid builds a block");
        w.ancestry = Some(WorkloadAncestry {
            ancestors: vec![WorkloadAncestor {
                pid: 900,
                exe: Some("/bin/sh".to_string()),
                name: "sh".to_string(),
                uid: 33,
                start_ns: None,
                exited: false,
            }],
            truncated: true,
            incomplete: false,
        });
        let json = serde_json::to_value(workload_response(Some(w)).expect("a block"))
            .expect("the block serialises");
        assert_eq!(json["ancestry"]["ancestors"][0]["exe"], "/bin/sh");
        assert_eq!(json["ancestry"]["ancestors"][0]["exited"], false);
        assert!(json["ancestry"]["ancestors"][0].get("start_ns").is_none());
        assert_eq!(json["ancestry"]["truncated"], true);
        assert_eq!(json["ancestry"]["incomplete"], false);
    }
}
