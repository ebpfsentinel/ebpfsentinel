//! The workload behind a flow: one block, the same block everywhere.
//!
//! A packet event, a conntrack row, an alert and a SIEM document all answer
//! the same question - which process on this node opened this - and before
//! this block each of them answered it in its own spelling or not at all.
//! There is one type now, built in one place, and every surface either
//! carries it whole or carries nothing.
//!
//! Absence is the design rather than a failure mode. A flow this node only
//! forwarded has no local process, a socket opened before the hooks attached
//! has no recorded opener, and a host that refused the cgroup attach has no
//! table to read: in all three the block is gone from the document, never a
//! pid of zero and never an empty string. One predicate, [`is_absent`],
//! decides that for every format, so no serialiser can disagree with another.

use serde::{Deserialize, Serialize};

use std::net::IpAddr;

use crate::container::entity::{ContainerContext, ContainerInfo, ContainerMetadata};
use crate::identity::IdentityKind;
use crate::identity::remote::RemoteEntry;
use crate::process::engine::Lineage;
use crate::process::entity::ProcessEntry;

/// How good the join is: read off the socket, or matched on the five-tuple.
///
/// The two are not the same claim and a reader is owed the difference. A
/// socket cookie is the kernel's own handle: the task it names is the task
/// that owns that socket, full stop. A five-tuple match says a socket with
/// these endpoints was opened by this task, which is the right answer for a
/// connection read out of the kernel's conntrack table and a weaker one: the
/// tuple could have been reused after the original socket closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadSource {
    /// The socket cookie on the event was found in the kernel's socket table.
    Socket,
    /// No cookie was available, so the five-tuple was matched against the
    /// index the socket hooks keep of established connections.
    Flow,
    /// The event already named a process and the rest was filled in from the
    /// process table, which is how a DLP write arrives: the uprobe knows its
    /// own thread without any socket being involved.
    Process,
}

impl WorkloadSource {
    /// The word an API response, an alert and a SIEM document use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Socket => "socket",
            Self::Flow => "flow",
            Self::Process => "process",
        }
    }

    /// Whether the join was read from the kernel's own handle on the socket
    /// rather than correlated after the fact.
    #[must_use]
    pub fn is_read(self) -> bool {
        matches!(self, Self::Socket | Self::Process)
    }
}

impl std::fmt::Display for WorkloadSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One process above the one behind a flow.
///
/// What a reader needs to tell a shell started by `sshd` from one started by
/// `nginx`: the executable where the table read one, the kernel's name for
/// the task otherwise, who it ran as and when it started. The start time is
/// what keeps the pid meaningful after it is handed to somebody else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadAncestor {
    /// The ancestor's pid when it ran.
    pub pid: u32,
    /// The executable path, where the process table read one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The kernel's 16-byte command name, always present.
    pub name: String,
    /// The uid it execed as.
    pub uid: u32,
    /// Kernel monotonic start time, where the kernel read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ns: Option<u64>,
    /// Whether it has exited and is kept because this process descends from
    /// it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exited: bool,
}

/// The chain above the process behind a flow, parent first.
///
/// Bounded at eight. The two flags say why it stops where it does, when that
/// is not the root: `truncated` when the chain went on past the bound,
/// `incomplete` when a named ancestor was never seen by the table or has been
/// dropped from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadAncestry {
    /// Parent first.
    pub ancestors: Vec<WorkloadAncestor>,
    /// The chain goes on past the last ancestor shown.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// The chain stops at an ancestor that was named and that the table does
    /// not hold.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub incomplete: bool,
}

impl WorkloadAncestry {
    /// The parent, which is the first ancestor where there is one.
    #[must_use]
    pub fn parent(&self) -> Option<&WorkloadAncestor> {
        self.ancestors.first()
    }

    /// The chain as one line, for a format whose fields hold text and not
    /// lists: parent first, each ancestor as its pid and its executable, or
    /// its kernel name in brackets where no path was read, joined by ` < `
    /// so the line reads from the closest ancestor outwards.
    ///
    /// The uid and the start time are not in it. A format that can nest
    /// carries them per ancestor; this one carries what a correlation rule
    /// matches on.
    #[must_use]
    pub fn chain_text(&self) -> String {
        self.ancestors
            .iter()
            .map(|a| match a.exe.as_deref().filter(|exe| !exe.is_empty()) {
                Some(exe) => format!("{} {exe}", a.pid),
                None => format!("{} [{}]", a.pid, a.name),
            })
            .collect::<Vec<_>>()
            .join(" < ")
    }

    /// The chain a lineage walk found, or nothing where it found nothing to
    /// say.
    #[must_use]
    pub fn from_lineage(lineage: &Lineage) -> Option<Self> {
        if lineage.is_empty() {
            return None;
        }
        Some(Self {
            ancestors: lineage
                .ancestors
                .iter()
                .map(|entry| WorkloadAncestor {
                    pid: entry.pid,
                    exe: entry.identity.path().map(ToOwned::to_owned),
                    name: entry.comm.clone(),
                    uid: entry.uid,
                    start_ns: entry.start_ns,
                    exited: entry.exited_at_ns.is_some(),
                })
                .collect(),
            truncated: lineage.truncated,
            incomplete: lineage.incomplete,
        })
    }
}

/// The workload a flow belongs to.
///
/// `pid` and `source` are the two fields that are never absent, because a
/// block exists only when there is a process to name and a reader must always
/// know how it was named. Everything else is what the node could add: a
/// process table that has not seen the exec gives a pid and nothing more, a
/// host process has no container, and a node outside Kubernetes has no pod.
///
/// There is deliberately no hash of the executable. The process table records
/// the path `/proc/<pid>/exe` answered and says so in its own identity type,
/// and until it can hash the file there is nothing truthful to put in such a
/// field. An always-absent key on the wire would be a promise the agent does
/// not keep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    /// The process that owns the socket. Never zero in a block that exists.
    pub pid: u32,
    /// How the process was reached from the flow.
    pub source: WorkloadSource,
    /// The executable path, where the process table holds one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The command line, where the process table captured one: absent unless
    /// the operator turned the capture on, and redacted of the secret-bearing
    /// shapes before it was ever stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// The real uid of the task at the moment the socket was opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    /// cgroup v2 id, as the kernel numbers it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<u64>,
    /// Container id, where the process runs in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Container image, where a runtime enricher could read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Pod name, on a Kubernetes node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// Namespace, on a Kubernetes node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Service account the pod runs as, where the enricher read one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    /// systemd unit, for a host process the agent could place in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// The processes above this one, where the process table holds any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ancestry: Option<WorkloadAncestry>,
    /// The workload at the other end of the flow, where its address is on
    /// another node of the fleet. Read from the list the console hands this
    /// node rather than from the kernel, and marked so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<PeerWorkload>,
}

/// Where the other end of a flow was named.
///
/// One way today, and stated on every block anyway: everything else in a
/// workload block is this node's own reading, and the peer half is what
/// another node said about an address, relayed by the console. A reader
/// weighing an alert is owed that difference in the document itself rather
/// than in the documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerSource {
    /// The address was in the list of remote identities this node holds.
    /// A corroboration: the node holding the address published it, nothing
    /// on the wire carried it, and a list older than a pod's move names the
    /// pod that left.
    RemoteList,
}

impl PeerSource {
    /// The word an API response, an alert and a SIEM document use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RemoteList => "remote_list",
        }
    }
}

/// The workload behind the remote address of a flow, as another node
/// published it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerWorkload {
    /// The remote address the name belongs to.
    pub address: IpAddr,
    /// How the name was reached. Never a kernel reading.
    pub source: PeerSource,
    /// The node holding the address, as the console knows it.
    pub node: String,
    /// What sits behind the address.
    pub kind: IdentityKind,
    /// The version of the list the name was read from.
    pub list_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<String>,
}

/// One field of the peer half on a flat export: the dotted name the OTLP and
/// JSON lines exports use, the camel-case name the SIEM line uses, and the
/// value where there is one.
pub type PeerField = (&'static str, &'static str, Option<String>);

impl PeerWorkload {
    /// The peer half flattened for an export that has no nesting. The source
    /// comes first so a reader meets the word saying the name was relayed
    /// before the name itself.
    #[must_use]
    pub fn fields(&self) -> [PeerField; 11] {
        [
            (
                "ebpfsentinel.workload.peer.source",
                "workloadPeerSource",
                Some(self.source.as_str().to_string()),
            ),
            (
                "ebpfsentinel.workload.peer.address",
                "workloadPeerAddress",
                Some(self.address.to_string()),
            ),
            (
                "ebpfsentinel.workload.peer.node",
                "workloadPeerNode",
                Some(self.node.clone()),
            ),
            (
                "ebpfsentinel.workload.peer.kind",
                "workloadPeerKind",
                Some(self.kind.as_str().to_string()),
            ),
            (
                "ebpfsentinel.workload.peer.list_version",
                "workloadPeerListVersion",
                Some(self.list_version.clone()),
            ),
            (
                "ebpfsentinel.workload.peer.container",
                "workloadPeerContainer",
                self.container.clone(),
            ),
            (
                "ebpfsentinel.workload.peer.image",
                "workloadPeerImage",
                self.image.clone(),
            ),
            (
                "ebpfsentinel.workload.peer.pod",
                "workloadPeerPod",
                self.pod.clone(),
            ),
            (
                "ebpfsentinel.workload.peer.namespace",
                "workloadPeerNamespace",
                self.namespace.clone(),
            ),
            (
                "ebpfsentinel.workload.peer.service_account",
                "workloadPeerServiceAccount",
                self.service_account.clone(),
            ),
            (
                "ebpfsentinel.workload.peer.guest",
                "workloadPeerGuest",
                self.guest.clone(),
            ),
        ]
    }

    /// The peer half for one entry of the list carrying `version`.
    ///
    /// Labels are left behind on purpose: a block riding every alert and
    /// every flow names the workload, and the label sets stay on the list
    /// where a rule reads them.
    #[must_use]
    pub fn from_entry(entry: &RemoteEntry, version: &str) -> Self {
        let identity = &entry.identity;
        Self {
            address: identity.address,
            source: PeerSource::RemoteList,
            node: entry.node.clone(),
            kind: identity.kind,
            list_version: version.to_string(),
            container: identity.container.clone(),
            image: identity.image.clone(),
            pod: identity.pod.clone(),
            namespace: identity.namespace.clone(),
            service_account: identity.service_account.clone(),
            guest: identity.guest.clone(),
        }
    }
}

impl Workload {
    /// A block naming nothing but the process and how it was reached.
    ///
    /// Returns `None` for pid zero, which is the whole absence rule in one
    /// place: a caller holding a zero has not resolved anything, and the
    /// alternative is a document claiming the kernel's swapper opened a
    /// connection.
    #[must_use]
    pub fn new(pid: u32, source: WorkloadSource) -> Option<Self> {
        if pid == 0 {
            return None;
        }
        Some(Self {
            pid,
            source,
            exe: None,
            command_line: None,
            uid: None,
            cgroup: None,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            unit: None,
            ancestry: None,
            peer: None,
        })
    }

    /// Fill in everything the process table knows about this pid.
    ///
    /// Only the fields the entry actually carries are set: an entry whose
    /// identity is `unknown` leaves `exe` absent rather than writing the
    /// `comm`, which is sixteen truncated bytes and not a path.
    #[must_use]
    pub fn with_process(mut self, entry: &ProcessEntry) -> Self {
        self.exe = entry.identity.path().map(ToOwned::to_owned);
        self.command_line.clone_from(&entry.command_line);
        self.uid = Some(entry.uid);
        if entry.cgroup_id != 0 {
            self.cgroup = Some(entry.cgroup_id);
        }
        if let Some(container) = entry.container.as_ref() {
            self.fill_container(container);
        }
        self
    }

    /// The chain above the process, from a walk of the process table.
    #[must_use]
    pub fn with_lineage(mut self, lineage: &Lineage) -> Self {
        self.ancestry = WorkloadAncestry::from_lineage(lineage);
        self
    }

    /// Fill in the container fields from a resolved container context.
    #[must_use]
    pub fn with_container(mut self, container: &ContainerContext) -> Self {
        self.fill_container(container);
        self
    }

    /// The uid read from the socket table, which knows it even when the
    /// process table has never seen the exec.
    #[must_use]
    pub fn with_uid(mut self, uid: u32) -> Self {
        self.uid = Some(uid);
        self
    }

    /// The cgroup id read from the socket table.
    #[must_use]
    pub fn with_cgroup(mut self, cgroup_id: u64) -> Self {
        if cgroup_id != 0 {
            self.cgroup = Some(cgroup_id);
        }
        self
    }

    /// The systemd unit a host process was placed in.
    #[must_use]
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        let unit = unit.into();
        if !unit.is_empty() {
            self.unit = Some(unit);
        }
        self
    }

    fn fill_container(&mut self, container: &ContainerContext) {
        if let ContainerInfo::Container { container_id, .. } = &container.info {
            self.container = Some(container_id.clone());
        }
        match container.metadata.as_ref() {
            Some(ContainerMetadata::Docker(docker)) => {
                if !docker.image.is_empty() {
                    self.image = Some(docker.image.clone());
                }
            }
            Some(ContainerMetadata::Kubernetes(k8s)) => {
                if !k8s.pod_name.is_empty() {
                    self.pod = Some(k8s.pod_name.clone());
                }
                if !k8s.namespace.is_empty() {
                    self.namespace = Some(k8s.namespace.clone());
                }
                if !k8s.service_account.is_empty() {
                    self.service_account = Some(k8s.service_account.clone());
                }
            }
            _ => {}
        }
    }
}

/// A pod on another node, named by a list, for the format tests.
#[cfg(test)]
pub(crate) fn sample_peer() -> PeerWorkload {
    PeerWorkload {
        address: IpAddr::V4(std::net::Ipv4Addr::new(10, 1, 2, 3)),
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
    }
}

/// A two-level chain with the shell's path read and its parent known only
/// by name, cut short at a lost ancestor, for the format tests.
#[cfg(test)]
pub(crate) fn sample_ancestry() -> WorkloadAncestry {
    WorkloadAncestry {
        ancestors: vec![
            WorkloadAncestor {
                pid: 900,
                exe: Some("/bin/sh".to_string()),
                name: "sh".to_string(),
                uid: 33,
                start_ns: Some(1_000),
                exited: true,
            },
            WorkloadAncestor {
                pid: 120,
                exe: None,
                name: "nginx".to_string(),
                uid: 0,
                start_ns: None,
                exited: false,
            },
        ],
        truncated: false,
        incomplete: true,
    }
}

/// Whether a workload block is absent, for every `skip_serializing_if` on
/// every surface.
///
/// One function rather than `Option::is_none` in eleven places, because the
/// rule is not simply "none": a block that somehow carries a pid of zero is
/// also absent, and a format that wrote it would be claiming a process that
/// does not exist. JSON, ECS, OCSF, CEF, LEEF and the Splunk envelope all ask
/// this and get the same answer.
#[must_use]
pub fn is_absent(workload: &Option<Workload>) -> bool {
    workload.as_ref().is_none_or(|w| w.pid == 0)
}

/// The block if it is present, `None` if the absence rule says it is not.
///
/// The reading half of [`is_absent`], for a mapper that needs the value
/// rather than a serde predicate.
#[must_use]
pub fn present(workload: &Option<Workload>) -> Option<&Workload> {
    workload.as_ref().filter(|w| w.pid != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::entity::{ContainerRuntime, DockerMetadata, KubernetesMetadata};
    use crate::process::entity::ProcessIdentity;

    fn k8s_container() -> ContainerContext {
        ContainerContext::with_metadata(
            ContainerInfo::Container {
                container_id: "c0ffee".to_string(),
                runtime: ContainerRuntime::Containerd,
                cgroup_path: "/kubepods/besteffort/podabc".to_string(),
                pid: 4242,
            },
            ContainerMetadata::Kubernetes(KubernetesMetadata {
                pod_name: "api-7f9".to_string(),
                namespace: "payments".to_string(),
                container_name: "api".to_string(),
                labels: Vec::new(),
                annotations: Vec::new(),
                service_account: "api-sa".to_string(),
                owner_kind: None,
                owner_name: None,
                node_name: "node-1".to_string(),
                namespace_labels: Vec::new(),
            }),
        )
    }

    #[test]
    fn a_pid_of_zero_builds_no_block_at_all() {
        assert!(Workload::new(0, WorkloadSource::Socket).is_none());
    }

    #[test]
    fn an_unresolved_workload_is_absent_rather_than_zero() {
        let absent: Option<Workload> = None;
        assert!(is_absent(&absent));
        assert!(present(&absent).is_none());
        let json = serde_json::to_string(&serde_json::json!({ "workload": absent })).unwrap();
        assert!(!json.contains("\"pid\":0"));
    }

    #[test]
    fn a_block_carrying_a_zero_pid_is_absent_too() {
        // Nothing builds one through the constructor; the predicate is what
        // guarantees that a block assembled field by field, by a future
        // caller or by a deserialiser, cannot publish a process of zero.
        let forged = Some(Workload {
            peer: None,
            pid: 0,
            source: WorkloadSource::Flow,
            exe: Some("/usr/bin/curl".to_string()),
            command_line: None,
            uid: None,
            cgroup: None,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            unit: None,
            ancestry: None,
        });
        assert!(is_absent(&forged));
        assert!(present(&forged).is_none());
    }

    #[test]
    fn a_resolved_block_serialises_only_the_fields_it_has() {
        let w = Workload::new(4242, WorkloadSource::Socket).unwrap();
        let json = serde_json::to_string(&w).unwrap();
        assert_eq!(json, r#"{"pid":4242,"source":"socket"}"#);
    }

    #[test]
    fn the_process_table_fills_the_path_the_uid_and_the_cgroup() {
        let mut entry = ProcessEntry::new(4242, "curl", 1_000);
        entry.identity = ProcessIdentity::Path {
            path: "/usr/bin/curl".to_string(),
            dev: 64,
            inode: 9,
        };
        entry.uid = 1000;
        entry.cgroup_id = 77;
        let w = Workload::new(4242, WorkloadSource::Socket)
            .unwrap()
            .with_process(&entry);
        assert_eq!(w.exe.as_deref(), Some("/usr/bin/curl"));
        assert_eq!(w.uid, Some(1000));
        assert_eq!(w.cgroup, Some(77));
    }

    #[test]
    fn an_unknown_identity_leaves_the_path_absent_rather_than_naming_the_comm() {
        let entry = ProcessEntry::new(4242, "curl", 1_000);
        let w = Workload::new(4242, WorkloadSource::Socket)
            .unwrap()
            .with_process(&entry);
        assert!(w.exe.is_none());
        assert!(w.cgroup.is_none());
    }

    #[test]
    fn a_kubernetes_container_fills_the_pod_the_namespace_and_the_account() {
        let w = Workload::new(4242, WorkloadSource::Flow)
            .unwrap()
            .with_container(&k8s_container());
        assert_eq!(w.container.as_deref(), Some("c0ffee"));
        assert_eq!(w.pod.as_deref(), Some("api-7f9"));
        assert_eq!(w.namespace.as_deref(), Some("payments"));
        assert_eq!(w.service_account.as_deref(), Some("api-sa"));
        assert!(w.image.is_none());
    }

    #[test]
    fn a_docker_container_fills_the_image_and_claims_no_pod() {
        let container = ContainerContext::with_metadata(
            ContainerInfo::Container {
                container_id: "deadbeef".to_string(),
                runtime: ContainerRuntime::Docker,
                cgroup_path: "/docker/deadbeef".to_string(),
                pid: 7,
            },
            ContainerMetadata::Docker(DockerMetadata {
                name: "web".to_string(),
                image: "nginx:1.27".to_string(),
                labels: Vec::new(),
                created_at: String::new(),
                status: String::new(),
            }),
        );
        let w = Workload::new(7, WorkloadSource::Socket)
            .unwrap()
            .with_container(&container);
        assert_eq!(w.image.as_deref(), Some("nginx:1.27"));
        assert!(w.pod.is_none());
        assert!(w.namespace.is_none());
    }

    #[test]
    fn a_host_process_names_no_container() {
        let w = Workload::new(7, WorkloadSource::Socket)
            .unwrap()
            .with_container(&ContainerContext::new(ContainerInfo::Host));
        assert!(w.container.is_none());
        assert!(w.image.is_none());
    }

    #[test]
    fn an_empty_unit_is_not_written_as_an_empty_string() {
        let w = Workload::new(7, WorkloadSource::Socket)
            .unwrap()
            .with_unit("");
        assert!(w.unit.is_none());
    }

    #[test]
    fn a_correlated_block_says_so_and_a_read_one_says_so() {
        assert!(!WorkloadSource::Flow.is_read());
        assert!(WorkloadSource::Socket.is_read());
        assert!(WorkloadSource::Process.is_read());
        assert_eq!(WorkloadSource::Flow.to_string(), "flow");
    }

    #[test]
    fn an_ancestry_reads_from_the_parent_outwards() {
        let ancestry = sample_ancestry();
        assert_eq!(ancestry.parent().map(|a| a.pid), Some(900));
        assert_eq!(ancestry.chain_text(), "900 /bin/sh < 120 [nginx]");
    }

    #[test]
    fn a_walk_that_found_nothing_adds_no_ancestry() {
        let w = Workload::new(4242, WorkloadSource::Socket)
            .expect("a pid builds a block")
            .with_lineage(&Lineage::default());
        assert!(w.ancestry.is_none());
        let json = serde_json::to_string(&w).unwrap();
        assert!(!json.contains("ancestry"));
    }

    #[test]
    fn a_lineage_becomes_the_block_with_its_flags() {
        let mut shell = ProcessEntry::new(900, "sh", 5);
        shell.identity = ProcessIdentity::Path {
            path: "/bin/sh".to_string(),
            dev: 1,
            inode: 2,
        };
        shell.uid = 33;
        shell.start_ns = Some(4);
        shell.exited_at_ns = Some(9);
        let lineage = Lineage {
            ancestors: vec![shell],
            truncated: true,
            incomplete: false,
        };
        let w = Workload::new(4242, WorkloadSource::Socket)
            .expect("a pid builds a block")
            .with_lineage(&lineage);
        let json = serde_json::to_value(&w).unwrap();
        let ancestor = &json["ancestry"]["ancestors"][0];
        assert_eq!(ancestor["pid"], 900);
        assert_eq!(ancestor["exe"], "/bin/sh");
        assert_eq!(ancestor["uid"], 33);
        assert_eq!(ancestor["start_ns"], 4);
        assert_eq!(ancestor["exited"], true);
        assert_eq!(json["ancestry"]["truncated"], true);
        assert!(json["ancestry"].get("incomplete").is_none());
    }
}
