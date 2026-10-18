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

use crate::container::entity::{ContainerContext, ContainerInfo, ContainerMetadata};
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
            uid: None,
            cgroup: None,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            unit: None,
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
        self.uid = Some(entry.uid);
        if entry.cgroup_id != 0 {
            self.cgroup = Some(entry.cgroup_id);
        }
        if let Some(container) = entry.container.as_ref() {
            self.fill_container(container);
        }
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
            pid: 0,
            source: WorkloadSource::Flow,
            exe: Some("/usr/bin/curl".to_string()),
            uid: None,
            cgroup: None,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            unit: None,
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
}
