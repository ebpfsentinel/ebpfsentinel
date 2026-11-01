//! This node's addresses and who holds each, kept as a versioned list.
//!
//! Read on demand: every answer takes a fresh reading of the process table,
//! the namespaces its tasks sit in and the sockets listening on the host, and
//! folds it into the journal, so the version a reader is handed moves exactly
//! when something it would see changed.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use domain::exposure::entity::BoundSocket;
use domain::identity::{
    AddressIdentity, Composition, HostListener, IdentityDelta, IdentityJournal, NamespaceReading,
    ServiceIdentity, compose, identity_of,
};
use domain::process::entity::ProcessEntry;
use domain::workload::entity::Workload;
use ports::secondary::namespace_address_port::NamespaceAddressReader;
use std::sync::Arc;

use crate::workload_resolver::WorkloadResolver;

/// Why this node cannot say who its addresses are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressInventoryError {
    /// No process table runs, so no workload is known.
    NoProcessTable,
    /// The host's network namespace could not be read, so a container's
    /// address cannot be told from the host's.
    HostUnreadable,
}

impl std::fmt::Display for AddressInventoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoProcessTable => {
                "the process table is off, so this node does not know which workload holds an \
                 address; turn on process_table.enabled"
            }
            Self::HostUnreadable => {
                "the host's network namespace could not be read under the procfs root; mount \
                 the host's procfs and set EBPFSENTINEL_HOST_PROC"
            }
        })
    }
}

impl std::error::Error for AddressInventoryError {}

/// The versioned list of this node's addresses.
pub struct AddressIdentityService {
    workloads: WorkloadResolver,
    reader: Arc<dyn NamespaceAddressReader>,
    journal: Mutex<IdentityJournal>,
}

impl AddressIdentityService {
    /// A list for one run of the agent, `epoch` telling it from the others.
    #[must_use]
    pub fn new(
        workloads: WorkloadResolver,
        reader: Arc<dyn NamespaceAddressReader>,
        epoch: u64,
    ) -> Self {
        Self {
            workloads,
            reader,
            journal: Mutex::new(IdentityJournal::new(epoch)),
        }
    }

    /// Read the node now and answer a reader that last saw `seen`, an epoch
    /// and a version, or nothing.
    pub fn read_since(
        &self,
        seen: Option<(u64, u64)>,
    ) -> Result<IdentityDelta, AddressInventoryError> {
        let processes = self
            .workloads
            .processes()
            .ok_or(AddressInventoryError::NoProcessTable)?;
        let listeners = self.workloads.bound_sockets().unwrap_or_default();
        let composition = gather(&processes, &listeners, self.reader.as_ref())?;
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        journal.apply(composition);
        Ok(journal.since(seen))
    }
}

/// Fold one reading of the node into what can be named.
fn gather(
    processes: &[ProcessEntry],
    listeners: &[(BoundSocket, Workload)],
    reader: &dyn NamespaceAddressReader,
) -> Result<Composition, AddressInventoryError> {
    let host = reader
        .host_namespace()
        .ok_or(AddressInventoryError::HostUnreadable)?;
    let host_addresses = reader
        .host_addresses()
        .ok_or(AddressInventoryError::HostUnreadable)?;

    // One task per namespace is enough to read its addresses; every distinct
    // workload seen in it is a claim on them.
    let mut namespaces: BTreeMap<u64, (u32, Vec<AddressIdentity>)> = BTreeMap::new();
    for entry in processes {
        let Some(workload) = entry.container.as_ref().and_then(identity_of) else {
            continue;
        };
        let Some(namespace) = reader.namespace_of(entry.pid).filter(|ns| *ns != host) else {
            continue;
        };
        let (_, claims) = namespaces
            .entry(namespace)
            .or_insert_with(|| (entry.pid, Vec::new()));
        if !claims.contains(&workload) {
            claims.push(workload);
        }
    }
    let readings: Vec<NamespaceReading> = namespaces
        .into_values()
        .filter_map(|(pid, claims)| Some((reader.addresses_of(pid)?, claims)))
        .flat_map(|(addresses, claims)| {
            claims.into_iter().map(move |workload| NamespaceReading {
                addresses: addresses.clone(),
                workload,
            })
        })
        .collect();

    let host_listeners: Vec<HostListener> = listeners
        .iter()
        .filter(|(socket, _)| socket.accepts())
        .filter(|(socket, _)| reader.namespace_of(socket.pid) == Some(host))
        .map(|(socket, workload)| HostListener {
            address: socket.address,
            service: ServiceIdentity {
                protocol: socket.protocol,
                port: socket.port,
                unit: workload.unit.clone(),
                exe: workload.exe.clone(),
                pod: workload.pod.clone(),
                namespace: workload.namespace.clone(),
            },
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    Ok(compose(&host_addresses, &host_listeners, &readings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::container::entity::{
        ContainerContext, ContainerInfo, ContainerMetadata, ContainerRuntime, DockerMetadata,
    };
    use domain::exposure::entity::ListenerProtocol;
    use domain::identity::IdentityKind;
    use domain::workload::entity::WorkloadSource;
    use std::collections::HashMap;
    use std::net::IpAddr;

    struct Namespaces {
        host: Option<u64>,
        by_pid: HashMap<u32, u64>,
        addresses: HashMap<u64, Vec<IpAddr>>,
    }

    impl NamespaceAddressReader for Namespaces {
        fn namespace_of(&self, pid: u32) -> Option<u64> {
            self.by_pid.get(&pid).copied()
        }
        fn host_namespace(&self) -> Option<u64> {
            self.host
        }
        fn addresses_of(&self, pid: u32) -> Option<Vec<IpAddr>> {
            self.addresses.get(self.by_pid.get(&pid)?).cloned()
        }
        fn host_addresses(&self) -> Option<Vec<IpAddr>> {
            self.addresses.get(&self.host?).cloned()
        }
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn node() -> Namespaces {
        Namespaces {
            host: Some(1),
            by_pid: HashMap::from([(10, 1), (20, 2), (21, 2), (30, 3), (40, 1)]),
            addresses: HashMap::from([
                (1, vec![ip("10.0.0.5"), ip("127.0.0.1")]),
                (2, vec![ip("172.17.0.2"), ip("127.0.0.1")]),
                (3, vec![ip("172.17.0.3")]),
            ]),
        }
    }

    fn process(pid: u32, container: Option<(&str, &str)>) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "task".to_owned(), 1);
        entry.container = container.map(|(id, name)| ContainerContext {
            info: ContainerInfo::Container {
                container_id: id.to_owned(),
                runtime: ContainerRuntime::Docker,
                cgroup_path: String::new(),
                pid,
            },
            metadata: Some(ContainerMetadata::Docker(DockerMetadata {
                name: name.to_owned(),
                image: "img".to_owned(),
                labels: Vec::new(),
                created_at: String::new(),
                status: String::new(),
            })),
        });
        entry
    }

    fn listener(pid: u32, address: &str, port: u16, unit: &str) -> (BoundSocket, Workload) {
        let socket = BoundSocket {
            address: ip(address),
            port,
            protocol: ListenerProtocol::Tcp,
            listening: true,
            pid,
            uid: 0,
            cgroup_id: 9,
            bound_at_ns: 0,
        };
        let workload = Workload::new(pid, WorkloadSource::Socket)
            .expect("a pid")
            .with_unit(unit);
        (socket, workload)
    }

    #[test]
    fn each_namespace_is_named_by_the_workloads_seen_in_it() {
        let processes = [
            process(10, None),
            process(20, Some(("a", "web"))),
            process(21, Some(("a", "web"))),
            process(30, Some(("b", "db"))),
        ];
        let composition = gather(&processes, &[], &node()).expect("read");
        assert!(composition.conflicts.is_empty());
        let web = &composition.entries[&ip("172.17.0.2")];
        assert_eq!(web.kind, IdentityKind::Container);
        assert_eq!(web.container.as_deref(), Some("web"));
        assert_eq!(
            composition.entries[&ip("172.17.0.3")].container.as_deref(),
            Some("db")
        );
        assert_eq!(
            composition.entries[&ip("10.0.0.5")].kind,
            IdentityKind::Host
        );
        assert_eq!(composition.entries.len(), 3);
    }

    #[test]
    fn a_container_on_the_host_network_names_no_address_of_its_own() {
        let processes = [process(40, Some(("c", "hostnet")))];
        let composition = gather(&processes, &[], &node()).expect("read");
        assert_eq!(composition.entries.len(), 1);
        assert_eq!(
            composition.entries[&ip("10.0.0.5")].kind,
            IdentityKind::Host
        );
    }

    #[test]
    fn host_services_are_the_host_namespace_listeners_only() {
        let listeners = [
            listener(10, "0.0.0.0", 22, "sshd.service"),
            listener(20, "0.0.0.0", 80, "docker.service"),
        ];
        let composition = gather(&[], &listeners, &node()).expect("read");
        let host = &composition.entries[&ip("10.0.0.5")];
        let units: Vec<&str> = host
            .services
            .iter()
            .filter_map(|s| s.unit.as_deref())
            .collect();
        assert_eq!(units, ["sshd.service"]);
    }

    #[test]
    fn a_host_namespace_that_cannot_be_read_is_refused() {
        let mut blind = node();
        blind.host = None;
        assert_eq!(
            gather(&[], &[], &blind),
            Err(AddressInventoryError::HostUnreadable)
        );
    }

    #[test]
    fn without_a_process_table_the_node_says_so() {
        let service = AddressIdentityService::new(WorkloadResolver::new(), Arc::new(node()), 1);
        assert_eq!(
            service.read_since(None),
            Err(AddressInventoryError::NoProcessTable)
        );
    }

    #[tokio::test]
    async fn a_reading_is_versioned_across_answers() {
        let table = crate::process_table_service::ProcessTableService::new(16, false);
        table
            .apply(domain::process::entity::ProcessLifecycleEvent::bare(
                domain::process::entity::ProcessEventKind::Exec,
                10,
                "init",
                1,
            ))
            .await;
        let resolver = WorkloadResolver::new().with_processes(Arc::new(table));
        let service = AddressIdentityService::new(resolver, Arc::new(node()), 5);
        let first = service.read_since(None).expect("read");
        assert!(first.full);
        assert_eq!(first.epoch, 5);
        assert_eq!(first.version, 1);
        assert_eq!(first.upserts.len(), 1);
        let again = service.read_since(Some((5, 1))).expect("read");
        assert!(!again.full);
        assert_eq!(again.version, 1);
        assert!(again.upserts.is_empty());
    }
}
