//! Who this node's addresses are, as a list another node can read.
//!
//! A flow carries its workload on the node that opened it and nowhere else:
//! the node at the other end sees an address. This module is the half that
//! turns a node's own addresses into names it can hand to the rest of the
//! fleet - the pod, the container, the guest or the host behind each one -
//! and keeps that list versioned, so a reader that saw it once is told what
//! changed since rather than handed the whole of it again, removals included.
//!
//! Three rules are written into the types.
//!
//! An address is named only where the node can say whose it is. A container
//! sitting in a network namespace of its own owns the addresses of that
//! namespace; a process in the host's namespace shares the host's, so a
//! systemd unit is never the owner of an address and is named on the ports
//! it listens on instead.
//!
//! An address two workloads hold names neither. Two containers sharing one
//! namespace, or a namespace holding an address the host also holds, is an
//! address the node cannot attribute, and naming one of the two would hand a
//! remote policy the wrong workload. It is left out and counted.
//!
//! Addresses nobody off the node can reach are not published: loopback,
//! link-local, multicast and the unspecified address.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::container::entity::{ContainerContext, ContainerInfo, ContainerMetadata};
use crate::coverage::PodSubject;
use crate::exposure::entity::ListenerProtocol;
use crate::guest::{GuestNaming, kubevirt_guest};

/// How many removals the journal remembers. A reader further behind than
/// that is handed the whole list, which is always correct and only costlier.
pub const IDENTITY_REMOVALS_KEPT: usize = 4096;

/// What sits behind an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityKind {
    /// The node itself: its own addresses, named by the services listening
    /// on them.
    Host,
    /// A container in a network namespace of its own.
    Container,
    /// A Kubernetes pod, whose containers share one namespace.
    Pod,
    /// A virtual machine whose address the node holds through its launcher
    /// pod.
    Guest,
}

impl IdentityKind {
    /// The word the API uses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Container => "container",
            Self::Pod => "pod",
            Self::Guest => "guest",
        }
    }
}

/// A service listening on one of the host's addresses, and who runs it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ServiceIdentity {
    /// `tcp` or `udp`.
    pub protocol: ListenerProtocol,
    pub port: u16,
    /// The systemd unit the listening task was placed in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// The executable the listening task runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The pod, for a pod on the host network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// That pod's namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

/// One address of this node and what it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressIdentity {
    pub address: IpAddr,
    pub kind: IdentityKind,
    /// The container's name where the runtime gave one, its id otherwise.
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
    /// The guest's name as its hypervisor gives it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub namespace_labels: BTreeMap<String, String>,
    /// For a host address, the services listening on it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceIdentity>,
}

impl AddressIdentity {
    fn bare(address: IpAddr, kind: IdentityKind) -> Self {
        Self {
            address,
            kind,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            guest: None,
            pod_labels: BTreeMap::new(),
            namespace_labels: BTreeMap::new(),
            services: Vec::new(),
        }
    }

    /// The same identity on another address.
    fn at(&self, address: IpAddr) -> Self {
        Self {
            address,
            ..self.clone()
        }
    }

    /// Whether two entries name the same workload, whatever address each
    /// sits on.
    fn same_workload(&self, other: &Self) -> bool {
        self.at(other.address) == *other
    }
}

/// Whether another node can reach this address at all.
#[must_use]
pub fn is_publishable(address: IpAddr) -> bool {
    if address.is_unspecified() || address.is_loopback() || address.is_multicast() {
        return false;
    }
    match address {
        IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// The workload a container context names, without an address yet.
///
/// `None` for a task in the host's cgroup, which is not a workload of its
/// own whatever namespace it unshared.
#[must_use]
pub fn identity_of(container: &ContainerContext) -> Option<AddressIdentity> {
    let placeholder = IpAddr::from([0, 0, 0, 0]);
    let id = match &container.info {
        ContainerInfo::Host => return None,
        ContainerInfo::Container { container_id, .. } => container_id.clone(),
    };
    match container.metadata.as_ref() {
        Some(ContainerMetadata::Kubernetes(k8s)) => {
            let pod_labels: BTreeMap<String, String> = k8s.labels.iter().cloned().collect();
            let subject = PodSubject {
                uid: String::new(),
                name: k8s.pod_name.clone(),
                namespace: k8s.namespace.clone(),
                host_network: false,
                labels: pod_labels.clone(),
            };
            let guest = match kubevirt_guest(&subject) {
                Some(GuestNaming::Named(identity)) => Some(identity.name),
                _ => None,
            };
            let mut entry = AddressIdentity::bare(
                placeholder,
                if guest.is_some() {
                    IdentityKind::Guest
                } else {
                    IdentityKind::Pod
                },
            );
            entry.guest = guest;
            entry.pod = non_empty(&k8s.pod_name);
            entry.namespace = non_empty(&k8s.namespace);
            entry.service_account = non_empty(&k8s.service_account);
            entry.pod_labels = pod_labels;
            entry.namespace_labels = k8s.namespace_labels.iter().cloned().collect();
            Some(entry)
        }
        Some(ContainerMetadata::Docker(docker)) => {
            let mut entry = AddressIdentity::bare(placeholder, IdentityKind::Container);
            entry.container = non_empty(docker.name.trim_start_matches('/')).or(Some(id));
            entry.image = non_empty(&docker.image);
            Some(entry)
        }
        _ => {
            let mut entry = AddressIdentity::bare(placeholder, IdentityKind::Container);
            entry.container = Some(id);
            Some(entry)
        }
    }
}

fn non_empty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

/// The addresses of one network namespace other than the host's, and the
/// workload a task in it belongs to.
///
/// One reading per workload seen in the namespace: two containers sharing a
/// namespace are two readings of the same addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceReading {
    pub addresses: Vec<IpAddr>,
    pub workload: AddressIdentity,
}

/// A socket accepting traffic in the host's namespace, with who holds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostListener {
    /// The bound address; the unspecified address of either family means
    /// every address of the host.
    pub address: IpAddr,
    pub service: ServiceIdentity,
}

/// What this node can say of its addresses now.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Composition {
    pub entries: BTreeMap<IpAddr, AddressIdentity>,
    /// Addresses two workloads hold, named for neither.
    pub conflicts: BTreeSet<IpAddr>,
}

/// Name every address of this node that can be named.
#[must_use]
pub fn compose(
    host_addresses: &[IpAddr],
    host_listeners: &[HostListener],
    namespaces: &[NamespaceReading],
) -> Composition {
    let mut composition = Composition::default();
    let claim = |entry: AddressIdentity, composition: &mut Composition| {
        let address = entry.address;
        if composition.conflicts.contains(&address) {
            return;
        }
        match composition.entries.get(&address) {
            Some(held) if held.same_workload(&entry) => {}
            Some(_) => {
                composition.entries.remove(&address);
                composition.conflicts.insert(address);
            }
            None => {
                composition.entries.insert(address, entry);
            }
        }
    };

    for &address in host_addresses.iter().filter(|a| is_publishable(**a)) {
        let mut entry = AddressIdentity::bare(address, IdentityKind::Host);
        let mut services: BTreeSet<ServiceIdentity> = BTreeSet::new();
        for listener in host_listeners {
            if listener.address == address || listener.address.is_unspecified() {
                services.insert(listener.service.clone());
            }
        }
        entry.services = services.into_iter().collect();
        claim(entry, &mut composition);
    }
    for reading in namespaces {
        for &address in reading.addresses.iter().filter(|a| is_publishable(**a)) {
            claim(reading.workload.at(address), &mut composition);
        }
    }
    composition
}

/// What a reader is told: either the whole list, or what changed after the
/// version it last saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityDelta {
    /// Which run of the agent wrote the versions. A reader holding versions
    /// of another run is handed the whole list.
    pub epoch: u64,
    /// The version this answer brings the reader to.
    pub version: u64,
    /// The answer is the whole list, and the reader drops what it held.
    pub full: bool,
    /// Entries added or changed.
    pub upserts: Vec<AddressIdentity>,
    /// Addresses no longer this node's, applied before `upserts`.
    pub removed: Vec<IpAddr>,
    /// How many of the node's addresses two workloads hold, and so are not
    /// in the list.
    pub conflicts: usize,
}

/// The versioned list.
#[derive(Debug, Clone)]
pub struct IdentityJournal {
    epoch: u64,
    version: u64,
    entries: BTreeMap<IpAddr, (u64, AddressIdentity)>,
    removals: VecDeque<(u64, IpAddr)>,
    /// The oldest version from which the removals kept are complete.
    floor: u64,
    conflicts: usize,
    capacity: usize,
}

impl IdentityJournal {
    /// An empty journal for one run of the agent.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self::with_capacity(epoch, IDENTITY_REMOVALS_KEPT)
    }

    /// The same, remembering `capacity` removals.
    #[must_use]
    pub fn with_capacity(epoch: u64, capacity: usize) -> Self {
        Self {
            epoch,
            version: 0,
            entries: BTreeMap::new(),
            removals: VecDeque::new(),
            floor: 0,
            conflicts: 0,
            capacity: capacity.max(1),
        }
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Take a new reading. The version moves only when an entry was added,
    /// changed or removed; returns whether it did.
    pub fn apply(&mut self, composition: Composition) -> bool {
        self.conflicts = composition.conflicts.len();
        let next = self.version + 1;
        let mut changed = false;
        let gone: Vec<IpAddr> = self
            .entries
            .keys()
            .filter(|address| !composition.entries.contains_key(address))
            .copied()
            .collect();
        for address in gone {
            self.entries.remove(&address);
            self.removals.push_back((next, address));
            changed = true;
        }
        while self.removals.len() > self.capacity {
            if let Some((version, _)) = self.removals.pop_front() {
                self.floor = version;
            }
        }
        for (address, entry) in composition.entries {
            match self.entries.get(&address) {
                Some((_, held)) if *held == entry => {}
                _ => {
                    self.entries.insert(address, (next, entry));
                    changed = true;
                }
            }
        }
        if changed {
            self.version = next;
        }
        changed
    }

    /// What a reader holding `seen` (an epoch and a version) is missing.
    #[must_use]
    pub fn since(&self, seen: Option<(u64, u64)>) -> IdentityDelta {
        let partial_from = seen.filter(|(epoch, version)| {
            *epoch == self.epoch && *version >= self.floor && *version <= self.version
        });
        match partial_from {
            Some((_, version)) => IdentityDelta {
                epoch: self.epoch,
                version: self.version,
                full: false,
                upserts: self
                    .entries
                    .values()
                    .filter(|(changed_at, _)| *changed_at > version)
                    .map(|(_, entry)| entry.clone())
                    .collect(),
                removed: self
                    .removals
                    .iter()
                    .filter(|(removed_at, _)| *removed_at > version)
                    .map(|(_, address)| *address)
                    .collect(),
                conflicts: self.conflicts,
            },
            None => IdentityDelta {
                epoch: self.epoch,
                version: self.version,
                full: true,
                upserts: self
                    .entries
                    .values()
                    .map(|(_, entry)| entry.clone())
                    .collect(),
                removed: Vec::new(),
                conflicts: self.conflicts,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::entity::{ContainerRuntime, DockerMetadata, KubernetesMetadata};

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("address")
    }

    fn container(id: &str, metadata: Option<ContainerMetadata>) -> ContainerContext {
        ContainerContext {
            info: ContainerInfo::Container {
                container_id: id.to_owned(),
                runtime: ContainerRuntime::Docker,
                cgroup_path: format!("/system.slice/docker-{id}.scope"),
                pid: 10,
            },
            metadata,
        }
    }

    fn docker(name: &str, image: &str) -> ContainerMetadata {
        ContainerMetadata::Docker(DockerMetadata {
            name: name.to_owned(),
            image: image.to_owned(),
            labels: Vec::new(),
            created_at: String::new(),
            status: String::new(),
        })
    }

    fn pod(name: &str, container_name: &str, labels: &[(&str, &str)]) -> ContainerMetadata {
        ContainerMetadata::Kubernetes(KubernetesMetadata {
            pod_name: name.to_owned(),
            namespace: "prod".to_owned(),
            container_name: container_name.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            annotations: Vec::new(),
            service_account: "db".to_owned(),
            owner_kind: None,
            owner_name: None,
            node_name: "node-a".to_owned(),
            namespace_labels: vec![("kubernetes.io/metadata.name".to_owned(), "prod".to_owned())],
        })
    }

    fn reading(addresses: &[&str], workload: &ContainerContext) -> NamespaceReading {
        NamespaceReading {
            addresses: addresses.iter().map(|a| ip(a)).collect(),
            workload: identity_of(workload).expect("a workload"),
        }
    }

    fn listener(address: &str, port: u16, unit: &str) -> HostListener {
        HostListener {
            address: ip(address),
            service: ServiceIdentity {
                protocol: ListenerProtocol::Tcp,
                port,
                unit: Some(unit.to_owned()),
                exe: None,
                pod: None,
                namespace: None,
            },
        }
    }

    #[test]
    fn only_addresses_another_node_can_reach_are_published() {
        for address in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
        ] {
            assert!(!is_publishable(ip(address)), "{address}");
        }
        for address in ["10.0.0.5", "192.168.1.2", "2001:db8::5", "fd00::1"] {
            assert!(is_publishable(ip(address)), "{address}");
        }
    }

    #[test]
    fn a_pod_is_named_by_its_pod_and_never_by_one_of_its_containers() {
        let identity = identity_of(&container(
            "aaa",
            Some(pod("db-0", "postgres", &[("app", "db")])),
        ))
        .expect("named");
        assert_eq!(identity.kind, IdentityKind::Pod);
        assert_eq!(identity.pod.as_deref(), Some("db-0"));
        assert_eq!(identity.namespace.as_deref(), Some("prod"));
        assert_eq!(identity.service_account.as_deref(), Some("db"));
        assert_eq!(
            identity.pod_labels.get("app").map(String::as_str),
            Some("db")
        );
        assert_eq!(
            identity
                .namespace_labels
                .get("kubernetes.io/metadata.name")
                .map(String::as_str),
            Some("prod")
        );
        assert_eq!(identity.container, None);
        let sidecar = identity_of(&container(
            "bbb",
            Some(pod("db-0", "envoy", &[("app", "db")])),
        ))
        .expect("named");
        assert!(identity.same_workload(&sidecar));
    }

    #[test]
    fn a_kubevirt_launcher_is_published_as_its_guest() {
        let identity = identity_of(&container(
            "ccc",
            Some(pod(
                "virt-launcher-web-x",
                "compute",
                &[
                    ("kubevirt.io", "virt-launcher"),
                    ("vm.kubevirt.io/name", "web"),
                ],
            )),
        ))
        .expect("named");
        assert_eq!(identity.kind, IdentityKind::Guest);
        assert_eq!(identity.guest.as_deref(), Some("prod/web"));
        assert_eq!(identity.pod.as_deref(), Some("virt-launcher-web-x"));
    }

    #[test]
    fn a_container_is_named_by_its_runtime_name_and_image_or_by_its_id() {
        let named =
            identity_of(&container("ddd", Some(docker("/nginx", "nginx:1.27")))).expect("named");
        assert_eq!(named.kind, IdentityKind::Container);
        assert_eq!(named.container.as_deref(), Some("nginx"));
        assert_eq!(named.image.as_deref(), Some("nginx:1.27"));
        let bare = identity_of(&container("eee", None)).expect("named");
        assert_eq!(bare.container.as_deref(), Some("eee"));
        assert_eq!(
            identity_of(&ContainerContext::new(ContainerInfo::Host)),
            None
        );
    }

    #[test]
    fn host_addresses_carry_the_services_listening_on_them() {
        let composition = compose(
            &[ip("10.0.0.5"), ip("10.0.1.5"), ip("127.0.0.1")],
            &[
                listener("0.0.0.0", 22, "sshd.service"),
                listener("10.0.1.5", 5432, "postgresql.service"),
            ],
            &[],
        );
        assert_eq!(composition.entries.len(), 2);
        let front = &composition.entries[&ip("10.0.0.5")];
        assert_eq!(front.kind, IdentityKind::Host);
        assert_eq!(front.services.len(), 1);
        assert_eq!(front.services[0].unit.as_deref(), Some("sshd.service"));
        let back = &composition.entries[&ip("10.0.1.5")];
        let units: Vec<&str> = back
            .services
            .iter()
            .filter_map(|s| s.unit.as_deref())
            .collect();
        assert_eq!(units, ["sshd.service", "postgresql.service"]);
    }

    #[test]
    fn an_address_two_workloads_hold_names_neither() {
        let composition = compose(
            &[ip("10.0.0.5")],
            &[],
            &[
                reading(
                    &["172.17.0.2"],
                    &container("a", Some(docker("web", "nginx"))),
                ),
                reading(
                    &["172.17.0.2"],
                    &container("b", Some(docker("sidecar", "envoy"))),
                ),
                reading(
                    &["172.17.0.3", "fe80::1"],
                    &container("c", Some(docker("db", "postgres"))),
                ),
                reading(&["10.0.0.5"], &container("d", Some(docker("macvlan", "x")))),
            ],
        );
        assert_eq!(
            composition.conflicts,
            BTreeSet::from([ip("172.17.0.2"), ip("10.0.0.5")])
        );
        assert_eq!(composition.entries.len(), 1);
        assert_eq!(
            composition.entries[&ip("172.17.0.3")].container.as_deref(),
            Some("db")
        );
    }

    #[test]
    fn two_containers_of_one_pod_name_its_addresses_once() {
        let composition = compose(
            &[],
            &[],
            &[
                reading(
                    &["10.244.0.7"],
                    &container("a", Some(pod("db-0", "postgres", &[]))),
                ),
                reading(
                    &["10.244.0.7"],
                    &container("b", Some(pod("db-0", "exporter", &[]))),
                ),
            ],
        );
        assert!(composition.conflicts.is_empty());
        assert_eq!(composition.entries.len(), 1);
    }

    fn one(address: &str, name: &str) -> Composition {
        compose(
            &[],
            &[],
            &[reading(
                &[address],
                &container(name, Some(docker(name, "img"))),
            )],
        )
    }

    fn merged(parts: &[Composition]) -> Composition {
        let mut all = Composition::default();
        for part in parts {
            all.entries.extend(part.entries.clone());
        }
        all
    }

    #[test]
    fn the_version_moves_only_on_a_change() {
        let mut journal = IdentityJournal::new(7);
        assert!(journal.apply(one("10.0.0.2", "web")));
        assert_eq!(journal.version(), 1);
        assert!(!journal.apply(one("10.0.0.2", "web")));
        assert_eq!(journal.version(), 1);
        assert!(journal.apply(one("10.0.0.2", "api")));
        assert_eq!(journal.version(), 2);
    }

    #[test]
    fn a_reader_is_told_what_changed_since_and_what_went() {
        let mut journal = IdentityJournal::new(7);
        journal.apply(merged(&[one("10.0.0.2", "web"), one("10.0.0.3", "db")]));
        let first = journal.since(None);
        assert!(first.full);
        assert_eq!(first.upserts.len(), 2);

        journal.apply(merged(&[one("10.0.0.2", "web"), one("10.0.0.4", "cache")]));
        let delta = journal.since(Some((7, first.version)));
        assert!(!delta.full);
        assert_eq!(delta.version, 2);
        assert_eq!(delta.removed, [ip("10.0.0.3")]);
        let added: Vec<IpAddr> = delta.upserts.iter().map(|e| e.address).collect();
        assert_eq!(added, [ip("10.0.0.4")]);

        let nothing = journal.since(Some((7, 2)));
        assert!(!nothing.full);
        assert!(nothing.upserts.is_empty() && nothing.removed.is_empty());
    }

    #[test]
    fn a_reader_of_another_run_or_too_far_behind_gets_the_whole_list() {
        let mut journal = IdentityJournal::with_capacity(7, 1);
        journal.apply(merged(&[one("10.0.0.2", "a"), one("10.0.0.3", "b")]));
        journal.apply(one("10.0.0.3", "b"));
        journal.apply(Composition::default());
        assert!(journal.since(Some((8, 3))).full, "another run");
        assert!(journal.since(Some((7, 9))).full, "a version never written");
        assert!(journal.since(Some((7, 1))).full, "a removal forgotten");
        let caught_up = journal.since(Some((7, 2)));
        assert!(!caught_up.full);
        assert_eq!(caught_up.removed, [ip("10.0.0.3")]);
        let whole = journal.since(None);
        assert!(whole.full && whole.upserts.is_empty() && whole.removed.is_empty());
    }

    #[test]
    fn an_address_removed_then_given_back_is_removed_then_upserted() {
        let mut journal = IdentityJournal::new(1);
        journal.apply(one("10.0.0.2", "web"));
        journal.apply(Composition::default());
        journal.apply(one("10.0.0.2", "api"));
        let delta = journal.since(Some((1, 1)));
        assert_eq!(delta.removed, [ip("10.0.0.2")]);
        assert_eq!(delta.upserts.len(), 1);
        assert_eq!(delta.upserts[0].container.as_deref(), Some("api"));
    }

    #[test]
    fn conflicts_are_counted_in_the_answer() {
        let mut journal = IdentityJournal::new(1);
        let mut composition = one("10.0.0.2", "web");
        composition.conflicts.insert(ip("10.0.0.9"));
        journal.apply(composition);
        assert_eq!(journal.since(None).conflicts, 1);
    }

    #[test]
    fn the_wire_form_names_kinds_and_protocols_in_lower_case() {
        let entry = compose(
            &[ip("10.0.0.5")],
            &[listener("10.0.0.5", 22, "sshd.service")],
            &[],
        )
        .entries[&ip("10.0.0.5")]
            .clone();
        let json = serde_json::to_value(&entry).expect("json");
        assert_eq!(json["kind"], "host");
        assert_eq!(json["services"][0]["protocol"], "tcp");
        assert!(json.get("pod").is_none());
        let back: AddressIdentity = serde_json::from_value(json).expect("read back");
        assert_eq!(back, entry);
        assert_eq!(IdentityKind::Guest.as_str(), "guest");
    }
}
