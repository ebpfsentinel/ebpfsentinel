//! From the cluster as the watchers see it to the table the hooks read.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::netpol::{ClusterView, LabelSelector, PodView, Protocol, ServicePort, ServiceView};
use ebpf_common::clusterip::{
    CLUSTERIP_MAX_BACKENDS, CLUSTERIP_MAX_BACKENDS_PER_SERVICE, CLUSTERIP_MAX_SERVICES,
};

/// How many backends the plan may hold across every entry: half the backend
/// table, because a list being replaced is written in full under its new
/// revision before the old one is removed.
pub const BACKEND_BUDGET: usize = CLUSTERIP_MAX_BACKENDS as usize / 2;

/// The pods whose connections are resolved here: those matching `pods` in
/// a namespace matching `namespaces`, each optional, both when both are set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadSelector {
    #[serde(default)]
    pub pods: Option<LabelSelector>,
    #[serde(default)]
    pub namespaces: Option<LabelSelector>,
}

impl WorkloadSelector {
    fn selects(&self, pod: &PodView, namespace_labels: Option<&BTreeMap<String, String>>) -> bool {
        if self.pods.is_none() && self.namespaces.is_none() {
            return false;
        }
        if let Some(pods) = self.pods.as_ref()
            && !pods.matches(&pod.labels)
        {
            return false;
        }
        if let Some(namespaces) = self.namespaces.as_ref()
            && !namespace_labels.is_some_and(|labels| namespaces.matches(labels))
        {
            return false;
        }
        true
    }
}

/// One cluster address, port and protocol, and where its connections go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterIpEntry {
    pub namespace: String,
    pub name: String,
    pub cluster_ip: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    /// `ClientIP` affinity timeout in seconds, zero for none.
    pub affinity_secs: u32,
    /// Ready backends of the cluster address's own family, sorted, never
    /// empty.
    pub backends: Vec<SocketAddr>,
}

/// Why a Service port stays with kube-proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LeftReason {
    /// `internalTrafficPolicy: Local` restricts the backends by node, which
    /// kube-proxy carries out.
    NodeLocal,
    /// A topology preference orders the backends by zone, which kube-proxy
    /// carries out.
    Topology,
    /// SCTP is not resolved at `connect()` here.
    Protocol,
    /// No ready backend serves this port in this address family.
    NoReadyBackend,
    /// More backends than one table entry carries.
    TooManyBackends,
    /// The table is full, in entries or in backends.
    TableFull,
}

impl fmt::Display for LeftReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NodeLocal => "internal traffic policy is Local",
            Self::Topology => "topology-aware routing is requested",
            Self::Protocol => "SCTP is left to kube-proxy",
            Self::NoReadyBackend => "no ready backend",
            Self::TooManyBackends => "more backends than one entry carries",
            Self::TableFull => "the service table is full",
        })
    }
}

/// A Service port, on one of its cluster addresses, that stays with
/// kube-proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeftToKubeProxy {
    pub namespace: String,
    pub name: String,
    pub cluster_ip: IpAddr,
    pub port: u16,
    pub reason: LeftReason,
}

/// What the hooks are given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClusterIpPlan {
    pub entries: Vec<ClusterIpEntry>,
    /// Uids of the pods whose connections are resolved here.
    pub selected_pods: BTreeSet<String>,
    pub left_to_kube_proxy: Vec<LeftToKubeProxy>,
}

/// Plan the table for the pods `workloads` selects.
#[must_use]
pub fn plan(view: &ClusterView, workloads: &[WorkloadSelector]) -> ClusterIpPlan {
    let namespace_labels: BTreeMap<&str, &BTreeMap<String, String>> = view
        .namespaces
        .iter()
        .map(|namespace| (namespace.name.as_str(), &namespace.labels))
        .collect();
    let selected_pods = view
        .pods
        .iter()
        // A pod on the host's network shares the node's cgroup tree position
        // but not a network namespace of its own; its connections are the
        // node's, and those stay with kube-proxy.
        .filter(|pod| !pod.host_network && !pod.terminal)
        .filter(|pod| {
            let labels = namespace_labels.get(pod.namespace.as_str()).copied();
            workloads.iter().any(|workload| workload.selects(pod, labels))
        })
        .map(|pod| pod.uid.clone())
        .collect();

    let mut services: Vec<&ServiceView> = view.services.iter().collect();
    services.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    let mut entries = Vec::new();
    let mut left = Vec::new();
    let mut budget = BACKEND_BUDGET;
    for service in services {
        for cluster_ip in &service.cluster_ips {
            for port in &service.ports {
                let leave = |reason| LeftToKubeProxy {
                    namespace: service.namespace.clone(),
                    name: service.name.clone(),
                    cluster_ip: *cluster_ip,
                    port: port.port,
                    reason,
                };
                if let Some(reason) = routing_left(service, port) {
                    left.push(leave(reason));
                    continue;
                }
                let backends = backends_of(service, port, *cluster_ip);
                if backends.is_empty() {
                    left.push(leave(LeftReason::NoReadyBackend));
                    continue;
                }
                if backends.len() > CLUSTERIP_MAX_BACKENDS_PER_SERVICE as usize {
                    left.push(leave(LeftReason::TooManyBackends));
                    continue;
                }
                if entries.len() >= CLUSTERIP_MAX_SERVICES as usize || backends.len() > budget {
                    left.push(leave(LeftReason::TableFull));
                    continue;
                }
                budget -= backends.len();
                entries.push(ClusterIpEntry {
                    namespace: service.namespace.clone(),
                    name: service.name.clone(),
                    cluster_ip: *cluster_ip,
                    port: port.port,
                    protocol: port.protocol,
                    affinity_secs: service.routing.affinity_secs.unwrap_or(0),
                    backends,
                });
            }
        }
    }
    ClusterIpPlan {
        entries,
        selected_pods,
        left_to_kube_proxy: left,
    }
}

fn routing_left(service: &ServiceView, port: &ServicePort) -> Option<LeftReason> {
    if port.protocol == Protocol::Sctp {
        return Some(LeftReason::Protocol);
    }
    if service.routing.node_local {
        return Some(LeftReason::NodeLocal);
    }
    if service.routing.topology {
        return Some(LeftReason::Topology);
    }
    None
}

/// The ready backends serving `port`, in the family of `cluster_ip`: the
/// slice port carrying the Service port's name and protocol gives the
/// backend's port.
fn backends_of(service: &ServiceView, port: &ServicePort, cluster_ip: IpAddr) -> Vec<SocketAddr> {
    service
        .backends
        .iter()
        .filter(|backend| backend.ip.is_ipv4() == cluster_ip.is_ipv4())
        .filter_map(|backend| {
            backend
                .ports
                .iter()
                .find(|named| named.name == port.name && named.protocol == port.protocol)
                .map(|named| SocketAddr::new(backend.ip, named.port))
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netpol::{NamedPort, NamespaceView, ServiceBackend, ServiceRouting};

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn selector(pairs: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: labels(pairs),
            ..LabelSelector::default()
        }
    }

    fn pod(uid: &str, namespace: &str, app: &str) -> PodView {
        PodView {
            uid: uid.into(),
            namespace: namespace.into(),
            name: uid.into(),
            labels: labels(&[("app", app)]),
            ips: Vec::new(),
            ports: Vec::new(),
            host_ips: Vec::new(),
            host_network: false,
            terminal: false,
        }
    }

    fn named(name: &str, port: u16, protocol: Protocol) -> NamedPort {
        NamedPort {
            name: name.into(),
            port,
            protocol,
        }
    }

    fn service(cluster_ips: &[&str], backends: &[&str]) -> ServiceView {
        ServiceView {
            namespace: "shop".into(),
            name: "api".into(),
            cluster_ips: cluster_ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            ports: vec![
                ServicePort {
                    name: "http".into(),
                    port: 80,
                    protocol: Protocol::Tcp,
                },
                ServicePort {
                    name: "dns".into(),
                    port: 53,
                    protocol: Protocol::Udp,
                },
            ],
            backends: backends
                .iter()
                .map(|ip| ServiceBackend {
                    ip: ip.parse().unwrap(),
                    ports: vec![
                        named("http", 8080, Protocol::Tcp),
                        named("dns", 5353, Protocol::Udp),
                    ],
                })
                .collect(),
            routing: ServiceRouting::default(),
        }
    }

    fn view(services: Vec<ServiceView>) -> ClusterView {
        ClusterView {
            policies: Vec::new(),
            pods: vec![
                pod("a", "shop", "web"),
                pod("b", "shop", "db"),
                pod("c", "lab", "web"),
            ],
            namespaces: vec![
                NamespaceView {
                    name: "shop".into(),
                    labels: labels(&[("kubernetes.io/metadata.name", "shop")]),
                },
                NamespaceView {
                    name: "lab".into(),
                    labels: labels(&[("kubernetes.io/metadata.name", "lab")]),
                },
            ],
            services,
        }
    }

    #[test]
    fn pods_and_namespaces_are_both_required_when_both_are_set() {
        let workloads = [WorkloadSelector {
            pods: Some(selector(&[("app", "web")])),
            namespaces: Some(selector(&[("kubernetes.io/metadata.name", "shop")])),
        }];
        let planned = plan(&view(Vec::new()), &workloads);
        assert_eq!(planned.selected_pods, BTreeSet::from(["a".to_string()]));
    }

    #[test]
    fn a_namespace_alone_selects_every_pod_in_it() {
        let workloads = [WorkloadSelector {
            pods: None,
            namespaces: Some(selector(&[("kubernetes.io/metadata.name", "shop")])),
        }];
        let planned = plan(&view(Vec::new()), &workloads);
        assert_eq!(
            planned.selected_pods,
            BTreeSet::from(["a".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn a_selector_naming_nothing_selects_nothing() {
        let planned = plan(&view(Vec::new()), &[WorkloadSelector::default()]);
        assert!(planned.selected_pods.is_empty());
    }

    #[test]
    fn host_network_and_finished_pods_are_never_selected() {
        let mut cluster = view(Vec::new());
        cluster.pods[0].host_network = true;
        cluster.pods[1].terminal = true;
        let workloads = [WorkloadSelector {
            pods: Some(LabelSelector::default()),
            namespaces: None,
        }];
        let planned = plan(&cluster, &workloads);
        assert_eq!(planned.selected_pods, BTreeSet::from(["c".to_string()]));
    }

    #[test]
    fn each_port_resolves_to_the_slice_port_of_its_name_and_protocol() {
        let planned = plan(
            &view(vec![service(
                &["10.96.0.10"],
                &["10.244.1.3", "10.244.2.4"],
            )]),
            &[],
        );
        assert_eq!(planned.entries.len(), 2);
        let http = &planned.entries[0];
        assert_eq!((http.port, http.protocol), (80, Protocol::Tcp));
        assert_eq!(
            http.backends,
            vec![
                "10.244.1.3:8080".parse().unwrap(),
                "10.244.2.4:8080".parse().unwrap()
            ]
        );
        let dns = &planned.entries[1];
        assert_eq!((dns.port, dns.protocol), (53, Protocol::Udp));
        assert_eq!(dns.backends[0], "10.244.1.3:5353".parse().unwrap());
        assert!(planned.left_to_kube_proxy.is_empty());
    }

    #[test]
    fn a_dual_stack_service_gets_each_family_its_own_backends() {
        let planned = plan(
            &view(vec![service(
                &["10.96.0.10", "fd00:96::10"],
                &["10.244.1.3", "fd00:244::3"],
            )]),
            &[],
        );
        for entry in &planned.entries {
            assert_eq!(entry.backends.len(), 1);
            assert_eq!(entry.backends[0].is_ipv4(), entry.cluster_ip.is_ipv4());
        }
        assert_eq!(planned.entries.len(), 4);
    }

    #[test]
    fn a_service_with_no_ready_backend_stays_with_kube_proxy() {
        let planned = plan(&view(vec![service(&["10.96.0.10"], &[])]), &[]);
        assert!(planned.entries.is_empty());
        assert_eq!(planned.left_to_kube_proxy.len(), 2);
        assert!(
            planned
                .left_to_kube_proxy
                .iter()
                .all(|left| left.reason == LeftReason::NoReadyBackend)
        );
    }

    #[test]
    fn node_local_and_topology_routing_stay_with_kube_proxy() {
        let mut local = service(&["10.96.0.10"], &["10.244.1.3"]);
        local.routing.node_local = true;
        let mut zoned = service(&["10.96.0.11"], &["10.244.1.3"]);
        zoned.name = "zoned".into();
        zoned.routing.topology = true;
        let planned = plan(&view(vec![local, zoned]), &[]);
        assert!(planned.entries.is_empty());
        let reasons: BTreeSet<LeftReason> = planned
            .left_to_kube_proxy
            .iter()
            .map(|left| left.reason)
            .collect();
        assert_eq!(
            reasons,
            BTreeSet::from([LeftReason::NodeLocal, LeftReason::Topology])
        );
    }

    #[test]
    fn sctp_stays_with_kube_proxy() {
        let mut sctp = service(&["10.96.0.10"], &["10.244.1.3"]);
        sctp.ports = vec![ServicePort {
            name: "sig".into(),
            port: 3868,
            protocol: Protocol::Sctp,
        }];
        let planned = plan(&view(vec![sctp]), &[]);
        assert_eq!(planned.left_to_kube_proxy[0].reason, LeftReason::Protocol);
    }

    #[test]
    fn client_ip_affinity_is_carried_with_its_timeout() {
        let mut sticky = service(&["10.96.0.10"], &["10.244.1.3"]);
        sticky.routing.affinity_secs = Some(600);
        let planned = plan(&view(vec![sticky]), &[]);
        assert!(
            planned
                .entries
                .iter()
                .all(|entry| entry.affinity_secs == 600)
        );
    }

    #[test]
    fn a_backend_listed_by_two_slices_is_counted_once() {
        let mut twice = service(&["10.96.0.10"], &["10.244.1.3", "10.244.1.3"]);
        twice.ports.truncate(1);
        let planned = plan(&view(vec![twice]), &[]);
        assert_eq!(planned.entries[0].backends.len(), 1);
    }
}
