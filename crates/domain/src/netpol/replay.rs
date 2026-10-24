//! What a set of policies would have refused, asked of flows already seen.
//!
//! The proposed policies are laid over the cluster's own (an object of the
//! same namespace and name replaces the one in force, any other is added),
//! both sets are compiled exactly as the agent compiles them, and every
//! observed flow is put to the compiled tables twice: once as the cluster
//! stands and once as it would stand. A flow the proposal refuses is
//! reported against the pod that would refuse it, saying whether the
//! policies in force already refuse it too.
//!
//! A flow is judged by its original direction only, because that is the
//! connection the policy decides; its answers ride on it. Egress is judged
//! against the address the pod connected to, a Service address included,
//! because that is what the socket hook sees. Ingress is judged where the
//! flow was delivered, which for a Service address is the backend the
//! translation chose, and against the address the backend saw it come from.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;

use super::compile::{CompiledPolicy, NodeContext, compile};
use super::entity::{ClusterView, Direction, NetworkPolicy, PodView};

const TCP: u8 = 6;
const UDP: u8 = 17;

/// One flow as the connection table recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedFlow {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    pub dst_port: u16,
    /// Where the flow was delivered and the source the receiver saw, when
    /// an address was translated on the way.
    pub delivered: Option<Delivery>,
}

/// The far end of a translated flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    pub to: IpAddr,
    pub port: u16,
    pub seen_from: IpAddr,
}

/// A flow the proposal refuses, folded with every flow of the same shape.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RefusedFlow {
    pub direction: Direction,
    /// The address at the other end, as the deciding hook sees it.
    pub peer: IpAddr,
    pub protocol: u8,
    pub port: u16,
    /// The policies in force refuse it already.
    pub already_refused: bool,
    /// How many observed flows had this shape.
    pub flows: usize,
}

/// Everything one pod would refuse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadReplay {
    pub namespace: String,
    pub pod: String,
    pub refused: Vec<RefusedFlow>,
}

/// What the replay found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Flows read.
    pub flows: usize,
    /// Flows with a known pod at one end at least, the only ones a policy
    /// can decide.
    pub judged: usize,
    /// Flows the proposal refuses that the policies in force let through.
    pub newly_refused: usize,
    /// Flows the proposal refuses that are refused already.
    pub still_refused: usize,
    pub workloads: Vec<WorkloadReplay>,
}

/// The cluster's policies with `proposed` laid over them.
pub fn overlay(view: &ClusterView, proposed: &[NetworkPolicy]) -> ClusterView {
    let replaced: BTreeSet<(&str, &str)> = proposed
        .iter()
        .map(|policy| (policy.namespace.as_str(), policy.name.as_str()))
        .collect();
    let mut policies: Vec<NetworkPolicy> = view
        .policies
        .iter()
        .filter(|policy| !replaced.contains(&(policy.namespace.as_str(), policy.name.as_str())))
        .cloned()
        .collect();
    policies.extend(proposed.iter().cloned());
    ClusterView {
        policies,
        ..view.clone()
    }
}

/// One deciding end of a flow.
struct Judgement<'a> {
    pod: &'a PodView,
    direction: Direction,
    peer: IpAddr,
    protocol: u8,
    port: u16,
}

/// Every deciding end of every flow, with the flow it came from, and how
/// many flows had a known pod at one end at least.
fn judgements<'a>(
    view: &'a ClusterView,
    flows: &[ObservedFlow],
) -> (Vec<(usize, Judgement<'a>)>, usize) {
    let by_ip: BTreeMap<IpAddr, &PodView> = view
        .pods
        .iter()
        .filter(|pod| pod.is_peer())
        .flat_map(|pod| pod.ips.iter().map(move |ip| (ip.to_canonical(), pod)))
        .collect();
    let mut judgements = Vec::new();
    let mut judged = 0;
    for (index, flow) in flows.iter().enumerate() {
        let mut known = false;
        if let Some(pod) = by_ip.get(&flow.src.to_canonical()) {
            known = true;
            judgements.push((
                index,
                Judgement {
                    pod,
                    direction: Direction::Egress,
                    peer: flow.dst,
                    protocol: flow.protocol,
                    port: flow.dst_port,
                },
            ));
        }
        let (to, port, from) = match flow.delivered {
            Some(delivery) => (delivery.to, delivery.port, delivery.seen_from),
            None => (flow.dst, flow.dst_port, flow.src),
        };
        if let Some(pod) = by_ip.get(&to.to_canonical()) {
            known = true;
            // Inbound ICMP and SCTP are not filtered, so nothing would
            // refuse them there.
            if matches!(flow.protocol, TCP | UDP) {
                judgements.push((
                    index,
                    Judgement {
                        pod,
                        direction: Direction::Ingress,
                        peer: from,
                        protocol: flow.protocol,
                        port,
                    },
                ));
            }
        }
        judged += usize::from(known);
    }
    (judgements, judged)
}

/// The tables as they stand and as they would stand, compiled for every
/// node a judged pod runs on, and for each pod the pair it is read from.
///
/// Each pod is compiled with the node it runs on, since the node's own
/// addresses are open to it whatever the policies say.
fn compile_per_node<'a>(
    before: &ClusterView,
    after: &ClusterView,
    judgements: &[(usize, Judgement<'a>)],
) -> (Vec<CompiledPolicy>, BTreeMap<&'a str, (usize, usize)>) {
    let mut nodes: BTreeMap<Vec<IpAddr>, HashSet<String>> = BTreeMap::new();
    for (_, judgement) in judgements {
        let mut host = judgement.pod.host_ips.clone();
        host.sort_unstable();
        nodes
            .entry(host)
            .or_default()
            .insert(judgement.pod.uid.clone());
    }
    let mut tables = Vec::new();
    let mut by_pod = BTreeMap::new();
    for (node_ips, local) in &nodes {
        let node = NodeContext {
            node_ips: node_ips.clone(),
        };
        let now = tables.len();
        tables.push(compile(before, local, &node));
        tables.push(compile(after, local, &node));
        for (_, judgement) in judgements {
            if local.contains(&judgement.pod.uid) {
                by_pod.insert(judgement.pod.uid.as_str(), (now, now + 1));
            }
        }
    }
    (tables, by_pod)
}

/// Replay `flows` against `view` with `proposed` laid over it.
pub fn replay(
    view: &ClusterView,
    proposed: &[NetworkPolicy],
    flows: &[ObservedFlow],
) -> ReplayReport {
    let (judgements, judged) = judgements(view, flows);
    let after = overlay(view, proposed);
    let (tables, compiled) = compile_per_node(view, &after, &judgements);
    let mut report = ReplayReport {
        flows: flows.len(),
        judged,
        ..ReplayReport::default()
    };

    let mut refused_flows: BTreeSet<usize> = BTreeSet::new();
    let mut newly: BTreeSet<usize> = BTreeSet::new();
    let mut folded: BTreeMap<(&str, &str), BTreeMap<RefusedFlow, usize>> = BTreeMap::new();
    for (index, judgement) in &judgements {
        let Some(&(now, then)) = compiled.get(judgement.pod.uid.as_str()) else {
            continue;
        };
        let ask = |table: &CompiledPolicy| {
            table.admits(
                &judgement.pod.uid,
                judgement.direction,
                judgement.peer,
                judgement.protocol,
                judgement.port,
            )
        };
        if ask(&tables[then]) {
            continue;
        }
        let already_refused = !ask(&tables[now]);
        refused_flows.insert(*index);
        if !already_refused {
            newly.insert(*index);
        }
        let shape = RefusedFlow {
            direction: judgement.direction,
            peer: judgement.peer,
            protocol: judgement.protocol,
            port: judgement.port,
            already_refused,
            flows: 0,
        };
        *folded
            .entry((
                judgement.pod.namespace.as_str(),
                judgement.pod.name.as_str(),
            ))
            .or_default()
            .entry(shape)
            .or_default() += 1;
    }

    report.newly_refused = newly.len();
    report.still_refused = refused_flows.len() - newly.len();
    report.workloads = folded
        .into_iter()
        .map(|((namespace, pod), shapes)| WorkloadReplay {
            namespace: namespace.to_string(),
            pod: pod.to_string(),
            refused: shapes
                .into_iter()
                .map(|(shape, flows)| RefusedFlow { flows, ..shape })
                .collect(),
        })
        .collect();
    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::netpol::entity::{
        LabelSelector, Peer, PolicyPort, PolicyRule, PortRef, Protocol, ServiceBackend,
        ServicePort, ServiceView,
    };

    const NODE: &str = "192.168.1.10";

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    fn pod(name: &str, app: &str, address: &str) -> PodView {
        PodView {
            uid: format!("uid-{name}"),
            namespace: "shop".into(),
            name: name.into(),
            labels: [("app".to_string(), app.to_string())].into(),
            ips: vec![ip(address)],
            ports: Vec::new(),
            host_ips: vec![ip(NODE)],
            host_network: false,
            terminal: false,
        }
    }

    fn select(app: &str) -> LabelSelector {
        LabelSelector {
            match_labels: [("app".to_string(), app.to_string())].into(),
            match_expressions: Vec::new(),
        }
    }

    /// `api` takes TCP 8080 from `web` and nothing else.
    fn api_from_web_only(name: &str) -> NetworkPolicy {
        NetworkPolicy {
            namespace: "shop".into(),
            name: name.into(),
            pod_selector: select("api"),
            ingress: vec![PolicyRule {
                peers: vec![Peer::Pods {
                    namespaces: None,
                    pods: Some(select("web")),
                }],
                ports: vec![PolicyPort {
                    protocol: Protocol::Tcp,
                    port: Some(PortRef::Number(8080)),
                    end_port: None,
                }],
            }],
            egress: Vec::new(),
            policy_types: None,
        }
    }

    fn cluster() -> ClusterView {
        ClusterView {
            pods: vec![
                pod("web-1", "web", "10.244.1.2"),
                pod("api-1", "api", "10.244.1.3"),
                pod("batch-1", "batch", "10.244.1.4"),
            ],
            ..ClusterView::default()
        }
    }

    fn tcp(src: &str, dst: &str, port: u16) -> ObservedFlow {
        ObservedFlow {
            src: ip(src),
            dst: ip(dst),
            protocol: TCP,
            dst_port: port,
            delivered: None,
        }
    }

    #[test]
    fn a_new_deny_reports_what_it_would_have_refused_by_pod() {
        let flows = [
            tcp("10.244.1.2", "10.244.1.3", 8080),
            tcp("10.244.1.4", "10.244.1.3", 8080),
            tcp("10.244.1.4", "10.244.1.3", 8080),
            tcp("10.244.1.2", "10.244.1.3", 9090),
            tcp("203.0.113.9", "198.51.100.1", 443),
        ];
        let report = replay(&cluster(), &[api_from_web_only("api")], &flows);
        assert_eq!(report.flows, 5);
        assert_eq!(report.judged, 4);
        assert_eq!(report.newly_refused, 3);
        assert_eq!(report.still_refused, 0);
        assert_eq!(report.workloads.len(), 1);
        let api = &report.workloads[0];
        assert_eq!(
            (api.namespace.as_str(), api.pod.as_str()),
            ("shop", "api-1")
        );
        assert_eq!(
            api.refused,
            vec![
                RefusedFlow {
                    direction: Direction::Ingress,
                    peer: ip("10.244.1.2"),
                    protocol: TCP,
                    port: 9090,
                    already_refused: false,
                    flows: 1,
                },
                RefusedFlow {
                    direction: Direction::Ingress,
                    peer: ip("10.244.1.4"),
                    protocol: TCP,
                    port: 8080,
                    already_refused: false,
                    flows: 2,
                },
            ]
        );
    }

    #[test]
    fn a_policy_of_the_same_name_replaces_the_one_in_force() {
        // In force: `api` takes 8080 from `batch` only.
        let mut view = cluster();
        let mut from_batch = api_from_web_only("api");
        from_batch.ingress[0].peers = vec![Peer::Pods {
            namespaces: None,
            pods: Some(select("batch")),
        }];
        view.policies.push(from_batch);
        let flows = [
            tcp("10.244.1.2", "10.244.1.3", 8080),
            tcp("10.244.1.4", "10.244.1.3", 8080),
        ];

        // Same name: `batch` loses its way in, `web` gains one.
        let report = replay(&view, &[api_from_web_only("api")], &flows);
        assert_eq!(report.newly_refused, 1);
        assert_eq!(report.still_refused, 0);
        assert_eq!(report.workloads[0].refused[0].peer, ip("10.244.1.4"));

        // Another name: the two policies add up and nothing is refused.
        let report = replay(&view, &[api_from_web_only("other")], &flows);
        assert_eq!(report.newly_refused + report.still_refused, 0);
    }

    #[test]
    fn a_flow_refused_already_is_told_apart() {
        let mut view = cluster();
        let mut deny_all = api_from_web_only("deny");
        deny_all.ingress.clear();
        view.policies.push(deny_all);
        let flows = [tcp("10.244.1.4", "10.244.1.3", 8080)];
        let report = replay(&view, &[api_from_web_only("api")], &flows);
        assert_eq!(report.newly_refused, 0);
        assert_eq!(report.still_refused, 1);
        assert!(report.workloads[0].refused[0].already_refused);
    }

    #[test]
    fn ingress_through_a_service_is_judged_at_the_backend() {
        let mut view = cluster();
        view.services.push(ServiceView {
            namespace: "shop".into(),
            name: "api".into(),
            cluster_ips: vec![ip("10.96.0.20")],
            ports: vec![ServicePort {
                name: "http".into(),
                port: 80,
                protocol: Protocol::Tcp,
            }],
            backends: vec![ServiceBackend {
                ip: ip("10.244.1.3"),
                ports: Vec::new(),
            }],
        });
        let flow = ObservedFlow {
            delivered: Some(Delivery {
                to: ip("10.244.1.3"),
                port: 8080,
                seen_from: ip("10.244.1.4"),
            }),
            ..tcp("10.244.1.4", "10.96.0.20", 80)
        };
        let report = replay(&view, &[api_from_web_only("api")], &[flow]);
        assert_eq!(report.newly_refused, 1);
        assert_eq!(report.workloads[0].pod, "api-1");
        assert_eq!(report.workloads[0].refused[0].port, 8080);
    }

    #[test]
    fn the_node_is_open_and_inbound_icmp_is_not_filtered() {
        let flows = [
            tcp(NODE, "10.244.1.3", 8080),
            ObservedFlow {
                protocol: 1,
                ..tcp("10.244.1.4", "10.244.1.3", 0)
            },
        ];
        let report = replay(&cluster(), &[api_from_web_only("api")], &flows);
        assert_eq!(report.judged, 2);
        assert_eq!(report.newly_refused, 0);
        assert!(report.workloads.is_empty());
    }

    #[test]
    fn egress_is_judged_against_the_address_the_pod_connected_to() {
        let egress = NetworkPolicy {
            namespace: "shop".into(),
            name: "web-out".into(),
            pod_selector: select("web"),
            ingress: Vec::new(),
            egress: vec![PolicyRule {
                peers: vec![Peer::Pods {
                    namespaces: None,
                    pods: Some(select("api")),
                }],
                ports: Vec::new(),
            }],
            policy_types: Some(vec![Direction::Egress]),
        };
        let flows = [
            tcp("10.244.1.2", "10.244.1.3", 8080),
            tcp("10.244.1.2", "10.244.1.4", 8080),
        ];
        let report = replay(&cluster(), &[egress], &flows);
        assert_eq!(report.newly_refused, 1);
        let web = &report.workloads[0];
        assert_eq!(web.pod, "web-1");
        assert_eq!(web.refused[0].direction, Direction::Egress);
        assert_eq!(web.refused[0].peer, ip("10.244.1.4"));
    }
}
