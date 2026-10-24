//! The Kubernetes `NetworkPolicy` semantics, case by case.
//!
//! Each case builds a small cluster, compiles it, and asks the compiled
//! tables the question the kernel asks: the longest prefix holding the peer
//! address, then whether its ports open this one. The answers are the ones
//! the upstream API documentation gives for the same objects.

#![allow(clippy::unwrap_used, clippy::too_many_lines)]

use std::collections::{BTreeMap, HashSet};
use std::net::IpAddr;

use super::compile::{CompiledPolicy, NodeContext, compile};
use super::entity::{
    ClusterView, Direction, IpBlock, LabelRequirement, LabelSelector, NamedPort, NamespaceView,
    NetPrefix, NetworkPolicy, Peer, PodView, PolicyPort, PolicyRule, PortRef, Protocol,
    SelectorOperator, ServiceBackend, ServicePort, ServiceView,
};
use ebpf_common::netpol::NETPOL_MAX_RANGES;

const TCP: u8 = 6;
const UDP: u8 = 17;
const NODE: &str = "192.168.1.10";

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn select(pairs: &[(&str, &str)]) -> LabelSelector {
    LabelSelector {
        match_labels: labels(pairs),
        match_expressions: Vec::new(),
    }
}

fn pod(uid: &str, namespace: &str, pairs: &[(&str, &str)], address: &str) -> PodView {
    PodView {
        uid: uid.into(),
        namespace: namespace.into(),
        name: uid.into(),
        labels: labels(pairs),
        ips: vec![ip(address)],
        ports: Vec::new(),
        host_ips: Vec::new(),
        host_network: false,
        terminal: false,
    }
}

fn namespace(name: &str, pairs: &[(&str, &str)]) -> NamespaceView {
    let mut labels = labels(pairs);
    labels.insert("kubernetes.io/metadata.name".into(), name.into());
    NamespaceView {
        name: name.into(),
        labels,
    }
}

fn policy(namespace: &str, selector: LabelSelector) -> NetworkPolicy {
    NetworkPolicy {
        namespace: namespace.into(),
        name: "p".into(),
        pod_selector: selector,
        ingress: Vec::new(),
        egress: Vec::new(),
        policy_types: None,
    }
}

fn tcp(port: u16) -> PolicyPort {
    PolicyPort {
        protocol: Protocol::Tcp,
        port: Some(PortRef::Number(port)),
        end_port: None,
    }
}

fn block(cidr: &str, except: &[&str]) -> Peer {
    Peer::Block(IpBlock {
        cidr: NetPrefix::parse(cidr).unwrap(),
        except: except
            .iter()
            .map(|e| NetPrefix::parse(e).unwrap())
            .collect(),
    })
}

fn pods_peer(namespaces: Option<LabelSelector>, pods: Option<LabelSelector>) -> Peer {
    Peer::Pods { namespaces, pods }
}

fn run(view: &ClusterView, local: &[&str]) -> CompiledPolicy {
    let local: HashSet<String> = local.iter().map(|s| (*s).to_string()).collect();
    compile(
        view,
        &local,
        &NodeContext {
            node_ips: vec![ip(NODE)],
        },
    )
}

/// The kernel's question, asked of the compiled tables.
fn allows(
    compiled: &CompiledPolicy,
    uid: &str,
    direction: Direction,
    peer: &str,
    protocol: u8,
    port: u16,
) -> bool {
    compiled.admits(uid, direction, ip(peer), protocol, port)
}

fn base() -> ClusterView {
    ClusterView {
        policies: Vec::new(),
        pods: vec![
            pod("web", "shop", &[("app", "web")], "10.0.0.1"),
            pod("api", "shop", &[("app", "api")], "10.0.0.2"),
            pod("db", "shop", &[("app", "db")], "10.0.0.3"),
            pod("mon", "ops", &[("app", "web")], "10.0.1.1"),
            pod("job", "ci", &[("app", "runner")], "10.0.2.1"),
        ],
        namespaces: vec![
            namespace("shop", &[("team", "shop")]),
            namespace("ops", &[("team", "ops")]),
            namespace("ci", &[]),
        ],
        services: Vec::new(),
    }
}

#[test]
fn a_pod_no_policy_selects_is_open_both_ways() {
    let compiled = run(&base(), &["web", "api", "db"]);
    assert!(compiled.pods.is_empty());
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.9.9.9",
        TCP,
        5432
    ));
}

#[test]
fn deny_all_ingress_closes_ingress_and_leaves_egress_open() {
    let mut view = base();
    view.policies.push(policy("shop", LabelSelector::default()));
    let compiled = run(&view, &["web", "api", "db", "mon"]);
    assert_eq!(
        compiled.report.selected_pods, 3,
        "a policy stays in its namespace"
    );
    assert!(!compiled.pods.contains_key("mon"));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.2",
        TCP,
        5432
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Egress,
        "10.0.0.2",
        TCP,
        5432
    ));
}

#[test]
fn the_node_and_loopback_are_open_under_any_policy() {
    let mut view = base();
    let mut deny = policy("shop", LabelSelector::default());
    deny.policy_types = Some(vec![Direction::Ingress, Direction::Egress]);
    view.policies.push(deny);
    let compiled = run(&view, &["db"]);
    for direction in [Direction::Ingress, Direction::Egress] {
        assert!(allows(&compiled, "db", direction, NODE, TCP, 10_250));
        assert!(allows(&compiled, "db", direction, "127.0.0.1", UDP, 53));
        assert!(allows(&compiled, "db", direction, "::1", TCP, 80));
        assert!(!allows(&compiled, "db", direction, "10.0.0.1", TCP, 80));
    }
}

#[test]
fn a_pod_selector_alone_stays_in_the_policy_namespace() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: vec![pods_peer(None, Some(select(&[("app", "web")])))],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        5432
    ));
    assert!(
        !allows(&compiled, "db", Direction::Ingress, "10.0.1.1", TCP, 5432),
        "the same label in another namespace is not selected"
    );
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.2",
        TCP,
        5432
    ));
}

#[test]
fn a_namespace_selector_alone_takes_every_pod_of_the_namespaces() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: vec![pods_peer(Some(select(&[("team", "ops")])), None)],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.1.1",
        TCP,
        1
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        1
    ));
}

#[test]
fn both_selectors_in_one_peer_intersect_and_in_two_peers_unite() {
    let mut view = base();
    let mut together = policy("shop", select(&[("app", "db")]));
    together.ingress.push(PolicyRule {
        peers: vec![pods_peer(
            Some(select(&[("team", "ops")])),
            Some(select(&[("app", "api")])),
        )],
        ports: Vec::new(),
    });
    view.policies.push(together);
    let compiled = run(&view, &["db"]);
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.1.1",
        TCP,
        1
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.2",
        TCP,
        1
    ));

    view.policies[0].ingress[0].peers = vec![
        pods_peer(Some(select(&[("team", "ops")])), None),
        pods_peer(None, Some(select(&[("app", "api")]))),
    ];
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.1.1",
        TCP,
        1
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.2",
        TCP,
        1
    ));
}

#[test]
fn an_empty_namespace_selector_is_every_namespace() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: vec![pods_peer(Some(LabelSelector::default()), None)],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.2.1",
        TCP,
        1
    ));
    assert!(
        !allows(&compiled, "db", Direction::Ingress, "8.8.8.8", TCP, 1),
        "pods of every namespace are not every address"
    );
}

#[test]
fn a_match_expression_selects_by_the_metadata_name_label() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: vec![pods_peer(
            Some(LabelSelector {
                match_labels: BTreeMap::new(),
                match_expressions: vec![LabelRequirement {
                    key: "kubernetes.io/metadata.name".into(),
                    operator: SelectorOperator::In,
                    values: vec!["ci".into()],
                }],
            }),
            None,
        )],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.2.1",
        TCP,
        1
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.1.1",
        TCP,
        1
    ));
}

#[test]
fn an_empty_rule_opens_everything_and_rules_of_two_policies_unite() {
    let mut view = base();
    let mut first = policy("shop", select(&[("app", "db")]));
    first.ingress.push(PolicyRule {
        peers: vec![block("10.0.0.0/24", &[])],
        ports: vec![tcp(5432)],
    });
    let mut second = policy("shop", select(&[("app", "db")]));
    second.name = "q".into();
    second.ingress.push(PolicyRule {
        peers: vec![block("10.0.0.0/24", &[])],
        ports: vec![tcp(9187)],
    });
    view.policies.extend([first, second]);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        5432
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        9187
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        22
    ));

    view.policies[1].ingress[0] = PolicyRule::default();
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "8.8.8.8",
        UDP,
        9
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "fd00::9",
        TCP,
        22
    ));
}

#[test]
fn an_ip_block_except_closes_inside_and_a_narrower_rule_reopens_it() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "web")]));
    p.policy_types = Some(vec![Direction::Egress]);
    p.egress.push(PolicyRule {
        peers: vec![block("10.0.0.0/8", &["10.1.0.0/16", "10.1.2.0/24"])],
        ports: Vec::new(),
    });
    p.egress.push(PolicyRule {
        peers: vec![block("10.1.2.0/24", &[])],
        ports: vec![tcp(80)],
    });
    view.policies.push(p);
    let compiled = run(&view, &["web"]);
    assert!(allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.2.0.1",
        UDP,
        53
    ));
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.1.3.1",
        TCP,
        80
    ));
    assert!(allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.1.2.5",
        TCP,
        80
    ));
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.1.2.5",
        TCP,
        81
    ));
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "11.0.0.1",
        TCP,
        80
    ));
    assert!(
        allows(&compiled, "web", Direction::Ingress, "11.0.0.1", TCP, 80),
        "an egress-only policy leaves ingress open"
    );
}

#[test]
fn an_ipv4_block_never_opens_an_ipv6_peer() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "web")]));
    p.policy_types = Some(vec![Direction::Egress]);
    p.egress.push(PolicyRule {
        peers: vec![block("0.0.0.0/0", &[])],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["web"]);
    assert!(allows(
        &compiled,
        "web",
        Direction::Egress,
        "1.1.1.1",
        TCP,
        443
    ));
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "2606:4700::1111",
        TCP,
        443
    ));
}

#[test]
fn ports_by_range_and_by_protocol_alone() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: Vec::new(),
        ports: vec![
            PolicyPort {
                protocol: Protocol::Tcp,
                port: Some(PortRef::Number(8000)),
                end_port: Some(8010),
            },
            PolicyPort {
                protocol: Protocol::Udp,
                port: None,
                end_port: None,
            },
        ],
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        8005
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        8010
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        8011
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        UDP,
        1
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        1
    ));
}

#[test]
fn a_named_port_resolves_on_the_local_pod_in_and_on_each_peer_out() {
    let mut view = base();
    view.pods[2].ports.push(NamedPort {
        name: "pg".into(),
        port: 5432,
        protocol: Protocol::Tcp,
    });
    view.pods[1].ports.push(NamedPort {
        name: "http".into(),
        port: 8080,
        protocol: Protocol::Tcp,
    });
    view.pods[0].ports.push(NamedPort {
        name: "http".into(),
        port: 3000,
        protocol: Protocol::Tcp,
    });
    let named = |name: &str| PolicyPort {
        protocol: Protocol::Tcp,
        port: Some(PortRef::Name(name.into())),
        end_port: None,
    };
    let mut inbound = policy("shop", select(&[("app", "db")]));
    inbound.ingress.push(PolicyRule {
        peers: Vec::new(),
        ports: vec![named("pg")],
    });
    let mut outbound = policy("shop", select(&[("app", "db")]));
    outbound.name = "out".into();
    outbound.policy_types = Some(vec![Direction::Egress]);
    outbound.egress.push(PolicyRule {
        peers: vec![pods_peer(None, Some(LabelSelector::default()))],
        ports: vec![named("http")],
    });
    view.policies.extend([inbound, outbound]);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "8.8.8.8",
        TCP,
        5432
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "8.8.8.8",
        TCP,
        5433
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Egress,
        "10.0.0.2",
        TCP,
        8080
    ));
    assert!(allows(
        &compiled,
        "db",
        Direction::Egress,
        "10.0.0.1",
        TCP,
        3000
    ));
    assert!(
        !allows(&compiled, "db", Direction::Egress, "10.0.0.1", TCP, 8080),
        "each peer's own number, not another's"
    );
}

#[test]
fn a_named_port_nothing_carries_opens_nothing() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: Vec::new(),
        ports: vec![PolicyPort {
            protocol: Protocol::Tcp,
            port: Some(PortRef::Name("missing".into())),
            end_port: None,
        }],
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(compiled.pods["db"].ingress_isolated);
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        5432
    ));
}

#[test]
fn egress_is_governed_by_default_only_when_written() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "web")]));
    p.egress.push(PolicyRule {
        peers: vec![pods_peer(None, Some(select(&[("app", "api")])))],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["web"]);
    let assignment = compiled.pods["web"];
    assert!(assignment.ingress_isolated && assignment.egress_isolated);
    assert!(allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.0.0.2",
        TCP,
        1
    ));
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.0.0.3",
        TCP,
        1
    ));
}

#[test]
fn host_network_and_finished_pods_are_neither_targets_nor_peers() {
    let mut view = base();
    view.pods[1].host_network = true;
    view.pods[0].terminal = true;
    view.policies.push(policy("shop", LabelSelector::default()));
    let mut p = policy("shop", select(&[("app", "db")]));
    p.name = "q".into();
    p.ingress.push(PolicyRule {
        peers: vec![pods_peer(None, Some(LabelSelector::default()))],
        ports: Vec::new(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["web", "api", "db"]);
    assert!(!compiled.pods.contains_key("api"));
    assert!(!compiled.pods.contains_key("web"));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        1
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.2",
        TCP,
        1
    ));
}

#[test]
fn pods_selected_the_same_way_share_a_slot() {
    let mut view = base();
    view.pods
        .push(pod("db-2", "shop", &[("app", "db")], "10.0.0.4"));
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: vec![pods_peer(None, Some(select(&[("app", "api")])))],
        ports: vec![tcp(5432)],
    });
    view.policies.push(p);
    view.policies
        .push(policy("shop", select(&[("app", "web")])));
    let compiled = run(&view, &["db", "db-2", "web"]);
    assert_eq!(compiled.pods["db"].slot, compiled.pods["db-2"].slot);
    assert_ne!(compiled.pods["db"].slot, compiled.pods["web"].slot);
    assert_eq!(compiled.slots.len(), 2);
}

fn service(backends: &[&str]) -> ServiceView {
    ServiceView {
        namespace: "shop".into(),
        name: "api".into(),
        cluster_ips: vec![ip("10.96.0.10")],
        ports: vec![ServicePort {
            name: "http".into(),
            port: 80,
            protocol: Protocol::Tcp,
        }],
        backends: backends
            .iter()
            .map(|address| ServiceBackend {
                ip: ip(address),
                ports: vec![NamedPort {
                    name: "http".into(),
                    port: 8080,
                    protocol: Protocol::Tcp,
                }],
            })
            .collect(),
    }
}

fn egress_to_api() -> ClusterView {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "web")]));
    p.policy_types = Some(vec![Direction::Egress]);
    p.egress.push(PolicyRule {
        peers: vec![pods_peer(None, Some(select(&[("app", "api")])))],
        ports: vec![tcp(8080)],
    });
    view.policies.push(p);
    view
}

#[test]
fn a_service_address_opens_when_every_backend_is_allowed() {
    let mut view = egress_to_api();
    view.services.push(service(&["10.0.0.2"]));
    let compiled = run(&view, &["web"]);
    assert!(allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.96.0.10",
        TCP,
        80
    ));
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.96.0.10",
        TCP,
        81
    ));
    assert!(compiled.report.refused_services.is_empty());
}

#[test]
fn a_service_with_some_backends_refused_stays_closed_and_is_reported() {
    let mut view = egress_to_api();
    view.services.push(service(&["10.0.0.2", "10.0.0.3"]));
    let compiled = run(&view, &["web"]);
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.96.0.10",
        TCP,
        80
    ));
    let refused = &compiled.report.refused_services;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].service, "shop/api");
    assert_eq!((refused[0].allowed_backends, refused[0].backends), (1, 2));
}

#[test]
fn a_service_with_no_backend_allowed_is_closed_without_a_report() {
    let mut view = egress_to_api();
    view.services.push(service(&["10.0.0.3"]));
    let compiled = run(&view, &["web"]);
    assert!(!allows(
        &compiled,
        "web",
        Direction::Egress,
        "10.96.0.10",
        TCP,
        80
    ));
    assert!(compiled.report.refused_services.is_empty());
}

#[test]
fn ranges_past_the_kernel_ceiling_are_closed_and_reported() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    let wanted = NETPOL_MAX_RANGES + 2;
    p.ingress.push(PolicyRule {
        peers: Vec::new(),
        ports: (0..wanted)
            .map(|i| tcp(1000 + 2 * u16::try_from(i).unwrap()))
            .collect(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        1000
    ));
    let last = 1000 + 2 * u16::try_from(wanted - 1).unwrap();
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        last
    ));
    assert!(
        compiled
            .report
            .truncated
            .iter()
            .any(|t| t.pod == "shop/db" && t.dropped == 2)
    );
}

#[test]
fn adjacent_ranges_merge_so_they_take_one_place() {
    let mut view = base();
    let mut p = policy("shop", select(&[("app", "db")]));
    p.ingress.push(PolicyRule {
        peers: Vec::new(),
        ports: (0..40).map(|i| tcp(2000 + i)).collect(),
    });
    view.policies.push(p);
    let compiled = run(&view, &["db"]);
    assert!(compiled.report.truncated.is_empty());
    assert!(allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        2039
    ));
    assert!(!allows(
        &compiled,
        "db",
        Direction::Ingress,
        "10.0.0.1",
        TCP,
        2040
    ));
}

#[test]
fn only_the_pods_of_this_node_are_compiled() {
    let mut view = base();
    view.policies.push(policy("shop", LabelSelector::default()));
    let compiled = run(&view, &["db"]);
    assert_eq!(compiled.pods.len(), 1);
    assert!(compiled.pods.contains_key("db"));
}

#[test]
fn the_node_is_the_host_its_local_pods_report() {
    let mut view = ClusterView::default();
    let mut here = pod("a", "shop", &[], "10.0.0.5");
    here.host_ips = vec![ip("192.168.1.10"), ip("fd00::10")];
    let mut also = pod("b", "shop", &[], "10.0.0.6");
    also.host_ips = vec![ip("192.168.1.10")];
    let mut elsewhere = pod("c", "shop", &[], "10.0.1.6");
    elsewhere.host_ips = vec![ip("192.168.1.11")];
    view.pods = vec![here, also, elsewhere];
    let local: HashSet<String> = ["a".to_string(), "b".to_string()].into_iter().collect();
    let node = NodeContext::from_pods(&view, &local);
    assert_eq!(node.node_ips, vec![ip("192.168.1.10"), ip("fd00::10")]);
}
