//! From the cluster's policies to the prefixes the kernel looks up.
//!
//! Each selected pod of this node gets a program: whether it is isolated in
//! each direction and, for each isolated one, a list of peer prefixes with the
//! ports they open. The list is built so that the longest prefix holding an
//! address is the whole answer for it: every rule's prefix is an entry, every
//! `except` is an entry too, and each entry carries the union of the rules
//! whose prefix contains it and whose excepts do not. An address no entry
//! holds is closed. Pods with identical programs share one slot.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::hash::BuildHasher;
use std::net::IpAddr;

use ebpf_common::netpol::{NETPOL_MAX_ENTRIES, NETPOL_MAX_RANGES, NETPOL_MAX_SLOTS};

use super::entity::{
    ClusterView, Direction, LabelSelector, NamedPort, NetPrefix, NetworkPolicy, Peer, PodView,
    PolicyPort, PolicyRule, PortRef, Protocol, ServiceView, resolve_named,
};

/// Programs kept back so a pod whose rule set did not fit can still be closed.
const CLOSED_SLOT_RESERVE: usize = 3;

/// An inclusive range of ports of one protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortRange {
    pub protocol: u8,
    pub lo: u16,
    pub hi: u16,
}

/// What a peer may reach: every port, or a set of ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PortSet {
    pub all: bool,
    pub ranges: Vec<PortRange>,
}

impl PortSet {
    pub fn all() -> Self {
        Self {
            all: true,
            ranges: Vec::new(),
        }
    }

    pub fn single(protocol: Protocol, port: u16) -> Self {
        Self {
            all: false,
            ranges: vec![PortRange {
                protocol: protocol.number(),
                lo: port,
                hi: port,
            }],
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.all && self.ranges.is_empty()
    }

    /// Whether this set opens `port` of `protocol`, the question the kernel
    /// asks of the entry it found.
    pub fn allows(&self, protocol: u8, port: u16) -> bool {
        self.all
            || self
                .ranges
                .iter()
                .any(|range| range.protocol == protocol && range.lo <= port && port <= range.hi)
    }

    fn union(&mut self, other: &Self) {
        self.all |= other.all;
        self.ranges.extend_from_slice(&other.ranges);
        self.normalise();
    }

    /// Sorted, merged, and empty of ranges once every port is open.
    fn normalise(&mut self) {
        if self.all {
            self.ranges.clear();
            return;
        }
        self.ranges.sort_unstable();
        let mut merged: Vec<PortRange> = Vec::with_capacity(self.ranges.len());
        for range in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && last.protocol == range.protocol
                && u32::from(range.lo) <= u32::from(last.hi) + 1
            {
                last.hi = last.hi.max(range.hi);
                continue;
            }
            merged.push(range);
        }
        self.ranges = merged;
    }
}

/// One prefix of a slot, in one direction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotEntry {
    pub direction: Direction,
    pub prefix: NetPrefix,
    pub ports: PortSet,
}

/// Everything the kernel needs for the pods sharing one slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotProgram {
    pub ingress_isolated: bool,
    pub egress_isolated: bool,
    pub entries: Vec<SlotEntry>,
}

/// The slot a selected pod of this node answers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodAssignment {
    pub slot: u16,
    pub ingress_isolated: bool,
    pub egress_isolated: bool,
}

/// A prefix that named more port ranges than the kernel carries; the ones
/// past the ceiling are closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Truncation {
    pub pod: String,
    pub direction: Direction,
    pub prefix: NetPrefix,
    pub dropped: usize,
}

/// A Service address left closed because only some of its backends are
/// allowed: the hook sees the Service address before it is translated, so it
/// cannot open it for the allowed backends alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedService {
    pub pod: String,
    pub service: String,
    pub port: u16,
    pub protocol: Protocol,
    pub allowed_backends: usize,
    pub backends: usize,
}

/// What the compile could not write as the policies say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompileReport {
    /// Pods of this node some policy selects.
    pub selected_pods: usize,
    pub truncated: Vec<Truncation>,
    pub refused_services: Vec<RefusedService>,
    /// Pods whose rule set did not fit the table, closed in every direction
    /// they are isolated in rather than left open.
    pub closed: Vec<String>,
}

/// What the kernel is given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CompiledPolicy {
    /// Indexed by slot.
    pub slots: Vec<SlotProgram>,
    /// Pod uid to slot. A pod absent from here is selected by no policy and
    /// open in both directions.
    pub pods: BTreeMap<String, PodAssignment>,
    pub report: CompileReport,
}

impl CompiledPolicy {
    pub fn entry_count(&self) -> usize {
        self.slots.iter().map(|slot| slot.entries.len()).sum()
    }
}

/// What the compile knows about the node itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NodeContext {
    /// The node's own addresses. Traffic to and from them is always allowed,
    /// so the kubelet's probes keep working under any policy.
    pub node_ips: Vec<IpAddr>,
}

impl NodeContext {
    /// The node's addresses, as the pods of `local` report the host they run
    /// on. Every pod of one node reports the same ones, so the union is the
    /// node's whole set without reading the `Node` object.
    pub fn from_pods<S: BuildHasher>(view: &ClusterView, local: &HashSet<String, S>) -> Self {
        let node_ips: BTreeSet<IpAddr> = view
            .pods
            .iter()
            .filter(|pod| local.contains(&pod.uid))
            .flat_map(|pod| pod.host_ips.iter().copied())
            .collect();
        Self {
            node_ips: node_ips.into_iter().collect(),
        }
    }
}

/// A rule, flattened to one prefix and what it opens.
#[derive(Debug, Clone)]
struct Grant {
    cidr: NetPrefix,
    except: Vec<NetPrefix>,
    ports: PortSet,
}

impl Grant {
    fn host(ip: IpAddr, ports: PortSet) -> Self {
        Self {
            cidr: NetPrefix::host(ip),
            except: Vec::new(),
            ports,
        }
    }

    fn opens(&self, ip: IpAddr, protocol: u8, port: u16) -> bool {
        self.cidr.contains_ip(ip)
            && !self.except.iter().any(|except| except.contains_ip(ip))
            && self.ports.allows(protocol, port)
    }
}

/// Compile every policy selecting a pod of `local` (by uid) into slots.
pub fn compile<S: BuildHasher>(
    view: &ClusterView,
    local: &HashSet<String, S>,
    node: &NodeContext,
) -> CompiledPolicy {
    let namespaces: BTreeMap<&str, &BTreeMap<String, String>> = view
        .namespaces
        .iter()
        .map(|namespace| (namespace.name.as_str(), &namespace.labels))
        .collect();
    let index = ClusterIndex {
        view,
        namespaces,
        empty: BTreeMap::new(),
    };

    let mut pods: Vec<&PodView> = view
        .pods
        .iter()
        .filter(|pod| local.contains(&pod.uid) && !pod.host_network && !pod.terminal)
        .collect();
    pods.sort_by(|a, b| a.uid.cmp(&b.uid));

    let mut compiled = CompiledPolicy::default();
    let mut slots: BTreeMap<SlotProgram, u16> = BTreeMap::new();
    let mut entries = 0usize;
    let max_entries = NETPOL_MAX_ENTRIES as usize;
    let max_slots = NETPOL_MAX_SLOTS as usize;

    for pod in pods {
        let selecting: Vec<&NetworkPolicy> = view
            .policies
            .iter()
            .filter(|policy| {
                policy.namespace == pod.namespace && policy.pod_selector.matches(&pod.labels)
            })
            .collect();
        let ingress = selecting.iter().any(|p| p.governs(Direction::Ingress));
        let egress = selecting.iter().any(|p| p.governs(Direction::Egress));
        if !ingress && !egress {
            continue;
        }
        compiled.report.selected_pods += 1;
        let label = format!("{}/{}", pod.namespace, pod.name);

        let mut program = SlotProgram {
            ingress_isolated: ingress,
            egress_isolated: egress,
            entries: Vec::new(),
        };
        for (direction, isolated) in [(Direction::Ingress, ingress), (Direction::Egress, egress)] {
            if !isolated {
                continue;
            }
            let mut grants = always_open(node);
            for policy in selecting.iter().filter(|p| p.governs(direction)) {
                for rule in policy.rules(direction) {
                    grants.extend(index.rule_grants(policy, rule, direction, pod));
                }
            }
            if direction == Direction::Egress {
                let vips = service_grants(&view.services, &grants, &label, &mut compiled.report);
                grants.extend(vips);
            }
            program.entries.extend(lay_out(
                direction,
                &grants,
                &label,
                &mut compiled.report.truncated,
            ));
        }
        program.entries.sort();

        let slot = if let Some(slot) = slots.get(&program) {
            *slot
        } else if slots.len() + CLOSED_SLOT_RESERVE < max_slots
            && entries + program.entries.len() <= max_entries
        {
            entries += program.entries.len();
            new_slot(&mut slots, &mut compiled.slots, program.clone())
        } else {
            compiled.report.closed.push(label);
            let closed = closed_program(ingress, egress, node);
            match slots.get(&closed) {
                Some(slot) => *slot,
                None => new_slot(&mut slots, &mut compiled.slots, closed),
            }
        };
        compiled.pods.insert(
            pod.uid.clone(),
            PodAssignment {
                slot,
                ingress_isolated: ingress,
                egress_isolated: egress,
            },
        );
    }
    compiled
}

/// A program closed in each isolated direction but for the node and loopback,
/// for a pod whose own rule set did not fit.
fn closed_program(ingress: bool, egress: bool, node: &NodeContext) -> SlotProgram {
    let mut closed = SlotProgram {
        ingress_isolated: ingress,
        egress_isolated: egress,
        entries: Vec::new(),
    };
    for (direction, isolated) in [(Direction::Ingress, ingress), (Direction::Egress, egress)] {
        if isolated {
            closed
                .entries
                .extend(lay_out(direction, &always_open(node), "", &mut Vec::new()));
        }
    }
    closed.entries.sort();
    closed
}

fn new_slot(
    slots: &mut BTreeMap<SlotProgram, u16>,
    ordered: &mut Vec<SlotProgram>,
    program: SlotProgram,
) -> u16 {
    let slot = u16::try_from(ordered.len()).unwrap_or(u16::MAX);
    slots.insert(program.clone(), slot);
    ordered.push(program);
    slot
}

/// The node and loopback: open in both directions whatever the policies say.
///
/// The pod's own addresses are left to the policies, as for any other peer:
/// writing them here would give every pod a program of its own, and the pods
/// of one deployment could no longer share a slot.
fn always_open(node: &NodeContext) -> Vec<Grant> {
    let mut grants: Vec<Grant> = node
        .node_ips
        .iter()
        .map(|ip| Grant::host(*ip, PortSet::all()))
        .collect();
    for loopback in ["127.0.0.0/8", "::1/128"] {
        if let Some(cidr) = NetPrefix::parse(loopback) {
            grants.push(Grant {
                cidr,
                except: Vec::new(),
                ports: PortSet::all(),
            });
        }
    }
    grants
}

struct ClusterIndex<'a> {
    view: &'a ClusterView,
    namespaces: BTreeMap<&'a str, &'a BTreeMap<String, String>>,
    empty: BTreeMap<String, String>,
}

impl ClusterIndex<'_> {
    fn namespace_labels(&self, name: &str) -> &BTreeMap<String, String> {
        self.namespaces.get(name).copied().unwrap_or(&self.empty)
    }

    /// The pods a `podSelector`/`namespaceSelector` peer names.
    fn peer_pods(
        &self,
        policy_namespace: &str,
        namespaces: Option<&LabelSelector>,
        pods: Option<&LabelSelector>,
    ) -> Vec<&PodView> {
        self.view
            .pods
            .iter()
            .filter(|pod| pod.is_peer())
            .filter(|pod| match namespaces {
                Some(selector) => selector.matches(self.namespace_labels(&pod.namespace)),
                None => pod.namespace == policy_namespace,
            })
            .filter(|pod| pods.is_none_or(|selector| selector.matches(&pod.labels)))
            .collect()
    }

    /// One rule as prefixes. A named port is resolved against the pod it
    /// names: on ingress that is the selected pod itself, on egress each peer
    /// pod in turn, and an address that is not a pod resolves no name.
    fn rule_grants(
        &self,
        policy: &NetworkPolicy,
        rule: &PolicyRule,
        direction: Direction,
        pod: &PodView,
    ) -> Vec<Grant> {
        let ingress = direction == Direction::Ingress;
        let local_ports = ingress.then_some(pod.ports.as_slice());
        let named = rule
            .ports
            .iter()
            .any(|port| matches!(port.port, Some(PortRef::Name(_))));
        let mut grants = Vec::new();

        if rule.peers.is_empty() {
            let ports = rule_ports(&rule.ports, local_ports);
            for anywhere in ["0.0.0.0/0", "::/0"] {
                if let Some(cidr) = NetPrefix::parse(anywhere)
                    && !ports.is_empty()
                {
                    grants.push(Grant {
                        cidr,
                        except: Vec::new(),
                        ports: ports.clone(),
                    });
                }
            }
            if !ingress && named {
                for peer in self.view.pods.iter().filter(|peer| peer.is_peer()) {
                    pod_grants(
                        &mut grants,
                        peer,
                        &rule_ports(&rule.ports, Some(&peer.ports)),
                    );
                }
            }
            return grants;
        }

        for peer in &rule.peers {
            match peer {
                Peer::Block(block) => {
                    let ports = rule_ports(&rule.ports, local_ports);
                    if ports.is_empty() {
                        continue;
                    }
                    grants.push(Grant {
                        cidr: block.cidr,
                        except: block
                            .except
                            .iter()
                            .copied()
                            .filter(|except| block.cidr.contains(except))
                            .collect(),
                        ports,
                    });
                }
                Peer::Pods { namespaces, pods } => {
                    for target in
                        self.peer_pods(&policy.namespace, namespaces.as_ref(), pods.as_ref())
                    {
                        let resolver = if ingress {
                            local_ports
                        } else {
                            Some(target.ports.as_slice())
                        };
                        pod_grants(&mut grants, target, &rule_ports(&rule.ports, resolver));
                    }
                }
            }
        }
        grants
    }
}

fn pod_grants(grants: &mut Vec<Grant>, pod: &PodView, ports: &PortSet) {
    if ports.is_empty() {
        return;
    }
    for ip in &pod.ips {
        grants.push(Grant::host(*ip, ports.clone()));
    }
}

/// The ports one rule opens. No `ports` at all is every port; a named port
/// with no resolver, or one the resolver does not carry, opens nothing.
fn rule_ports(ports: &[PolicyPort], named: Option<&[NamedPort]>) -> PortSet {
    if ports.is_empty() {
        return PortSet::all();
    }
    let mut set = PortSet::default();
    for port in ports {
        let protocol = port.protocol.number();
        let range = match &port.port {
            None => Some((0, u16::MAX)),
            Some(PortRef::Number(number)) => Some((
                *number,
                port.end_port.filter(|end| end >= number).unwrap_or(*number),
            )),
            Some(PortRef::Name(name)) => named
                .and_then(|ports| resolve_named(ports, name, port.protocol))
                .map(|number| (number, number)),
        };
        if let Some((lo, hi)) = range {
            set.ranges.push(PortRange { protocol, lo, hi });
        }
    }
    set.normalise();
    set
}

/// The Service addresses this pod may reach.
///
/// Inside the pod the hook sees the Service address, before kube-proxy
/// translates it to a backend, so it opens the Service address on a port only
/// when every ready backend is allowed on its target port. A Service whose
/// backends are only partly allowed stays closed, and is reported, unless the
/// rules already open its address directly.
fn service_grants(
    services: &[ServiceView],
    grants: &[Grant],
    pod: &str,
    report: &mut CompileReport,
) -> Vec<Grant> {
    let opens = |ip: IpAddr, protocol: u8, port: u16| {
        grants.iter().any(|grant| grant.opens(ip, protocol, port))
    };
    let mut added = Vec::new();
    for service in services.iter().filter(|s| !s.cluster_ips.is_empty()) {
        for service_port in &service.ports {
            let protocol = service_port.protocol.number();
            let targets: Vec<(IpAddr, u16)> = service
                .backends
                .iter()
                .filter_map(|backend| {
                    resolve_named(&backend.ports, &service_port.name, service_port.protocol)
                        .map(|port| (backend.ip, port))
                })
                .collect();
            if targets.is_empty() {
                continue;
            }
            let allowed = targets
                .iter()
                .filter(|(ip, port)| opens(*ip, protocol, *port))
                .count();
            if allowed == targets.len() {
                for vip in &service.cluster_ips {
                    added.push(Grant::host(
                        *vip,
                        PortSet::single(service_port.protocol, service_port.port),
                    ));
                }
            } else if allowed > 0
                && !service
                    .cluster_ips
                    .iter()
                    .all(|vip| opens(*vip, protocol, service_port.port))
            {
                report.refused_services.push(RefusedService {
                    pod: pod.to_string(),
                    service: format!("{}/{}", service.namespace, service.name),
                    port: service_port.port,
                    protocol: service_port.protocol,
                    allowed_backends: allowed,
                    backends: targets.len(),
                });
            }
        }
    }
    added
}

/// The grants of one direction as longest-prefix entries.
///
/// Walked in address order, a prefix comes right after every prefix that
/// contains it, so a stack holds its ancestors and the value of each entry is
/// read off the grants sitting on that stack. An entry opening exactly what
/// its nearest ancestor opens is left out, since the lookup lands on the
/// ancestor and gives the same answer, and so is an entry opening nothing
/// with no ancestor, since no entry is already closed.
fn lay_out(
    direction: Direction,
    grants: &[Grant],
    pod: &str,
    truncated: &mut Vec<Truncation>,
) -> Vec<SlotEntry> {
    let mut by_cidr: BTreeMap<NetPrefix, Vec<&Grant>> = BTreeMap::new();
    let mut keys: BTreeSet<NetPrefix> = BTreeSet::new();
    for grant in grants {
        by_cidr.entry(grant.cidr).or_default().push(grant);
        keys.insert(grant.cidr);
        keys.extend(grant.except.iter().copied());
    }

    let mut out = Vec::new();
    // (prefix, what it opens)
    let mut stack: Vec<(NetPrefix, PortSet)> = Vec::new();
    for key in keys {
        while stack
            .last()
            .is_some_and(|(ancestor, _)| !ancestor.contains(&key))
        {
            stack.pop();
        }
        let mut ports = PortSet::default();
        let holders = stack
            .iter()
            .map(|(ancestor, _)| *ancestor)
            .chain(std::iter::once(key));
        for holder in holders {
            for grant in by_cidr.get(&holder).into_iter().flatten() {
                if !grant.except.iter().any(|except| except.contains(&key)) {
                    ports.union(&grant.ports);
                }
            }
        }
        if ports.ranges.len() > NETPOL_MAX_RANGES {
            truncated.push(Truncation {
                pod: pod.to_string(),
                direction,
                prefix: key,
                dropped: ports.ranges.len() - NETPOL_MAX_RANGES,
            });
            ports.ranges.truncate(NETPOL_MAX_RANGES);
        }
        let redundant = match stack.last() {
            Some((_, parent)) => *parent == ports,
            None => ports.is_empty(),
        };
        if !redundant {
            out.push(SlotEntry {
                direction,
                prefix: key,
                ports: ports.clone(),
            });
        }
        stack.push((key, ports));
    }
    out
}
