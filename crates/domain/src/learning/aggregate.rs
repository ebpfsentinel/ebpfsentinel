use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::common::entity::Protocol;

use super::entity::{Observation, WorkloadKey};

/// One thing a workload reached, with the key the aggregate holds it under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EdgeKey {
    workload: WorkloadKey,
    destination: IpAddr,
    port: u16,
    protocol: Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EdgeStat {
    first_seen_ns: u64,
    last_seen_ns: u64,
    observations: u64,
}

/// One edge of the aggregate, in the shape everything downstream reads it:
/// the progress view, the stored session and the rendered document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningEdge {
    /// The workload that reached it.
    pub workload: WorkloadKey,
    /// The address it reached.
    pub destination: IpAddr,
    /// The port, host order.
    pub port: u16,
    /// The protocol of the flow.
    pub protocol: Protocol,
    /// When this edge was first seen inside the window.
    pub first_seen_ns: u64,
    /// When it was last seen.
    pub last_seen_ns: u64,
    /// How many observations folded into it. A long-lived flow is counted
    /// once per sample rather than once per connection, so this figure says
    /// how persistent the edge was and not how many times it was opened.
    pub observations: u64,
}

/// The most addresses a window keeps for one workload.
///
/// A workload holds an address per interface it dials from, which is a
/// handful; a figure past this is a workload being rescheduled across a
/// pool, and the first ones are enough to recognise it from another node.
pub const LEARNING_MAX_ADDRESSES_PER_WORKLOAD: usize = 16;

/// The local addresses one workload was seen dialling from.
///
/// This is what lets a reader holding several nodes' windows recognise the
/// destination of one node's edge as a workload another node saw, rather
/// than as an address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadAddresses {
    pub workload: WorkloadKey,
    pub addresses: Vec<IpAddr>,
}

/// The persisted shape of an aggregate.
///
/// A map keyed by a structure has no representation in the formats the store
/// writes, and a list of edges is what the renderer wants anyway, so this is
/// both the serialised form and the read-back form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateRepr {
    pub capacity: usize,
    pub dropped_edges: u64,
    pub last_new_edge_ns: Option<u64>,
    pub edges: Vec<LearningEdge>,
    /// Absent from a window stored before addresses were kept, which then
    /// reads back with none rather than failing to load.
    #[serde(default)]
    pub addresses: Vec<WorkloadAddresses>,
}

/// What a node reached during a window, bounded.
///
/// Bounded is the whole point: an aggregate keyed per flow grows with the
/// traffic and an agent learning for a week would hold a table the size of
/// the week. Keyed per edge it grows with the shape of the node, which stops
/// growing once the node has been described. When even that fills up, new
/// edges are refused and counted rather than evicting old ones: an evicted
/// edge is a hole in a policy nobody can see, while a refused one is a figure
/// the document prints at the top of itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(into = "AggregateRepr", from = "AggregateRepr")]
pub struct LearningAggregate {
    capacity: usize,
    edges: HashMap<EdgeKey, EdgeStat>,
    dropped_edges: u64,
    last_new_edge_ns: Option<u64>,
    addresses: BTreeMap<WorkloadKey, BTreeSet<IpAddr>>,
}

impl LearningAggregate {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            edges: HashMap::new(),
            dropped_edges: 0,
            last_new_edge_ns: None,
            addresses: BTreeMap::new(),
        }
    }

    /// Distinct edges held.
    pub fn len(&self) -> usize {
        self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.edges.is_empty()
    }

    /// How many edges it can hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many new edges were refused because it was full.
    pub fn dropped_edges(&self) -> u64 {
        self.dropped_edges
    }

    /// When the last new edge appeared.
    pub fn last_new_edge_ns(&self) -> Option<u64> {
        self.last_new_edge_ns
    }

    /// Fold one observation in.
    pub fn record(
        &mut self,
        workload: WorkloadKey,
        destination: IpAddr,
        port: u16,
        protocol: Protocol,
        now_ns: u64,
    ) -> Observation {
        let key = EdgeKey {
            workload,
            destination,
            port,
            protocol,
        };
        if let Some(stat) = self.edges.get_mut(&key) {
            stat.last_seen_ns = now_ns;
            stat.observations = stat.observations.saturating_add(1);
            return Observation::KnownEdge;
        }
        if self.edges.len() >= self.capacity {
            self.dropped_edges = self.dropped_edges.saturating_add(1);
            return Observation::Dropped;
        }
        self.edges.insert(
            key,
            EdgeStat {
                first_seen_ns: now_ns,
                last_seen_ns: now_ns,
                observations: 1,
            },
        );
        self.last_new_edge_ns = Some(now_ns);
        Observation::NewEdge
    }

    /// Remember that `workload` dialled from `source`.
    ///
    /// Only a workload the aggregate holds an edge for is remembered, so the
    /// table is bounded by the edges. A loopback or unspecified address names
    /// no workload from another node and is left out.
    pub fn note_source(&mut self, workload: &WorkloadKey, source: IpAddr) {
        if source.is_loopback() || source.is_unspecified() {
            return;
        }
        if !self.edges.keys().any(|k| &k.workload == workload)
            && !self.addresses.contains_key(workload)
        {
            return;
        }
        let held = self.addresses.entry(workload.clone()).or_default();
        if held.len() < LEARNING_MAX_ADDRESSES_PER_WORKLOAD {
            held.insert(source);
        }
    }

    /// Each workload with the addresses it dialled from, by workload.
    pub fn addresses(&self) -> Vec<WorkloadAddresses> {
        self.addresses
            .iter()
            .map(|(workload, addresses)| WorkloadAddresses {
                workload: workload.clone(),
                addresses: addresses.iter().copied().collect(),
            })
            .collect()
    }

    /// Every edge, in a stable order: by workload, then address, then port,
    /// then protocol. A document rendered twice from the same aggregate is
    /// byte for byte the same document, which is what makes it diffable
    /// against what the node runs today.
    pub fn edges(&self) -> Vec<LearningEdge> {
        let mut edges: Vec<LearningEdge> = self
            .edges
            .iter()
            .map(|(key, stat)| LearningEdge {
                workload: key.workload.clone(),
                destination: key.destination,
                port: key.port,
                protocol: key.protocol,
                first_seen_ns: stat.first_seen_ns,
                last_seen_ns: stat.last_seen_ns,
                observations: stat.observations,
            })
            .collect();
        edges.sort_by(|a, b| {
            a.workload
                .cmp(&b.workload)
                .then(a.destination.cmp(&b.destination))
                .then(a.port.cmp(&b.port))
                .then(a.protocol.to_u8().cmp(&b.protocol.to_u8()))
        });
        edges
    }
}

impl From<LearningAggregate> for AggregateRepr {
    fn from(aggregate: LearningAggregate) -> Self {
        Self {
            capacity: aggregate.capacity,
            dropped_edges: aggregate.dropped_edges,
            last_new_edge_ns: aggregate.last_new_edge_ns,
            edges: aggregate.edges(),
            addresses: aggregate.addresses(),
        }
    }
}

impl From<AggregateRepr> for LearningAggregate {
    fn from(repr: AggregateRepr) -> Self {
        let mut edges = HashMap::with_capacity(repr.edges.len());
        for edge in repr.edges {
            edges.insert(
                EdgeKey {
                    workload: edge.workload,
                    destination: edge.destination,
                    port: edge.port,
                    protocol: edge.protocol,
                },
                EdgeStat {
                    first_seen_ns: edge.first_seen_ns,
                    last_seen_ns: edge.last_seen_ns,
                    observations: edge.observations,
                },
            );
        }
        let addresses = repr
            .addresses
            .into_iter()
            .map(|held| {
                let set: BTreeSet<IpAddr> = held
                    .addresses
                    .into_iter()
                    .take(LEARNING_MAX_ADDRESSES_PER_WORKLOAD)
                    .collect();
                (held.workload, set)
            })
            .collect();
        Self {
            capacity: repr.capacity.max(edges.len()),
            edges,
            dropped_edges: repr.dropped_edges,
            last_new_edge_ns: repr.last_new_edge_ns,
            addresses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str) -> WorkloadKey {
        WorkloadKey::Unit(name.to_string())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn the_same_edge_twice_is_one_edge_with_two_observations() {
        let mut aggregate = LearningAggregate::new(16);
        assert_eq!(
            aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1_000),
            Observation::NewEdge
        );
        assert_eq!(
            aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 2_000),
            Observation::KnownEdge
        );
        assert_eq!(aggregate.len(), 1);
        let edges = aggregate.edges();
        assert_eq!(edges[0].observations, 2);
        assert_eq!(edges[0].first_seen_ns, 1_000);
        assert_eq!(edges[0].last_seen_ns, 2_000);
    }

    #[test]
    fn a_different_port_protocol_or_workload_is_a_different_edge() {
        let mut aggregate = LearningAggregate::new(16);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 80, Protocol::Tcp, 1);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Udp, 1);
        aggregate.record(unit("b.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);
        aggregate.record(unit("a.service"), ip("10.0.0.2"), 443, Protocol::Tcp, 1);
        assert_eq!(aggregate.len(), 5);
    }

    #[test]
    fn a_full_aggregate_refuses_new_edges_and_counts_them() {
        let mut aggregate = LearningAggregate::new(2);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 1, Protocol::Tcp, 1);
        aggregate.record(unit("a.service"), ip("10.0.0.2"), 1, Protocol::Tcp, 1);
        assert_eq!(
            aggregate.record(unit("a.service"), ip("10.0.0.3"), 1, Protocol::Tcp, 2),
            Observation::Dropped
        );
        assert_eq!(aggregate.len(), 2);
        assert_eq!(aggregate.dropped_edges(), 1);
        assert_eq!(
            aggregate.record(unit("a.service"), ip("10.0.0.1"), 1, Protocol::Tcp, 3),
            Observation::KnownEdge,
            "a full aggregate still follows the edges it already holds"
        );
    }

    #[test]
    fn the_last_new_edge_is_when_the_aggregate_last_learned_something() {
        let mut aggregate = LearningAggregate::new(4);
        assert_eq!(aggregate.last_new_edge_ns(), None);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 1, Protocol::Tcp, 500);
        assert_eq!(aggregate.last_new_edge_ns(), Some(500));
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 1, Protocol::Tcp, 900);
        assert_eq!(
            aggregate.last_new_edge_ns(),
            Some(500),
            "seeing a known edge again is not learning anything"
        );
        aggregate.record(unit("a.service"), ip("10.0.0.9"), 1, Protocol::Tcp, 1_200);
        assert_eq!(aggregate.last_new_edge_ns(), Some(1_200));
    }

    #[test]
    fn edges_come_back_in_a_stable_order() {
        let mut aggregate = LearningAggregate::new(16);
        aggregate.record(unit("b.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);
        aggregate.record(unit("a.service"), ip("10.0.0.2"), 53, Protocol::Udp, 1);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);

        let first = aggregate.edges();
        let second = aggregate.edges();
        assert_eq!(first, second);
        assert_eq!(first[0].workload, unit("a.service"));
        assert_eq!(first[0].destination, ip("10.0.0.1"));
        assert_eq!(first[2].workload, unit("b.service"));
    }

    #[test]
    fn an_aggregate_survives_a_round_trip_through_its_stored_shape() {
        let mut aggregate = LearningAggregate::new(3);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 10);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 20);
        aggregate.record(unit("a.service"), ip("fd00::1"), 53, Protocol::Udp, 30);

        let encoded = serde_json::to_string(&aggregate).unwrap();
        let back: LearningAggregate = serde_json::from_str(&encoded).unwrap();

        assert_eq!(back.len(), 2);
        assert_eq!(back.capacity(), 3);
        assert_eq!(back.last_new_edge_ns(), Some(30));
        assert_eq!(back.edges(), aggregate.edges());
    }

    #[test]
    fn a_workload_keeps_the_addresses_it_dialled_from_and_nothing_else() {
        let mut aggregate = LearningAggregate::new(8);
        aggregate.note_source(&unit("a.service"), ip("10.1.0.5"));
        assert!(
            aggregate.addresses().is_empty(),
            "no edge held for it, so nothing is remembered"
        );
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);
        aggregate.note_source(&unit("a.service"), ip("10.1.0.5"));
        aggregate.note_source(&unit("a.service"), ip("10.1.0.5"));
        aggregate.note_source(&unit("a.service"), ip("127.0.0.1"));
        aggregate.note_source(&unit("a.service"), ip("::"));
        let held = aggregate.addresses();
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].addresses, vec![ip("10.1.0.5")]);
    }

    #[test]
    fn a_workload_keeps_a_bounded_number_of_addresses() {
        let mut aggregate = LearningAggregate::new(8);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);
        for i in 0..40u8 {
            aggregate.note_source(&unit("a.service"), IpAddr::from([10, 2, 0, i]));
        }
        assert_eq!(
            aggregate.addresses()[0].addresses.len(),
            LEARNING_MAX_ADDRESSES_PER_WORKLOAD
        );
    }

    #[test]
    fn addresses_survive_the_stored_shape_and_an_old_window_reads_back_with_none() {
        let mut aggregate = LearningAggregate::new(4);
        aggregate.record(unit("a.service"), ip("10.0.0.1"), 443, Protocol::Tcp, 1);
        aggregate.note_source(&unit("a.service"), ip("10.1.0.5"));
        let encoded = serde_json::to_string(&aggregate).unwrap();
        let back: LearningAggregate = serde_json::from_str(&encoded).unwrap();
        assert_eq!(back.addresses(), aggregate.addresses());

        let old = r#"{"capacity":4,"dropped_edges":0,"last_new_edge_ns":null,"edges":[]}"#;
        let back: LearningAggregate = serde_json::from_str(old).unwrap();
        assert!(back.addresses().is_empty());
    }
}
