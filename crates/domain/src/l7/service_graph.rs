//! Who called whom, minute by minute, from the requests the L7 meter reads.
//!
//! Every finished or abandoned request becomes one count on an edge: the
//! client end, the server end, the protocol and the side of the connection
//! this node saw it from. Edges are kept in one-minute buckets for the last
//! [`GRAPH_MINUTES`] minutes, so a reading over any window up to that long is
//! the sum of the buckets it covers.
//!
//! A bucket holds at most a fixed number of edges. A request on an edge the
//! bucket has no room for is counted as dropped rather than folded into a
//! neighbour, so a reading says how much of the minute it is missing.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use super::red::{RedOutcome, RedProtocol};

/// How many one-minute buckets are kept.
pub const GRAPH_MINUTES: u64 = 60;

/// How many distinct edges one minute may hold.
pub const DEFAULT_MAX_EDGES_PER_MINUTE: usize = 4_096;

const MINUTE_NS: u64 = 60_000_000_000;

/// One end of a call: the service this node named it as, when the process
/// is on this node, and the address it used.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GraphEnd {
    pub service: Option<String>,
    pub address: IpAddr,
}

/// The side of the connection the counting node was on. A request whose two
/// ends are both on the node is counted from the server side, so it is
/// counted once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Observer {
    /// The server process runs on this node.
    Server,
    /// Only the client process runs on this node.
    Client,
    /// Neither end runs on this node: the request crossed it.
    Transit,
}

impl Observer {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
            Self::Transit => "transit",
        }
    }
}

/// What identifies an edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeKey {
    pub client: GraphEnd,
    pub server: GraphEnd,
    pub server_port: u16,
    pub protocol: RedProtocol,
    pub observer: Observer,
}

/// The counts an edge carries over a reading.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EdgeCounts {
    pub requests: u64,
    pub errors: u64,
    pub unanswered: u64,
    /// Requests that were answered, which are the ones timed.
    pub answered: u64,
    /// Sum of the durations of the answered requests.
    pub duration_ns_sum: u64,
}

impl EdgeCounts {
    fn add(&mut self, other: &Self) {
        self.requests = self.requests.saturating_add(other.requests);
        self.errors = self.errors.saturating_add(other.errors);
        self.unanswered = self.unanswered.saturating_add(other.unanswered);
        self.answered = self.answered.saturating_add(other.answered);
        self.duration_ns_sum = self.duration_ns_sum.saturating_add(other.duration_ns_sum);
    }
}

#[derive(Debug, Default)]
struct Minute {
    index: u64,
    edges: HashMap<EdgeKey, EdgeCounts>,
    dropped: u64,
}

/// The edges over a window, newest bucket included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphReading {
    /// Edges sorted by key, so two readings of the same buckets compare equal.
    pub edges: Vec<(EdgeKey, EdgeCounts)>,
    /// Requests left out because their minute had no room for their edge.
    pub dropped: u64,
    /// How many minutes the reading covers.
    pub minutes: u64,
}

/// The rolling graph.
#[derive(Debug)]
pub struct ServiceGraph {
    minutes: VecDeque<Minute>,
    max_edges: usize,
}

impl Default for ServiceGraph {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_EDGES_PER_MINUTE)
    }
}

impl ServiceGraph {
    #[must_use]
    pub fn new(max_edges: usize) -> Self {
        Self {
            minutes: VecDeque::with_capacity(usize::try_from(GRAPH_MINUTES).unwrap_or(60)),
            max_edges: max_edges.max(1),
        }
    }

    /// Count one request on its edge, in the minute `at_ns` falls in.
    pub fn record(
        &mut self,
        at_ns: u64,
        key: EdgeKey,
        outcome: RedOutcome,
        duration_ns: Option<u64>,
    ) {
        let index = at_ns / MINUTE_NS;
        let max_edges = self.max_edges;
        let minute = self.minute(index);
        let Some(minute) = minute else {
            // Older than every kept bucket: a late answer to a request whose
            // minute has rolled out of the window.
            return;
        };
        let room = minute.edges.len() < max_edges;
        let counts = match minute.edges.get_mut(&key) {
            Some(counts) => counts,
            None if room => minute.edges.entry(key).or_default(),
            None => {
                minute.dropped = minute.dropped.saturating_add(1);
                return;
            }
        };
        counts.requests = counts.requests.saturating_add(1);
        match outcome {
            RedOutcome::Ok => {}
            RedOutcome::Error => counts.errors = counts.errors.saturating_add(1),
            RedOutcome::Unanswered => counts.unanswered = counts.unanswered.saturating_add(1),
        }
        if let Some(ns) = duration_ns {
            counts.answered = counts.answered.saturating_add(1);
            counts.duration_ns_sum = counts.duration_ns_sum.saturating_add(ns);
        }
    }

    /// The bucket for `index`, opening it and retiring buckets that fell out
    /// of the window. `None` when the index is older than every kept bucket.
    fn minute(&mut self, index: u64) -> Option<&mut Minute> {
        let newest = self.minutes.back().map(|m| m.index);
        if newest.is_none_or(|newest| index > newest) {
            self.open(index);
        }
        self.minutes.iter_mut().rev().find(|m| m.index == index)
    }

    /// Open the bucket for `index` and retire every bucket older than the
    /// window it closes. Minutes nobody counted in are simply absent.
    fn open(&mut self, index: u64) {
        let oldest_kept = index.saturating_sub(GRAPH_MINUTES - 1);
        while self.minutes.front().is_some_and(|m| m.index < oldest_kept) {
            self.minutes.pop_front();
        }
        self.minutes.push_back(Minute {
            index,
            ..Minute::default()
        });
    }

    /// The edges of the last `minutes` minutes up to `now_ns`, the current
    /// one included. `minutes` is clamped to between 1 and [`GRAPH_MINUTES`].
    #[must_use]
    pub fn read(&self, now_ns: u64, minutes: u64) -> GraphReading {
        let minutes = minutes.clamp(1, GRAPH_MINUTES);
        let current = now_ns / MINUTE_NS;
        let first = current.saturating_sub(minutes - 1);
        let mut edges: HashMap<&EdgeKey, EdgeCounts> = HashMap::new();
        let mut dropped = 0_u64;
        for minute in self
            .minutes
            .iter()
            .filter(|m| m.index >= first && m.index <= current)
        {
            dropped = dropped.saturating_add(minute.dropped);
            for (key, counts) in &minute.edges {
                edges.entry(key).or_default().add(counts);
            }
        }
        let mut edges: Vec<(EdgeKey, EdgeCounts)> = edges
            .into_iter()
            .map(|(key, counts)| (key.clone(), counts))
            .collect();
        edges.sort_by(|a, b| a.0.cmp(&b.0));
        GraphReading {
            edges,
            dropped,
            minutes,
        }
    }

    /// How many buckets are held, for tests and the bench.
    #[must_use]
    pub fn buckets(&self) -> usize {
        self.minutes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn end(service: Option<&str>, last: u8) -> GraphEnd {
        GraphEnd {
            service: service.map(str::to_string),
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        }
    }

    fn edge(client: u8) -> EdgeKey {
        EdgeKey {
            client: end(None, client),
            server: end(Some("shop/api"), 1),
            server_port: 8080,
            protocol: RedProtocol::Http,
            observer: Observer::Server,
        }
    }

    const MIN: u64 = MINUTE_NS;

    #[test]
    fn requests_on_one_edge_add_up_across_minutes() {
        let mut g = ServiceGraph::default();
        g.record(10 * MIN, edge(2), RedOutcome::Ok, Some(1_000));
        g.record(10 * MIN + 5, edge(2), RedOutcome::Error, Some(3_000));
        g.record(11 * MIN, edge(2), RedOutcome::Unanswered, None);
        let r = g.read(11 * MIN + 1, 5);
        assert_eq!(r.edges.len(), 1);
        let c = r.edges[0].1;
        assert_eq!(
            (
                c.requests,
                c.errors,
                c.unanswered,
                c.answered,
                c.duration_ns_sum
            ),
            (3, 1, 1, 2, 4_000)
        );
        let last = g.read(11 * MIN + 1, 1);
        assert_eq!(last.edges[0].1.requests, 1);
    }

    #[test]
    fn minutes_past_the_window_are_retired_and_late_samples_ignored() {
        let mut g = ServiceGraph::default();
        g.record(0, edge(2), RedOutcome::Ok, None);
        g.record(GRAPH_MINUTES * MIN, edge(2), RedOutcome::Ok, None);
        assert_eq!(g.buckets(), 1);
        g.record(0, edge(3), RedOutcome::Ok, None);
        let r = g.read(GRAPH_MINUTES * MIN, GRAPH_MINUTES);
        assert_eq!(r.edges.len(), 1);
        assert_eq!(r.edges[0].0.client.address, end(None, 2).address);
    }

    #[test]
    fn a_full_minute_counts_what_it_drops() {
        let mut g = ServiceGraph::new(2);
        for client in 2..6 {
            g.record(MIN, edge(client), RedOutcome::Ok, None);
        }
        g.record(MIN, edge(2), RedOutcome::Ok, None);
        let r = g.read(MIN, 1);
        assert_eq!(r.edges.len(), 2);
        assert_eq!(r.dropped, 2);
        assert_eq!(r.edges[0].1.requests, 2);
    }

    #[test]
    fn the_window_is_clamped() {
        let g = ServiceGraph::default();
        assert_eq!(g.read(0, 0).minutes, 1);
        assert_eq!(g.read(0, 500).minutes, GRAPH_MINUTES);
    }
}
