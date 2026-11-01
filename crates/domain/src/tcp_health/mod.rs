//! TCP health per edge: retransmissions, resets, connections opened,
//! failed and closed, and the round-trip time.
//!
//! The kernel side counts every event under the edge the connection runs
//! on: the local and remote addresses, the service port and the cgroup of
//! the local socket. This module turns two readings of those counters into
//! what was added between them, so a counter fed from it follows the
//! kernel's own counts rather than the poll cadence.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

pub mod reset_scan;

/// The service a reset is counted under when it answered a segment no
/// socket was there to take: a connection attempt to a closed port.
pub const NO_LISTENER: &str = "no_listener";

/// Buckets of the round-trip time histogram, as the kernel side keeps them.
pub const RTT_BUCKETS: usize = 16;
/// Upper bound of the first bucket, in microseconds; each next one doubles.
pub const RTT_FIRST_BOUND_US: u64 = 64;

/// The upper bound of `bucket` in microseconds, `None` for the last one,
/// which holds everything above the one before it.
#[must_use]
pub const fn rtt_bucket_bound_us(bucket: usize) -> Option<u64> {
    if bucket + 1 >= RTT_BUCKETS {
        None
    } else {
        Some(RTT_FIRST_BOUND_US << bucket)
    }
}

/// Round-trip time samples of one edge: one when a connection is
/// established and one when it leaves that state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpRtt {
    /// Samples per bucket, not cumulative.
    pub buckets: [u64; RTT_BUCKETS],
    /// Sum of every sample, in microseconds.
    pub sum_us: u64,
    /// Number of samples.
    pub count: u64,
}

impl TcpRtt {
    /// Add `other` to these samples.
    pub fn add(&mut self, other: &Self) {
        for (mine, theirs) in self.buckets.iter_mut().zip(other.buckets) {
            *mine = mine.saturating_add(theirs);
        }
        self.sum_us = self.sum_us.saturating_add(other.sum_us);
        self.count = self.count.saturating_add(other.count);
    }

    fn went_back_from(&self, before: &Self) -> bool {
        self.count < before.count
            || self.sum_us < before.sum_us
            || self
                .buckets
                .iter()
                .zip(before.buckets)
                .any(|(now, then)| *now < then)
    }

    fn minus(&self, before: &Self) -> Self {
        let mut buckets = [0; RTT_BUCKETS];
        for ((out, now), then) in buckets.iter_mut().zip(self.buckets).zip(before.buckets) {
            *out = now - then;
        }
        Self {
            buckets,
            sum_us: self.sum_us - before.sum_us,
            count: self.count - before.count,
        }
    }
}

/// What one edge has counted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpCounts {
    /// Segments sent again.
    pub retransmits: u64,
    /// Resets this node sent.
    pub resets_sent: u64,
    /// Resets this node received.
    pub resets_received: u64,
    /// Connections that reached the established state.
    pub opened: u64,
    /// Established connections that closed.
    pub closed: u64,
    /// Connections that closed before they were established.
    pub failed: u64,
    /// Round-trip time samples.
    pub rtt: TcpRtt,
}

impl TcpCounts {
    /// Whether nothing was counted.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::default()
    }

    /// Add `other` to these counts.
    pub fn add(&mut self, other: &Self) {
        self.retransmits = self.retransmits.saturating_add(other.retransmits);
        self.resets_sent = self.resets_sent.saturating_add(other.resets_sent);
        self.resets_received = self.resets_received.saturating_add(other.resets_received);
        self.opened = self.opened.saturating_add(other.opened);
        self.closed = self.closed.saturating_add(other.closed);
        self.failed = self.failed.saturating_add(other.failed);
        self.rtt.add(&other.rtt);
    }

    /// What these counts added over `before`. The kernel side never evicts
    /// an edge, so a count only goes down when the counter itself was loaded
    /// again, and every count is then new.
    #[must_use]
    pub fn since(&self, before: &Self) -> Self {
        let went_back = self.retransmits < before.retransmits
            || self.resets_sent < before.resets_sent
            || self.resets_received < before.resets_received
            || self.opened < before.opened
            || self.closed < before.closed
            || self.failed < before.failed
            || self.rtt.went_back_from(&before.rtt);
        if went_back {
            return *self;
        }
        Self {
            retransmits: self.retransmits - before.retransmits,
            resets_sent: self.resets_sent - before.resets_sent,
            resets_received: self.resets_received - before.resets_received,
            opened: self.opened - before.opened,
            closed: self.closed - before.closed,
            failed: self.failed - before.failed,
            rtt: self.rtt.minus(&before.rtt),
        }
    }
}

/// Which end of a connection this node holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdgeRole {
    /// The local end opened the connection.
    Client,
    /// The local end holds the service port.
    Server,
}

impl EdgeRole {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

/// The identity of one edge as the kernel side keys it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TcpEdgeId {
    pub local: IpAddr,
    pub remote: IpAddr,
    /// The service port, `0` for a reset with no socket behind it.
    pub port: u16,
    pub role: EdgeRole,
    /// cgroup v2 id of the local socket, `0` where none was read.
    pub cgroup: u64,
}

impl TcpEdgeId {
    /// Whether this edge is the resets answering segments no socket took.
    #[must_use]
    pub fn is_no_listener(&self) -> bool {
        self.port == 0
    }
}

/// How many one-minute buckets of round-trip times are kept.
pub const RTT_MINUTES: u64 = 60;

/// How many distinct pairs one minute of round-trip times may hold.
pub const DEFAULT_MAX_RTT_PAIRS_PER_MINUTE: usize = 4_096;

const MINUTE_NS: u64 = 60_000_000_000;

/// The two ends of a connection and the side this node measured it from,
/// which is how a service map edge finds its round-trip time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RttPair {
    pub client: IpAddr,
    pub server: IpAddr,
    pub server_port: u16,
    /// `Server` when the sample was read off the accepting socket, `Client`
    /// when off the connecting one. Where both run here the connection is
    /// sampled from each, and a reader picks one side so it counts once.
    pub measured_from: RttSide,
}

/// The socket a round-trip time was read off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RttSide {
    Client,
    Server,
}

impl RttPair {
    /// The pair an edge's samples belong to, `None` for the resets with no
    /// socket behind them, which carry no round-trip time.
    #[must_use]
    pub fn of(id: &TcpEdgeId) -> Option<Self> {
        if id.is_no_listener() {
            return None;
        }
        Some(match id.role {
            EdgeRole::Server => Self {
                client: id.remote,
                server: id.local,
                server_port: id.port,
                measured_from: RttSide::Server,
            },
            EdgeRole::Client => Self {
                client: id.local,
                server: id.remote,
                server_port: id.port,
                measured_from: RttSide::Client,
            },
        })
    }
}

/// Round-trip times by pair, minute by minute, so a service map reading over
/// any window carries the samples of that window and no older ones.
///
/// A minute holds at most a fixed number of pairs; samples on a pair it has
/// no room for are left out of the window, and only out of the window: the
/// histogram series carries them all.
#[derive(Debug)]
pub struct RttWindow {
    minutes: VecDeque<(u64, HashMap<RttPair, TcpRtt>)>,
    max_pairs: usize,
}

impl Default for RttWindow {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_RTT_PAIRS_PER_MINUTE)
    }
}

impl RttWindow {
    #[must_use]
    pub fn new(max_pairs: usize) -> Self {
        Self {
            minutes: VecDeque::new(),
            max_pairs: max_pairs.max(1),
        }
    }

    /// Add samples on `pair`, in the minute `at_ns` falls in.
    pub fn record(&mut self, at_ns: u64, pair: RttPair, rtt: &TcpRtt) {
        if rtt.count == 0 {
            return;
        }
        let index = at_ns / MINUTE_NS;
        if self
            .minutes
            .back()
            .is_none_or(|(newest, _)| index > *newest)
        {
            let oldest_kept = index.saturating_sub(RTT_MINUTES - 1);
            while self.minutes.front().is_some_and(|(i, _)| *i < oldest_kept) {
                self.minutes.pop_front();
            }
            self.minutes.push_back((index, HashMap::new()));
        }
        let max_pairs = self.max_pairs;
        let Some((_, pairs)) = self.minutes.iter_mut().rev().find(|(i, _)| *i == index) else {
            return;
        };
        if let Some(held) = pairs.get_mut(&pair) {
            held.add(rtt);
        } else if pairs.len() < max_pairs {
            pairs.insert(pair, *rtt);
        }
    }

    /// The samples of the last `minutes` minutes up to `now_ns`, the current
    /// one included, by pair. `minutes` is clamped to between 1 and
    /// [`RTT_MINUTES`].
    #[must_use]
    pub fn read(&self, now_ns: u64, minutes: u64) -> HashMap<RttPair, TcpRtt> {
        let minutes = minutes.clamp(1, RTT_MINUTES);
        let current = now_ns / MINUTE_NS;
        let first = current.saturating_sub(minutes - 1);
        let mut out: HashMap<RttPair, TcpRtt> = HashMap::new();
        for (_, pairs) in self
            .minutes
            .iter()
            .filter(|(i, _)| *i >= first && *i <= current)
        {
            for (pair, rtt) in pairs {
                out.entry(*pair).or_default().add(rtt);
            }
        }
        out
    }
}

/// One edge as the kernel side holds it, summed over the CPUs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawTcpEdge {
    pub id: TcpEdgeId,
    pub counts: TcpCounts,
}

/// What one reading added.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpIncrements {
    /// Every edge that moved, with what it added.
    pub edges: Vec<RawTcpEdge>,
    /// Events the kernel side saw but could not count under an edge.
    pub uncounted: u64,
}

/// The counts of the previous reading, per edge.
#[derive(Debug, Default)]
pub struct TcpEdgeDeltas {
    last: HashMap<TcpEdgeId, TcpCounts>,
    last_uncounted: u64,
}

impl TcpEdgeDeltas {
    /// The increments `edges` and `uncounted` carry over the previous
    /// reading.
    pub fn advance(&mut self, edges: &[RawTcpEdge], uncounted: u64) -> TcpIncrements {
        let mut moved = Vec::new();
        for edge in edges {
            let before = self.last.insert(edge.id, edge.counts).unwrap_or_default();
            let added = edge.counts.since(&before);
            if !added.is_zero() {
                moved.push(RawTcpEdge {
                    id: edge.id,
                    counts: added,
                });
            }
        }
        let added_uncounted = if uncounted >= self.last_uncounted {
            uncounted - self.last_uncounted
        } else {
            uncounted
        };
        self.last_uncounted = uncounted;
        TcpIncrements {
            edges: moved,
            uncounted: added_uncounted,
        }
    }

    /// What every edge of the workload under `cgroup` has counted so far, as
    /// of the last reading.
    #[must_use]
    pub fn totals_of(&self, cgroup: u64) -> Vec<RawTcpEdge> {
        self.last
            .iter()
            .filter(|(id, _)| id.cgroup == cgroup)
            .map(|(id, counts)| RawTcpEdge {
                id: *id,
                counts: *counts,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn edge(port: u16, counts: TcpCounts) -> RawTcpEdge {
        RawTcpEdge {
            id: TcpEdgeId {
                local: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                remote: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port,
                role: EdgeRole::Server,
                cgroup: 7,
            },
            counts,
        }
    }

    #[test]
    fn the_totals_of_a_workload_are_its_edges_as_last_read() {
        let mut deltas = TcpEdgeDeltas::default();
        let mut other = edge(80, TcpCounts::default());
        other.id.cgroup = 9;
        deltas.advance(
            &[
                edge(
                    443,
                    TcpCounts {
                        retransmits: 4,
                        ..TcpCounts::default()
                    },
                ),
                other,
            ],
            0,
        );
        deltas.advance(
            &[edge(
                443,
                TcpCounts {
                    retransmits: 6,
                    ..TcpCounts::default()
                },
            )],
            0,
        );
        let totals = deltas.totals_of(7);
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[0].counts.retransmits, 6);
        assert_eq!(deltas.totals_of(9).len(), 1);
        assert!(deltas.totals_of(1).is_empty());
    }

    #[test]
    fn a_reading_adds_what_moved_since_the_last_one() {
        let mut deltas = TcpEdgeDeltas::default();
        let first = deltas.advance(
            &[edge(
                443,
                TcpCounts {
                    opened: 3,
                    retransmits: 1,
                    ..TcpCounts::default()
                },
            )],
            2,
        );
        assert_eq!(first.edges.len(), 1);
        assert_eq!(first.edges[0].counts.opened, 3);
        assert_eq!(first.uncounted, 2);

        let second = deltas.advance(
            &[edge(
                443,
                TcpCounts {
                    opened: 5,
                    retransmits: 1,
                    closed: 2,
                    ..TcpCounts::default()
                },
            )],
            2,
        );
        assert_eq!(second.edges.len(), 1);
        assert_eq!(
            second.edges[0].counts,
            TcpCounts {
                opened: 2,
                closed: 2,
                ..TcpCounts::default()
            }
        );
        assert_eq!(second.uncounted, 0);

        let still = deltas.advance(
            &[edge(
                443,
                TcpCounts {
                    opened: 5,
                    retransmits: 1,
                    closed: 2,
                    ..TcpCounts::default()
                },
            )],
            2,
        );
        assert_eq!(still.edges.len(), 0);
    }

    #[test]
    fn a_counter_that_went_back_was_loaded_again() {
        let mut deltas = TcpEdgeDeltas::default();
        deltas.advance(
            &[edge(
                22,
                TcpCounts {
                    failed: 9,
                    ..TcpCounts::default()
                },
            )],
            5,
        );
        let after = deltas.advance(
            &[edge(
                22,
                TcpCounts {
                    failed: 1,
                    ..TcpCounts::default()
                },
            )],
            1,
        );
        assert_eq!(after.edges[0].counts.failed, 1);
        assert_eq!(after.uncounted, 1);
    }

    #[test]
    fn counts_add_and_roles_read_as_words() {
        let mut total = TcpCounts::default();
        assert!(total.is_zero());
        total.add(&TcpCounts {
            resets_sent: 2,
            ..TcpCounts::default()
        });
        total.add(&TcpCounts {
            resets_sent: 1,
            resets_received: 4,
            ..TcpCounts::default()
        });
        assert_eq!(total.resets_sent, 3);
        assert_eq!(total.resets_received, 4);
        assert_eq!(EdgeRole::Client.as_str(), "client");
        assert_eq!(EdgeRole::Server.as_str(), "server");
        assert!(edge(0, TcpCounts::default()).id.is_no_listener());
        assert!(!edge(443, TcpCounts::default()).id.is_no_listener());
    }

    #[test]
    fn round_trip_samples_add_their_increments_and_a_reload_restarts_them() {
        let rtt = |b0: u64, b3: u64, sum_us: u64| {
            let mut buckets = [0; RTT_BUCKETS];
            buckets[0] = b0;
            buckets[3] = b3;
            TcpRtt {
                buckets,
                sum_us,
                count: b0 + b3,
            }
        };
        let mut deltas = TcpEdgeDeltas::default();
        let with = |r: TcpRtt| TcpCounts {
            rtt: r,
            ..TcpCounts::default()
        };
        let first = deltas.advance(&[edge(443, with(rtt(1, 2, 900)))], 0);
        assert_eq!(first.edges[0].counts.rtt, rtt(1, 2, 900));

        let second = deltas.advance(&[edge(443, with(rtt(1, 5, 2_100)))], 0);
        assert_eq!(second.edges[0].counts.rtt, rtt(0, 3, 1_200));

        let unchanged = deltas.advance(&[edge(443, with(rtt(1, 5, 2_100)))], 0);
        assert_eq!(unchanged.edges.len(), 0);

        let reloaded = deltas.advance(&[edge(443, with(rtt(0, 1, 400)))], 0);
        assert_eq!(reloaded.edges[0].counts.rtt, rtt(0, 1, 400));
    }

    #[test]
    fn the_last_round_trip_bucket_has_no_bound() {
        assert_eq!(rtt_bucket_bound_us(0), Some(RTT_FIRST_BOUND_US));
        assert_eq!(rtt_bucket_bound_us(1), Some(RTT_FIRST_BOUND_US * 2));
        assert_eq!(rtt_bucket_bound_us(RTT_BUCKETS - 1), None);
    }

    fn sampled(count: u64, sum_us: u64) -> TcpRtt {
        let mut buckets = [0; RTT_BUCKETS];
        buckets[5] = count;
        TcpRtt {
            buckets,
            sum_us,
            count,
        }
    }

    #[test]
    fn an_edge_names_its_pair_from_the_side_it_was_read_on() {
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let server = TcpEdgeId {
            local: a,
            remote: b,
            port: 443,
            role: EdgeRole::Server,
            cgroup: 1,
        };
        let pair = RttPair::of(&server).expect("a served edge has a pair");
        assert_eq!((pair.client, pair.server, pair.server_port), (b, a, 443));
        assert_eq!(pair.measured_from, RttSide::Server);
        let client = TcpEdgeId {
            role: EdgeRole::Client,
            ..server
        };
        let pair = RttPair::of(&client).expect("a client edge has a pair");
        assert_eq!((pair.client, pair.server), (a, b));
        assert_eq!(pair.measured_from, RttSide::Client);
        assert_eq!(RttPair::of(&TcpEdgeId { port: 0, ..server }), None);
    }

    #[test]
    fn a_window_reads_the_minutes_it_covers_and_retires_the_rest() {
        let pair = RttPair {
            client: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            server_port: 443,
            measured_from: RttSide::Server,
        };
        let mut window = RttWindow::default();
        window.record(0, pair, &sampled(2, 400));
        window.record(MINUTE_NS * 3, pair, &sampled(1, 300));
        window.record(MINUTE_NS * 3 + 5, pair, &sampled(1, 100));
        window.record(MINUTE_NS * 3, pair, &TcpRtt::default());

        assert_eq!(window.read(MINUTE_NS * 3, 1)[&pair], sampled(2, 400));
        assert_eq!(window.read(MINUTE_NS * 3, 4)[&pair], sampled(4, 800));

        window.record(MINUTE_NS * (RTT_MINUTES + 3), pair, &sampled(1, 50));
        assert_eq!(
            window.read(MINUTE_NS * (RTT_MINUTES + 3), RTT_MINUTES)[&pair],
            sampled(1, 50)
        );
    }

    #[test]
    fn a_full_minute_leaves_a_new_pair_out_and_keeps_adding_to_the_held_ones() {
        let pair = |port| RttPair {
            client: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            server: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            server_port: port,
            measured_from: RttSide::Client,
        };
        let mut window = RttWindow::new(1);
        window.record(0, pair(1), &sampled(1, 10));
        window.record(0, pair(2), &sampled(1, 10));
        window.record(0, pair(1), &sampled(1, 10));
        let read = window.read(0, 1);
        assert_eq!(read.len(), 1);
        assert_eq!(read[&pair(1)], sampled(2, 20));
    }
}
