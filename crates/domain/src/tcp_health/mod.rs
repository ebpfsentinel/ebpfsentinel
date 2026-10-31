//! TCP health per edge: retransmissions, resets, and connections opened,
//! failed and closed.
//!
//! The kernel side counts every event under the edge the connection runs
//! on: the local and remote addresses, the service port and the cgroup of
//! the local socket. This module turns two readings of those counters into
//! what was added between them, so a counter fed from it follows the
//! kernel's own counts rather than the poll cadence.

use std::collections::HashMap;
use std::net::IpAddr;

/// The service a reset is counted under when it answered a segment no
/// socket was there to take: a connection attempt to a closed port.
pub const NO_LISTENER: &str = "no_listener";

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
            || self.failed < before.failed;
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
}
