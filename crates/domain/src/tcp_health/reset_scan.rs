//! Resets read as a scan.
//!
//! A host probing ports that nobody listens on draws one reset per probe:
//! the stack answers a segment no socket took with a reset, and a client
//! whose connection was refused receives one. Both are counted per edge
//! already, so the same reading an SRE uses to find a crash-looping
//! dependency names a host sweeping the node's ports.
//!
//! The source of a probe is the remote end of a reset this node sent with no
//! socket behind it, or the local end of a client connection that was
//! refused. Its resets are summed over a sliding window and handed to a
//! judge, which says whether the count is above what that source is expected
//! to draw.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::{RuleId, Severity};

use super::{EdgeRole, RawTcpEdge};

/// The component a TCP health alert carries.
pub const TCP_HEALTH_COMPONENT: &str = "tcp_health";

/// The rule id of the alert raised for a reset rate above its line.
pub const RESET_SCAN_RULE_ID: &str = "tcp-reset-scan";

/// How many sources the window holds. A sweep from spoofed addresses could
/// otherwise grow it without bound; the source seen longest ago goes first.
pub const MAX_SOURCES: usize = 4_096;

/// Which side of this node the source of the resets is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanDirection {
    /// Another host probed this node's closed ports.
    Inbound,
    /// A workload on this node had its connections refused.
    Outbound,
}

impl ScanDirection {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }
}

/// The resets one source drew in one reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResetObservation {
    /// The host that sent the probes.
    pub source: IpAddr,
    /// The host that answered them with resets.
    pub target: IpAddr,
    pub resets: u64,
    pub direction: ScanDirection,
    /// cgroup v2 id of the local socket that was refused, `0` for an
    /// inbound probe, which has no local socket.
    pub cgroup: u64,
}

/// Turns one reading's increments into resets per source.
///
/// A connection between two ends on this node is held twice, so a refused
/// local connection shows both as a reset sent with no listener and as a
/// reset received by the client: per source, the larger of the two sides is
/// taken rather than their sum.
#[must_use]
pub fn observations(increments: &[RawTcpEdge]) -> Vec<ResetObservation> {
    #[derive(Default)]
    struct Side {
        resets: u64,
        target: Option<IpAddr>,
        // The socket that drew the most resets, with how many it drew.
        cgroup: (u64, u64),
    }
    let mut inbound: HashMap<IpAddr, Side> = HashMap::new();
    let mut outbound: HashMap<IpAddr, Side> = HashMap::new();
    for RawTcpEdge { id, counts } in increments {
        if id.is_no_listener() {
            if counts.resets_sent > 0 {
                let side = inbound.entry(id.remote).or_default();
                side.resets = side.resets.saturating_add(counts.resets_sent);
                side.target.get_or_insert(id.local);
            }
        } else if id.role == EdgeRole::Client && counts.resets_received > 0 {
            let side = outbound.entry(id.local).or_default();
            side.resets = side.resets.saturating_add(counts.resets_received);
            side.target.get_or_insert(id.remote);
            if counts.resets_received > side.cgroup.1 {
                side.cgroup = (id.cgroup, counts.resets_received);
            }
        }
    }
    let mut out: Vec<ResetObservation> = Vec::with_capacity(inbound.len() + outbound.len());
    for (source, side) in &outbound {
        let seen_in = inbound.get(source).map_or(0, |s| s.resets);
        out.push(ResetObservation {
            source: *source,
            target: side.target.unwrap_or(*source),
            resets: side.resets.max(seen_in),
            direction: ScanDirection::Outbound,
            cgroup: side.cgroup.0,
        });
    }
    for (source, side) in inbound {
        if outbound.contains_key(&source) {
            continue;
        }
        out.push(ResetObservation {
            source,
            target: side.target.unwrap_or(source),
            resets: side.resets,
            direction: ScanDirection::Inbound,
            cgroup: 0,
        });
    }
    out.sort_by_key(|o| o.source);
    out
}

/// One source's resets over the window, as a judge reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceRate {
    pub source: IpAddr,
    pub target: IpAddr,
    /// Resets summed over the window.
    pub resets: u64,
    pub direction: ScanDirection,
    pub cgroup: u64,
}

/// The line a source's resets crossed.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResetVerdict {
    /// The count over the window above which a source raises an alert.
    pub threshold: f64,
    /// What this source was expected to draw over the window, where a
    /// baseline exists for it; `None` for a fixed line.
    pub expected: Option<f64>,
}

#[derive(Debug)]
struct SourceWindow {
    samples: VecDeque<(u64, u64)>,
    sum: u64,
    target: IpAddr,
    direction: ScanDirection,
    cgroup: u64,
    last_seen_ns: u64,
    alerted_ns: Option<u64>,
}

/// Resets per source over a sliding window.
#[derive(Debug)]
pub struct ResetRates {
    window_ns: u64,
    sources: HashMap<IpAddr, SourceWindow>,
}

impl ResetRates {
    /// A window of `window_secs` seconds.
    #[must_use]
    pub fn new(window_secs: u64) -> Self {
        Self {
            window_ns: window_secs.max(1).saturating_mul(1_000_000_000),
            sources: HashMap::new(),
        }
    }

    /// How long the window is, in seconds.
    #[must_use]
    pub fn window_secs(&self) -> u64 {
        self.window_ns / 1_000_000_000
    }

    /// How many sources the window holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    /// Whether the window holds no source.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Add one reading at `now_ns` and return, for every source it moved,
    /// that source's resets over the window.
    pub fn record(&mut self, now_ns: u64, observations: &[ResetObservation]) -> Vec<SourceRate> {
        let window_ns = self.window_ns;
        let expired = |at: u64| now_ns.saturating_sub(at) >= window_ns;
        self.sources.retain(|_, w| {
            while w.samples.front().is_some_and(|(at, _)| expired(*at)) {
                if let Some((_, resets)) = w.samples.pop_front() {
                    w.sum = w.sum.saturating_sub(resets);
                }
            }
            !w.samples.is_empty() || w.alerted_ns.is_some_and(|at| !expired(at))
        });
        let mut moved = Vec::with_capacity(observations.len());
        for o in observations {
            if o.resets == 0 {
                continue;
            }
            if !self.sources.contains_key(&o.source) && self.sources.len() >= MAX_SOURCES {
                self.evict_oldest();
            }
            let w = self
                .sources
                .entry(o.source)
                .or_insert_with(|| SourceWindow {
                    samples: VecDeque::new(),
                    sum: 0,
                    target: o.target,
                    direction: o.direction,
                    cgroup: o.cgroup,
                    last_seen_ns: now_ns,
                    alerted_ns: None,
                });
            w.samples.push_back((now_ns, o.resets));
            w.sum = w.sum.saturating_add(o.resets);
            w.target = o.target;
            w.direction = o.direction;
            if o.cgroup != 0 {
                w.cgroup = o.cgroup;
            }
            w.last_seen_ns = now_ns;
            moved.push(SourceRate {
                source: o.source,
                target: w.target,
                resets: w.sum,
                direction: w.direction,
                cgroup: w.cgroup,
            });
        }
        moved
    }

    /// Whether `source` raised an alert within the last window. One sweep
    /// is one alert, however many readings it spans.
    #[must_use]
    pub fn quiet(&self, source: IpAddr, now_ns: u64) -> bool {
        self.sources
            .get(&source)
            .and_then(|w| w.alerted_ns)
            .is_some_and(|at| now_ns.saturating_sub(at) < self.window_ns)
    }

    /// Note that `source` raised an alert at `now_ns`.
    pub fn alerted(&mut self, source: IpAddr, now_ns: u64) {
        if let Some(w) = self.sources.get_mut(&source) {
            w.alerted_ns = Some(now_ns);
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .sources
            .iter()
            .min_by_key(|(_, w)| w.last_seen_ns)
            .map(|(source, _)| *source)
        {
            self.sources.remove(&oldest);
        }
    }
}

/// A reset rate above its line.
#[derive(Debug, Clone, PartialEq)]
pub struct ResetScan {
    pub rate: SourceRate,
    pub window_secs: u64,
    pub verdict: ResetVerdict,
}

impl ResetScan {
    #[must_use]
    pub fn rule_id() -> RuleId {
        RuleId(RESET_SCAN_RULE_ID.to_string())
    }

    /// Probing for services that answer is network service scanning.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1046".to_string(),
            technique_name: "Network Service Scanning".to_string(),
            tactic: "discovery".to_string(),
        }
    }

    /// High when the count is more than ten times its line, medium below.
    #[must_use]
    pub fn severity(&self) -> Severity {
        let resets = f64::from(u32::try_from(self.rate.resets).unwrap_or(u32::MAX));
        if resets > self.verdict.threshold * 10.0 {
            Severity::High
        } else {
            Severity::Medium
        }
    }

    /// The alert's sentence.
    #[must_use]
    pub fn message(&self) -> String {
        let SourceRate {
            source,
            target,
            resets,
            direction,
            ..
        } = self.rate;
        let line = match self.verdict.expected {
            Some(expected) => format!(
                "above its baseline of {expected:.1} (line {:.1})",
                self.verdict.threshold
            ),
            None => format!("above the line of {:.0}", self.verdict.threshold),
        };
        match direction {
            ScanDirection::Inbound => format!(
                "{source} drew {resets} resets from closed ports on {target} in {}s, {line}",
                self.window_secs
            ),
            ScanDirection::Outbound => format!(
                "{source} had {resets} connections to {target} refused in {}s, {line}",
                self.window_secs
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::super::{TcpCounts, TcpEdgeId};
    use super::*;

    const SEC: u64 = 1_000_000_000;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    fn no_listener(remote: IpAddr, resets: u64) -> RawTcpEdge {
        RawTcpEdge {
            id: TcpEdgeId {
                local: ip(1),
                remote,
                port: 0,
                role: EdgeRole::Server,
                cgroup: 0,
            },
            counts: TcpCounts {
                resets_sent: resets,
                ..TcpCounts::default()
            },
        }
    }

    fn refused(local: IpAddr, remote: IpAddr, cgroup: u64, resets: u64) -> RawTcpEdge {
        RawTcpEdge {
            id: TcpEdgeId {
                local,
                remote,
                port: 443,
                role: EdgeRole::Client,
                cgroup,
            },
            counts: TcpCounts {
                resets_received: resets,
                ..TcpCounts::default()
            },
        }
    }

    #[test]
    fn a_probe_to_a_closed_port_names_its_remote_end() {
        let seen = observations(&[no_listener(ip(9), 3), no_listener(ip(9), 2)]);
        assert_eq!(
            seen,
            vec![ResetObservation {
                source: ip(9),
                target: ip(1),
                resets: 5,
                direction: ScanDirection::Inbound,
                cgroup: 0,
            }]
        );
    }

    #[test]
    fn a_refused_client_names_its_local_end_and_its_socket() {
        let seen = observations(&[refused(ip(1), ip(7), 42, 4), refused(ip(1), ip(8), 43, 1)]);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].source, ip(1));
        assert_eq!(seen[0].resets, 5);
        assert_eq!(seen[0].direction, ScanDirection::Outbound);
        assert_eq!(seen[0].cgroup, 42);
    }

    #[test]
    fn a_connection_held_twice_on_this_node_counts_once() {
        let seen = observations(&[no_listener(ip(1), 6), refused(ip(1), ip(1), 42, 6)]);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].resets, 6);
        assert_eq!(seen[0].cgroup, 42);
    }

    #[test]
    fn a_reset_on_an_established_server_edge_is_not_a_probe() {
        let mut edge = no_listener(ip(9), 0);
        edge.id.port = 80;
        edge.counts.resets_sent = 9;
        assert_eq!(observations(&[edge]).len(), 0);
    }

    #[test]
    fn the_window_sums_readings_and_forgets_old_ones() {
        let mut rates = ResetRates::new(60);
        let o = |resets| ResetObservation {
            source: ip(9),
            target: ip(1),
            resets,
            direction: ScanDirection::Inbound,
            cgroup: 0,
        };
        assert_eq!(rates.record(0, &[o(10)])[0].resets, 10);
        assert_eq!(rates.record(30 * SEC, &[o(5)])[0].resets, 15);
        assert_eq!(rates.record(61 * SEC, &[o(1)])[0].resets, 6);
        assert_eq!(rates.record(200 * SEC, &[]).len(), 0);
        assert!(rates.is_empty());
    }

    #[test]
    fn one_sweep_is_one_alert_per_window() {
        let mut rates = ResetRates::new(60);
        let o = ResetObservation {
            source: ip(9),
            target: ip(1),
            resets: 100,
            direction: ScanDirection::Inbound,
            cgroup: 0,
        };
        rates.record(0, &[o]);
        assert!(!rates.quiet(ip(9), 0));
        rates.alerted(ip(9), 0);
        rates.record(10 * SEC, &[o]);
        assert!(rates.quiet(ip(9), 10 * SEC));
        rates.record(70 * SEC, &[o]);
        assert!(!rates.quiet(ip(9), 70 * SEC));
    }

    #[test]
    fn the_window_holds_a_bounded_number_of_sources() {
        let mut rates = ResetRates::new(60);
        for n in 0..=MAX_SOURCES {
            let source = IpAddr::V4(Ipv4Addr::from(u32::try_from(n).unwrap() + 1));
            rates.record(
                u64::try_from(n).unwrap(),
                &[ResetObservation {
                    source,
                    target: ip(1),
                    resets: 1,
                    direction: ScanDirection::Inbound,
                    cgroup: 0,
                }],
            );
        }
        assert_eq!(rates.len(), MAX_SOURCES);
    }

    #[test]
    fn the_sentence_says_which_line_was_crossed() {
        let scan = ResetScan {
            rate: SourceRate {
                source: ip(9),
                target: ip(1),
                resets: 400,
                direction: ScanDirection::Inbound,
                cgroup: 0,
            },
            window_secs: 60,
            verdict: ResetVerdict {
                threshold: 100.0,
                expected: None,
            },
        };
        assert_eq!(
            scan.message(),
            "10.0.0.9 drew 400 resets from closed ports on 10.0.0.1 in 60s, above the line of 100"
        );
        assert_eq!(scan.severity(), Severity::Medium);
        let flood = ResetScan {
            rate: SourceRate {
                resets: 1_001,
                ..scan.rate
            },
            ..scan.clone()
        };
        assert_eq!(flood.severity(), Severity::High);
    }

    #[test]
    fn the_alert_carries_the_prober_as_its_source() {
        let scan = ResetScan {
            rate: SourceRate {
                source: ip(9),
                target: ip(1),
                resets: 150,
                direction: ScanDirection::Inbound,
                cgroup: 0,
            },
            window_secs: 60,
            verdict: ResetVerdict {
                threshold: 40.0,
                expected: Some(4.5),
            },
        };
        let alert = crate::alert::entity::Alert::from_reset_scan(&scan, None, 7);
        assert_eq!(alert.component, TCP_HEALTH_COMPONENT);
        assert_eq!(alert.rule_id.0, RESET_SCAN_RULE_ID);
        assert_eq!(
            alert.src_addr,
            [u32::from(Ipv4Addr::new(10, 0, 0, 9)), 0, 0, 0]
        );
        assert_eq!(
            alert.dst_addr,
            [u32::from(Ipv4Addr::new(10, 0, 0, 1)), 0, 0, 0]
        );
        assert_eq!(alert.protocol, 6);
        assert!(!alert.is_ipv6);
        assert_eq!(
            alert.mitre_attack.map(|m| m.technique_id),
            Some("T1046".to_string())
        );
        assert!(
            alert
                .message
                .contains("above its baseline of 4.5 (line 40.0)")
        );
        assert_eq!(alert.workload, None);
    }
}
