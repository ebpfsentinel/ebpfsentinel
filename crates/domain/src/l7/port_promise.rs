//! The protocol a well-known port promises, against the one a connection speaks.
//!
//! A port number is a convention, not a guarantee: SSH answers on 443 behind a
//! tunnel, HTTP rides port 53 to slip past a firewall that trusts DNS. The L7
//! detector already names a protocol from the first bytes of a payload, so the
//! first payload of each connection on a listed port is compared with what the
//! port promises.
//!
//! Three outcomes are counted. A **match** spoke one of the protocols the port
//! promises. A **mismatch** spoke a protocol whose first bytes cannot be
//! mistaken for anything else, and it is not the promised one. Everything else
//! is **unclassified**: a payload shorter than [`MIN_CLASSIFY_BYTES`], a
//! protocol the detector does not know, or one whose signature is a heuristic
//! that could have mistaken another protocol for it. Only a mismatch raises an
//! alert, which is why the protocols that can produce one are the five whose
//! opening bytes are fixed: TLS, SSH, HTTP, the HTTP/2 preface and SMB.
//!
//! Each connection is judged once, on the first payload seen in either
//! direction, and remembered in a bounded table so that the rest of its
//! payloads, encrypted or mid-stream, are never judged against the port.

use std::collections::HashMap;

use super::entity::DetectedProtocol;

/// The rule an alert raised for a mismatch carries.
pub const PORT_MISMATCH_RULE_ID: &str = "l7-port-mismatch";

/// The fewest payload bytes a connection is judged on. Below it, a payload is
/// unclassified whatever the detector made of it, because three bytes that
/// happen to open a TLS record are not a TLS connection.
pub const MIN_CLASSIFY_BYTES: usize = 8;

/// Connections remembered as judged, by default.
pub const DEFAULT_MAX_CONNECTIONS: usize = 65_536;

/// How long a judged connection is remembered after its last payload, by
/// default: five minutes.
pub const DEFAULT_IDLE_NS: u64 = 300 * 1_000_000_000;

/// A TCP port and the protocols a connection to it is expected to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Promise {
    pub port: u16,
    pub protocols: &'static [DetectedProtocol],
}

/// The ports treated as promises, in port order. A port missing here promises
/// nothing, and connections to it are neither judged nor counted.
pub const PROMISES: &[Promise] = &[
    Promise {
        port: 21,
        protocols: &[DetectedProtocol::Ftp],
    },
    Promise {
        port: 22,
        protocols: &[DetectedProtocol::Ssh],
    },
    Promise {
        port: 25,
        protocols: &[DetectedProtocol::Smtp],
    },
    Promise {
        port: 53,
        protocols: &[DetectedProtocol::DnsTcp],
    },
    Promise {
        port: 80,
        protocols: &[DetectedProtocol::Http, DetectedProtocol::Grpc],
    },
    Promise {
        port: 110,
        protocols: &[DetectedProtocol::Pop3],
    },
    Promise {
        port: 139,
        protocols: &[DetectedProtocol::Smb],
    },
    Promise {
        port: 143,
        protocols: &[DetectedProtocol::Imap],
    },
    Promise {
        port: 443,
        protocols: &[DetectedProtocol::Tls],
    },
    Promise {
        port: 445,
        protocols: &[DetectedProtocol::Smb],
    },
    Promise {
        port: 465,
        protocols: &[DetectedProtocol::Tls],
    },
    Promise {
        port: 587,
        protocols: &[DetectedProtocol::Smtp],
    },
    Promise {
        port: 853,
        protocols: &[DetectedProtocol::Tls],
    },
    Promise {
        port: 993,
        protocols: &[DetectedProtocol::Tls],
    },
    Promise {
        port: 995,
        protocols: &[DetectedProtocol::Tls],
    },
    Promise {
        port: 3306,
        protocols: &[DetectedProtocol::MySql],
    },
    Promise {
        port: 5432,
        protocols: &[DetectedProtocol::Postgres],
    },
    Promise {
        port: 6379,
        protocols: &[DetectedProtocol::Redis],
    },
    Promise {
        port: 8080,
        protocols: &[DetectedProtocol::Http, DetectedProtocol::Grpc],
    },
    Promise {
        port: 8443,
        protocols: &[DetectedProtocol::Tls],
    },
];

/// The promise a port makes, if it makes one.
#[must_use]
pub fn promise_of(port: u16) -> Option<&'static Promise> {
    PROMISES
        .binary_search_by_key(&port, |promise| promise.port)
        .ok()
        .map(|index| &PROMISES[index])
}

/// Whether a protocol's opening bytes are fixed enough that seeing them on the
/// wrong port is a fact rather than a guess.
#[must_use]
pub fn is_conclusive(protocol: DetectedProtocol) -> bool {
    matches!(
        protocol,
        DetectedProtocol::Tls
            | DetectedProtocol::Ssh
            | DetectedProtocol::Http
            | DetectedProtocol::Grpc
            | DetectedProtocol::Smb
    )
}

/// How a connection's first payload compares with its port's promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Match,
    Mismatch,
    Unclassified,
}

impl Verdict {
    /// The value the verdict is counted under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Match => "match",
            Self::Mismatch => "mismatch",
            Self::Unclassified => "unclassified",
        }
    }
}

/// Compare what a payload of `len` bytes spoke with what `promise` promised.
#[must_use]
pub fn judge(promise: &Promise, spoken: DetectedProtocol, len: usize) -> Verdict {
    if len < MIN_CLASSIFY_BYTES {
        Verdict::Unclassified
    } else if promise.protocols.contains(&spoken) {
        Verdict::Match
    } else if is_conclusive(spoken) {
        Verdict::Mismatch
    } else {
        Verdict::Unclassified
    }
}

/// One TCP endpoint.
pub type Endpoint = ([u32; 4], u16);

/// A connection, the same whichever direction a payload travelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    low: Endpoint,
    high: Endpoint,
    is_ipv6: bool,
}

impl ConnectionKey {
    #[must_use]
    pub fn new(src: Endpoint, dst: Endpoint, is_ipv6: bool) -> Self {
        let (low, high) = if src <= dst { (src, dst) } else { (dst, src) };
        Self { low, high, is_ipv6 }
    }
}

/// A connection's first payload, judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Judgement {
    /// The listed port the connection was judged against.
    pub promise: &'static Promise,
    pub spoken: DetectedProtocol,
    pub verdict: Verdict,
}

/// What offering one payload to the tracker came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// The connection's first payload, judged.
    Judged(Judgement),
    /// The connection was judged on an earlier payload.
    AlreadyJudged,
    /// Neither end is on a listed port, or the port is ignored.
    NoPromise,
    /// The table of judged connections was full of live ones, so the
    /// connection was neither judged nor remembered.
    Uncounted,
}

/// The ports a tracker compares against, and the bounds of its memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortPromiseConfig {
    /// Listed ports left out on purpose, such as 443 on a host that serves
    /// SSH there behind a multiplexer.
    pub ignore_ports: Vec<u16>,
    pub max_connections: usize,
    pub idle_ns: u64,
}

impl Default for PortPromiseConfig {
    fn default() -> Self {
        Self {
            ignore_ports: Vec::new(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            idle_ns: DEFAULT_IDLE_NS,
        }
    }
}

/// The longest a full table goes between two sweeps for idle connections.
/// A sweep walks the whole table, so a flood of new connections against a
/// table full of live ones pays for one walk a second rather than one each.
const MAX_SWEEP_INTERVAL_NS: u64 = 1_000_000_000;

/// Judges each connection once and remembers it until it goes idle.
#[derive(Debug)]
pub struct PortPromiseTracker {
    config: PortPromiseConfig,
    judged: HashMap<ConnectionKey, u64>,
    last_sweep_ns: Option<u64>,
}

impl PortPromiseTracker {
    #[must_use]
    pub fn new(config: PortPromiseConfig) -> Self {
        Self {
            config,
            judged: HashMap::new(),
            last_sweep_ns: None,
        }
    }

    /// The promise this tracker holds a connection between `src_port` and
    /// `dst_port` to: the destination's when it has one, the source's
    /// otherwise, since a server speaking first sends from the listed port.
    #[must_use]
    pub fn promise_for(&self, src_port: u16, dst_port: u16) -> Option<&'static Promise> {
        [dst_port, src_port]
            .into_iter()
            .filter(|port| !self.config.ignore_ports.contains(port))
            .find_map(promise_of)
    }

    /// Offer one TCP payload of `len` bytes, which the detector named `spoken`.
    pub fn offer(
        &mut self,
        src: Endpoint,
        dst: Endpoint,
        is_ipv6: bool,
        spoken: DetectedProtocol,
        len: usize,
        at_ns: u64,
    ) -> Offer {
        let Some(promise) = self.promise_for(src.1, dst.1) else {
            return Offer::NoPromise;
        };
        let key = ConnectionKey::new(src, dst, is_ipv6);
        if let Some(last) = self.judged.get_mut(&key) {
            *last = at_ns;
            return Offer::AlreadyJudged;
        }
        if self.judged.len() >= self.config.max_connections {
            let interval = self.config.idle_ns.min(MAX_SWEEP_INTERVAL_NS);
            let due = self
                .last_sweep_ns
                .is_none_or(|last| at_ns.saturating_sub(last) >= interval);
            if due {
                self.last_sweep_ns = Some(at_ns);
                self.forget_idle(at_ns);
            }
            if self.judged.len() >= self.config.max_connections {
                return Offer::Uncounted;
            }
        }
        self.judged.insert(key, at_ns);
        Offer::Judged(Judgement {
            promise,
            spoken,
            verdict: judge(promise, spoken, len),
        })
    }

    /// Forget every connection with no payload for longer than the idle
    /// timeout. Returns how many were forgotten.
    pub fn forget_idle(&mut self, now_ns: u64) -> usize {
        let idle_ns = self.config.idle_ns;
        let before = self.judged.len();
        self.judged
            .retain(|_, last| now_ns.saturating_sub(*last) <= idle_ns);
        before - self.judged.len()
    }

    /// Connections currently remembered as judged.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.judged.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Endpoint = ([0x0a00_0001, 0, 0, 0], 51_234);

    fn server(port: u16) -> Endpoint {
        ([0x0a00_0002, 0, 0, 0], port)
    }

    fn tracker() -> PortPromiseTracker {
        PortPromiseTracker::new(PortPromiseConfig::default())
    }

    fn verdict(offer: Offer) -> Verdict {
        match offer {
            Offer::Judged(judgement) => judgement.verdict,
            other => panic!("expected a judgement, got {other:?}"),
        }
    }

    #[test]
    fn the_table_is_in_port_order_so_it_can_be_searched() {
        assert!(PROMISES.windows(2).all(|pair| pair[0].port < pair[1].port));
        assert_eq!(
            promise_of(22).map(|p| p.protocols),
            Some(&[DetectedProtocol::Ssh][..])
        );
        assert!(promise_of(2222).is_none());
    }

    #[test]
    fn ssh_on_443_is_a_mismatch() {
        let offer = tracker().offer(CLIENT, server(443), false, DetectedProtocol::Ssh, 40, 1);
        let Offer::Judged(judgement) = offer else {
            panic!("expected a judgement, got {offer:?}");
        };
        assert_eq!(judgement.verdict, Verdict::Mismatch);
        assert_eq!(judgement.promise.port, 443);
        assert_eq!(judgement.spoken, DetectedProtocol::Ssh);
    }

    #[test]
    fn http_on_53_and_tls_on_22_are_mismatches() {
        let mut t = tracker();
        let http = t.offer(CLIENT, server(53), false, DetectedProtocol::Http, 64, 1);
        let tls = t.offer(CLIENT, server(22), false, DetectedProtocol::Tls, 300, 1);
        assert_eq!(verdict(http), Verdict::Mismatch);
        assert_eq!(verdict(tls), Verdict::Mismatch);
    }

    #[test]
    fn the_promised_protocol_is_a_match() {
        let mut t = tracker();
        let tls = t.offer(CLIENT, server(443), false, DetectedProtocol::Tls, 517, 1);
        let h2 = t.offer(CLIENT, server(80), false, DetectedProtocol::Grpc, 24, 1);
        assert_eq!(verdict(tls), Verdict::Match);
        assert_eq!(verdict(h2), Verdict::Match);
    }

    #[test]
    fn a_payload_too_short_to_classify_is_unclassified_not_a_match() {
        let offer = tracker().offer(CLIENT, server(443), false, DetectedProtocol::Tls, 3, 1);
        assert_eq!(verdict(offer), Verdict::Unclassified);
    }

    /// A heuristic signature on the wrong port is a guess, not a fact.
    #[test]
    fn an_unknown_or_heuristic_protocol_is_unclassified() {
        let mut t = tracker();
        let unknown = t.offer(
            CLIENT,
            server(443),
            false,
            DetectedProtocol::Unknown,
            900,
            1,
        );
        let dns = t.offer(CLIENT, server(3306), false, DetectedProtocol::DnsTcp, 60, 1);
        assert_eq!(verdict(unknown), Verdict::Unclassified);
        assert_eq!(verdict(dns), Verdict::Unclassified);
    }

    #[test]
    fn a_connection_is_judged_once_whichever_way_its_payloads_travel() {
        let mut t = tracker();
        let first = t.offer(server(22), CLIENT, false, DetectedProtocol::Ssh, 30, 1);
        assert_eq!(verdict(first), Verdict::Match);
        let reply = t.offer(
            CLIENT,
            server(22),
            false,
            DetectedProtocol::Unknown,
            1_000,
            2,
        );
        assert_eq!(reply, Offer::AlreadyJudged);
        assert_eq!(t.remembered(), 1);
    }

    #[test]
    fn a_server_speaking_first_is_held_to_its_own_port() {
        let promise = tracker().promise_for(22, CLIENT.1).map(|p| p.port);
        assert_eq!(promise, Some(22));
        let both = tracker().promise_for(8080, 443).map(|p| p.port);
        assert_eq!(both, Some(443));
    }

    #[test]
    fn an_unlisted_or_ignored_port_promises_nothing() {
        let mut t = PortPromiseTracker::new(PortPromiseConfig {
            ignore_ports: vec![443],
            ..PortPromiseConfig::default()
        });
        let ignored = t.offer(CLIENT, server(443), false, DetectedProtocol::Ssh, 40, 1);
        let unlisted = t.offer(CLIENT, server(2222), false, DetectedProtocol::Ssh, 40, 1);
        assert_eq!(ignored, Offer::NoPromise);
        assert_eq!(unlisted, Offer::NoPromise);
        assert_eq!(t.remembered(), 0);
    }

    #[test]
    fn a_full_table_forgets_idle_connections_before_refusing_one() {
        let mut t = PortPromiseTracker::new(PortPromiseConfig {
            max_connections: 1,
            idle_ns: 10,
            ..PortPromiseConfig::default()
        });
        let other = ([0x0a00_0003, 0, 0, 0], 40_000);
        assert!(matches!(
            t.offer(CLIENT, server(22), false, DetectedProtocol::Ssh, 30, 0),
            Offer::Judged(_)
        ));
        assert_eq!(
            t.offer(other, server(22), false, DetectedProtocol::Ssh, 30, 5),
            Offer::Uncounted
        );
        assert!(matches!(
            t.offer(other, server(22), false, DetectedProtocol::Ssh, 30, 20),
            Offer::Judged(_)
        ));
        assert_eq!(t.remembered(), 1);
    }

    #[test]
    fn a_full_table_of_live_connections_is_swept_at_most_once_per_interval() {
        let mut t = PortPromiseTracker::new(PortPromiseConfig {
            max_connections: 1,
            idle_ns: 10,
            ..PortPromiseConfig::default()
        });
        let late = ([0x0a00_0003, 0, 0, 0], 40_000);
        let later = ([0x0a00_0004, 0, 0, 0], 40_000);
        let _ = t.offer(CLIENT, server(22), false, DetectedProtocol::Ssh, 30, 0);
        // Swept at 5 and found nothing idle.
        assert_eq!(
            t.offer(late, server(22), false, DetectedProtocol::Ssh, 30, 5),
            Offer::Uncounted
        );
        // At 12 the first connection is idle, but the last sweep was 7 ago.
        assert_eq!(
            t.offer(later, server(22), false, DetectedProtocol::Ssh, 30, 12),
            Offer::Uncounted
        );
        assert!(matches!(
            t.offer(later, server(22), false, DetectedProtocol::Ssh, 30, 15),
            Offer::Judged(_)
        ));
    }

    #[test]
    fn a_connection_idle_past_the_timeout_is_forgotten() {
        let mut t = PortPromiseTracker::new(PortPromiseConfig {
            idle_ns: 10,
            ..PortPromiseConfig::default()
        });
        let _ = t.offer(CLIENT, server(22), false, DetectedProtocol::Ssh, 30, 0);
        assert_eq!(t.forget_idle(5), 0);
        assert_eq!(t.forget_idle(11), 1);
        assert_eq!(t.remembered(), 0);
    }

    #[test]
    fn the_verdicts_are_counted_under_three_values() {
        let names: Vec<_> = [Verdict::Match, Verdict::Mismatch, Verdict::Unclassified]
            .into_iter()
            .map(Verdict::as_str)
            .collect();
        assert_eq!(names, ["match", "mismatch", "unclassified"]);
    }
}
