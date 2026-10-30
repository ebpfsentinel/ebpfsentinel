//! Rate, errors and duration per service, read off the L7 stream.
//!
//! A request is remembered against its flow until the first payload on the
//! reverse flow answers it, and the pair becomes one sample: which protocol,
//! whether the answer was a failure, and how long it took. Only protocols
//! whose answer says plainly whether it failed are measured: HTTP/1.x,
//! Redis, `PostgreSQL`, `MySQL` and DNS over TCP. Everything else the parsers
//! recognise is left out rather than counted as a success nobody checked.
//!
//! Every dimension is bounded. The pending table holds at most
//! [`RedConfig::max_pending`] requests, a request nobody answered within
//! [`RedConfig::answer_timeout_ns`] or pushed out of a full table is counted
//! `unanswered`, and the service names are capped by [`ServiceNames`], past
//! which every new name reads `other`.

use std::collections::HashSet;
use std::num::NonZeroUsize;

use lru::LruCache;

use crate::l7::reassembler::FlowId;
use crate::workload::entity::Workload;

/// Requests remembered at once, by default.
pub const DEFAULT_MAX_PENDING: usize = 65_536;

/// How long a request waits for its answer, by default.
pub const DEFAULT_ANSWER_TIMEOUT_NS: u64 = 30 * 1_000_000_000;

/// Distinct service names, by default, before new ones read [`OTHER_SERVICE`].
pub const DEFAULT_MAX_SERVICES: usize = 256;

/// The name every service past the cap is counted under.
pub const OTHER_SERVICE: &str = "other";

/// The name of a request whose two ends no workload could be found for.
pub const UNATTRIBUTED_SERVICE: &str = "unattributed";

/// Upper bounds of the request duration histogram, in seconds.
///
/// Half a millisecond is a cache answering on the same node; ten seconds is
/// past every default client timeout, so a request slower than that is
/// already a failure to whoever sent it.
pub const DURATION_BUCKETS_SECONDS: [f64; 14] = [
    0.000_5, 0.001, 0.002_5, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// A protocol whose answer says whether the request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RedProtocol {
    Http,
    Redis,
    Postgres,
    MySql,
    DnsTcp,
}

impl RedProtocol {
    /// The label value, the same word the L7 detector uses.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Redis => "redis",
            Self::Postgres => "postgres",
            Self::MySql => "mysql",
            Self::DnsTcp => "dns-tcp",
        }
    }

    /// The protocol a payload opens a request in, when it is a request at
    /// all. `label` is what the L7 detector named the payload; the bytes are
    /// then checked for the client's side of that protocol, so an answer
    /// that happens to look like the protocol is not taken for a question.
    #[must_use]
    pub fn of_request(label: &str, payload: &[u8]) -> Option<Self> {
        match label {
            "http" if is_http_request(payload) => Some(Self::Http),
            // A client sends commands as arrays of bulk strings.
            "redis" if payload.first() == Some(&b'*') => Some(Self::Redis),
            // A simple query or the parse step of an extended one.
            "postgres" if matches!(payload.first(), Some(b'Q' | b'P')) => Some(Self::Postgres),
            "mysql" if is_mysql_command(payload) => Some(Self::MySql),
            "dns-tcp" if payload.get(4).is_some_and(|flags| flags & 0x80 == 0) => {
                Some(Self::DnsTcp)
            }
            _ => None,
        }
    }

    /// Read the first payload of an answer: `Some(true)` for a failure,
    /// `Some(false)` for a success, `None` when the payload is not an
    /// answer this protocol gives, which leaves the request waiting.
    #[must_use]
    pub fn read_answer(self, payload: &[u8]) -> Option<bool> {
        match self {
            Self::Http => http_status(payload).and_then(|status| match status {
                // An interim answer: the final one is still to come.
                100..=199 => None,
                500..=599 => Some(true),
                _ => Some(false),
            }),
            Self::Redis => match payload.first()? {
                b'-' => Some(true),
                b'+' | b':' | b'$' | b'*' | b'_' | b',' | b'#' | b'%' | b'~' | b'>' | b'(' => {
                    Some(false)
                }
                _ => None,
            },
            Self::Postgres => match payload.first()? {
                b'E' => Some(true),
                b'T' | b'C' | b'D' | b'I' | b'1' | b'2' | b'Z' | b'N' | b'n' | b't' | b's' => {
                    Some(false)
                }
                _ => None,
            },
            // Four bytes of length and sequence, then the packet itself.
            Self::MySql => payload.get(4).map(|first| *first == 0xFF),
            // Two bytes of length, two of id, then the flags; the answer bit
            // must be set and the code is the low nibble of the fourth byte.
            Self::DnsTcp => {
                let flags = payload.get(4)?;
                if flags & 0x80 == 0 {
                    return None;
                }
                let rcode = payload.get(5)? & 0x0F;
                // SERVFAIL and REFUSED are the server failing; NXDOMAIN is
                // an answer.
                Some(matches!(rcode, 2 | 5))
            }
        }
    }
}

const HTTP_METHODS: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
];

fn is_http_request(payload: &[u8]) -> bool {
    HTTP_METHODS
        .iter()
        .any(|method| payload.starts_with(method))
}

fn http_status(payload: &[u8]) -> Option<u16> {
    if !payload.starts_with(b"HTTP/1.") {
        return None;
    }
    let digits = payload.get(9..12)?;
    if payload.get(8) != Some(&b' ') || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        digits
            .iter()
            .fold(0u16, |status, digit| status * 10 + u16::from(digit - b'0')),
    )
}

/// `COM_QUERY`, `COM_STMT_PREPARE` and `COM_STMT_EXECUTE`, each opening a
/// command phase at sequence zero.
fn is_mysql_command(payload: &[u8]) -> bool {
    payload.get(3) == Some(&0) && matches!(payload.get(4), Some(0x03 | 0x16 | 0x17))
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedOutcome {
    Ok,
    Error,
    Unanswered,
}

impl RedOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Error => "error",
            Self::Unanswered => "unanswered",
        }
    }
}

/// One request, finished. `T` is whatever the caller attached to it when
/// it was seen, usually the names of the workloads at each end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedSample<T> {
    pub tag: T,
    pub protocol: RedProtocol,
    pub outcome: RedOutcome,
    /// Request to first answer byte, absent for an unanswered request.
    pub duration_ns: Option<u64>,
}

/// Tunables for [`RedTracker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RedConfig {
    pub max_pending: usize,
    pub answer_timeout_ns: u64,
}

impl Default for RedConfig {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            answer_timeout_ns: DEFAULT_ANSWER_TIMEOUT_NS,
        }
    }
}

struct Pending<T> {
    at_ns: u64,
    protocol: RedProtocol,
    tag: T,
}

/// Requests waiting for their answer, keyed by the flow they left on.
pub struct RedTracker<T> {
    pending: LruCache<FlowId, Pending<T>>,
    answer_timeout_ns: u64,
}

impl<T> RedTracker<T> {
    #[must_use]
    pub fn new(config: RedConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_pending).unwrap_or(NonZeroUsize::MIN);
        Self {
            pending: LruCache::new(cap),
            answer_timeout_ns: config.answer_timeout_ns,
        }
    }

    /// Requests waiting now.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Whether a request left on the reverse of `flow` is waiting, which is
    /// what makes a payload on `flow` a candidate answer.
    #[must_use]
    pub fn awaits_answer_on(&self, flow: &FlowId) -> bool {
        self.pending.contains(&reversed(flow))
    }

    /// Remember a request. A flow already waiting keeps its first request,
    /// so a pipelined second one is timed from the first. Returns the
    /// requests that were given up on to make room or by age.
    pub fn request(
        &mut self,
        flow: FlowId,
        at_ns: u64,
        protocol: RedProtocol,
        tag: T,
    ) -> Vec<RedSample<T>> {
        let mut gone = self.expire(at_ns);
        if self.pending.contains(&flow) {
            return gone;
        }
        let entry = Pending {
            at_ns,
            protocol,
            tag,
        };
        if let Some((_, pushed)) = self.pending.push(flow, entry) {
            gone.push(unanswered(pushed));
        }
        gone
    }

    /// Offer a payload seen on `flow` as the answer to the request waiting
    /// on its reverse. Returns the finished request, or `None` when nothing
    /// waits or the payload is not an answer, in which case the request
    /// keeps waiting.
    pub fn answer(&mut self, flow: &FlowId, at_ns: u64, payload: &[u8]) -> Option<RedSample<T>> {
        let key = reversed(flow);
        let waiting = self.pending.peek(&key)?;
        let failed = waiting.protocol.read_answer(payload)?;
        let done = self.pending.pop(&key)?;
        Some(RedSample {
            tag: done.tag,
            protocol: done.protocol,
            outcome: if failed {
                RedOutcome::Error
            } else {
                RedOutcome::Ok
            },
            duration_ns: Some(at_ns.saturating_sub(done.at_ns)),
        })
    }

    /// Give up on every request older than the answer timeout at `now_ns`.
    pub fn expire(&mut self, now_ns: u64) -> Vec<RedSample<T>> {
        let mut gone = Vec::new();
        while let Some((_, oldest)) = self.pending.peek_lru() {
            if now_ns.saturating_sub(oldest.at_ns) < self.answer_timeout_ns {
                break;
            }
            if let Some((_, pending)) = self.pending.pop_lru() {
                gone.push(unanswered(pending));
            }
        }
        gone
    }
}

fn unanswered<T>(pending: Pending<T>) -> RedSample<T> {
    RedSample {
        tag: pending.tag,
        protocol: pending.protocol,
        outcome: RedOutcome::Unanswered,
        duration_ns: None,
    }
}

fn reversed(flow: &FlowId) -> FlowId {
    FlowId::new(
        flow.dst_addr,
        flow.src_addr,
        flow.dst_port,
        flow.src_port,
        flow.is_ipv6,
    )
}

/// The service names handed out so far, capped.
#[derive(Debug, Clone)]
pub struct ServiceNames {
    seen: HashSet<String>,
    cap: usize,
}

impl Default for ServiceNames {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SERVICES)
    }
}

impl ServiceNames {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            seen: HashSet::new(),
            cap,
        }
    }

    /// The label a name is counted under: itself while there is room or
    /// once it has been admitted, [`OTHER_SERVICE`] after that.
    pub fn admit(&mut self, name: String) -> String {
        if self.seen.contains(&name) {
            return name;
        }
        if self.seen.len() >= self.cap {
            return OTHER_SERVICE.to_string();
        }
        self.seen.insert(name.clone());
        name
    }
}

/// The service a workload is counted as.
///
/// On Kubernetes the namespace and the pod name with the generated suffixes
/// taken off, so every replica of a deployment is one service; elsewhere the
/// systemd unit, then the container image without its tag, then the
/// executable's file name.
#[must_use]
pub fn service_name(workload: &Workload) -> String {
    if let (Some(namespace), Some(pod)) = (&workload.namespace, &workload.pod) {
        return format!("{namespace}/{}", controller_of(pod));
    }
    if let Some(unit) = &workload.unit {
        return unit.clone();
    }
    if let Some(image) = &workload.image {
        let repository = image.split('@').next().unwrap_or(image);
        let name = repository.rsplit('/').next().unwrap_or(repository);
        return name.split(':').next().unwrap_or(name).to_string();
    }
    if let Some(exe) = &workload.exe
        && let Some(name) = exe.rsplit('/').next()
        && !name.is_empty()
    {
        return name.to_string();
    }
    UNATTRIBUTED_SERVICE.to_string()
}

/// A pod name without what its controller generated: the five-character
/// pod suffix, then a replica set's template hash, or a stateful set's
/// ordinal.
fn controller_of(pod: &str) -> &str {
    let Some((base, last)) = pod.rsplit_once('-') else {
        return pod;
    };
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return base;
    }
    if !is_generated(last, 5..=5) {
        return pod;
    }
    match base.rsplit_once('-') {
        Some((deployment, hash)) if is_generated(hash, 6..=10) => deployment,
        _ => base,
    }
}

fn is_generated(segment: &str, len: std::ops::RangeInclusive<usize>) -> bool {
    len.contains(&segment.len())
        && segment
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && segment.bytes().any(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload::entity::WorkloadSource;

    fn flow(src_port: u16, dst_port: u16) -> FlowId {
        FlowId::new([1, 0, 0, 0], [2, 0, 0, 0], src_port, dst_port, false)
    }

    fn back(f: &FlowId) -> FlowId {
        reversed(f)
    }

    #[test]
    fn requests_are_told_from_answers_by_their_bytes() {
        assert_eq!(
            RedProtocol::of_request("http", b"GET / HTTP/1.1\r\n"),
            Some(RedProtocol::Http)
        );
        assert_eq!(RedProtocol::of_request("http", b"HTTP/1.1 200 OK"), None);
        assert_eq!(
            RedProtocol::of_request("redis", b"*1\r\n$4\r\nPING\r\n"),
            Some(RedProtocol::Redis)
        );
        assert_eq!(RedProtocol::of_request("redis", b"+PONG\r\n"), None);
        assert_eq!(
            RedProtocol::of_request("postgres", b"Q\0\0\0\x0dselect 1\0"),
            Some(RedProtocol::Postgres)
        );
        assert_eq!(
            RedProtocol::of_request("mysql", &[5, 0, 0, 0, 0x03, b's']),
            Some(RedProtocol::MySql)
        );
        assert_eq!(RedProtocol::of_request("mysql", &[5, 0, 0, 1, 0x03]), None);
        assert_eq!(
            RedProtocol::of_request("dns-tcp", &[0, 29, 0xab, 0xcd, 0x01, 0x00]),
            Some(RedProtocol::DnsTcp)
        );
        assert_eq!(RedProtocol::of_request("tls", b"\x16\x03\x01"), None);
    }

    #[test]
    fn each_protocol_says_how_its_answer_failed() {
        assert_eq!(
            RedProtocol::Http.read_answer(b"HTTP/1.1 503 Busy"),
            Some(true)
        );
        assert_eq!(
            RedProtocol::Http.read_answer(b"HTTP/1.0 404 Not Found"),
            Some(false)
        );
        assert_eq!(
            RedProtocol::Http.read_answer(b"HTTP/1.1 100 Continue"),
            None
        );
        assert_eq!(RedProtocol::Http.read_answer(b"<html>"), None);
        assert_eq!(RedProtocol::Redis.read_answer(b"-ERR wrong"), Some(true));
        assert_eq!(RedProtocol::Redis.read_answer(b"$5\r\nhello"), Some(false));
        assert_eq!(RedProtocol::Postgres.read_answer(b"E\0\0\0"), Some(true));
        assert_eq!(RedProtocol::Postgres.read_answer(b"T\0\0\0"), Some(false));
        assert_eq!(
            RedProtocol::MySql.read_answer(&[9, 0, 0, 1, 0xFF]),
            Some(true)
        );
        assert_eq!(
            RedProtocol::MySql.read_answer(&[7, 0, 0, 1, 0x00]),
            Some(false)
        );
        assert_eq!(
            RedProtocol::DnsTcp.read_answer(&[0, 29, 0xab, 0xcd, 0x81, 0x82]),
            Some(true)
        );
        assert_eq!(
            RedProtocol::DnsTcp.read_answer(&[0, 29, 0xab, 0xcd, 0x81, 0x83]),
            Some(false)
        );
        assert_eq!(
            RedProtocol::DnsTcp.read_answer(&[0, 29, 0xab, 0xcd, 0x01, 0x00]),
            None
        );
    }

    #[test]
    fn an_answer_on_the_reverse_flow_finishes_the_request_with_its_duration() {
        let mut tracker = RedTracker::new(RedConfig::default());
        let out = flow(40_000, 80);
        assert!(
            tracker
                .request(out, 1_000, RedProtocol::Http, "web")
                .is_empty()
        );
        assert!(tracker.awaits_answer_on(&back(&out)));
        assert!(!tracker.awaits_answer_on(&out));
        assert_eq!(tracker.answer(&out, 2_000, b"HTTP/1.1 200 OK"), None);
        assert_eq!(tracker.answer(&back(&out), 1_500, b"chunk"), None);
        let done = tracker.answer(&back(&out), 4_000, b"HTTP/1.1 500 Oops");
        assert_eq!(
            done,
            Some(RedSample {
                tag: "web",
                protocol: RedProtocol::Http,
                outcome: RedOutcome::Error,
                duration_ns: Some(3_000),
            })
        );
        assert!(tracker.is_empty());
    }

    #[test]
    fn a_pipelined_request_is_timed_from_the_first() {
        let mut tracker = RedTracker::new(RedConfig::default());
        let out = flow(40_000, 6379);
        tracker.request(out, 100, RedProtocol::Redis, 1);
        tracker.request(out, 200, RedProtocol::Redis, 2);
        assert_eq!(tracker.len(), 1);
        let done = tracker.answer(&back(&out), 300, b"+OK\r\n");
        assert_eq!(done.map(|s| (s.tag, s.duration_ns)), Some((1, Some(200))));
    }

    #[test]
    fn requests_nobody_answered_are_counted_unanswered_by_age_or_by_room() {
        let mut tracker = RedTracker::new(RedConfig {
            max_pending: 2,
            answer_timeout_ns: 1_000,
        });
        tracker.request(flow(1, 80), 0, RedProtocol::Http, "a");
        tracker.request(flow(2, 80), 10, RedProtocol::Http, "b");
        let pushed = tracker.request(flow(3, 80), 20, RedProtocol::Http, "c");
        assert_eq!(pushed.len(), 1);
        assert_eq!(pushed[0].tag, "a");
        assert_eq!(pushed[0].outcome, RedOutcome::Unanswered);
        assert_eq!(pushed[0].duration_ns, None);

        let aged = tracker.expire(1_015);
        assert_eq!(aged.iter().map(|s| s.tag).collect::<Vec<_>>(), vec!["b"]);
        assert_eq!(tracker.len(), 1);
        assert_eq!(tracker.expire(5_000).len(), 1);
        assert!(tracker.is_empty());
    }

    #[test]
    fn service_names_past_the_cap_read_other() {
        let mut names = ServiceNames::new(2);
        assert_eq!(names.admit("a".into()), "a");
        assert_eq!(names.admit("b".into()), "b");
        assert_eq!(names.admit("c".into()), OTHER_SERVICE);
        assert_eq!(names.admit("a".into()), "a");
    }

    fn workload() -> Workload {
        Workload {
            pid: 42,
            source: WorkloadSource::Flow,
            exe: Some("/usr/sbin/nginx".into()),
            uid: None,
            cgroup: None,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            unit: None,
        }
    }

    #[test]
    fn a_service_is_named_from_the_most_stable_part_of_the_workload() {
        let mut w = workload();
        assert_eq!(service_name(&w), "nginx");
        w.image = Some("registry.example/team/api:1.4@sha256:abc".into());
        assert_eq!(service_name(&w), "api");
        w.unit = Some("nginx.service".into());
        assert_eq!(service_name(&w), "nginx.service");
        w.namespace = Some("shop".into());
        w.pod = Some("checkout-7d9f8b6c5d-x2k4p".into());
        assert_eq!(service_name(&w), "shop/checkout");
        w.pod = Some("postgres-0".into());
        assert_eq!(service_name(&w), "shop/postgres");
        w.pod = Some("node-exporter-9qz7m".into());
        assert_eq!(service_name(&w), "shop/node-exporter");
        w.pod = Some("standalone".into());
        assert_eq!(service_name(&w), "shop/standalone");
        w.pod = Some("my-app".into());
        assert_eq!(service_name(&w), "shop/my-app");

        let mut bare = workload();
        bare.exe = None;
        assert_eq!(service_name(&bare), UNATTRIBUTED_SERVICE);
    }
}
