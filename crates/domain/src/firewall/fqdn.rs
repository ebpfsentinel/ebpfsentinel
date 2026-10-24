//! Destinations named by their DNS name, learned per workload.
//!
//! A rule naming `api.example.com` cannot be written down as an address: the
//! address is whatever the resolver answered, it changes, and two pods asking
//! the same name at different moments can be told different things. So the
//! rule is enforced from the answers themselves. The DNS packets of a named
//! workload are read on their way in and out of its sockets, an answer is
//! believed only when it answers a query that same cgroup sent to a resolver
//! the operator trusts, and every address it carries is opened for that
//! cgroup alone, for the record's own TTL plus a bounded grace.
//!
//! Three things follow and are stated rather than hidden. A workload that
//! resolves through anything else - DNS over HTTPS, DNS over TCP, an address
//! written into its configuration - learns nothing here and its connection
//! is refused. An address shared by many names, which is what a content
//! network does, is opened for every one of them as soon as one resolves, so
//! the allowance is coarser than the rule reads. And a connection already
//! open outlives the grant: only `connect()` and `sendmsg()` consult it.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::entity::IpNetwork;
use super::error::FirewallError;
use crate::dns::entity::{DnsPacket, DnsRecordType, DnsResponseCode};
use crate::dns::parser::parse_dns_packet;

/// Seconds an address stays open past its record's TTL when nothing says
/// otherwise.
///
/// A resolver hands out the remaining TTL of its cache, so an application
/// that resolved at the last second of it connects a moment after the record
/// lapsed. Thirty seconds covers that and a slow connect behind it.
pub const DEFAULT_GRACE_SECS: u32 = 30;

/// The longest grace an operator may set.
///
/// Past five minutes the grace stops being slack around a TTL and becomes a
/// second, longer TTL nobody wrote, which is an address left open after the
/// name moved away from it.
pub const MAX_GRACE_SECS: u32 = 300;

/// The longest TTL believed from an answer, whatever the record says.
///
/// A record carrying a week is honoured for a day: the address is learned
/// again at the next resolution, and an answer cached for longer than the
/// agent's own uptime is not one anybody can reason about.
pub const MAX_TTL_SECS: u32 = 86_400;

/// How long a query waits for its answer before it is forgotten.
pub const PENDING_QUERY_NS: u64 = 5_000_000_000;

/// How many unanswered queries are held at once.
///
/// Past it a new query is not recorded, so its answer teaches nothing and the
/// connection that follows is refused: a workload flooding its resolver
/// loses its own resolutions rather than everybody's.
pub const MAX_PENDING_QUERIES: usize = 4_096;

/// How many names are remembered per node after their last answer lapsed.
///
/// Remembering is what lets a report tell a name that resolved an hour ago
/// from one that never resolved at all, which is usually a typo. Past it the
/// name refreshed longest ago is forgotten first.
pub const MAX_REMEMBERED_NAMES: usize = 4_096;

/// How many CNAME hops are followed from the name asked to its addresses.
const MAX_CNAME_HOPS: usize = 8;

/// The longest name DNS carries, in its presentation form.
const MAX_NAME_LEN: usize = 253;

/// The longest label.
const MAX_LABEL_LEN: usize = 63;

/// One name, or one level of names under a domain, as a rule writes it.
///
/// `*.example.com` matches `api.example.com` and nothing deeper: one label,
/// which is the only wildcard a reading of the name asked for can decide
/// precisely. Every other shape of wildcard is refused when the rule is read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum FqdnPattern {
    /// Exactly this name, lowercase, without a trailing dot.
    Exact(String),
    /// Any one label in front of this suffix.
    Wildcard(String),
}

impl FqdnPattern {
    /// Read a pattern as an operator wrote it.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::InvalidFqdnPattern`] with the reason for a
    /// name DNS cannot carry and for every wildcard that would be enforced
    /// more widely than it reads.
    pub fn parse(raw: &str) -> Result<Self, FirewallError> {
        let refuse = |reason: &'static str| FirewallError::InvalidFqdnPattern {
            pattern: raw.to_string(),
            reason,
        };
        let name = normalize(raw);
        if name.is_empty() {
            return Err(refuse("the name is empty"));
        }
        if name == "*" {
            return Err(refuse(
                "a bare * matches every name, which is not a destination",
            ));
        }
        let (wildcard, rest) = match name.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, name.as_str()),
        };
        if rest.contains('*') {
            return Err(refuse(
                "only a whole leftmost label, as in *.example.com, can be matched precisely",
            ));
        }
        validate_name(rest).map_err(refuse)?;
        if wildcard {
            if rest.split('.').count() < 2 {
                return Err(refuse(
                    "a wildcard directly under a top-level domain admits every host registered \
                     there",
                ));
            }
            return Ok(Self::Wildcard(rest.to_string()));
        }
        Ok(Self::Exact(name))
    }

    /// Whether `name`, as an answer or a query carries it, is one this
    /// pattern names.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let name = normalize(name);
        match self {
            Self::Exact(exact) => name == *exact,
            Self::Wildcard(suffix) => name
                .strip_suffix(suffix.as_str())
                .and_then(|head| head.strip_suffix('.'))
                .is_some_and(|label| !label.is_empty() && !label.contains('.')),
        }
    }
}

impl fmt::Display for FqdnPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => f.write_str(name),
            Self::Wildcard(suffix) => write!(f, "*.{suffix}"),
        }
    }
}

impl TryFrom<String> for FqdnPattern {
    type Error = FirewallError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<FqdnPattern> for String {
    fn from(value: FqdnPattern) -> Self {
        value.to_string()
    }
}

/// A name in the one form every comparison here uses: lowercase, trimmed,
/// without the root's trailing dot.
#[must_use]
pub fn normalize(name: &str) -> String {
    let trimmed = name.trim();
    trimmed
        .strip_suffix('.')
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
}

/// Whether DNS can carry this name, as labels of letters, digits, hyphens
/// and the underscore service records use.
fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.len() > MAX_NAME_LEN {
        return Err("the name is longer than the 253 characters DNS carries");
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err("the name has an empty label");
        }
        if label.len() > MAX_LABEL_LEN {
            return Err("a label is longer than the 63 characters DNS carries");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("a label starts or ends with a hyphen");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("a label carries a character DNS names do not");
        }
    }
    Ok(())
}

/// Who an answer is believed from, and how long past its TTL it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadDnsSettings {
    /// The resolvers whose answers are believed, as networks.
    ///
    /// A workload able to answer its own query would otherwise open any
    /// address it likes, so only a query sent to one of these and an answer
    /// coming back from one of these is read. On Kubernetes this is the
    /// cluster DNS Service address.
    pub resolvers: Vec<IpNetwork>,
    /// Seconds past the record's TTL the address stays open.
    pub grace_secs: u32,
}

impl Default for WorkloadDnsSettings {
    fn default() -> Self {
        Self {
            resolvers: Vec::new(),
            grace_secs: DEFAULT_GRACE_SECS,
        }
    }
}

impl WorkloadDnsSettings {
    /// # Errors
    ///
    /// Returns [`FirewallError::InvalidWorkloadDns`] for a grace past
    /// [`MAX_GRACE_SECS`].
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.grace_secs > MAX_GRACE_SECS {
            return Err(FirewallError::InvalidWorkloadDns {
                reason: format!(
                    "grace_secs is {}, more than the {MAX_GRACE_SECS} allowed",
                    self.grace_secs
                ),
            });
        }
        Ok(())
    }

    /// Whether answers from `addr` are believed.
    #[must_use]
    pub fn trusts(&self, addr: IpAddr) -> bool {
        self.resolvers.iter().any(|network| match addr {
            IpAddr::V4(v4) => network.contains_v4(u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => network.contains_v4(u32::from(v4)),
                None => network.contains_v6(&v6.octets()),
            },
        })
    }

    /// The `CLOCK_BOOTTIME` instant an address answered at `at_ns` with
    /// `ttl` seconds stops opening connections.
    #[must_use]
    pub fn expiry_ns(&self, at_ns: u64, ttl: u32) -> u64 {
        let secs = u64::from(ttl.min(MAX_TTL_SECS)) + u64::from(self.grace_secs);
        at_ns.saturating_add(secs.saturating_mul(1_000_000_000))
    }
}

/// Which way a captured DNS packet was going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDirection {
    /// Leaving the workload, towards a resolver.
    Query,
    /// Arriving at the workload, from a resolver.
    Response,
}

/// One DNS packet of a named workload, as the capture saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCapture {
    /// `CLOCK_BOOTTIME` at the hook.
    pub at_ns: u64,
    /// The cgroup of the socket the packet belongs to.
    pub cgroup_id: u64,
    /// Which way it was going.
    pub direction: DnsDirection,
    /// The workload's own port: the source of a query, the destination of an
    /// answer.
    pub client_port: u16,
    /// The resolver's address: the destination of a query, the source of an
    /// answer.
    pub resolver: IpAddr,
    /// The DNS message from its header, as much of it as the capture kept.
    pub payload: Vec<u8>,
}

/// What one believed answer taught: the name asked and where it lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    /// The cgroup that asked, and the only one the addresses open for.
    pub cgroup_id: u64,
    /// The name the workload asked for, normalized.
    pub name: String,
    /// Every address the answer carried for that name, with its TTL.
    pub addresses: Vec<(IpAddr, u32)>,
    /// `CLOCK_BOOTTIME` the answer arrived at.
    pub at_ns: u64,
}

/// One query waiting for its answer.
#[derive(Debug, Clone)]
struct PendingQuery {
    name: String,
    at_ns: u64,
}

/// Pairs a workload's queries with their answers and keeps only the answers
/// it can believe.
#[derive(Debug, Clone, Default)]
pub struct FqdnLearner {
    settings: WorkloadDnsSettings,
    pending: HashMap<(u64, u16, u16), PendingQuery>,
}

impl FqdnLearner {
    #[must_use]
    pub fn new(settings: WorkloadDnsSettings) -> Self {
        Self {
            settings,
            pending: HashMap::new(),
        }
    }

    /// The settings answers are read under.
    #[must_use]
    pub fn settings(&self) -> &WorkloadDnsSettings {
        &self.settings
    }

    /// How many queries are waiting for an answer.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Read one captured packet, and return what it taught if it was an
    /// answer worth believing.
    ///
    /// A query is recorded under its cgroup, its transaction id and the
    /// workload's port. An answer is believed only when it comes from a
    /// trusted resolver, matches such a record from the same cgroup within
    /// [`PENDING_QUERY_NS`], and names the same question. Anything else is
    /// dropped without a word, because a forged answer and a late one look
    /// the same from here and both are refused the same way.
    pub fn observe(&mut self, capture: &DnsCapture) -> Option<Resolution> {
        if !self.settings.trusts(capture.resolver) {
            return None;
        }
        let txid = u16::from_be_bytes([*capture.payload.first()?, *capture.payload.get(1)?]);
        let key = (capture.cgroup_id, txid, capture.client_port);
        match capture.direction {
            DnsDirection::Query => {
                let DnsPacket::Query(query) =
                    parse_dns_packet(&capture.payload, capture.resolver, capture.at_ns).ok()?
                else {
                    return None;
                };
                self.prune(capture.at_ns);
                if self.pending.len() >= MAX_PENDING_QUERIES {
                    return None;
                }
                self.pending.insert(
                    key,
                    PendingQuery {
                        name: normalize(&query.domain),
                        at_ns: capture.at_ns,
                    },
                );
                None
            }
            DnsDirection::Response => {
                let asked = self.pending.remove(&key)?;
                if capture.at_ns.saturating_sub(asked.at_ns) > PENDING_QUERY_NS {
                    return None;
                }
                let DnsPacket::Response(response) =
                    parse_dns_packet(&capture.payload, capture.resolver, capture.at_ns).ok()?
                else {
                    return None;
                };
                if response.rcode != DnsResponseCode::NoError {
                    return None;
                }
                let question = response.queries.first()?;
                if normalize(&question.domain) != asked.name {
                    return None;
                }
                let chain = cname_chain(&asked.name, &response.answers);
                let addresses: Vec<(IpAddr, u32)> = response
                    .answers
                    .iter()
                    .filter(|record| {
                        matches!(record.record_type, DnsRecordType::A | DnsRecordType::AAAA)
                            && chain.contains(&normalize(&record.domain))
                    })
                    .flat_map(|record| record.resolved_ips.iter().map(|ip| (*ip, record.ttl)))
                    .collect();
                if addresses.is_empty() {
                    return None;
                }
                Some(Resolution {
                    cgroup_id: capture.cgroup_id,
                    name: asked.name,
                    addresses,
                    at_ns: capture.at_ns,
                })
            }
        }
    }

    /// Forget every query older than [`PENDING_QUERY_NS`] at `now_ns`.
    pub fn prune(&mut self, now_ns: u64) {
        self.pending
            .retain(|_, query| now_ns.saturating_sub(query.at_ns) <= PENDING_QUERY_NS);
    }
}

/// The name asked and every name a CNAME in the answer leads to from it.
fn cname_chain(name: &str, answers: &[crate::dns::entity::DnsRecord]) -> Vec<String> {
    let mut chain = vec![name.to_string()];
    for _ in 0..MAX_CNAME_HOPS {
        let Some(next) = answers.iter().find_map(|record| {
            let target = record.cname_target.as_deref()?;
            let owner = normalize(&record.domain);
            let target = normalize(target);
            (record.record_type == DnsRecordType::CNAME
                && chain.contains(&owner)
                && !chain.contains(&target))
            .then_some(target)
        }) else {
            break;
        };
        chain.push(next);
    }
    chain
}

/// One address opened for one cgroup by one rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FqdnGrantKey {
    /// The cgroup that resolved the name.
    pub cgroup_id: u64,
    /// The address the answer carried.
    pub addr: IpAddr,
    /// The kernel slot of the rule naming the name.
    pub slot: u16,
}

/// What is known about one grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FqdnGrant {
    /// The name that resolved to the address.
    pub name: String,
    /// `CLOCK_BOOTTIME` the grant stops opening connections at.
    pub expires_ns: u64,
    /// `CLOCK_BOOTTIME` of the last answer that refreshed it.
    pub refreshed_ns: u64,
}

/// Every address currently open by name, mirrored from the kernel map so it
/// can be swept and reported, and when each name under each rule last
/// resolved, kept after its addresses lapsed.
#[derive(Debug, Clone, Default)]
pub struct FqdnLedger {
    grants: HashMap<FqdnGrantKey, FqdnGrant>,
    last_resolved: HashMap<(u16, String), u64>,
}

/// One name a rule's pattern matched, as a report writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FqdnNameReport {
    /// The name the workload asked for.
    pub name: String,
    /// Distinct addresses currently open for it.
    pub addresses: usize,
    /// Distinct cgroups it is currently open for.
    pub workloads: usize,
    /// `CLOCK_BOOTTIME` of the last answer naming it.
    pub refreshed_ns: u64,
    /// `CLOCK_BOOTTIME` its last address lapses at, `None` once all have.
    pub expires_ns: Option<u64>,
}

/// What one pattern of one rule has resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FqdnPatternReport {
    /// The pattern as the rule wrote it.
    pub pattern: FqdnPattern,
    /// Every name it matched that is still remembered, the most recently
    /// refreshed first. Empty is a pattern that never resolved on this node.
    pub names: Vec<FqdnNameReport>,
}

impl FqdnLedger {
    /// Record an answer for one key, and return the expiry now in force.
    ///
    /// The later of the two expiries wins: two names on one address under
    /// one rule each keep it open for as long as their own record says, and
    /// the shorter answer arriving second must not close it early.
    pub fn record(&mut self, key: FqdnGrantKey, name: &str, expires_ns: u64, at_ns: u64) -> u64 {
        let grant = self.grants.entry(key).or_insert_with(|| FqdnGrant {
            name: name.to_string(),
            expires_ns,
            refreshed_ns: at_ns,
        });
        if expires_ns >= grant.expires_ns {
            grant.expires_ns = expires_ns;
            name.clone_into(&mut grant.name);
        }
        grant.refreshed_ns = grant.refreshed_ns.max(at_ns);
        let in_force = grant.expires_ns;
        self.remember(key.slot, name, at_ns);
        in_force
    }

    fn remember(&mut self, slot: u16, name: &str, at_ns: u64) {
        let entry = (slot, name.to_string());
        if !self.last_resolved.contains_key(&entry)
            && self.last_resolved.len() >= MAX_REMEMBERED_NAMES
            && let Some(oldest) = self
                .last_resolved
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(key, _)| key.clone())
        {
            self.last_resolved.remove(&oldest);
        }
        let at = self.last_resolved.entry(entry).or_insert(at_ns);
        *at = (*at).max(at_ns);
    }

    /// What `pattern`, written on the rule in `slot`, has resolved, with the
    /// addresses still open at `now_ns`.
    #[must_use]
    pub fn report(&self, slot: u16, pattern: &FqdnPattern, now_ns: u64) -> FqdnPatternReport {
        let mut names: Vec<FqdnNameReport> = self
            .last_resolved
            .iter()
            .filter(|((at_slot, name), _)| *at_slot == slot && pattern.matches(name))
            .map(|((_, name), refreshed_ns)| {
                let open: Vec<(&FqdnGrantKey, &FqdnGrant)> = self
                    .grants
                    .iter()
                    .filter(|(key, grant)| {
                        key.slot == slot && grant.name == *name && grant.expires_ns > now_ns
                    })
                    .collect();
                let mut addresses: Vec<IpAddr> = open.iter().map(|(key, _)| key.addr).collect();
                addresses.sort_unstable();
                addresses.dedup();
                let mut workloads: Vec<u64> = open.iter().map(|(key, _)| key.cgroup_id).collect();
                workloads.sort_unstable();
                workloads.dedup();
                FqdnNameReport {
                    name: name.clone(),
                    addresses: addresses.len(),
                    workloads: workloads.len(),
                    refreshed_ns: *refreshed_ns,
                    expires_ns: open.iter().map(|(_, grant)| grant.expires_ns).max(),
                }
            })
            .collect();
        names.sort_by(|a, b| {
            b.refreshed_ns
                .cmp(&a.refreshed_ns)
                .then_with(|| a.name.cmp(&b.name))
        });
        FqdnPatternReport {
            pattern: pattern.clone(),
            names,
        }
    }

    /// Remove and return every grant lapsed at `now_ns`.
    pub fn sweep(&mut self, now_ns: u64) -> Vec<FqdnGrantKey> {
        let lapsed: Vec<FqdnGrantKey> = self
            .grants
            .iter()
            .filter(|(_, grant)| grant.expires_ns <= now_ns)
            .map(|(key, _)| *key)
            .collect();
        for key in &lapsed {
            self.grants.remove(key);
        }
        lapsed
    }

    /// Remove one grant, as when the kernel refused to hold it.
    pub fn remove(&mut self, key: &FqdnGrantKey) {
        self.grants.remove(key);
    }

    /// Forget every grant, which is what a new policy means: its slots are
    /// numbered afresh.
    pub fn clear(&mut self) {
        self.grants.clear();
        self.last_resolved.clear();
    }

    /// How many grants are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// Whether no grant is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Every grant held, in no order.
    pub fn grants(&self) -> impl Iterator<Item = (&FqdnGrantKey, &FqdnGrant)> {
        self.grants.iter()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn settings() -> WorkloadDnsSettings {
        WorkloadDnsSettings {
            resolvers: vec![IpNetwork::V4 {
                addr: u32::from(Ipv4Addr::new(10, 96, 0, 10)),
                prefix_len: 32,
            }],
            grace_secs: 30,
        }
    }

    const RESOLVER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10));

    fn encode_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn query(txid: u16, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&txid.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        encode_name(&mut out, name);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out
    }

    /// An answer to `name`, optionally through one CNAME, with A records.
    fn answer(txid: u16, name: &str, cname: Option<&str>, addrs: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&txid.to_be_bytes());
        let count = u16::try_from(addrs.len() + usize::from(cname.is_some())).unwrap();
        out.extend_from_slice(&[0x81, 0x80, 0, 1]);
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        encode_name(&mut out, name);
        out.extend_from_slice(&[0, 1, 0, 1]);
        let owner = if let Some(target) = cname {
            encode_name(&mut out, name);
            out.extend_from_slice(&[0, 5, 0, 1]);
            out.extend_from_slice(&ttl.to_be_bytes());
            let mut rdata = Vec::new();
            encode_name(&mut rdata, target);
            out.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            out.extend_from_slice(&rdata);
            target
        } else {
            name
        };
        for addr in addrs {
            encode_name(&mut out, owner);
            out.extend_from_slice(&[0, 1, 0, 1]);
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&[0, 4]);
            out.extend_from_slice(&addr.octets());
        }
        out
    }

    fn capture(
        cgroup_id: u64,
        direction: DnsDirection,
        resolver: IpAddr,
        payload: &[u8],
        at_ns: u64,
    ) -> DnsCapture {
        DnsCapture {
            at_ns,
            cgroup_id,
            direction,
            client_port: 40_000,
            resolver,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn an_exact_name_is_normalized_and_matched_without_case() {
        let pattern = FqdnPattern::parse("API.Example.com.").unwrap();
        assert_eq!(pattern, FqdnPattern::Exact("api.example.com".to_string()));
        assert!(pattern.matches("api.EXAMPLE.com"));
        assert!(!pattern.matches("www.api.example.com"));
    }

    #[test]
    fn a_wildcard_matches_exactly_one_label() {
        let pattern = FqdnPattern::parse("*.example.com").unwrap();
        assert!(pattern.matches("api.example.com"));
        assert!(!pattern.matches("example.com"));
        assert!(!pattern.matches("a.b.example.com"));
        assert!(!pattern.matches("badexample.com"));
        assert_eq!(pattern.to_string(), "*.example.com");
    }

    #[test]
    fn every_imprecise_wildcard_is_refused_with_its_reason() {
        for raw in [
            "*",
            "*.com",
            "api.*.com",
            "api*.example.com",
            "**.example.com",
            "",
        ] {
            let error = FqdnPattern::parse(raw).unwrap_err();
            assert!(
                matches!(error, FirewallError::InvalidFqdnPattern { .. }),
                "{raw} should be refused"
            );
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn a_name_dns_cannot_carry_is_refused() {
        assert!(FqdnPattern::parse("bad name.com").is_err());
        assert!(FqdnPattern::parse("-api.example.com").is_err());
        assert!(FqdnPattern::parse(&format!("{}.com", "a".repeat(64))).is_err());
        assert!(FqdnPattern::parse("_https._tcp.example.com").is_ok());
    }

    #[test]
    fn a_pattern_round_trips_through_its_text() {
        let pattern: FqdnPattern = serde_json::from_str("\"*.example.com\"").unwrap();
        assert_eq!(
            serde_json::to_string(&pattern).unwrap(),
            "\"*.example.com\""
        );
        assert!(serde_json::from_str::<FqdnPattern>("\"*.com\"").is_err());
    }

    #[test]
    fn a_trusted_answer_to_a_recorded_query_is_believed() {
        let mut learner = FqdnLearner::new(settings());
        let q = query(7, "api.example.com");
        assert!(
            learner
                .observe(&capture(1, DnsDirection::Query, RESOLVER, &q, 1_000))
                .is_none()
        );
        let a = answer(
            7,
            "api.example.com",
            None,
            &[Ipv4Addr::new(192, 0, 2, 1)],
            60,
        );
        let learned = learner
            .observe(&capture(1, DnsDirection::Response, RESOLVER, &a, 2_000))
            .expect("the answer pairs with its query");
        assert_eq!(learned.cgroup_id, 1);
        assert_eq!(learned.name, "api.example.com");
        assert_eq!(
            learned.addresses,
            vec![(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 60)]
        );
        assert_eq!(learner.pending(), 0);
    }

    #[test]
    fn an_answer_through_a_cname_teaches_the_target_addresses() {
        let mut learner = FqdnLearner::new(settings());
        let q = query(9, "api.example.com");
        learner.observe(&capture(1, DnsDirection::Query, RESOLVER, &q, 0));
        let a = answer(
            9,
            "api.example.com",
            Some("edge.cdn.net"),
            &[Ipv4Addr::new(198, 51, 100, 4)],
            30,
        );
        let learned = learner
            .observe(&capture(1, DnsDirection::Response, RESOLVER, &a, 1))
            .unwrap();
        assert_eq!(learned.name, "api.example.com");
        assert_eq!(learned.addresses.len(), 1);
    }

    #[test]
    fn an_answer_for_another_cgroup_teaches_nothing() {
        // The query came from cgroup 1; the same transaction id and port
        // arriving at cgroup 2 is not its answer, and opens nothing there.
        let mut learner = FqdnLearner::new(settings());
        let q = query(7, "api.example.com");
        learner.observe(&capture(1, DnsDirection::Query, RESOLVER, &q, 0));
        let a = answer(
            7,
            "api.example.com",
            None,
            &[Ipv4Addr::new(192, 0, 2, 1)],
            60,
        );
        assert!(
            learner
                .observe(&capture(2, DnsDirection::Response, RESOLVER, &a, 1))
                .is_none()
        );
    }

    #[test]
    fn an_answer_from_an_untrusted_source_is_not_believed() {
        let mut learner = FqdnLearner::new(settings());
        let q = query(7, "api.example.com");
        learner.observe(&capture(1, DnsDirection::Query, RESOLVER, &q, 0));
        let forger = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 66));
        let a = answer(
            7,
            "api.example.com",
            None,
            &[Ipv4Addr::new(203, 0, 113, 9)],
            60,
        );
        assert!(
            learner
                .observe(&capture(1, DnsDirection::Response, forger, &a, 1))
                .is_none()
        );
    }

    #[test]
    fn a_query_to_an_untrusted_resolver_is_never_paired() {
        let mut learner = FqdnLearner::new(settings());
        let other = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let q = query(7, "api.example.com");
        learner.observe(&capture(1, DnsDirection::Query, other, &q, 0));
        assert_eq!(learner.pending(), 0);
    }

    #[test]
    fn a_late_or_mismatched_answer_is_dropped() {
        let mut learner = FqdnLearner::new(settings());
        let q = query(7, "api.example.com");
        learner.observe(&capture(1, DnsDirection::Query, RESOLVER, &q, 0));
        let a = answer(
            7,
            "api.example.com",
            None,
            &[Ipv4Addr::new(192, 0, 2, 1)],
            60,
        );
        assert!(
            learner
                .observe(&capture(
                    1,
                    DnsDirection::Response,
                    RESOLVER,
                    &a,
                    PENDING_QUERY_NS + 1
                ))
                .is_none()
        );

        learner.observe(&capture(1, DnsDirection::Query, RESOLVER, &q, 0));
        let other = answer(
            7,
            "evil.example.com",
            None,
            &[Ipv4Addr::new(192, 0, 2, 2)],
            60,
        );
        assert!(
            learner
                .observe(&capture(1, DnsDirection::Response, RESOLVER, &other, 1))
                .is_none()
        );
    }

    #[test]
    fn the_expiry_is_the_ttl_capped_plus_the_grace() {
        let settings = settings();
        assert_eq!(settings.expiry_ns(1_000, 60), 1_000 + 90 * 1_000_000_000);
        assert_eq!(
            settings.expiry_ns(0, u32::MAX),
            u64::from(MAX_TTL_SECS + 30) * 1_000_000_000
        );
    }

    #[test]
    fn a_grace_past_the_ceiling_is_refused() {
        let mut settings = settings();
        settings.grace_secs = MAX_GRACE_SECS + 1;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn the_ledger_keeps_the_later_expiry_and_sweeps_what_lapsed() {
        let mut ledger = FqdnLedger::default();
        let key = FqdnGrantKey {
            cgroup_id: 1,
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            slot: 0,
        };
        assert_eq!(ledger.record(key, "a.example.com", 100, 1), 100);
        assert_eq!(ledger.record(key, "b.example.com", 50, 2), 100);
        assert_eq!(ledger.grants().next().unwrap().1.refreshed_ns, 2);
        assert!(ledger.sweep(99).is_empty());
        assert_eq!(ledger.sweep(100), vec![key]);
        assert!(ledger.is_empty());
    }

    #[test]
    fn a_report_tells_a_lapsed_name_from_one_that_never_resolved() {
        let mut ledger = FqdnLedger::default();
        let wildcard = FqdnPattern::parse("*.cdn.example.com").unwrap();
        let exact = FqdnPattern::parse("api.example.com").unwrap();
        let one = |cgroup_id, last| FqdnGrantKey {
            cgroup_id,
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            slot: 3,
        };
        ledger.record(one(7, 1), "a.cdn.example.com", 100, 10);
        ledger.record(one(8, 1), "a.cdn.example.com", 120, 20);
        ledger.record(one(7, 2), "a.cdn.example.com", 110, 15);
        ledger.record(one(7, 3), "b.cdn.example.com", 50, 5);

        let report = ledger.report(3, &wildcard, 60);
        assert_eq!(report.names.len(), 2);
        assert_eq!(report.names[0].name, "a.cdn.example.com");
        assert_eq!(report.names[0].addresses, 2);
        assert_eq!(report.names[0].workloads, 2);
        assert_eq!(report.names[0].refreshed_ns, 20);
        assert_eq!(report.names[0].expires_ns, Some(120));

        ledger.sweep(60);
        let lapsed = &ledger.report(3, &wildcard, 60).names[1];
        assert_eq!(lapsed.name, "b.cdn.example.com");
        assert_eq!(lapsed.addresses, 0);
        assert_eq!(lapsed.expires_ns, None);

        assert!(ledger.report(3, &exact, 60).names.is_empty());
        assert!(ledger.report(4, &wildcard, 60).names.is_empty());

        ledger.clear();
        assert!(ledger.report(3, &wildcard, 60).names.is_empty());
    }

    #[test]
    fn the_names_remembered_are_bounded_and_the_oldest_goes_first() {
        let mut ledger = FqdnLedger::default();
        let key = FqdnGrantKey {
            cgroup_id: 1,
            addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            slot: 0,
        };
        for index in 0..=MAX_REMEMBERED_NAMES {
            let at = u64::try_from(index).unwrap() + 1;
            ledger.record(key, &format!("n{index}.example.com"), at, at);
        }
        let all = FqdnPattern::parse("*.example.com").unwrap();
        let names = ledger.report(0, &all, 0).names;
        assert_eq!(names.len(), MAX_REMEMBERED_NAMES);
        assert!(names.iter().all(|name| name.name != "n0.example.com"));
    }
}
