use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Instant;

use regex::Regex;
use regex::bytes::Regex as BytesRegex;

use crate::common::entity::RuleId;
use crate::common::error::DomainError;
use ebpf_common::event::PacketEvent;

use super::entity::{DomainMatchMode, IdsRule, SamplingMode, ThresholdType};
use super::error::IdsError;
use super::flow::{Ended, FlowTable, Packet, Seen, Wire};
use super::packet::{IpPacket, L4};
use super::prefilter::{Entry, Prefilter, needle};

use super::sig::inspect::{Inspect, Program};
use super::stream::Segment;
use crate::common::entity::Protocol;
use crate::dns::entity::DomainPattern;

/// The most ports an imported rule is indexed under; past it the rule is a
/// candidate for every packet and its header decides.
const INDEXED_PORTS: usize = 64;

/// Internal state for per-rule, per-track-key threshold tracking.
#[derive(Debug)]
struct ThresholdState {
    count: u32,
    window_start: Instant,
    alerted_in_window: bool,
}

/// A pre-compiled domain matcher for a single IDS rule.
/// Compiled once at rule load time, used per-packet in userspace.
#[derive(Debug, Clone)]
pub enum CompiledDomainMatcher {
    /// Case-insensitive exact match (lowercased at compile time).
    Exact(String),
    /// Wildcard prefix match via `DomainPattern` (e.g. `*.evil.com`).
    Wildcard(DomainPattern),
    /// Full regex match (compiled with `DoS` limits).
    Regex(Regex),
}

impl CompiledDomainMatcher {
    /// Check if a domain matches this pattern.
    pub fn matches(&self, domain: &str) -> bool {
        match self {
            Self::Exact(expected) => domain.eq_ignore_ascii_case(expected),
            Self::Wildcard(pat) => pat.matches(domain),
            Self::Regex(re) => re.is_match(domain),
        }
    }
}

/// IDS engine: validates, stores, and manages IDS rules.
/// Regex patterns are compiled at rule load time (not per-packet).
#[derive(Debug, Clone)]
pub struct IdsEngine {
    rules: Vec<IdsRule>,
    compiled_patterns: Vec<Option<BytesRegex>>,
    compiled_domain_patterns: Vec<Option<CompiledDomainMatcher>>,
    /// The matches an imported rule runs over the payload, in place of a
    /// pattern.
    inspections: Vec<Option<Arc<Program>>>,
    /// Which rules a payload is worth running, built on first use after the
    /// rules change.
    prefilter: OnceLock<Arc<Prefilter>>,
    sampling: SamplingMode,
    threshold_tracker: Arc<Mutex<HashMap<(RuleId, u64), ThresholdState>>>,
    /// What flows, hosts and pairs remember for the rules that read or
    /// write it, locked only when such a rule matched.
    flows: Arc<Mutex<FlowTable>>,
}

impl IdsEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_patterns: Vec::new(),
            compiled_domain_patterns: Vec::new(),
            inspections: Vec::new(),
            prefilter: OnceLock::new(),
            sampling: SamplingMode::default(),
            threshold_tracker: Arc::new(Mutex::new(HashMap::new())),
            flows: Arc::new(Mutex::new(FlowTable::default())),
        }
    }

    /// Return `true` if any loaded rule carries a compiled domain pattern.
    ///
    /// Lets the packet pipeline skip the reverse-DNS lookup (an `RwLock` read
    /// plus a `Vec<String>` allocation) on every IDS event when no rule needs
    /// resolved domains - the common case.
    #[must_use]
    pub fn has_domain_rules(&self) -> bool {
        self.compiled_domain_patterns.iter().any(Option::is_some)
    }

    /// Add a single IDS rule. Validates, checks for duplicates,
    /// and compiles the regex pattern.
    pub fn add_rule(&mut self, rule: IdsRule) -> Result<(), DomainError> {
        rule.validate()
            .map_err(|reason| IdsError::InvalidRuleId { reason })?;

        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(IdsError::DuplicateRule {
                id: rule.id.0.clone(),
            }
            .into());
        }

        let inspection = inspection(&rule);
        let compiled = compile_rule_pattern(&rule, inspection.is_some())?;
        let domain_compiled = compile_domain_pattern(&rule)?;
        self.rules.push(rule);
        self.compiled_patterns.push(compiled);
        self.compiled_domain_patterns.push(domain_compiled);
        self.inspections.push(inspection);
        self.prefilter = OnceLock::new();
        let streams = self.reads_streams();
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.forget_filters();
        flows.keep_streams(streams);
        Ok(())
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&mut self, id: &crate::common::entity::RuleId) -> Result<(), DomainError> {
        let pos = self
            .rules
            .iter()
            .position(|r| r.id == *id)
            .ok_or_else(|| IdsError::RuleNotFound { id: id.0.clone() })?;
        self.rules.remove(pos);
        self.compiled_patterns.remove(pos);
        self.compiled_domain_patterns.remove(pos);
        self.inspections.remove(pos);
        self.prefilter = OnceLock::new();
        let streams = self.reads_streams();
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.forget_filters();
        flows.keep_streams(streams);
        Ok(())
    }

    /// Atomically replace all rules. Validates all rules and compiles
    /// all patterns before replacing. Rolls back on any error.
    pub fn reload(&mut self, rules: Vec<IdsRule>) -> Result<(), DomainError> {
        // Validate all rules first
        for rule in &rules {
            rule.validate()
                .map_err(|reason| IdsError::InvalidRuleId { reason })?;
        }

        // Check for duplicates
        let mut ids = std::collections::HashSet::with_capacity(rules.len());
        for rule in &rules {
            if !ids.insert(&rule.id) {
                return Err(IdsError::DuplicateRule {
                    id: rule.id.0.clone(),
                }
                .into());
            }
        }

        // Compile all patterns
        let mut compiled = Vec::with_capacity(rules.len());
        let mut domain_compiled = Vec::with_capacity(rules.len());
        let mut inspections = Vec::with_capacity(rules.len());
        for rule in &rules {
            let program = inspection(rule);
            compiled.push(compile_rule_pattern(rule, program.is_some())?);
            domain_compiled.push(compile_domain_pattern(rule)?);
            inspections.push(program);
        }

        // Atomic replace
        self.rules = rules;
        self.compiled_patterns = compiled;
        self.compiled_domain_patterns = domain_compiled;
        self.inspections = inspections;
        self.prefilter = OnceLock::new();
        let streams = self.reads_streams();
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.forget_filters();
        flows.keep_streams(streams);
        drop(flows);
        self.threshold_tracker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        Ok(())
    }

    /// Whether a loaded rule reads a TCP connection's streams: one whose
    /// matches run on them, or one reading `stream_size`.
    fn reads_streams(&self) -> bool {
        self.inspections
            .iter()
            .flatten()
            .any(|p| p.inspect() != Inspect::Packet || p.reads_stream_size())
    }

    /// Read-only access to the loaded rules.
    pub fn rules(&self) -> &[IdsRule] {
        &self.rules
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Access the compiled content pattern for a rule at the given index.
    pub fn compiled_pattern(&self, index: usize) -> Option<&BytesRegex> {
        self.compiled_patterns.get(index).and_then(Option::as_ref)
    }

    /// Return `true` if any loaded rule carries a content pattern.
    ///
    /// Lets the L7 path skip the whole content scan when no rule asks for
    /// one, which is the common case.
    #[must_use]
    pub fn has_content_rules(&self) -> bool {
        self.compiled_patterns.iter().any(Option::is_some)
    }

    /// The ports whose traffic has to be captured for the content rules to
    /// have a payload to match against. A rule may name either leg, so both
    /// are reported.
    pub fn content_ports(&self) -> Vec<u16> {
        let mut ports: Vec<u16> = self
            .rules
            .iter()
            .zip(self.compiled_patterns.iter())
            .filter(|(rule, pattern)| rule.enabled && pattern.is_some())
            .flat_map(|(rule, _)| [rule.dst_port, rule.src_port])
            .flatten()
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Set the sampling mode for event processing.
    pub fn set_sampling(&mut self, mode: SamplingMode) {
        self.sampling = mode;
    }

    /// Read-only access to the current sampling mode.
    pub fn sampling(&self) -> &SamplingMode {
        &self.sampling
    }

    /// Look up the rule that generated this event by its `rule_id` index.
    /// The eBPF TC classifier sets `event.rule_id` to the rule's position
    /// in the engine. Returns `None` if the index is out of range, the
    /// rule is disabled, or the event is sampled out.
    ///
    /// Backward-compatible wrapper: does not perform domain matching.
    /// Use `evaluate_event_with_context` for domain-aware evaluation.
    pub fn evaluate_event(&self, event: &PacketEvent) -> Option<(usize, &IdsRule)> {
        self.evaluate_event_with_context(event, &[], None)
            .map(|(idx, rule, _matched_domain)| (idx, rule))
    }

    /// Evaluate an event with optional domain and country context.
    ///
    /// `dst_domains` contains the domains resolved for the destination IP
    /// (from the DNS cache reverse lookup). If a rule has a `domain_pattern`,
    /// at least one domain in the list must match. If `dst_domains` is empty,
    /// rules with `domain_pattern` will not match.
    ///
    /// `src_country` is the resolved ISO 3166-1 alpha-2 country code for the
    /// source IP. When provided, country-based sampling uses it to apply
    /// different sampling rates.
    ///
    /// Returns `(rule_index, rule, matched_domain)` on match.
    pub fn evaluate_event_with_context<'a>(
        &'a self,
        event: &PacketEvent,
        dst_domains: &[String],
        src_country: Option<&str>,
    ) -> Option<(usize, &'a IdsRule, Option<String>)> {
        self.evaluate_index_with_context(event.rule_id as usize, event, dst_domains, src_country)
    }

    /// Evaluate one named rule index against an event, applying the same
    /// sampling, content and domain gating as [`Self::evaluate_event_with_context`].
    ///
    /// The kernel names a single rule per event because a map slot holds one
    /// rule, so a rule that shares a port with the slot's owner never reaches
    /// the classifier. The pipeline replays those rules through this entry
    /// point; the sampling decision is a pure function of the addresses, or
    /// for random sampling was already taken by the kernel for this packet, so
    /// evaluating several rules for one packet keeps the same verdict.
    pub fn evaluate_index_with_context<'a>(
        &'a self,
        idx: usize,
        event: &PacketEvent,
        dst_domains: &[String],
        src_country: Option<&str>,
    ) -> Option<(usize, &'a IdsRule, Option<String>)> {
        if !self
            .sampling
            .should_process_kernel_event(event.src_ip(), event.dst_ip(), src_country)
        {
            return None;
        }
        let rule = self.rules.get(idx)?;
        if !rule.enabled {
            return None;
        }
        // An imported rule names the networks on either side as well as the
        // port; the kernel slot keys on the port alone.
        if rule
            .imported
            .as_ref()
            .is_some_and(|imported| !imported.addresses_match(event))
        {
            return None;
        }

        // A content rule is decided on the payload, which this event does not
        // carry: the kernel classifier keys on port and protocol alone. Firing
        // here would alert on every packet to the port and make the pattern
        // decorative. The payload reaches the rule through
        // `evaluate_payload_with_context`, or `evaluate_packet` for a rule
        // imported from Suricata.
        if self.compiled_patterns.get(idx).is_some_and(Option::is_some)
            || self.inspections.get(idx).is_some_and(Option::is_some)
        {
            return None;
        }

        // If the rule has a domain pattern, check it against resolved domains
        if let Some(matcher) = self
            .compiled_domain_patterns
            .get(idx)
            .and_then(Option::as_ref)
        {
            // Domain-aware rule: must match at least one resolved domain.
            // No match means the rule does not apply at all.
            let domain = dst_domains.iter().find(|d| matcher.matches(d))?;
            return Some((idx, rule, Some(domain.clone())));
        }

        // No domain pattern - standard IP+port match
        Some((idx, rule, None))
    }

    /// Match the captured payload of a TCP segment against the content
    /// rules, returning every rule whose pattern matches, in rule order:
    /// as in Suricata, each matching rule raises its own alert.
    ///
    /// `event` is the header of the captured segment: its ports select the
    /// rules that apply, and its addresses feed the sampling decision. Payload
    /// capture is not sampled in the kernel, so random sampling selects here on
    /// the address pair at the configured rate rather than passing the segment.
    ///
    /// Only TCP carries a captured payload, so `udp` and `icmp` rules never
    /// match here even when they name a matching port.
    pub fn evaluate_payload_with_context(
        &self,
        event: &PacketEvent,
        payload: &[u8],
        src_country: Option<&str>,
    ) -> Vec<(usize, &IdsRule)> {
        if payload.is_empty() {
            return Vec::new();
        }
        if !self
            .sampling
            .should_process_with_country(event.src_ip(), event.dst_ip(), src_country)
        {
            return Vec::new();
        }

        let ports = [event.dst_port, event.src_port];
        let matched = self
            .prefilter()
            .candidates(&ports, payload)
            .into_iter()
            .filter_map(|idx| {
                let rule = self.rules.get(idx)?;
                let applies = rule.enabled
                    && match rule.imported.as_ref() {
                        // A rule imported from Suricata is decided on the
                        // packet, and on its connection's streams.
                        Some(imported) if imported.scope.is_some() => false,
                        imported => {
                            matches!(rule.protocol, Protocol::Tcp | Protocol::Any)
                                && (rule.dst_port == Some(event.dst_port)
                                    || rule.src_port == Some(event.src_port))
                                && imported.is_none_or(|i| i.addresses_match(event))
                        }
                    };
                if !applies {
                    return None;
                }
                let decided = match (self.inspections.get(idx)?, self.compiled_patterns.get(idx)?) {
                    (Some(program), _) => program.matches(payload),
                    (None, Some(pattern)) => pattern.is_match(payload),
                    (None, None) => false,
                };
                decided.then_some((idx, rule))
            })
            .collect();
        self.run_state(event, matched)
    }

    /// Evaluate the rules imported from Suricata against one whole IP
    /// packet, from its IP header on: protocol, addresses, ports, direction,
    /// every header keyword, then the payload and the header buffers.
    ///
    /// `event` is the packet's summary, which keys the sampling decision and
    /// the flow state; `bytes` is the packet from its IP header. A packet
    /// that does not decode matches nothing.
    ///
    /// A TCP connection whose SYN was seen keeps its two byte streams, as
    /// Suricata does: a rule Suricata reads on the stream is decided on the
    /// windows this packet has inspected, a rule it reads on the packet on
    /// the packet, and some rules on both, so one rule may alert twice. On
    /// a connection met midstream, or off TCP, every rule is read on the
    /// packet.
    pub fn evaluate_packet(
        &self,
        event: &PacketEvent,
        bytes: &[u8],
        src_country: Option<&str>,
    ) -> Vec<(usize, &IdsRule)> {
        let Some(packet) = IpPacket::decode(bytes) else {
            return Vec::new();
        };
        if !self
            .sampling
            .should_process_with_country(event.src_ip(), event.dst_ip(), src_country)
        {
            return Vec::new();
        }
        let ports = packet.ports();
        let keys: Vec<u16> = ports.map_or_else(Vec::new, |(s, d)| vec![d, s]);
        let payload = packet.payload().unwrap_or_default();
        let (tcp_flags, segment) = match packet.l4 {
            L4::Tcp(t) => (
                Some(t.flags),
                Some(Segment {
                    seq: t.seq,
                    ack: t.ack,
                    flags: t.flags,
                    data: t.payload,
                }),
            ),
            _ => (None, None),
        };
        let wire = Wire {
            tcp_flags,
            payload: packet.payload_len().unwrap_or(0) > 0,
            frame_len: u64::from(event.pkt_len),
            segment,
        };
        let (seen, blocks) = self
            .flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(&Packet::of(event), event, wire);
        let streamed = seen.stream_size.is_some();
        let mut matched: Vec<(usize, &IdsRule)> = self
            .prefilter()
            .candidates(&keys, payload)
            .into_iter()
            .filter_map(|idx| {
                let (rule, program) = self.imported(idx, event, ports, &seen)?;
                let on_packet = !streamed || program.inspect() != Inspect::Stream;
                (on_packet && program.matches_packet(&packet)).then_some((idx, rule))
            })
            .collect();
        for block in &blocks {
            matched.extend(self.stream_matches(event, ports, &seen, block));
        }
        self.run_state(event, matched)
    }

    /// Inspect what the flows idle past their timeout still hold, as
    /// Suricata does when it ends a flow, at most once a second of packet
    /// time. Each alert travels on the last packet the inspected side sent.
    pub fn flush_idle(&self, now_ns: u64) -> Vec<(PacketEvent, usize, &IdsRule)> {
        let ended = self
            .flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain_idle(now_ns);
        self.ended(ended)
    }

    /// Inspect what every flow still holds, as Suricata does when a capture
    /// ends.
    pub fn flush_all(&self) -> Vec<(PacketEvent, usize, &IdsRule)> {
        let ended = self
            .flows
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain_all();
        self.ended(ended)
    }

    fn ended(&self, ended: Vec<Ended>) -> Vec<(PacketEvent, usize, &IdsRule)> {
        let mut out = Vec::new();
        for end in ended {
            let ports = Some((end.event.src_port, end.event.dst_port));
            let mut matched = Vec::new();
            for block in &end.blocks {
                matched.extend(self.stream_matches(&end.event, ports, &end.seen, block));
            }
            out.extend(
                self.run_state(&end.event, matched)
                    .into_iter()
                    .map(|(idx, rule)| (end.event, idx, rule)),
            );
        }
        out
    }

    /// An enabled rule imported from Suricata whose header and session hold
    /// for the packet, with its program.
    fn imported(
        &self,
        idx: usize,
        event: &PacketEvent,
        ports: Option<(u16, u16)>,
        seen: &Seen,
    ) -> Option<(&IdsRule, &Program)> {
        let rule = self.rules.get(idx)?;
        let imported = rule.imported.as_ref().filter(|i| i.scope.is_some())?;
        if !rule.enabled || !imported.header_matches(event, ports) {
            return None;
        }
        let program = self.inspections.get(idx)?.as_ref()?;
        program
            .matches_session(seen)
            .then_some((rule, program.as_ref()))
    }

    /// The rules matching a window of the stream the packet's sender sent.
    fn stream_matches(
        &self,
        event: &PacketEvent,
        ports: Option<(u16, u16)>,
        seen: &Seen,
        block: &[u8],
    ) -> Vec<(usize, &IdsRule)> {
        let keys: Vec<u16> = ports.map_or_else(Vec::new, |(s, d)| vec![d, s]);
        self.prefilter()
            .candidates(&keys, block)
            .into_iter()
            .filter_map(|idx| {
                let (rule, program) = self.imported(idx, event, ports, seen)?;
                (program.inspect() != Inspect::Packet && program.matches_stream(block))
                    .then_some((idx, rule))
            })
            .collect()
    }

    /// The candidate index, built on first use from the rules' ports and
    /// fast patterns.
    fn prefilter(&self) -> &Prefilter {
        self.prefilter.get_or_init(|| {
            Arc::new(Prefilter::build(
                self.rules
                    .iter()
                    .zip(&self.inspections)
                    .map(|(rule, program)| Entry {
                        ports: match rule.imported.as_ref().and_then(|i| i.scope.as_ref()) {
                            Some(scope) => scope.index_ports(INDEXED_PORTS),
                            None => Some(rule.dst_port.into_iter().chain(rule.src_port).collect()),
                        },
                        needle: needle(program.as_ref()),
                    }),
            ))
        })
    }

    /// Run what the matched rules read and write outside the packet, in
    /// the order Suricata runs them, and keep the rules that alert.
    fn run_state<'a>(
        &self,
        event: &PacketEvent,
        mut matched: Vec<(usize, &'a IdsRule)>,
    ) -> Vec<(usize, &'a IdsRule)> {
        let state = |idx: usize| {
            self.inspections
                .get(idx)
                .and_then(Option::as_ref)
                .and_then(|program| program.state())
        };
        if matched.iter().all(|(idx, _)| state(*idx).is_none()) {
            return matched;
        }
        matched.sort_by_key(|(idx, _)| (state(*idx).map_or(3, super::flow::State::rank), *idx));
        let packet = Packet::of(event);
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.touch(&packet);
        matched.retain(|(idx, _)| state(*idx).is_none_or(|s| s.run(&mut flows, &packet, *idx)));
        drop(flows);
        matched.sort_by_key(|(idx, _)| *idx);
        matched
    }

    /// Check whether an alert for the matched rule should be emitted
    /// based on the rule's threshold configuration. Returns `true` if
    /// the alert should proceed, `false` if it should be suppressed.
    ///
    /// If the rule has no threshold config, always returns `true`.
    pub fn check_threshold(
        &self,
        rule_id: &RuleId,
        threshold: &super::entity::ThresholdConfig,
        src_ip: u32,
        dst_ip: u32,
    ) -> bool {
        let track_key = threshold.track_by.track_key(src_ip, dst_ip);
        let now = Instant::now();
        let window = std::time::Duration::from_secs(threshold.window_secs);

        let mut tracker = self
            .threshold_tracker
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        let state = tracker
            .entry((rule_id.clone(), track_key))
            .or_insert_with(|| ThresholdState {
                count: 0,
                window_start: now,
                alerted_in_window: false,
            });

        // Reset window if expired
        if now.duration_since(state.window_start) >= window {
            state.count = 0;
            state.window_start = now;
            state.alerted_in_window = false;
        }

        state.count += 1;

        match threshold.threshold_type {
            ThresholdType::Limit => {
                // Alert the first `count` times, then suppress
                state.count <= threshold.count
            }
            ThresholdType::Threshold => {
                // Alert every `count`-th occurrence
                state.count.is_multiple_of(threshold.count)
            }
            ThresholdType::Both => {
                // After `count` occurrences, alert once per window
                if state.count >= threshold.count && !state.alerted_in_window {
                    state.alerted_in_window = true;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Country-aware threshold check.
    ///
    /// When the rule has `country_thresholds` and `src_country` matches a
    /// key, that per-country [`ThresholdConfig`] is used instead of the
    /// default rule threshold.
    pub fn check_threshold_with_country(
        &self,
        rule: &IdsRule,
        src_ip: u32,
        dst_ip: u32,
        src_country: Option<&str>,
    ) -> bool {
        let Some(base_threshold) = &rule.threshold else {
            return true; // no threshold config → always alert
        };

        // Check for per-country override
        let country_threshold =
            src_country.and_then(|cc| rule.country_thresholds.as_ref().and_then(|ct| ct.get(cc)));

        let effective = country_threshold.unwrap_or(base_threshold);
        self.check_threshold(&rule.id, effective, src_ip, dst_ip)
    }

    /// Remove expired threshold entries to prevent unbounded memory growth.
    pub fn cleanup_expired_thresholds(&self) {
        let now = Instant::now();
        let rules = &self.rules;
        self.threshold_tracker
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(rule_id, _), state| {
                // Look up the rule to find its window; if the rule is gone, remove the entry
                let Some(rule) = rules.iter().find(|r| r.id == *rule_id) else {
                    return false;
                };
                let Some(ref threshold) = rule.threshold else {
                    return false;
                };
                let window = std::time::Duration::from_secs(threshold.window_secs);
                now.duration_since(state.window_start) < window
            });
    }
}

impl Default for IdsEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Maximum compiled regex size (10 MiB) to prevent regex denial-of-service.
const REGEX_SIZE_LIMIT: usize = 10 * (1 << 20);

/// Maximum regex nesting depth to prevent stack overflow.
const REGEX_NEST_LIMIT: u32 = 200;

/// Compile a content pattern into a byte regex. Empty patterns return
/// `None`. Invalid patterns return an error.
///
/// The payload it runs against is raw bytes off the wire, not text, so the
/// byte engine is the right one: it matches binary protocols and never has
/// to reject or lossily rewrite a segment that is not valid UTF-8.
///
/// Uses `RegexBuilder` with size and nesting limits to prevent
/// denial-of-service via malicious patterns.
pub(crate) fn compile_pattern(pattern: &str) -> Result<Option<BytesRegex>, DomainError> {
    if pattern.is_empty() {
        return Ok(None);
    }
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map(Some)
        .map_err(|e| DomainError::InvalidRule(format!("invalid regex pattern '{pattern}': {e}")))
}

/// The inspection program an imported rule carries.
fn inspection(rule: &IdsRule) -> Option<Arc<Program>> {
    rule.imported
        .as_ref()
        .and_then(|imported| imported.inspection.as_ref())
        .map(|inspection| Arc::clone(&inspection.0))
}

/// A rule's pattern compiled, unless an inspection program decides the rule
/// and the pattern only names it.
fn compile_rule_pattern(
    rule: &IdsRule,
    inspected: bool,
) -> Result<Option<BytesRegex>, DomainError> {
    if inspected {
        return Ok(None);
    }
    // An imported rule's pattern is written in Suricata's notation, not as an
    // expression: without its program there is nothing to decide it with.
    if rule.imported.is_some() && !rule.pattern.is_empty() {
        return Err(DomainError::InvalidRule(format!(
            "rule '{}' was imported without its compiled matches",
            rule.id.0
        )));
    }
    compile_pattern(&rule.pattern)
}

/// Compile a rule's domain pattern into a `CompiledDomainMatcher`.
/// Returns `None` if the rule has no domain pattern.
fn compile_domain_pattern(rule: &IdsRule) -> Result<Option<CompiledDomainMatcher>, DomainError> {
    let (Some(pattern), Some(mode)) = (&rule.domain_pattern, &rule.domain_match_mode) else {
        return Ok(None);
    };

    let matcher = match mode {
        DomainMatchMode::Exact => CompiledDomainMatcher::Exact(pattern.to_lowercase()),
        DomainMatchMode::Wildcard => {
            let dp = DomainPattern::parse(pattern).map_err(|e| {
                DomainError::InvalidRule(format!(
                    "invalid wildcard domain pattern '{pattern}': {e}"
                ))
            })?;
            CompiledDomainMatcher::Wildcard(dp)
        }
        DomainMatchMode::Regex => {
            let re = regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .nest_limit(REGEX_NEST_LIMIT)
                .build()
                .map_err(|e| {
                    DomainError::InvalidRule(format!(
                        "invalid domain regex pattern '{pattern}': {e}"
                    ))
                })?;
            CompiledDomainMatcher::Regex(re)
        }
    };

    Ok(Some(matcher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::{DomainMode, Protocol, RuleId, Severity};
    use crate::ids::entity::{IdsRule, SamplingMode};
    use ebpf_common::event::EVENT_TYPE_IDS;

    fn rule(id: &str) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: format!("Test rule {id}"),
            severity: Severity::Medium,
            mode: DomainMode::Alert,
            protocol: Protocol::Tcp,
            dst_port: Some(22),
            src_port: None,
            pattern: String::new(),
            enabled: true,
            threshold: None,
            country_thresholds: None,
            domain_pattern: None,
            domain_match_mode: None,
            group_mask: 0,
            tenant_id: 0,
            workload: None,
            kill_process: false,
            imported: None,
        }
    }

    fn rule_with_pattern(id: &str, pattern: &str) -> IdsRule {
        IdsRule {
            pattern: pattern.to_string(),
            ..rule(id)
        }
    }

    // ── new / default ────────────────────────────────────────────

    #[test]
    fn new_engine_is_empty() {
        let engine = IdsEngine::new();
        assert_eq!(engine.rule_count(), 0);
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn default_is_same_as_new() {
        let engine = IdsEngine::default();
        assert_eq!(engine.rule_count(), 0);
    }

    // ── add_rule ─────────────────────────────────────────────────

    #[test]
    fn add_rule_succeeds() {
        let mut engine = IdsEngine::new();
        assert!(engine.add_rule(rule("ids-001")).is_ok());
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.rules()[0].id.0, "ids-001");
    }

    #[test]
    fn add_rule_with_pattern_compiles_regex() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", r"GET\s+/admin"))
            .unwrap();
        assert!(engine.compiled_pattern(0).is_some());
    }

    #[test]
    fn add_rule_empty_pattern_no_compiled() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        assert!(engine.compiled_pattern(0).is_none());
    }

    #[test]
    fn add_rule_invalid_regex_rejected() {
        let mut engine = IdsEngine::new();
        let result = engine.add_rule(rule_with_pattern("ids-001", r"[invalid"));
        assert!(result.is_err());
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn add_duplicate_rule_fails() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        assert!(engine.add_rule(rule("ids-001")).is_err());
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn add_rule_invalid_id_rejected() {
        let mut engine = IdsEngine::new();
        let mut r = rule("ids-001");
        r.id = RuleId(String::new());
        assert!(engine.add_rule(r).is_err());
    }

    // ── remove_rule ──────────────────────────────────────────────

    #[test]
    fn remove_rule_succeeds() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine.add_rule(rule("ids-002")).unwrap();
        engine.remove_rule(&RuleId("ids-001".to_string())).unwrap();
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.rules()[0].id.0, "ids-002");
    }

    #[test]
    fn remove_nonexistent_rule_fails() {
        let mut engine = IdsEngine::new();
        assert!(engine.remove_rule(&RuleId("nope".to_string())).is_err());
    }

    #[test]
    fn remove_cleans_compiled_pattern() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", r"foo"))
            .unwrap();
        engine.add_rule(rule("ids-002")).unwrap();
        assert!(engine.compiled_pattern(0).is_some());
        engine.remove_rule(&RuleId("ids-001".to_string())).unwrap();
        // ids-002 is now at index 0, has no pattern
        assert!(engine.compiled_pattern(0).is_none());
    }

    // ── reload ───────────────────────────────────────────────────

    #[test]
    fn reload_replaces_all_rules() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine
            .reload(vec![rule("ids-010"), rule("ids-020")])
            .unwrap();
        assert_eq!(engine.rule_count(), 2);
        assert_eq!(engine.rules()[0].id.0, "ids-010");
        assert_eq!(engine.rules()[1].id.0, "ids-020");
    }

    #[test]
    fn reload_empty_clears_all() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine.reload(vec![]).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = IdsEngine::new();
        let result = engine.reload(vec![rule("ids-001"), rule("ids-001")]);
        assert!(result.is_err());
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn reload_rejects_invalid_pattern() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-old")).unwrap();
        let result = engine.reload(vec![rule_with_pattern("ids-001", r"[bad")]);
        assert!(result.is_err());
        // Original rules preserved on failure
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.rules()[0].id.0, "ids-old");
    }

    #[test]
    fn reload_validates_all_rules() {
        let mut engine = IdsEngine::new();
        let mut bad = rule("ids-001");
        bad.id = RuleId(String::new());
        assert!(engine.reload(vec![bad]).is_err());
    }

    #[test]
    fn reload_compiles_all_patterns() {
        let mut engine = IdsEngine::new();
        engine
            .reload(vec![
                rule_with_pattern("ids-001", r"GET /admin"),
                rule("ids-002"),
                rule_with_pattern("ids-003", r"\d{4}-\d{4}"),
            ])
            .unwrap();
        assert!(engine.compiled_pattern(0).is_some());
        assert!(engine.compiled_pattern(1).is_none());
        assert!(engine.compiled_pattern(2).is_some());
    }

    // ── compiled_pattern ─────────────────────────────────────────

    #[test]
    fn compiled_pattern_out_of_bounds() {
        let engine = IdsEngine::new();
        assert!(engine.compiled_pattern(0).is_none());
    }

    #[test]
    fn compiled_pattern_matches() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", r"^SSH-2\.0"))
            .unwrap();
        let re = engine.compiled_pattern(0).unwrap();
        assert!(re.is_match(b"SSH-2.0-OpenSSH_8.9"));
        assert!(!re.is_match(b"HTTP/1.1 200 OK"));
    }

    // ── content rules ─────────────────────────────────────────────

    #[test]
    fn an_engine_without_a_pattern_has_no_content_rule() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        assert!(!engine.has_content_rules());
        assert!(engine.content_ports().is_empty());
    }

    #[test]
    fn content_ports_cover_both_legs_a_rule_names() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(IdsRule {
                src_port: Some(2222),
                ..rule_with_pattern("ids-001", "root")
            })
            .unwrap();
        engine.add_rule(rule("ids-002")).unwrap();
        assert!(engine.has_content_rules());
        // 22 from the destination leg, 2222 from the source leg; the
        // patternless rule contributes nothing.
        assert_eq!(engine.content_ports(), vec![22, 2222]);
    }

    #[test]
    fn a_disabled_content_rule_asks_for_no_capture() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(IdsRule {
                enabled: false,
                ..rule_with_pattern("ids-001", "root")
            })
            .unwrap();
        assert!(engine.content_ports().is_empty());
    }

    #[test]
    fn a_content_rule_does_not_fire_on_the_port_alone() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", "GET /admin"))
            .unwrap();
        assert!(engine.evaluate_event(&make_event(0)).is_none());
    }

    #[test]
    fn a_content_rule_fires_on_the_payload_it_names() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", "GET /admin"))
            .unwrap();
        let (idx, matched) = engine
            .evaluate_payload_with_context(&make_event(0), b"GET /admin HTTP/1.1\r\n", None)
            .first()
            .copied()
            .unwrap();
        assert_eq!(idx, 0);
        assert_eq!(matched.id.0, "ids-001");
    }

    #[test]
    fn a_content_rule_ignores_a_payload_it_does_not_name() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", "GET /admin"))
            .unwrap();
        assert!(
            engine
                .evaluate_payload_with_context(&make_event(0), b"GET / HTTP/1.1\r\n", None)
                .is_empty()
        );
    }

    #[test]
    fn a_content_rule_matches_a_payload_that_is_not_text() {
        let mut engine = IdsEngine::new();
        engine
            // `(?-u)` drops Unicode mode, so `\x90` is the raw byte rather
            // than the two bytes that encode U+0090.
            .add_rule(rule_with_pattern("ids-001", r"(?-u)\x90{4}"))
            .unwrap();
        assert!(
            !engine
                .evaluate_payload_with_context(&make_event(0), &[0x90, 0x90, 0x90, 0x90], None)
                .is_empty()
        );
    }

    #[test]
    fn every_content_rule_a_payload_matches_is_returned() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", "GET /admin"))
            .unwrap();
        engine
            .add_rule(rule_with_pattern("ids-002", "HTTP/1"))
            .unwrap();
        engine
            .add_rule(rule_with_pattern("ids-003", "POST"))
            .unwrap();
        let matched: Vec<&str> = engine
            .evaluate_payload_with_context(&make_event(0), b"GET /admin HTTP/1.1\r\n", None)
            .into_iter()
            .map(|(_, rule)| rule.id.0.as_str())
            .collect();
        assert_eq!(matched, ["ids-001", "ids-002"]);
    }

    #[test]
    fn a_content_rule_stays_on_the_ports_it_names() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_pattern("ids-001", "GET /admin"))
            .unwrap();
        let other_port = PacketEvent {
            dst_port: 80,
            ..make_event(0)
        };
        assert!(
            engine
                .evaluate_payload_with_context(&other_port, b"GET /admin HTTP/1.1\r\n", None)
                .is_empty()
        );
    }

    #[test]
    fn a_udp_rule_never_matches_a_captured_payload() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(IdsRule {
                protocol: Protocol::Udp,
                ..rule_with_pattern("ids-001", "GET /admin")
            })
            .unwrap();
        assert!(
            engine
                .evaluate_payload_with_context(&make_event(0), b"GET /admin HTTP/1.1\r\n", None)
                .is_empty()
        );
    }

    // ── evaluate_event ────────────────────────────────────────────

    fn make_event(rule_id: u32) -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [0, 0, 0, 0],
            dst_addr: [0, 0, 0, 0],
            src_port: 0,
            dst_port: 22,
            protocol: 6,
            event_type: EVENT_TYPE_IDS,
            action: 0,
            flags: 0,
            rule_id,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
            cgroup_id: 0,
            cgroup1_id: 0,
            rss_hash: 0,
            rss_hash_type: 0,
            rx_hw_timestamp_ns: 0,
            pkt_len: 0,
            _pad: 0,
        }
    }

    #[test]
    fn evaluate_event_returns_matching_rule() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine.add_rule(rule("ids-002")).unwrap();

        let event = make_event(1); // index 1 → ids-002
        let (idx, matched) = engine.evaluate_event(&event).unwrap();
        assert_eq!(idx, 1);
        assert_eq!(matched.id.0, "ids-002");
    }

    #[test]
    fn evaluate_event_out_of_range_returns_none() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();

        let event = make_event(99);
        assert!(engine.evaluate_event(&event).is_none());
    }

    #[test]
    fn evaluate_event_disabled_rule_returns_none() {
        let mut engine = IdsEngine::new();
        let mut r = rule("ids-001");
        r.enabled = false;
        engine.add_rule(r).unwrap();

        let event = make_event(0);
        assert!(engine.evaluate_event(&event).is_none());
    }

    #[test]
    fn evaluate_event_empty_engine_returns_none() {
        let engine = IdsEngine::new();
        let event = make_event(0);
        assert!(engine.evaluate_event(&event).is_none());
    }

    // ── sampling ───────────────────────────────────────────────────

    #[test]
    fn sampling_default_is_none() {
        let engine = IdsEngine::new();
        assert_eq!(*engine.sampling(), SamplingMode::None);
    }

    #[test]
    fn set_sampling_updates() {
        let mut engine = IdsEngine::new();
        engine.set_sampling(SamplingMode::Hash { rate: 0.5 });
        assert_eq!(*engine.sampling(), SamplingMode::Hash { rate: 0.5 });
    }

    #[test]
    fn evaluate_event_with_sampling_none_passes() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine.set_sampling(SamplingMode::None);

        let event = make_event(0);
        assert!(engine.evaluate_event(&event).is_some());
    }

    #[test]
    fn evaluate_event_with_zero_rate_all_sampled_out() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine.set_sampling(SamplingMode::Hash { rate: 0.0 });

        let event = make_event(0);
        assert!(engine.evaluate_event(&event).is_none());
    }

    #[test]
    fn evaluate_event_with_full_rate_all_pass() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        engine.set_sampling(SamplingMode::Hash { rate: 1.0 });

        let event = make_event(0);
        assert!(engine.evaluate_event(&event).is_some());
    }

    // ── threshold detection ─────────────────────────────────────────

    use crate::ids::entity::{ThresholdConfig, ThresholdType, TrackBy};

    fn threshold_limit(count: u32, window_secs: u64) -> ThresholdConfig {
        ThresholdConfig {
            threshold_type: ThresholdType::Limit,
            count,
            window_secs,
            track_by: TrackBy::SrcIp,
        }
    }

    fn threshold_every(count: u32, window_secs: u64) -> ThresholdConfig {
        ThresholdConfig {
            threshold_type: ThresholdType::Threshold,
            count,
            window_secs,
            track_by: TrackBy::SrcIp,
        }
    }

    fn threshold_both(count: u32, window_secs: u64) -> ThresholdConfig {
        ThresholdConfig {
            threshold_type: ThresholdType::Both,
            count,
            window_secs,
            track_by: TrackBy::SrcIp,
        }
    }

    #[test]
    fn threshold_limit_alerts_first_n() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = threshold_limit(3, 60);

        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // 1
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // 2
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // 3
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 4 → suppressed
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 5 → suppressed
    }

    #[test]
    fn threshold_every_alerts_at_multiples() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = threshold_every(3, 60);

        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 1
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 2
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // 3 → alert
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 4
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 5
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // 6 → alert
    }

    #[test]
    fn threshold_both_alerts_once_after_count() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = threshold_both(3, 60);

        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 1
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 2
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // 3 → alert (once)
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 4 → no more
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // 5 → no more
    }

    #[test]
    fn threshold_window_expiry_resets() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        // Use 1ms window so it expires immediately
        let thresh = threshold_limit(2, 0);

        // With window_secs=0, every check resets because Duration::from_secs(0) is always elapsed.
        // So we only get up to `count` alerts per "window" which resets every time.
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // resets, count=1 → ok
    }

    #[test]
    fn threshold_different_track_keys_independent() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = threshold_limit(2, 60);

        // src_ip=1 (TrackBy::SrcIp → key is src_ip)
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 10)); // key=1, count=1
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 10)); // key=1, count=2

        // src_ip=2 → different track key, separate counter
        assert!(engine.check_threshold(&rule_id, &thresh, 2, 10)); // key=2, count=1
        assert!(engine.check_threshold(&rule_id, &thresh, 2, 10)); // key=2, count=2

        // src_ip=1 → exceeded
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 10)); // key=1, count=3 → suppressed
    }

    #[test]
    fn threshold_track_by_dst_ip() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = ThresholdConfig {
            threshold_type: ThresholdType::Limit,
            count: 1,
            window_secs: 60,
            track_by: TrackBy::DstIp,
        };

        assert!(engine.check_threshold(&rule_id, &thresh, 100, 200)); // dst=200, count=1
        assert!(!engine.check_threshold(&rule_id, &thresh, 100, 200)); // dst=200, count=2 → suppressed
        assert!(engine.check_threshold(&rule_id, &thresh, 100, 201)); // dst=201 → new key
    }

    #[test]
    fn threshold_track_by_both() {
        let engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = ThresholdConfig {
            threshold_type: ThresholdType::Limit,
            count: 1,
            window_secs: 60,
            track_by: TrackBy::Both,
        };

        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // (1,2) count=1
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // (1,2) count=2 → suppressed
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 3)); // (1,3) → new key
        assert!(engine.check_threshold(&rule_id, &thresh, 2, 2)); // (2,2) → new key
    }

    #[test]
    fn reload_clears_threshold_state() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();
        let rule_id = RuleId("ids-001".to_string());
        let thresh = threshold_limit(1, 60);

        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // count=1 → alert
        assert!(!engine.check_threshold(&rule_id, &thresh, 1, 2)); // count=2 → suppressed

        engine.reload(vec![rule("ids-001")]).unwrap();

        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // reset → count=1 → alert
    }

    // ── regex DoS prevention ──────────────────────────────────────

    #[test]
    fn deeply_nested_regex_rejected() {
        let mut engine = IdsEngine::new();
        // Pattern with deep nesting beyond the nest_limit
        let deep = "(".repeat(300) + &")".repeat(300);
        let result = engine.add_rule(rule_with_pattern("ids-redos", &deep));
        assert!(result.is_err());
    }

    // ── domain-aware evaluation ──────────────────────────────────

    fn rule_with_domain(id: &str, pattern: &str, mode: DomainMatchMode) -> IdsRule {
        IdsRule {
            domain_pattern: Some(pattern.to_string()),
            domain_match_mode: Some(mode),
            ..rule(id)
        }
    }

    #[test]
    fn exact_domain_matches() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        let event = make_event(0);
        let domains = vec!["evil.com".to_string()];
        let result = engine.evaluate_event_with_context(&event, &domains, None);
        assert!(result.is_some());
        let (idx, r, matched) = result.unwrap();
        assert_eq!(idx, 0);
        assert_eq!(r.id.0, "ids-dom-1");
        assert_eq!(matched.unwrap(), "evil.com");
    }

    #[test]
    fn exact_domain_case_insensitive() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "Evil.COM",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        let event = make_event(0);
        let domains = vec!["evil.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &domains, None)
                .is_some()
        );
    }

    #[test]
    fn exact_domain_no_match() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        let event = make_event(0);
        let domains = vec!["good.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &domains, None)
                .is_none()
        );
    }

    #[test]
    fn wildcard_domain_matches_subdomain() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "*.evil.com",
                DomainMatchMode::Wildcard,
            ))
            .unwrap();

        let event = make_event(0);
        let domains = vec!["malware.evil.com".to_string()];
        let result = engine.evaluate_event_with_context(&event, &domains, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().2.unwrap(), "malware.evil.com");
    }

    #[test]
    fn wildcard_domain_does_not_match_base() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "*.evil.com",
                DomainMatchMode::Wildcard,
            ))
            .unwrap();

        let event = make_event(0);
        // Base domain itself does not match wildcard
        let domains = vec!["evil.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &domains, None)
                .is_none()
        );
    }

    #[test]
    fn regex_domain_matches() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                r"^c2-\d+\.evil\.com$",
                DomainMatchMode::Regex,
            ))
            .unwrap();

        let event = make_event(0);
        let domains = vec!["c2-42.evil.com".to_string()];
        let result = engine.evaluate_event_with_context(&event, &domains, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().2.unwrap(), "c2-42.evil.com");
    }

    #[test]
    fn regex_domain_no_match() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                r"^c2-\d+\.evil\.com$",
                DomainMatchMode::Regex,
            ))
            .unwrap();

        let event = make_event(0);
        let domains = vec!["legit.evil.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &domains, None)
                .is_none()
        );
    }

    #[test]
    fn domain_rule_with_port_requires_both() {
        let mut engine = IdsEngine::new();
        // Rule has dst_port=22 AND domain_pattern
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        // Event matches rule index 0 (port matched in eBPF), domain also matches
        let event = make_event(0);
        let domains = vec!["evil.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &domains, None)
                .is_some()
        );

        // Port matched but domain doesn't → no match
        let bad_domains = vec!["good.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &bad_domains, None)
                .is_none()
        );
    }

    #[test]
    fn rule_without_domain_works_as_before() {
        let mut engine = IdsEngine::new();
        engine.add_rule(rule("ids-001")).unwrap();

        let event = make_event(0);
        // Even with domain context, non-domain rules match without checking domains
        let domains = vec!["anything.com".to_string()];
        let result = engine.evaluate_event_with_context(&event, &domains, None);
        assert!(result.is_some());
        let (_, _, matched_domain) = result.unwrap();
        assert!(matched_domain.is_none());
    }

    #[test]
    fn domain_rule_empty_domain_list_no_match() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        let event = make_event(0);
        // No resolved domains → domain-only rule cannot match
        assert!(
            engine
                .evaluate_event_with_context(&event, &[], None)
                .is_none()
        );
    }

    #[test]
    fn invalid_domain_regex_rejected() {
        let mut engine = IdsEngine::new();
        let result = engine.add_rule(rule_with_domain(
            "ids-dom-1",
            "[invalid",
            DomainMatchMode::Regex,
        ));
        assert!(result.is_err());
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn domain_pattern_compiled_on_reload() {
        let mut engine = IdsEngine::new();
        engine
            .reload(vec![rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            )])
            .unwrap();

        let event = make_event(0);
        let domains = vec!["evil.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &domains, None)
                .is_some()
        );
    }

    #[test]
    fn domain_pattern_removed_on_remove_rule() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();
        engine.add_rule(rule("ids-002")).unwrap();

        engine
            .remove_rule(&RuleId("ids-dom-1".to_string()))
            .unwrap();
        // ids-002 is now at index 0, has no domain pattern
        let event = make_event(0);
        let result = engine.evaluate_event_with_context(&event, &["evil.com".to_string()], None);
        assert!(result.is_some());
        assert!(result.unwrap().2.is_none()); // No matched domain
    }

    #[test]
    fn domain_matches_any_in_list() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        let event = make_event(0);
        // Multiple domains resolved for the same IP - one matches
        let domains = vec![
            "good.com".to_string(),
            "evil.com".to_string(),
            "other.com".to_string(),
        ];
        let result = engine.evaluate_event_with_context(&event, &domains, None);
        assert!(result.is_some());
        assert_eq!(result.unwrap().2.unwrap(), "evil.com");
    }

    #[test]
    fn backward_compat_evaluate_event_ignores_domain_rules() {
        let mut engine = IdsEngine::new();
        engine
            .add_rule(rule_with_domain(
                "ids-dom-1",
                "evil.com",
                DomainMatchMode::Exact,
            ))
            .unwrap();

        let event = make_event(0);
        // Old evaluate_event passes empty domains → domain rule doesn't match
        assert!(engine.evaluate_event(&event).is_none());
    }
}
