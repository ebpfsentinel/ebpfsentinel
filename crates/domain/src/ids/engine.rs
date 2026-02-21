use std::collections::HashMap;
use std::time::Instant;

use regex::Regex;

use crate::common::entity::RuleId;
use crate::common::error::DomainError;
use ebpf_common::event::PacketEvent;

use super::entity::{DomainMatchMode, IdsRule, SamplingMode, ThresholdType};
use super::error::IdsError;
use crate::dns::entity::DomainPattern;

/// Internal state for per-rule, per-track-key threshold tracking.
#[derive(Debug)]
struct ThresholdState {
    count: u32,
    window_start: Instant,
    alerted_in_window: bool,
}

/// A pre-compiled domain matcher for a single IDS rule.
/// Compiled once at rule load time, used per-packet in userspace.
#[derive(Debug)]
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
#[derive(Debug)]
pub struct IdsEngine {
    rules: Vec<IdsRule>,
    compiled_patterns: Vec<Option<Regex>>,
    compiled_domain_patterns: Vec<Option<CompiledDomainMatcher>>,
    sampling: SamplingMode,
    threshold_tracker: HashMap<(RuleId, u64), ThresholdState>,
}

impl IdsEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            compiled_patterns: Vec::new(),
            compiled_domain_patterns: Vec::new(),
            sampling: SamplingMode::default(),
            threshold_tracker: HashMap::new(),
        }
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

        let compiled = compile_pattern(&rule.pattern)?;
        let domain_compiled = compile_domain_pattern(&rule)?;
        self.rules.push(rule);
        self.compiled_patterns.push(compiled);
        self.compiled_domain_patterns.push(domain_compiled);
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
        for (i, rule) in rules.iter().enumerate() {
            if rules[i + 1..].iter().any(|r| r.id == rule.id) {
                return Err(IdsError::DuplicateRule {
                    id: rule.id.0.clone(),
                }
                .into());
            }
        }

        // Compile all patterns
        let mut compiled = Vec::with_capacity(rules.len());
        let mut domain_compiled = Vec::with_capacity(rules.len());
        for rule in &rules {
            compiled.push(compile_pattern(&rule.pattern)?);
            domain_compiled.push(compile_domain_pattern(rule)?);
        }

        // Atomic replace
        self.rules = rules;
        self.compiled_patterns = compiled;
        self.compiled_domain_patterns = domain_compiled;
        self.threshold_tracker.clear();
        Ok(())
    }

    /// Read-only access to the loaded rules.
    pub fn rules(&self) -> &[IdsRule] {
        &self.rules
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Access the compiled pattern for a rule at the given index.
    pub fn compiled_pattern(&self, index: usize) -> Option<&Regex> {
        self.compiled_patterns.get(index).and_then(Option::as_ref)
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
        self.evaluate_event_with_context(event, &[])
            .map(|(idx, rule, _matched_domain)| (idx, rule))
    }

    /// Evaluate an event with optional domain context.
    ///
    /// `dst_domains` contains the domains resolved for the destination IP
    /// (from the DNS cache reverse lookup). If a rule has a `domain_pattern`,
    /// at least one domain in the list must match. If `dst_domains` is empty,
    /// rules with `domain_pattern` will not match.
    ///
    /// Returns `(rule_index, rule, matched_domain)` on match.
    pub fn evaluate_event_with_context<'a>(
        &'a self,
        event: &PacketEvent,
        dst_domains: &[String],
    ) -> Option<(usize, &'a IdsRule, Option<String>)> {
        if !self.sampling.should_process(event.src_ip(), event.dst_ip()) {
            return None;
        }
        let idx = event.rule_id as usize;
        let rule = self.rules.get(idx)?;
        if !rule.enabled {
            return None;
        }

        // If the rule has a domain pattern, check it against resolved domains
        if let Some(matcher) = self
            .compiled_domain_patterns
            .get(idx)
            .and_then(Option::as_ref)
        {
            // Domain-aware rule: must match at least one resolved domain
            let matched = dst_domains.iter().find(|d| matcher.matches(d));
            match matched {
                Some(domain) => return Some((idx, rule, Some(domain.clone()))),
                None => return None, // Domain pattern set but no match
            }
        }

        // No domain pattern — standard IP+port match
        Some((idx, rule, None))
    }

    /// Check whether an alert for the matched rule should be emitted
    /// based on the rule's threshold configuration. Returns `true` if
    /// the alert should proceed, `false` if it should be suppressed.
    ///
    /// If the rule has no threshold config, always returns `true`.
    pub fn check_threshold(
        &mut self,
        rule_id: &RuleId,
        threshold: &super::entity::ThresholdConfig,
        src_ip: u32,
        dst_ip: u32,
    ) -> bool {
        let track_key = threshold.track_by.track_key(src_ip, dst_ip);
        let now = Instant::now();
        let window = std::time::Duration::from_secs(threshold.window_secs);

        let state = self
            .threshold_tracker
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

    /// Remove expired threshold entries to prevent unbounded memory growth.
    pub fn cleanup_expired_thresholds(&mut self) {
        let now = Instant::now();
        self.threshold_tracker.retain(|(rule_id, _), state| {
            // Look up the rule to find its window; if the rule is gone, remove the entry
            let Some(rule) = self.rules.iter().find(|r| r.id == *rule_id) else {
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

/// Compile a pattern string to a `Regex`. Empty patterns return `None`.
/// Invalid patterns return an error.
///
/// Uses `RegexBuilder` with size and nesting limits to prevent
/// denial-of-service via malicious patterns.
fn compile_pattern(pattern: &str) -> Result<Option<Regex>, DomainError> {
    if pattern.is_empty() {
        return Ok(None);
    }
    regex::RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .nest_limit(REGEX_NEST_LIMIT)
        .build()
        .map(Some)
        .map_err(|e| DomainError::InvalidRule(format!("invalid regex pattern '{pattern}': {e}")))
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
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
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
        assert!(re.is_match("SSH-2.0-OpenSSH_8.9"));
        assert!(!re.is_match("HTTP/1.1 200 OK"));
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
        let mut engine = IdsEngine::new();
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
        let mut engine = IdsEngine::new();
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
        let mut engine = IdsEngine::new();
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
        let mut engine = IdsEngine::new();
        let rule_id = RuleId("ids-001".to_string());
        // Use 1ms window so it expires immediately
        let thresh = threshold_limit(2, 0);

        // With window_secs=0, every check resets because Duration::from_secs(0) is always elapsed.
        // So we only get up to `count` alerts per "window" which resets every time.
        assert!(engine.check_threshold(&rule_id, &thresh, 1, 2)); // resets, count=1 → ok
    }

    #[test]
    fn threshold_different_track_keys_independent() {
        let mut engine = IdsEngine::new();
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
        let mut engine = IdsEngine::new();
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
        let mut engine = IdsEngine::new();
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
        let result = engine.evaluate_event_with_context(&event, &domains);
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
                .evaluate_event_with_context(&event, &domains)
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
                .evaluate_event_with_context(&event, &domains)
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
        let result = engine.evaluate_event_with_context(&event, &domains);
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
                .evaluate_event_with_context(&event, &domains)
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
        let result = engine.evaluate_event_with_context(&event, &domains);
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
                .evaluate_event_with_context(&event, &domains)
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
                .evaluate_event_with_context(&event, &domains)
                .is_some()
        );

        // Port matched but domain doesn't → no match
        let bad_domains = vec!["good.com".to_string()];
        assert!(
            engine
                .evaluate_event_with_context(&event, &bad_domains)
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
        let result = engine.evaluate_event_with_context(&event, &domains);
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
        assert!(engine.evaluate_event_with_context(&event, &[]).is_none());
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
                .evaluate_event_with_context(&event, &domains)
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
        let result = engine.evaluate_event_with_context(&event, &["evil.com".to_string()]);
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
        // Multiple domains resolved for the same IP — one matches
        let domains = vec![
            "good.com".to_string(),
            "evil.com".to_string(),
            "other.com".to_string(),
        ];
        let result = engine.evaluate_event_with_context(&event, &domains);
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
