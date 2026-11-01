//! A host rule: one intention, a map of matchers, and what to do.
//!
//! There is no expression language. `when` names one intention, or lists
//! several alternatives under one `any_of`, and each intention takes a map
//! of matchers: a key is a field, optionally followed by a matcher suffix,
//! and a list of values is "any of these". Keys must all hold, one value of a list must,
//! and that is the whole of the grammar: no parenthesis, no operator, no
//! function, so there is no parser to write, none to fuzz and no precedence
//! to document.
//!
//! Every check that can be made when the rule is loaded is made then,
//! against the typed field registry: a field the intention does not carry,
//! a value of the wrong type, a numeric comparison on text, two fields of
//! different types compared with each other. A rule that loads is a rule
//! whose every matcher can be true for some event.
//!
//! A field the event does not carry is a mismatch for every matcher,
//! `_not_in` included: a rule asks about a value, and a value nobody could
//! read is not one of the values it lists any more than it is one it
//! excludes. The workload selector reads absence the same way.

use std::collections::BTreeMap;
use std::net::IpAddr;

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::alert::filter::parse_severity;
use crate::common::entity::Severity;
use crate::firewall::workload::{WorkloadFacts, WorkloadSelector};

use super::count::{Count, CountPer, compile_count};
use super::error::HostRuleError;
use super::event::IntentEvent;
use super::field::{FieldSpec, FieldType, FieldValue, RESERVED_KEYS};
use super::intent::Intent;

/// Component every host rule alert carries.
pub const HOST_RULE_COMPONENT: &str = "host_rule";

/// The one key of `when` that is not an intention.
pub const ANY_OF: &str = "any_of";

/// Longest identifier a rule may carry.
pub const HOST_RULE_ID_MAX_LEN: usize = 128;

/// Longest value, glob or text, one matcher may carry.
pub const HOST_RULE_VALUE_MAX_LEN: usize = 4096;

/// Most values one list may carry.
pub const HOST_RULE_LIST_MAX: usize = 256;

/// The matcher suffixes this build evaluates, longest first among those
/// sharing an ending, so `_not_in` is found before `_in`.
const SUFFIXES: [(&str, Op); 8] = [
    ("_not_in", Op::NotIn),
    ("_eq_field", Op::EqField),
    ("_ne_field", Op::NeField),
    ("_matches", Op::Matches),
    ("_regex", Op::Regex),
    ("_in", Op::In),
    ("_gt", Op::Gt),
    ("_lt", Op::Lt),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    In,
    NotIn,
    Matches,
    Regex,
    Gt,
    Lt,
    EqField,
    NeField,
}

/// A value as a rule file writes it, before it is checked against the
/// field it is given to.
///
/// It is shaped like the configuration file rather than like the rule, so
/// that a misplaced map or list reaches the check that names the mistake,
/// instead of failing in the deserialiser with a message about variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RawValue {
    Boolean(bool),
    Integer(i64),
    Text(String),
    List(Vec<RawValue>),
    Map(BTreeMap<String, RawValue>),
}

impl RawValue {
    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Boolean(_) => "a boolean",
            Self::Integer(_) => "an integer",
            Self::Text(_) => "text",
            Self::List(_) => "a list",
            Self::Map(_) => "a map",
        }
    }
}

/// What a rule does when it matches.
///
/// The words are the response vocabulary the agent already uses: `alert`
/// raises the alert every rule raises anyway and is the default, and
/// `kill_process` stops the process behind the event through the same kill
/// the process detections and an IPS rule ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRuleAction {
    Alert,
    KillProcess,
}

impl HostRuleAction {
    /// The word the configuration and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::KillProcess => "kill_process",
        }
    }
}

fn default_severity() -> String {
    "medium".to_string()
}

fn default_then() -> Vec<HostRuleAction> {
    vec![HostRuleAction::Alert]
}

/// A host rule as it is written in the configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRuleSpec {
    /// Identifier, unique among the rules, carried by every alert.
    pub id: String,
    /// One line saying what the rule catches, carried by the alert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `low`, `medium`, `high` or `critical`.
    #[serde(default = "default_severity")]
    pub severity: String,
    /// The workload the rule is about, the selector the firewall's workload
    /// rules use, beside the intention rather than inside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadSelector>,
    /// The intention and its matchers.
    pub when: BTreeMap<String, RawValue>,
    /// A second step, the window it must arrive in as `within`, and nothing
    /// else: about the process `when` matched, or one started below it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub followed_by: Option<BTreeMap<String, RawValue>>,
    /// What to do when it matches.
    #[serde(default = "default_then")]
    pub then: Vec<HostRuleAction>,
}

/// A shell-style pattern: `*` is any run of characters, `?` is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glob {
    pattern: Vec<char>,
}

impl Glob {
    #[must_use]
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.chars().collect(),
        }
    }

    /// Whether `text` matches, in time bounded by the product of the two
    /// lengths: one star is remembered, so a later star never backtracks
    /// into an earlier one. Nothing is allocated: `t` is a byte offset
    /// into `text`, always on a character boundary.
    #[must_use]
    pub fn matches(&self, text: &str) -> bool {
        let (mut p, mut t) = (0, 0);
        let mut star: Option<(usize, usize)> = None;
        while let Some(ch) = text[t..].chars().next() {
            match self.pattern.get(p) {
                Some('*') => {
                    star = Some((p, t));
                    p += 1;
                }
                Some(&c) if c == '?' || c == ch => {
                    p += 1;
                    t += ch.len_utf8();
                }
                _ => match star {
                    Some((sp, st)) => {
                        let skipped = text[st..].chars().next().map_or(1, char::len_utf8);
                        p = sp + 1;
                        t = st + skipped;
                        star = Some((sp, t));
                    }
                    None => return false,
                },
            }
        }
        self.pattern[p..].iter().all(|&c| c == '*')
    }
}

/// The most a regular expression may compile to, in bytes; a pattern
/// above it is refused at load.
pub const HOST_RULE_REGEX_SIZE_LIMIT: usize = 512 * 1024;

/// The most the lazy DFA of one regular expression may cache, in bytes. A
/// pattern whose search needs more is not refused: the engine falls back to
/// a slower search of the same linear bound, so this caps memory rather
/// than the patterns that load.
pub const HOST_RULE_REGEX_DFA_LIMIT: usize = 512 * 1024;

/// A regular expression in the `regex` crate's syntax: linear in the text
/// by construction, with no backtracking, no lookaround and no
/// backreference to bound. Unanchored, unlike a glob: `^` and `$` say so.
#[derive(Debug, Clone)]
pub struct Pattern(Regex);

impl Pattern {
    /// Compile `source` under both limits.
    ///
    /// # Errors
    ///
    /// The engine's reason, a syntax error or a compiled size above
    /// [`HOST_RULE_REGEX_SIZE_LIMIT`].
    pub fn new(source: &str) -> Result<Self, String> {
        RegexBuilder::new(source)
            .size_limit(HOST_RULE_REGEX_SIZE_LIMIT)
            .dfa_size_limit(HOST_RULE_REGEX_DFA_LIMIT)
            .build()
            .map(Self)
            .map_err(|e| match e {
                regex::Error::CompiledTooBig(limit) => format!(
                    "compiles to more than {limit} bytes; a counted repetition of a Unicode class \
                     such as `\\w{{100}}` is the usual cause, and `(?-u)` or a narrower class \
                     shrinks it"
                ),
                other => other.to_string(),
            })
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        self.0.is_match(text)
    }
}

impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for Pattern {}

/// One test on one field of an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Test {
    /// Equal to one of these.
    In(Vec<FieldValue>),
    /// Present and equal to none of these.
    NotIn(Vec<FieldValue>),
    /// Matching one of these globs.
    Matches(Vec<Glob>),
    /// Matching one of these regular expressions somewhere in the text.
    Regex(Vec<Pattern>),
    /// Greater than this.
    Gt(i64),
    /// Less than this.
    Lt(i64),
    /// Equal to that other field of the same event.
    EqField(&'static str),
    /// Different from that other field of the same event.
    NeField(&'static str),
}

/// One matcher: a field and the test it must pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    pub field: &'static str,
    pub test: Test,
}

impl Matcher {
    fn holds(&self, event: &IntentEvent) -> bool {
        let Some(own) = event.get(self.field) else {
            return false;
        };
        match &self.test {
            Test::In(values) => values.contains(own),
            Test::NotIn(values) => !values.contains(own),
            Test::Matches(globs) => match own {
                FieldValue::Text(text) => globs.iter().any(|g| g.matches(text)),
                _ => false,
            },
            Test::Regex(patterns) => match own {
                FieldValue::Text(text) => patterns.iter().any(|p| p.is_match(text)),
                _ => false,
            },
            Test::Gt(bound) => matches!(own, FieldValue::Integer(v) if v > bound),
            Test::Lt(bound) => matches!(own, FieldValue::Integer(v) if v < bound),
            Test::EqField(other) => event.get(other).is_some_and(|o| o == own),
            Test::NeField(other) => event.get(other).is_some_and(|o| o != own),
        }
    }

    /// The fields this matcher reads.
    fn fields(&self) -> impl Iterator<Item = &'static str> {
        let other = match self.test {
            Test::EqField(other) | Test::NeField(other) => Some(other),
            _ => None,
        };
        std::iter::once(self.field).chain(other)
    }
}

/// One intention and the matchers an event of it must pass, every one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntentBlock {
    pub intent: Intent,
    pub matchers: Vec<Matcher>,
    /// How many events matching the block must arrive before it holds.
    pub count: Option<Count>,
}

impl IntentBlock {
    pub(super) fn holds(&self, event: &IntentEvent) -> bool {
        self.intent == event.intent() && self.matchers.iter().all(|m| m.holds(event))
    }
}

/// What `when` asks for: one intention, or any of several.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    All(IntentBlock),
    Any(Vec<IntentBlock>),
}

impl Condition {
    /// Every block, in the order written.
    #[must_use]
    pub fn blocks(&self) -> &[IntentBlock] {
        match self {
            Self::All(block) => std::slice::from_ref(block),
            Self::Any(blocks) => blocks,
        }
    }
}

/// A rule that loaded: every check that could be made has been.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRule {
    pub spec: HostRuleSpec,
    pub severity: Severity,
    pub when: Condition,
    /// The second step, where the rule is a sequence.
    pub followed_by: Option<FollowedBy>,
}

/// The second step of a sequence and the window it must arrive in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowedBy {
    pub then: Condition,
    /// Nanoseconds after the first step, inclusive.
    pub within_ns: u64,
    /// The window as it was written, for the alert's line.
    pub within: String,
}

impl HostRule {
    /// Check `spec` against the field registry and keep what it compiles to.
    ///
    /// # Errors
    ///
    /// [`HostRuleError::Rule`] naming the rule, what is wrong with it and,
    /// where there is one, what to write instead.
    pub fn compile(spec: HostRuleSpec) -> Result<Self, HostRuleError> {
        let refuse = |reason: String| HostRuleError::Rule {
            id: spec.id.clone(),
            reason,
        };
        check_id(&spec.id).map_err(refuse)?;
        let severity = parse_severity(&spec.severity).ok_or_else(|| {
            refuse(format!(
                "severity `{}` is not one of low, medium, high or critical",
                spec.severity
            ))
        })?;
        if let Some(selector) = &spec.workload {
            if selector.guest.is_some() {
                return Err(refuse(
                    "a host rule is about a task on this host, and a guest runs its own kernel: \
                     `guest` is not a matcher of a host rule's workload"
                        .to_string(),
                ));
            }
            selector
                .validate()
                .map_err(|e| refuse(format!("workload: {e}")))?;
        }
        let when = compile_when(&spec.when).map_err(refuse)?;
        let followed_by = spec
            .followed_by
            .as_ref()
            .map(|map| compile_followed_by(map, &when))
            .transpose()
            .map_err(refuse)?;
        let acted_on = followed_by.as_ref().map_or(&when, |f| &f.then);
        check_then(&spec.then, acted_on).map_err(refuse)?;
        Ok(Self {
            spec,
            severity,
            when,
            followed_by,
        })
    }

    /// The identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.spec.id
    }

    /// Whether `event`, from a task whose workload is `workload`, matches
    /// `when` and the workload selector: the whole rule for a single event,
    /// the first step of a sequence.
    ///
    /// Total: no event and no workload makes it panic or fail, which a
    /// property test asserts over every intention.
    #[must_use]
    pub fn matches(&self, event: &IntentEvent, workload: Option<&WorkloadFacts<'_>>) -> bool {
        self.matching_block(event, workload).is_some()
    }

    /// The first block of `when` that `event` matches, once the workload
    /// selector agrees; a count on that block is still to be met.
    pub(super) fn matching_block(
        &self,
        event: &IntentEvent,
        workload: Option<&WorkloadFacts<'_>>,
    ) -> Option<usize> {
        let block = self.when.blocks().iter().position(|b| b.holds(event))?;
        match &self.spec.workload {
            Some(selector) => workload
                .is_some_and(|facts| selector.matches(facts))
                .then_some(block),
            None => Some(block),
        }
    }

    /// The intentions the rule names, each once, in the order written.
    #[must_use]
    pub fn intents(&self) -> Vec<Intent> {
        let mut intents = Vec::new();
        for block in self.blocks() {
            if !intents.contains(&block.intent) {
                intents.push(block.intent);
            }
        }
        intents
    }

    /// Whether a matcher on `intent` reads `field`, so a source can skip a
    /// read nobody asks for.
    #[must_use]
    pub fn reads(&self, intent: Intent, field: &str) -> bool {
        self.blocks().filter(|b| b.intent == intent).any(|b| {
            b.matchers.iter().any(|m| m.fields().any(|f| f == field))
                || b.count.as_ref().and_then(|c| c.distinct) == Some(field)
        })
    }

    /// Every block of both steps, `when` first.
    fn blocks(&self) -> impl Iterator<Item = &IntentBlock> {
        self.when
            .blocks()
            .iter()
            .chain(self.followed_by.iter().flat_map(|f| f.then.blocks()))
    }

    /// The alert's line: what the rule says it catches, then the event as
    /// it was matched, every field it carried, for a sequence the first
    /// step it followed, and for a count what was counted.
    #[must_use]
    pub fn message(&self, event: &IntentEvent) -> String {
        let fields: Vec<String> = event
            .fields()
            .map(|(name, value)| {
                let rendered = match value {
                    FieldValue::Boolean(b) => b.to_string(),
                    FieldValue::Integer(n) => n.to_string(),
                    FieldValue::Address(a) => a.to_string(),
                    FieldValue::Text(t) => t.clone(),
                };
                format!(" {name}={rendered}")
            })
            .collect();
        let after = self.followed_by.as_ref().map_or(String::new(), |f| {
            let first: Vec<&str> = self
                .when
                .blocks()
                .iter()
                .map(|b| b.intent.as_str())
                .collect();
            format!(" after {} within {}", first.join(" or "), f.within)
        });
        let counted = if self.followed_by.is_none()
            && let Some(count) = self
                .when
                .blocks()
                .iter()
                .find(|b| b.holds(event))
                .and_then(|b| b.count.as_ref())
        {
            format!(", {count}")
        } else {
            String::new()
        };
        format!(
            "host rule {}: {} ({}{}){after}{counted}",
            self.spec.id,
            self.spec
                .description
                .as_deref()
                .unwrap_or(event.intent().as_str()),
            event.intent(),
            fields.concat()
        )
    }

    /// Whether a match stops the process behind the event.
    #[must_use]
    pub fn kills(&self) -> bool {
        self.spec.then.contains(&HostRuleAction::KillProcess)
    }
}

/// Every loaded rule, identifiers unique.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRuleSet {
    rules: Vec<HostRule>,
}

impl HostRuleSet {
    /// Compile every spec, refusing the first that does not load and any
    /// identifier used twice.
    ///
    /// # Errors
    ///
    /// [`HostRuleError::Rule`] or [`HostRuleError::DuplicateRule`].
    pub fn compile(specs: Vec<HostRuleSpec>) -> Result<Self, HostRuleError> {
        let mut rules: Vec<HostRule> = Vec::with_capacity(specs.len());
        for spec in specs {
            if rules.iter().any(|r| r.id() == spec.id) {
                return Err(HostRuleError::DuplicateRule { id: spec.id });
            }
            rules.push(HostRule::compile(spec)?);
        }
        Ok(Self { rules })
    }

    /// Every rule, in the order written.
    #[must_use]
    pub fn rules(&self) -> &[HostRule] {
        &self.rules
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether any rule names `intent`, so a source with no reader can stay
    /// quiet.
    #[must_use]
    pub fn names(&self, intent: Intent) -> bool {
        self.rules.iter().any(|r| r.intents().contains(&intent))
    }

    /// Whether any rule reads `field` of `intent`.
    #[must_use]
    pub fn reads(&self, intent: Intent, field: &str) -> bool {
        self.rules.iter().any(|r| r.reads(intent, field))
    }
}

fn check_id(id: &str) -> Result<(), String> {
    if id.is_empty() || id.len() > HOST_RULE_ID_MAX_LEN {
        return Err(format!(
            "the id must be 1 to {HOST_RULE_ID_MAX_LEN} characters"
        ));
    }
    if !id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err("the id holds only letters, digits, `-` and `_`".to_string());
    }
    Ok(())
}

fn check_then(then: &[HostRuleAction], when: &Condition) -> Result<(), String> {
    if then.is_empty() {
        return Err("`then` is empty, so the rule would do nothing: write `[alert]`".to_string());
    }
    for (i, action) in then.iter().enumerate() {
        if then[..i].contains(action) {
            return Err(format!("`then` names `{}` twice", action.as_str()));
        }
    }
    if then.contains(&HostRuleAction::KillProcess) {
        for block in when.blocks() {
            if block.intent == Intent::ProcessEnds {
                return Err(
                    "`kill_process` stops a running process, and `process.ends` is about one \
                     that has already ended: keep `alert` alone"
                        .to_string(),
                );
            }
            if !names_a_process(block.intent) {
                return Err(format!(
                    "`kill_process` stops the process behind the event, and an event of `{}` \
                     names no process: keep `alert` alone",
                    block.intent
                ));
            }
            if let Some(count) = &block.count
                && count.per != CountPer::Process
            {
                return Err(format!(
                    "`kill_process` stops the process behind the event, and a count per {} is \
                     reached by many processes at once: count `per: process`, or keep `alert` \
                     alone",
                    count.per.as_str()
                ));
            }
        }
    }
    Ok(())
}

/// Whether an event of `intent` comes from a process that can be stopped.
fn names_a_process(intent: Intent) -> bool {
    intent.field("exe").is_ok() || intent == Intent::ProcessHidden
}

fn compile_when(when: &BTreeMap<String, RawValue>) -> Result<Condition, String> {
    compile_condition(when, "`when`")
}

/// The longest window a sequence may wait: every first step is held for
/// that long, so the window is a memory bound as much as a semantic one.
pub const HOST_RULE_WINDOW_MAX_NS: u64 = 3_600 * 1_000_000_000;

fn compile_followed_by(
    map: &BTreeMap<String, RawValue>,
    when: &Condition,
) -> Result<FollowedBy, String> {
    if map.contains_key("followed_by") {
        return Err(
            "a sequence is two steps and `followed_by` does not nest: what came before the \
             first step is in the ancestry the alert carries, and a third step is a second rule"
                .to_string(),
        );
    }
    if map.contains_key("workload") {
        return Err(
            "`workload` sits at the top of the rule and scopes the first step; the second is \
             about the same process or one started below it"
                .to_string(),
        );
    }
    let Some(raw) = map.get("within") else {
        return Err(
            "`followed_by` needs `within`, the window the second step must arrive in, such as \
             `within: 30s`: a sequence with no window is a first event held for ever"
                .to_string(),
        );
    };
    let (within_ns, within) = parse_window(raw, "and every first step is held for it")?;
    let mut rest = map.clone();
    rest.remove("within");
    let then = compile_condition(&rest, "`followed_by`")?;
    if then.blocks().iter().any(|b| b.count.is_some()) {
        return Err(
            "a sequence closes on one event, so its second step carries no `count`: count the \
             first step in `when`, or write the count as a rule of its own"
                .to_string(),
        );
    }
    for block in when.blocks().iter().chain(then.blocks()) {
        if !names_a_process(block.intent) {
            return Err(format!(
                "a sequence follows one process and the processes it starts, and an event of \
                 `{}` names no process",
                block.intent
            ));
        }
    }
    Ok(FollowedBy {
        then,
        within_ns,
        within,
    })
}

/// `within` as nanoseconds and as written: a whole number followed by
/// `ms`, `s`, `m` or `h`, above zero and at most an hour. `held` says what
/// the window holds, for the refusal of one too long.
pub(super) fn parse_window(raw: &RawValue, held: &str) -> Result<(u64, String), String> {
    let RawValue::Text(text) = raw else {
        return Err(format!(
            "`within` is a duration such as `30s`, `500ms`, `5m` or `1h`, and {} was given",
            raw.kind()
        ));
    };
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, unit) = text.split_at(split);
    let scale: u64 = match unit {
        "ms" => 1_000_000,
        "s" => 1_000_000_000,
        "m" => 60_000_000_000,
        "h" => 3_600_000_000_000,
        _ => {
            return Err(format!(
                "`within: {text}` is not a duration: write a whole number followed by `ms`, \
                 `s`, `m` or `h`"
            ));
        }
    };
    let ns = digits
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(scale))
        .filter(|ns| *ns > 0)
        .ok_or_else(|| format!("`within: {text}` is not a duration above zero"))?;
    if ns > HOST_RULE_WINDOW_MAX_NS {
        return Err(format!("`within: {text}` is longer than an hour, {held}"));
    }
    Ok((ns, text.clone()))
}

fn compile_condition(when: &BTreeMap<String, RawValue>, place: &str) -> Result<Condition, String> {
    if when.is_empty() {
        return Err(format!(
            "{place} names no intent: name one, such as `process.starts`"
        ));
    }
    let Some(any) = when.get(ANY_OF) else {
        return compile_alternative(when, place).map(Condition::All);
    };
    if when.len() > 1 {
        return Err(format!(
            "`any_of` stands alone in {place}: write each other intent as one more entry of its \
             list"
        ));
    }
    let RawValue::List(entries) = any else {
        return Err(format!(
            "`any_of` takes a list of intents, each with its matchers, and {} was given",
            any.kind()
        ));
    };
    match entries.len() {
        0 => return Err("`any_of` is empty: list at least two alternatives".to_string()),
        1 => {
            return Err(
                "`any_of` with one alternative is that alternative: write it directly in `when`"
                    .to_string(),
            );
        }
        n if n > HOST_RULE_LIST_MAX => {
            return Err(format!(
                "`any_of` lists {n} alternatives, more than {HOST_RULE_LIST_MAX}"
            ));
        }
        _ => {}
    }
    entries
        .iter()
        .map(|entry| match entry {
            RawValue::Map(map) => compile_alternative(map, "an entry of `any_of`"),
            other => Err(format!(
                "an entry of `any_of` is an intent with its matchers, and {} was given",
                other.kind()
            )),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Condition::Any)
}

/// One intention and its block, from a map that must name exactly one.
fn compile_alternative(
    map: &BTreeMap<String, RawValue>,
    place: &str,
) -> Result<IntentBlock, String> {
    for key in map.keys() {
        if let Some(message) = misplaced_at_when(key) {
            return Err(message);
        }
    }
    let mut entries = map.iter();
    let Some((name, block)) = entries.next() else {
        return Err(format!("{place} names no intent"));
    };
    if let Some((second, _)) = entries.next() {
        return Err(format!(
            "{place} names `{name}` and `{second}`, and one event is one intent, so the two can \
             never hold at once: use `any_of` to match either"
        ));
    }
    let intent = Intent::parse(name).map_err(|e| e.to_string())?;
    let RawValue::Map(matchers) = block else {
        return Err(format!(
            "`{intent}` takes a map of matchers, such as `exe: /usr/bin/curl`, and {} was given",
            block.kind()
        ));
    };
    let mut matchers = matchers.clone();
    let count = matchers
        .remove("count")
        .map(|raw| compile_count(intent, &raw))
        .transpose()?;
    compile_block(intent, &matchers).map(|matchers| IntentBlock {
        intent,
        matchers,
        count,
    })
}

/// The refusal for a reserved key written where an intent was expected.
fn misplaced_at_when(key: &str) -> Option<String> {
    match key {
        ANY_OF => Some(
            "`any_of` does not nest: list every alternative in the one `any_of` at the top of \
             `when`"
                .to_string(),
        ),
        "workload" => Some("`workload` sits beside `when`, at the top of the rule".to_string()),
        "count" => Some("`count` is a key of an intent block, never of `when`".to_string()),
        "followed_by" => Some(
            "`followed_by` sits beside `when`, at the top of the rule, and holds the second step"
                .to_string(),
        ),
        "within" => Some(
            "`within` is the window of a sequence and sits in `followed_by`, beside the intent \
             it waits for"
                .to_string(),
        ),
        _ => None,
    }
}

/// The refusal for a reserved key written inside an intent block.
fn misplaced_in_block(intent: Intent, key: &str) -> Option<String> {
    match key {
        ANY_OF => Some(format!(
            "`any_of` sits at the top of `when`, never inside `{intent}`: list the alternatives \
             there, each an intent with its matchers"
        )),
        "workload" => Some(format!(
            "`workload` sits beside `when`, at the top of the rule, never inside `{intent}`"
        )),
        "followed_by" => Some(format!(
            "`followed_by` sits beside `when`, at the top of the rule, never inside `{intent}`"
        )),
        "within" => Some(format!(
            "`within` sits in `followed_by`, beside the intent it waits for, never inside \
             `{intent}`"
        )),
        _ => None,
    }
}

fn split_key(intent: Intent, key: &str) -> Result<(&'static FieldSpec, Option<Op>), String> {
    if let Ok(spec) = intent.field(key) {
        return Ok((spec, None));
    }
    for (suffix, op) in SUFFIXES {
        if let Some(base) = key.strip_suffix(suffix) {
            if RESERVED_KEYS.contains(&base) {
                return Err(format!(
                    "`{key}` puts a matcher on the reserved key `{base}`, and a reserved key takes \
                     none"
                ));
            }
            let spec = intent.field(base).map_err(|e| e.to_string())?;
            return Ok((spec, Some(op)));
        }
    }
    Err(format!(
        "{}; a matcher is a field, optionally followed by `_in`, `_not_in`, `_matches`, `_gt`, \
         `_lt`, `_eq_field` or `_ne_field`",
        intent
            .field(key)
            .map_err(|e| e.to_string())
            .err()
            .unwrap_or_default()
    ))
}

fn compile_block(intent: Intent, map: &BTreeMap<String, RawValue>) -> Result<Vec<Matcher>, String> {
    let mut matchers = Vec::with_capacity(map.len());
    for (key, value) in map {
        if let Some(message) = misplaced_in_block(intent, key) {
            return Err(message);
        }
        let (spec, op) = split_key(intent, key)?;
        let test = match op {
            None | Some(Op::In) => Test::In(values(intent, spec, key, value)?),
            Some(Op::NotIn) => Test::NotIn(values(intent, spec, key, value)?),
            Some(Op::Matches) => Test::Matches(globs(spec, key, value)?),
            Some(Op::Regex) => Test::Regex(patterns(spec, key, value)?),
            Some(op @ (Op::Gt | Op::Lt)) => {
                let bound = bound(intent, spec, key, value)?;
                if op == Op::Gt {
                    Test::Gt(bound)
                } else {
                    Test::Lt(bound)
                }
            }
            Some(op @ (Op::EqField | Op::NeField)) => {
                let other = other_field(intent, spec, key, value)?;
                if op == Op::EqField {
                    Test::EqField(other)
                } else {
                    Test::NeField(other)
                }
            }
        };
        matchers.push(Matcher {
            field: spec.name,
            test,
        });
    }
    Ok(matchers)
}

/// The values of an equality or a list, each checked against the field.
fn values(
    intent: Intent,
    spec: &FieldSpec,
    key: &str,
    value: &RawValue,
) -> Result<Vec<FieldValue>, String> {
    let items: &[RawValue] = match value {
        RawValue::List(items) => items,
        single => std::slice::from_ref(single),
    };
    check_list(key, items.len())?;
    items
        .iter()
        .map(|item| coerce(intent, spec, key, item))
        .collect()
}

fn check_list(key: &str, len: usize) -> Result<(), String> {
    if len == 0 {
        return Err(format!("`{key}` lists no value"));
    }
    if len > HOST_RULE_LIST_MAX {
        return Err(format!(
            "`{key}` lists {len} values, more than {HOST_RULE_LIST_MAX}"
        ));
    }
    Ok(())
}

/// A raw value as a value of `spec`'s type, or the reason it is not one.
fn coerce(
    intent: Intent,
    spec: &FieldSpec,
    key: &str,
    raw: &RawValue,
) -> Result<FieldValue, String> {
    let value = match (spec.ty, raw) {
        (FieldType::Address, RawValue::Text(text)) => {
            FieldValue::Address(text.parse::<IpAddr>().map_err(|_| {
                format!(
                    "`{key}`: `{}` is an address, and `{text}` is not one",
                    spec.name
                )
            })?)
        }
        (_, RawValue::Text(text)) => {
            if text.len() > HOST_RULE_VALUE_MAX_LEN {
                return Err(format!(
                    "`{key}`: a value is at most {HOST_RULE_VALUE_MAX_LEN} bytes"
                ));
            }
            FieldValue::Text(text.clone())
        }
        (_, RawValue::Integer(n)) => FieldValue::Integer(*n),
        (_, RawValue::Boolean(b)) => FieldValue::Boolean(*b),
        (_, other @ (RawValue::List(_) | RawValue::Map(_))) => {
            return Err(format!(
                "`{key}` takes a value or a list of values, and {} was given inside it",
                other.kind()
            ));
        }
    };
    IntentEvent::new(intent)
        .with(spec.name, value.clone())
        .map(|_| value)
        .map_err(|e| format!("`{key}`: {e}"))
}

fn patterns(spec: &FieldSpec, key: &str, value: &RawValue) -> Result<Vec<Pattern>, String> {
    if !matches!(spec.ty, FieldType::Text | FieldType::Path | FieldType::Hash) {
        return Err(format!(
            "`{key}`: a regular expression matches text, and `{}` is {}: use `{}_in`",
            spec.name,
            spec.ty.as_str(),
            spec.name
        ));
    }
    let items: &[RawValue] = match value {
        RawValue::List(items) => items,
        single => std::slice::from_ref(single),
    };
    check_list(key, items.len())?;
    items
        .iter()
        .map(|item| match item {
            RawValue::Text(source) if source.len() <= HOST_RULE_VALUE_MAX_LEN => {
                Pattern::new(source).map_err(|reason| format!("`{key}: {source}` {reason}"))
            }
            RawValue::Text(_) => Err(format!(
                "`{key}`: a regular expression is at most {HOST_RULE_VALUE_MAX_LEN} bytes"
            )),
            other => Err(format!(
                "`{key}` takes a regular expression, and {} was given",
                other.kind()
            )),
        })
        .collect()
}

fn globs(spec: &FieldSpec, key: &str, value: &RawValue) -> Result<Vec<Glob>, String> {
    if !matches!(spec.ty, FieldType::Text | FieldType::Path | FieldType::Hash) {
        return Err(format!(
            "`{key}`: a glob matches text, and `{}` is {}: use `{}_in`",
            spec.name,
            spec.ty.as_str(),
            spec.name
        ));
    }
    let items: &[RawValue] = match value {
        RawValue::List(items) => items,
        single => std::slice::from_ref(single),
    };
    check_list(key, items.len())?;
    items
        .iter()
        .map(|item| match item {
            RawValue::Text(pattern) if pattern.len() <= HOST_RULE_VALUE_MAX_LEN => {
                Ok(Glob::new(pattern))
            }
            RawValue::Text(_) => Err(format!(
                "`{key}`: a glob is at most {HOST_RULE_VALUE_MAX_LEN} bytes"
            )),
            other => Err(format!(
                "`{key}` takes a glob, and {} was given",
                other.kind()
            )),
        })
        .collect()
}

fn bound(intent: Intent, spec: &FieldSpec, key: &str, value: &RawValue) -> Result<i64, String> {
    if !spec.ty.is_numeric() {
        return Err(format!(
            "`{key}` compares numbers, and `{}` is {}",
            spec.name,
            spec.ty.as_str()
        ));
    }
    let RawValue::Integer(n) = value else {
        return Err(format!(
            "`{key}` takes one integer, and {} was given",
            value.kind()
        ));
    };
    coerce(intent, spec, key, value)?;
    Ok(*n)
}

fn other_field(
    intent: Intent,
    spec: &FieldSpec,
    key: &str,
    value: &RawValue,
) -> Result<&'static str, String> {
    let RawValue::Text(name) = value else {
        return Err(format!(
            "`{key}` takes the name of another field of `{intent}`, and {} was given",
            value.kind()
        ));
    };
    let other = intent.field(name).map_err(|e| format!("`{key}`: {e}"))?;
    if other.name == spec.name {
        return Err(format!("`{key}` compares `{name}` with itself"));
    }
    if other.ty != spec.ty {
        return Err(format!(
            "`{key}` compares `{}`, {}, with `{}`, {}, and two fields compare only when their \
             types are the same",
            spec.name,
            spec.ty.as_str(),
            other.name,
            other.ty.as_str()
        ));
    }
    Ok(other.name)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use super::*;

    fn spec(yaml_like: &str) -> HostRuleSpec {
        serde_json::from_str(yaml_like).unwrap()
    }

    fn compile(json: &str) -> Result<HostRule, String> {
        HostRule::compile(spec(json)).map_err(|e| e.to_string())
    }

    fn refused(json: &str) -> String {
        compile(json).unwrap_err()
    }

    fn text(value: &str) -> FieldValue {
        FieldValue::Text(value.to_string())
    }

    fn start(exe: &str, uid: i64) -> IntentEvent {
        IntentEvent::new(Intent::ProcessStarts)
            .with("exe", text(exe))
            .unwrap()
            .with("uid", FieldValue::Integer(uid))
            .unwrap()
    }

    #[test]
    fn a_key_is_and_and_a_list_is_or() {
        let rule = compile(
            r#"{"id":"r","when":{"process.starts":{"exe":["/bin/sh","/bin/bash"],"uid":0}}}"#,
        )
        .unwrap();
        assert!(rule.matches(&start("/bin/sh", 0), None));
        assert!(rule.matches(&start("/bin/bash", 0), None));
        assert!(!rule.matches(&start("/bin/bash", 1000), None));
        assert!(!rule.matches(&start("/bin/zsh", 0), None));
        assert_eq!(rule.severity, Severity::Medium);
        assert_eq!(rule.spec.then, vec![HostRuleAction::Alert]);
    }

    #[test]
    fn another_intent_never_matches() {
        let rule = compile(r#"{"id":"r","when":{"process.ends":{"exe":"/bin/sh"}}}"#).unwrap();
        assert!(!rule.matches(&start("/bin/sh", 0), None));
    }

    #[test]
    fn the_suffixes_do_what_they_say() {
        let rule = compile(
            r#"{"id":"r","when":{"process.starts":{
                "exe_matches":["/tmp/*","/dev/shm/?x*"],
                "uid_lt":1000,
                "exe_not_in":["/tmp/allowed"]}}}"#,
        )
        .unwrap();
        assert!(rule.matches(&start("/tmp/a/b", 0), None));
        assert!(rule.matches(&start("/dev/shm/1xyz", 999), None));
        assert!(!rule.matches(&start("/dev/shm/xyz", 0), None));
        assert!(!rule.matches(&start("/tmp/a", 1000), None));
        assert!(!rule.matches(&start("/tmp/allowed", 0), None));
        assert!(!rule.matches(&start("/usr/bin/tmp", 0), None));

        let gt = compile(r#"{"id":"r","when":{"process.starts":{"uid_gt":0}}}"#).unwrap();
        assert!(gt.matches(&start("/x", 1), None));
        assert!(!gt.matches(&start("/x", 0), None));
    }

    #[test]
    fn two_fields_of_one_event_compare() {
        let rule = compile(r#"{"id":"r","when":{"process.starts":{"uid_ne_field":"parent_uid"}}}"#)
            .unwrap();
        let event = start("/usr/bin/sudo", 0)
            .with("parent_uid", FieldValue::Integer(1000))
            .unwrap();
        assert!(rule.matches(&event, None));
        let same = start("/usr/bin/id", 1000)
            .with("parent_uid", FieldValue::Integer(1000))
            .unwrap();
        assert!(!rule.matches(&same, None));
        // Nothing to compare with is no difference.
        assert!(!rule.matches(&start("/usr/bin/id", 0), None));

        let eq = compile(r#"{"id":"r","when":{"process.starts":{"exe_eq_field":"parent_exe"}}}"#)
            .unwrap();
        let event = start("/bin/sh", 0)
            .with("parent_exe", text("/bin/sh"))
            .unwrap();
        assert!(eq.matches(&event, None));
    }

    #[test]
    fn an_absent_field_matches_no_matcher_not_even_not_in() {
        let rule = compile(r#"{"id":"r","when":{"process.starts":{"command_line_not_in":["x"]}}}"#)
            .unwrap();
        assert!(!rule.matches(&start("/bin/sh", 0), None));
    }

    #[test]
    fn addresses_and_booleans_are_typed() {
        let rule = compile(
            r#"{"id":"r","when":{"process.connects":{"remote_address":["192.0.2.7","2001:db8::1"],
                "exe_on_disk":false,"remote_port_in":[4444,1337]}}}"#,
        )
        .unwrap();
        let event = IntentEvent::new(Intent::ProcessConnects)
            .with(
                "remote_address",
                FieldValue::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
            )
            .unwrap()
            .with("exe_on_disk", FieldValue::Boolean(false))
            .unwrap()
            .with("remote_port", FieldValue::Integer(4444))
            .unwrap();
        assert!(rule.matches(&event, None));
    }

    #[test]
    fn any_of_matches_either_alternative() {
        let rule = compile(
            r#"{"id":"r","when":{"any_of":[
                {"process.starts":{"exe":"/bin/nc"}},
                {"process.connects":{"remote_port":4444}}]}}"#,
        )
        .unwrap();
        assert!(rule.matches(&start("/bin/nc", 0), None));
        let connect = IntentEvent::new(Intent::ProcessConnects)
            .with("remote_port", FieldValue::Integer(4444))
            .unwrap();
        assert!(rule.matches(&connect, None));
        assert!(!rule.matches(&start("/bin/sh", 0), None));
        assert_eq!(
            rule.intents(),
            vec![Intent::ProcessStarts, Intent::ProcessConnects]
        );
    }

    #[test]
    fn any_of_empty_single_nested_or_beside_an_intent_is_refused() {
        assert!(refused(r#"{"id":"r","when":{"any_of":[]}}"#).contains("is empty"));
        assert!(
            refused(r#"{"id":"r","when":{"any_of":[{"process.starts":{}}]}}"#)
                .contains("one alternative")
        );
        assert!(
            refused(
                r#"{"id":"r","when":{"any_of":[{"process.starts":{}},
                    {"any_of":[{"process.ends":{}},{"process.starts":{}}]}]}}"#
            )
            .contains("does not nest")
        );
        assert!(
            refused(
                r#"{"id":"r","when":{"any_of":[{"process.starts":{}},{"process.ends":{}}],
                "process.connects":{}}}"#
            )
            .contains("stands alone")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"any_of":[]}}}"#)
                .contains("never inside")
        );
    }

    #[test]
    fn two_intents_anded_are_refused_naming_any_of() {
        let message = refused(r#"{"id":"r","when":{"process.starts":{},"process.ends":{}}}"#);
        assert!(message.contains("never hold at once"), "{message}");
        assert!(message.contains("any_of"), "{message}");
    }

    #[test]
    fn every_reserved_key_is_refused_where_it_does_not_belong() {
        for key in RESERVED_KEYS {
            let in_block = refused(&format!(
                r#"{{"id":"r","when":{{"process.starts":{{"{key}":1}}}}}}"#
            ));
            assert!(in_block.contains(&format!("`{key}`")), "{key}: {in_block}");
            let in_when = refused(&format!(r#"{{"id":"r","when":{{"{key}":1}}}}"#));
            assert!(in_when.contains(&format!("`{key}`")), "{key}: {in_when}");
            let with_suffix = refused(&format!(
                r#"{{"id":"r","when":{{"process.starts":{{"{key}_gt":1}}}}}}"#
            ));
            assert!(with_suffix.contains("reserved key"), "{key}: {with_suffix}");
        }
    }

    #[test]
    fn the_type_refusals_name_the_mistake() {
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"exe_gt":3}}}"#)
                .contains("compares numbers")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"uid_matches":"1*"}}}"#)
                .contains("use `uid_in`")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"uid":"root"}}}"#)
                .contains("is an integer")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.connects":{"remote_address":"nope"}}}"#)
                .contains("is not one")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.connects":{"remote_port_lt":70000}}}"#)
                .contains("outside 0 to 65535")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"uid_eq_field":"exe"}}}"#)
                .contains("types are the same")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"uid_eq_field":"uid"}}}"#)
                .contains("with itself")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"uid_gt":[1,2]}}}"#)
                .contains("one integer")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"exe":[]}}}"#)
                .contains("lists no value")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"exe":{"a":1}}}}"#)
                .contains("a map was given")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"uid_regex":"^0$"}}}"#)
                .contains("a regular expression matches text")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"exe_regex":"(unclosed"}}}"#)
                .contains("`exe_regex: (unclosed`")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"nope_in":["x"]}}}"#)
                .contains("has no field `nope`")
        );
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":{"nope":"x"}}}"#).contains("`_not_in`")
        );
        assert!(refused(r#"{"id":"r","when":{"process.sleeps":{}}}"#).contains("process.starts"));
        assert!(
            refused(r#"{"id":"r","when":{"process.starts":["x"]}}"#)
                .contains("takes a map of matchers")
        );
    }

    #[test]
    fn the_rule_around_the_condition_is_checked() {
        assert!(refused(r#"{"id":"","when":{"process.starts":{}}}"#).contains("1 to 128"));
        assert!(refused(r#"{"id":"a b","when":{"process.starts":{}}}"#).contains("letters"));
        assert!(
            refused(r#"{"id":"r","severity":"dire","when":{"process.starts":{}}}"#)
                .contains("severity")
        );
        assert!(refused(r#"{"id":"r","when":{}}"#).contains("names no intent"));
        assert!(
            refused(r#"{"id":"r","then":[],"when":{"process.starts":{}}}"#).contains("do nothing")
        );
        assert!(
            refused(r#"{"id":"r","then":["alert","alert"],"when":{"process.starts":{}}}"#)
                .contains("twice")
        );
        assert!(
            refused(r#"{"id":"r","then":["kill_process"],"when":{"port.hidden":{}}}"#)
                .contains("names no process")
        );
        assert!(
            refused(r#"{"id":"r","then":["kill_process"],"when":{"process.ends":{}}}"#)
                .contains("already ended")
        );
        assert!(
            refused(r#"{"id":"r","workload":{"guest":"vm1"},"when":{"process.starts":{}}}"#)
                .contains("guest")
        );
        assert!(
            serde_json::from_str::<HostRuleSpec>(
                r#"{"id":"r","when":{"process.starts":{}},"then":["quarantine"]}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<HostRuleSpec>(
                r#"{"id":"r","when":{"process.starts":{}},"expression":"a && b"}"#
            )
            .is_err()
        );
        let kill = compile(
            r#"{"id":"r","severity":"critical","then":["alert","kill_process"],
                "when":{"process.starts":{"exe":"/tmp/x"}}}"#,
        )
        .unwrap();
        assert!(kill.kills());
        assert_eq!(kill.severity, Severity::Critical);
    }

    #[test]
    fn the_workload_selector_reads_absence_as_a_mismatch() {
        let rule =
            compile(r#"{"id":"r","workload":{"container":"web"},"when":{"process.starts":{}}}"#)
                .unwrap();
        assert!(!rule.matches(&start("/bin/sh", 0), None));
        let facts = WorkloadFacts {
            container_name: Some("web"),
            ..WorkloadFacts::default()
        };
        assert!(rule.matches(&start("/bin/sh", 0), Some(&facts)));
        let other = WorkloadFacts {
            container_name: Some("db"),
            ..WorkloadFacts::default()
        };
        assert!(!rule.matches(&start("/bin/sh", 0), Some(&other)));
    }

    #[test]
    fn the_set_refuses_an_id_twice_and_answers_who_reads_what() {
        let one = spec(r#"{"id":"a","when":{"process.starts":{"exe_on_disk":false}}}"#);
        let err = HostRuleSet::compile(vec![one.clone(), one.clone()]).unwrap_err();
        assert!(matches!(err, HostRuleError::DuplicateRule { .. }));
        let set = HostRuleSet::compile(vec![
            one,
            spec(r#"{"id":"b","when":{"process.ends":{"uid_eq_field":"exit_code"}}}"#),
        ])
        .unwrap();
        assert!(set.names(Intent::ProcessStarts));
        assert!(!set.names(Intent::ProcessConnects));
        assert!(set.reads(Intent::ProcessStarts, "exe_on_disk"));
        assert!(!set.reads(Intent::ProcessStarts, "exe"));
        assert!(set.reads(Intent::ProcessEnds, "exit_code"));
        let event = start("/bin/sh", 0)
            .with("exe_on_disk", FieldValue::Boolean(false))
            .unwrap();
        let mut pending = crate::hostrule::sequence::HostRuleState::default();
        let ids: Vec<&str> = set
            .evaluate(
                &mut pending,
                &event,
                None,
                &crate::hostrule::sequence::Subject::default(),
                0,
            )
            .into_iter()
            .map(HostRule::id)
            .collect();
        assert_eq!(ids, vec!["a"]);
    }

    #[test]
    fn the_message_names_the_rule_and_the_event() {
        let rule = compile(
            r#"{"id":"shell-as-root","description":"a shell started as root",
                "when":{"process.starts":{"uid":0}}}"#,
        )
        .unwrap();
        assert_eq!(
            rule.message(&start("/bin/sh", 0)),
            "host rule shell-as-root: a shell started as root (process.starts exe=/bin/sh uid=0)"
        );
    }

    #[test]
    fn a_sequence_needs_a_window_and_stops_at_two_steps() {
        let rule = |followed_by: &str| {
            compile(&format!(
                r#"{{"id":"s","when":{{"process.starts":{{"exe":"/bin/sh"}}}},"followed_by":{followed_by}}}"#
            ))
        };
        let ok = rule(r#"{"within":"30s","any_of":[{"process.starts":{}},{"process.connects":{"remote_port":4444}}]}"#)
            .unwrap();
        let followed = ok.followed_by.as_ref().unwrap();
        assert_eq!(followed.within_ns, 30_000_000_000);
        assert_eq!(followed.then.blocks().len(), 2);
        assert_eq!(
            ok.intents(),
            vec![Intent::ProcessStarts, Intent::ProcessConnects]
        );
        assert!(ok.reads(Intent::ProcessConnects, "remote_port"));
        assert_eq!(
            rule(r#"{"within":"500ms","process.ends":{}}"#)
                .unwrap()
                .followed_by
                .unwrap()
                .within_ns,
            500_000_000
        );
        for (followed_by, expected) in [
            (r#"{"process.starts":{}}"#, "needs `within`"),
            (r#"{"within":"30","process.starts":{}}"#, "not a duration"),
            (r#"{"within":"0s","process.starts":{}}"#, "above zero"),
            (
                r#"{"within":"2h","process.starts":{}}"#,
                "longer than an hour",
            ),
            (r#"{"within":30,"process.starts":{}}"#, "a duration such as"),
            (r#"{"within":"30s"}"#, "names no intent"),
            (
                r#"{"within":"30s","process.starts":{},"followed_by":{}}"#,
                "does not nest",
            ),
            (
                r#"{"within":"30s","process.starts":{},"workload":{}}"#,
                "scopes the first step",
            ),
            (r#"{"within":"30s","port.hidden":{}}"#, "names no process"),
            (
                r#"{"within":"30s","process.starts":{"within":"1s"}}"#,
                "beside the intent",
            ),
        ] {
            let message = rule(followed_by).unwrap_err();
            assert!(message.contains(expected), "{followed_by}: {message}");
        }
        let in_when = refused(r#"{"id":"s","when":{"process.starts":{},"within":"30s"}}"#);
        assert!(in_when.contains("sits in `followed_by`"), "{in_when}");
    }

    #[test]
    fn a_sequence_stops_the_process_of_its_second_step() {
        assert!(
            compile(
                r#"{"id":"s","then":["alert","kill_process"],"when":{"process.ends":{}},
                    "followed_by":{"within":"5s","process.starts":{}}}"#
            )
            .is_ok()
        );
        let message = refused(
            r#"{"id":"s","then":["alert","kill_process"],"when":{"process.starts":{}},
                "followed_by":{"within":"5s","process.ends":{}}}"#,
        );
        assert!(message.contains("already ended"), "{message}");
    }

    #[test]
    fn the_message_of_a_sequence_names_the_first_step() {
        let rule = compile(
            r#"{"id":"shell-then-curl","when":{"process.starts":{"exe":"/bin/sh"}},
                "followed_by":{"within":"30s","process.starts":{"exe":"/usr/bin/curl"}}}"#,
        )
        .unwrap();
        assert_eq!(
            rule.message(&start("/usr/bin/curl", 0)),
            "host rule shell-then-curl: process.starts (process.starts exe=/usr/bin/curl uid=0) \
             after process.starts within 30s"
        );
    }

    #[test]
    fn a_regex_searches_the_text_and_is_bounded_at_load() {
        let rule = compile(
            r#"{"id":"r","when":{"process.starts":{"exe_regex":["^/tmp/[a-z0-9]{8}$","/\\.[^/]+/"]}}}"#,
        )
        .unwrap();
        assert!(rule.matches(&start("/tmp/a1b2c3d4", 0), None));
        assert!(
            rule.matches(&start("/home/u/.cache/x", 0), None),
            "unanchored"
        );
        assert!(!rule.matches(&start("/tmp/a1b2c3d4e", 0), None));
        assert!(!rule.matches(&start("/usr/bin/curl", 0), None));
        let too_big = refused(r#"{"id":"r","when":{"process.starts":{"exe_regex":"\\w{200}"}}}"#);
        assert!(too_big.contains("compiles to more than"), "{too_big}");
        assert!(too_big.contains("(?-u)"), "{too_big}");
        let narrow =
            compile(r#"{"id":"r","when":{"process.starts":{"exe_regex":"(?-u)\\w{200}"}}}"#);
        assert!(narrow.is_ok(), "the way round it the refusal names loads");
    }

    #[test]
    fn a_unicode_pattern_matches_with_its_dfa_cache_bounded() {
        // The cache bound never refuses: a search needing more falls back
        // to a slower engine of the same linear bound and still answers.
        let pattern = Pattern::new(r"^(\w+\s+){8}\w*z$").unwrap();
        let mut text = "wörd ".repeat(8);
        assert!(!pattern.is_match(&text));
        text.push('z');
        assert!(pattern.is_match(&text));
    }

    #[test]
    fn a_glob_steps_over_characters_rather_than_bytes() {
        assert!(Glob::new("/tmp/caf?/*").matches("/tmp/caf\u{e9}/x"));
        assert!(Glob::new("*\u{e9}*z").matches("\u{e9}a\u{e9}bz"));
        assert!(!Glob::new("/tmp/caf?").matches("/tmp/caf\u{e9}\u{e9}"));
        assert!(Glob::new("*/payload*").matches("/\u{4e2d}\u{6587}/payload.bin"));
    }

    #[test]
    fn a_glob_is_anchored_at_both_ends() {
        let g = Glob::new("/usr/*/python?");
        assert!(g.matches("/usr/bin/python3"));
        assert!(g.matches("/usr/local/bin/python3"));
        assert!(!g.matches("/usr/bin/python"));
        assert!(!g.matches("/opt/usr/bin/python3"));
        assert!(Glob::new("*").matches(""));
        assert!(Glob::new("**a").matches("bba"));
        assert!(!Glob::new("").matches("a"));
        assert!(Glob::new("é?").matches("éx"));
    }

    fn any_value() -> impl Strategy<Value = FieldValue> {
        prop_oneof![
            any::<bool>().prop_map(FieldValue::Boolean),
            any::<i64>().prop_map(FieldValue::Integer),
            any::<[u8; 4]>().prop_map(|b| FieldValue::Address(IpAddr::from(b))),
            "[a-z/*?.]{0,12}".prop_map(FieldValue::Text),
        ]
    }

    proptest! {
        /// Whatever an event of any intent carries, every compiled rule
        /// answers rather than panicking.
        #[test]
        fn matching_is_total(
            intent_index in 0..Intent::ALL.len(),
            values in proptest::collection::vec(any_value(), 0..8),
            pattern in "[a-z/*?]{0,8}",
            bound in any::<i64>(),
        ) {
            let intent = Intent::ALL[intent_index];
            let mut event = IntentEvent::new(intent);
            for (spec, value) in intent.fields().iter().zip(values) {
                if let Ok(next) = event.clone().with(spec.name, value) {
                    event = next;
                }
            }
            for spec in intent.fields() {
                let mut block = BTreeMap::new();
                if spec.ty.is_numeric() {
                    let bound = RawValue::Integer(bound.clamp(0, 65_535));
                    block.insert(format!("{}_gt", spec.name), bound.clone());
                    block.insert(format!("{}_lt", spec.name), bound);
                } else {
                    block.insert(format!("{}_matches", spec.name), RawValue::Text(pattern.clone()));
                    block.insert(format!("{}_not_in", spec.name), RawValue::Text(pattern.clone()));
                }
                let mut when = BTreeMap::new();
                when.insert(intent.as_str().to_string(), RawValue::Map(block));
                let rule = HostRuleSpec {
                    id: "p".to_string(),
                    description: None,
                    severity: "low".to_string(),
                    workload: None,
                    when,
                    followed_by: None,
                    then: vec![HostRuleAction::Alert],
                };
                if let Ok(rule) = HostRule::compile(rule) {
                    let _ = rule.matches(&event, None);
                    let _ = rule.matches(&event, Some(&WorkloadFacts::default()));
                }
            }
        }
    }
}
