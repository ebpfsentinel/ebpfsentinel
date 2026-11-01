//! Counted rules: an intent block that holds only once enough events of it
//! arrived within a window.
//!
//! A count is four typed fields and no expression: how many events, over
//! which window, grouped by which closed key, and optionally how many
//! distinct values of one field rather than how many events. Each group
//! keeps the times of the events still inside its window and drops them
//! one by one as they age out, so the window slides rather than resets.
//! The groups held at once are bounded in number and in events across
//! every rule, and an event refused because a bound is hit is counted
//! rather than evicting a group that is still counting.

use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::firewall::workload::WorkloadFacts;
use crate::process::entity::ProcessKey;

use super::event::IntentEvent;
use super::intent::Intent;
use super::rule::{RawValue, parse_window};
use super::sequence::Subject;

/// The highest `min` a count may ask for: every group holds up to that many
/// events, so it is a memory bound as much as a threshold.
pub const HOST_RULE_COUNT_MIN_MAX: u64 = 1_024;

/// The groups a node counts at once, across every rule.
pub const HOST_RULE_COUNT_KEYS_MAX: usize = 8_192;

/// The events a node holds in windows at once, across every group.
pub const HOST_RULE_COUNT_EVENTS_MAX: usize = 262_144;

const COUNT_KEYS: [&str; 4] = ["min", "within", "per", "distinct"];

/// What a count groups its events by: a closed list, because a key chosen
/// freely is a cardinality incident waiting on a busy node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountPer {
    /// The process behind each event.
    Process,
    /// The workload the process runs in: its container, else its cgroup,
    /// else its systemd unit.
    Workload,
    /// The whole host.
    Host,
}

impl CountPer {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Workload => "workload",
            Self::Host => "host",
        }
    }
}

/// How many events of one block, over which window, grouped how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Count {
    pub min: u64,
    /// Nanoseconds, inclusive at both ends.
    pub within_ns: u64,
    /// The window as it was written, for the alert's line.
    pub within: String,
    pub per: CountPer,
    /// The field whose distinct values are counted, rather than events.
    pub distinct: Option<&'static str>,
}

impl fmt::Display for Count {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.distinct {
            Some(field) => write!(f, "{} distinct {field}", self.min)?,
            None => write!(f, "{} events", self.min)?,
        }
        write!(f, " within {} per {}", self.within, self.per.as_str())
    }
}

/// Check the `count` of a block of `intent`.
pub(super) fn compile_count(intent: Intent, raw: &RawValue) -> Result<Count, String> {
    let RawValue::Map(map) = raw else {
        return Err(format!(
            "`count` is a map of `min`, `within`, `per` and `distinct`, such as \
             `count: {{min: 20, within: 60s}}`, and {} was given",
            raw.kind()
        ));
    };
    if let Some(key) = map.keys().find(|k| !COUNT_KEYS.contains(&k.as_str())) {
        return Err(format!(
            "`count` takes `min`, `within`, `per` and `distinct`, and `{key}` is none of them"
        ));
    }
    let min = compile_min(map)?;
    let Some(within) = map.get("within") else {
        return Err(
            "`count` needs `within`, the window its events must fall in, such as `within: 60s`: \
             a counter with no window is a gauge and never fires on what is happening now"
                .to_string(),
        );
    };
    let (within_ns, within) = parse_window(within, "and every event counted is held for it")?;
    let per = match map.get("per") {
        None => CountPer::Process,
        Some(RawValue::Text(text)) => match text.as_str() {
            "process" => CountPer::Process,
            "workload" => CountPer::Workload,
            "host" => CountPer::Host,
            other => {
                return Err(format!(
                    "`per: {other}` is not one of `process`, `workload` or `host`"
                ));
            }
        },
        Some(other) => {
            return Err(format!(
                "`per` is one of `process`, `workload` or `host`, and {} was given",
                other.kind()
            ));
        }
    };
    if per != CountPer::Host && intent.field("exe").is_err() {
        return Err(format!(
            "an event of `{intent}` names no process, so it has no {} to count by: write \
             `per: host`",
            per.as_str()
        ));
    }
    let distinct = match map.get("distinct") {
        None => None,
        Some(RawValue::Text(name)) => Some(intent.field(name).map_err(|e| e.to_string())?.name),
        Some(other) => {
            return Err(format!(
                "`distinct` names one field of `{intent}`, and {} was given",
                other.kind()
            ));
        }
    };
    Ok(Count {
        min,
        within_ns,
        within,
        per,
        distinct,
    })
}

fn compile_min(map: &BTreeMap<String, RawValue>) -> Result<u64, String> {
    let Some(raw) = map.get("min") else {
        return Err(
            "`count` needs `min`, how many events within the window make the block hold"
                .to_string(),
        );
    };
    let RawValue::Integer(min) = raw else {
        return Err(format!(
            "`min` is a whole number, and {} was given",
            raw.kind()
        ));
    };
    match u64::try_from(*min) {
        Ok(min) if (2..=HOST_RULE_COUNT_MIN_MAX).contains(&min) => Ok(min),
        Ok(1) => Err(
            "`min: 1` is the event itself: drop `count` and the block holds on every event"
                .to_string(),
        ),
        _ => Err(format!(
            "`min: {min}` is outside 2 to {HOST_RULE_COUNT_MIN_MAX}: every group holds up to \
             `min` events"
        )),
    }
}

/// The group one event is counted in, below its rule and block.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Group {
    Process(ProcessKey),
    Workload(String),
    Host,
}

#[derive(Debug, Clone)]
struct Window {
    within_ns: u64,
    /// Time and value of every event still inside the window, oldest
    /// first; one entry per value when the count is of distinct values.
    seen: VecDeque<(u64, u64)>,
}

impl Window {
    /// Drop the events older than the window ending at `at_ns`, and say
    /// how many went.
    fn age(&mut self, at_ns: u64) -> usize {
        let floor = at_ns.saturating_sub(self.within_ns);
        let before = self.seen.len();
        while self.seen.front().is_some_and(|(t, _)| *t < floor) {
            self.seen.pop_front();
        }
        before - self.seen.len()
    }
}

/// Every group counting now, bounded in groups and in events.
#[derive(Debug, Clone)]
pub struct WindowCounts {
    windows: HashMap<(usize, usize, Group), Window>,
    events: usize,
    key_capacity: usize,
    event_capacity: usize,
    refused: u64,
}

impl Default for WindowCounts {
    fn default() -> Self {
        Self::new(HOST_RULE_COUNT_KEYS_MAX, HOST_RULE_COUNT_EVENTS_MAX)
    }
}

impl WindowCounts {
    #[must_use]
    pub fn new(key_capacity: usize, event_capacity: usize) -> Self {
        Self {
            windows: HashMap::new(),
            events: 0,
            key_capacity,
            event_capacity,
            refused: 0,
        }
    }

    /// Groups counting now, aged ones included until the next sweep.
    #[must_use]
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }

    /// Events held in windows now.
    #[must_use]
    pub fn events(&self) -> usize {
        self.events
    }

    /// Events not counted because a bound was hit by groups still counting.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// Count `event` for block `block` of rule `rule`, and say whether this
    /// event reached `count.min`. The group starts again from nothing once
    /// it has, so one burst raises one alert per `min` events.
    ///
    /// An event with nothing to group by - no process for `per: process`,
    /// no workload for `per: workload`, no value of the `distinct` field -
    /// is not counted.
    pub(super) fn record(
        &mut self,
        (rule, block): (usize, usize),
        count: &Count,
        event: &IntentEvent,
        workload: Option<&WorkloadFacts<'_>>,
        subject: &Subject<'_>,
        at_ns: u64,
    ) -> bool {
        let group = match count.per {
            CountPer::Process => subject.process.map(Group::Process),
            CountPer::Workload => workload
                .and_then(|w| w.container_id.or(w.cgroup).or(w.unit))
                .map(|name| Group::Workload(name.to_string())),
            CountPer::Host => Some(Group::Host),
        };
        let Some(group) = group else {
            return false;
        };
        let value = match count.distinct {
            None => 0,
            Some(field) => match event.get(field) {
                Some(value) => {
                    let mut hasher = DefaultHasher::new();
                    value.hash(&mut hasher);
                    hasher.finish()
                }
                None => return false,
            },
        };
        let key = (rule, block, group);
        let known = self.windows.contains_key(&key);
        if (!known && self.windows.len() >= self.key_capacity) || self.events >= self.event_capacity
        {
            self.sweep(at_ns);
        }
        if (!known && self.windows.len() >= self.key_capacity) || self.events >= self.event_capacity
        {
            self.refused += 1;
            return false;
        }
        let window = self.windows.entry(key.clone()).or_insert_with(|| Window {
            within_ns: count.within_ns,
            seen: VecDeque::new(),
        });
        self.events -= window.age(at_ns);
        if count.distinct.is_some()
            && let Some(at) = window.seen.iter().position(|(_, v)| *v == value)
        {
            window.seen.remove(at);
            self.events -= 1;
        }
        window.seen.push_back((at_ns, value));
        self.events += 1;
        if (window.seen.len() as u64) < count.min {
            return false;
        }
        self.events -= window.seen.len();
        self.windows.remove(&key);
        true
    }

    /// Age every window to `at_ns` and drop the groups left with nothing.
    fn sweep(&mut self, at_ns: u64) {
        let mut aged = 0;
        self.windows.retain(|_, window| {
            aged += window.age(at_ns);
            !window.seen.is_empty()
        });
        self.events -= aged;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostrule::field::FieldValue;
    use crate::hostrule::rule::HostRuleSet;
    use crate::hostrule::rule::HostRuleSpec;
    use crate::hostrule::sequence::HostRuleState;

    const SECOND: u64 = 1_000_000_000;

    fn set(json: &str) -> HostRuleSet {
        let specs: Vec<HostRuleSpec> = serde_json::from_str(json).unwrap();
        HostRuleSet::compile(specs).unwrap()
    }

    fn refused(json: &str) -> String {
        let specs: Vec<HostRuleSpec> = serde_json::from_str(json).unwrap();
        HostRuleSet::compile(specs).unwrap_err().to_string()
    }

    fn start(exe: &str) -> IntentEvent {
        IntentEvent::new(Intent::ProcessStarts)
            .with("exe", FieldValue::Text(exe.to_string()))
            .unwrap()
    }

    fn process(pid: u32) -> Subject<'static> {
        Subject {
            process: Some(ProcessKey { pid, start_ns: 1 }),
            ancestors: &[],
        }
    }

    fn fires(
        rules: &HostRuleSet,
        state: &mut HostRuleState,
        event: &IntentEvent,
        subject: &Subject<'_>,
        at: u64,
    ) -> bool {
        !rules.evaluate(state, event, None, subject, at).is_empty()
    }

    fn three_in_ten_seconds(extra: &str) -> HostRuleSet {
        set(&format!(
            r#"[{{"id":"burst","when":{{"process.starts":{{
                 "count":{{"min":3,"within":"10s"{extra}}}}}}}}}]"#
        ))
    }

    #[test]
    fn min_is_reached_exactly_at_the_edge_of_the_window() {
        let rules = three_in_ten_seconds("");
        let mut state = HostRuleState::default();
        let shell = process(1);
        let event = start("/bin/sh");
        assert!(!fires(&rules, &mut state, &event, &shell, 0));
        assert!(!fires(&rules, &mut state, &event, &shell, 5 * SECOND));
        assert!(
            fires(&rules, &mut state, &event, &shell, 10 * SECOND),
            "the window is inclusive at both ends"
        );
        assert!(
            state.counts.is_empty(),
            "the group starts again after it fires"
        );
        assert_eq!(state.counts.events(), 0);
    }

    #[test]
    fn the_window_slides_rather_than_resets() {
        let rules = three_in_ten_seconds("");
        let mut state = HostRuleState::default();
        let shell = process(1);
        let event = start("/bin/sh");
        assert!(!fires(&rules, &mut state, &event, &shell, 0));
        assert!(!fires(&rules, &mut state, &event, &shell, 8 * SECOND));
        assert!(
            !fires(&rules, &mut state, &event, &shell, 11 * SECOND),
            "the first event aged out, two remain"
        );
        assert_eq!(state.counts.events(), 2);
        assert!(
            fires(&rules, &mut state, &event, &shell, 12 * SECOND),
            "a reset window would hold one event here, a sliding one holds three"
        );
    }

    #[test]
    fn per_process_counts_each_process_apart_and_per_host_counts_them_together() {
        let event = start("/bin/sh");
        let rules = three_in_ten_seconds("");
        let mut state = HostRuleState::default();
        for pid in 1..=3 {
            assert!(!fires(&rules, &mut state, &event, &process(pid), SECOND));
        }
        let rules = three_in_ten_seconds(r#","per":"host""#);
        let mut state = HostRuleState::default();
        assert!(!fires(&rules, &mut state, &event, &process(1), SECOND));
        assert!(!fires(&rules, &mut state, &event, &process(2), SECOND));
        assert!(fires(&rules, &mut state, &event, &process(3), SECOND));
    }

    #[test]
    fn per_workload_groups_by_container_and_skips_a_task_with_none() {
        let rules = three_in_ten_seconds(r#","per":"workload""#);
        let mut state = HostRuleState::default();
        let event = start("/bin/sh");
        let web = WorkloadFacts {
            container_id: Some("web"),
            ..WorkloadFacts::default()
        };
        for pid in 1..=2 {
            let fired = rules.evaluate(&mut state, &event, Some(&web), &process(pid), SECOND);
            assert!(fired.is_empty());
        }
        let fired = rules.evaluate(&mut state, &event, None, &process(9), SECOND);
        assert!(fired.is_empty(), "no workload, nothing to count by");
        let fired = rules.evaluate(&mut state, &event, Some(&web), &process(3), SECOND);
        assert_eq!(fired.len(), 1);
    }

    #[test]
    fn distinct_separates_many_writes_to_one_file_from_many_files() {
        let rules = set(r#"[{"id":"many-files","when":{"file.changes":{
                 "count":{"min":200,"within":"60s","per":"host","distinct":"path"}}}}]"#);
        let write = |path: &str| {
            IntentEvent::new(Intent::FileChanges)
                .with("path", FieldValue::Text(path.to_string()))
                .unwrap()
        };
        let mut state = HostRuleState::default();
        let nobody = Subject::default();
        for i in 0..400 {
            assert!(
                !fires(&rules, &mut state, &write("/var/log/syslog"), &nobody, i),
                "four hundred writes to one file are one distinct path"
            );
        }
        assert_eq!(state.counts.events(), 1);
        let mut fired = 0;
        for i in 0..200 {
            if fires(
                &rules,
                &mut state,
                &write(&format!("/home/a/{i}.doc")),
                &nobody,
                i,
            ) {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "the syslog path is the first of the two hundred");
        let held = state.counts.events();
        let no_path = IntentEvent::new(Intent::FileChanges);
        assert!(!fires(&rules, &mut state, &no_path, &nobody, 0));
        assert_eq!(
            state.counts.events(),
            held,
            "an event without the field is not counted"
        );
    }

    #[test]
    fn the_group_cap_is_hit_counted_and_aged_groups_make_room() {
        let rules = three_in_ten_seconds("");
        let mut state = HostRuleState {
            counts: WindowCounts::new(2, 100),
            ..HostRuleState::default()
        };
        let event = start("/bin/sh");
        for pid in 1..=3 {
            assert!(!fires(&rules, &mut state, &event, &process(pid), 0));
        }
        assert_eq!((state.counts.len(), state.counts.refused()), (2, 1));
        assert!(!fires(&rules, &mut state, &event, &process(1), 5 * SECOND));
        assert_eq!(state.counts.refused(), 1, "a known group is not refused");
        assert!(!fires(&rules, &mut state, &event, &process(3), 20 * SECOND));
        assert_eq!(
            (state.counts.len(), state.counts.refused()),
            (1, 1),
            "the aged groups were swept for the new one"
        );
    }

    #[test]
    fn a_churn_of_keys_stays_inside_both_bounds() {
        let rules = three_in_ten_seconds("");
        let mut state = HostRuleState {
            counts: WindowCounts::new(64, 96),
            ..HostRuleState::default()
        };
        let event = start("/bin/sh");
        for step in 0..10_000_u32 {
            let at = u64::from(step) * SECOND;
            fires(&rules, &mut state, &event, &process(step), at);
            assert!(state.counts.len() <= 64);
            assert!(state.counts.events() <= 96);
        }
        assert_eq!(
            state.counts.refused(),
            0,
            "about ten keys are live at once, so the sweeps always made room"
        );
    }

    #[test]
    fn the_event_cap_is_hit_and_counted() {
        let rules = set(r#"[{"id":"many","when":{"process.starts":{
                 "count":{"min":50,"within":"10s"}}}}]"#);
        let mut state = HostRuleState {
            counts: WindowCounts::new(10, 4),
            ..HostRuleState::default()
        };
        let event = start("/bin/sh");
        for _ in 0..6 {
            fires(&rules, &mut state, &event, &process(1), 0);
        }
        assert_eq!((state.counts.events(), state.counts.refused()), (4, 2));
    }

    #[test]
    fn a_count_is_refused_where_it_cannot_be_bounded_or_grouped() {
        let rule = |count: &str| {
            refused(&format!(
                r#"[{{"id":"c","when":{{"process.starts":{{"count":{count}}}}}}}]"#
            ))
        };
        for (count, expected) in [
            (r#"{"min":5}"#, "needs `within`"),
            (r#"{"within":"10s"}"#, "needs `min`"),
            (r#"{"min":1,"within":"10s"}"#, "the event itself"),
            (r#"{"min":5000,"within":"10s"}"#, "outside 2 to 1024"),
            (r#"{"min":"5","within":"10s"}"#, "whole number"),
            (r#"{"min":5,"within":"2h"}"#, "longer than an hour"),
            (r#"{"min":5,"within":"10s","per":"user"}"#, "`per: user`"),
            (r#"{"min":5,"within":"10s","distinct":"colour"}"#, "colour"),
            (r#"{"min":5,"within":"10s","max":9}"#, "`max` is none"),
            ("5", "is a map"),
        ] {
            let message = rule(count);
            assert!(message.contains(expected), "{count}: {message}");
        }
        let no_process =
            refused(r#"[{"id":"c","when":{"port.hidden":{"count":{"min":5,"within":"10s"}}}}]"#);
        assert!(no_process.contains("write `per: host`"), "{no_process}");
        let in_sequence = refused(
            r#"[{"id":"c","when":{"process.starts":{}},"followed_by":{"within":"10s",
                 "process.starts":{"count":{"min":5,"within":"10s"}}}}]"#,
        );
        assert!(
            in_sequence.contains("count the first step"),
            "{in_sequence}"
        );
        let kill_per_host = refused(
            r#"[{"id":"c","then":["alert","kill_process"],"when":{"process.starts":{
                 "count":{"min":5,"within":"10s","per":"host"}}}}]"#,
        );
        assert!(kill_per_host.contains("per: process"), "{kill_per_host}");
    }

    #[test]
    fn a_counted_first_step_opens_the_sequence_once_reached() {
        let rules = set(r#"[{"id":"burst-then-curl",
                 "when":{"process.starts":{"exe":"/bin/sh","count":{"min":2,"within":"10s"}}},
                 "followed_by":{"within":"10s","process.starts":{"exe":"/usr/bin/curl"}}}]"#);
        let mut state = HostRuleState::default();
        let shell = process(1);
        assert!(!fires(&rules, &mut state, &start("/bin/sh"), &shell, 0));
        assert!(
            !fires(&rules, &mut state, &start("/usr/bin/curl"), &shell, 1),
            "one shell is not the count"
        );
        assert!(!fires(&rules, &mut state, &start("/bin/sh"), &shell, 2));
        assert!(fires(
            &rules,
            &mut state,
            &start("/usr/bin/curl"),
            &shell,
            3
        ));
    }

    #[test]
    fn the_message_says_what_was_counted() {
        let rules = three_in_ten_seconds(r#","distinct":"exe""#);
        let rule = &rules.rules()[0];
        assert!(
            rule.message(&start("/bin/sh"))
                .ends_with(", 3 distinct exe within 10s per process"),
            "{}",
            rule.message(&start("/bin/sh"))
        );
    }
}
