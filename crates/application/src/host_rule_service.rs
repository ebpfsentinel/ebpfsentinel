//! Evaluating host rules against what the process table learns.
//!
//! The process table is the one place in the agent that hears of every exec
//! and every exit with the binary, the user and the parent already
//! resolved, so the events of `process.starts` and `process.ends` are built
//! there and handed here. Each event is evaluated against every rule
//! naming its intention, and against the first steps of sequences waiting
//! for its process or one above it; a match becomes an alert carrying the
//! process and its ancestry, and a rule asking for it stops the process
//! through the same kill the process detections use.
//!
//! The file watch hands its settled changes here the same way: the file
//! intentions arrive carrying the path as the writer sees it, and the writer
//! and its ancestry as the process table holds them. A change whose writer
//! the table no longer holds is evaluated without one, so a rule on the
//! writer's fields does not match it and no process is stopped for it.
//!
//! A rule in shadow, the default, does neither: what it would have done is
//! counted per workload in a reading, and putting it in force is decided on
//! that reading.
//!
//! Only the intentions in [`FED_INTENTS`] reach this service in this build.
//! A rule naming another one loads, and the API says it is not applicable
//! here rather than letting it sit silent.

use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;

use domain::alert::entity::Alert;
use std::sync::{Arc, Mutex, PoisonError};

use domain::firewall::entity::RuleMode;
use domain::hostrule::{
    FieldValue, HostRuleException, HostRuleSet, HostRuleState, HostShadowBook, HostShadowReading,
    Intent, IntentEvent, PromotionRefused, Subject,
};
use domain::process::engine::Lineage;
use domain::process::entity::{ProcessEntry, ProcessKey};
use domain::workload::entity::{Workload, WorkloadSource};
use ports::secondary::process_facts_port::ProcessFactsReader;
use tokio::sync::mpsc;
use tracing::warn;

use crate::alert_event::AlertEvent;
use crate::workload_policy_service::{ResolvedWorkload, workload_of};

/// The intentions a source in this build delivers to host rules.
pub const FED_INTENTS: &[Intent] = &[
    Intent::ProcessStarts,
    Intent::ProcessEnds,
    Intent::FileChanges,
    Intent::FileAppears,
    Intent::FileDisappears,
    Intent::FilePermissionsChange,
    Intent::FileIntegrityBreaks,
];

/// Why an intention outside [`FED_INTENTS`] is not applicable.
#[must_use]
pub fn not_fed_reason(intent: Intent) -> String {
    format!("no source in this build delivers `{intent}` events to host rules")
}

/// What the rules remember between events, and what a bound turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HostRuleMemory {
    /// First steps of sequences waiting for their second.
    pub pending: usize,
    /// First steps not held because the set of waiting ones was full.
    pub pending_refused: u64,
    /// Groups a count is running for.
    pub counting: usize,
    /// Events not counted because the groups or the events held were at
    /// their bound.
    pub counting_refused: u64,
}

/// The host rules and where their alerts go.
pub struct HostRuleService {
    rules: ArcSwap<HostRuleSet>,
    alerts: mpsc::Sender<AlertEvent>,
    facts: Option<Arc<dyn ProcessFactsReader>>,
    state: Mutex<HostRuleState>,
    shadow: Mutex<HostShadowBook>,
    exceptions: ArcSwap<Vec<HostRuleException>>,
    matched: AtomicU64,
    dropped: AtomicU64,
    exempted: AtomicU64,
}

impl HostRuleService {
    #[must_use]
    pub fn new(rules: HostRuleSet, alerts: mpsc::Sender<AlertEvent>) -> Self {
        Self {
            shadow: Mutex::new(HostShadowBook::new(&rules, now_ns())),
            rules: ArcSwap::from_pointee(rules),
            alerts,
            facts: None,
            state: Mutex::new(HostRuleState::default()),
            exceptions: ArcSwap::from_pointee(Vec::new()),
            matched: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            exempted: AtomicU64::new(0),
        }
    }

    /// Read whether an executable is still on disk through `reader`, and
    /// only for an exec some rule asks it of.
    #[must_use]
    pub fn with_facts(mut self, reader: Arc<dyn ProcessFactsReader>) -> Self {
        self.facts = Some(reader);
        self
    }

    /// The loaded rules.
    #[must_use]
    pub fn rules(&self) -> Arc<HostRuleSet> {
        self.rules.load_full()
    }

    /// Evaluate `rules` from now on, in place of the ones loaded.
    ///
    /// The readings start again, because a reading of the old set says
    /// nothing of the new one, and a rule promoted here stays in force only
    /// where the new set carries it written exactly as it was. What the old
    /// rules were waiting for or counting is dropped with them.
    pub fn replace(&self, rules: HostRuleSet) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let previous = self.rules.swap(Arc::new(rules));
        let next = self.rules.load();
        let mut book = self.book();
        *book = book.renewed(&previous, &next, now_ns());
        *state = HostRuleState::default();
    }

    /// Leave the workloads `exceptions` select alone from now on, in place
    /// of the exceptions held. The rules and their readings are untouched:
    /// an exception decides what a match does, not what matches.
    pub fn set_exceptions(&self, exceptions: Vec<HostRuleException>) {
        self.exceptions.store(Arc::new(exceptions));
    }

    /// The exceptions in force.
    #[must_use]
    pub fn exceptions(&self) -> Arc<Vec<HostRuleException>> {
        self.exceptions.load_full()
    }

    /// How many matches an exception left alone.
    #[must_use]
    pub fn exempted(&self) -> u64 {
        self.exempted.load(Ordering::Relaxed)
    }

    /// How many events matched a rule, and how many of those alerts were
    /// lost to a full alert queue.
    #[must_use]
    pub fn counts(&self) -> (u64, u64) {
        (
            self.matched.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// What the rules remember between events.
    #[must_use]
    pub fn memory(&self) -> HostRuleMemory {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        HostRuleMemory {
            pending: state.sequences.len(),
            pending_refused: state.sequences.refused(),
            counting: state.counts.len(),
            counting_refused: state.counts.refused(),
        }
    }

    /// The mode `id` is in now, `None` for no such rule.
    #[must_use]
    pub fn mode(&self, id: &str) -> Option<RuleMode> {
        self.book().mode(id)
    }

    /// When the shadow readings started, wall clock nanoseconds.
    #[must_use]
    pub fn shadow_since_ns(&self) -> u64 {
        self.book().since_ns()
    }

    /// Put `id` in force on the reading that started at `seen_since_ns`.
    ///
    /// Returns when the readings started and the reading the rule stopped
    /// counting on. The flip and the reading are taken under one lock, so no
    /// event lands between what is recorded and what is decided.
    ///
    /// # Errors
    ///
    /// [`PromotionRefused`] for an unknown rule, one already in force, or a
    /// reading that started at another time.
    pub fn promote(
        &self,
        id: &str,
        seen_since_ns: u64,
    ) -> Result<(u64, HostShadowReading), PromotionRefused> {
        let mut book = self.book();
        let since_ns = book.since_ns();
        book.promote(id, seen_since_ns)
            .map(|reading| (since_ns, reading))
    }

    /// What `id` would have done since the readings started, `None` for a
    /// rule in force.
    #[must_use]
    pub fn reading(&self, id: &str) -> Option<HostShadowReading> {
        self.book().reading(id).cloned()
    }

    // The book is a mode per rule and a few counters, each written in one
    // statement: a panic elsewhere leaves nothing half done in it.
    fn book(&self) -> std::sync::MutexGuard<'_, HostShadowBook> {
        self.shadow.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether any rule names `intent`, so the table can skip the lineage
    /// walk for an event nobody asks about.
    #[must_use]
    pub fn wants(&self, intent: Intent) -> bool {
        self.rules.load().names(intent)
    }

    /// An exec the process table has recorded, with its ancestry, the
    /// parent first, as the table holds it.
    pub fn record_exec(&self, entry: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        if !self.rules.load().names(Intent::ProcessStarts) {
            return;
        }
        let event = self.starts_event(entry, lineage.ancestors.first());
        self.evaluate(&event, Some((entry, lineage)), at_ns);
    }

    /// An exit the process table has purged, with the entry it held.
    pub fn record_exit(&self, entry: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        if !self.rules.load().names(Intent::ProcessEnds) {
            return;
        }
        let event = with_process(IntentEvent::new(Intent::ProcessEnds), entry);
        self.evaluate(&event, Some((entry, lineage)), at_ns);
    }

    /// A change to a watched file, with the process that made it and its
    /// ancestry where the process table knows it. The event carries the
    /// file's own fields; the writer's executable and user are added here.
    pub fn record_file(
        &self,
        event: IntentEvent,
        writer: Option<(&ProcessEntry, &Lineage)>,
        at_ns: u64,
    ) {
        if !self.rules.load().names(event.intent()) {
            return;
        }
        let event = match writer {
            Some((entry, _)) => with_process(event, entry),
            None => event,
        };
        self.evaluate(&event, writer, at_ns);
    }

    fn starts_event(&self, entry: &ProcessEntry, parent: Option<&ProcessEntry>) -> IntentEvent {
        let mut event = with_process(IntentEvent::new(Intent::ProcessStarts), entry);
        if let Some(line) = &entry.command_line {
            event = set(event, "command_line", FieldValue::Text(line.clone()));
        }
        if self
            .rules
            .load()
            .reads(Intent::ProcessStarts, "exe_on_disk")
            && let Some(facts) = self.facts.as_ref().and_then(|r| r.read_facts(entry.pid))
        {
            event = set(event, "exe_on_disk", FieldValue::Boolean(!facts.fileless));
        }
        if let Some(parent) = parent {
            if let Some(path) = parent.identity.path() {
                event = set(event, "parent_exe", FieldValue::Text(path.to_owned()));
            }
            event = set(
                event,
                "parent_uid",
                FieldValue::Integer(i64::from(parent.uid)),
            );
        }
        event
    }

    fn evaluate(
        &self,
        event: &IntentEvent,
        process: Option<(&ProcessEntry, &Lineage)>,
        at_ns: u64,
    ) {
        // A change whose writer the table never heard of, or has forgotten,
        // is still evaluated: on the file's own fields, with no workload for
        // a selector to match and nobody to stop.
        let resolved = process.map_or_else(ResolvedWorkload::default, |(entry, lineage)| {
            workload_of(entry).with_ancestry(lineage)
        });
        let facts = resolved.facts();
        let ancestors: Vec<ProcessKey> = process.map_or_else(Vec::new, |(_, lineage)| {
            lineage.ancestors.iter().map(ProcessEntry::key).collect()
        });
        let subject = Subject {
            process: process.map(|(entry, _)| entry.key()),
            ancestors: &ancestors,
        };
        // A waiting step is written in one insert, and a count's window
        // and the tally of events it holds can disagree at worst by the
        // one event being recorded, which only moves when a bound is hit:
        // nothing a panic elsewhere could leave is worth refusing to
        // evaluate the next event for.
        // The rules are read under the state's lock, which a replacement
        // also takes, so the state an evaluation writes is always the one
        // of the set it evaluated.
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let rules = self.rules.load_full();
        let fired = rules.evaluate(&mut state, event, Some(&facts), &subject, at_ns);
        drop(state);
        let exceptions = self.exceptions.load();
        for rule in fired {
            self.matched.fetch_add(1, Ordering::Relaxed);
            if exceptions
                .iter()
                .any(|exception| exception.silences(rule.id(), &facts))
            {
                self.exempted.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let hit = facts.container_id.or(facts.cgroup).or(facts.unit);
            {
                // A set replaced since this one was evaluated may no longer
                // carry the rule: it then does nothing rather than act in a
                // mode nobody chose for it.
                let mut book = self.book();
                match book.mode(rule.id()) {
                    None => continue,
                    Some(RuleMode::Shadow) => {
                        book.record(rule.id(), hit);
                        continue;
                    }
                    Some(RuleMode::Enforce) => {}
                }
            }
            let workload = process.and_then(|(entry, lineage)| {
                Workload::new(entry.pid, WorkloadSource::Process)
                    .map(|w| w.with_process(entry).with_lineage(lineage))
            });
            let alert = Alert::from_host_rule(rule, event, workload, at_ns);
            let sent = self.alerts.try_send(AlertEvent::ProcessDetection {
                alert: Box::new(alert),
                kill_process: rule.kills() && process.is_some(),
            });
            if sent.is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                warn!(
                    rule = rule.id(),
                    pid = process.map_or(0, |(entry, _)| entry.pid),
                    "host rule matched and the alert queue is full: the alert is lost"
                );
            }
        }
    }
}

/// Wall clock nanoseconds, where the readings are dated from.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// The fields every process intention takes from the entry.
fn with_process(event: IntentEvent, entry: &ProcessEntry) -> IntentEvent {
    let event = match entry.identity.path() {
        Some(path) => set(event, "exe", FieldValue::Text(path.to_owned())),
        None => event,
    };
    set(event, "uid", FieldValue::Integer(i64::from(entry.uid)))
}

/// `event` with `name` set, or unchanged where the registry refuses it. The
/// names here are the registry's own, so a refusal is a field renamed in
/// the domain without this file, which the tests below would catch first.
fn set(event: IntentEvent, name: &str, value: FieldValue) -> IntentEvent {
    match event.clone().with(name, value) {
        Ok(next) => next,
        Err(err) => {
            warn!(error = %err, "host rule event field refused");
            event
        }
    }
}

#[cfg(test)]
mod tests {
    use domain::container::entity::{ContainerContext, ContainerInfo, ContainerRuntime};
    use domain::hostrule::HostRuleSpec;
    use domain::process::detection::ProcessFacts;
    use domain::process::entity::ProcessIdentity;

    use super::*;

    /// The rules in `json`, in force unless one names its mode.
    fn rules(json: &str) -> HostRuleSet {
        let mut raw: Vec<serde_json::Value> = serde_json::from_str(json).unwrap();
        for rule in &mut raw {
            if let Some(map) = rule.as_object_mut() {
                map.entry("mode").or_insert_with(|| "enforce".into());
            }
        }
        let specs: Vec<HostRuleSpec> = serde_json::from_value(raw.into()).unwrap();
        HostRuleSet::compile(specs).unwrap()
    }

    #[test]
    fn a_shadow_rule_counts_by_workload_and_raises_nothing() {
        let (tx, mut rx) = mpsc::channel(4);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"quiet","mode":"shadow","then":["alert","kill_process"],
                     "when":{"process.starts":{"exe":"/bin/sh"}}}]"#,
            ),
            tx,
        );
        let mut shell = entry(4, "/bin/sh", 0);
        shell.container = Some(ContainerContext::new(ContainerInfo::Container {
            container_id: "web".to_string(),
            runtime: ContainerRuntime::Containerd,
            cgroup_path: "/kubepods/web".to_string(),
            pid: 4,
        }));
        service.record_exec(&shell, &Lineage::default(), 1);
        service.record_exec(&entry(5, "/bin/sh", 0), &Lineage::default(), 2);
        assert!(
            rx.try_recv().is_err(),
            "a shadow rule raises nothing and stops nothing"
        );
        assert_eq!(service.mode("quiet"), Some(RuleMode::Shadow));
        let reading = service.reading("quiet").unwrap();
        assert_eq!(reading.events, 2);
        assert_eq!(reading.workloads[0].workload.as_deref(), Some("web"));
        assert_eq!(reading.workloads[1].workload, None);
    }

    #[test]
    fn a_promoted_rule_raises_what_it_used_to_count() {
        let (tx, mut rx) = mpsc::channel(4);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"quiet","mode":"shadow","when":{"process.starts":{"exe":"/bin/sh"}}}]"#,
            ),
            tx,
        );
        service.record_exec(&entry(4, "/bin/sh", 0), &Lineage::default(), 1);
        assert!(rx.try_recv().is_err());
        let since = service.shadow_since_ns();
        assert_eq!(
            service.promote("quiet", since + 5_000),
            Err(PromotionRefused::StaleReading { since_ns: since })
        );
        let (at, reading) = service.promote("quiet", since).unwrap();
        assert_eq!((at, reading.events), (since, 1));
        assert_eq!(service.mode("quiet"), Some(RuleMode::Enforce));
        service.record_exec(&entry(5, "/bin/sh", 0), &Lineage::default(), 2);
        assert!(rx.try_recv().is_ok(), "a rule in force raises");
    }

    #[test]
    fn a_replaced_set_is_evaluated_and_keeps_a_promotion_of_an_unchanged_rule() {
        let (tx, mut rx) = mpsc::channel(4);
        let quiet = r#"{"id":"quiet","mode":"shadow","when":{"process.starts":{"exe":"/bin/sh"}}}"#;
        let service = HostRuleService::new(rules(&format!("[{quiet}]")), tx);
        let since = service.shadow_since_ns();
        service.promote("quiet", since).unwrap();
        service.replace(rules(&format!(
            r#"[{quiet},{{"id":"curl","mode":"shadow","when":{{"process.starts":{{"exe":"/usr/bin/curl"}}}}}}]"#
        )));
        assert_eq!(service.rules().rules().len(), 2);
        assert_eq!(service.mode("quiet"), Some(RuleMode::Enforce));
        assert_eq!(service.mode("curl"), Some(RuleMode::Shadow));
        service.record_exec(&entry(6, "/usr/bin/curl", 0), &Lineage::default(), 3);
        assert!(rx.try_recv().is_err(), "a new rule starts in shadow");
        assert_eq!(service.reading("curl").unwrap().events, 1);
        service.replace(rules("[]"));
        service.record_exec(&entry(7, "/bin/sh", 0), &Lineage::default(), 4);
        assert!(rx.try_recv().is_err(), "a rule taken away does nothing");
        assert_eq!(service.mode("quiet"), None);
    }

    #[test]
    fn an_exception_leaves_its_workload_without_alert_or_reading() {
        let (tx, mut rx) = mpsc::channel(4);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"loud","mode":"enforce","when":{"process.starts":{"exe":"/bin/sh"}}},
                    {"id":"quiet","mode":"shadow","when":{"process.starts":{"exe":"/bin/sh"}}}]"#,
            ),
            tx,
        );
        let make = Lineage {
            ancestors: Vec::new(),
            ..Lineage::default()
        };
        let selector = serde_json::from_str(r#"{"exe":"/bin/sh"}"#).unwrap();
        service.set_exceptions(vec![
            HostRuleException::new("shells", Vec::new(), selector).unwrap(),
        ]);
        service.record_exec(&entry(8, "/bin/sh", 0), &make, 1);
        assert!(rx.try_recv().is_err(), "an exempted match sends nothing");
        assert_eq!(service.reading("quiet").unwrap().events, 0);
        assert_eq!(service.exempted(), 2);

        service.set_exceptions(Vec::new());
        service.record_exec(&entry(9, "/bin/sh", 0), &make, 2);
        assert_eq!(take(&mut rx).len(), 1);
        assert_eq!(service.reading("quiet").unwrap().events, 1);
    }

    fn entry(pid: u32, exe: &str, uid: u32) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "x".to_string(), 1);
        entry.identity = ProcessIdentity::Path {
            path: exe.to_string(),
            dev: 1,
            inode: u64::from(pid),
        };
        entry.uid = uid;
        entry
    }

    fn lineage_of(parent: ProcessEntry) -> Lineage {
        Lineage {
            ancestors: vec![parent],
            ..Lineage::default()
        }
    }

    struct Fileless;
    impl ProcessFactsReader for Fileless {
        fn read_facts(&self, _pid: u32) -> Option<ProcessFacts> {
            Some(ProcessFacts {
                streams_on_socket: false,
                fileless: true,
            })
        }
    }

    fn take(rx: &mut mpsc::Receiver<AlertEvent>) -> Vec<(Alert, bool)> {
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            match event {
                AlertEvent::ProcessDetection {
                    alert,
                    kill_process,
                } => out.push((*alert, kill_process)),
                _ => panic!("host rules send process detections only"),
            }
        }
        out
    }

    #[test]
    fn a_count_fires_on_the_event_that_reaches_it() {
        let (tx, mut rx) = mpsc::channel(4);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"fork-burst","when":{"process.starts":{
                     "count":{"min":3,"within":"10s","per":"host"}}}}]"#,
            ),
            tx,
        );
        for pid in 1..=2 {
            service.record_exec(
                &entry(pid, "/bin/true", 0),
                &Lineage::default(),
                u64::from(pid),
            );
            assert!(rx.try_recv().is_err());
        }
        assert_eq!(service.memory().counting, 1);
        service.record_exec(&entry(3, "/bin/true", 0), &Lineage::default(), 3);
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("expected one alert");
        };
        assert!(
            alert.message.ends_with(", 3 events within 10s per host"),
            "{}",
            alert.message
        );
        assert_eq!(service.memory(), HostRuleMemory::default());
    }

    #[test]
    fn a_sequence_closes_on_a_child_and_reports_what_waits() {
        let (tx, mut rx) = mpsc::channel(4);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"shell-then-curl","when":{"process.starts":{"exe":"/bin/sh"}},
                     "followed_by":{"within":"10s","process.starts":{"exe":"/usr/bin/curl"}}}]"#,
            ),
            tx,
        );
        let shell = entry(10, "/bin/sh", 0);
        service.record_exec(&shell, &Lineage::default(), 1_000);
        assert!(rx.try_recv().is_err());
        assert_eq!(service.memory().pending, 1);
        let curl = entry(11, "/usr/bin/curl", 0);
        let lineage = Lineage {
            ancestors: vec![shell],
            ..Lineage::default()
        };
        service.record_exec(&curl, &lineage, 2_000);
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("expected one alert");
        };
        assert_eq!(alert.rule_id.0, "shell-then-curl");
        assert!(
            alert.message.contains("after process.starts within 10s"),
            "{}",
            alert.message
        );
        assert_eq!(service.memory(), HostRuleMemory::default());
    }

    #[test]
    fn every_fed_intent_carries_the_fields_built_here() {
        for intent in FED_INTENTS {
            for name in ["exe", "uid"] {
                assert!(intent.field(name).is_ok(), "{intent} lost `{name}`");
            }
        }
        for name in ["command_line", "exe_on_disk", "parent_exe", "parent_uid"] {
            assert!(Intent::ProcessStarts.field(name).is_ok(), "lost `{name}`");
        }
    }

    #[test]
    fn a_start_matching_a_rule_raises_one_alert_carrying_the_process() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"shell-from-web","severity":"high","then":["alert","kill_process"],
                "when":{"process.starts":{"exe":"/bin/sh","uid_ne_field":"parent_uid"}}}]"#,
            ),
            tx,
        );
        let child = entry(20, "/bin/sh", 0);
        let parent = entry(10, "/usr/sbin/nginx", 33);
        service.record_exec(&child, &lineage_of(parent), 5);
        let alerts = take(&mut rx);
        assert_eq!(alerts.len(), 1);
        let (alert, kill) = &alerts[0];
        assert!(kill);
        assert_eq!(alert.rule_id.0, "shell-from-web");
        assert_eq!(alert.workload.as_ref().map(|w| w.pid), Some(20));
        assert!(alert.message.contains("parent_exe=/usr/sbin/nginx"));
        assert_eq!(service.counts(), (1, 0));

        // The same uid as the parent is no match.
        let same = entry(10, "/usr/sbin/nginx", 0);
        service.record_exec(&child, &lineage_of(same), 6);
        assert!(take(&mut rx).is_empty());
        // No parent read is no parent_uid, and no difference.
        service.record_exec(&child, &Lineage::default(), 7);
        assert!(take(&mut rx).is_empty());
    }

    #[test]
    fn exe_on_disk_is_read_only_when_a_rule_asks_for_it() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = HostRuleService::new(
            rules(r#"[{"id":"fileless","when":{"process.starts":{"exe_on_disk":false}}}]"#),
            tx.clone(),
        )
        .with_facts(Arc::new(Fileless));
        service.record_exec(&entry(1, "/x", 0), &Lineage::default(), 1);
        assert_eq!(take(&mut rx).len(), 1);

        let quiet = HostRuleService::new(
            rules(r#"[{"id":"x","when":{"process.starts":{"exe":"/x"}}}]"#),
            tx,
        )
        .with_facts(Arc::new(Fileless));
        let event = quiet.starts_event(&entry(1, "/x", 0), None);
        assert!(event.get("exe_on_disk").is_none());
    }

    #[test]
    fn an_exit_is_matched_by_process_ends_rules_only() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"ends","when":{"process.ends":{"exe_matches":"/tmp/*"}}},
                    {"id":"starts","when":{"process.starts":{"exe_matches":"/tmp/*"}}}]"#,
            ),
            tx,
        );
        service.record_exit(&entry(3, "/tmp/a", 0), &Lineage::default(), 9);
        let alerts = take(&mut rx);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].0.rule_id.0, "ends");
        assert!(!alerts[0].1);
    }

    #[test]
    fn a_workload_selector_is_decided_on_the_process_and_its_ancestry() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = HostRuleService::new(
            rules(
                r#"[{"id":"under-nginx","workload":{"ancestor":"/usr/sbin/nginx"},
                    "when":{"process.starts":{}}}]"#,
            ),
            tx,
        );
        let lineage = Lineage {
            ancestors: vec![entry(10, "/usr/sbin/nginx", 33)],
            ..Lineage::default()
        };
        service.record_exec(&entry(20, "/bin/sh", 33), &lineage, 1);
        assert_eq!(take(&mut rx).len(), 1);
        service.record_exec(&entry(21, "/bin/sh", 33), &Lineage::default(), 2);
        assert!(take(&mut rx).is_empty());
    }

    #[test]
    fn a_full_queue_loses_the_alert_and_counts_it() {
        let (tx, _rx) = mpsc::channel(1);
        let service =
            HostRuleService::new(rules(r#"[{"id":"all","when":{"process.starts":{}}}]"#), tx);
        for at in 0..3 {
            service.record_exec(&entry(1, "/x", 0), &Lineage::default(), at);
        }
        assert_eq!(service.counts(), (3, 2));
    }

    #[test]
    fn no_rule_on_an_intent_builds_no_event() {
        let (tx, mut rx) = mpsc::channel(8);
        let service = HostRuleService::new(HostRuleSet::default(), tx);
        service.record_exec(&entry(1, "/x", 0), &Lineage::default(), 1);
        service.record_exit(&entry(1, "/x", 0), &Lineage::default(), 2);
        assert!(take(&mut rx).is_empty());
        assert_eq!(service.counts(), (0, 0));
    }
}
