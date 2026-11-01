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
//! Only the intentions in [`FED_INTENTS`] reach this service in this build.
//! A rule naming another one loads, and the API says it is not applicable
//! here rather than letting it sit silent.

use std::sync::atomic::{AtomicU64, Ordering};

use domain::alert::entity::Alert;
use std::sync::{Arc, Mutex, PoisonError};

use domain::hostrule::{FieldValue, HostRuleSet, Intent, IntentEvent, PendingSequences, Subject};
use domain::process::engine::Lineage;
use domain::process::entity::{ProcessEntry, ProcessKey};
use domain::workload::entity::{Workload, WorkloadSource};
use ports::secondary::process_facts_port::ProcessFactsReader;
use tokio::sync::mpsc;
use tracing::warn;

use crate::alert_event::AlertEvent;
use crate::workload_policy_service::workload_of;

/// The intentions a source in this build delivers to host rules.
pub const FED_INTENTS: &[Intent] = &[Intent::ProcessStarts, Intent::ProcessEnds];

/// Why an intention outside [`FED_INTENTS`] is not applicable.
#[must_use]
pub fn not_fed_reason(intent: Intent) -> String {
    format!("no source in this build delivers `{intent}` events to host rules")
}

/// The host rules and where their alerts go.
pub struct HostRuleService {
    rules: HostRuleSet,
    alerts: mpsc::Sender<AlertEvent>,
    facts: Option<Arc<dyn ProcessFactsReader>>,
    pending: Mutex<PendingSequences>,
    matched: AtomicU64,
    dropped: AtomicU64,
}

impl HostRuleService {
    #[must_use]
    pub fn new(rules: HostRuleSet, alerts: mpsc::Sender<AlertEvent>) -> Self {
        Self {
            rules,
            alerts,
            facts: None,
            pending: Mutex::new(PendingSequences::default()),
            matched: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
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
    pub fn rules(&self) -> &HostRuleSet {
        &self.rules
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

    /// First steps of sequences waiting now, and first steps not held
    /// because the bounded set was full.
    #[must_use]
    pub fn pending(&self) -> (usize, u64) {
        let pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        (pending.len(), pending.refused())
    }

    /// Whether any rule names `intent`, so the table can skip the lineage
    /// walk for an event nobody asks about.
    #[must_use]
    pub fn wants(&self, intent: Intent) -> bool {
        self.rules.names(intent)
    }

    /// An exec the process table has recorded, with its ancestry, the
    /// parent first, as the table holds it.
    pub fn record_exec(&self, entry: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        if !self.rules.names(Intent::ProcessStarts) {
            return;
        }
        let event = self.starts_event(entry, lineage.ancestors.first());
        self.evaluate(&event, entry, lineage, at_ns);
    }

    /// An exit the process table has purged, with the entry it held.
    pub fn record_exit(&self, entry: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        if !self.rules.names(Intent::ProcessEnds) {
            return;
        }
        let event = with_process(IntentEvent::new(Intent::ProcessEnds), entry);
        self.evaluate(&event, entry, lineage, at_ns);
    }

    fn starts_event(&self, entry: &ProcessEntry, parent: Option<&ProcessEntry>) -> IntentEvent {
        let mut event = with_process(IntentEvent::new(Intent::ProcessStarts), entry);
        if let Some(line) = &entry.command_line {
            event = set(event, "command_line", FieldValue::Text(line.clone()));
        }
        if self.rules.reads(Intent::ProcessStarts, "exe_on_disk")
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

    fn evaluate(&self, event: &IntentEvent, entry: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        let resolved = workload_of(entry).with_ancestry(lineage);
        let facts = resolved.facts();
        let ancestors: Vec<ProcessKey> = lineage.ancestors.iter().map(ProcessEntry::key).collect();
        let subject = Subject {
            process: Some(entry.key()),
            ancestors: &ancestors,
        };
        // Every entry of the set is a whole waiting step, written in one
        // insert, so a panic elsewhere leaves nothing half-written to
        // recover from.
        let fired = {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            self.rules
                .evaluate(&mut pending, event, Some(&facts), &subject, at_ns)
        };
        for rule in fired {
            self.matched.fetch_add(1, Ordering::Relaxed);
            let workload = Workload::new(entry.pid, WorkloadSource::Process)
                .map(|w| w.with_process(entry).with_lineage(lineage));
            let alert = Alert::from_host_rule(rule, event, workload, at_ns);
            let sent = self.alerts.try_send(AlertEvent::ProcessDetection {
                alert: Box::new(alert),
                kill_process: rule.kills(),
            });
            if sent.is_err() {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                warn!(
                    rule = rule.id(),
                    pid = entry.pid,
                    "host rule matched and the alert queue is full: the alert is lost"
                );
            }
        }
    }
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
    use domain::hostrule::HostRuleSpec;
    use domain::process::detection::ProcessFacts;
    use domain::process::entity::ProcessIdentity;

    use super::*;

    fn rules(json: &str) -> HostRuleSet {
        let specs: Vec<HostRuleSpec> = serde_json::from_str(json).unwrap();
        HostRuleSet::compile(specs).unwrap()
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
        assert_eq!(service.pending(), (1, 0));
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
        assert_eq!(service.pending(), (0, 0));
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
