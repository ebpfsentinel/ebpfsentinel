//! Mass encryption: the signals each reader produces, composed per actor
//! into one verdict, and the verdict raised as an alert.
//!
//! The readers stay where their reading lives - the file watcher hands every
//! settled change here - and nothing here decides a signal's weight: that is
//! the tier table in the domain. What this service adds is the lock around
//! the engine, the host's own account of which sources it reads, and the
//! alert channel.

use std::sync::{Arc, Mutex, PoisonError};

use domain::alert::entity::Alert;
use domain::file_watch::entity::FileChangeKind;
use domain::hostrule::HostSources;
use domain::process::engine::Lineage;
use domain::process::entity::ProcessEntry;
use domain::ransom::{
    Actor, DistinctPaths, RansomEngine, RansomSignal, RansomVerdict, SignalKind, actor_of,
    entropy_rose, header_mismatch, unavailable,
};
use domain::workload::entity::{Workload, WorkloadSource};
use tokio::sync::mpsc;
use tracing::warn;

use crate::alert_event::AlertEvent;

/// What this host reports reading, asked when a verdict is reached.
pub type HostSourcesReader = Arc<dyn Fn() -> HostSources + Send + Sync>;

/// The signals this agent produces today. A signal missing here is named in
/// every verdict as not read, so a verdict never reads as the whole engine
/// when part of it is absent.
const READ: &[SignalKind] = &[
    SignalKind::DistinctRewrites,
    SignalKind::EntropyRise,
    SignalKind::HeaderMismatch,
];

/// Whether a settled change rewrote the file's content or put a file in its
/// place, which is what an encryption run does to every file it touches.
fn rewrites(kinds: impl IntoIterator<Item = FileChangeKind>) -> bool {
    kinds.into_iter().any(|kind| {
        matches!(
            kind,
            FileChangeKind::Written | FileChangeKind::Created | FileChangeKind::MovedIn
        )
    })
}

/// One settled change to a file: its path, its sampled entropy before and
/// after where both readings measured one, and its first four bytes now.
#[derive(Debug, Clone, Copy)]
pub struct FileRewrite<'a> {
    pub path: &'a str,
    pub entropy_before: Option<u16>,
    pub entropy_now: Option<u16>,
    pub head: Option<[u8; 4]>,
}

/// One change as every counter records it.
struct Held<'a> {
    actor: &'a Actor,
    writer: &'a ProcessEntry,
    lineage: &'a Lineage,
    path: &'a str,
    at_ns: u64,
}

pub struct RansomService {
    engine: Mutex<RansomEngine>,
    rewrites: Mutex<DistinctPaths>,
    entropy_rises: Mutex<DistinctPaths>,
    header_mismatches: Mutex<DistinctPaths>,
    sources: HostSourcesReader,
    alerts: mpsc::Sender<AlertEvent>,
}

impl RansomService {
    #[must_use]
    pub fn new(alerts: mpsc::Sender<AlertEvent>, sources: HostSourcesReader) -> Self {
        Self {
            engine: Mutex::new(RansomEngine::default()),
            rewrites: Mutex::new(DistinctPaths::rewrites()),
            entropy_rises: Mutex::new(DistinctPaths::entropy_rises()),
            header_mismatches: Mutex::new(DistinctPaths::header_mismatches()),
            sources,
            alerts,
        }
    }

    /// A settled change by `writer`, as the file watcher reports it.
    /// Changes that rewrite nothing are not counted.
    pub fn record_file_change(
        &self,
        writer: &ProcessEntry,
        lineage: &Lineage,
        kinds: impl IntoIterator<Item = FileChangeKind>,
        change: FileRewrite<'_>,
        at_ns: u64,
    ) {
        if !rewrites(kinds) {
            return;
        }
        let actor = actor_of(writer, lineage);
        let held = Held {
            actor: &actor,
            writer,
            lineage,
            path: change.path,
            at_ns,
        };
        self.count(&self.rewrites, &held);
        if entropy_rose(change.entropy_before, change.entropy_now) {
            self.count(&self.entropy_rises, &held);
        }
        if header_mismatch(change.path, change.head) {
            self.count(&self.header_mismatches, &held);
        }
    }

    /// Count the path toward its actor on one counter, and observe the
    /// signal that counter raises.
    fn count(&self, counter: &Mutex<DistinctPaths>, held: &Held<'_>) {
        let raised = counter
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .record(held.actor, held.writer.pid, held.path, held.at_ns);
        if let Some(signal) = raised {
            self.observe(signal, held.writer, held.lineage);
        }
    }

    /// Hold `signal`, produced by `writer`, and raise the verdict if its
    /// actor now reaches one.
    fn observe(&self, signal: RansomSignal, writer: &ProcessEntry, lineage: &Lineage) {
        let at_ns = signal.at_ns;
        let verdict = self
            .engine
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(signal, || unavailable(&(self.sources)(), READ));
        if let Some(verdict) = verdict {
            self.raise(&verdict, writer, lineage, at_ns);
        }
    }

    fn raise(&self, verdict: &RansomVerdict, writer: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        let workload = actor_workload(verdict, writer, lineage);
        let alert = Alert::from_ransom_verdict(verdict, workload, at_ns);
        let sent = self.alerts.try_send(AlertEvent::ProcessDetection {
            alert: Box::new(alert),
            kill_process: false,
        });
        if sent.is_err() {
            warn!(
                actor = verdict.actor.pid,
                "mass encryption verdict dropped: the alert channel is full or closed"
            );
        }
    }
}

/// The actor as a workload: the writer itself, or the ancestor the actor
/// names, with the ancestry above it.
fn actor_workload(
    verdict: &RansomVerdict,
    writer: &ProcessEntry,
    lineage: &Lineage,
) -> Option<Workload> {
    let key = verdict.actor.key;
    let (entry, above) = if writer.key() == key {
        (writer, lineage.clone())
    } else {
        let at = lineage.ancestors.iter().position(|a| a.key() == key)?;
        (
            &lineage.ancestors[at],
            Lineage {
                ancestors: lineage.ancestors[at + 1..].to_vec(),
                truncated: lineage.truncated,
                incomplete: lineage.incomplete,
            },
        )
    };
    Workload::new(entry.pid, WorkloadSource::Process)
        .map(|w| w.with_process(entry).with_lineage(&above))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::hostrule::Source;
    use domain::process::entity::ProcessIdentity;
    use domain::ransom::{
        RANSOM_DISTINCT_REWRITES, RANSOM_ENTROPY_RISES, RANSOM_HEADER_MISMATCHES,
    };

    fn running(pid: u32, path: &str, inode: u64) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "p", u64::from(pid));
        entry.start_ns = Some(u64::from(pid));
        entry.identity = ProcessIdentity::Path {
            path: path.to_string(),
            dev: 8,
            inode,
        };
        entry
    }

    fn service() -> (RansomService, mpsc::Receiver<AlertEvent>) {
        let (tx, rx) = mpsc::channel(8);
        let sources: HostSourcesReader = Arc::new(|| {
            HostSources::new(Some((6, 12)))
                .present(Source::ProcessTracing)
                .present(Source::FileWatch)
        });
        (RansomService::new(tx, sources), rx)
    }

    #[test]
    fn rewrites_alone_are_supporting_and_raise_nothing() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        for n in 0..RANSOM_DISTINCT_REWRITES * 2 {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/{n}"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                },
                1,
            );
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn rewrites_that_turn_content_random_corroborate_with_two_supporting_signals_and_a_strong_one()
    {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let actor = actor_of(&run, &lineage);
        let held = service.engine.lock().unwrap().observe(
            RansomSignal {
                kind: SignalKind::MassRename,
                actor,
                pid: 100,
                at_ns: 1,
                evidence: "renamed".to_string(),
            },
            Vec::new,
        );
        assert!(held.is_none());
        for n in 0..RANSOM_DISTINCT_REWRITES.max(RANSOM_ENTROPY_RISES) {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/{n}"),
                    entropy_before: Some(4_200),
                    entropy_now: Some(7_995),
                    head: None,
                },
                2,
            );
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(alert.message.contains("entropy_rise"));
        assert!(alert.message.contains("near-random content"));
        assert!(alert.message.contains("entropy_rise (pid 100)"));
        assert!(!alert.message.contains("entropy_rise (not read"));
    }

    #[test]
    fn documents_left_unlike_their_names_are_decisive_on_their_own() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        // Files still what they say they are raise nothing.
        for n in 0..RANSOM_HEADER_MISMATCHES {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/ok{n}.pdf"),
                    entropy_before: None,
                    entropy_now: None,
                    head: Some(*b"%PDF"),
                },
                1,
            );
        }
        assert!(rx.try_recv().is_err());
        for n in 0..RANSOM_HEADER_MISMATCHES {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/report{n}.docx"),
                    entropy_before: None,
                    entropy_now: None,
                    head: Some([0x9A, 0x13, 0x7F, 0x02]),
                },
                2,
            );
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(alert.message.contains("header_mismatch (pid 100)"));
        assert!(alert.message.contains("do not match their extension"));
    }

    #[test]
    fn a_change_that_rewrites_nothing_is_not_counted() {
        assert!(!rewrites([FileChangeKind::AttributesChanged]));
        assert!(!rewrites([
            FileChangeKind::Deleted,
            FileChangeKind::MovedOut
        ]));
        assert!(rewrites([FileChangeKind::MovedIn]));
    }

    #[test]
    fn a_verdict_is_raised_against_the_actor_and_names_what_was_not_read() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let worker = running(101, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: vec![run.clone(), running(50, "/bin/sh", 3)],
            truncated: false,
            incomplete: false,
        };
        let actor = actor_of(&worker, &lineage);
        let mut engine = service.engine.lock().unwrap();
        // A strong signal already held for the actor, as a later reader
        // would hand it in.
        let held = engine.observe(
            RansomSignal {
                kind: SignalKind::MassRename,
                actor: actor.clone(),
                pid: 101,
                at_ns: 1,
                evidence: "renamed".to_string(),
            },
            Vec::new,
        );
        assert!(held.is_none());
        drop(engine);
        service.observe(
            RansomSignal {
                kind: SignalKind::RansomNote,
                actor,
                pid: 101,
                at_ns: 2,
                evidence: "note".to_string(),
            },
            &worker,
            &lineage,
        );
        let Ok(AlertEvent::ProcessDetection {
            alert,
            kill_process,
        }) = rx.try_recv()
        else {
            panic!("no verdict raised");
        };
        assert!(!kill_process);
        assert_eq!(alert.tgid, Some(100));
        assert_eq!(alert.workload.as_ref().map(|w| w.pid), Some(100));
        assert!(
            alert
                .message
                .contains("canary_touched (not read by this agent)")
        );
        assert!(!alert.message.contains("distinct_rewrites ("));
    }
}
