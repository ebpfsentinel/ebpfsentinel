//! Mass encryption: the signals each reader produces, composed per actor
//! into one verdict, and the verdict raised as an alert.
//!
//! The readers stay where their reading lives - the file watcher hands every
//! settled change here - and nothing here decides a signal's weight: that is
//! the tier table in the domain. What this service adds is the lock around
//! the engine, the host's own account of which sources it reads, and the
//! alert channel.

use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::{Duration, Instant};

use domain::alert::entity::Alert;
use domain::file_watch::entity::FileChangeKind;
use domain::firewall::entity::RuleMode;
use domain::hostrule::HostSources;
use domain::process::engine::Lineage;
use domain::process::entity::ProcessEntry;
use domain::ransom::{
    Actor, CryptoRates, DistinctPaths, FilesWritten, MASS_ENCRYPTION_RULE_ID, MassRenames,
    RansomEngine, RansomNotes, RansomShadow, RansomSignal, RansomStop, RansomVerdict, Replacements,
    ShadowVerdict, SignalKind, UnavailableSignal, actor_of, backup_destroyed,
    backup_destroyed_signal, backup_program, bounded_threshold, canary_touched, entropy_rose,
    header_mismatch, initiator, original_of, renamed_over, renamed_to_new_extension, run_members,
    served_actor, serves_files, unavailable,
};
use domain::workload::entity::{Workload, WorkloadSource};
use ports::secondary::ransom_baseline_port::RansomBaselinePort;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::alert_event::AlertEvent;
use crate::process_signal_service::ProcessSignalService;
use crate::process_table_service::ProcessTableService;
use crate::workload_policy_service::workload_of;

/// Why the encryption calls are not read before anything said otherwise.
const CRYPTO_NOT_LOADED: &str = "the crypto library probes are not loaded";

/// What this host reports reading, asked when a verdict is reached.
pub type HostSourcesReader = Arc<dyn Fn() -> HostSources + Send + Sync>;

/// The address of the one client a file service's process is connected to,
/// asked with its pid; `None` where it holds none, or several.
pub type ServedPeerReader = Arc<dyn Fn(u32) -> Option<std::net::IpAddr> + Send + Sync>;

/// The signals this agent produces today. A signal missing here is named in
/// every verdict as not read, so a verdict never reads as the whole engine
/// when part of it is absent.
const READ: &[SignalKind] = &[
    SignalKind::BackupDestroyed,
    SignalKind::CanaryTouched,
    SignalKind::CryptoRate,
    SignalKind::DistinctRewrites,
    SignalKind::EntropyRise,
    SignalKind::HeaderMismatch,
    SignalKind::MassRename,
    SignalKind::ReplaceSequence,
    SignalKind::RansomNote,
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
    /// The path the file was renamed from, when the kernel named both.
    pub renamed_from: Option<&'a str>,
    /// The size the path held before the change, when it was known.
    pub size_before: Option<u64>,
    /// The size it holds now, absent when it is gone or unreadable.
    pub size_now: Option<u64>,
    /// Its modification time is now rather than a time carried from a source.
    pub written_now: bool,
}

/// What stops a run once its verdict is in force: the signal service, the
/// table the run's members are read from, and how long the watch is given
/// to read back what the run wrote before the count is taken. The table is
/// held weakly because it holds this service.
#[derive(Clone)]
struct Stopper {
    signals: Arc<ProcessSignalService>,
    processes: Weak<ProcessTableService>,
    settle: Duration,
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
    renames: Mutex<MassRenames>,
    notes: Mutex<RansomNotes>,
    replaced: Mutex<DistinctPaths>,
    replacements: Mutex<Replacements>,
    crypto: Mutex<CryptoRates>,
    crypto_unread: Mutex<Option<String>>,
    command_lines: bool,
    mode: RuleMode,
    shadow: Mutex<RansomShadow>,
    baseline: RwLock<Option<Arc<dyn RansomBaselinePort>>>,
    stopper: RwLock<Option<Stopper>>,
    written: Arc<Mutex<FilesWritten>>,
    sources: HostSourcesReader,
    served_peer: Option<ServedPeerReader>,
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
            renames: Mutex::new(MassRenames::default()),
            notes: Mutex::new(RansomNotes::default()),
            replaced: Mutex::new(DistinctPaths::replacements()),
            replacements: Mutex::new(Replacements::default()),
            crypto: Mutex::new(CryptoRates::default()),
            crypto_unread: Mutex::new(Some(CRYPTO_NOT_LOADED.to_string())),
            command_lines: false,
            mode: RuleMode::Shadow,
            shadow: Mutex::new(RansomShadow::default()),
            baseline: RwLock::new(None),
            stopper: RwLock::new(None),
            written: Arc::new(Mutex::new(FilesWritten::default())),
            sources,
            served_peer: None,
            alerts,
        }
    }

    /// How the client of a file service's process is named. Without it a
    /// write a file service made is still the client's, with its address
    /// stated as not read.
    #[must_use]
    pub fn with_served_peers(mut self, reader: ServedPeerReader) -> Self {
        self.served_peer = Some(reader);
        self
    }

    /// The actor a change by `writer` counts against: the client a file
    /// service wrote for, or the writer's own run on this host.
    fn actor(&self, writer: &ProcessEntry, lineage: &Lineage) -> Actor {
        if serves_files(writer) {
            let peer = self.served_peer.as_ref().and_then(|read| read(writer.pid));
            served_actor(writer, peer)
        } else {
            actor_of(writer, lineage)
        }
    }

    /// Whether the process table captures command lines, which is what the
    /// destruction of backups is read from. Without them that prior is
    /// named in every verdict as unavailable, with the setting that would
    /// give it.
    #[must_use]
    pub fn with_command_lines(mut self, captured: bool) -> Self {
        self.command_lines = captured;
        self
    }

    /// Whether a verdict raises an alert, `Enforce`, or is only counted,
    /// `Shadow`, the default: a verdict is put in force on a reading of what
    /// it would have raised on this host.
    #[must_use]
    pub fn with_mode(mut self, mode: RuleMode) -> Self {
        self.mode = mode;
        self
    }

    /// The mode verdicts are taken in.
    #[must_use]
    pub fn mode(&self) -> RuleMode {
        self.mode
    }

    /// The verdicts reached in shadow since the agent started.
    #[must_use]
    pub fn shadow(&self) -> RansomShadow {
        self.shadow
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// An exec the process table recorded: when its command line destroys
    /// snapshots or backups, a prior is held for whoever ran it, which then
    /// counts for every run that process started.
    pub fn record_exec(&self, entry: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        let Some(line) = entry.command_line.as_deref() else {
            return;
        };
        let Some(what) = backup_destroyed(entry.identity.path(), line) else {
            return;
        };
        let Some(by) = initiator(lineage) else {
            debug!(
                pid = entry.pid,
                what, "backups destroyed by a command no process ran but init"
            );
            return;
        };
        warn!(
            pid = entry.pid,
            initiator = by.pid,
            what,
            "backups destroyed: a later mass encryption by this process needs less to be raised"
        );
        let signal = backup_destroyed_signal(by, entry.pid, line, &what, at_ns);
        self.engine
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .hold_prior(signal);
    }

    /// Whether the calls into the system crypto libraries are counted on
    /// this host: `None` once the probes hold, otherwise why not, which every
    /// verdict then names beside the signal.
    pub fn set_crypto_calls(&self, unread: Option<String>) {
        *self
            .crypto_unread
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = unread;
    }

    /// `calls` new calls into a system encryption entry point by `caller`
    /// since the last reading. The signal is raised once those calls keep
    /// pace with the files the same actor rewrites.
    pub fn record_crypto_calls(
        &self,
        caller: &ProcessEntry,
        lineage: &Lineage,
        calls: u64,
        at_ns: u64,
    ) {
        // A file service encrypts its own transport for every client, which
        // is a rate of calls with no bearing on what its clients write.
        if calls == 0 || serves_files(caller) {
            return;
        }
        let actor = actor_of(caller, lineage);
        let raised = self
            .crypto
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .called(&actor, caller.pid, calls, at_ns);
        if let Some(signal) = raised {
            self.observe(signal, caller, lineage);
        }
    }

    /// What this host cannot read, the command lines and the encryption
    /// calls among it.
    fn unavailable(&self) -> Vec<UnavailableSignal> {
        let mut missing = unavailable(&(self.sources)(), READ);
        if let Some(reason) = self
            .crypto_unread
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        {
            missing.retain(|u| u.kind != SignalKind::CryptoRate);
            missing.push(UnavailableSignal {
                kind: SignalKind::CryptoRate,
                reason,
            });
        }
        if !self.command_lines {
            missing.retain(|u| u.kind != SignalKind::BackupDestroyed);
            missing.push(UnavailableSignal {
                kind: SignalKind::BackupDestroyed,
                reason: "process_table.capture_command_line is off".to_string(),
            });
        }
        missing
    }

    /// A settled change by `writer`, as the file watcher reports it.
    /// Changes that neither rewrite nor delete anything are not counted.
    pub fn record_file_change(
        &self,
        writer: &ProcessEntry,
        lineage: &Lineage,
        kinds: impl IntoIterator<Item = FileChangeKind>,
        change: FileRewrite<'_>,
        at_ns: u64,
    ) {
        let kinds: Vec<FileChangeKind> = kinds.into_iter().collect();
        if kinds.contains(&FileChangeKind::Deleted)
            && change.size_now.is_none()
            && let Some(size) = change.size_before
        {
            let actor = self.actor(writer, lineage);
            let completed = self
                .replacements
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .deleted(&actor, change.path, size, at_ns);
            if completed {
                self.count_replacement(&actor, writer, lineage, change.path, at_ns);
            }
        }
        if !rewrites(kinds.iter().copied()) {
            return;
        }
        let actor = self.actor(writer, lineage);
        self.written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            // A document written then renamed is one file lost, so the new
            // name is counted under the one it had.
            .record(actor.key, change.renamed_from.unwrap_or(change.path), at_ns);
        let held = Held {
            actor: &actor,
            writer,
            lineage,
            path: change.path,
            at_ns,
        };
        self.count(&self.rewrites, &held);
        // The encryption rate is read against files that held content before
        // the write: a download writes new files and encrypts a request for
        // each, which is a rate with nothing rewritten behind it.
        if change.size_before.is_some_and(|size| size > 0) {
            let raised = self
                .crypto
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .wrote(&actor, writer.pid, at_ns);
            if let Some(signal) = raised {
                self.observe(signal, writer, lineage);
            }
        }
        if entropy_rose(change.entropy_before, change.entropy_now) {
            self.count(&self.entropy_rises, &held);
        }
        // A document renamed to a name the table does not judge is still held
        // to the name it had: encrypting `report.pdf` and leaving it as
        // `report.pdf.locked` is the commonest shape of a run, and a name
        // chosen by the run is no reason to stop reading what it wrote.
        let mismatch = header_mismatch(change.path, change.head)
            || change
                .renamed_from
                .is_some_and(|from| header_mismatch(from, change.head));
        if mismatch {
            self.count(&self.header_mismatches, &held);
        }
        if let Some(from) = change.renamed_from {
            let learned = renamed_to_new_extension(from, change.path)
                .and_then(|_| self.learned(&actor, SignalKind::MassRename, at_ns));
            let raised = self
                .renames
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record_against(&actor, writer.pid, (from, change.path), at_ns, learned);
            if let Some(signal) = raised {
                self.observe(signal, writer, lineage);
            }
        }
        if kinds.contains(&FileChangeKind::Created) {
            let raised = self
                .notes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record(&actor, writer.pid, change.path, at_ns);
            if let Some(signal) = raised {
                self.observe(signal, writer, lineage);
            }
        }
        self.record_replacement(&actor, writer, lineage, &kinds, change, at_ns);
    }

    /// A canary at `path` opened by `opener`: decisive on its own, so the
    /// verdict follows from this one open. `path` is absent when the
    /// canary's directory could not be named.
    pub fn record_canary(
        &self,
        opener: &ProcessEntry,
        lineage: &Lineage,
        path: Option<&str>,
        at_ns: u64,
    ) {
        let actor = self.actor(opener, lineage);
        self.observe(
            canary_touched(&actor, opener.pid, path, at_ns),
            opener,
            lineage,
        );
    }

    /// The half of a replacement a rewrite may be: a file renamed over a
    /// known one of its size, or a new file written beside its original.
    /// Either way the replacement must have been written now.
    fn record_replacement(
        &self,
        actor: &Actor,
        writer: &ProcessEntry,
        lineage: &Lineage,
        kinds: &[FileChangeKind],
        change: FileRewrite<'_>,
        at_ns: u64,
    ) {
        let Some(size) = change.size_now.filter(|_| change.written_now) else {
            return;
        };
        match change.renamed_from {
            Some(from) => {
                if change
                    .size_before
                    .is_some_and(|before| renamed_over(from, change.path, before, size))
                {
                    self.count_replacement(actor, writer, lineage, change.path, at_ns);
                }
            }
            None if kinds.contains(&FileChangeKind::Created) => {
                let Some(original) = original_of(change.path) else {
                    return;
                };
                let completed = self
                    .replacements
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .written(actor, original, size, at_ns);
                if completed {
                    self.count_replacement(actor, writer, lineage, original, at_ns);
                }
            }
            None => {}
        }
    }

    fn count_replacement(
        &self,
        actor: &Actor,
        writer: &ProcessEntry,
        lineage: &Lineage,
        original: &str,
        at_ns: u64,
    ) {
        self.count(
            &self.replaced,
            &Held {
                actor,
                writer,
                lineage,
                path: original,
                at_ns,
            },
        );
    }

    /// Count the path toward its actor on one counter, and observe the
    /// signal that counter raises.
    fn count(&self, counter: &Mutex<DistinctPaths>, held: &Held<'_>) {
        let mut counter = counter.lock().unwrap_or_else(PoisonError::into_inner);
        let learned = self.learned(held.actor, counter.kind(), held.at_ns);
        let raised =
            counter.record_against(held.actor, held.writer.pid, held.path, held.at_ns, learned);
        drop(counter);
        if let Some(signal) = raised {
            self.observe(signal, held.writer, held.lineage);
        }
    }

    /// Stop every run a verdict in force names: the actor and everything it
    /// started, read from `processes` before the first signal, each killed
    /// through `signals`. Once the last member answered and `settle` has
    /// passed, an alert says how many files the run wrote before it died.
    pub fn install_stop(
        &self,
        signals: Arc<ProcessSignalService>,
        processes: &Arc<ProcessTableService>,
        settle: Duration,
    ) {
        *self.stopper.write().unwrap_or_else(PoisonError::into_inner) = Some(Stopper {
            signals,
            processes: Arc::downgrade(processes),
            settle,
        });
    }

    /// Whether a verdict in force stops the run it names, which is a stop
    /// installed and verdicts taken in `Enforce`.
    #[must_use]
    pub fn stops(&self) -> bool {
        self.mode == RuleMode::Enforce
            && self
                .stopper
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .is_some()
    }

    /// Kill the run `verdict` names, then raise what that cost beside
    /// `alert`. Nothing happens where no stop is installed.
    fn stop(&self, verdict: &RansomVerdict, alert: &Alert) {
        let Some(stopper) = self
            .stopper
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            warn!(
                actor = verdict.actor.pid,
                "mass encryption run not stopped: no runtime to signal from"
            );
            return;
        };
        let started = Instant::now();
        let actor = verdict.actor.key;
        let members = stopper.processes.upgrade().map_or_else(
            || vec![actor.pid],
            |table| run_members(&table.list(), actor),
        );
        let written = Arc::clone(&self.written);
        let alerts = self.alerts.clone();
        let alert = alert.clone();
        runtime.spawn(async move {
            let outcomes = stopper
                .signals
                .kill_run(members, MASS_ENCRYPTION_RULE_ID)
                .await;
            let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            tokio::time::sleep(stopper.settle).await;
            let files_written = written
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .count(actor);
            let stop = RansomStop {
                outcomes,
                files_written,
                latency_ms,
            };
            info!(actor = actor.pid, stop = %stop.describe(), "mass encryption run stopped");
            let sent = alerts.try_send(AlertEvent::ProcessDetection {
                alert: Box::new(Alert::from_ransom_stop(&alert, &stop)),
                kill_process: false,
            });
            if sent.is_err() {
                warn!(
                    actor = actor.pid,
                    "mass encryption stop dropped: the alert channel is full or closed"
                );
            }
        });
    }

    /// Read the counts a baseline may move against what `baseline` learned
    /// for each executable from here on. What it answers is held inside the
    /// band the content fixes, and the decisive signals never ask it.
    pub fn install_baseline(&self, baseline: Arc<dyn RansomBaselinePort>) {
        *self
            .baseline
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(baseline);
    }

    /// Report one file counted toward `kind` for `actor` to the baseline,
    /// and return the threshold it learned for that executable, bounded.
    fn learned(&self, actor: &Actor, kind: SignalKind, at_ns: u64) -> Option<usize> {
        bounded_threshold(kind, 0)?;
        let baseline = self
            .baseline
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()?;
        let exe = actor.exe.as_deref()?;
        baseline.counted(exe, kind, at_ns);
        baseline
            .threshold(exe, kind)
            .and_then(|learned| bounded_threshold(kind, learned))
    }

    /// Hold `signal`, produced by `writer`, and raise the verdict if its
    /// actor now reaches one.
    fn observe(&self, signal: RansomSignal, writer: &ProcessEntry, lineage: &Lineage) {
        let at_ns = signal.at_ns;
        // A backup program prunes its repository and then writes into it
        // encrypted, both under the job that started it: its writes are
        // judged on what they show alone rather than against that prior.
        let ancestry: Vec<_> =
            if backup_program(writer.identity.path(), writer.command_line.as_deref()) {
                Vec::new()
            } else {
                lineage.ancestors.iter().map(ProcessEntry::key).collect()
            };
        let verdict = self
            .engine
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe_under(signal, &ancestry, || self.unavailable());
        if let Some(verdict) = verdict {
            self.raise(&verdict, writer, lineage, at_ns);
        }
    }

    fn raise(&self, verdict: &RansomVerdict, writer: &ProcessEntry, lineage: &Lineage, at_ns: u64) {
        let workload = actor_workload(verdict, writer, lineage);
        if self.mode == RuleMode::Shadow {
            let actor = lineage
                .ancestors
                .iter()
                .find(|entry| entry.key() == verdict.actor.key)
                .unwrap_or(writer);
            let facts = workload_of(actor);
            let hit = facts.container_id.or(facts.cgroup).or(facts.unit);
            let message = Alert::from_ransom_verdict(verdict, workload, at_ns).message;
            self.shadow
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record(ShadowVerdict {
                    at_ns,
                    pid: verdict.actor.pid,
                    exe: verdict.actor.exe.clone(),
                    workload: hit,
                    message,
                });
            return;
        }
        let alert = Alert::from_ransom_verdict(verdict, workload, at_ns);
        // A run written through a file service is stopped where it runs, on
        // the client's host: killing the service here would end every
        // client's session and leave the run untouched.
        if verdict.actor.remote.is_none() {
            self.stop(verdict, &alert);
        }
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
    use domain::process::entity::{ProcessEventKind, ProcessIdentity, ProcessLifecycleEvent};
    use domain::ransom::{
        RANSOM_CRYPTO_CALLS, RANSOM_DISTINCT_REWRITES, RANSOM_ENTROPY_RISES,
        RANSOM_HEADER_MISMATCHES, RANSOM_MASS_RENAMES, RANSOM_NOTE_DIRECTORIES,
        RANSOM_REPLACEMENTS,
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
        (
            RansomService::new(tx, sources)
                .with_command_lines(true)
                .with_mode(RuleMode::Enforce),
            rx,
        )
    }

    #[test]
    fn backups_destroyed_lower_what_a_run_started_by_the_same_hand_needs() {
        let (service, mut rx) = service();
        let session = running(40, "/usr/sbin/sshd", 2);
        let shell = running(41, "/usr/bin/bash", 3);
        let init = running(1, "/sbin/init", 1);
        let mut zfs = running(50, "/usr/sbin/zfs", 4);
        zfs.command_line = Some("zfs destroy -r tank/home@daily".into());
        let above_zfs = Lineage {
            ancestors: vec![shell.clone(), session.clone(), init.clone()],
            truncated: false,
            incomplete: false,
        };
        service.record_exec(&zfs, &above_zfs, 1_000);
        // The prior is held for the session that ran the shell, and is no
        // verdict by itself.
        assert_eq!(service.engine.lock().unwrap().priors(), 1);
        assert!(rx.try_recv().is_err());
        // Another command by the same hand holds nothing more.
        let mut ls = running(51, "/usr/bin/ls", 5);
        ls.command_line = Some("ls /".into());
        service.record_exec(&ls, &above_zfs, 1_001);
        assert_eq!(service.engine.lock().unwrap().priors(), 1);

        // A run started from the same session reaches a verdict on one
        // strong signal.
        let run = running(60, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: vec![shell, session, init],
            truncated: false,
            incomplete: false,
        };
        for n in 0..RANSOM_NOTE_DIRECTORIES {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Created],
                FileRewrite {
                    path: &format!("/srv/d{n}/README_RESTORE.txt"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: None,
                    size_before: None,
                    size_now: Some(10),
                    written_now: true,
                },
                2_000 + n as u64,
            );
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("a verdict after the prior");
        };
        assert!(alert.message.contains("after backups were destroyed"));
        assert!(alert.message.contains("backup_destroyed (pid 50)"));
        assert!(alert.message.contains("zfs destroy -r tank/home@daily"));
    }

    #[test]
    fn without_command_lines_the_prior_is_named_unavailable_and_why() {
        let (tx, _rx) = mpsc::channel(1);
        let sources: HostSourcesReader = Arc::new(|| {
            HostSources::new(Some((6, 12)))
                .present(Source::ProcessTracing)
                .present(Source::FileWatch)
        });
        let blind = RansomService::new(tx, sources);
        let missing = blind.unavailable();
        let prior: Vec<_> = missing
            .iter()
            .filter(|u| u.kind == SignalKind::BackupDestroyed)
            .collect();
        assert_eq!(prior.len(), 1);
        assert_eq!(prior[0].reason, "process_table.capture_command_line is off");
        let (service, _rx) = service();
        assert!(
            service
                .unavailable()
                .iter()
                .all(|u| u.kind != SignalKind::BackupDestroyed)
        );
    }

    #[test]
    fn encryption_calls_keeping_pace_with_the_files_written_are_one_strong_signal() {
        let (service, mut rx) = service();
        // Unread until the probes hold, and named so.
        let unread: Vec<_> = service
            .unavailable()
            .into_iter()
            .filter(|u| u.kind == SignalKind::CryptoRate)
            .collect();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].reason, CRYPTO_NOT_LOADED);
        service.set_crypto_calls(None);
        assert!(
            service
                .unavailable()
                .iter()
                .all(|u| u.kind != SignalKind::CryptoRate)
        );

        let run = running(70, "/tmp/enc", 9);
        let lineage = Lineage::default();
        // Seen calling first, so the files after it count toward the rate.
        service.record_crypto_calls(&run, &lineage, 1, 900);
        // A download: new files beside the calls, which rewrite nothing and
        // leave the rate unread.
        let fetch = running(71, "/usr/lib/apt/methods/https", 10);
        service.record_crypto_calls(&fetch, &lineage, 1, 900);
        for n in 0..RANSOM_NOTE_DIRECTORIES {
            service.record_file_change(
                &fetch,
                &lineage,
                [FileChangeKind::Created],
                FileRewrite {
                    path: &format!("/var/cache/p{n}.deb"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: None,
                    size_before: None,
                    size_now: Some(10),
                    written_now: true,
                },
                950,
            );
        }
        service.record_crypto_calls(&fetch, &lineage, RANSOM_CRYPTO_CALLS, 960);
        assert!(rx.try_recv().is_err());
        // One note in every directory walked, one strong signal, and as many
        // documents rewritten beside the calls.
        for n in 0..RANSOM_NOTE_DIRECTORIES {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/d{n}/ledger.ods"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: None,
                    size_before: Some(4_096),
                    size_now: Some(4_112),
                    written_now: true,
                },
                1_000 + n as u64,
            );
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Created],
                FileRewrite {
                    path: &format!("/srv/d{n}/README_RESTORE.txt"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: None,
                    size_before: None,
                    size_now: Some(10),
                    written_now: true,
                },
                1_000 + n as u64,
            );
        }
        assert!(rx.try_recv().is_err());
        // The calls catch up with the files: the second strong signal.
        service.record_crypto_calls(&run, &lineage, RANSOM_CRYPTO_CALLS, 5_000);
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("a verdict on two strong signals");
        };
        assert!(alert.message.contains("crypto_rate"));
        assert!(alert.message.contains("encryption calls beside"));
        // No call at all is no reading.
        service.record_crypto_calls(&run, &lineage, 0, 6_000);
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
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
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
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
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

    /// Signal maps where every armed target is reached at once.
    #[derive(Default)]
    struct ReachedMaps {
        armed: Vec<u32>,
        events: Vec<ebpf_common::signal::SignalEvent>,
    }

    impl ports::secondary::process_signal_map_port::ProcessSignalMapPort for ReachedMaps {
        fn set_protected(
            &mut self,
            _tgids: &[u32],
        ) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }
        fn arm(
            &mut self,
            tgid: u32,
            _signal: u32,
            _window_ns: u64,
        ) -> Result<(), domain::common::error::DomainError> {
            self.armed.push(tgid);
            self.events.push(ebpf_common::signal::SignalEvent {
                tgid,
                outcome: ebpf_common::signal::SIGNAL_OUTCOME_SENT,
                ..Default::default()
            });
            Ok(())
        }
        fn disarm(&mut self, _tgid: u32) -> Result<(), domain::common::error::DomainError> {
            Ok(())
        }
        fn drain_events(
            &mut self,
        ) -> Result<Vec<ebpf_common::signal::SignalEvent>, domain::common::error::DomainError>
        {
            Ok(std::mem::take(&mut self.events))
        }
    }

    /// Every process runs until it has been looked at once, the look the
    /// guard takes before arming, and is gone after.
    #[derive(Default)]
    struct GoneOnceSignalled(Mutex<std::collections::HashSet<u32>>);

    impl ports::secondary::process_executable_port::ProcessExecutableReader for GoneOnceSignalled {
        fn read_executable(&self, pid: u32) -> Option<domain::dlp::entity::DlpExecutable> {
            let first = self
                .0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(pid);
            first.then(|| domain::dlp::entity::DlpExecutable {
                path: "/tmp/enc".to_string(),
                dev: 0,
                inode: 0,
                source: domain::dlp::entity::DlpIdentitySource::ProcessAtAlertTime,
            })
        }
    }

    fn started(pid: u32, parent: Option<u32>) -> ProcessLifecycleEvent {
        ProcessLifecycleEvent {
            kind: ProcessEventKind::Exec,
            pid,
            tgid: pid,
            uid: 0,
            gid: 0,
            cgroup_id: 1,
            comm: "enc".to_string(),
            at_ns: u64::from(pid),
            start_ns: Some(u64::from(pid)),
            parent_pid: parent,
            parent_start_ns: parent.map(u64::from),
        }
    }

    #[tokio::test]
    async fn a_verdict_in_force_kills_the_whole_run_and_says_how_many_files_it_cost() {
        let (service, mut rx) = service();
        let table = Arc::new(ProcessTableService::new(64, false));
        // The actor, a worker it forked, the worker's own worker, and a
        // process that is no part of the run.
        table.apply(started(100, None)).await;
        table.apply(started(101, Some(100))).await;
        table.apply(started(102, Some(101))).await;
        table.apply(started(200, None)).await;
        let maps = Arc::new(tokio::sync::Mutex::new(ReachedMaps::default()));
        let signals = Arc::new(
            ProcessSignalService::new(
                maps.clone(),
                Arc::new(GoneOnceSignalled::default()),
                None,
                domain::response::signal::ProcessSignalGuard::new(4242, &[], &[]),
                crate::process_signal_service::ProcessSignalSettings {
                    signal: 9,
                    window: Duration::from_millis(200),
                    poll_interval: Duration::from_millis(2),
                },
            )
            .await
            .expect("the fake maps take the protected set"),
        );
        assert!(!service.stops(), "no stop is installed yet");
        service.install_stop(signals, &table, Duration::from_millis(5));
        assert!(
            service.stops(),
            "a verdict in force with a stop installed stops"
        );

        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
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
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
                },
                2,
            );
        }
        let Some(AlertEvent::ProcessDetection { alert: verdict, .. }) = rx.recv().await else {
            panic!("no verdict raised");
        };
        assert!(verdict.mitigation_status.is_none());
        let stopped = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("the stop is reported");
        let Some(AlertEvent::ProcessDetection {
            alert,
            kill_process,
        }) = stopped
        else {
            panic!("the stop is a process detection");
        };
        assert!(!kill_process, "the stop has already been taken");
        assert_eq!(alert.mitigation_status.as_deref(), Some("stopped"));
        assert_ne!(alert.id, verdict.id);
        assert!(alert.message.starts_with(&format!(
            "{RANSOM_HEADER_MISMATCHES} files written before the run was stopped; 3 of 3 processes of the run gone"
        )));
        assert!(alert.message.contains("header_mismatch (pid 100)"));
        let mut armed = maps.lock().await.armed.clone();
        armed.sort_unstable();
        assert_eq!(armed, vec![100, 101, 102], "the run and nothing else");
    }

    fn mismatch(service: &RansomService, writer: &ProcessEntry, lineage: &Lineage, n: usize) {
        service.record_file_change(
            writer,
            lineage,
            [FileChangeKind::Written],
            FileRewrite {
                path: &format!("/srv/share/report{}-{n}.docx", writer.pid),
                entropy_before: None,
                entropy_now: None,
                head: Some([0x9A, 0x13, 0x7F, 0x02]),
                renamed_from: None,
                size_before: None,
                size_now: None,
                written_now: false,
            },
            2,
        );
    }

    fn samba_clients() -> (ProcessEntry, ProcessEntry, Lineage) {
        let master = running(500, "/usr/sbin/smbd", 4);
        let lineage = Lineage {
            ancestors: vec![master],
            truncated: false,
            incomplete: false,
        };
        (
            running(501, "/usr/sbin/smbd", 4),
            running(502, "/usr/sbin/smbd", 4),
            lineage,
        )
    }

    fn peers_by_pid(pid: u32) -> Option<std::net::IpAddr> {
        match pid {
            501 => Some("10.0.0.7".parse().expect("ip")),
            502 => Some("10.0.0.8".parse().expect("ip")),
            _ => None,
        }
    }

    #[test]
    fn a_file_service_writing_for_one_client_raises_against_that_client() {
        let (service, mut rx) = service();
        let service = service.with_served_peers(Arc::new(peers_by_pid));
        let (first, _, lineage) = samba_clients();
        for n in 0..RANSOM_HEADER_MISMATCHES {
            mismatch(&service, &first, &lineage, n);
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(alert.message.starts_with(
            "mass encryption written for the client at 10.0.0.7 through /usr/sbin/smbd (pid 501)"
        ));
        assert_eq!(
            alert.src_addr[0],
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 7))
        );
    }

    #[test]
    fn two_clients_of_one_file_service_are_never_added_together() {
        let (service, mut rx) = service();
        let service = service.with_served_peers(Arc::new(peers_by_pid));
        let (first, second, lineage) = samba_clients();
        let half = RANSOM_HEADER_MISMATCHES / 2;
        for n in 0..half {
            mismatch(&service, &first, &lineage, n);
            mismatch(&service, &second, &lineage, n);
        }
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn a_client_and_a_process_of_this_host_are_never_one_actor() {
        let (service, mut rx) = service();
        let (first, _, lineage) = samba_clients();
        let local = running(600, "/tmp/enc", 7);
        let alone = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let half = RANSOM_HEADER_MISMATCHES / 2;
        for n in 0..half {
            mismatch(&service, &first, &lineage, n);
            mismatch(&service, &local, &alone, n);
        }
        assert!(rx.try_recv().is_err());
        // Without a reader the client is still a client, unnamed.
        for n in half..RANSOM_HEADER_MISMATCHES {
            mismatch(&service, &first, &lineage, n);
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(
            alert
                .message
                .contains("a client on another host, address not read")
        );
        assert_eq!(alert.src_addr, [0; 4]);
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
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
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
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
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
    fn documents_renamed_away_from_their_names_are_still_held_to_them() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let rename = |n: usize, head: [u8; 4], at: u64| {
            let from = format!("/srv/report{n}.pdf");
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::MovedIn],
                FileRewrite {
                    path: &format!("{from}.lockd"),
                    entropy_before: None,
                    entropy_now: None,
                    head: Some(head),
                    renamed_from: Some(&from),
                    size_before: None,
                    size_now: None,
                    written_now: false,
                },
                at,
            );
        };
        // A document kept as it was under a new name raises nothing.
        for n in 0..RANSOM_HEADER_MISMATCHES {
            rename(n, *b"%PDF", 1);
        }
        assert!(rx.try_recv().is_err());
        for n in RANSOM_HEADER_MISMATCHES..RANSOM_HEADER_MISMATCHES * 2 {
            rename(n, [0x9A, 0x13, 0x7F, 0x02], 2);
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(alert.message.contains("header_mismatch (pid 100)"));
    }

    #[test]
    fn a_document_written_then_renamed_is_one_file_written() {
        let (service, _rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let change = |kind: FileChangeKind, path: &str, renamed_from: Option<&str>| {
            service.record_file_change(
                &run,
                &lineage,
                [kind],
                FileRewrite {
                    path,
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from,
                    size_before: None,
                    size_now: None,
                    written_now: true,
                },
                1,
            );
        };
        change(FileChangeKind::Written, "/srv/a.pdf", None);
        change(
            FileChangeKind::MovedIn,
            "/srv/a.pdf.lockd",
            Some("/srv/a.pdf"),
        );
        change(FileChangeKind::Written, "/srv/b.pdf", None);
        let actor = actor_of(&run, &lineage).key;
        let counted = service
            .written
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .count(actor);
        assert_eq!(counted, 2);
    }

    #[test]
    fn a_verdict_in_shadow_is_counted_by_workload_and_raises_nothing() {
        let (tx, mut rx) = mpsc::channel(8);
        let sources: HostSourcesReader = Arc::new(|| {
            HostSources::new(Some((6, 12)))
                .present(Source::ProcessTracing)
                .present(Source::FileWatch)
        });
        let service = RansomService::new(tx, sources);
        assert_eq!(service.mode(), RuleMode::Shadow);
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
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
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
                },
                2,
            );
        }
        assert!(
            rx.try_recv().is_err(),
            "a verdict in shadow raised an alert"
        );
        let shadow = service.shadow();
        assert_eq!(shadow.reading.events, 1);
        let Some(verdict) = shadow.recent.back() else {
            panic!("the verdict was not kept");
        };
        assert_eq!(verdict.pid, 100);
        assert_eq!(verdict.exe.as_deref(), Some("/tmp/enc"));
        assert!(verdict.message.contains("header_mismatch (pid 100)"));
    }

    #[test]
    fn files_renamed_to_one_new_extension_are_strong_and_corroborate() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let rename = |n: usize, at_ns: u64| {
            let from = format!("/srv/q{n}.xlsx");
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::MovedIn],
                FileRewrite {
                    path: &format!("/srv/q{n}.xlsx.locked"),
                    entropy_before: (n < RANSOM_ENTROPY_RISES).then_some(4_000),
                    entropy_now: (n < RANSOM_ENTROPY_RISES).then_some(7_950),
                    head: None,
                    renamed_from: Some(&from),
                    size_before: None,
                    size_now: None,
                    written_now: false,
                },
                at_ns,
            );
        };
        // A rise, then the renames: a strong and a supporting signal are not
        // yet a verdict.
        for n in 0..RANSOM_DISTINCT_REWRITES - 1 {
            rename(n, 1);
        }
        assert!(rx.try_recv().is_err());
        // The distinct rewrites are the second supporting signal.
        rename(RANSOM_DISTINCT_REWRITES, 2);
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(alert.message.contains("mass_rename (pid 100)"));
        assert!(alert.message.contains("renamed to .locked"));
    }

    /// A baseline that has learned every executable runs at `threshold`,
    /// and counts what it is told.
    struct Learned {
        threshold: usize,
        counted: Mutex<Vec<(String, SignalKind)>>,
    }

    impl RansomBaselinePort for Learned {
        fn counted(&self, exe: &str, kind: SignalKind, _at_ns: u64) {
            self.counted
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((exe.to_string(), kind));
        }

        fn threshold(&self, _exe: &str, _kind: SignalKind) -> Option<usize> {
            Some(self.threshold)
        }
    }

    #[test]
    fn a_learned_baseline_moves_the_counts_inside_their_band_and_never_a_canary() {
        let (service, mut rx) = service();
        let baseline = Arc::new(Learned {
            threshold: usize::MAX,
            counted: Mutex::new(Vec::new()),
        });
        service.install_baseline(Arc::clone(&baseline) as Arc<dyn RansomBaselinePort>);
        let run = running(100, "/usr/bin/nightly-sync", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let rename = |n: usize| {
            let from = format!("/srv/q{n}.xlsx");
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::MovedIn],
                FileRewrite {
                    path: &format!("/srv/q{n}.xlsx.locked"),
                    entropy_before: Some(4_000),
                    entropy_now: Some(7_950),
                    head: None,
                    renamed_from: Some(&from),
                    size_before: None,
                    size_now: None,
                    written_now: false,
                },
                1,
            );
        };
        // Past every shipped threshold and under every ceiling: the run this
        // executable normally makes is not a verdict.
        for n in 0..=RANSOM_DISTINCT_REWRITES {
            rename(n);
        }
        assert!(rx.try_recv().is_err());
        let counted = baseline
            .counted
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        assert!(
            counted
                .iter()
                .all(|(exe, _)| exe == "/usr/bin/nightly-sync")
        );
        for kind in [
            SignalKind::DistinctRewrites,
            SignalKind::EntropyRise,
            SignalKind::MassRename,
        ] {
            assert!(counted.iter().any(|(_, k)| *k == kind), "{kind:?}");
        }
        // The ceiling holds whatever was learned: four times the shipped
        // renames are a signal, and with the entropy rises past their own
        // ceiling the verdict is reached and names the learned threshold.
        for n in RANSOM_DISTINCT_REWRITES + 1..4 * RANSOM_DISTINCT_REWRITES {
            rename(n);
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised past the ceiling");
        };
        assert!(alert.message.contains("learned for this executable"));
        // No baseline is asked about a canary, and one open still decides.
        let (fresh, mut rx) = self::service();
        fresh.install_baseline(Arc::clone(&baseline) as Arc<dyn RansomBaselinePort>);
        fresh.record_canary(&run, &lineage, Some("/srv/.canary.docx"), 1);
        assert!(matches!(
            rx.try_recv(),
            Ok(AlertEvent::ProcessDetection { .. })
        ));
    }

    #[test]
    fn originals_replaced_by_a_file_of_their_size_written_beside_them_are_strong() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let write = |n: usize, written_now: bool| {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Created, FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/r{n}.docx.locked"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: None,
                    size_before: None,
                    size_now: Some(4_096 + 512),
                    written_now,
                },
                1,
            );
        };
        let delete = |n: usize| {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Deleted],
                FileRewrite {
                    path: &format!("/srv/r{n}.docx"),
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: None,
                    size_before: Some(4_096),
                    size_now: None,
                    written_now: false,
                },
                2,
            );
        };
        // Copies carrying their source's time replace nothing.
        for n in 0..RANSOM_REPLACEMENTS {
            write(n, false);
            delete(n);
        }
        // The rest of the run: enough distinct rewrites to support a verdict.
        for n in RANSOM_REPLACEMENTS..RANSOM_DISTINCT_REWRITES + RANSOM_REPLACEMENTS {
            write(n, true);
        }
        assert!(rx.try_recv().is_err());
        // Two supporting signals are needed beside one strong one; this run
        // has one, so its replacements alone are not a verdict.
        for n in RANSOM_REPLACEMENTS..RANSOM_REPLACEMENTS * 2 {
            delete(n);
        }
        assert!(rx.try_recv().is_err());
        // Renamed over the original, the same shape is counted too, and once
        // the entropy also rose the verdict is reached.
        for n in 0..RANSOM_ENTROPY_RISES {
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::Written],
                FileRewrite {
                    path: &format!("/srv/e{n}.txt"),
                    entropy_before: Some(4_000),
                    entropy_now: Some(7_950),
                    head: None,
                    renamed_from: None,
                    size_before: None,
                    size_now: None,
                    written_now: false,
                },
                3,
            );
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(
            alert.message.contains("replace_sequence (pid 100)"),
            "{}",
            alert.message
        );
        assert!(alert.message.contains("written fresh beside them"));
    }

    #[test]
    fn a_rename_over_a_known_file_of_its_size_is_a_replacement() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        // Each file renamed over by a hidden temporary of its size plus a
        // header: distinct rewrites, entropy rises on some, and replacements.
        for n in 0..RANSOM_DISTINCT_REWRITES {
            let rose = n < RANSOM_ENTROPY_RISES;
            service.record_file_change(
                &run,
                &lineage,
                [FileChangeKind::MovedIn],
                FileRewrite {
                    path: &format!("/srv/r{n}.pdf"),
                    entropy_before: rose.then_some(4_000),
                    entropy_now: rose.then_some(7_950),
                    head: None,
                    renamed_from: Some(&format!("/srv/.r{n}.tmp")),
                    size_before: Some(10_000),
                    size_now: Some(10_016),
                    written_now: true,
                },
                1,
            );
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(
            alert.message.contains("replace_sequence (pid 100)"),
            "{}",
            alert.message
        );
    }

    #[test]
    fn one_new_name_in_many_directories_is_strong_and_corroborates_with_renames() {
        let (service, mut rx) = service();
        let run = running(100, "/tmp/enc", 7);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        let change = |kinds: &[FileChangeKind], path: &str, from: Option<&str>| {
            service.record_file_change(
                &run,
                &lineage,
                kinds.iter().copied(),
                FileRewrite {
                    path,
                    entropy_before: None,
                    entropy_now: None,
                    head: None,
                    renamed_from: from,
                    size_before: None,
                    size_now: Some(900),
                    written_now: true,
                },
                1,
            );
        };
        // A build scattering one of its own names raises nothing, and the
        // note in every directory is one strong signal, not yet a verdict.
        for n in 0..RANSOM_NOTE_DIRECTORIES {
            change(
                &[FileChangeKind::Created],
                &format!("/srv/d{n}/__init__.py"),
                None,
            );
            change(
                &[FileChangeKind::Created],
                &format!("/srv/d{n}/README_RESTORE.txt"),
                None,
            );
        }
        assert!(rx.try_recv().is_err());
        for n in 0..RANSOM_MASS_RENAMES {
            let from = format!("/srv/d0/f{n}.pdf");
            change(
                &[FileChangeKind::MovedIn],
                &format!("{from}.locked"),
                Some(&from),
            );
        }
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(
            alert.message.contains("ransom_note (pid 100)"),
            "{}",
            alert.message
        );
        assert!(alert.message.contains("README_RESTORE.txt written into"));
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
                .contains("crypto_rate (the crypto library probes are not loaded)")
        );
        assert!(!alert.message.contains("distinct_rewrites ("));
        assert!(!alert.message.contains("canary_touched ("));
    }

    #[test]
    fn one_open_of_a_canary_raises_the_verdict_alone() {
        let (service, mut rx) = service();
        let opener = running(300, "/tmp/enc", 9);
        let lineage = Lineage {
            ancestors: Vec::new(),
            truncated: false,
            incomplete: false,
        };
        service.record_canary(&opener, &lineage, Some("/srv/0000-archive.docx"), 1);
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert_eq!(alert.tgid, Some(300));
        assert!(
            alert
                .message
                .contains("canary /srv/0000-archive.docx opened")
        );
    }
}
