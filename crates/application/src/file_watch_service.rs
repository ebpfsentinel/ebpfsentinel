//! Keeping the file watch open and reading it.
//!
//! The watch covers whole filesystems and is held by whoever holds the
//! privilege, the warden for a rootless agent. A warden that restarts takes
//! the watch with it, so a failed reading is answered by opening the watch
//! again rather than by giving up. A filesystem that cannot be watched is
//! reported once, with its reason, and costs the agent nothing else.
//!
//! Every path a change names is read again once the change is seen: its
//! kind, mode, owner, size and time, the digest of its content and of each
//! extended attribute. The first reading is kept as the path's baseline and
//! raises nothing; every later one is compared with it and kept in its
//! place. A path that disappears is forgotten, so a log rotated away and its
//! successor moved in read as one disappearance and one first sight.
//!
//! Each settled change is named the way its writer sees it, read from the
//! writer's own root mount, and handed to the host rules with the writer
//! and its ancestry as the process table holds them.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;

use domain::file_watch::{
    FileBaseline, FileChangeBatch, FileChangeKind, FileDrift, FileFacts, FileReading, RootMount,
    RootedPath, WatchedFilesystem, rooted,
};
use domain::hostrule::{Intent, SettledChange, file_events};
use ports::secondary::file_watch_port::{FileBaselineStore, FileWatchSource, ProcessRootReader};
use ports::secondary::metrics_port::MetricsPort;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::host_rule_service::HostRuleService;
use crate::process_table_service::ProcessTableService;

/// How long one reading waits for a first change. Short enough that a
/// cancelled agent stops within it.
pub const FILE_WATCH_READ_WAIT: Duration = Duration::from_secs(1);

/// How long the watcher waits before opening the watch again, after the
/// watch could not be opened or could no longer be read.
pub const FILE_WATCH_REOPEN_DELAY: Duration = Duration::from_secs(30);

/// Paths asked for in one reading of facts; the reader may answer fewer.
pub const FILE_FACTS_BATCH: usize = 256;

/// Changed paths waiting to be read. A burst beyond this is counted as lost,
/// the same way a full kernel queue is.
pub const FILE_FACTS_PENDING_MAX: usize = 65_536;

/// What baselines cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaselinePolicy {
    /// A regular file larger than this is not hashed: its size and time are
    /// compared instead, and the baseline says why it carries no hash.
    pub max_hash_bytes: u64,
    /// Baselines kept at most. A path first seen once the store holds this
    /// many gets none, and is counted.
    pub max_files: u64,
}

/// The file intentions, any of which a rule may name.
const FILE_INTENTS: [Intent; 5] = [
    Intent::FileChanges,
    Intent::FileAppears,
    Intent::FileDisappears,
    Intent::FilePermissionsChange,
    Intent::FileIntegrityBreaks,
];

/// A changed path waiting to be read again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Pending {
    /// The last writer seen.
    pid: u32,
    /// Every kind of change seen since the path was last read.
    kinds: BTreeSet<FileChangeKind>,
    dev: Option<u64>,
    ino: Option<u64>,
}

/// Where settled changes go beyond the baseline: the host rules, the
/// process table naming each writer, and the reader of each writer's root.
pub struct FileRuleFeed {
    pub rules: Arc<HostRuleService>,
    pub processes: Option<Arc<ProcessTableService>>,
    pub roots: Option<Arc<dyn ProcessRootReader>>,
}

/// Opens the watch on the configured filesystems, reads it until cancelled,
/// and compares every changed path with its baseline.
pub struct FileWatcher {
    source: Box<dyn FileWatchSource>,
    paths: Vec<String>,
    metrics: Arc<dyn MetricsPort>,
    baselines: Arc<dyn FileBaselineStore>,
    policy: BaselinePolicy,
    /// Changed paths not read yet, each with the last writer seen.
    pending: BTreeMap<String, Pending>,
    kept: u64,
    reopen_delay: Duration,
    feed: Option<FileRuleFeed>,
}

impl FileWatcher {
    #[must_use]
    pub fn new(
        source: Box<dyn FileWatchSource>,
        paths: Vec<String>,
        metrics: Arc<dyn MetricsPort>,
        baselines: Arc<dyn FileBaselineStore>,
        policy: BaselinePolicy,
    ) -> Self {
        Self {
            source,
            paths,
            metrics,
            baselines,
            policy,
            pending: BTreeMap::new(),
            kept: 0,
            reopen_delay: FILE_WATCH_REOPEN_DELAY,
            feed: None,
        }
    }

    /// Hand every settled change to the host rules, named the way its writer
    /// sees it and carrying the writer and its ancestry.
    #[must_use]
    pub fn with_rules(mut self, feed: FileRuleFeed) -> Self {
        self.feed = Some(feed);
        self
    }

    /// Where the watch lives: `warden` or `local`.
    #[must_use]
    pub fn source(&self) -> &'static str {
        self.source.source()
    }

    /// Open the watch, publish what it covers, and say whether anything is
    /// watched.
    fn open(&mut self, last: &mut Option<Vec<WatchedFilesystem>>) -> bool {
        let marks = match self.source.open(&self.paths) {
            Ok(marks) => marks,
            Err(e) => {
                warn!(source = self.source.source(), error = %e, "file watch could not be opened");
                self.metrics.set_file_watch_filesystems(0, 0);
                return false;
            }
        };
        let watched = marks.iter().filter(|m| m.is_watched()).count();
        let refused = marks.len() - watched;
        self.metrics
            .set_file_watch_filesystems(watched as u64, refused as u64);
        // A reopen that changes nothing is not news: the outcome of every
        // mark is logged when it differs from the last time.
        if last.as_ref() != Some(&marks) {
            for mark in &marks {
                match &mark.error {
                    None => {
                        info!(path = %mark.path, "file watch covers the filesystem holding this path");
                    }
                    Some(reason) => {
                        warn!(path = %mark.path, reason = %reason, "file watch does not cover this path");
                    }
                }
            }
        }
        *last = Some(marks);
        watched > 0
    }

    /// Count one reading's changes into the metrics.
    fn record(&self, batch: &FileChangeBatch) {
        if batch.overflowed {
            warn!("file changes were lost: the kernel's queue was full");
            self.metrics.record_file_change_overflow();
        }
        let mut counts: BTreeMap<FileChangeKind, u64> = BTreeMap::new();
        for change in &batch.changes {
            debug!(
                pid = change.pid,
                directory = change.directory.as_deref().unwrap_or("-"),
                name = %change.name,
                kinds = ?change.kinds,
                unresolved = change.unresolved.as_deref().unwrap_or("-"),
                "file changed"
            );
            for kind in &change.kinds {
                *counts.entry(*kind).or_default() += 1;
            }
        }
        for (kind, count) in counts {
            self.metrics.record_file_changes(kind.as_str(), count);
        }
    }

    /// Queue the path each change names, to be read again.
    fn queue(&mut self, batch: &FileChangeBatch) {
        let mut lost = false;
        for change in &batch.changes {
            let Some(directory) = change.directory.as_deref() else {
                continue;
            };
            let path = if change.name.is_empty() {
                directory.to_owned()
            } else if directory.ends_with('/') {
                format!("{directory}{}", change.name)
            } else {
                format!("{directory}/{}", change.name)
            };
            let full = self.pending.len() >= FILE_FACTS_PENDING_MAX;
            let pending = match self.pending.entry(path) {
                Entry::Occupied(slot) => slot.into_mut(),
                Entry::Vacant(slot) if !full => slot.insert(Pending::default()),
                Entry::Vacant(_) => {
                    lost = true;
                    continue;
                }
            };
            pending.pid = change.pid;
            pending.kinds.extend(change.kinds.iter().copied());
            pending.dev = change.dev.or(pending.dev);
            pending.ino = change.ino.or(pending.ino);
        }
        if lost {
            warn!(
                pending = FILE_FACTS_PENDING_MAX,
                "changed paths were lost: too many are waiting to be read"
            );
            self.metrics.record_file_change_overflow();
        }
    }

    /// Read one batch of the pending paths and compare each with its
    /// baseline.
    ///
    /// # Errors
    ///
    /// The reader could not be asked; the paths stay pending.
    fn settle(&mut self) -> Result<(), String> {
        let asked: Vec<String> = self
            .pending
            .keys()
            .take(FILE_FACTS_BATCH)
            .cloned()
            .collect();
        let facts = self
            .source
            .facts(&asked, self.policy.max_hash_bytes)
            .map_err(|e| e.to_string())?;
        if facts.is_empty() {
            return Err("the reader answered none of the paths".into());
        }
        let mut roots = HashMap::new();
        for fact in facts {
            let pending = self.pending.remove(&fact.path).unwrap_or_default();
            let rooted = self.rooted(&fact.path, pending.pid, &mut roots);
            self.compare(&fact, &pending, &rooted);
        }
        self.metrics.set_file_baselines(self.kept);
        Ok(())
    }

    /// `path` as the writer `pid` sees it, its root read once per batch.
    fn rooted(
        &self,
        path: &str,
        pid: u32,
        roots: &mut HashMap<u32, Option<RootMount>>,
    ) -> RootedPath {
        let Some(reader) = self.feed.as_ref().and_then(|feed| feed.roots.as_ref()) else {
            return RootedPath::default();
        };
        roots
            .entry(pid)
            .or_insert_with(|| reader.root_mount(pid))
            .as_ref()
            .map_or_else(RootedPath::default, |root| rooted(path, root))
    }

    fn compare(&mut self, fact: &FileFacts, pending: &Pending, rooted: &RootedPath) {
        let path = fact.path.as_str();
        let pid = pending.pid;
        let kept = match self.baselines.get(path) {
            Ok(kept) => kept,
            Err(e) => {
                warn!(path, error = %e, "file baseline could not be read");
                return;
            }
        };
        self.feed(fact, pending, rooted, kept.as_ref());
        let inside = rooted.path.as_deref().unwrap_or(path);
        match (&fact.reading, kept) {
            (FileReading::Present(new), None) => {
                if self.kept >= self.policy.max_files {
                    debug!(path, "file baseline store is full, path not kept");
                    self.metrics.record_file_baseline_refused();
                    return;
                }
                match self.baselines.put(path, new) {
                    Ok(()) => self.kept += 1,
                    Err(e) => warn!(path, error = %e, "file baseline could not be kept"),
                }
            }
            (FileReading::Present(new), Some(old)) => {
                self.report(path, inside, pid, &old.drift(&fact.reading), &fact.reading);
                if let Err(e) = self.baselines.put(path, new) {
                    warn!(path, error = %e, "file baseline could not be kept");
                }
            }
            (FileReading::Gone, Some(old)) => {
                self.report(path, inside, pid, &old.drift(&fact.reading), &fact.reading);
                match self.baselines.remove(path) {
                    Ok(true) => self.kept = self.kept.saturating_sub(1),
                    Ok(false) => {}
                    Err(e) => warn!(path, error = %e, "file baseline could not be forgotten"),
                }
            }
            // The baseline is kept: what the path named before is still the
            // last thing known about it, and the next readable reading is
            // compared against it.
            (FileReading::Unreadable(_), Some(old)) => {
                self.report(path, inside, pid, &old.drift(&fact.reading), &fact.reading);
            }
            (FileReading::Unreadable(reason), None) => {
                debug!(path, reason = %reason, "changed path could not be read");
            }
            (FileReading::Gone, None) => {}
        }
    }

    fn report(
        &self,
        path: &str,
        inside: &str,
        pid: u32,
        drift: &[FileDrift],
        reading: &FileReading,
    ) {
        if drift.is_empty() {
            return;
        }
        let what: Vec<&str> = drift.iter().map(|d| d.as_str()).collect();
        let exe = self
            .feed
            .as_ref()
            .and_then(|feed| feed.processes.as_ref())
            .and_then(|table| table.get(pid))
            .and_then(|entry| entry.identity.path().map(ToOwned::to_owned));
        let exe = exe.as_deref().unwrap_or("-");
        if let FileReading::Unreadable(reason) = reading {
            warn!(path, rooted = inside, pid, exe, drift = ?what, reason = %reason, "file differs from its baseline");
        } else {
            warn!(path, rooted = inside, pid, exe, drift = ?what, "file differs from its baseline");
        }
        for d in drift {
            self.metrics.record_file_drifts(d.as_str(), 1);
        }
    }

    /// Hand the intentions `fact` raises to the host rules, with the writer
    /// and its ancestry, where a rule names any file intention.
    fn feed(
        &mut self,
        fact: &FileFacts,
        pending: &Pending,
        rooted: &RootedPath,
        before: Option<&FileBaseline>,
    ) {
        let Some(feed) = self.feed.as_ref() else {
            return;
        };
        if !FILE_INTENTS.iter().any(|intent| feed.rules.wants(*intent)) {
            return;
        }
        let rules = Arc::clone(&feed.rules);
        let writer = feed.processes.as_ref().and_then(|table| {
            table
                .get(pending.pid)
                .map(|entry| (table.lineage(pending.pid), entry))
        });
        let arrived = pending.kinds.contains(&FileChangeKind::Created)
            || pending.kinds.contains(&FileChangeKind::MovedIn);
        let in_image = before.is_none()
            && arrived
            && matches!(fact.reading, FileReading::Present(_))
            && self.in_image(&rooted.layers);
        let events = file_events(&SettledChange {
            kinds: &pending.kinds,
            host_path: &fact.path,
            rooted,
            before,
            reading: &fact.reading,
            in_image,
            dev: pending.dev,
            ino: pending.ino,
        });
        let at_ns = now_ns();
        for event in events {
            rules.record_file(
                event,
                writer.as_ref().map(|(lineage, entry)| (entry, lineage)),
                at_ns,
            );
        }
    }

    /// Whether any of `layers` holds a file: a name the container creates
    /// that its image already carried was copied up, not made.
    fn in_image(&mut self, layers: &[String]) -> bool {
        if layers.is_empty() {
            return false;
        }
        match self.source.facts(layers, 0) {
            Ok(facts) => facts
                .iter()
                .any(|fact| matches!(fact.reading, FileReading::Present(_))),
            Err(e) => {
                debug!(error = %e, "image layers could not be read");
                false
            }
        }
    }

    /// Wait `delay` in steps no longer than a reading, and say whether the
    /// watcher was cancelled meanwhile.
    fn pause(delay: Duration, cancel: &CancellationToken) -> bool {
        let mut left = delay;
        while !left.is_zero() {
            if cancel.is_cancelled() {
                return true;
            }
            let step = left.min(FILE_WATCH_READ_WAIT);
            std::thread::sleep(step);
            left -= step;
        }
        cancel.is_cancelled()
    }

    /// Open and read until `cancel` fires. Blocking: run it on a thread of
    /// its own.
    pub fn run_blocking(mut self, cancel: &CancellationToken) {
        self.kept = self.baselines.count().unwrap_or_else(|e| {
            warn!(error = %e, "file baselines could not be counted");
            0
        });
        self.metrics.set_file_baselines(self.kept);
        let mut last = None;
        let mut open = false;
        while !cancel.is_cancelled() {
            if !open {
                open = self.open(&mut last);
                if !open {
                    if Self::pause(self.reopen_delay, cancel) {
                        return;
                    }
                    continue;
                }
            }
            // Paths still waiting to be read are not waited on.
            let wait = if self.pending.is_empty() {
                FILE_WATCH_READ_WAIT
            } else {
                Duration::ZERO
            };
            match self.source.read(wait) {
                Ok(batch) => {
                    self.record(&batch);
                    self.queue(&batch);
                }
                Err(e) => {
                    debug!(error = %e, "file watch reading failed, opening it again");
                    open = false;
                    continue;
                }
            }
            if !self.pending.is_empty()
                && let Err(e) = self.settle()
            {
                debug!(error = %e, "changed paths could not be read, opening the watch again");
                open = false;
            }
        }
    }
}

/// Wall clock nanoseconds, the time a settled change is dated with.
fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use domain::common::error::DomainError;
    use domain::file_watch::{FileBaseline, FileChange, FileType};
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };

    use domain::process::entity::ProcessLifecycleEvent;
    use tokio::sync::mpsc;

    use crate::alert_event::AlertEvent;

    use super::*;

    #[derive(Default)]
    struct Counted {
        changes: Mutex<BTreeMap<String, u64>>,
        overflows: AtomicU64,
        filesystems: Mutex<Vec<(u64, u64)>>,
        drifts: Mutex<BTreeMap<String, u64>>,
        baselines: AtomicU64,
        refused: AtomicU64,
    }

    impl PacketMetrics for Counted {}
    impl FirewallMetrics for Counted {}
    impl AlertMetrics for Counted {}
    impl IpsMetrics for Counted {}
    impl DnsMetrics for Counted {}
    impl DomainMetrics for Counted {}
    impl ConfigMetrics for Counted {}
    impl EventMetrics for Counted {}
    impl DlpMetrics for Counted {}
    impl DdosMetrics for Counted {}
    impl ConntrackMetrics for Counted {}
    impl RoutingMetrics for Counted {}
    impl AuditMetrics for Counted {}
    impl LbMetrics for Counted {}
    impl FingerprintMetrics for Counted {}
    impl ContainerMetrics for Counted {}
    impl CtMetrics for Counted {}
    impl ThreatIntelMetrics for Counted {}
    impl ZoneMetrics for Counted {}
    impl SystemMetrics for Counted {
        fn record_file_changes(&self, kind: &str, count: u64) {
            *self
                .changes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(kind.to_owned())
                .or_default() += count;
        }
        fn record_file_change_overflow(&self) {
            self.overflows.fetch_add(1, Ordering::Relaxed);
        }
        fn set_file_watch_filesystems(&self, watched: u64, refused: u64) {
            self.filesystems
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((watched, refused));
        }
        fn record_file_drifts(&self, what: &str, count: u64) {
            *self
                .drifts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .entry(what.to_owned())
                .or_default() += count;
        }
        fn set_file_baselines(&self, count: u64) {
            self.baselines.store(count, Ordering::Relaxed);
        }
        fn record_file_baseline_refused(&self) {
            self.refused.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl Counted {
        fn drifts(&self) -> BTreeMap<String, u64> {
            self.drifts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    #[derive(Default)]
    struct Memory(Mutex<BTreeMap<String, FileBaseline>>);

    impl Memory {
        fn map(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, FileBaseline>> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }
    }

    impl FileBaselineStore for Memory {
        fn get(&self, path: &str) -> Result<Option<FileBaseline>, DomainError> {
            Ok(self.map().get(path).cloned())
        }
        fn put(&self, path: &str, baseline: &FileBaseline) -> Result<(), DomainError> {
            self.map().insert(path.to_owned(), baseline.clone());
            Ok(())
        }
        fn remove(&self, path: &str) -> Result<bool, DomainError> {
            Ok(self.map().remove(path).is_some())
        }
        fn count(&self) -> Result<u64, DomainError> {
            Ok(self.map().len() as u64)
        }
    }

    /// Answers each call from a script, then cancels the watcher.
    struct Scripted {
        opens: Vec<Result<Vec<WatchedFilesystem>, DomainError>>,
        reads: Vec<Result<FileChangeBatch, DomainError>>,
        /// What each path reads as, one answer used per question.
        facts: Vec<Result<Vec<FileFacts>, DomainError>>,
        cancel: CancellationToken,
        opened: Arc<AtomicU64>,
    }

    impl FileWatchSource for Scripted {
        fn open(&mut self, _paths: &[String]) -> Result<Vec<WatchedFilesystem>, DomainError> {
            self.opened.fetch_add(1, Ordering::Relaxed);
            if self.opens.is_empty() {
                self.cancel.cancel();
                return Ok(Vec::new());
            }
            self.opens.remove(0)
        }

        fn read(&mut self, _max_wait: Duration) -> Result<FileChangeBatch, DomainError> {
            if self.reads.is_empty() {
                self.cancel.cancel();
                return Ok(FileChangeBatch::default());
            }
            self.reads.remove(0)
        }

        fn facts(
            &mut self,
            paths: &[String],
            _max_hash_bytes: u64,
        ) -> Result<Vec<FileFacts>, DomainError> {
            if self.facts.is_empty() {
                return Err(DomainError::EngineError("no facts scripted".into()));
            }
            let answer = self.facts.remove(0)?;
            assert!(
                answer.iter().all(|f| paths.contains(&f.path)),
                "answered {answer:?} for {paths:?}"
            );
            Ok(answer)
        }

        fn source(&self) -> &'static str {
            "local"
        }
    }

    fn watched(path: &str) -> WatchedFilesystem {
        WatchedFilesystem {
            path: path.into(),
            error: None,
        }
    }

    fn refused(path: &str) -> WatchedFilesystem {
        WatchedFilesystem {
            path: path.into(),
            error: Some("this filesystem cannot report file handles".into()),
        }
    }

    fn change(kinds: Vec<FileChangeKind>) -> FileChange {
        FileChange {
            kinds,
            is_dir: false,
            pid: 7,
            directory: Some("/etc".into()),
            name: "hosts".into(),
            dev: Some(1),
            ino: Some(2),
            unresolved: None,
        }
    }

    fn watcher(source: Scripted, metrics: Arc<Counted>) -> FileWatcher {
        watcher_with(source, metrics, Arc::new(Memory::default()), 10)
    }

    fn watcher_with(
        source: Scripted,
        metrics: Arc<Counted>,
        store: Arc<Memory>,
        max_files: u64,
    ) -> FileWatcher {
        let mut w = FileWatcher::new(
            Box::new(source),
            vec!["/".into(), "/var/lib/containerd".into()],
            metrics,
            store,
            BaselinePolicy {
                max_hash_bytes: 1024,
                max_files,
            },
        );
        w.reopen_delay = Duration::ZERO;
        w
    }

    #[test]
    fn changes_are_counted_by_kind_and_a_lost_queue_is_counted() {
        let cancel = CancellationToken::new();
        let metrics = Arc::new(Counted::default());
        let source = Scripted {
            opens: vec![Ok(vec![watched("/"), refused("/var/lib/containerd")])],
            reads: vec![Ok(FileChangeBatch {
                changes: vec![
                    change(vec![FileChangeKind::Created, FileChangeKind::Written]),
                    change(vec![FileChangeKind::Written]),
                ],
                overflowed: true,
            })],
            facts: vec![Ok(Vec::new())],
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        watcher(source, Arc::clone(&metrics)).run_blocking(&cancel);
        let changes = metrics
            .changes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(changes.get("written"), Some(&2));
        assert_eq!(changes.get("created"), Some(&1));
        assert_eq!(metrics.overflows.load(Ordering::Relaxed), 1);
        let filesystems = metrics
            .filesystems
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        assert_eq!(filesystems.first(), Some(&(1, 1)));
    }

    #[test]
    fn a_failed_reading_opens_the_watch_again() {
        let cancel = CancellationToken::new();
        let opened = Arc::new(AtomicU64::new(0));
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")]), Ok(vec![watched("/")])],
            reads: vec![
                Err(DomainError::EngineError("no file watch is open".into())),
                Ok(FileChangeBatch::default()),
            ],
            facts: Vec::new(),
            cancel: cancel.clone(),
            opened: Arc::clone(&opened),
        };
        watcher(source, Arc::new(Counted::default())).run_blocking(&cancel);
        assert_eq!(opened.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn a_watch_covering_nothing_is_retried_and_never_read() {
        let cancel = CancellationToken::new();
        let opened = Arc::new(AtomicU64::new(0));
        let source = Scripted {
            opens: vec![
                Ok(vec![refused("/")]),
                Err(DomainError::EngineError("warden unreachable".into())),
            ],
            // A read would cancel early and leave `opened` at one.
            reads: vec![Err(DomainError::EngineError("must not be read".into()))],
            facts: Vec::new(),
            cancel: cancel.clone(),
            opened: Arc::clone(&opened),
        };
        let metrics = Arc::new(Counted::default());
        watcher(source, Arc::clone(&metrics)).run_blocking(&cancel);
        assert_eq!(opened.load(Ordering::Relaxed), 3);
        assert!(
            metrics
                .changes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_empty()
        );
    }

    fn file(sha: char, mode: u32) -> FileBaseline {
        FileBaseline {
            file_type: FileType::Regular,
            size: 4,
            mtime_ns: 9,
            mode,
            uid: 0,
            gid: 0,
            dev: 1,
            ino: 2,
            link_target: None,
            sha256: Some(sha.to_string().repeat(64)),
            hash_unread: None,
            xattrs: Vec::new(),
            xattrs_unread: None,
        }
    }

    fn fact(path: &str, reading: FileReading) -> FileFacts {
        FileFacts {
            path: path.into(),
            reading,
        }
    }

    fn written() -> FileChangeBatch {
        FileChangeBatch {
            changes: vec![change(vec![FileChangeKind::Written])],
            overflowed: false,
        }
    }

    fn run(facts: Vec<Vec<FileFacts>>, reads: usize, store: Arc<Memory>, max: u64) -> Arc<Counted> {
        let facts = facts.into_iter().map(Ok).collect();
        let cancel = CancellationToken::new();
        let metrics = Arc::new(Counted::default());
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")])],
            reads: (0..reads).map(|_| Ok(written())).collect(),
            facts,
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        watcher_with(source, Arc::clone(&metrics), store, max).run_blocking(&cancel);
        metrics
    }

    #[test]
    fn a_first_sight_is_kept_and_raises_nothing() {
        let store = Arc::new(Memory::default());
        let metrics = run(
            vec![vec![fact(
                "/etc/hosts",
                FileReading::Present(file('a', 0o644)),
            )]],
            1,
            Arc::clone(&store),
            10,
        );
        assert!(metrics.drifts().is_empty());
        assert_eq!(store.map().get("/etc/hosts"), Some(&file('a', 0o644)));
        assert_eq!(metrics.baselines.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_later_reading_is_compared_and_replaces_the_baseline() {
        let store = Arc::new(Memory::default());
        let metrics = run(
            vec![
                vec![fact("/etc/hosts", FileReading::Present(file('a', 0o644)))],
                vec![fact("/etc/hosts", FileReading::Present(file('b', 0o666)))],
            ],
            2,
            Arc::clone(&store),
            10,
        );
        let drifts = metrics.drifts();
        assert_eq!(drifts.get("content"), Some(&1));
        assert_eq!(drifts.get("mode"), Some(&1));
        assert_eq!(store.map().get("/etc/hosts"), Some(&file('b', 0o666)));
    }

    #[test]
    fn a_path_that_disappears_is_reported_and_forgotten() {
        let store = Arc::new(Memory::default());
        store.map().insert("/etc/hosts".into(), file('a', 0o644));
        let metrics = run(
            vec![vec![fact("/etc/hosts", FileReading::Gone)]],
            1,
            Arc::clone(&store),
            10,
        );
        assert_eq!(metrics.drifts().get("disappeared"), Some(&1));
        assert!(store.map().is_empty());
        assert_eq!(metrics.baselines.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn an_unreadable_path_keeps_its_baseline() {
        let store = Arc::new(Memory::default());
        store.map().insert("/etc/hosts".into(), file('a', 0o644));
        let metrics = run(
            vec![vec![fact(
                "/etc/hosts",
                FileReading::Unreadable("permission denied".into()),
            )]],
            1,
            Arc::clone(&store),
            10,
        );
        assert_eq!(metrics.drifts().get("unreadable"), Some(&1));
        assert_eq!(store.map().get("/etc/hosts"), Some(&file('a', 0o644)));
    }

    #[test]
    fn a_full_store_refuses_a_new_path_and_counts_it() {
        let store = Arc::new(Memory::default());
        store.map().insert("/etc/passwd".into(), file('a', 0o644));
        let metrics = run(
            vec![vec![fact(
                "/etc/hosts",
                FileReading::Present(file('a', 0o644)),
            )]],
            1,
            Arc::clone(&store),
            1,
        );
        assert_eq!(metrics.refused.load(Ordering::Relaxed), 1);
        assert!(!store.map().contains_key("/etc/hosts"));
    }

    #[test]
    fn paths_the_reader_could_not_answer_are_asked_again_after_a_reopen() {
        let store = Arc::new(Memory::default());
        let cancel = CancellationToken::new();
        let opened = Arc::new(AtomicU64::new(0));
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")]), Ok(vec![watched("/")])],
            reads: vec![Ok(written()), Ok(FileChangeBatch::default())],
            facts: vec![
                Err(DomainError::EngineError("no file watch is open".into())),
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('a', 0o644)),
                )]),
            ],
            cancel: cancel.clone(),
            opened: Arc::clone(&opened),
        };
        watcher_with(source, Arc::new(Counted::default()), Arc::clone(&store), 10)
            .run_blocking(&cancel);
        assert_eq!(opened.load(Ordering::Relaxed), 2);
        assert!(store.map().contains_key("/etc/hosts"));
    }

    #[test]
    fn a_change_names_its_directory_and_entry_once() {
        let mut w = watcher(
            Scripted {
                opens: Vec::new(),
                reads: Vec::new(),
                facts: Vec::new(),
                cancel: CancellationToken::new(),
                opened: Arc::new(AtomicU64::new(0)),
            },
            Arc::new(Counted::default()),
        );
        let mut root = change(vec![FileChangeKind::Created]);
        root.directory = Some("/".into());
        let mut dir_itself = change(vec![FileChangeKind::AttributesChanged]);
        dir_itself.name = String::new();
        let mut unnamed = change(vec![FileChangeKind::Written]);
        unnamed.directory = None;
        let mut later = change(vec![FileChangeKind::Written]);
        later.pid = 8;
        w.queue(&FileChangeBatch {
            changes: vec![
                change(vec![FileChangeKind::Written]),
                root,
                dir_itself,
                unnamed,
                later,
            ],
            overflowed: false,
        });
        let pending: Vec<_> = w
            .pending
            .iter()
            .map(|(p, pending)| (p.as_str(), pending.pid))
            .collect();
        assert_eq!(pending, vec![("/etc", 7), ("/etc/hosts", 8), ("/hosts", 7)]);
    }

    /// A writer whose root is the overlay of one container.
    struct Overlay;
    impl ProcessRootReader for Overlay {
        fn root_mount(&self, pid: u32) -> Option<RootMount> {
            (pid == 42).then(|| RootMount {
                fstype: "overlay".into(),
                upper: Some("/var/lib/c/9/fs".into()),
                lowers: vec!["/var/lib/c/3/fs".into()],
            })
        }
    }

    fn lifecycle(pid: u32, parent: Option<u32>, comm: &str) -> ProcessLifecycleEvent {
        ProcessLifecycleEvent {
            kind: domain::process::entity::ProcessEventKind::Exec,
            pid,
            tgid: pid,
            uid: 0,
            gid: 0,
            cgroup_id: 9,
            comm: comm.into(),
            at_ns: u64::from(pid),
            start_ns: None,
            parent_pid: parent,
            parent_start_ns: None,
        }
    }

    /// A table holding `sshd` (pid 10) and the shell it started (pid 42).
    async fn table() -> Arc<ProcessTableService> {
        let table = Arc::new(ProcessTableService::new(16, false));
        table.apply(lifecycle(10, None, "sshd")).await;
        table.apply(lifecycle(42, Some(10), "sh")).await;
        table
    }

    /// One rule in force per `(id, when)`.
    fn rules(whens: &[(&str, &str)]) -> (Arc<HostRuleService>, mpsc::Receiver<AlertEvent>) {
        let specs: Vec<domain::hostrule::HostRuleSpec> = whens
            .iter()
            .map(|(id, when)| {
                serde_json::from_str(&format!(
                    r#"{{"id":"{id}","mode":"enforce","when":{{{when}}}}}"#
                ))
                .unwrap()
            })
            .collect();
        let (tx, rx) = mpsc::channel(8);
        let set = domain::hostrule::HostRuleSet::compile(specs).unwrap();
        (Arc::new(HostRuleService::new(set, tx)), rx)
    }

    fn alerts(rx: &mut mpsc::Receiver<AlertEvent>) -> Vec<domain::alert::entity::Alert> {
        let mut out = Vec::new();
        while let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() {
            out.push(*alert);
        }
        out
    }

    /// One settled change of `host` by pid 42, the reader answering each
    /// question from `answers` in turn.
    fn settle_one(
        w: &mut FileWatcher,
        host: &str,
        kinds: Vec<FileChangeKind>,
        answers: Vec<Vec<FileFacts>>,
    ) {
        let (directory, name) = host.rsplit_once('/').unwrap();
        let mut change = change(kinds);
        change.pid = 42;
        change.directory = Some(directory.into());
        change.name = name.into();
        w.queue(&FileChangeBatch {
            changes: vec![change],
            overflowed: false,
        });
        let source = Scripted {
            opens: Vec::new(),
            reads: Vec::new(),
            facts: answers.into_iter().map(Ok).collect(),
            cancel: CancellationToken::new(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        w.source = Box::new(source);
        w.settle().unwrap();
    }

    fn fed(
        rules: Arc<HostRuleService>,
        processes: Arc<ProcessTableService>,
        store: Arc<Memory>,
    ) -> FileWatcher {
        watcher_with(
            Scripted {
                opens: Vec::new(),
                reads: Vec::new(),
                facts: Vec::new(),
                cancel: CancellationToken::new(),
                opened: Arc::new(AtomicU64::new(0)),
            },
            Arc::new(Counted::default()),
            store,
            10,
        )
        .with_rules(FileRuleFeed {
            rules,
            processes: Some(processes),
            roots: Some(Arc::new(Overlay)),
        })
    }

    const KEYS: &str = "/var/lib/c/9/fs/root/.ssh/authorized_keys";

    #[tokio::test]
    async fn a_new_file_in_a_container_names_its_writer_and_ancestry() {
        let (rules, mut rx) = rules(&[(
            "keys",
            r#""file.appears":{"path":"/root/.ssh/authorized_keys"}"#,
        )]);
        let mut w = fed(rules, table().await, Arc::new(Memory::default()));
        settle_one(
            &mut w,
            KEYS,
            vec![FileChangeKind::Created, FileChangeKind::Written],
            vec![
                vec![fact(KEYS, FileReading::Present(file('a', 0o600)))],
                vec![fact(
                    "/var/lib/c/3/fs/root/.ssh/authorized_keys",
                    FileReading::Gone,
                )],
            ],
        );
        let raised = alerts(&mut rx);
        assert_eq!(raised.len(), 1);
        let workload = raised[0].workload.as_ref().unwrap();
        assert_eq!(workload.pid, 42);
        let ancestry = workload.ancestry.as_ref().unwrap();
        assert_eq!(ancestry.ancestors[0].pid, 10);
        assert_eq!(ancestry.ancestors[0].name, "sshd");
    }

    #[tokio::test]
    async fn a_move_over_a_known_file_is_a_change_and_not_a_disappearance() {
        let (rules, mut rx) = rules(&[
            (
                "changed",
                r#""file.changes":{"path":"/root/.ssh/authorized_keys"}"#,
            ),
            (
                "gone",
                r#""file.disappears":{"path":"/root/.ssh/authorized_keys"}"#,
            ),
        ]);
        let store = Arc::new(Memory::default());
        store.map().insert(KEYS.into(), file('a', 0o600));
        let mut w = fed(rules, table().await, store);
        settle_one(
            &mut w,
            KEYS,
            vec![FileChangeKind::MovedIn],
            vec![vec![fact(KEYS, FileReading::Present(file('b', 0o600)))]],
        );
        let raised = alerts(&mut rx);
        assert_eq!(raised.len(), 1, "{raised:?}");
        assert_eq!(raised[0].rule_id.0, "changed");
    }

    #[tokio::test]
    async fn a_first_write_to_a_file_of_the_image_is_a_change() {
        let (rules, mut rx) = rules(&[("passwd", r#""file.changes":{"path":"/etc/passwd"}"#)]);
        let mut w = fed(rules, table().await, Arc::new(Memory::default()));
        let host = "/var/lib/c/9/fs/etc/passwd";
        settle_one(
            &mut w,
            host,
            vec![FileChangeKind::Created, FileChangeKind::Written],
            vec![
                vec![fact(host, FileReading::Present(file('a', 0o644)))],
                vec![fact(
                    "/var/lib/c/3/fs/etc/passwd",
                    FileReading::Present(file('b', 0o644)),
                )],
            ],
        );
        assert_eq!(alerts(&mut rx).len(), 1, "copied up from the image");
    }
}
