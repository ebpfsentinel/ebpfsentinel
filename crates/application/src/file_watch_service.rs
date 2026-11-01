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
//!
//! The agent's own files are watched whatever the configuration names: the
//! filesystem holding each is opened, each is read and kept as soon as the
//! watch is, past the cap on baselines, and a difference another process
//! leaves on one is an alert rather than a log line. A difference found
//! when the watch is opened again, after a gap nothing was read in, is one
//! too; the first opening only learns, since an upgrade replaces the binary
//! and the objects while the agent is stopped.
//!
//! The watched paths, declared in the configuration or named by a profile,
//! decide what a difference elsewhere amounts to: one under a watched path is
//! an alert, and so is a file arriving under a watched directory. A watched
//! path is read as soon as the watch opens, past the cap, so its first change
//! is compared rather than learned. The set can be swapped whole while the
//! watch runs; the watch is opened again on the filesystems the new set needs.

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use domain::alert::entity::Alert;
use domain::file_watch::{
    ExpectedBaseline, ExpectedBaselines, FileBaseline, FileChange, FileChangeBatch, FileChangeKind,
    FileDrift, FileFacts, FileFingerprint, FileReading, OwnFiles, PlantedCanary, RootMount,
    RootedPath, SettledPath, WatchedFilesystem, WatchedPaths, own_file_change, rooted,
    watched_path_change,
};
use domain::hostrule::{Intent, SettledChange, file_events};
use domain::process::engine::Lineage;
use domain::process::entity::ProcessEntry;
use domain::ransom::{canary_exempt, written_now};
use ports::secondary::file_watch_port::{FileBaselineStore, FileWatchSource, ProcessRootReader};
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::alert_event::AlertEvent;
use crate::host_rule_service::HostRuleService;
use crate::process_table_service::ProcessTableService;
use crate::ransom_service::{FileRewrite, RansomService};
use crate::workload_resolver::WorkloadResolver;

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
const FILE_INTENTS: [Intent; 6] = [
    Intent::FileChanges,
    Intent::FileAppears,
    Intent::FileDisappears,
    Intent::FileRenames,
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
    /// The last writer as the process table named it when the change
    /// arrived, with its ancestry. Read then rather than when the path is
    /// read back, because a worker that writes its share and exits is gone
    /// from the table by the time the batch settles.
    writer: Option<(Lineage, ProcessEntry)>,
    /// The host path a rename reported with both names moved the entry from.
    renamed_from: Option<String>,
    /// The path is the old end of a rename reported with both names.
    renamed_away: bool,
}

/// Where settled changes go beyond the baseline: the host rules, the
/// process table naming each writer, and the reader of each writer's root.
pub struct FileRuleFeed {
    pub rules: Arc<HostRuleService>,
    pub processes: Option<Arc<ProcessTableService>>,
    pub roots: Option<Arc<dyn ProcessRootReader>>,
    /// Where every change by a named writer is counted toward a mass
    /// encryption verdict, whatever the rules ask for.
    pub ransom: Option<Arc<RansomService>>,
}

/// Canary files planted into data directories, and the executables whose
/// opens of one are not a signal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanaryWatch {
    /// Where each canary is planted.
    pub paths: Vec<String>,
    /// Executables, by full path, that read every file of a directory by
    /// design: a backup tool or a virus scanner.
    pub exempt: Vec<String>,
}

impl CanaryWatch {
    /// The directories the canaries sit in, each once, in order.
    #[must_use]
    pub fn directories(&self) -> Vec<String> {
        let mut dirs: Vec<String> = Vec::new();
        for path in &self.paths {
            let dir = match path.rsplit_once('/') {
                Some(("", _)) => "/",
                Some((dir, _)) => dir,
                None => continue,
            };
            if !dirs.iter().any(|d| d == dir) {
                dirs.push(dir.to_owned());
            }
        }
        dirs
    }
}

/// The path a change names: its directory joined with its name.
fn change_path(change: &FileChange) -> Option<String> {
    let directory = change.directory.as_deref()?;
    Some(if change.name.is_empty() {
        directory.to_owned()
    } else if directory.ends_with('/') {
        format!("{directory}{}", change.name)
    } else {
        format!("{directory}/{}", change.name)
    })
}

/// The agent's own files, and where a change another process makes to one
/// goes.
pub struct OwnFileGuard {
    pub files: OwnFiles,
    /// The agent's pid as the watch reports writers: its own writes are not
    /// an alert.
    pub own_pid: u32,
    pub alerts: mpsc::Sender<AlertEvent>,
    pub workloads: WorkloadResolver,
}

/// The watched paths, swapped whole while the watch runs.
///
/// Each replacement that changes the set moves its generation, which is how
/// the watcher learns to open the watch again on what the new set needs.
#[derive(Debug, Default)]
pub struct WatchedPathSet {
    inner: RwLock<(u64, Arc<WatchedPaths>)>,
}

impl WatchedPathSet {
    #[must_use]
    pub fn new(paths: WatchedPaths) -> Self {
        Self {
            inner: RwLock::new((0, Arc::new(paths))),
        }
    }

    /// Put `paths` in force, and say whether that changed anything.
    pub fn replace(&self, paths: WatchedPaths) -> bool {
        // A replacement is one assignment, so a poisoned lock still holds a
        // whole set.
        let mut held = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if *held.1 == paths {
            return false;
        }
        *held = (held.0 + 1, Arc::new(paths));
        true
    }

    /// The set in force and its generation.
    #[must_use]
    pub fn current(&self) -> (u64, Arc<WatchedPaths>) {
        let held = self.inner.read().unwrap_or_else(PoisonError::into_inner);
        (held.0, Arc::clone(&held.1))
    }
}

/// The state a fleet expects of its watched files, swapped whole while the
/// watch runs.
///
/// A path this node has no baseline of yet is compared against it instead
/// of learned, so a node joining an estate is held to what its peers carry
/// rather than to whatever its disk held when the agent first started.
#[derive(Debug, Default)]
pub struct ExpectedBaselineSet {
    inner: RwLock<Arc<ExpectedBaselines>>,
}

impl ExpectedBaselineSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Put `expected` in force, and say whether that changed anything.
    pub fn replace(&self, expected: ExpectedBaselines) -> bool {
        // One assignment: a poisoned lock still holds a whole set.
        let mut held = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        if **held == expected {
            return false;
        }
        *held = Arc::new(expected);
        true
    }

    /// The set in force.
    #[must_use]
    pub fn current(&self) -> Arc<ExpectedBaselines> {
        Arc::clone(&self.inner.read().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Most baselines one node lists for its fleet to compare.
pub const LISTED_BASELINES_MAX: usize = 10_000;

/// The fingerprints this node keeps for every watched path and what lies
/// beneath it, in path order, at most `limit`, and whether more were left
/// out. This is the shape a fleet's expected state is written in, so what
/// one node lists can be handed back to every other.
///
/// # Errors
///
/// The store could not be read.
pub fn listed_baselines(
    store: &dyn FileBaselineStore,
    watched: &WatchedPaths,
    limit: usize,
) -> Result<(Vec<ExpectedBaseline>, bool), String> {
    let mut listed = Vec::new();
    let mut truncated = false;
    let mut seen = BTreeSet::new();
    for path in watched.paths() {
        let room = limit.saturating_sub(listed.len());
        // One more than the room says whether anything was left out.
        let found = store
            .under(path, room.saturating_add(1))
            .map_err(|e| e.to_string())?;
        for (key, baseline) in found {
            if listed.len() >= limit {
                truncated = true;
                break;
            }
            // A watched file beneath a watched directory is listed once.
            if seen.insert(key.clone()) {
                listed.push(ExpectedBaseline {
                    path: key,
                    fingerprint: FileFingerprint::of(&baseline),
                });
            }
        }
    }
    listed.sort_by(|a, b| a.path.cmp(&b.path));
    Ok((listed, truncated))
}

/// What a difference on a watched path is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Basis {
    /// Nothing: the path is seen for the first time.
    Unknown,
    /// This node's own baseline.
    Kept,
    /// The fleet's expected state.
    Expected,
}

/// The watched paths, and where a difference under one goes.
pub struct WatchedPathGuard {
    pub set: Arc<WatchedPathSet>,
    /// The agent's pid as the watch reports writers: its own writes are not
    /// an alert.
    pub own_pid: u32,
    pub alerts: mpsc::Sender<AlertEvent>,
    pub workloads: WorkloadResolver,
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
    own: Option<OwnFileGuard>,
    /// How many of `paths` the configuration named; the rest hold the
    /// agent's own files.
    configured: usize,
    /// Whether the agent's files were read once already.
    primed: bool,
    watched: Option<WatchedPathGuard>,
    /// The watched set the watch was last opened for, and its generation.
    watching: (u64, Arc<WatchedPaths>),
    /// Watched paths read once already: a later reading reports what
    /// differs, the first only learns.
    learned: BTreeSet<String>,
    /// The fleet's expected state, compared on a path's first sight.
    expected: Option<Arc<ExpectedBaselineSet>>,
    canaries: Option<CanaryWatch>,
    /// The canaries standing now, by path.
    planted: BTreeSet<String>,
    /// What the last planting answered, so an unchanged answer is not
    /// logged again.
    planted_last: Option<Vec<PlantedCanary>>,
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
            configured: paths.len(),
            paths,
            metrics,
            baselines,
            policy,
            pending: BTreeMap::new(),
            kept: 0,
            reopen_delay: FILE_WATCH_REOPEN_DELAY,
            feed: None,
            own: None,
            primed: false,
            watched: None,
            watching: (0, Arc::new(WatchedPaths::new())),
            learned: BTreeSet::new(),
            expected: None,
            canaries: None,
            planted: BTreeSet::new(),
            planted_last: None,
        }
    }

    /// Plant canary files and raise any open of one by a process not
    /// exempt as a decisive mass encryption signal.
    #[must_use]
    pub fn with_canaries(mut self, canaries: CanaryWatch) -> Self {
        for dir in canaries.directories() {
            if !self.paths.contains(&dir) {
                self.paths.push(dir);
            }
        }
        self.canaries = Some(canaries);
        self
    }

    /// Plant every canary, after an opening: a new watch holds no mark on
    /// one, and a canary already standing is kept.
    fn plant_canaries(&mut self) {
        let Some(canaries) = self.canaries.as_ref().filter(|c| !c.paths.is_empty()) else {
            return;
        };
        let planted = match self.source.plant(&canaries.paths) {
            Ok(planted) => planted,
            Err(e) => {
                warn!(error = %e, "canary files could not be planted");
                self.planted.clear();
                return;
            }
        };
        self.planted = planted
            .iter()
            .filter(|c| c.error.is_none())
            .map(|c| c.path.clone())
            .collect();
        if self.planted_last.as_ref() != Some(&planted) {
            info!(
                planted = self.planted.len(),
                refused = planted.len() - self.planted.len(),
                "canary files planted"
            );
            for canary in &planted {
                if let Some(reason) = &canary.error {
                    warn!(path = %canary.path, reason = %reason, "no canary file is planted at this path");
                }
            }
        }
        self.planted_last = Some(planted);
    }

    /// Every canary one reading reports opened, moved or deleted, raised
    /// once per process and path; a canary taken away is planted again.
    fn canaries_touched(&mut self, batch: &FileChangeBatch) {
        if self.planted.is_empty() {
            return;
        }
        // Only a canary carries an open mark, so every open reported is one.
        let mut touched: Vec<(u32, Option<String>)> = batch
            .opened
            .iter()
            .map(|o| (o.pid, o.path.clone()))
            .collect();
        let mut gone: Vec<String> = Vec::new();
        for change in &batch.changes {
            let path = change_path(change);
            let left = change
                .renamed_from
                .as_ref()
                .filter(|from| self.planted.contains(from.as_str()));
            if let Some(from) = left {
                gone.push(from.clone());
                touched.push((change.pid, Some(from.clone())));
            }
            let Some(path) = path.filter(|p| self.planted.contains(p)) else {
                continue;
            };
            if change
                .kinds
                .iter()
                .any(|k| matches!(k, FileChangeKind::Deleted | FileChangeKind::MovedOut))
            {
                gone.push(path.clone());
            }
            touched.push((change.pid, Some(path)));
        }
        touched.sort();
        touched.dedup();
        let at_ns = now_ns();
        for (pid, path) in touched {
            self.canary_touched(pid, path.as_deref(), at_ns);
        }
        if !gone.is_empty() {
            gone.sort();
            gone.dedup();
            self.replant(&gone);
        }
    }

    /// Plant again the canaries in `paths`, taken away by a process.
    fn replant(&mut self, paths: &[String]) {
        match self.source.plant(paths) {
            Ok(planted) => {
                for canary in planted {
                    if let Some(reason) = canary.error {
                        self.planted.remove(&canary.path);
                        warn!(path = %canary.path, reason = %reason, "a canary file taken away could not be planted again");
                    }
                }
            }
            Err(e) => warn!(error = %e, "canary files taken away could not be planted again"),
        }
    }

    /// One canary opened by `pid`: logged, and counted toward a verdict
    /// unless its executable is exempt.
    fn canary_touched(&self, pid: u32, path: Option<&str>, at_ns: u64) {
        let shown = path.unwrap_or("-");
        let feed = self.feed.as_ref();
        let named = feed
            .and_then(|f| f.processes.as_ref())
            .and_then(|table| table.get(pid).map(|entry| (table.lineage(pid), entry)));
        let Some((lineage, entry)) = named else {
            warn!(
                path = shown,
                pid, "canary file opened by a process the agent could not name"
            );
            return;
        };
        let exe = entry.identity.path();
        let exempt = self
            .canaries
            .as_ref()
            .is_some_and(|c| canary_exempt(exe, &c.exempt));
        if exempt {
            debug!(
                path = shown,
                pid, exe, "canary file opened by an exempt executable"
            );
            return;
        }
        warn!(path = shown, pid, exe, "canary file opened");
        if let Some(ransom) = feed.and_then(|f| f.ransom.as_ref()) {
            ransom.record_canary(&entry, &lineage, path, at_ns);
        }
    }

    /// Compare a watched path seen for the first time against the fleet's
    /// expected state rather than learning it.
    #[must_use]
    pub fn with_expected(mut self, expected: Arc<ExpectedBaselineSet>) -> Self {
        self.expected = Some(expected);
        self
    }

    /// The fingerprint the fleet expects at `path`.
    fn expected_at(&self, path: &str) -> Option<FileFingerprint> {
        self.expected
            .as_ref()
            .and_then(|set| set.current().get(path).cloned())
    }

    /// Alert on a difference under a watched path, and follow the set as it
    /// is replaced.
    #[must_use]
    pub fn with_watched_paths(mut self, guard: WatchedPathGuard) -> Self {
        self.watching = guard.set.current();
        self.watched = Some(guard);
        self
    }

    /// Watch the agent's own files as well, alerting on a change another
    /// process makes to one.
    #[must_use]
    pub fn with_own_files(mut self, guard: OwnFileGuard) -> Self {
        for dir in guard.files.directories() {
            if !self.paths.contains(&dir) {
                self.paths.push(dir);
            }
        }
        self.own = Some(guard);
        self
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
        if let Some(guard) = self.watched.as_ref() {
            self.watching = guard.set.current();
        }
        let mut paths = self.paths.clone();
        for dir in self.watching.1.directories() {
            if !paths.contains(&dir) {
                paths.push(dir);
            }
        }
        let marks = match self.source.open(&paths) {
            Ok(marks) => marks,
            Err(e) => {
                warn!(source = self.source.source(), error = %e, "file watch could not be opened");
                self.metrics.set_file_watch_filesystems(0, 0);
                return false;
            }
        };
        let named = &marks[..self.configured.min(marks.len())];
        let watched = named.iter().filter(|m| m.is_watched()).count();
        let refused = named.len() - watched;
        self.metrics
            .set_file_watch_filesystems(watched as u64, refused as u64);
        // A reopen that changes nothing is not news: the outcome of every
        // mark is logged when it differs from the last time.
        if last.as_ref() != Some(&marks) {
            for mark in &marks {
                match &mark.error {
                    None if mark.renames => {
                        info!(path = %mark.path, "file watch covers the filesystem holding this path");
                    }
                    None => {
                        warn!(
                            path = %mark.path,
                            "file watch covers the filesystem holding this path, but its kernel \
                             reports no rename with both names: a rename there reads as a \
                             disappearance plus an appearance"
                        );
                    }
                    Some(reason) => {
                        warn!(path = %mark.path, reason = %reason, "file watch does not cover this path");
                    }
                }
            }
        }
        let any = marks.iter().any(WatchedFilesystem::is_watched);
        *last = Some(marks);
        any
    }

    /// Read the agent's own files and keep each, past the cap. The first
    /// time only learns; a later opening follows a gap in which nothing was
    /// read, so what differs then is reported.
    fn prime_own(&mut self) {
        let Some(guard) = self.own.as_ref() else {
            return;
        };
        let paths: Vec<String> = guard.files.paths().map(ToOwned::to_owned).collect();
        let facts = match self.read_all(&paths) {
            Ok(facts) => facts,
            Err(e) => {
                warn!(error = %e, "the agent's own files could not be read");
                return;
            }
        };
        let first = !self.primed;
        self.primed = true;
        let unseen = BTreeSet::new();
        for fact in facts {
            let kept = match self.baselines.get(&fact.path) {
                Ok(kept) => kept,
                Err(e) => {
                    warn!(path = %fact.path, error = %e, "file baseline could not be read");
                    continue;
                }
            };
            if let Some(old) = &kept {
                let drift = old.drift(&fact.reading);
                if first {
                    if !drift.is_empty() {
                        let what: Vec<&str> = drift.iter().map(|d| d.as_str()).collect();
                        info!(path = %fact.path, drift = ?what, "the agent's file differs from when it last ran");
                    }
                } else {
                    self.guard(&fact.path, &unseen, &drift, 0);
                }
            }
            self.keep_listed(&fact, kept.is_some());
        }
        self.metrics.set_file_baselines(self.kept);
    }

    /// Read every watched path and keep each, past the cap. A path read for
    /// the first time only learns; one read before follows a gap in which
    /// nothing was read, so what differs then is reported.
    fn prime_watched(&mut self) {
        if self.watched.is_none() {
            return;
        }
        let watching = Arc::clone(&self.watching.1);
        let mut paths: Vec<String> = watching
            .paths()
            .filter(|path| !self.is_own(path))
            .map(ToOwned::to_owned)
            .collect();
        // What the fleet expects beneath a watched path is read too, so a
        // file nobody touches on this node is still held to its peers.
        if let Some(expected) = self.expected.as_ref().map(|set| set.current()) {
            for path in expected.paths() {
                if watching.covering(path).is_some()
                    && !self.is_own(path)
                    && !paths.iter().any(|p| p == path)
                {
                    paths.push(path.to_owned());
                }
            }
        }
        let facts = match self.read_all(&paths) {
            Ok(facts) => facts,
            Err(e) => {
                warn!(error = %e, "the watched paths could not be read");
                return;
            }
        };
        let unseen = BTreeSet::new();
        for fact in facts {
            let kept = match self.baselines.get(&fact.path) {
                Ok(kept) => kept,
                Err(e) => {
                    warn!(path = %fact.path, error = %e, "file baseline could not be read");
                    continue;
                }
            };
            if let Some(old) = &kept
                && self.learned.contains(&fact.path)
            {
                let drift = old.drift(&fact.reading);
                self.watch(&fact.path, &unseen, Basis::Kept, &drift, &fact.reading, 0);
            } else if let Some(expected) = self.expected_at(&fact.path) {
                let drift = expected.drift(&fact.reading);
                self.watch(
                    &fact.path,
                    &unseen,
                    Basis::Expected,
                    &drift,
                    &fact.reading,
                    0,
                );
            }
            self.keep_listed(&fact, kept.is_some());
            self.learned.insert(fact.path);
        }
        self.metrics.set_file_baselines(self.kept);
    }

    /// Read what each of `paths` names, however many readings that takes.
    fn read_all(&mut self, paths: &[String]) -> Result<Vec<FileFacts>, String> {
        let mut facts = Vec::with_capacity(paths.len());
        let mut asked = paths;
        while !asked.is_empty() {
            match self.source.facts(asked, self.policy.max_hash_bytes) {
                Ok(read) if !read.is_empty() => {
                    asked = &asked[read.len().min(asked.len())..];
                    facts.extend(read);
                }
                Ok(_) => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(facts)
    }

    /// Alert on a difference `writer` left under a watched path.
    fn watch(
        &self,
        path: &str,
        kinds: &BTreeSet<FileChangeKind>,
        basis: Basis,
        drift: &[FileDrift],
        reading: &FileReading,
        writer: u32,
    ) {
        let Some(guard) = self.watched.as_ref() else {
            return;
        };
        let settled = SettledPath {
            path,
            kinds,
            had_baseline: basis != Basis::Unknown,
            expected: basis == Basis::Expected,
            drift,
            present: matches!(reading, FileReading::Present(_)),
            writer,
        };
        let Some(change) = watched_path_change(&self.watching.1, &settled, guard.own_pid) else {
            return;
        };
        warn!(
            path,
            writer,
            watched = %change.watched,
            origin = %change.origin,
            "a watched path changed"
        );
        let workload = (writer != 0)
            .then(|| guard.workloads.by_pid(writer))
            .flatten();
        let alert = Alert::from_watched_path_change(&change, workload, now_ns());
        if let Err(e) = guard.alerts.try_send(AlertEvent::System(Box::new(alert))) {
            warn!(path, error = %e, "alert on a watched path could not be queued");
        }
    }

    /// Whether the watched set moved since the watch was opened.
    fn watched_moved(&self) -> bool {
        self.watched
            .as_ref()
            .is_some_and(|guard| guard.set.current().0 != self.watching.0)
    }

    /// Keep or forget the baseline of a path kept past the cap.
    fn keep_listed(&mut self, fact: &FileFacts, had: bool) {
        let path = fact.path.as_str();
        match &fact.reading {
            FileReading::Present(now) => match self.baselines.put(path, now) {
                Ok(()) if !had => self.kept += 1,
                Ok(()) => {}
                Err(e) => warn!(path, error = %e, "file baseline could not be kept"),
            },
            FileReading::Gone if had => match self.baselines.remove(path) {
                Ok(true) => self.kept = self.kept.saturating_sub(1),
                Ok(false) => {}
                Err(e) => warn!(path, error = %e, "file baseline could not be forgotten"),
            },
            FileReading::Gone | FileReading::Unreadable(_) => {}
        }
    }

    /// Alert on a difference `writer` left on one of the agent's files.
    fn guard(
        &self,
        path: &str,
        kinds: &BTreeSet<FileChangeKind>,
        drift: &[FileDrift],
        writer: u32,
    ) {
        let Some(guard) = self.own.as_ref() else {
            return;
        };
        let Some(role) = guard.files.role(path) else {
            return;
        };
        let Some(change) = own_file_change(path, role, kinds, drift, writer, guard.own_pid) else {
            return;
        };
        warn!(
            path,
            writer,
            role = role.describe(),
            "another process changed one of the agent's files"
        );
        let workload = (writer != 0)
            .then(|| guard.workloads.by_pid(writer))
            .flatten();
        let alert = Alert::from_own_file_change(&change, workload, now_ns());
        if let Err(e) = guard.alerts.try_send(AlertEvent::System(Box::new(alert))) {
            warn!(path, error = %e, "alert on one of the agent's files could not be queued");
        }
    }

    fn is_own(&self, path: &str) -> bool {
        self.own
            .as_ref()
            .is_some_and(|guard| guard.files.role(path).is_some())
    }

    /// Whether `path` is itself a watched path, kept past the cap.
    fn is_watched(&self, path: &str) -> bool {
        self.watched.is_some() && self.watching.1.names(path)
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

    /// The process `pid` and its ancestry, where a reader of the writer is
    /// wired and the table holds it.
    fn writer_of(&self, pid: u32) -> Option<(Lineage, ProcessEntry)> {
        let feed = self.feed.as_ref()?;
        let wanted =
            feed.ransom.is_some() || FILE_INTENTS.iter().any(|intent| feed.rules.wants(*intent));
        if !wanted {
            return None;
        }
        let table = feed.processes.as_ref()?;
        table.get(pid).map(|entry| (table.lineage(pid), entry))
    }

    /// Queue the path each change names, to be read again.
    fn queue(&mut self, batch: &FileChangeBatch) {
        let mut lost = false;
        for change in &batch.changes {
            let Some(path) = change_path(change) else {
                continue;
            };
            let writer = self.writer_of(change.pid);
            let full = self.pending.len() >= FILE_FACTS_PENDING_MAX;
            let pending = match self.pending.entry(path) {
                Entry::Occupied(slot) => slot.into_mut(),
                Entry::Vacant(slot) if !full => slot.insert(Pending::default()),
                Entry::Vacant(_) => {
                    lost = true;
                    continue;
                }
            };
            if writer.is_some() || pending.pid != change.pid {
                pending.writer = writer;
            }
            pending.pid = change.pid;
            pending.kinds.extend(change.kinds.iter().copied());
            pending.dev = change.dev.or(pending.dev);
            pending.ino = change.ino.or(pending.ino);
            if let Some(from) = &change.renamed_from {
                pending.renamed_from = Some(from.clone());
                // The old name's own move-out may come before or after, and
                // either way the rename is what reports it.
                let full = self.pending.len() >= FILE_FACTS_PENDING_MAX;
                match self.pending.entry(from.clone()) {
                    Entry::Occupied(slot) => slot.into_mut().renamed_away = true,
                    Entry::Vacant(slot) if !full => {
                        slot.insert(Pending {
                            pid: change.pid,
                            renamed_away: true,
                            ..Pending::default()
                        });
                    }
                    Entry::Vacant(_) => lost = true,
                }
            }
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
        let drift = kept
            .as_ref()
            .map(|old| old.drift(&fact.reading))
            .unwrap_or_default();
        if kept.is_some() {
            self.guard(path, &pending.kinds, &drift, pid);
        }
        if !self.is_own(path) {
            // A path this node never kept is held to the fleet's expected
            // state where there is one, and learned where there is none.
            let (basis, drift) = match (&kept, self.expected_at(path)) {
                (Some(_), _) => (Basis::Kept, drift),
                (None, Some(expected)) => (Basis::Expected, expected.drift(&fact.reading)),
                (None, None) => (Basis::Unknown, Vec::new()),
            };
            self.watch(path, &pending.kinds, basis, &drift, &fact.reading, pid);
        }
        let inside = rooted.path.as_deref().unwrap_or(path);
        match (&fact.reading, kept) {
            (FileReading::Present(new), None) => {
                if self.kept >= self.policy.max_files
                    && !self.is_own(path)
                    && !self.is_watched(path)
                {
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
        let wanted = FILE_INTENTS.iter().any(|intent| feed.rules.wants(*intent));
        if !wanted && feed.ransom.is_none() {
            return;
        }
        let rules = Arc::clone(&feed.rules);
        // The writer as it was when the change arrived, and the table only
        // where that was not read.
        let writer = pending.writer.clone().or_else(|| {
            feed.processes.as_ref().and_then(|table| {
                table
                    .get(pending.pid)
                    .map(|entry| (table.lineage(pending.pid), entry))
            })
        });
        let at_ns = now_ns();
        if let (Some(ransom), Some((lineage, entry))) = (feed.ransom.as_ref(), writer.as_ref()) {
            let now = match &fact.reading {
                FileReading::Present(now) => Some(now),
                FileReading::Gone | FileReading::Unreadable(_) => None,
            };
            ransom.record_file_change(
                entry,
                lineage,
                pending.kinds.iter().copied(),
                FileRewrite {
                    path: &fact.path,
                    entropy_before: before.and_then(|b| b.entropy_millibits),
                    entropy_now: now.and_then(|n| n.entropy_millibits),
                    head: now.and_then(|n| n.head),
                    renamed_from: pending.renamed_from.as_deref(),
                    size_before: before.map(|b| b.size),
                    size_now: now.map(|n| n.size),
                    written_now: now.is_some_and(|n| written_now(n.mtime_ns, at_ns)),
                },
                at_ns,
            );
        }
        if !wanted {
            return;
        }
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
            renamed_from: pending.renamed_from.as_deref(),
            renamed_away: pending.renamed_away,
        });
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
                self.prime_own();
                self.prime_watched();
                self.plant_canaries();
            } else if self.watched_moved() {
                info!("the watched paths changed, opening the watch again");
                open = false;
                continue;
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
                    self.canaries_touched(&batch);
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
    use domain::file_watch::{FileBaseline, FileChange, FileOpened, FileType};
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
        fn under(
            &self,
            path: &str,
            limit: usize,
        ) -> Result<Vec<(String, FileBaseline)>, DomainError> {
            let beneath = format!("{path}/");
            Ok(self
                .map()
                .iter()
                .filter(|(key, _)| *key == path || key.starts_with(&beneath))
                .take(limit)
                .map(|(key, b)| (key.clone(), b.clone()))
                .collect())
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

        /// A path ending in `refused` is refused; every other stands.
        fn plant(&mut self, paths: &[String]) -> Result<Vec<PlantedCanary>, DomainError> {
            Ok(paths
                .iter()
                .map(|path| PlantedCanary {
                    path: path.clone(),
                    error: path.ends_with("refused").then(|| "read-only".to_owned()),
                })
                .collect())
        }

        fn source(&self) -> &'static str {
            "local"
        }
    }

    fn watched(path: &str) -> WatchedFilesystem {
        WatchedFilesystem {
            path: path.into(),
            error: None,
            renames: true,
        }
    }

    fn refused(path: &str) -> WatchedFilesystem {
        WatchedFilesystem {
            path: path.into(),
            error: Some("this filesystem cannot report file handles".into()),
            renames: false,
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
            renamed_from: None,
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
                opened: Vec::new(),
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
            entropy_millibits: None,
            head: None,
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

    fn guard(own_pid: u32) -> (OwnFileGuard, mpsc::Receiver<AlertEvent>) {
        let (alerts, rx) = mpsc::channel(8);
        let mut files = OwnFiles::new();
        files.add("/etc/hosts", domain::file_watch::OwnFileRole::Configuration);
        (
            OwnFileGuard {
                files,
                own_pid,
                alerts,
                workloads: WorkloadResolver::new(),
            },
            rx,
        )
    }

    fn own_alerts(rx: &mut mpsc::Receiver<AlertEvent>) -> Vec<Alert> {
        let mut out = Vec::new();
        while let Ok(event) = rx.try_recv() {
            match event {
                AlertEvent::System(alert) => out.push(*alert),
                _ => panic!("an agent file alert travels as a system alert"),
            }
        }
        out
    }

    fn own_run(own_pid: u32) -> Vec<Alert> {
        let cancel = CancellationToken::new();
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")])],
            reads: vec![Ok(written())],
            facts: vec![
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('a', 0o644)),
                )]),
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('b', 0o644)),
                )]),
            ],
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, mut rx) = guard(own_pid);
        watcher(source, Arc::new(Counted::default()))
            .with_own_files(guard)
            .run_blocking(&cancel);
        own_alerts(&mut rx)
    }

    #[test]
    fn another_process_changing_an_agent_file_is_an_alert() {
        let alerts = own_run(99);
        assert_eq!(alerts.len(), 1);
        let alert = &alerts[0];
        assert_eq!(alert.component, "agent_files");
        assert_eq!(alert.rule_id.0, "agent-configuration-changed");
        assert_eq!(alert.tgid, Some(7));
        assert!(
            alert
                .message
                .contains("/etc/hosts was changed by process 7: content"),
            "{}",
            alert.message
        );
    }

    #[test]
    fn the_agent_changing_its_own_file_is_not() {
        assert!(own_run(7).is_empty());
    }

    #[test]
    fn the_first_opening_learns_and_a_later_one_reports_the_gap() {
        let cancel = CancellationToken::new();
        let store = Arc::new(Memory::default());
        store.map().insert("/etc/hosts".into(), file('a', 0o644));
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")]), Ok(vec![watched("/")])],
            reads: vec![
                Err(DomainError::EngineError("no file watch is open".into())),
                Ok(FileChangeBatch::default()),
            ],
            facts: vec![
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('b', 0o644)),
                )]),
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('c', 0o600)),
                )]),
            ],
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, mut rx) = guard(99);
        // No room for baselines: the agent's own files are kept anyway.
        watcher_with(source, Arc::new(Counted::default()), Arc::clone(&store), 0)
            .with_own_files(guard)
            .run_blocking(&cancel);
        let alerts = own_alerts(&mut rx);
        assert_eq!(alerts.len(), 1, "the upgrade-time difference only learns");
        assert_eq!(alerts[0].tgid, None);
        assert!(
            alerts[0]
                .message
                .contains("changed by a process the agent cannot name: content, mode"),
            "{}",
            alerts[0].message
        );
        assert_eq!(store.map().get("/etc/hosts"), Some(&file('c', 0o600)));
    }

    #[test]
    fn the_filesystem_of_every_agent_file_is_opened() {
        let cancel = CancellationToken::new();
        let source = Scripted {
            opens: Vec::new(),
            reads: Vec::new(),
            facts: Vec::new(),
            cancel,
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, _rx) = guard(1);
        let w = watcher(source, Arc::new(Counted::default())).with_own_files(guard);
        assert_eq!(w.paths, vec!["/", "/var/lib/containerd", "/etc"]);
        assert_eq!(w.configured, 2);
    }

    fn watched_set(path: &str) -> Arc<WatchedPathSet> {
        let mut paths = WatchedPaths::new();
        paths
            .add(path, domain::file_watch::DECLARED_ORIGIN)
            .unwrap();
        Arc::new(WatchedPathSet::new(paths))
    }

    fn watched_guard(set: Arc<WatchedPathSet>) -> (WatchedPathGuard, mpsc::Receiver<AlertEvent>) {
        let (alerts, rx) = mpsc::channel(8);
        (
            WatchedPathGuard {
                set,
                own_pid: 99,
                alerts,
                workloads: WorkloadResolver::new(),
            },
            rx,
        )
    }

    #[test]
    fn a_difference_under_a_watched_path_is_an_alert_and_its_first_change_is_compared() {
        let cancel = CancellationToken::new();
        let store = Arc::new(Memory::default());
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")])],
            reads: vec![Ok(written())],
            facts: vec![
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('a', 0o644)),
                )]),
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('b', 0o644)),
                )]),
            ],
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, mut rx) = watched_guard(watched_set("/etc/hosts"));
        // No room for baselines: a watched path is kept anyway, so the
        // write after the opening is compared rather than learned.
        watcher_with(source, Arc::new(Counted::default()), Arc::clone(&store), 0)
            .with_watched_paths(guard)
            .run_blocking(&cancel);
        let alerts = own_alerts(&mut rx);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].component, "file_integrity");
        assert_eq!(alerts[0].rule_id.0, "watched-path-changed");
        assert_eq!(alerts[0].tgid, Some(7));
        assert_eq!(
            alerts[0].message,
            "/etc/hosts watched through configuration was changed by process 7: content"
        );
        assert_eq!(store.map().get("/etc/hosts"), Some(&file('b', 0o644)));
    }

    #[test]
    fn a_file_arriving_under_a_watched_directory_is_an_alert() {
        let cancel = CancellationToken::new();
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")])],
            reads: vec![Ok(FileChangeBatch {
                changes: vec![change(vec![
                    FileChangeKind::Created,
                    FileChangeKind::Written,
                ])],
                overflowed: false,
                opened: Vec::new(),
            })],
            facts: vec![
                Ok(vec![fact("/etc", FileReading::Present(file('d', 0o755)))]),
                Ok(vec![fact(
                    "/etc/hosts",
                    FileReading::Present(file('a', 0o644)),
                )]),
            ],
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, mut rx) = watched_guard(watched_set("/etc"));
        watcher(source, Arc::new(Counted::default()))
            .with_watched_paths(guard)
            .run_blocking(&cancel);
        let alerts = own_alerts(&mut rx);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id.0, "watched-path-appeared");
        assert_eq!(
            alerts[0].message,
            "/etc/hosts appeared under /etc, watched through configuration, put there by process 7"
        );
    }

    #[test]
    fn a_replaced_set_is_followed_on_the_filesystems_it_needs() {
        let set = watched_set("/etc/hosts");
        assert!(!set.replace(set.current().1.as_ref().clone()));
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")])],
            reads: Vec::new(),
            facts: Vec::new(),
            cancel: CancellationToken::new(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, _rx) = watched_guard(Arc::clone(&set));
        let mut w = watcher(source, Arc::new(Counted::default())).with_watched_paths(guard);
        assert!(!w.watched_moved());
        let mut next = WatchedPaths::new();
        next.add("/srv/app/config.toml", "web").unwrap();
        assert!(set.replace(next));
        assert!(w.watched_moved());
        assert!(w.open(&mut None));
        assert!(!w.watched_moved());
        assert_eq!(w.watching.1.directories(), vec!["/srv/app".to_owned()]);
        assert!(w.is_watched("/srv/app/config.toml"));
        assert!(!w.is_watched("/etc/hosts"));
    }

    fn expected(entries: &[(&str, FileBaseline)]) -> Arc<ExpectedBaselineSet> {
        let set = Arc::new(ExpectedBaselineSet::new());
        let held = ExpectedBaselines::from_entries(
            entries
                .iter()
                .map(|(path, baseline)| ExpectedBaseline {
                    path: (*path).to_owned(),
                    fingerprint: FileFingerprint::of(baseline),
                })
                .collect(),
        )
        .unwrap();
        assert!(set.replace(held.clone()));
        assert!(!set.replace(held));
        set
    }

    fn expected_run(on_disk: FileBaseline, fleet: FileBaseline, then: FileBaseline) -> Vec<Alert> {
        let cancel = CancellationToken::new();
        let source = Scripted {
            opens: vec![Ok(vec![watched("/")])],
            reads: vec![Ok(written())],
            facts: vec![
                Ok(vec![fact("/etc", FileReading::Present(file('d', 0o755)))]),
                Ok(vec![fact("/etc/hosts", FileReading::Present(on_disk))]),
                Ok(vec![fact("/etc/hosts", FileReading::Present(then))]),
            ],
            cancel: cancel.clone(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let (guard, mut rx) = watched_guard(watched_set("/etc"));
        watcher(source, Arc::new(Counted::default()))
            .with_watched_paths(guard)
            .with_expected(expected(&[("/etc/hosts", fleet)]))
            .run_blocking(&cancel);
        own_alerts(&mut rx)
    }

    #[test]
    fn a_first_sight_unlike_the_fleet_is_an_alert_rather_than_learned() {
        // The file is read when the watch opens because the fleet names it,
        // although nothing touches it and only its directory is watched.
        let alerts = expected_run(file('b', 0o600), file('a', 0o644), file('b', 0o600));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id.0, "watched-path-unexpected");
        assert_eq!(
            alerts[0].message,
            "/etc/hosts under /etc, watched through configuration differs from the fleet's \
             expected state: content, mode"
        );
        assert_eq!(alerts[0].tgid, None);
    }

    #[test]
    fn a_first_sight_like_the_fleet_is_kept_and_later_compared_with_itself() {
        let alerts = expected_run(file('a', 0o644), file('a', 0o644), file('c', 0o644));
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id.0, "watched-path-changed");
    }

    #[test]
    fn a_node_lists_what_it_keeps_beneath_its_watched_paths_once_and_bounded() {
        let store = Memory::default();
        for path in ["/etc/ssh", "/etc/ssh/sshd_config", "/etc/sshd", "/var/x"] {
            store.put(path, &file('a', 0o644)).unwrap();
        }
        let mut watched = WatchedPaths::new();
        watched.add("/etc/ssh", "debian").unwrap();
        watched.add("/etc/ssh/sshd_config", "rhel").unwrap();
        let (listed, truncated) = listed_baselines(&store, &watched, 10).unwrap();
        let paths: Vec<&str> = listed.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["/etc/ssh", "/etc/ssh/sshd_config"]);
        assert!(!truncated);
        assert_eq!(
            listed[1].fingerprint,
            FileFingerprint::of(&file('a', 0o644))
        );
        let (one, truncated) = listed_baselines(&store, &watched, 1).unwrap();
        assert_eq!(one.len(), 1);
        assert!(truncated);
        // What one node lists is what every other is handed back.
        assert!(ExpectedBaselines::from_entries(listed).is_ok());
    }

    fn written() -> FileChangeBatch {
        FileChangeBatch {
            changes: vec![change(vec![FileChangeKind::Written])],
            overflowed: false,
            opened: Vec::new(),
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
            opened: Vec::new(),
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
            opened: Vec::new(),
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
            ransom: None,
        })
    }

    const KEYS: &str = "/var/lib/c/9/fs/root/.ssh/authorized_keys";

    #[test]
    fn the_canaries_directories_are_watched_once_each() {
        let canaries = CanaryWatch {
            paths: vec![
                "/srv/a.docx".into(),
                "/srv/b.xlsx".into(),
                "/c.docx".into(),
                "relative".into(),
            ],
            exempt: Vec::new(),
        };
        assert_eq!(canaries.directories(), vec!["/srv", "/"]);
        let source = Scripted {
            opens: Vec::new(),
            reads: Vec::new(),
            facts: Vec::new(),
            cancel: CancellationToken::new(),
            opened: Arc::new(AtomicU64::new(0)),
        };
        let w = watcher(source, Arc::new(Counted::default())).with_canaries(canaries);
        assert_eq!(w.paths.iter().filter(|p| *p == "/srv").count(), 1);
        assert_eq!(w.paths.iter().filter(|p| *p == "/").count(), 1);
    }

    #[tokio::test]
    async fn an_open_of_a_canary_raises_the_verdict_and_a_canary_taken_away_is_planted_again() {
        let (rules, _rules_rx) = rules(&[]);
        let (tx, mut rx) = mpsc::channel(8);
        let sources: crate::ransom_service::HostSourcesReader = Arc::new(|| {
            domain::hostrule::HostSources::new(Some((6, 12)))
                .present(domain::hostrule::Source::ProcessTracing)
                .present(domain::hostrule::Source::FileWatch)
        });
        let ransom = Arc::new(
            RansomService::new(tx, sources).with_mode(domain::firewall::entity::RuleMode::Enforce),
        );
        let mut w = fed(rules, table().await, Arc::new(Memory::default()));
        if let Some(feed) = w.feed.as_mut() {
            feed.ransom = Some(ransom);
        }
        let mut w = w.with_canaries(CanaryWatch {
            paths: vec!["/srv/0000-archive.docx".into(), "/mnt/refused".into()],
            exempt: vec!["/usr/bin/restic".into()],
        });
        w.plant_canaries();
        assert_eq!(
            w.planted.iter().collect::<Vec<_>>(),
            vec!["/srv/0000-archive.docx"]
        );
        // An open by a process nobody can name is logged and raises nothing.
        w.canaries_touched(&FileChangeBatch {
            opened: vec![FileOpened {
                pid: 999,
                path: Some("/srv/0000-archive.docx".into()),
            }],
            ..FileChangeBatch::default()
        });
        assert!(rx.try_recv().is_err());
        w.canaries_touched(&FileChangeBatch {
            opened: vec![FileOpened {
                pid: 42,
                path: Some("/srv/0000-archive.docx".into()),
            }],
            ..FileChangeBatch::default()
        });
        let Ok(AlertEvent::ProcessDetection { alert, .. }) = rx.try_recv() else {
            panic!("no verdict raised");
        };
        assert!(
            alert
                .message
                .contains("canary /srv/0000-archive.docx opened")
        );
        // A deletion by another process is a touch, and the canary stands
        // again afterwards.
        let mut gone = change(vec![FileChangeKind::Deleted]);
        gone.pid = 42;
        gone.directory = Some("/srv".into());
        gone.name = "0000-archive.docx".into();
        w.canaries_touched(&FileChangeBatch {
            changes: vec![gone],
            ..FileChangeBatch::default()
        });
        assert!(w.planted.contains("/srv/0000-archive.docx"));
    }

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
    async fn a_writer_that_exits_before_the_path_is_read_back_is_still_named() {
        let (rules, mut rx) = rules(&[(
            "keys",
            r#""file.appears":{"path":"/root/.ssh/authorized_keys"}"#,
        )]);
        let processes = table().await;
        let mut w = fed(rules, Arc::clone(&processes), Arc::new(Memory::default()));
        let (directory, name) = KEYS.rsplit_once('/').unwrap();
        let mut written = change(vec![FileChangeKind::Created, FileChangeKind::Written]);
        written.pid = 42;
        written.directory = Some(directory.into());
        written.name = name.into();
        w.queue(&FileChangeBatch {
            changes: vec![written],
            overflowed: false,
            opened: Vec::new(),
        });
        let mut exit = lifecycle(42, Some(10), "sh");
        exit.kind = domain::process::entity::ProcessEventKind::Exit;
        processes.apply(exit).await;
        assert!(processes.get(42).is_none());
        w.source = Box::new(Scripted {
            opens: Vec::new(),
            reads: Vec::new(),
            facts: vec![
                Ok(vec![fact(KEYS, FileReading::Present(file('a', 0o600)))]),
                Ok(vec![fact(
                    "/var/lib/c/3/fs/root/.ssh/authorized_keys",
                    FileReading::Gone,
                )]),
            ],
            cancel: CancellationToken::new(),
            opened: Arc::new(AtomicU64::new(0)),
        });
        w.settle().unwrap();
        let raised = alerts(&mut rx);
        assert_eq!(raised.len(), 1);
        let workload = raised[0].workload.as_ref().unwrap();
        assert_eq!(workload.pid, 42);
        assert_eq!(workload.ancestry.as_ref().unwrap().ancestors[0].pid, 10);
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
    async fn a_rename_with_both_names_is_one_rename_and_no_disappearance() {
        let (rules, mut rx) = rules(&[
            (
                "renamed",
                r#""file.renames":{"path":"/srv/q3.xlsx.locked","previous_path":"/srv/q3.xlsx"}"#,
            ),
            ("gone", r#""file.disappears":{"path":"/srv/q3.xlsx"}"#),
        ]);
        let old = "/var/lib/c/9/fs/srv/q3.xlsx";
        let new = "/var/lib/c/9/fs/srv/q3.xlsx.locked";
        let store = Arc::new(Memory::default());
        store.map().insert(old.into(), file('a', 0o600));
        let mut w = fed(rules, table().await, store);
        let mut arrived = change(vec![FileChangeKind::MovedIn]);
        arrived.pid = 42;
        arrived.directory = Some("/var/lib/c/9/fs/srv".into());
        arrived.name = "q3.xlsx.locked".into();
        arrived.renamed_from = Some(old.into());
        let mut left = change(vec![FileChangeKind::MovedOut]);
        left.pid = 42;
        left.directory = Some("/var/lib/c/9/fs/srv".into());
        left.name = "q3.xlsx".into();
        w.queue(&FileChangeBatch {
            changes: vec![arrived, left],
            overflowed: false,
            opened: Vec::new(),
        });
        w.source = Box::new(Scripted {
            opens: Vec::new(),
            reads: Vec::new(),
            facts: vec![Ok(vec![
                fact(new, FileReading::Present(file('a', 0o600))),
                fact(old, FileReading::Gone),
            ])],
            cancel: CancellationToken::new(),
            opened: Arc::new(AtomicU64::new(0)),
        });
        w.settle().unwrap();
        let raised = alerts(&mut rx);
        assert_eq!(raised.len(), 1, "{raised:?}");
        assert_eq!(raised[0].rule_id.0, "renamed");
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
