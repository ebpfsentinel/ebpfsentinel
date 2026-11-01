//! Keeping the file watch open and reading it.
//!
//! The watch covers whole filesystems and is held by whoever holds the
//! privilege, the warden for a rootless agent. A warden that restarts takes
//! the watch with it, so a failed reading is answered by opening the watch
//! again rather than by giving up. A filesystem that cannot be watched is
//! reported once, with its reason, and costs the agent nothing else.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use domain::file_watch::{FileChangeBatch, FileChangeKind, WatchedFilesystem};
use ports::secondary::file_watch_port::FileWatchSource;
use ports::secondary::metrics_port::MetricsPort;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// How long one reading waits for a first change. Short enough that a
/// cancelled agent stops within it.
pub const FILE_WATCH_READ_WAIT: Duration = Duration::from_secs(1);

/// How long the watcher waits before opening the watch again, after the
/// watch could not be opened or could no longer be read.
pub const FILE_WATCH_REOPEN_DELAY: Duration = Duration::from_secs(30);

/// Opens the watch on the configured filesystems and reads it until
/// cancelled.
pub struct FileWatcher {
    source: Box<dyn FileWatchSource>,
    paths: Vec<String>,
    metrics: Arc<dyn MetricsPort>,
    reopen_delay: Duration,
}

impl FileWatcher {
    #[must_use]
    pub fn new(
        source: Box<dyn FileWatchSource>,
        paths: Vec<String>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            source,
            paths,
            metrics,
            reopen_delay: FILE_WATCH_REOPEN_DELAY,
        }
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
            match self.source.read(FILE_WATCH_READ_WAIT) {
                Ok(batch) => self.record(&batch),
                Err(e) => {
                    debug!(error = %e, "file watch reading failed, opening it again");
                    open = false;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    use domain::common::error::DomainError;
    use domain::file_watch::FileChange;
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };

    use super::*;

    #[derive(Default)]
    struct Counted {
        changes: Mutex<BTreeMap<String, u64>>,
        overflows: AtomicU64,
        filesystems: Mutex<Vec<(u64, u64)>>,
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
    }

    /// Answers each call from a script, then cancels the watcher.
    struct Scripted {
        opens: Vec<Result<Vec<WatchedFilesystem>, DomainError>>,
        reads: Vec<Result<FileChangeBatch, DomainError>>,
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
        let mut w = FileWatcher::new(
            Box::new(source),
            vec!["/".into(), "/var/lib/containerd".into()],
            metrics,
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
}
