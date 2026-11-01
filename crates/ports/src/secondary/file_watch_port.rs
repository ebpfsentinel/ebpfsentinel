//! Watching filesystems for changes.

use std::time::Duration;

use domain::common::error::DomainError;
use domain::file_watch::{FileBaseline, FileChangeBatch, FileFacts, WatchedFilesystem};

/// A watch over whole filesystems, read in a loop by one owner.
///
/// Blocking: [`FileWatchSource::read`] waits for the first change, so the
/// caller runs it off the async runtime.
pub trait FileWatchSource: Send {
    /// Watch the filesystem holding each of `paths`, replacing any watch
    /// already open.
    ///
    /// # Errors
    ///
    /// The watch could not be asked for at all: the warden is unreachable. A
    /// path that cannot be watched is reported in its own entry instead.
    fn open(&mut self, paths: &[String]) -> Result<Vec<WatchedFilesystem>, DomainError>;

    /// The changes seen since the last reading, waiting at most `max_wait`
    /// for the first one.
    ///
    /// # Errors
    ///
    /// No watch is open, which is what a warden restart leaves behind, or the
    /// watch could not be read. Either way the caller opens it again.
    fn read(&mut self, max_wait: Duration) -> Result<FileChangeBatch, DomainError>;

    /// What each path names, its content hashed when it is a regular file no
    /// larger than `max_hash_bytes`. Only a path on a watched filesystem is
    /// read. Fewer answers than paths means the reader's budget ran out and
    /// the rest are to be asked for again; the answers are a prefix of
    /// `paths`, in order.
    ///
    /// # Errors
    ///
    /// No watch is open, or the reader is unreachable.
    fn facts(
        &mut self,
        paths: &[String],
        max_hash_bytes: u64,
    ) -> Result<Vec<FileFacts>, DomainError>;

    /// Where the watch lives: `warden` or `local`.
    fn source(&self) -> &'static str;
}

/// Where the last reading of every watched path is kept, by path.
pub trait FileBaselineStore: Send + Sync {
    /// The baseline kept for `path`.
    ///
    /// # Errors
    ///
    /// The store could not be read.
    fn get(&self, path: &str) -> Result<Option<FileBaseline>, DomainError>;

    /// Keep `baseline` for `path`, replacing the one kept.
    ///
    /// # Errors
    ///
    /// The store could not be written.
    fn put(&self, path: &str, baseline: &FileBaseline) -> Result<(), DomainError>;

    /// Forget `path`, saying whether a baseline was kept for it.
    ///
    /// # Errors
    ///
    /// The store could not be written.
    fn remove(&self, path: &str) -> Result<bool, DomainError>;

    /// How many baselines are kept.
    ///
    /// # Errors
    ///
    /// The store could not be read.
    fn count(&self) -> Result<u64, DomainError>;

    /// The baselines kept for `path` and everything beneath it, in path
    /// order, at most `limit` of them.
    ///
    /// # Errors
    ///
    /// The store could not be read.
    fn under(&self, path: &str, limit: usize) -> Result<Vec<(String, FileBaseline)>, DomainError>;
}

/// Reads where a process's root lives, so a path the watch reports on the
/// backing filesystem can be named the way that process sees it.
pub trait ProcessRootReader: Send + Sync {
    /// The root mount of `pid`, `None` when the process is gone or its
    /// mount table cannot be read.
    fn root_mount(&self, pid: u32) -> Option<domain::file_watch::RootMount>;
}
