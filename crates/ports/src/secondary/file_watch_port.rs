//! Watching filesystems for changes.

use std::time::Duration;

use domain::common::error::DomainError;
use domain::file_watch::{FileChangeBatch, WatchedFilesystem};

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

    /// Where the watch lives: `warden` or `local`.
    fn source(&self) -> &'static str;
}
