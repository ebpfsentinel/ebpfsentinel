//! The file watch, held by the warden or in-process.
//!
//! Marking a whole filesystem and naming the directory a change happened in
//! both need a privilege the rootless agent does not hold, so a rootless agent
//! asks the warden on a connection of its own: the watch belongs to that
//! connection and ends with it. An agent holding the privilege opens the
//! watch in-process with the same code the warden runs.

use std::path::PathBuf;
use std::time::Duration;

use domain::common::error::DomainError;
use domain::file_watch::{FileChange, FileChangeBatch, FileChangeKind, WatchedFilesystem};
use ebpfsentinel_warden_client::ReconnectingClient;
pub use ebpfsentinel_warden_client::{FimEvent, FimMark};
use ports::secondary::file_watch_port::FileWatchSource;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

const FAN_ATTRIB: u64 = 0x0000_0004;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_MOVED_FROM: u64 = 0x0000_0040;
const FAN_MOVED_TO: u64 = 0x0000_0080;
const FAN_CREATE: u64 = 0x0000_0100;
const FAN_DELETE: u64 = 0x0000_0200;
const FAN_ONDIR: u64 = 0x4000_0000;

/// An open in-process watch: reads what it queued, waiting at most the
/// duration given.
pub type LocalRead = Box<dyn FnMut(Duration) -> Result<(Vec<FimEvent>, bool), String> + Send>;

/// Opens an in-process watch on the filesystems holding the paths given.
pub type LocalOpen = fn(&[String]) -> (Option<LocalRead>, Vec<FimMark>);

enum Source {
    Warden(Box<ReconnectingClient>),
    Local {
        open: LocalOpen,
        watch: Option<LocalRead>,
    },
}

/// The file watch, through the warden when `EBPFSENTINEL_WARDEN_SOCK` is set
/// and in-process otherwise.
pub struct FileWatch {
    source: Source,
}

impl FileWatch {
    /// The warden when the environment names one, else `open` in-process.
    #[must_use]
    pub fn new(open: LocalOpen) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());
        let source = match warden {
            Some(sock) => Source::Warden(Box::new(ReconnectingClient::new(sock))),
            None => Source::Local { open, watch: None },
        };
        Self { source }
    }
}

/// The kernel's event bits as the domain names them.
#[must_use]
pub fn kinds_of(mask: u64) -> Vec<FileChangeKind> {
    FileChangeKind::ALL
        .into_iter()
        .filter(|kind| {
            let bit = match kind {
                FileChangeKind::Created => FAN_CREATE,
                FileChangeKind::Written => FAN_CLOSE_WRITE,
                FileChangeKind::AttributesChanged => FAN_ATTRIB,
                FileChangeKind::MovedOut => FAN_MOVED_FROM,
                FileChangeKind::MovedIn => FAN_MOVED_TO,
                FileChangeKind::Deleted => FAN_DELETE,
            };
            mask & bit != 0
        })
        .collect()
}

fn to_change(event: FimEvent) -> Option<FileChange> {
    let kinds = kinds_of(event.mask);
    if kinds.is_empty() {
        return None;
    }
    Some(FileChange {
        kinds,
        is_dir: event.mask & FAN_ONDIR != 0,
        pid: event.pid,
        directory: event.directory,
        name: event.name,
        dev: event.dev,
        ino: event.ino,
        unresolved: event.unresolved,
    })
}

fn to_batch(events: Vec<FimEvent>, overflowed: bool) -> FileChangeBatch {
    FileChangeBatch {
        changes: events.into_iter().filter_map(to_change).collect(),
        overflowed,
    }
}

fn to_marks(marks: Vec<FimMark>) -> Vec<WatchedFilesystem> {
    marks
        .into_iter()
        .map(|m| WatchedFilesystem {
            path: m.path,
            error: m.error,
        })
        .collect()
}

impl FileWatchSource for FileWatch {
    fn open(&mut self, paths: &[String]) -> Result<Vec<WatchedFilesystem>, DomainError> {
        match &mut self.source {
            Source::Warden(client) => client.fim_open(paths).map(to_marks).map_err(|e| {
                DomainError::EngineError(format!("warden could not open the file watch: {e}"))
            }),
            Source::Local { open, watch } => {
                let (opened, marks) = open(paths);
                *watch = opened;
                Ok(to_marks(marks))
            }
        }
    }

    fn read(&mut self, max_wait: Duration) -> Result<FileChangeBatch, DomainError> {
        let millis = u32::try_from(max_wait.as_millis()).unwrap_or(u32::MAX);
        let (events, overflowed) = match &mut self.source {
            Source::Warden(client) => client.fim_read(millis).map_err(|e| {
                DomainError::EngineError(format!("warden could not read the file watch: {e}"))
            })?,
            Source::Local { watch, .. } => match watch {
                Some(read) => read(max_wait).map_err(DomainError::EngineError)?,
                None => {
                    return Err(DomainError::EngineError(
                        "no file watch is open: no filesystem could be marked".into(),
                    ));
                }
            },
        };
        Ok(to_batch(events, overflowed))
    }

    fn source(&self) -> &'static str {
        match self.source {
            Source::Warden(_) => "warden",
            Source::Local { .. } => "local",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(mask: u64) -> FimEvent {
        FimEvent {
            mask,
            pid: 4242,
            directory: Some("/etc".into()),
            name: "passwd".into(),
            dev: Some(2049),
            ino: Some(131_074),
            unresolved: None,
        }
    }

    fn opens_one(paths: &[String]) -> (Option<LocalRead>, Vec<FimMark>) {
        let read: LocalRead = Box::new(|_| Ok((vec![event(FAN_CREATE | FAN_CLOSE_WRITE)], true)));
        let marks = paths
            .iter()
            .map(|p| FimMark {
                path: p.clone(),
                error: None,
            })
            .collect();
        (Some(read), marks)
    }

    fn opens_none(paths: &[String]) -> (Option<LocalRead>, Vec<FimMark>) {
        let marks = paths
            .iter()
            .map(|p| FimMark {
                path: p.clone(),
                error: Some("no such path".into()),
            })
            .collect();
        (None, marks)
    }

    #[test]
    fn merged_bits_become_every_kind_in_order() {
        assert_eq!(
            kinds_of(FAN_DELETE | FAN_CREATE | FAN_ATTRIB),
            vec![
                FileChangeKind::Created,
                FileChangeKind::AttributesChanged,
                FileChangeKind::Deleted
            ]
        );
        assert!(kinds_of(FAN_ONDIR).is_empty());
    }

    #[test]
    fn a_local_watch_reads_what_it_opened() {
        let mut watch = FileWatch {
            source: Source::Local {
                open: opens_one,
                watch: None,
            },
        };
        assert_eq!(watch.source(), "local");
        assert!(watch.read(Duration::ZERO).is_err());
        let marks = watch.open(&["/".into()]).unwrap_or_default();
        assert!(marks[0].is_watched());
        let batch = watch.read(Duration::ZERO).unwrap_or_default();
        assert!(batch.overflowed);
        assert_eq!(batch.changes.len(), 1);
        let change = &batch.changes[0];
        assert_eq!(
            change.kinds,
            vec![FileChangeKind::Created, FileChangeKind::Written]
        );
        assert!(!change.is_dir);
        assert_eq!(change.pid, 4242);
        assert_eq!(change.ino, Some(131_074));
    }

    #[test]
    fn a_local_watch_that_marked_nothing_says_why_and_reads_nothing() {
        let mut watch = FileWatch {
            source: Source::Local {
                open: opens_none,
                watch: None,
            },
        };
        let marks = watch.open(&["/nope".into()]).unwrap_or_default();
        assert_eq!(marks[0].error.as_deref(), Some("no such path"));
        assert!(watch.read(Duration::ZERO).is_err());
    }

    #[test]
    fn an_unreachable_warden_is_an_error() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut watch = FileWatch {
            source: Source::Warden(Box::new(ReconnectingClient::new(
                dir.path().join("absent.sock"),
            ))),
        };
        assert_eq!(watch.source(), "warden");
        assert!(watch.open(&["/".into()]).is_err());
        assert!(watch.read(Duration::ZERO).is_err());
    }

    #[test]
    fn a_change_with_no_kind_is_dropped() {
        assert!(to_batch(vec![event(FAN_ONDIR)], false).changes.is_empty());
    }
}
