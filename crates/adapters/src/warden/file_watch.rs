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
use domain::file_watch::{
    FileBaseline, FileChange, FileChangeBatch, FileChangeKind, FileFacts, FileOpened, FileReading,
    FileType, PlantedCanary, WatchedFilesystem, XattrDigest,
};
use ebpfsentinel_warden_client::ReconnectingClient;
pub use ebpfsentinel_warden_client::{
    FimCanary, FimEvent, FimFacts, FimFile, FimFileType, FimMark, FimReading, FimXattr,
};
use ports::secondary::file_watch_port::FileWatchSource;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

const FAN_ACCESS: u64 = 0x0000_0001;
const FAN_ATTRIB: u64 = 0x0000_0004;
const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
const FAN_OPEN: u64 = 0x0000_0020;
const FAN_MOVED_FROM: u64 = 0x0000_0040;
const FAN_MOVED_TO: u64 = 0x0000_0080;
const FAN_CREATE: u64 = 0x0000_0100;
const FAN_DELETE: u64 = 0x0000_0200;
const FAN_RENAME: u64 = 0x1000_0000;
const FAN_ONDIR: u64 = 0x4000_0000;

/// An open in-process watch, run by the same code the warden runs.
pub trait LocalWatch: Send {
    /// What the watch queued, waiting at most `max_wait` for a first change.
    ///
    /// # Errors
    ///
    /// The watch could not be read.
    fn read(&mut self, max_wait: Duration) -> Result<(Vec<FimEvent>, bool), String>;

    /// What each path on a watched filesystem names.
    fn facts(&self, paths: &[String], max_hash_bytes: u64) -> Vec<FimFacts>;

    /// Plant a canary at each path and watch it for any open or read.
    fn plant(&mut self, paths: &[String]) -> Vec<FimCanary>;
}

/// Opens an in-process watch on the filesystems holding the paths given.
pub type LocalOpen = fn(&[String]) -> (Option<Box<dyn LocalWatch>>, Vec<FimMark>);

enum Source {
    Warden(Box<ReconnectingClient>),
    Local {
        open: LocalOpen,
        watch: Option<Box<dyn LocalWatch>>,
    },
}

const NO_LOCAL_WATCH: &str = "no file watch is open: no filesystem could be marked";

/// Why no file is watched before the watch was ever opened.
const NEVER_OPENED: &str = "the file watch is not enabled";

static STATUS: std::sync::OnceLock<std::sync::Mutex<Option<String>>> = std::sync::OnceLock::new();

fn status_cell() -> &'static std::sync::Mutex<Option<String>> {
    STATUS.get_or_init(|| std::sync::Mutex::new(Some(NEVER_OPENED.to_owned())))
}

fn publish(reason: Option<String>) {
    *status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = reason;
}

/// Why no filesystem is watched right now, `None` while at least one is.
/// Published by every opening of the watch, so a watch the warden lost
/// reads as lost until it is opened again.
#[must_use]
pub fn status() -> Option<String> {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Why an opening left nothing watched, `None` when it watches something.
fn unwatched(opened: &Result<Vec<WatchedFilesystem>, DomainError>) -> Option<String> {
    match opened {
        Err(e) => Some(e.to_string()),
        Ok(marks) if marks.iter().any(WatchedFilesystem::is_watched) => None,
        Ok(marks) => Some(
            marks
                .iter()
                .find_map(|m| m.error.clone())
                .unwrap_or_else(|| "no filesystem is configured to be watched".to_owned()),
        ),
    }
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
                // A rename names the entry where it arrived.
                FileChangeKind::MovedIn => FAN_MOVED_TO | FAN_RENAME,
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
        renamed_from: event.renamed_from,
    })
}

/// The canary an event reports opened, when it reports an open.
fn to_opened(event: &FimEvent) -> Option<FileOpened> {
    if event.mask & (FAN_OPEN | FAN_ACCESS) == 0 {
        return None;
    }
    Some(FileOpened {
        pid: event.pid,
        path: event.directory.as_deref().map(|dir| {
            if dir.ends_with('/') {
                format!("{dir}{}", event.name)
            } else {
                format!("{dir}/{}", event.name)
            }
        }),
    })
}

fn to_batch(events: Vec<FimEvent>, overflowed: bool) -> FileChangeBatch {
    let opened = events.iter().filter_map(to_opened).collect();
    FileChangeBatch {
        changes: events.into_iter().filter_map(to_change).collect(),
        overflowed,
        opened,
    }
}

fn to_planted(canaries: Vec<FimCanary>) -> Vec<PlantedCanary> {
    canaries
        .into_iter()
        .map(|c| PlantedCanary {
            path: c.path,
            error: c.error,
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn to_baseline(file: FimFile) -> FileBaseline {
    FileBaseline {
        file_type: match file.file_type {
            FimFileType::Regular => FileType::Regular,
            FimFileType::Directory => FileType::Directory,
            FimFileType::Symlink => FileType::Symlink,
            FimFileType::Other => FileType::Other,
        },
        size: file.size,
        mtime_ns: file.mtime_ns,
        mode: file.mode,
        uid: file.uid,
        gid: file.gid,
        dev: file.dev,
        ino: file.ino,
        link_target: file.link_target,
        sha256: file.sha256.map(|d| hex(&d)),
        hash_unread: file.hash_unread,
        entropy_millibits: file.entropy_millibits,
        head: file.head,
        xattrs: file
            .xattrs
            .into_iter()
            .map(|x| XattrDigest {
                name: x.name,
                sha256: hex(&x.sha256),
            })
            .collect(),
        xattrs_unread: file.xattrs_unread,
    }
}

fn to_facts(facts: Vec<FimFacts>) -> Vec<FileFacts> {
    facts
        .into_iter()
        .map(|f| FileFacts {
            path: f.path,
            reading: match f.reading {
                FimReading::Present(file) => FileReading::Present(to_baseline(file)),
                FimReading::Gone => FileReading::Gone,
                FimReading::Unreadable(reason) => FileReading::Unreadable(reason),
            },
        })
        .collect()
}

fn to_marks(marks: Vec<FimMark>) -> Vec<WatchedFilesystem> {
    marks
        .into_iter()
        .map(|m| WatchedFilesystem {
            path: m.path,
            error: m.error,
            renames: m.renames,
        })
        .collect()
}

impl FileWatchSource for FileWatch {
    fn open(&mut self, paths: &[String]) -> Result<Vec<WatchedFilesystem>, DomainError> {
        let opened = match &mut self.source {
            Source::Warden(client) => client.fim_open(paths).map(to_marks).map_err(|e| {
                DomainError::EngineError(format!("warden could not open the file watch: {e}"))
            }),
            Source::Local { open, watch } => {
                let (opened, marks) = open(paths);
                *watch = opened;
                Ok(to_marks(marks))
            }
        };
        publish(unwatched(&opened));
        opened
    }

    fn read(&mut self, max_wait: Duration) -> Result<FileChangeBatch, DomainError> {
        let millis = u32::try_from(max_wait.as_millis()).unwrap_or(u32::MAX);
        let (events, overflowed) = match &mut self.source {
            Source::Warden(client) => client.fim_read(millis).map_err(|e| {
                DomainError::EngineError(format!("warden could not read the file watch: {e}"))
            })?,
            Source::Local { watch, .. } => match watch {
                Some(watch) => watch.read(max_wait).map_err(DomainError::EngineError)?,
                None => return Err(DomainError::EngineError(NO_LOCAL_WATCH.into())),
            },
        };
        Ok(to_batch(events, overflowed))
    }

    fn facts(
        &mut self,
        paths: &[String],
        max_hash_bytes: u64,
    ) -> Result<Vec<FileFacts>, DomainError> {
        let facts = match &mut self.source {
            Source::Warden(client) => client.fim_facts(paths, max_hash_bytes).map_err(|e| {
                DomainError::EngineError(format!("warden could not read the files: {e}"))
            })?,
            Source::Local { watch, .. } => match watch {
                Some(watch) => watch.facts(paths, max_hash_bytes),
                None => return Err(DomainError::EngineError(NO_LOCAL_WATCH.into())),
            },
        };
        Ok(to_facts(facts))
    }

    fn plant(&mut self, paths: &[String]) -> Result<Vec<PlantedCanary>, DomainError> {
        let planted = match &mut self.source {
            Source::Warden(client) => client.fim_canaries(paths).map_err(|e| {
                DomainError::EngineError(format!("warden could not plant the canaries: {e}"))
            })?,
            Source::Local { watch, .. } => match watch {
                Some(watch) => watch.plant(paths),
                None => return Err(DomainError::EngineError(NO_LOCAL_WATCH.into())),
            },
        };
        Ok(to_planted(planted))
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
            renamed_from: None,
        }
    }

    struct OneEvent;

    impl LocalWatch for OneEvent {
        fn read(&mut self, _: Duration) -> Result<(Vec<FimEvent>, bool), String> {
            Ok((vec![event(FAN_CREATE | FAN_CLOSE_WRITE)], true))
        }

        fn facts(&self, paths: &[String], _: u64) -> Vec<FimFacts> {
            paths
                .iter()
                .map(|p| FimFacts {
                    path: p.clone(),
                    reading: FimReading::Present(FimFile {
                        file_type: FimFileType::Regular,
                        size: 2,
                        mtime_ns: 5,
                        mode: 0o600,
                        uid: 1,
                        gid: 2,
                        dev: 3,
                        ino: 4,
                        link_target: None,
                        sha256: Some([0xab; 32]),
                        hash_unread: None,
                        entropy_millibits: None,
                        head: None,
                        xattrs: vec![FimXattr {
                            name: "security.ima".into(),
                            sha256: [0x01; 32],
                        }],
                        xattrs_unread: None,
                    }),
                })
                .collect()
        }

        fn plant(&mut self, paths: &[String]) -> Vec<FimCanary> {
            paths
                .iter()
                .map(|p| FimCanary {
                    path: p.clone(),
                    error: None,
                })
                .collect()
        }
    }

    fn opens_one(paths: &[String]) -> (Option<Box<dyn LocalWatch>>, Vec<FimMark>) {
        let read: Box<dyn LocalWatch> = Box::new(OneEvent);
        let marks = paths
            .iter()
            .map(|p| FimMark {
                path: p.clone(),
                error: None,
                renames: true,
            })
            .collect();
        (Some(read), marks)
    }

    fn opens_none(paths: &[String]) -> (Option<Box<dyn LocalWatch>>, Vec<FimMark>) {
        let marks = paths
            .iter()
            .map(|p| FimMark {
                path: p.clone(),
                error: Some("no such path".into()),
                renames: false,
            })
            .collect();
        (None, marks)
    }

    #[test]
    fn an_opening_says_why_nothing_is_watched() {
        let mark = |error: Option<&str>| WatchedFilesystem {
            path: "/".into(),
            error: error.map(Into::into),
            renames: error.is_none(),
        };
        assert_eq!(
            unwatched(&Ok(vec![mark(Some("refused")), mark(None)])),
            None
        );
        assert_eq!(
            unwatched(&Ok(vec![mark(Some("refused"))])).as_deref(),
            Some("refused")
        );
        assert!(unwatched(&Ok(Vec::new())).is_some());
        assert!(
            unwatched(&Err(DomainError::EngineError("warden unreachable".into())))
                .is_some_and(|r| r.contains("warden unreachable"))
        );
    }

    #[test]
    fn an_open_of_a_canary_is_reported_apart_from_the_changes() {
        let batch = to_batch(
            vec![event(FAN_OPEN), event(FAN_ACCESS | FAN_CLOSE_WRITE)],
            false,
        );
        assert_eq!(batch.changes.len(), 1);
        assert_eq!(
            batch.opened,
            vec![
                FileOpened {
                    pid: 4242,
                    path: Some("/etc/passwd".into())
                };
                2
            ]
        );
        let mut root = event(FAN_OPEN);
        root.directory = Some("/".into());
        assert_eq!(
            to_opened(&root).and_then(|o| o.path).as_deref(),
            Some("/passwd")
        );
        root.directory = None;
        assert_eq!(to_opened(&root).map(|o| o.path), Some(None));
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
        assert_eq!(kinds_of(FAN_RENAME), vec![FileChangeKind::MovedIn]);
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
    fn local_facts_carry_digests_as_hex() {
        let mut watch = FileWatch {
            source: Source::Local {
                open: opens_one,
                watch: None,
            },
        };
        assert!(watch.facts(&["/etc/hosts".into()], 1).is_err());
        assert!(watch.plant(&["/srv/0000-archive.docx".into()]).is_err());
        let _ = watch.open(&["/".into()]);
        let planted = watch
            .plant(&["/srv/0000-archive.docx".into()])
            .unwrap_or_default();
        assert_eq!(planted.len(), 1);
        assert!(planted[0].error.is_none());
        let facts = watch.facts(&["/etc/hosts".into()], 1).unwrap_or_default();
        let FileReading::Present(file) = &facts[0].reading else {
            panic!("expected an entry");
        };
        assert_eq!(facts[0].path, "/etc/hosts");
        assert_eq!(file.sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(file.xattrs[0].sha256, "01".repeat(32));
        assert_eq!((file.mode, file.uid, file.gid), (0o600, 1, 2));
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
        assert!(watch.facts(&["/etc/hosts".into()], 1).is_err());
    }

    #[test]
    fn a_change_with_no_kind_is_dropped() {
        assert!(to_batch(vec![event(FAN_ONDIR)], false).changes.is_empty());
    }
}
