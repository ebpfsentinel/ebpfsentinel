//! Changes to files on the node, and who made them.
//!
//! The kernel reports a change on a watched filesystem after it happened, as
//! the directory, the entry's name, the kinds of change and the process that
//! made it. This module holds that report in the product's words; it decides
//! nothing about whether a change matters.

pub mod baseline;
pub mod entity;
pub mod expected;
pub mod own;
pub mod rooted;
pub mod watched;

pub use baseline::{FileBaseline, FileDrift, FileFacts, FileReading, FileType, XattrDigest};
pub use entity::{
    FileChange, FileChangeBatch, FileChangeKind, FileOpened, PlantedCanary, WatchedFilesystem,
};
pub use expected::{
    EXPECTED_BASELINES_MAX, ExpectedBaseline, ExpectedBaselines, ExpectedBaselinesDocument,
    FileFingerprint,
};
pub use own::{AGENT_FILES_COMPONENT, OwnFileChange, OwnFileRole, OwnFiles, own_file_change};
pub use rooted::{RootMount, RootedPath, root_mount, rooted};
pub use watched::{
    DECLARED_ORIGIN, FILE_INTEGRITY_COMPONENT, SettledPath, WATCHED_PATHS_MAX, WatchedPathChange,
    WatchedPaths, check_watched_path, watched_path_change,
};
