//! Changes to files on the node, and who made them.
//!
//! The kernel reports a change on a watched filesystem after it happened, as
//! the directory, the entry's name, the kinds of change and the process that
//! made it. This module holds that report in the product's words; it decides
//! nothing about whether a change matters.

pub mod baseline;
pub mod entity;

pub use baseline::{FileBaseline, FileDrift, FileFacts, FileReading, FileType, XattrDigest};
pub use entity::{FileChange, FileChangeBatch, FileChangeKind, WatchedFilesystem};
