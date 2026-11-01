//! The file intentions, built from a change once the path was read again.
//!
//! The kernel says what kind of change it saw; the reading and the baseline
//! say what it amounted to. A name created over a file that was already
//! there, by `mv` or by an overlay copying a file of the image up into the
//! container, is a change to that file rather than a new one, and a name
//! moved away or deleted is a disappearance only where something was known
//! to be there. A rename the kernel reported with both names is one event
//! carrying both, and the name it left raises nothing of its own.

use std::collections::BTreeSet;

use crate::file_watch::{FileBaseline, FileChangeKind, FileReading, RootedPath};

use super::event::IntentEvent;
use super::field::FieldValue;
use super::intent::Intent;

/// One changed path, settled.
#[derive(Debug, Clone, Copy)]
pub struct SettledChange<'a> {
    /// Every kind of change seen on the path since it was last read.
    pub kinds: &'a BTreeSet<FileChangeKind>,
    /// The path on the host, as the watch reported it.
    pub host_path: &'a str,
    /// The path as the writer sees it.
    pub rooted: &'a RootedPath,
    /// What the path was known to be before.
    pub before: Option<&'a FileBaseline>,
    /// What the path reads as now.
    pub reading: &'a FileReading,
    /// A layer of the writer's image holds the same name.
    pub in_image: bool,
    /// Device and inode the change named, for a path no longer readable.
    pub dev: Option<u64>,
    pub ino: Option<u64>,
    /// The host path the entry was renamed from, when the kernel named it.
    pub renamed_from: Option<&'a str>,
    /// The path is the old end of a rename reported with both names.
    pub renamed_away: bool,
}

/// The intentions `change` raises, each carrying the file's fields. The
/// writer's own fields are the caller's to add.
#[must_use]
pub fn file_events(change: &SettledChange<'_>) -> Vec<IntentEvent> {
    let arrived = change.kinds.contains(&FileChangeKind::Created)
        || change.kinds.contains(&FileChangeKind::MovedIn);
    let left = change.kinds.contains(&FileChangeKind::Deleted)
        || change.kinds.contains(&FileChangeKind::MovedOut);
    let mut events = Vec::new();
    match change.reading {
        FileReading::Present(now) => {
            let existed = change.before.is_some() || change.in_image;
            if change.renamed_from.is_some() {
                events.push(Intent::FileRenames);
                if change.kinds.contains(&FileChangeKind::Written) {
                    events.push(Intent::FileChanges);
                }
            } else if arrived && !existed {
                events.push(Intent::FileAppears);
            } else if arrived || change.kinds.contains(&FileChangeKind::Written) {
                events.push(Intent::FileChanges);
            }
            let mut out: Vec<IntentEvent> = events
                .into_iter()
                .map(|intent| file_fields(intent, change, Some(now)))
                .collect();
            if let Some(before) = change.before {
                if before.mode != now.mode || before.uid != now.uid {
                    let event = file_fields(Intent::FilePermissionsChange, change, Some(now));
                    let event = put(event, "mode", FieldValue::Integer(i64::from(now.mode)));
                    let event = put(
                        event,
                        "previous_mode",
                        FieldValue::Integer(i64::from(before.mode)),
                    );
                    out.push(put(
                        event,
                        "owner_uid",
                        FieldValue::Integer(i64::from(now.uid)),
                    ));
                }
                if let (Some(expected), Some(actual)) = (&before.sha256, &now.sha256)
                    && expected != actual
                {
                    let event = file_fields(Intent::FileIntegrityBreaks, change, Some(now));
                    let event = put(event, "expected_hash", FieldValue::Text(expected.clone()));
                    out.push(put(event, "actual_hash", FieldValue::Text(actual.clone())));
                }
            }
            out
        }
        FileReading::Gone
            if !change.renamed_away && (change.before.is_some() || (left && !arrived)) =>
        {
            vec![file_fields(Intent::FileDisappears, change, change.before)]
        }
        FileReading::Gone | FileReading::Unreadable(_) => Vec::new(),
    }
}

/// `intent` carrying the path, the host path, the extension, the device and
/// the inode.
fn file_fields(
    intent: Intent,
    change: &SettledChange<'_>,
    file: Option<&FileBaseline>,
) -> IntentEvent {
    let path = change.rooted.path.as_deref().unwrap_or(change.host_path);
    let mut event = put(
        IntentEvent::new(intent),
        "path",
        FieldValue::Text(path.to_owned()),
    );
    event = put(
        event,
        "host_path",
        FieldValue::Text(change.host_path.to_owned()),
    );
    if intent.field("extension").is_ok()
        && let Some(extension) = extension(path)
    {
        event = put(event, "extension", FieldValue::Text(extension.to_owned()));
    }
    let dev = file.map(|f| f.dev).or(change.dev);
    let ino = file.map(|f| f.ino).or(change.ino);
    if let Some(dev) = dev.and_then(|d| i64::try_from(d).ok()) {
        event = put(event, "device", FieldValue::Integer(dev));
    }
    if let Some(ino) = ino.and_then(|i| i64::try_from(i).ok()) {
        event = put(event, "inode", FieldValue::Integer(ino));
    }
    if intent == Intent::FileRenames
        && let Some(from) = change.renamed_from
    {
        let previous = previous_path(change, from);
        if let Some(extension) = extension(previous) {
            event = put(
                event,
                "previous_extension",
                FieldValue::Text(extension.to_owned()),
            );
        }
        event = put(
            event,
            "previous_path",
            FieldValue::Text(previous.to_owned()),
        );
    }
    event
}

/// The old name as the writer saw it: the host prefix the new name loses
/// inside the writer's root is taken off the old one too, since a rename
/// never crosses a filesystem.
fn previous_path<'a>(change: &SettledChange<'_>, from: &'a str) -> &'a str {
    let Some(inside) = change.rooted.path.as_deref() else {
        return from;
    };
    change
        .host_path
        .strip_suffix(inside)
        .filter(|prefix| !prefix.is_empty())
        .and_then(|prefix| from.strip_prefix(prefix))
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(from)
}

/// The extension of the last component, without the dot: none for a name
/// without one, and none for a name whose only dot leads it, which is a
/// hidden file rather than an extension.
fn extension(path: &str) -> Option<&str> {
    let name = path.rsplit('/').next()?;
    let (stem, extension) = name.rsplit_once('.')?;
    (!stem.is_empty() && !extension.is_empty()).then_some(extension)
}

/// `event` with `name` set, or unchanged where the registry refuses it. The
/// names here are the registry's own, and the tests below fail first on a
/// field renamed without this file.
fn put(event: IntentEvent, name: &str, value: FieldValue) -> IntentEvent {
    event.clone().with(name, value).unwrap_or(event)
}

#[cfg(test)]
mod tests {
    use crate::file_watch::FileType;

    use super::*;

    fn file(sha: char, mode: u32, uid: u32) -> FileBaseline {
        FileBaseline {
            file_type: FileType::Regular,
            size: 4,
            mtime_ns: 9,
            mode,
            uid,
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

    fn kinds(list: &[FileChangeKind]) -> BTreeSet<FileChangeKind> {
        list.iter().copied().collect()
    }

    fn events(
        list: &[FileChangeKind],
        before: Option<&FileBaseline>,
        reading: &FileReading,
        in_image: bool,
    ) -> Vec<IntentEvent> {
        let kinds = kinds(list);
        let rooted = RootedPath {
            path: Some("/root/.ssh/authorized_keys".into()),
            layers: Vec::new(),
        };
        file_events(&SettledChange {
            kinds: &kinds,
            host_path: "/var/lib/c/9/fs/root/.ssh/authorized_keys",
            rooted: &rooted,
            before,
            reading,
            in_image,
            dev: Some(7),
            ino: Some(8),
            renamed_from: None,
            renamed_away: false,
        })
    }

    fn intents(events: &[IntentEvent]) -> Vec<Intent> {
        events.iter().map(IntentEvent::intent).collect()
    }

    fn text(event: &IntentEvent, name: &str) -> Option<String> {
        match event.get(name) {
            Some(FieldValue::Text(t)) => Some(t.clone()),
            _ => None,
        }
    }

    fn integer(event: &IntentEvent, name: &str) -> Option<i64> {
        match event.get(name) {
            Some(FieldValue::Integer(n)) => Some(*n),
            _ => None,
        }
    }

    #[test]
    fn a_new_name_appears_and_carries_both_paths() {
        let now = FileReading::Present(file('a', 0o600, 0));
        let out = events(
            &[FileChangeKind::Created, FileChangeKind::Written],
            None,
            &now,
            false,
        );
        assert_eq!(intents(&out), vec![Intent::FileAppears]);
        let event = &out[0];
        assert_eq!(
            text(event, "path").as_deref(),
            Some("/root/.ssh/authorized_keys")
        );
        assert_eq!(
            text(event, "host_path").as_deref(),
            Some("/var/lib/c/9/fs/root/.ssh/authorized_keys")
        );
        assert_eq!(integer(event, "device"), Some(1));
        assert_eq!(integer(event, "inode"), Some(2));
        assert_eq!(text(event, "extension"), None);
    }

    #[test]
    fn a_move_over_a_known_file_is_a_change_not_an_appearance() {
        let before = file('a', 0o600, 0);
        let now = FileReading::Present(file('b', 0o600, 0));
        let out = events(&[FileChangeKind::MovedIn], Some(&before), &now, false);
        assert_eq!(
            intents(&out),
            vec![Intent::FileChanges, Intent::FileIntegrityBreaks]
        );
        let broken = &out[1];
        assert_eq!(text(broken, "expected_hash"), Some("a".repeat(64)));
        assert_eq!(text(broken, "actual_hash"), Some("b".repeat(64)));
    }

    #[test]
    fn a_copy_up_from_the_image_is_a_change() {
        let now = FileReading::Present(file('a', 0o644, 0));
        let out = events(
            &[FileChangeKind::Created, FileChangeKind::Written],
            None,
            &now,
            true,
        );
        assert_eq!(intents(&out), vec![Intent::FileChanges]);
    }

    #[test]
    fn a_mode_or_owner_change_carries_both_modes() {
        let before = file('a', 0o644, 0);
        let now = FileReading::Present(file('a', 0o4755, 1000));
        let out = events(
            &[FileChangeKind::AttributesChanged],
            Some(&before),
            &now,
            false,
        );
        assert_eq!(intents(&out), vec![Intent::FilePermissionsChange]);
        let event = &out[0];
        assert_eq!(integer(event, "mode"), Some(0o4755));
        assert_eq!(integer(event, "previous_mode"), Some(0o644));
        assert_eq!(integer(event, "owner_uid"), Some(1000));
    }

    #[test]
    fn a_name_gone_disappears_where_something_was_known_there() {
        let before = file('a', 0o644, 0);
        let out = events(
            &[FileChangeKind::MovedOut],
            Some(&before),
            &FileReading::Gone,
            false,
        );
        assert_eq!(intents(&out), vec![Intent::FileDisappears]);
        assert_eq!(integer(&out[0], "inode"), Some(2));
        let out = events(&[FileChangeKind::Deleted], None, &FileReading::Gone, false);
        assert_eq!(intents(&out), vec![Intent::FileDisappears]);
        assert_eq!(integer(&out[0], "inode"), Some(8));
        // Created and removed before it was read: nothing was ever there.
        let out = events(
            &[FileChangeKind::Created, FileChangeKind::Deleted],
            None,
            &FileReading::Gone,
            false,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn an_unreadable_path_raises_nothing() {
        let before = file('a', 0o644, 0);
        let out = events(
            &[FileChangeKind::Written],
            Some(&before),
            &FileReading::Unreadable("denied".into()),
            false,
        );
        assert!(out.is_empty());
    }

    #[test]
    fn the_host_path_is_the_path_when_the_writer_root_is_unknown() {
        let kinds = kinds(&[FileChangeKind::Written]);
        let rooted = RootedPath::default();
        let now = FileReading::Present(file('a', 0o644, 0));
        let out = file_events(&SettledChange {
            kinds: &kinds,
            host_path: "/data/report.CSV",
            rooted: &rooted,
            before: None,
            reading: &now,
            in_image: false,
            dev: None,
            ino: None,
            renamed_from: None,
            renamed_away: false,
        });
        assert_eq!(text(&out[0], "path").as_deref(), Some("/data/report.CSV"));
        assert_eq!(text(&out[0], "extension").as_deref(), Some("CSV"));
    }

    #[test]
    fn a_rename_reported_with_both_names_is_one_event_carrying_both() {
        let arrived = kinds(&[FileChangeKind::MovedIn]);
        let rooted = RootedPath {
            path: Some("/srv/q3.locked".into()),
            layers: Vec::new(),
        };
        let now = FileReading::Present(file('a', 0o644, 0));
        let out = file_events(&SettledChange {
            kinds: &arrived,
            host_path: "/var/lib/c/9/fs/srv/q3.locked",
            rooted: &rooted,
            before: None,
            reading: &now,
            in_image: false,
            dev: None,
            ino: None,
            renamed_from: Some("/var/lib/c/9/fs/srv/q3.xlsx"),
            renamed_away: false,
        });
        assert_eq!(intents(&out), vec![Intent::FileRenames]);
        assert_eq!(text(&out[0], "path").as_deref(), Some("/srv/q3.locked"));
        assert_eq!(text(&out[0], "extension").as_deref(), Some("locked"));
        assert_eq!(
            text(&out[0], "previous_path").as_deref(),
            Some("/srv/q3.xlsx")
        );
        assert_eq!(text(&out[0], "previous_extension").as_deref(), Some("xlsx"));
        // The name it left is gone, and says nothing the rename did not.
        let left = kinds(&[FileChangeKind::MovedOut]);
        let before = file('a', 0o644, 0);
        let out = file_events(&SettledChange {
            kinds: &left,
            host_path: "/var/lib/c/9/fs/srv/q3.xlsx",
            rooted: &RootedPath::default(),
            before: Some(&before),
            reading: &FileReading::Gone,
            in_image: false,
            dev: None,
            ino: None,
            renamed_from: None,
            renamed_away: true,
        });
        assert!(out.is_empty());
    }

    #[test]
    fn without_the_rename_event_a_move_is_a_disappearance_and_an_appearance() {
        let now = FileReading::Present(file('a', 0o644, 0));
        let out = events(&[FileChangeKind::MovedIn], None, &now, false);
        assert_eq!(intents(&out), vec![Intent::FileAppears]);
        let before = file('a', 0o644, 0);
        let out = events(
            &[FileChangeKind::MovedOut],
            Some(&before),
            &FileReading::Gone,
            false,
        );
        assert_eq!(intents(&out), vec![Intent::FileDisappears]);
    }

    #[test]
    fn extensions_skip_hidden_names() {
        assert_eq!(extension("/a/b.tar.gz"), Some("gz"));
        assert_eq!(extension("/a/.bashrc"), None);
        assert_eq!(extension("/a/b."), None);
        assert_eq!(extension("/a/b"), None);
    }
}
