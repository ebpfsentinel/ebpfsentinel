//! The decisive signal read from a file nobody has a reason to open.
//!
//! A canary is a small file of fixed content planted in a data directory and
//! watched for any open or read, whatever the access mode. A run that walks
//! the directory to encrypt it opens the canary along with everything else,
//! and one open is enough: no legitimate process reads a file it never
//! wrote and nothing names. What decides the value is placement. A canary in
//! a directory nobody walks catches nothing, and one in a directory a backup
//! or an indexer walks fires every time it runs, which is what the exempt
//! executables are for.

use super::actor::Actor;
use super::signal::{RansomSignal, SignalKind};

/// The names planted in each directory by default. One sorts before and one
/// after almost every other name, so a run that walks a directory in name
/// order meets a canary first or last, and the extensions are the documents
/// a run sets out to encrypt.
pub const CANARY_NAMES: &[&str] = &["0000-archive.docx", "zzzz-archive.xlsx"];

/// The directories seeded by default: where data an operator keeps lives, and
/// where a run sets out from. A directory absent on the host is skipped.
pub const CANARY_DIRECTORIES: &[&str] = &[
    "/home", "/root", "/srv", "/var/www", "/opt", "/mnt", "/media",
];

/// The executables whose opens of a canary are not a signal by default:
/// backup tools and virus scanners that read every file of a directory by
/// design. Matched against the executable's full path, so a copy of one
/// elsewhere is not exempt.
pub const CANARY_EXEMPT: &[&str] = &[
    "/usr/bin/restic",
    "/usr/bin/rclone",
    "/usr/bin/kopia",
    "/usr/bin/rsync",
    "/usr/bin/tar",
    "/usr/sbin/bacula-fd",
    "/usr/sbin/bareos-fd",
    "/usr/bin/clamscan",
    "/usr/sbin/clamd",
];

/// Canaries planted at most.
pub const CANARIES_MAX: usize = 512;

/// Why `name` cannot be a canary's name, `None` when it can.
#[must_use]
pub fn canary_name_refusal(name: &str) -> Option<&'static str> {
    if name.is_empty() || name == "." || name == ".." {
        Some("is not a file name")
    } else if name.contains('/') || name.contains('\0') {
        Some("holds a slash or a NUL byte")
    } else if name.len() > 255 {
        Some("is longer than 255 bytes")
    } else {
        None
    }
}

/// Every canary path: each name in each directory, once.
#[must_use]
pub fn canary_paths(directories: &[String], names: &[String]) -> Vec<String> {
    let mut paths = Vec::with_capacity(directories.len() * names.len());
    for directory in directories {
        let directory = directory.trim_end_matches('/');
        for name in names {
            let path = format!("{directory}/{name}");
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    paths
}

/// Whether an open by the executable at `exe` is exempt under `exempt`.
#[must_use]
pub fn canary_exempt(exe: Option<&str>, exempt: &[String]) -> bool {
    exe.is_some_and(|exe| exempt.iter().any(|listed| listed == exe))
}

/// The signal one open of the canary at `path` raises, by `pid` on behalf of
/// `actor`.
#[must_use]
pub fn canary_touched(actor: &Actor, pid: u32, path: Option<&str>, at_ns: u64) -> RansomSignal {
    let evidence = match path {
        Some(path) => format!("canary {path} opened"),
        None => "a canary whose directory could not be named was opened".to_owned(),
    };
    RansomSignal {
        kind: SignalKind::CanaryTouched,
        actor: actor.clone(),
        pid,
        at_ns,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::entity::ProcessKey;
    use crate::ransom::signal::Tier;

    #[test]
    fn every_name_lands_in_every_directory_once() {
        let directories = vec!["/srv/".to_owned(), "/home".to_owned(), "/srv".to_owned()];
        let names = vec!["a.docx".to_owned(), "b.xlsx".to_owned()];
        assert_eq!(
            canary_paths(&directories, &names),
            vec!["/srv/a.docx", "/srv/b.xlsx", "/home/a.docx", "/home/b.xlsx"]
        );
        assert_eq!(canary_paths(&["/".to_owned()], &names)[0], "/a.docx");
    }

    #[test]
    fn the_defaults_are_valid_and_within_the_bound() {
        assert!(
            CANARY_NAMES
                .iter()
                .all(|n| canary_name_refusal(n).is_none())
        );
        assert!(CANARY_DIRECTORIES.iter().all(|d| d.starts_with('/')));
        assert!(CANARY_EXEMPT.iter().all(|e| e.starts_with('/')));
        assert!(CANARY_NAMES.len() * CANARY_DIRECTORIES.len() <= CANARIES_MAX);
        assert!(canary_name_refusal("a/b").is_some());
        assert!(canary_name_refusal("..").is_some());
    }

    #[test]
    fn one_open_is_decisive_unless_its_executable_is_exempt() {
        let actor = Actor {
            key: ProcessKey {
                pid: 7,
                start_ns: 1,
            },
            pid: 7,
            exe: Some("/tmp/x".to_owned()),
            remote: None,
        };
        let signal = canary_touched(&actor, 8, Some("/srv/0000-archive.docx"), 5);
        assert_eq!(signal.tier(), Tier::Decisive);
        assert_eq!(signal.evidence, "canary /srv/0000-archive.docx opened");
        let exempt = vec!["/usr/bin/restic".to_owned()];
        assert!(canary_exempt(Some("/usr/bin/restic"), &exempt));
        assert!(!canary_exempt(Some("/tmp/restic"), &exempt));
        assert!(!canary_exempt(None, &exempt));
    }
}
