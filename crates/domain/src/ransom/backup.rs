//! The prior read from what a run starts: the snapshots and backups it
//! destroys before it encrypts.
//!
//! A run that means to be paid removes what would restore the files first.
//! On Linux that is a `btrfs` subvolume or a `zfs` dataset destroyed, a
//! `restic`, `borg` or `borgmatic` repository purged, snapper or timeshift
//! snapshots deleted, a backup unit stopped, disabled or masked, or a crontab
//! removed. Each of those is also an administrator's Tuesday, so it is a
//! prior: it lowers what the run's later signals must add up to, and never
//! reaches a verdict by itself.
//!
//! The prior belongs to whoever ran the command rather than to the command,
//! since `zfs destroy` encrypts nothing. That is the process that started it,
//! climbed past the shells a command line passes through, and the prior then
//! counts for every run started below that process.

use crate::process::engine::Lineage;
use crate::process::entity::{ProcessEntry, ProcessKey};

use super::actor::Actor;
use super::signal::{RansomSignal, SignalKind};

/// How long a prior counts for after it was seen: ten minutes, since it
/// comes before the encryption rather than during it.
pub const BACKUP_PRIOR_WINDOW_NS: u64 = 600_000_000_000;

/// Words that name a backup or snapshot unit, compared against a unit's name
/// without regard to case.
pub const BACKUP_UNIT_MARKERS: &[&str] = &[
    "backup",
    "restic",
    "borg",
    "kopia",
    "duplicity",
    "duplicati",
    "rsnapshot",
    "bacula",
    "bareos",
    "urbackup",
    "amanda",
    "veeam",
    "snapper",
    "timeshift",
    "sanoid",
    "syncoid",
    "zfs-auto-snapshot",
];

/// Backup programs, which prune their own repository and then write into it
/// encrypted: what such a program writes is never judged against a prior,
/// because the prior is held for a run like its own. Its writes still reach
/// a verdict on what they show alone.
pub const BACKUP_PROGRAMS: &[&str] = &[
    "restic",
    "rustic",
    "borg",
    "borgmatic",
    "kopia",
    "duplicity",
];

/// Interpreters a command line passes through on its way to the command,
/// climbed past when naming who ran it.
pub const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ash", "ksh", "busybox"];

/// The most ancestors climbed past when naming who ran a command.
const SHELLS_CLIMBED_MAX: usize = 4;

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether `word` is an abbreviation of `full` a command accepts, as `btrfs`
/// takes `sub del` for `subvolume delete`.
fn abbreviates(word: &str, full: &str) -> bool {
    !word.is_empty() && full.starts_with(word)
}

fn backup_unit(unit: &str) -> bool {
    let unit = unit.to_ascii_lowercase();
    BACKUP_UNIT_MARKERS
        .iter()
        .any(|marker| unit.contains(marker))
}

/// Whether the process running `exe` with `command_line` is one of the
/// [`BACKUP_PROGRAMS`], named by its executable or by the program its
/// command line starts.
#[must_use]
pub fn backup_program(exe: Option<&str>, command_line: Option<&str>) -> bool {
    let first = command_line.and_then(|line| line.split_whitespace().next());
    [exe, first]
        .into_iter()
        .flatten()
        .any(|path| BACKUP_PROGRAMS.contains(&base(path)))
}

/// What the command line destroys, in a few words, when it destroys
/// snapshots or backups; `None` for any other command. `exe` is the
/// executable that ran, `command_line` its argv joined with spaces.
#[must_use]
pub fn backup_destroyed(exe: Option<&str>, command_line: &str) -> Option<String> {
    let mut argv = command_line.split_whitespace();
    let first = argv.next()?;
    let program = base(exe.unwrap_or(first));
    let args: Vec<&str> = argv.collect();
    let words: Vec<&str> = args
        .iter()
        .copied()
        .filter(|a| !a.starts_with('-'))
        .collect();
    let word = |n: usize| words.get(n).copied().unwrap_or("");
    let flag = |f: &str| args.contains(&f);
    let what = match program {
        "btrfs"
            if abbreviates(word(0), "subvolume")
                && word(0).len() >= 2
                && abbreviates(word(1), "delete") =>
        {
            "btrfs subvolume deleted"
        }
        "zfs" if word(0) == "destroy" => "zfs dataset or snapshot destroyed",
        // Global options take values (`-r <repository>`), so the command
        // is looked for among every word rather than the first.
        "restic" if words.iter().any(|w| matches!(*w, "forget" | "prune")) => {
            "restic snapshots removed"
        }
        "borg" if matches!(word(0), "delete" | "prune" | "rdelete" | "repo-delete") => {
            "borg archives removed"
        }
        "borgmatic"
            if words
                .iter()
                .any(|w| matches!(*w, "delete" | "rdelete" | "repo-delete")) =>
        {
            "borgmatic repository or archives deleted"
        }
        "snapper"
            if words
                .iter()
                .any(|w| matches!(*w, "delete" | "remove" | "rm")) =>
        {
            "snapper snapshots deleted"
        }
        "timeshift" if flag("--delete") || flag("--delete-all") => "timeshift snapshots deleted",
        "systemctl"
            if matches!(word(0), "stop" | "disable" | "mask")
                && words.iter().skip(1).any(|unit| backup_unit(unit)) =>
        {
            "backup unit stopped, disabled or masked"
        }
        "crontab"
            if args.iter().any(|a| {
                a.len() >= 2
                    && a.starts_with('-')
                    && !a.starts_with("--")
                    && a[1..].contains('r')
                    && a[1..].chars().all(|c| c.is_ascii_alphabetic())
            }) =>
        {
            "crontab removed"
        }
        _ => return None,
    };
    Some(what.to_owned())
}

/// Who ran `entry`: its parent, or above it while the parent is a shell, and
/// never the init process, under which everything runs. `None` where the
/// ancestry is unknown or ends at init.
#[must_use]
pub fn initiator(lineage: &Lineage) -> Option<&ProcessEntry> {
    for (climbed, ancestor) in lineage.ancestors.iter().enumerate() {
        if ancestor.pid <= 1 {
            return None;
        }
        let shell = ancestor
            .identity
            .path()
            .is_some_and(|path| SHELLS.contains(&base(path)));
        if !shell || climbed + 1 >= SHELLS_CLIMBED_MAX {
            return Some(ancestor);
        }
    }
    None
}

/// The prior, held for `initiator`: `pid` ran the command `what` names.
#[must_use]
pub fn backup_destroyed_signal(
    initiator: &ProcessEntry,
    pid: u32,
    command_line: &str,
    what: &str,
    at_ns: u64,
) -> RansomSignal {
    let key: ProcessKey = initiator.key();
    RansomSignal {
        kind: SignalKind::BackupDestroyed,
        actor: Actor {
            key,
            pid: initiator.pid,
            exe: initiator.identity.path().map(ToOwned::to_owned),
            remote: None,
        },
        pid,
        at_ns,
        evidence: format!("{what}: {command_line}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_program_is_named_by_its_executable_or_its_command_line() {
        assert!(backup_program(Some("/usr/bin/restic"), None));
        assert!(backup_program(
            Some("/usr/bin/python3.12"),
            Some("/usr/bin/borg create ::{now} /srv")
        ));
        assert!(!backup_program(
            Some("/usr/bin/rsync"),
            Some("rsync -a /a /b")
        ));
        assert!(!backup_program(None, None));
    }
    use crate::process::entity::ProcessIdentity;

    fn found(exe: &str, line: &str) -> Option<String> {
        backup_destroyed(Some(exe), line)
    }

    #[test]
    fn the_commands_that_destroy_backups_are_named() {
        for (exe, line) in [
            ("/usr/bin/btrfs", "btrfs subvolume delete /snap/1"),
            ("/usr/bin/btrfs", "btrfs sub del -c /snap/1"),
            ("/usr/sbin/zfs", "zfs destroy -r tank/home@daily"),
            (
                "/usr/bin/restic",
                "restic -r /srv/repo forget --keep-last 0 --prune",
            ),
            ("/usr/bin/restic", "restic prune"),
            ("/usr/bin/borg", "borg delete /srv/borg"),
            ("/usr/bin/borgmatic", "borgmatic --verbosity 1 repo-delete"),
            ("/usr/bin/snapper", "snapper -c root delete 1-90"),
            ("/usr/bin/timeshift", "timeshift --delete-all --yes"),
            (
                "/usr/bin/systemctl",
                "systemctl --now mask restic-backup.timer",
            ),
            (
                "/usr/bin/systemctl",
                "systemctl stop nginx Borgmatic.service",
            ),
            ("/usr/bin/crontab", "crontab -u backup -r"),
            ("/usr/bin/crontab", "crontab -ir"),
        ] {
            assert!(found(exe, line).is_some(), "{line}");
        }
    }

    #[test]
    fn the_same_programs_doing_anything_else_are_not() {
        for (exe, line) in [
            ("/usr/bin/btrfs", "btrfs subvolume list /"),
            ("/usr/bin/btrfs", "btrfs subvolume snapshot / /snap/2"),
            ("/usr/bin/btrfs", "btrfs s delete /x"),
            ("/usr/sbin/zfs", "zfs snapshot tank/home@now"),
            ("/usr/bin/restic", "restic backup /home"),
            ("/usr/bin/borg", "borg create ::now /home"),
            ("/usr/bin/borgmatic", "borgmatic"),
            ("/usr/bin/systemctl", "systemctl stop nginx.service"),
            (
                "/usr/bin/systemctl",
                "systemctl start restic-backup.service",
            ),
            ("/usr/bin/crontab", "crontab -l"),
            ("/usr/bin/crontab", "crontab --help"),
            ("/usr/bin/rm", "rm -rf /tmp/x"),
        ] {
            assert!(found(exe, line).is_none(), "{line}");
        }
        assert_eq!(backup_destroyed(None, ""), None);
        // The executable decides, not what the command line calls itself.
        assert!(backup_destroyed(None, "zfs destroy tank").is_some());
        assert!(found("/usr/bin/true", "zfs destroy tank").is_none());
    }

    fn running(pid: u32, path: &str) -> ProcessEntry {
        let mut entry = ProcessEntry::new(pid, "p", u64::from(pid));
        entry.start_ns = Some(u64::from(pid));
        entry.identity = ProcessIdentity::Path {
            path: path.to_owned(),
            dev: 8,
            inode: u64::from(pid),
        };
        entry
    }

    fn lineage(ancestors: Vec<ProcessEntry>) -> Lineage {
        Lineage {
            ancestors,
            truncated: false,
            incomplete: false,
        }
    }

    #[test]
    fn who_ran_a_command_is_found_past_its_shells_and_never_init() {
        let run = running(40, "/tmp/enc");
        let via_shell = lineage(vec![
            running(42, "/bin/sh"),
            running(41, "/usr/bin/bash"),
            run.clone(),
            running(1, "/sbin/init"),
        ]);
        assert_eq!(initiator(&via_shell).map(|e| e.pid), Some(40));
        assert_eq!(
            initiator(&lineage(vec![run.clone()])).map(|e| e.pid),
            Some(40)
        );
        assert!(initiator(&lineage(vec![running(1, "/sbin/init")])).is_none());
        assert!(
            initiator(&lineage(vec![
                running(9, "/bin/sh"),
                running(1, "/sbin/init")
            ]))
            .is_none()
        );
        assert!(initiator(&Lineage::default()).is_none());
        let signal = backup_destroyed_signal(&run, 43, "zfs destroy tank", "zfs destroyed", 7);
        assert_eq!(signal.kind, SignalKind::BackupDestroyed);
        assert_eq!(signal.actor.key, run.key());
        assert_eq!(signal.evidence, "zfs destroyed: zfs destroy tank");
    }
}
