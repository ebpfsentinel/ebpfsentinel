//! The work a busy host does every day, replayed against the mass encryption
//! verdict in force. Each workload is shaped the way the file watcher and the
//! crypto probe report it, at the volume and pace of a large run, and each
//! reaches one or more of the signals on purpose: none of them may reach a
//! verdict, alone or one after another under the same session. The last test
//! runs an encryption through the same harness, so a corpus that raises
//! nothing is a corpus the engine was listening to.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use application::alert_event::AlertEvent;
use application::ransom_service::{FileRewrite, HostSourcesReader, RansomService};
use domain::file_watch::entity::FileChangeKind;
use domain::firewall::entity::RuleMode;
use domain::hostrule::{HostSources, Source};
use domain::process::engine::Lineage;
use domain::process::entity::{ProcessEntry, ProcessIdentity};
use domain::ransom::{
    RANSOM_CRYPTO_CALLS, RANSOM_DISTINCT_REWRITES, RANSOM_MASS_RENAMES, RANSOM_NOTE_DIRECTORIES,
    RANSOM_REPLACEMENTS,
};
use tokio::sync::mpsc;

/// Five milliseconds between two changes: a run of thousands of files fits
/// in one window, which is the hardest case for every counter.
const STEP_NS: u64 = 5_000_000;

/// Volumes well past every threshold, so a workload that stays quiet does so
/// for its shape and not for its size.
const MANY: usize = 3 * RANSOM_DISTINCT_REWRITES;
const DIRECTORIES: usize = 3 * RANSOM_NOTE_DIRECTORIES;

const PDF: [u8; 4] = *b"%PDF";
const PNG: [u8; 4] = *b"\x89PNG";
const GZIP: [u8; 4] = *b"\x1F\x8B\x08\x00";
const FLAC: [u8; 4] = *b"fLaC";
const OGG: [u8; 4] = *b"OggS";
const SQLITE: [u8; 4] = *b"SQLi";

/// Entropy of text, of a database page and of compressed data, in millibits.
const TEXT: u16 = 4_800;
const PAGES: u16 = 3_100;
const PACKED: u16 = 7_960;

struct Proc {
    entry: ProcessEntry,
    lineage: Lineage,
}

fn inode(exe: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    exe.hash(&mut hasher);
    hasher.finish()
}

#[derive(Default)]
struct Change {
    path: String,
    before: Option<u16>,
    now: Option<u16>,
    head: Option<[u8; 4]>,
    from: Option<String>,
    size_before: Option<u64>,
    size_now: Option<u64>,
    fresh: bool,
}

struct Host {
    service: RansomService,
    alerts: mpsc::Receiver<AlertEvent>,
    clock: u64,
    next_pid: u32,
}

impl Host {
    fn new() -> Self {
        let (tx, alerts) = mpsc::channel(64);
        let sources: HostSourcesReader = Arc::new(|| {
            HostSources::new(Some((6, 12)))
                .present(Source::ProcessTracing)
                .present(Source::FileWatch)
        });
        let service = RansomService::new(tx, sources)
            .with_command_lines(true)
            .with_mode(RuleMode::Enforce);
        Self {
            service,
            alerts,
            clock: 1_000_000_000_000,
            next_pid: 1_000,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += STEP_NS;
        self.clock
    }

    /// `exe` started by `parent` with `command_line`, recorded the way the
    /// process table records an exec.
    fn spawn(&mut self, parent: Option<&Proc>, exe: &str, command_line: &str) -> Proc {
        self.next_pid += 1;
        let pid = self.next_pid;
        let mut entry = ProcessEntry::new(pid, "p", u64::from(pid));
        entry.start_ns = Some(u64::from(pid));
        entry.identity = ProcessIdentity::Path {
            path: exe.to_string(),
            dev: 8,
            inode: inode(exe),
        };
        entry.command_line = Some(command_line.to_string());
        let mut ancestors = Vec::new();
        if let Some(parent) = parent {
            ancestors.push(parent.entry.clone());
            ancestors.extend(parent.lineage.ancestors.iter().cloned());
        }
        let lineage = Lineage {
            ancestors,
            truncated: false,
            incomplete: false,
        };
        let at = self.tick();
        self.service.record_exec(&entry, &lineage, at);
        Proc { entry, lineage }
    }

    fn change(&mut self, by: &Proc, kinds: &[FileChangeKind], change: &Change) {
        let at = self.tick();
        self.service.record_file_change(
            &by.entry,
            &by.lineage,
            kinds.iter().copied(),
            FileRewrite {
                path: &change.path,
                entropy_before: change.before,
                entropy_now: change.now,
                head: change.head,
                renamed_from: change.from.as_deref(),
                size_before: change.size_before,
                size_now: change.size_now,
                written_now: change.fresh,
            },
            at,
        );
    }

    fn calls(&mut self, by: &Proc, calls: u64) {
        let at = self.tick();
        self.service
            .record_crypto_calls(&by.entry, &by.lineage, calls, at);
    }

    #[track_caller]
    fn quiet(&mut self, workload: &str) {
        let reached = match self.alerts.try_recv() {
            Ok(AlertEvent::ProcessDetection { alert, .. }) => Some(alert.message),
            _ => None,
        };
        assert!(
            reached.is_none(),
            "{workload} reached a verdict: {reached:?}"
        );
    }
}

fn session(host: &mut Host) -> Proc {
    let sshd = host.spawn(None, "/usr/sbin/sshd", "sshd: admin [priv]");
    host.spawn(Some(&sshd), "/usr/bin/bash", "-bash")
}

const CREATED: &[FileChangeKind] = &[FileChangeKind::Created];
const WRITTEN: &[FileChangeKind] = &[FileChangeKind::Written];
const MOVED_IN: &[FileChangeKind] = &[FileChangeKind::MovedIn];
const DELETED: &[FileChangeKind] = &[FileChangeKind::Deleted];

/// A document of the kind a file server holds, with the head it carries.
fn document(n: usize) -> (String, Option<[u8; 4]>, u16) {
    match n % 4 {
        0 => (format!("report{n}.pdf"), Some(PDF), PACKED),
        1 => (format!("scan{n}.png"), Some(PNG), PACKED),
        2 => (format!("notes{n}.txt"), None, TEXT),
        _ => (format!("export{n}.csv.gz"), Some(GZIP), PACKED),
    }
}

/// `rsync -a` of a file tree onto a copy of it: each changed file is written
/// under a hidden temporary beside it and renamed over the old one, keeping
/// the source's modification time.
fn rsync_archive(host: &mut Host, shell: &Proc) {
    let rsync = host.spawn(
        Some(shell),
        "/usr/bin/rsync",
        "rsync -a /srv/data/ /mnt/copy/",
    );
    for n in 0..MANY {
        let (name, head, entropy) = document(n);
        let dir = format!("/mnt/copy/d{}", n % DIRECTORIES);
        let temp = format!("{dir}/.{name}.Xa9b2c");
        host.change(
            &rsync,
            CREATED,
            &Change {
                path: temp.clone(),
                now: Some(entropy),
                head,
                size_now: Some(40_000),
                ..Change::default()
            },
        );
        host.change(
            &rsync,
            MOVED_IN,
            &Change {
                path: format!("{dir}/{name}"),
                before: Some(entropy),
                now: Some(entropy),
                head,
                from: Some(temp),
                size_before: Some(39_800),
                size_now: Some(40_000),
                ..Change::default()
            },
        );
    }
}

/// `tar -xf` of a source tree: thousands of new files with the archive's
/// modification times, documentation pages in every directory, a message
/// catalogue in every locale and a build file in every directory.
fn tar_extraction(host: &mut Host, shell: &Proc) {
    let tar = host.spawn(Some(shell), "/usr/bin/tar", "tar -xf linux-6.12.tar.xz");
    for n in 0..MANY {
        let (name, head, entropy) = document(n);
        host.change(
            &tar,
            CREATED,
            &Change {
                path: format!("/usr/src/linux/d{}/{name}", n % DIRECTORIES),
                now: Some(entropy),
                head,
                size_now: Some(12_000),
                ..Change::default()
            },
        );
    }
    for dir in 0..DIRECTORIES {
        for name in ["Kconfig", "Makefile", "index.html", "README.md"] {
            host.change(
                &tar,
                CREATED,
                &Change {
                    path: format!("/usr/src/linux/d{dir}/{name}"),
                    now: Some(TEXT),
                    size_now: Some(900),
                    ..Change::default()
                },
            );
        }
        host.change(
            &tar,
            CREATED,
            &Change {
                path: format!("/usr/src/linux/po/l{dir}/LC_MESSAGES/linux.mo"),
                now: Some(TEXT),
                size_now: Some(30_000),
                ..Change::default()
            },
        );
    }
}

/// `apt upgrade` over HTTPS: the transport encrypting a request for every
/// package it writes into the cache, then `dpkg` unpacking every file under
/// its own name and renaming it over the installed one, a catalogue in every
/// locale and a changelog per package among them.
fn package_upgrade(host: &mut Host, shell: &Proc) {
    let apt = host.spawn(Some(shell), "/usr/bin/apt", "apt upgrade -y");
    let https = host.spawn(Some(&apt), "/usr/lib/apt/methods/https", "https");
    host.calls(&https, 1);
    for n in 0..MANY {
        host.change(
            &https,
            CREATED,
            &Change {
                path: format!("/var/cache/apt/archives/partial/p{n}.deb"),
                now: Some(PACKED),
                size_now: Some(800_000),
                fresh: true,
                ..Change::default()
            },
        );
        host.calls(&https, 4);
        host.change(
            &https,
            MOVED_IN,
            &Change {
                path: format!("/var/cache/apt/archives/p{n}.deb"),
                now: Some(PACKED),
                from: Some(format!("/var/cache/apt/archives/partial/p{n}.deb")),
                size_now: Some(800_000),
                fresh: true,
                ..Change::default()
            },
        );
    }
    let dpkg = host.spawn(Some(&apt), "/usr/bin/dpkg", "/usr/bin/dpkg --unpack");
    let installed = (0..DIRECTORIES)
        .map(|n| {
            (
                format!("/usr/share/locale/l{n}/LC_MESSAGES/coreutils.mo"),
                None,
                TEXT,
            )
        })
        .chain((0..DIRECTORIES).map(|n| {
            (
                format!("/usr/share/doc/p{n}/changelog.Debian.gz"),
                Some(GZIP),
                PACKED,
            )
        }))
        .chain((0..MANY).map(|n| {
            (
                format!("/usr/lib/python3/dist-packages/pkg/m{n}.py"),
                None,
                TEXT,
            )
        }));
    for (path, head, entropy) in installed {
        let unpacked = format!("{path}.dpkg-new");
        host.change(
            &dpkg,
            CREATED,
            &Change {
                path: unpacked.clone(),
                now: Some(entropy),
                head,
                size_now: Some(20_400),
                ..Change::default()
            },
        );
        host.change(
            &dpkg,
            MOVED_IN,
            &Change {
                path,
                before: Some(entropy),
                now: Some(entropy),
                head,
                from: Some(unpacked),
                size_before: Some(20_000),
                size_now: Some(20_400),
                ..Change::default()
            },
        );
    }
    // The same transaction as `rpm` writes it, under a suffix of its own.
    let rpm = host.spawn(Some(shell), "/usr/bin/rpm", "rpm -Uvh *.rpm");
    for n in 0..MANY {
        let path = format!(
            "/usr/lib64/python3/site-packages/q{}/m{n}.py",
            n % DIRECTORIES
        );
        host.change(
            &rpm,
            MOVED_IN,
            &Change {
                path: path.clone(),
                before: Some(TEXT),
                now: Some(TEXT),
                from: Some(format!("{path};65a1b2c3")),
                size_before: Some(8_000),
                size_now: Some(8_100),
                ..Change::default()
            },
        );
    }
}

/// `git checkout` across a large tree: every tracked file rewritten in place
/// with this moment's modification time, the build files and readmes of
/// every directory among them, and the index swapped under its lock.
fn git_checkout(host: &mut Host, shell: &Proc) {
    let git = host.spawn(Some(shell), "/usr/bin/git", "git checkout v6.12");
    for n in 0..MANY {
        let (name, head, entropy) = document(n);
        host.change(
            &git,
            WRITTEN,
            &Change {
                path: format!("/home/admin/linux/d{}/{name}", n % DIRECTORIES),
                before: Some(entropy),
                now: Some(entropy),
                head,
                size_before: Some(6_000),
                size_now: Some(6_200),
                fresh: true,
                ..Change::default()
            },
        );
    }
    for dir in 0..DIRECTORIES {
        for name in ["Makefile", "Kconfig", "README.md", ".gitignore"] {
            host.change(
                &git,
                CREATED,
                &Change {
                    path: format!("/home/admin/linux/d{dir}/{name}"),
                    now: Some(TEXT),
                    size_now: Some(700),
                    fresh: true,
                    ..Change::default()
                },
            );
        }
    }
    host.change(
        &git,
        MOVED_IN,
        &Change {
            path: "/home/admin/linux/.git/index".into(),
            from: Some("/home/admin/linux/.git/index.lock".into()),
            size_before: Some(9_000_000),
            size_now: Some(9_100_000),
            fresh: true,
            ..Change::default()
        },
    );
}

/// `updatedb`: the whole database written under a temporary name and renamed
/// over the last one.
fn updatedb(host: &mut Host, shell: &Proc) {
    let updatedb = host.spawn(Some(shell), "/usr/sbin/updatedb.plocate", "updatedb");
    host.change(
        &updatedb,
        MOVED_IN,
        &Change {
            path: "/var/lib/plocate/plocate.db".into(),
            before: Some(PACKED),
            now: Some(PACKED),
            from: Some("/var/lib/plocate/plocate.db.XXXXa1".into()),
            size_before: Some(48_000_000),
            size_now: Some(48_200_000),
            fresh: true,
            ..Change::default()
        },
    );
}

/// `logrotate` over many services: the oldest generation removed, each one
/// shifted, the newest set aside under the day it was rotated, the one
/// before compressed beside itself and removed, and the live log truncated.
fn log_rotation(host: &mut Host, shell: &Proc) {
    let logrotate = host.spawn(
        Some(shell),
        "/usr/sbin/logrotate",
        "logrotate /etc/logrotate.conf",
    );
    for n in 0..MANY {
        let log = format!("/var/log/app{n}/app.log");
        host.change(
            &logrotate,
            DELETED,
            &Change {
                path: format!("{log}.4.gz"),
                size_before: Some(90_000),
                ..Change::default()
            },
        );
        for generation in (1..4).rev() {
            host.change(
                &logrotate,
                MOVED_IN,
                &Change {
                    path: format!("{log}.{}.gz", generation + 1),
                    now: Some(PACKED),
                    head: Some(GZIP),
                    from: Some(format!("{log}.{generation}.gz")),
                    size_now: Some(90_000),
                    ..Change::default()
                },
            );
        }
        host.change(
            &logrotate,
            MOVED_IN,
            &Change {
                path: format!("{log}-20261101"),
                now: Some(TEXT),
                from: Some(log.clone()),
                size_now: Some(900_000),
                ..Change::default()
            },
        );
        host.change(
            &logrotate,
            CREATED,
            &Change {
                path: format!("{log}-20261031.gz"),
                now: Some(PACKED),
                head: Some(GZIP),
                size_now: Some(90_000),
                fresh: true,
                ..Change::default()
            },
        );
        host.change(
            &logrotate,
            DELETED,
            &Change {
                path: format!("{log}-20261031"),
                size_before: Some(900_000),
                ..Change::default()
            },
        );
        host.change(
            &logrotate,
            WRITTEN,
            &Change {
                path: log,
                before: Some(TEXT),
                size_before: Some(1_200),
                size_now: Some(0),
                fresh: true,
                ..Change::default()
            },
        );
    }
}

/// A media encoder over a library: compressed audio and video written beside
/// their sources and over the last encode, and artwork left in every album.
fn media_encoder(host: &mut Host, shell: &Proc) {
    let ffmpeg = host.spawn(
        Some(shell),
        "/usr/bin/ffmpeg",
        "ffmpeg -y -i in.wav out.flac",
    );
    for n in 0..MANY {
        let album = format!("/srv/media/a{}", n % DIRECTORIES);
        let (name, head) = match n % 3 {
            0 => (format!("t{n}.flac"), Some(FLAC)),
            1 => (format!("t{n}.ogg"), Some(OGG)),
            _ => (format!("t{n}.mp4"), None),
        };
        host.change(
            &ffmpeg,
            WRITTEN,
            &Change {
                path: format!("{album}/{name}"),
                before: Some(PACKED),
                now: Some(7_990),
                head,
                size_before: Some(30_000_000),
                size_now: Some(30_400_000),
                fresh: true,
                ..Change::default()
            },
        );
    }
    let beets = host.spawn(Some(shell), "/usr/bin/beet", "beet fetchart");
    for dir in 0..DIRECTORIES {
        host.change(
            &beets,
            CREATED,
            &Change {
                path: format!("/srv/media/a{dir}/cover.jpg"),
                now: Some(PACKED),
                head: Some(*b"\xFF\xD8\xFF\xE0"),
                size_now: Some(200_000),
                fresh: true,
                ..Change::default()
            },
        );
    }
}

/// Database compaction: a `SQLite` vacuum through its journal, `PostgreSQL`
/// rewriting every relation into a new file and dropping the old one, and a
/// column store merging parts, each part a directory of the same files.
fn database_compaction(host: &mut Host, shell: &Proc) {
    let sqlite = host.spawn(Some(shell), "/usr/bin/sqlite3", "sqlite3 app.sqlite VACUUM");
    for n in 0..RANSOM_REPLACEMENTS * 2 {
        let db = format!("/var/lib/app{n}/app.sqlite");
        host.change(
            &sqlite,
            CREATED,
            &Change {
                path: format!("{db}-journal"),
                now: Some(PAGES),
                size_now: Some(4_096_000),
                fresh: true,
                ..Change::default()
            },
        );
        host.change(
            &sqlite,
            WRITTEN,
            &Change {
                path: db.clone(),
                before: Some(PAGES),
                now: Some(PAGES),
                head: Some(SQLITE),
                size_before: Some(4_096_000),
                size_now: Some(3_000_000),
                fresh: true,
                ..Change::default()
            },
        );
        host.change(
            &sqlite,
            DELETED,
            &Change {
                path: format!("{db}-journal"),
                size_before: Some(4_096_000),
                ..Change::default()
            },
        );
    }
    let postgres = host.spawn(
        None,
        "/usr/lib/postgresql/17/bin/postgres",
        "postgres: autovacuum",
    );
    for n in 0..MANY {
        host.change(
            &postgres,
            CREATED,
            &Change {
                path: format!("/var/lib/postgresql/17/main/base/16384/{}", 90_000 + n),
                now: Some(PAGES),
                size_now: Some(8_192_000),
                fresh: true,
                ..Change::default()
            },
        );
        host.change(
            &postgres,
            DELETED,
            &Change {
                path: format!("/var/lib/postgresql/17/main/base/16384/{}", 20_000 + n),
                size_before: Some(9_000_000),
                ..Change::default()
            },
        );
    }
    let clickhouse = host.spawn(None, "/usr/bin/clickhouse", "clickhouse-server");
    for part in 0..DIRECTORIES {
        let dir = format!("/var/lib/clickhouse/store/a1b/events/all_1_{part}_1");
        for name in [
            "data.bin",
            "primary.idx",
            "columns.txt",
            "checksums.txt",
            "count.txt",
        ] {
            host.change(
                &clickhouse,
                CREATED,
                &Change {
                    path: format!("{dir}/{name}"),
                    now: Some(if name == "data.bin" { 7_990 } else { TEXT }),
                    size_now: Some(1_000_000),
                    fresh: true,
                    ..Change::default()
                },
            );
        }
    }
}

/// A backup job as `borgmatic` runs it: the repository pruned, then a new
/// archive written into it encrypted through the system library.
fn backup_job(host: &mut Host) {
    let cron = host.spawn(None, "/usr/sbin/cron", "/usr/sbin/cron -f");
    let borgmatic = host.spawn(Some(&cron), "/usr/bin/python3.12", "/usr/bin/borgmatic");
    host.spawn(
        Some(&borgmatic),
        "/usr/bin/borg",
        "borg prune --keep-daily 7 /backup/repo",
    );
    let borg = host.spawn(
        Some(&borgmatic),
        "/usr/bin/borg",
        "borg create /backup/repo::{now} /srv",
    );
    host.calls(&borg, 1);
    for n in 0..MANY {
        host.calls(&borg, RANSOM_CRYPTO_CALLS);
        host.change(
            &borg,
            CREATED,
            &Change {
                path: format!("/backup/repo/data/{}/{n}", n / 100),
                now: Some(7_990),
                size_now: Some(500_000_000),
                fresh: true,
                ..Change::default()
            },
        );
    }
    // Compaction rewrites the segments it keeps.
    let compact = host.spawn(
        Some(&borgmatic),
        "/usr/bin/borg",
        "borg compact /backup/repo",
    );
    for n in 0..MANY {
        host.calls(&compact, RANSOM_CRYPTO_CALLS);
        host.change(
            &compact,
            WRITTEN,
            &Change {
                path: format!("/backup/repo/data/{}/{n}", n / 100),
                before: Some(7_990),
                now: Some(7_990),
                size_before: Some(500_000_000),
                size_now: Some(500_000_000),
                fresh: true,
                ..Change::default()
            },
        );
    }
}

/// An administrator pruning snapshots and backups from their own shell.
fn snapshot_prune(host: &mut Host, shell: &Proc) {
    for line in [
        "zfs destroy -r tank@auto-2026-10-01",
        "btrfs subvolume delete /.snapshots/12/snapshot",
        "snapper delete 10-20",
        "restic -r /backup forget --keep-last 5 --prune",
        "systemctl stop restic-backup.timer",
    ] {
        let program = line.split_whitespace().next().unwrap_or(line);
        host.spawn(Some(shell), &format!("/usr/bin/{program}"), line);
    }
}

fn each_alone(workload: fn(&mut Host, &Proc), name: &str) {
    let mut host = Host::new();
    let shell = session(&mut host);
    workload(&mut host, &shell);
    host.quiet(name);
}

#[test]
fn rsync_raises_nothing() {
    each_alone(rsync_archive, "rsync -a");
}

#[test]
fn a_tar_extraction_raises_nothing() {
    each_alone(tar_extraction, "tar -xf");
}

#[test]
fn a_package_upgrade_raises_nothing() {
    each_alone(package_upgrade, "a package upgrade");
}

#[test]
fn a_git_checkout_of_a_large_tree_raises_nothing() {
    each_alone(git_checkout, "git checkout");
}

#[test]
fn updatedb_raises_nothing() {
    each_alone(updatedb, "updatedb");
}

#[test]
fn log_rotation_raises_nothing() {
    each_alone(log_rotation, "logrotate");
}

#[test]
fn a_media_encoder_raises_nothing() {
    each_alone(media_encoder, "a media encoder");
}

#[test]
fn a_database_compaction_raises_nothing() {
    each_alone(database_compaction, "a database compaction");
}

#[test]
fn a_backup_job_raises_nothing() {
    let mut host = Host::new();
    backup_job(&mut host);
    host.quiet("a backup job");
}

#[test]
fn an_administrator_pruning_snapshots_raises_nothing() {
    each_alone(snapshot_prune, "pruning snapshots");
}

/// The whole corpus one after another, from one administrator's shell that
/// has just pruned its snapshots, so every workload runs under that prior.
#[test]
fn the_whole_corpus_after_a_prune_raises_nothing() {
    let mut host = Host::new();
    let shell = session(&mut host);
    snapshot_prune(&mut host, &shell);
    for (workload, name) in [
        (rsync_archive as fn(&mut Host, &Proc), "rsync -a"),
        (tar_extraction, "tar -xf"),
        (package_upgrade, "a package upgrade"),
        (git_checkout, "git checkout"),
        (updatedb, "updatedb"),
        (log_rotation, "logrotate"),
        (media_encoder, "a media encoder"),
        (database_compaction, "a database compaction"),
    ] {
        workload(&mut host, &shell);
        host.quiet(name);
    }
    backup_job(&mut host);
    host.quiet("a backup job");
    assert_eq!(host.service.shadow().reading.events, 0);
}

/// The control: in the same session, after the same prune, a program
/// writing every document back under a new extension is raised, by the
/// shape of the write and against that prior.
#[test]
fn an_encryption_in_the_same_session_is_raised() {
    let mut host = Host::new();
    let shell = session(&mut host);
    snapshot_prune(&mut host, &shell);
    git_checkout(&mut host, &shell);
    host.quiet("git checkout");
    let run = host.spawn(Some(&shell), "/tmp/.x/update", "./update");
    for n in 0..RANSOM_MASS_RENAMES {
        let (name, _, _) = document(n);
        host.change(
            &run,
            MOVED_IN,
            &Change {
                path: format!("/srv/data/d{n}/{name}.lockd"),
                before: Some(TEXT),
                now: Some(7_990),
                from: Some(format!("/srv/data/d{n}/{name}")),
                size_before: Some(40_000),
                size_now: Some(40_016),
                fresh: true,
                ..Change::default()
            },
        );
    }
    let Ok(AlertEvent::ProcessDetection { alert, .. }) = host.alerts.try_recv() else {
        panic!("the control raised nothing");
    };
    assert!(
        alert.message.contains("/tmp/.x/update"),
        "{}",
        alert.message
    );
    assert!(
        alert.message.contains("backup_destroyed"),
        "{}",
        alert.message
    );
}
