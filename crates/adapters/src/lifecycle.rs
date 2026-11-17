//! The run record on disk and the service unit files, read for the domain's
//! lifecycle judgements.

use std::fmt::Write as _;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::lifecycle::{
    EndCause, PreviousRun, RunEnd, RunRecord, UnitEntry, UnitFingerprint, clean_stop_text,
};
use sha2::{Digest, Sha256};

/// The file name the run record is kept under, beside the agent's stores.
pub const RUN_RECORD_FILE: &str = "run.json";

/// Where the kernel names the current boot.
const BOOT_ID_PATH: &str = "/proc/sys/kernel/random/boot_id";

/// The directories systemd reads unit files from, most specific first.
pub const UNIT_DIRECTORIES: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The kernel's identifier for this boot, empty when it cannot be read.
#[must_use]
pub fn boot_id() -> String {
    std::fs::read_to_string(BOOT_ID_PATH).map_or_else(|_| String::new(), |s| s.trim().to_string())
}

/// This run's record: read the previous one, write this one, and complete it
/// when the run ends in order.
#[derive(Debug)]
pub struct RunJournal {
    path: PathBuf,
    record: Mutex<RunRecord>,
}

impl RunJournal {
    /// Read the record at `path`, judge it against `this_boot`, and replace it
    /// with this run's. A record that cannot be written is logged and the
    /// journal carries on in memory: losing it costs the next start's
    /// judgement, never this run.
    #[must_use]
    pub fn open(path: PathBuf, this_boot: &str) -> (Self, PreviousRun) {
        let previous = std::fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RunRecord>(&bytes).ok());
        let judged = PreviousRun::judge(previous, this_boot);
        let journal = Self {
            path,
            record: Mutex::new(RunRecord {
                boot_id: this_boot.to_string(),
                pid: std::process::id(),
                started_at: now_secs(),
                ended: None,
            }),
        };
        journal.persist();
        (journal, judged)
    }

    /// Record how this run ends. The first call wins: a stop command followed
    /// by the signal its own shutdown raises stays a stop command.
    pub fn finish(&self, how: EndCause, requested_by: Option<&str>, reason: Option<&str>) {
        {
            let mut record = self
                .record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if record.ended.is_some() {
                return;
            }
            let clean = |t: Option<&str>| t.map(clean_stop_text).filter(|t| !t.is_empty());
            record.ended = Some(RunEnd {
                at: now_secs(),
                how,
                requested_by: clean(requested_by),
                reason: clean(reason),
            });
        }
        self.persist();
    }

    /// How this run is recorded as ending, if it is.
    #[must_use]
    pub fn ended(&self) -> Option<RunEnd> {
        self.record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ended
            .clone()
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn persist(&self) {
        let json = {
            let record = self
                .record
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            serde_json::to_vec(&*record)
        };
        let written = json
            .map_err(std::io::Error::other)
            .and_then(|json| write_atomic(&self.path, &json));
        if let Err(e) = written {
            tracing::warn!(path = %self.path.display(), error = %e, "the run record could not be written; the next start will not know how this run ended");
        }
    }
}

fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

/// The service unit this process runs under, read off its cgroup, or `None`
/// outside systemd (a container, a shell).
#[must_use]
pub fn own_unit() -> Option<String> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    unit_from_cgroup(&cgroup)
}

/// The `.service` a cgroup file names, read from the unified hierarchy line.
#[must_use]
pub fn unit_from_cgroup(cgroup: &str) -> Option<String> {
    cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .and_then(|path| {
            path.split('/')
                .rev()
                .find(|part| part.ends_with(".service"))
        })
        .map(str::to_string)
}

/// The units to watch for `unit`: itself and its warden, which is named
/// after it (`ebpfsentinel.service` and `ebpfsentinel-warden.service`).
#[must_use]
pub fn watched_units(unit: &str) -> Vec<String> {
    let stem = unit.strip_suffix(".service").unwrap_or(unit);
    vec![unit.to_string(), format!("{stem}-warden.service")]
}

/// Every file under `roots` that defines one of `units`: the unit file in
/// each directory, and every drop-in beside it.
#[must_use]
pub fn unit_fingerprint(roots: &[&Path], units: &[String]) -> UnitFingerprint {
    let mut fingerprint = UnitFingerprint::new();
    for root in roots {
        for unit in units {
            let file = root.join(unit);
            if let Some(entry) = read_entry(&file) {
                fingerprint.insert(file.display().to_string(), entry);
            }
            let dropins = root.join(format!("{unit}.d"));
            if let Ok(dir) = std::fs::read_dir(&dropins) {
                for entry in dir.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "conf")
                        && let Some(read) = read_entry(&path)
                    {
                        fingerprint.insert(path.display().to_string(), read);
                    }
                }
            }
        }
    }
    fingerprint
}

/// The fingerprint under the standard directories.
#[must_use]
pub fn system_unit_fingerprint(units: &[String]) -> UnitFingerprint {
    let roots: Vec<&Path> = UNIT_DIRECTORIES.iter().map(Path::new).collect();
    unit_fingerprint(&roots, units)
}

fn read_entry(path: &Path) -> Option<UnitEntry> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        return Some(if target == Path::new("/dev/null") {
            UnitEntry::Masked
        } else {
            UnitEntry::Link(target.display().to_string())
        });
    }
    if !meta.is_file() {
        return None;
    }
    if meta.len() == 0 {
        // An empty unit file masks it the same way a link to /dev/null does.
        return Some(UnitEntry::Masked);
    }
    let bytes = std::fs::read(path).ok()?;
    let digest = Sha256::digest(&bytes);
    let hex = digest.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    });
    Some(UnitEntry::File(hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_is_read_off_the_unified_cgroup_line() {
        assert_eq!(
            unit_from_cgroup("0::/system.slice/ebpfsentinel.service\n").as_deref(),
            Some("ebpfsentinel.service")
        );
        assert_eq!(
            unit_from_cgroup("0::/system.slice/ebpfsentinel.service/agent\n").as_deref(),
            Some("ebpfsentinel.service")
        );
        assert_eq!(unit_from_cgroup("0::/user.slice/session-3.scope\n"), None);
        assert_eq!(unit_from_cgroup("0::/\n"), None);
    }

    #[test]
    fn the_warden_is_watched_beside_the_agent() {
        assert_eq!(
            watched_units("ebpfsentinel-enterprise.service"),
            vec![
                "ebpfsentinel-enterprise.service".to_string(),
                "ebpfsentinel-enterprise-warden.service".to_string()
            ]
        );
    }

    #[test]
    fn a_mask_a_dropin_and_an_edit_are_seen() {
        let dir = tempfile::tempdir().expect("dir");
        let etc = dir.path().join("etc");
        let lib = dir.path().join("lib");
        std::fs::create_dir_all(&etc).expect("etc");
        std::fs::create_dir_all(&lib).expect("lib");
        std::fs::write(lib.join("a.service"), "[Service]\nRestart=always\n").expect("unit");
        let units = vec!["a.service".to_string()];
        let roots = [etc.as_path(), lib.as_path()];
        let before = unit_fingerprint(&roots, &units);
        assert_eq!(before.len(), 1);

        std::os::unix::fs::symlink("/dev/null", etc.join("a.service")).expect("mask");
        std::fs::create_dir_all(etc.join("a.service.d")).expect("dropin dir");
        std::fs::write(etc.join("a.service.d/x.conf"), "[Service]\nRestart=no\n").expect("drop");
        std::fs::write(etc.join("a.service.d/ignored.txt"), "x").expect("ignored");
        let after = unit_fingerprint(&roots, &units);
        let tamper = after.compare(&before).expect("tamper");
        assert_eq!(tamper.masked.len(), 1);
        assert_eq!(tamper.added.len(), 1);

        std::fs::remove_file(etc.join("a.service")).expect("unmask");
        std::fs::write(lib.join("a.service"), "[Service]\nRestart=no\n").expect("edit");
        let edited = unit_fingerprint(&roots, &units);
        let tamper = edited.compare(&after).expect("tamper");
        assert_eq!(tamper.changed.len(), 1);
        assert_eq!(tamper.removed.len(), 1);
    }

    #[test]
    fn the_journal_judges_the_last_run_and_keeps_the_first_end() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("state").join(RUN_RECORD_FILE);
        let (first, previous) = RunJournal::open(path.clone(), "boot-1");
        assert_eq!(previous, PreviousRun::Unknown);
        drop(first);
        // A run that never finished its record is unrecorded on this boot.
        let (second, previous) = RunJournal::open(path.clone(), "boot-1");
        assert!(matches!(
            previous,
            PreviousRun::Unrecorded {
                same_boot: true,
                ..
            }
        ));
        second.finish(EndCause::Command, Some("ops"), Some("upgrade\n"));
        second.finish(EndCause::Signal, None, None);
        assert_eq!(second.ended().map(|e| e.how), Some(EndCause::Command));
        let (_third, previous) = RunJournal::open(path, "boot-1");
        let PreviousRun::Commanded(end) = previous else {
            panic!("expected a commanded stop, got {previous:?}");
        };
        assert_eq!(end.reason.as_deref(), Some("upgrade"));
        assert_eq!(end.requested_by.as_deref(), Some("ops"));
    }
}
