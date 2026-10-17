//! Reads the capture directory, applies the retention policy and deletes what
//! the policy names.
//!
//! The policy itself is in the domain and touches no filesystem; everything
//! here is the part that does. A sweep is deliberately quiet about a file it
//! could not stat or remove: the directory belongs to the agent, but a capture
//! an operator copied away under their own name is not a reason to fail a
//! startup or a capture.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use domain::capture::entity::{CaptureSession, CaptureStatus};
use domain::capture::retention::{CaptureFile, RetentionPolicy};
use tracing::{debug, warn};

/// Where the agent writes capture files. The session id is the file name, so
/// a path here is `<dir>/<id>.pcap` and the directory is what a sweep reads.
pub const CAPTURE_DIR: &str = "/var/lib/ebpfsentinel/captures";

/// What a sweep did, for the one log line that reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Files deleted.
    pub deleted: usize,
    /// Bytes the deleted files occupied.
    pub bytes_freed: u64,
    /// Files the policy named that could not be deleted.
    pub failed: usize,
}

/// The capture files in `dir`, with their age against `now`.
///
/// Only `.pcap` files are listed, because that is what a capture writes and
/// what the session id names: anything else an operator left in the directory
/// is theirs and is not swept.
pub fn capture_files(dir: &Path, now: SystemTime) -> Vec<CaptureFile> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            debug!(dir = %dir.display(), error = %e, "capture directory not readable");
            return Vec::new();
        }
    };

    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("pcap") {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        // A file written in the future, after a clock step, reads as age zero
        // rather than as an enormous age that the sweep would delete at once.
        let age_secs = meta
            .modified()
            .ok()
            .and_then(|m| now.duration_since(m).ok())
            .map_or(0, |d| d.as_secs());
        files.push(CaptureFile {
            path: path.to_string_lossy().into_owned(),
            age_secs,
            size_bytes: meta.len(),
        });
    }
    files
}

/// Apply `policy` to `dir`, keeping the paths in `keep` whatever it says.
pub fn sweep(dir: &Path, policy: &RetentionPolicy, keep: &[String]) -> SweepOutcome {
    let files = capture_files(dir, SystemTime::now());
    let doomed = policy.files_to_delete(&files, keep);
    let sized: Vec<(String, u64)> = files.into_iter().map(|f| (f.path, f.size_bytes)).collect();

    let mut outcome = SweepOutcome::default();
    for path in doomed {
        match fs::remove_file(&path) {
            Ok(()) => {
                outcome.deleted += 1;
                if let Some((_, size)) = sized.iter().find(|(p, _)| p == &path) {
                    outcome.bytes_freed += size;
                }
            }
            Err(e) => {
                outcome.failed += 1;
                warn!(path = %path, error = %e, "capture file not deleted by the retention sweep");
            }
        }
    }
    outcome
}

/// The sessions a restart finds on disk: a file with no session behind it.
///
/// Session state is in memory, so every file written before a restart is one
/// of these. They are listed as `Interrupted` rather than dropped, because the
/// alternative is a short `.pcap` in the directory that the API says nothing
/// about: an operator who finds one needs to be told the agent went down under
/// it. The duration and the filter are gone with the process, and are left at
/// their zero values rather than guessed at.
pub fn orphan_sessions(dir: &Path, known: &[String], now: SystemTime) -> Vec<CaptureSession> {
    let mut sessions: Vec<CaptureSession> = capture_files(dir, now)
        .into_iter()
        .filter_map(|file| {
            let id = PathBuf::from(&file.path)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())?;
            if known.iter().any(|k| k == &id) {
                return None;
            }
            let started_at_ns = now
                .duration_since(SystemTime::UNIX_EPOCH)
                .ok()
                .map(|since| {
                    since
                        .as_nanos()
                        .saturating_sub(u128::from(file.age_secs) * 1_000_000_000)
                })
                .and_then(|ns| u64::try_from(ns).ok())
                .unwrap_or(0);
            Some(CaptureSession {
                id,
                filter: String::new(),
                duration_secs: 0,
                snap_length: 0,
                output_path: file.path,
                interface: String::new(),
                status: CaptureStatus::Interrupted,
                started_at_ns,
                file_size_bytes: file.size_bytes,
                packets_captured: 0,
            })
        })
        .collect();
    sessions.sort_by(|a, b| a.id.cmp(&b.id));
    sessions
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn write(dir: &Path, name: &str, size: usize, age: Duration) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, vec![0u8; size]).expect("test file must be writable");
        let file = fs::File::options()
            .write(true)
            .open(&path)
            .expect("test file must be reopenable");
        let when = SystemTime::now() - age;
        file.set_times(fs::FileTimes::new().set_modified(when))
            .expect("test file mtime must be settable");
        path
    }

    #[test]
    fn only_pcap_files_are_listed() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        write(dir, "cap-1.pcap", 10, Duration::from_secs(0));
        write(dir, "notes.txt", 10, Duration::from_secs(0));

        let files = capture_files(dir, SystemTime::now());

        assert_eq!(files.len(), 1);
        assert!(files[0].path.ends_with("cap-1.pcap"));
        assert_eq!(files[0].size_bytes, 10);
    }

    #[test]
    fn a_missing_directory_is_an_empty_listing() {
        let files = capture_files(
            Path::new("/nonexistent/ebpfsentinel/captures"),
            SystemTime::now(),
        );
        assert!(files.is_empty());
    }

    #[test]
    fn the_sweep_deletes_what_the_policy_names_and_keeps_the_rest() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        let old = write(dir, "cap-old.pcap", 1024, Duration::from_hours(10 * 24));
        let fresh = write(dir, "cap-fresh.pcap", 1024, Duration::from_secs(60));

        let outcome = sweep(dir, &RetentionPolicy::new(7, 0), &[]);

        assert_eq!(outcome.deleted, 1);
        assert_eq!(outcome.bytes_freed, 1024);
        assert_eq!(outcome.failed, 0);
        assert!(!old.exists());
        assert!(fresh.exists());
    }

    #[test]
    fn a_running_capture_file_survives_its_own_age() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        let running = write(dir, "cap-running.pcap", 512, Duration::from_hours(30 * 24));

        let keep = vec![running.to_string_lossy().into_owned()];
        let outcome = sweep(dir, &RetentionPolicy::new(1, 0), &keep);

        assert_eq!(outcome.deleted, 0);
        assert!(running.exists());
    }

    #[test]
    fn a_file_left_by_an_earlier_run_is_adopted_as_interrupted() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let dir = tmp.path();
        write(dir, "cap-gone.pcap", 2048, Duration::from_secs(120));
        write(dir, "cap-known.pcap", 2048, Duration::from_secs(10));

        let sessions = orphan_sessions(dir, &["cap-known".to_string()], SystemTime::now());

        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "cap-gone");
        assert_eq!(sessions[0].status, CaptureStatus::Interrupted);
        assert_eq!(sessions[0].file_size_bytes, 2048);
        assert!(sessions[0].output_path.ends_with("cap-gone.pcap"));
        assert!(
            sessions[0].started_at_ns > 0,
            "the start time is derived from the file, so it is not zero"
        );
    }
}
