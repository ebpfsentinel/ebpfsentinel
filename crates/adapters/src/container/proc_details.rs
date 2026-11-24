use std::path::{Path, PathBuf};

use domain::process::command_line;
use domain::process::entity::ProcessDetails;
use ports::secondary::process_details_port::ProcessDetailsReader;

/// Reads a process's parent and command line from `/proc`.
///
/// The proc root is configurable for the same reason the executable resolver's
/// is: an agent holding the host procfs at `/host/proc` must describe the
/// node's processes rather than its own container's.
pub struct ProcDetailsResolver {
    proc_root: PathBuf,
}

impl ProcDetailsResolver {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    /// Convenience constructor that defaults to `/proc`.
    pub fn with_default_proc() -> Self {
        Self::new(Path::new("/proc"))
    }

    pub fn proc_path(&self) -> &Path {
        &self.proc_root
    }
}

impl ProcessDetailsReader for ProcDetailsResolver {
    fn read_details(&self, pid: u32) -> Option<ProcessDetails> {
        let dir = self.proc_root.join(pid.to_string());
        // `status` rather than `stat` for the parent: a comm containing a
        // space or a bracket turns the positional fields of `stat` into a
        // parsing puzzle, and the keyed file has no such ambiguity.
        let parent_pid = std::fs::read_to_string(dir.join("status"))
            .ok()
            .and_then(|status| parse_parent_pid(&status));
        let command_line = std::fs::read(dir.join("cmdline"))
            .ok()
            .and_then(|raw| command_line::from_argv(&raw, false));
        if parent_pid.is_none() && command_line.is_none() {
            return None;
        }
        Some(ProcessDetails {
            parent_pid,
            command_line,
        })
    }
}

/// The `PPid:` line of `/proc/<pid>/status`.
#[must_use]
pub fn parse_parent_pid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|value| value.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn fake_proc(pid: u32, status: &str, cmdline: &[u8]) -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let pid_dir = dir.path().join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("status"), status).unwrap();
        fs::write(pid_dir.join("cmdline"), cmdline).unwrap();
        dir
    }

    #[test]
    fn the_parent_comes_off_the_keyed_line() {
        let status = "Name:\tcurl\nState:\tS (sleeping)\nTgid:\t42\nPid:\t42\nPPid:\t1\n";
        assert_eq!(parse_parent_pid(status), Some(1));
    }

    #[test]
    fn a_status_without_a_parent_yields_nothing() {
        assert_eq!(parse_parent_pid("Name:\tcurl\n"), None);
    }

    #[test]
    fn a_live_pid_resolves_to_both_halves() {
        let dir = fake_proc(42, "Name:\tcurl\nPPid:\t7\n", b"curl\0-s\0");
        let resolver = ProcDetailsResolver::new(dir.path());
        let details = resolver.read_details(42).unwrap();
        assert_eq!(details.parent_pid, Some(7));
        assert_eq!(details.command_line.as_deref(), Some("curl -s"));
    }

    #[test]
    fn a_pid_that_is_gone_resolves_to_nothing() {
        let dir = tempdir().unwrap();
        let resolver = ProcDetailsResolver::new(dir.path());
        assert!(resolver.read_details(42).is_none());
        assert_eq!(resolver.proc_path(), dir.path());
    }
}
