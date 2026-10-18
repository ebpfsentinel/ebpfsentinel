use std::path::{Path, PathBuf};

use domain::process::entity::ProcessDetails;
use ports::secondary::process_details_port::ProcessDetailsReader;

/// How much of `/proc/<pid>/cmdline` is read.
///
/// argv is not bounded by the kernel at any size an agent wants to hold per
/// process, and a table of a few thousand entries holding a megabyte each is
/// the memory bug this bound exists to prevent. What is kept is the start of
/// the line, which is the part that names the program and its first
/// arguments; the cut is marked so nobody reads a truncated command as the
/// whole one.
pub const MAX_COMMAND_LINE: usize = 4096;

/// The marker appended where argv was longer than the bound.
pub const TRUNCATION_MARKER: &str = " ...";

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
            .and_then(|raw| parse_command_line(&raw));
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

/// argv as `/proc/<pid>/cmdline` holds it: NUL-separated, NUL-terminated.
///
/// Returns `None` for an empty file, which is what a kernel thread has: it
/// never execed anything, so it has no command line rather than an empty one.
#[must_use]
pub fn parse_command_line(raw: &[u8]) -> Option<String> {
    let mut joined = String::new();
    for argument in raw.split(|byte| *byte == 0) {
        if argument.is_empty() {
            continue;
        }
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(&String::from_utf8_lossy(argument));
        if joined.len() >= MAX_COMMAND_LINE {
            break;
        }
    }
    if joined.is_empty() {
        return None;
    }
    if joined.len() > MAX_COMMAND_LINE {
        // Cut on a character boundary: argv is bytes and the lossy decode
        // above can land a multi-byte character across the bound.
        let mut cut = MAX_COMMAND_LINE;
        while cut > 0 && !joined.is_char_boundary(cut) {
            cut -= 1;
        }
        joined.truncate(cut);
        joined.push_str(TRUNCATION_MARKER);
    }
    Some(joined)
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
    fn argv_is_joined_with_single_spaces() {
        let raw = b"curl\0-s\0https://example.test\0";
        assert_eq!(
            parse_command_line(raw).as_deref(),
            Some("curl -s https://example.test")
        );
    }

    #[test]
    fn a_kernel_thread_has_no_command_line_rather_than_an_empty_one() {
        assert_eq!(parse_command_line(b""), None);
        assert_eq!(parse_command_line(b"\0\0\0"), None);
    }

    #[test]
    fn a_long_argv_is_cut_and_says_so() {
        let mut raw = Vec::new();
        for _ in 0..1000 {
            raw.extend_from_slice(b"argument-of-some-length\0");
        }
        let line = parse_command_line(&raw).unwrap();
        assert!(line.ends_with(TRUNCATION_MARKER));
        assert!(line.len() <= MAX_COMMAND_LINE + TRUNCATION_MARKER.len());
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
