//! Naming the executable a process runs.
//!
//! `/proc/<pid>/exe` is guarded by a ptrace access check, which a task in the
//! agent's user namespace fails against every process outside it, so the
//! rootless agent cannot name a single binary on the host. The warden runs in
//! the initial user namespace and answers for it: a readlink and a stat, nothing
//! from the process's memory or environment.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ebpfsentinel_warden_proto::ExecutableIdentity;

/// Suffix the kernel appends to the link once the binary has been unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// The executable behind `pid` in the procfs at `proc_root`, or `None` when the
/// process is gone or its link cannot be read.
///
/// The path comes from the link and the `(dev, ino)` pair from a stat through
/// the same link, so both describe one file even when the binary was replaced
/// since. A deleted binary has no file left behind its name and answers `None`.
pub fn read_executable(proc_root: &Path, pid: u32) -> Option<ExecutableIdentity> {
    let link = proc_root.join(pid.to_string()).join("exe");
    let target = std::fs::read_link(&link).ok()?;
    let path = target.to_string_lossy();
    let path = path.strip_suffix(DELETED_SUFFIX).unwrap_or(path.as_ref());
    if path.is_empty() {
        return None;
    }
    let meta = std::fs::metadata(&link).ok()?;
    Some(ExecutableIdentity {
        path: path.to_owned(),
        dev: meta.dev(),
        ino: meta.ino(),
    })
}

#[cfg(test)]
mod tests {
    use super::read_executable;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    /// A fake procfs holding one `exe` link to a real file, the target
    /// suffixed with `suffix` the way the kernel marks a deleted binary.
    fn fake_proc(pid: u32, suffix: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let binary = dir.path().join("binary");
        fs::write(&binary, b"\x7fELF").expect("write binary");
        let pid_dir = dir.path().join("proc").join(pid.to_string());
        fs::create_dir_all(&pid_dir).expect("pid dir");
        let mut target = binary.clone().into_os_string();
        target.push(suffix);
        std::os::unix::fs::symlink(&target, pid_dir.join("exe")).expect("exe link");
        let root = dir.path().join("proc");
        (dir, root, binary)
    }

    #[test]
    fn names_the_file_behind_the_link() {
        let (_dir, root, binary) = fake_proc(4242, "");
        let exe = read_executable(&root, 4242).expect("a live pid resolves");
        let meta = fs::metadata(&binary).expect("stat binary");
        assert_eq!(exe.path, binary.to_string_lossy());
        assert_eq!((exe.dev, exe.ino), (meta.dev(), meta.ino()));
    }

    #[test]
    fn a_deleted_binary_answers_nothing() {
        let (_dir, root, _binary) = fake_proc(4243, " (deleted)");
        assert!(read_executable(&root, 4243).is_none());
    }

    #[test]
    fn a_process_that_is_gone_answers_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(read_executable(dir.path(), 999_999).is_none());
    }
}
