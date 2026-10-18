use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use domain::dlp::entity::{DlpExecutable, DlpIdentitySource};
use ports::secondary::process_executable_port::ProcessExecutableReader;

/// Suffix the kernel appends to `/proc/<pid>/exe` once the binary has been
/// unlinked. Kept off the reported path: the file is gone, the name is not.
const DELETED_SUFFIX: &str = " (deleted)";

/// Resolves a pid's executable through `/proc/<pid>/exe`, from a configurable
/// proc root so an agent holding the host procfs at `/host/proc` names the
/// node's binaries rather than its own container's.
///
/// The path comes from the symlink and the `(dev, ino)` pair from a stat of
/// the same link target, so the two always describe one file. A process that
/// exited between the write and the alert, or one the agent may not look at,
/// resolves to nothing.
pub struct ProcExecutableResolver {
    proc_root: PathBuf,
}

impl ProcExecutableResolver {
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

impl ProcessExecutableReader for ProcExecutableResolver {
    fn read_executable(&self, pid: u32) -> Option<DlpExecutable> {
        let link = self.proc_root.join(pid.to_string()).join("exe");
        let target = std::fs::read_link(&link).ok()?;
        let path = target.to_string_lossy();
        let path = path
            .strip_suffix(DELETED_SUFFIX)
            .unwrap_or(path.as_ref())
            .to_string();
        if path.is_empty() {
            return None;
        }

        // Stat the link rather than the resolved name: the binary may have
        // been replaced since, and a deleted one has no name left to stat.
        let meta = std::fs::metadata(&link).ok()?;
        Some(DlpExecutable {
            path,
            dev: meta.dev(),
            inode: meta.ino(),
            source: DlpIdentitySource::ProcessAtAlertTime,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Build a fake `/proc/<pid>/exe` pointing at a real file, as the kernel
    /// does, so the stat behind the link has something to answer.
    fn fake_proc(pid: u32, link_name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let binary = dir.path().join("binary");
        fs::write(&binary, b"\x7fELF").unwrap();
        let pid_dir = dir.path().join("proc").join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        let mut target = binary.clone().into_os_string();
        target.push(link_name);
        std::os::unix::fs::symlink(&target, pid_dir.join("exe")).unwrap();
        let root = dir.path().join("proc");
        (dir, root)
    }

    #[test]
    fn reads_the_executable_behind_a_pid() {
        let (_dir, root) = fake_proc(4242, "");
        let resolver = ProcExecutableResolver::new(&root);

        let exe = resolver.read_executable(4242).expect("a live pid resolves");
        assert!(exe.path.ends_with("/binary"), "path was {}", exe.path);
        assert_ne!(exe.inode, 0);
        assert_eq!(exe.source, DlpIdentitySource::ProcessAtAlertTime);
    }

    #[test]
    fn a_deleted_binary_keeps_its_name_without_the_kernel_suffix() {
        let (_dir, root) = fake_proc(4243, " (deleted)");
        let resolver = ProcExecutableResolver::new(&root);

        // The link target carries the suffix and the stat behind it fails,
        // so nothing is reported: a path with no file is not an identity.
        assert!(resolver.read_executable(4243).is_none());
    }

    #[test]
    fn a_process_that_is_gone_resolves_to_nothing() {
        let dir = tempdir().unwrap();
        let resolver = ProcExecutableResolver::new(dir.path());
        assert!(resolver.read_executable(999_999).is_none());
    }

    #[test]
    fn proc_path_is_exposed() {
        let resolver = ProcExecutableResolver::new("/host/proc");
        assert_eq!(resolver.proc_path(), Path::new("/host/proc"));
    }

    #[test]
    fn default_uses_proc() {
        assert_eq!(
            ProcExecutableResolver::with_default_proc().proc_path(),
            Path::new("/proc")
        );
    }
}
