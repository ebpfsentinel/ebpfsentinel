use std::io;
use std::path::{Path, PathBuf};

use domain::container::engine::CgroupReader;

/// Reads `/proc/{pid}/cgroup` from a configurable proc root. Running
/// inside a container with the host proc mounted at `/host/proc` is
/// supported by passing that path to `new`.
pub struct ProcContainerResolver {
    proc_root: PathBuf,
}

impl ProcContainerResolver {
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

impl CgroupReader for ProcContainerResolver {
    fn read_cgroup(&self, pid: u32) -> io::Result<String> {
        let path = self.proc_root.join(pid.to_string()).join("cgroup");
        std::fs::read_to_string(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn reads_cgroup_file_from_configured_root() {
        let dir = tempdir().unwrap();
        let proc_root = dir.path();
        let pid_dir = proc_root.join("1234");
        fs::create_dir_all(&pid_dir).unwrap();
        fs::write(pid_dir.join("cgroup"), "0::/init.scope\n").unwrap();

        let resolver = ProcContainerResolver::new(proc_root);
        let payload = resolver.read_cgroup(1234).unwrap();
        assert_eq!(payload.trim(), "0::/init.scope");
    }

    #[test]
    fn missing_pid_returns_error() {
        let dir = tempdir().unwrap();
        let resolver = ProcContainerResolver::new(dir.path());
        assert!(resolver.read_cgroup(999_999).is_err());
    }

    #[test]
    fn proc_path_is_exposed() {
        let resolver = ProcContainerResolver::new("/custom/proc");
        assert_eq!(resolver.proc_path(), Path::new("/custom/proc"));
    }

    #[test]
    fn default_uses_proc() {
        let resolver = ProcContainerResolver::with_default_proc();
        assert_eq!(resolver.proc_path(), Path::new("/proc"));
    }
}
