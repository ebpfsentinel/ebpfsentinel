use std::path::{Path, PathBuf};

use domain::file_watch::{RootMount, root_mount};
use ports::secondary::file_watch_port::ProcessRootReader;

/// Reads a process's root mount from `/proc/<pid>/mountinfo`.
///
/// The proc root is configurable for the same reason the executable
/// resolver's is: an agent holding the host procfs at `/host/proc` must read
/// the node's processes rather than its own container's.
pub struct ProcRootReader {
    proc_root: PathBuf,
}

impl ProcRootReader {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
        }
    }

    pub fn proc_path(&self) -> &Path {
        &self.proc_root
    }
}

impl ProcessRootReader for ProcRootReader {
    fn root_mount(&self, pid: u32) -> Option<RootMount> {
        if pid == 0 {
            return None;
        }
        let table =
            std::fs::read_to_string(self.proc_root.join(pid.to_string()).join("mountinfo")).ok()?;
        root_mount(&table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_root_of_a_process_and_nothing_for_one_gone() {
        let dir = tempfile::tempdir().unwrap();
        let pid = dir.path().join("42");
        std::fs::create_dir(&pid).unwrap();
        std::fs::write(
            pid.join("mountinfo"),
            "1 0 0:1 / / rw - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n",
        )
        .unwrap();
        let reader = ProcRootReader::new(dir.path());
        let root = reader.root_mount(42).unwrap();
        assert_eq!(root.upper.as_deref(), Some("/u"));
        assert!(reader.root_mount(43).is_none());
        assert!(reader.root_mount(0).is_none());
    }
}
