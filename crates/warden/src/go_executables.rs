//! The build information of every running Go executable.
//!
//! A Go linker writes the module list of the program it links, with each
//! module's version, into a `.go.buildinfo` section. Reading it takes the
//! executable's ELF headers and that one section, opened through
//! `/proc/<pid>/exe` so a binary deleted or replaced on disk is still the one
//! running. Each distinct `(dev, ino)` is opened once however many processes
//! run it.
//!
//! Nothing is parsed here beyond finding the section: its bytes are handed
//! back to the agent, which parses them as untrusted input outside the
//! privileged process.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ebpfsentinel_warden_proto::{
    GO_BUILDINFO_MAX, GO_PIDS_MAX, GO_SCAN_BYTES_MAX, GoExecutable, GoExecutableScan,
};
use object::{Object, ObjectSection};

/// The most bytes of `/proc/<pid>/cgroup` handed back.
const CGROUP_MAX: usize = 4096;

/// The section a Go linker writes its build information into.
const BUILDINFO_SECTION: &str = ".go.buildinfo";

/// The marker the kernel appends to the link of a deleted executable.
const DELETED_SUFFIX: &str = " (deleted)";

/// What one executable's section gave.
enum Section {
    /// No `.go.buildinfo`: not a Go program, or not one this reads.
    None,
    Bytes(Vec<u8>),
    Unreadable(String),
}

/// Read the build information section of the file open at `link`.
fn section_of(link: &Path) -> Section {
    let Ok(image) = std::fs::File::open(link) else {
        return Section::None;
    };
    let cache = object::read::ReadCache::new(image);
    let Ok(file) = object::File::parse(&cache) else {
        return Section::None;
    };
    let Some(section) = file.section_by_name(BUILDINFO_SECTION) else {
        return Section::None;
    };
    if usize::try_from(section.size()).map_or(true, |n| n > GO_BUILDINFO_MAX) {
        return Section::Unreadable(format!(
            "the build information section is {} bytes, past the {GO_BUILDINFO_MAX} read",
            section.size()
        ));
    }
    match section.data() {
        Ok(data) => Section::Bytes(data.to_vec()),
        Err(err) => Section::Unreadable(format!("the build information section: {err}")),
    }
}

/// Every running executable carrying a `.go.buildinfo` section under
/// `proc_root`, once per inode, the lowest pid naming it.
pub fn scan(proc_root: &Path) -> GoExecutableScan {
    let host = std::fs::metadata(proc_root.join("1").join("root"))
        .ok()
        .map(|m| (m.dev(), m.ino()));
    let mut pids: Vec<u32> = match std::fs::read_dir(proc_root) {
        Ok(dir) => dir
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
            .collect(),
        Err(_) => return GoExecutableScan::default(),
    };
    pids.sort_unstable();
    // Every running inode and the pids running it, lowest first. A kernel
    // thread has no executable and a process gone meanwhile has no link:
    // both are skipped.
    let mut running: BTreeMap<(u64, u64), Vec<u32>> = BTreeMap::new();
    for pid in pids {
        let Ok(meta) = std::fs::metadata(proc_root.join(pid.to_string()).join("exe")) else {
            continue;
        };
        running
            .entry((meta.dev(), meta.ino()))
            .or_default()
            .push(pid);
    }
    let mut out = GoExecutableScan {
        examined: u32::try_from(running.len()).unwrap_or(u32::MAX),
        ..GoExecutableScan::default()
    };
    let mut carried = 0usize;
    for ((dev, ino), mut pids) in running {
        let Some(&lowest) = pids.first() else {
            continue;
        };
        let dir = proc_root.join(lowest.to_string());
        let link = dir.join("exe");
        let (buildinfo, error) = match section_of(&link) {
            Section::None => continue,
            Section::Bytes(bytes) => (Some(bytes), None),
            Section::Unreadable(reason) => (None, Some(reason)),
        };
        let size = buildinfo.as_ref().map_or(0, Vec::len);
        if carried + size > GO_SCAN_BYTES_MAX {
            out.not_read = out.not_read.saturating_add(1);
            continue;
        }
        carried += size;
        let path = std::fs::read_link(&link)
            .map(|t| {
                let t = t.to_string_lossy();
                t.strip_suffix(DELETED_SUFFIX).unwrap_or(&t).to_owned()
            })
            .unwrap_or_default();
        let root = std::fs::metadata(dir.join("root"))
            .ok()
            .map(|m| (m.dev(), m.ino()));
        let mut cgroup = std::fs::read_to_string(dir.join("cgroup")).unwrap_or_default();
        cgroup.truncate(cgroup.floor_char_boundary(CGROUP_MAX));
        pids.truncate(GO_PIDS_MAX);
        out.executables.push(GoExecutable {
            dev,
            ino,
            path,
            pids,
            host: root.is_some() && root == host,
            cgroup,
            buildinfo,
            error,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::scan;
    use std::os::unix::fs::symlink;

    #[test]
    fn a_process_running_no_go_program_is_examined_and_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path();
        let pid = proc_root.join("4242");
        std::fs::create_dir(&pid).unwrap();
        let exe = dir.path().join("plain");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        symlink(&exe, pid.join("exe")).unwrap();
        symlink(dir.path(), pid.join("root")).unwrap();
        let out = scan(proc_root);
        assert_eq!(out.examined, 1);
        assert!(out.executables.is_empty());
    }

    #[test]
    fn a_rust_executable_is_examined_and_carries_no_go_section() {
        use std::os::unix::fs::MetadataExt;
        // The test binary is Rust, so it is examined and carries none: the
        // scan of the real procfs must not mistake it for a Go program.
        let out = scan(std::path::Path::new("/proc"));
        assert!(out.examined >= 1);
        let me = std::fs::metadata("/proc/self/exe").unwrap();
        assert!(
            out.executables
                .iter()
                .all(|e| (e.dev, e.ino) != (me.dev(), me.ino()))
        );
    }
}
