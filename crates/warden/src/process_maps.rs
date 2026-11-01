//! The files every process has mapped executable.
//!
//! `/proc/<pid>/maps` is readable only by a process allowed to trace the
//! one it describes, which a rootless agent is not, so the warden lists the
//! processes and reads their maps. Only what a library or an executable
//! leaves there is kept: a file-backed mapping with execute permission, named
//! by its device, inode and path inside the process's own root.
//!
//! The walk is incremental. Each process is stamped by its start time and its
//! virtual size from `/proc/<pid>/stat`, both readable without tracing it,
//! and the caller hands back the stamps it already holds: a process whose
//! stamp has not moved is listed and not read again. A `dlopen` or an `exec`
//! moves the stamp, and so does a pid taken by a new process.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ebpfsentinel_warden_proto::{
    MAPPED_FILES_PER_PID_MAX, MAPPED_PIDS_MAX, MAPPINGS_BYTES_MAX, MAPS_BYTES_MAX, MappedFile,
    MappingScan, ProcessMappings, ProcessStamp,
};

/// The stamp of `pid`, from `/proc/<pid>/stat`.
fn stamp(proc_root: &Path, pid: u32) -> Option<ProcessStamp> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    // The command name is in parentheses and may hold anything, spaces and
    // parentheses included, so the fields are counted from the last `)`.
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_ascii_whitespace();
    // `state` is field 3; `starttime` is 22 and `vsize` 23.
    let start_time = fields.nth(19)?.parse().ok()?;
    let vsize = fields.next()?.parse().ok()?;
    Some(ProcessStamp {
        pid,
        start_time,
        vsize,
    })
}

/// One line of `/proc/<pid>/maps`, kept when it maps a file executable.
fn executable_mapping(line: &str) -> Option<(u64, u64, &str)> {
    let mut fields = line.splitn(6, ' ');
    let _range = fields.next()?;
    let perms = fields.next()?;
    let _offset = fields.next()?;
    let dev = fields.next()?;
    let ino: u64 = fields.next()?.parse().ok()?;
    let path = fields.next()?.trim_start();
    if perms.as_bytes().get(2) != Some(&b'x') || ino == 0 || !path.starts_with('/') {
        return None;
    }
    let (major, minor) = dev.split_once(':')?;
    let major = u32::from_str_radix(major, 16).ok()?;
    let minor = u32::from_str_radix(minor, 16).ok()?;
    Some((libc::makedev(major, minor), ino, path))
}

/// What reading the maps of one process gave.
struct Read1 {
    files: Vec<MappedFile>,
    truncated: bool,
}

fn read_maps(proc_root: &Path, pid: u32) -> std::io::Result<Read1> {
    let file = std::fs::File::open(proc_root.join(pid.to_string()).join("maps"))?;
    let mut text = String::new();
    let cap = u64::try_from(MAPS_BYTES_MAX).unwrap_or(u64::MAX);
    file.take(cap + 1).read_to_string(&mut text)?;
    let mut truncated = text.len() > MAPS_BYTES_MAX;
    if truncated {
        // Drop the partial last line rather than parse half of it.
        let end = text[..MAPS_BYTES_MAX].rfind('\n').unwrap_or(0);
        text.truncate(end);
    }
    let mut seen = HashSet::new();
    let mut files = Vec::new();
    for (dev, ino, path) in text.lines().filter_map(executable_mapping) {
        if !seen.insert((dev, ino)) {
            continue;
        }
        if files.len() == MAPPED_FILES_PER_PID_MAX {
            truncated = true;
            break;
        }
        let (path, deleted) = match path.strip_suffix(" (deleted)") {
            Some(p) => (p, true),
            None => (path, false),
        };
        files.push(MappedFile {
            dev,
            ino,
            path: path.to_string(),
            deleted,
        });
    }
    Ok(Read1 { files, truncated })
}

/// List every process under `proc_root` and read the executable mappings of
/// those whose stamp is not in `known`, up to [`MAPPINGS_BYTES_MAX`] of
/// paths.
pub fn scan(proc_root: &Path, known: &[ProcessStamp]) -> MappingScan {
    let known: HashSet<ProcessStamp> = known.iter().copied().collect();
    let mut pids: Vec<u32> = match std::fs::read_dir(proc_root) {
        Ok(dir) => dir
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
            .collect(),
        Err(_) => return MappingScan::default(),
    };
    pids.sort_unstable();
    let mut out = MappingScan::default();
    let mut index: HashMap<MappedFile, u32> = HashMap::new();
    let mut bytes = 0usize;
    for pid in pids {
        // A process gone between the listing and its stat is not listed.
        let Some(stamp) = stamp(proc_root, pid) else {
            continue;
        };
        if out.processes.len() == MAPPED_PIDS_MAX {
            out.not_listed = out.not_listed.saturating_add(1);
            continue;
        }
        out.processes.push(stamp);
        if known.contains(&stamp) {
            continue;
        }
        if bytes >= MAPPINGS_BYTES_MAX {
            out.pending = out.pending.saturating_add(1);
            continue;
        }
        let root = std::fs::metadata(proc_root.join(pid.to_string()).join("root"));
        let read = root.and_then(|root| Ok((root, read_maps(proc_root, pid)?)));
        let entry = match read {
            Ok((root, read)) => {
                let mut ids = Vec::with_capacity(read.files.len());
                for file in read.files {
                    let next = u32::try_from(index.len()).unwrap_or(u32::MAX);
                    let id = *index.entry(file).or_insert_with_key(|file| {
                        bytes += file.path.len() + 16;
                        out.files.push(file.clone());
                        next
                    });
                    ids.push(id);
                    bytes += 4;
                }
                ProcessMappings {
                    stamp,
                    root_dev: root.dev(),
                    root_ino: root.ino(),
                    files: ids,
                    truncated: read.truncated,
                    error: None,
                }
            }
            Err(e) => ProcessMappings {
                stamp,
                root_dev: 0,
                root_ino: 0,
                files: Vec::new(),
                truncated: false,
                error: Some(e.to_string()),
            },
        };
        out.read.push(entry);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    const STAT_TAIL: &str = "S 1 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0";

    /// A fake process `pid` started at `start` with virtual size `vsize`,
    /// mapping `maps`, running in `root`.
    fn process(proc_root: &Path, pid: u32, start: u64, vsize: u64, maps: &str, root: &Path) {
        let dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("stat"),
            format!("{pid} (a (b) c) {STAT_TAIL} {start} {vsize} 300 18446744073709551615\n"),
        )
        .unwrap();
        fs::write(dir.join("maps"), maps).unwrap();
        symlink(root, dir.join("root")).unwrap();
    }

    const LIBC: &str = "\
5600a0000000-5600a0020000 r--p 00000000 fd:01 1048602 /usr/bin/bash
5600a0020000-5600a00f0000 r-xp 00020000 fd:01 1048602 /usr/bin/bash
7f0000000000-7f0000028000 r--p 00000000 fd:01 1050000 /usr/lib/x86_64-linux-gnu/libc.so.6
7f0000028000-7f00001bd000 r-xp 00028000 fd:01 1050000 /usr/lib/x86_64-linux-gnu/libc.so.6
7f00001bd000-7f0000215000 r--p 00000000 fd:01 1050100 /usr/lib/locale/C.utf8/LC_CTYPE
7f0000300000-7f0000301000 r-xp 00000000 00:01 4242 /memfd:jit (deleted)
7f0000400000-7f0000420000 r-xp 00000000 fd:01 1050200 /usr/lib/libold.so.1 (deleted)
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0 [stack]
7ffd00030000-7ffd00032000 r-xp 00000000 00:00 0 [vdso]
";

    #[test]
    fn only_files_mapped_executable_are_kept_once_each() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        process(&proc_root, 40, 900, 7_000_000, LIBC, dir.path());
        let scan = scan(&proc_root, &[]);
        assert_eq!(scan.processes.len(), 1);
        assert_eq!(scan.processes[0].start_time, 900);
        assert_eq!(scan.processes[0].vsize, 7_000_000);
        let paths: Vec<_> = scan.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "/usr/bin/bash",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/memfd:jit",
                "/usr/lib/libold.so.1",
            ]
        );
        assert!(scan.files[3].deleted);
        assert_eq!(scan.files[1].dev, libc::makedev(0xfd, 1));
        assert_eq!(scan.read[0].files, [0, 1, 2, 3]);
        let root = fs::metadata(dir.path()).unwrap();
        assert_eq!(
            (scan.read[0].root_dev, scan.read[0].root_ino),
            (root.dev(), root.ino())
        );
    }

    #[test]
    fn a_process_whose_stamp_has_not_moved_is_listed_and_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        process(&proc_root, 40, 900, 7_000_000, LIBC, dir.path());
        process(&proc_root, 41, 905, 7_000_000, LIBC, dir.path());
        let first = scan(&proc_root, &[]);
        assert_eq!(first.read.len(), 2);
        // Two processes mapping the same files share one table entry each.
        assert_eq!(first.files.len(), 4);
        let mut known = first.processes.clone();
        known[1].vsize += 4096;
        let second = scan(&proc_root, &known);
        assert_eq!(second.processes, first.processes);
        assert_eq!(second.read.len(), 1);
        assert_eq!(second.read[0].stamp.pid, 41);
    }

    #[test]
    fn a_stat_with_a_hostile_command_name_still_parses() {
        let dir = tempfile::tempdir().unwrap();
        let proc_root = dir.path().join("proc");
        process(&proc_root, 9, 1, 2, "", dir.path());
        let got = stamp(&proc_root, 9).unwrap();
        assert_eq!((got.start_time, got.vsize), (1, 2));
    }

    #[test]
    fn the_real_procfs_names_this_test_s_own_executable() {
        let me = fs::metadata("/proc/self/exe").unwrap();
        let scan = scan(Path::new("/proc"), &[]);
        let pid = std::process::id();
        let mine = scan.read.iter().find(|p| p.stamp.pid == pid).unwrap();
        assert!(
            mine.files
                .iter()
                .any(|&i| scan.files[i as usize].ino == me.ino())
        );
    }
}
