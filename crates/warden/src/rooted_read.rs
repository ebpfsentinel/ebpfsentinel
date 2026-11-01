//! Reading package databases inside the root a process runs in.
//!
//! A container's files are reached through `/proc/<pid>/root`, and a path
//! taken from inside a container is the container's to point anywhere: a
//! link to `/` there resolves to the host's root when followed naively from
//! outside. Each file is therefore opened with `openat2` and
//! `RESOLVE_IN_ROOT` against that root, so every link is resolved as the
//! container would resolve it and none leads out, and only a regular file is
//! read. The file is named by what it is, never by a path the caller chose.
//!
//! Nothing is parsed here: the bytes are handed back to the agent, which
//! parses them as untrusted input outside the privileged process.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;

use ebpfsentinel_warden_proto::{FileRoot, ROOTED_CHUNK_MAX, RootedFile, RootedRead};

/// The most bytes of `/proc/<pid>/cgroup` handed back.
const CGROUP_MAX: usize = 4096;

/// Every distinct root processes run in under `proc_root`, named by its
/// lowest pid, the host's first.
pub fn file_roots(proc_root: &Path) -> Vec<FileRoot> {
    let host = std::fs::metadata(proc_root.join("1").join("root"))
        .ok()
        .map(|m| (m.dev(), m.ino()));
    let mut pids: Vec<u32> = match std::fs::read_dir(proc_root) {
        Ok(dir) => dir
            .flatten()
            .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
            .collect(),
        Err(_) => return Vec::new(),
    };
    pids.sort_unstable();
    let mut roots: BTreeMap<(u64, u64), u32> = BTreeMap::new();
    for pid in pids {
        // A process that is gone, or whose root the reader may not follow,
        // is skipped: another process in the same root names it.
        let Ok(meta) = std::fs::metadata(proc_root.join(pid.to_string()).join("root")) else {
            continue;
        };
        roots.entry((meta.dev(), meta.ino())).or_insert(pid);
    }
    let mut out: Vec<FileRoot> = roots
        .into_iter()
        .map(|((dev, ino), pid)| {
            let mut cgroup =
                std::fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup"))
                    .unwrap_or_default();
            cgroup.truncate(cgroup.floor_char_boundary(CGROUP_MAX));
            FileRoot {
                pid,
                dev,
                ino,
                host: host == Some((dev, ino)),
                cgroup,
            }
        })
        .collect();
    out.sort_by_key(|r| (!r.host, r.pid));
    out
}

/// `struct open_how` of `openat2(2)`, in its first published size.
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// Open the root directory of `pid`.
fn open_root(proc_root: &Path, pid: u32) -> io::Result<OwnedFd> {
    let path = CString::new(
        proc_root
            .join(pid.to_string())
            .join("root")
            .as_os_str()
            .as_bytes(),
    )
    .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` is a valid NUL-terminated string that outlives the call.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by `open` and is owned by nobody else.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open `relative` read-only, resolved inside the directory `root`.
fn open_in_root(root: &OwnedFd, relative: &str) -> io::Result<File> {
    let path = CString::new(relative).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK;
    let how = OpenHow {
        flags: u64::try_from(flags).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?,
        mode: 0,
        resolve: libc::RESOLVE_IN_ROOT | libc::RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path` and `how` outlive the call and `how`'s size is passed
    // with it, as `openat2(2)` requires.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &raw const how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = i32::try_from(fd).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    // SAFETY: `fd` was just returned by `openat2` and is owned by nobody else.
    Ok(File::from(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// Read up to `len` bytes from `offset` of `file` inside the root of `pid`.
pub fn read_rooted_file(
    proc_root: &Path,
    pid: u32,
    file: &RootedFile,
    offset: u64,
    len: u32,
) -> RootedRead {
    let unreadable = |reason: String| RootedRead::Unreadable { reason };
    let Some(candidates) = file.candidates() else {
        return unreadable("not a package database this reader opens".into());
    };
    let root = match open_root(proc_root, pid) {
        Ok(root) => root,
        Err(e) => return unreadable(format!("the root of pid {pid} could not be opened: {e}")),
    };
    for path in candidates {
        let opened = match open_in_root(&root, &path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return unreadable(format!("/{path}: {e}")),
        };
        let meta = match opened.metadata() {
            Ok(m) => m,
            Err(e) => return unreadable(format!("/{path}: {e}")),
        };
        if !meta.file_type().is_file() {
            return unreadable(format!("/{path} is not a regular file"));
        }
        let size = meta.len();
        let want = u64::from(len.min(ROOTED_CHUNK_MAX)).min(size.saturating_sub(offset));
        let mut data = vec![0u8; usize::try_from(want).unwrap_or(0)];
        let mut filled = 0;
        while filled < data.len() {
            match opened.read_at(&mut data[filled..], offset + filled as u64) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return unreadable(format!("/{path}: {e}")),
            }
        }
        data.truncate(filled);
        return RootedRead::Chunk {
            path,
            dev: meta.dev(),
            ino: meta.ino(),
            size,
            mtime_ns: meta
                .mtime()
                .saturating_mul(1_000_000_000)
                .saturating_add(meta.mtime_nsec()),
            data,
        };
    }
    RootedRead::Absent
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fake procfs whose pid `pid` has `root` as its root.
    fn fake_proc(dir: &Path, pid: u32, root: &Path) -> std::path::PathBuf {
        let proc_root = dir.join("proc");
        let pid_dir = proc_root.join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        std::os::unix::fs::symlink(root, pid_dir.join("root")).unwrap();
        fs::write(pid_dir.join("cgroup"), "0::/system.slice/x.service\n").unwrap();
        proc_root
    }

    #[test]
    fn a_database_is_read_in_pieces_from_inside_its_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("rootfs");
        fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        fs::write(root.join("var/lib/dpkg/status"), b"Package: a\n").unwrap();
        let proc_root = fake_proc(dir.path(), 7, &root);

        let RootedRead::Chunk {
            path, size, data, ..
        } = read_rooted_file(&proc_root, 7, &RootedFile::DpkgStatus, 0, 4)
        else {
            panic!("the status file is read");
        };
        assert_eq!(
            (path.as_str(), size, data.as_slice()),
            ("var/lib/dpkg/status", 11, &b"Pack"[..])
        );
        let RootedRead::Chunk { data, .. } =
            read_rooted_file(&proc_root, 7, &RootedFile::DpkgStatus, 4, 1024)
        else {
            panic!("the rest is read");
        };
        assert_eq!(data, b"age: a\n");
        assert_eq!(
            read_rooted_file(&proc_root, 7, &RootedFile::ApkInstalled, 0, 16),
            RootedRead::Absent
        );
    }

    #[test]
    fn a_link_inside_the_root_does_not_lead_out_of_it() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("secret");
        fs::write(&outside, b"host only").unwrap();
        let root = dir.path().join("rootfs");
        fs::create_dir_all(root.join("lib/apk/db")).unwrap();
        // An absolute link and a climbing one, both meant to reach the file
        // beside the root.
        std::os::unix::fs::symlink(&outside, root.join("lib/apk/db/installed")).unwrap();
        fs::create_dir_all(root.join("var/lib/dpkg")).unwrap();
        std::os::unix::fs::symlink("../../../../secret", root.join("var/lib/dpkg/status")).unwrap();
        let proc_root = fake_proc(dir.path(), 9, &root);

        for file in [RootedFile::ApkInstalled, RootedFile::DpkgStatus] {
            let read = read_rooted_file(&proc_root, 9, &file, 0, 64);
            assert!(
                !matches!(&read, RootedRead::Chunk { data, .. } if data == b"host only"),
                "{file:?} escaped its root: {read:?}"
            );
        }
    }

    #[test]
    fn a_directory_is_not_read_and_a_bad_list_name_is_not_opened() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("rootfs");
        fs::create_dir_all(root.join("var/lib/dpkg/status")).unwrap();
        let proc_root = fake_proc(dir.path(), 3, &root);
        assert!(matches!(
            read_rooted_file(&proc_root, 3, &RootedFile::DpkgStatus, 0, 64),
            RootedRead::Unreadable { .. }
        ));
        assert!(matches!(
            read_rooted_file(
                &proc_root,
                3,
                &RootedFile::DpkgList {
                    name: "../status".into()
                },
                0,
                64
            ),
            RootedRead::Unreadable { .. }
        ));
        assert!(matches!(
            read_rooted_file(&proc_root, 4, &RootedFile::DpkgStatus, 0, 64),
            RootedRead::Unreadable { .. }
        ));
    }

    #[test]
    fn roots_are_told_apart_and_the_lowest_pid_names_each() {
        let dir = tempfile::tempdir().unwrap();
        let host = dir.path().join("host");
        let other = dir.path().join("other");
        fs::create_dir_all(&host).unwrap();
        fs::create_dir_all(&other).unwrap();
        fake_proc(dir.path(), 1, &host);
        fake_proc(dir.path(), 40, &other);
        fake_proc(dir.path(), 12, &other);
        let proc_root = fake_proc(dir.path(), 5, &host);
        let roots = file_roots(&proc_root);
        assert_eq!(roots.len(), 2);
        assert_eq!((roots[0].pid, roots[0].host), (1, true));
        assert_eq!((roots[1].pid, roots[1].host), (12, false));
        assert!(roots[1].cgroup.contains("x.service"));
    }
}
