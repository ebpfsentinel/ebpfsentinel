//! Reading what a watched path names: its kind, mode, owner, size and time,
//! the digest of its content and of each extended attribute.
//!
//! The warden reads for the agent because the agent reaches neither the
//! host's files nor the right to read them. It reads only on a filesystem the
//! asking connection's watch covers, returns digests and never content, and
//! never follows a link or opens anything but a regular file or a directory,
//! so a pipe or a device put at a watched path cannot block or be consumed.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use ebpfsentinel_warden_proto::{
    FIM_ENTROPY_SAMPLE, FIM_NOT_WATCHED, FimFacts, FimFile, FimFileType, FimReading, FimXattr,
};
use sha2::{Digest, Sha256};

use crate::fim_watch::{FSID_LEN, fsid_of, open_path};

/// Paths one request may name; the rest are left for the next one.
pub const FIM_FACTS_PATHS_MAX: usize = 256;

/// Bytes hashed for one request before the remaining paths are left for the
/// next one, so one request stays well inside the agent's call timeout.
pub const FIM_FACTS_BYTES_BUDGET: u64 = 64 * 1024 * 1024;

/// Extended attributes read per entry.
const XATTRS_MAX: usize = 64;
/// Bytes of attribute names, and of one attribute's value, read per entry.
const XATTR_BYTES_MAX: usize = 64 * 1024;
const HASH_CHUNK: usize = 64 * 1024;

/// Read each of `paths` in order, until [`FIM_FACTS_PATHS_MAX`] paths or
/// [`FIM_FACTS_BYTES_BUDGET`] hashed bytes. `covered` says whether a
/// filesystem, by its identifier, may be read.
pub fn read_facts(
    paths: &[String],
    max_hash_bytes: u64,
    covered: &dyn Fn([u8; FSID_LEN]) -> bool,
) -> Vec<FimFacts> {
    read_facts_within(paths, max_hash_bytes, covered, FIM_FACTS_BYTES_BUDGET)
}

fn read_facts_within(
    paths: &[String],
    max_hash_bytes: u64,
    covered: &dyn Fn([u8; FSID_LEN]) -> bool,
    budget: u64,
) -> Vec<FimFacts> {
    let mut spent = 0_u64;
    let mut facts = Vec::new();
    for path in paths.iter().take(FIM_FACTS_PATHS_MAX) {
        if spent >= budget && !facts.is_empty() {
            break;
        }
        let reading = read_one(path, max_hash_bytes, covered, &mut spent);
        facts.push(FimFacts {
            path: path.clone(),
            reading,
        });
    }
    facts
}

fn is_gone(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::ENOENT | libc::ENOTDIR))
}

fn read_one(
    path: &str,
    max_hash_bytes: u64,
    covered: &dyn Fn([u8; FSID_LEN]) -> bool,
    spent: &mut u64,
) -> FimReading {
    let as_path = Path::new(path);
    let (Some(parent), Some(name)) = (as_path.parent(), as_path.file_name()) else {
        return FimReading::Unreadable("not an absolute path to an entry".into());
    };
    if !as_path.is_absolute() || path.ends_with('/') {
        return FimReading::Unreadable("not an absolute path to an entry".into());
    }
    let Ok(name) = CString::new(name.as_bytes()) else {
        return FimReading::Unreadable("the name holds a NUL byte".into());
    };
    let dir = match open_path(parent, libc::O_PATH | libc::O_DIRECTORY) {
        Ok(dir) => dir,
        Err(e) if is_gone(&e) => return FimReading::Gone,
        Err(e) => return FimReading::Unreadable(format!("its directory: {e}")),
    };
    match fsid_of(dir.as_raw_fd()) {
        Ok(fsid) if covered(fsid) => {}
        Ok(_) => return FimReading::Unreadable(FIM_NOT_WATCHED.into()),
        Err(e) => return FimReading::Unreadable(format!("its filesystem: {e}")),
    }
    let st = match fstatat(dir.as_raw_fd(), &name) {
        Ok(st) => st,
        Err(e) if is_gone(&e) => return FimReading::Gone,
        Err(e) => return FimReading::Unreadable(e.to_string()),
    };
    let mut file = file_from_stat(&st);
    match file.file_type {
        FimFileType::Symlink => match readlinkat(dir.as_raw_fd(), &name) {
            Ok(target) => file.link_target = Some(target),
            Err(e) if is_gone(&e) => return FimReading::Gone,
            Err(e) => return FimReading::Unreadable(format!("the link: {e}")),
        },
        FimFileType::Regular | FimFileType::Directory => {
            let regular = file.file_type == FimFileType::Regular;
            let flags = if regular {
                libc::O_RDONLY | libc::O_NONBLOCK
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY
            };
            let fd = match openat(dir.as_raw_fd(), &name, flags | libc::O_NOFOLLOW) {
                Ok(fd) => fd,
                Err(e) if is_gone(&e) => return FimReading::Gone,
                Err(e) => {
                    let reason = e.to_string();
                    if regular {
                        file.hash_unread = Some(reason.clone());
                    }
                    file.xattrs_unread = Some(reason);
                    return FimReading::Present(file);
                }
            };
            // What was opened must be what was stat'ed: a path swapped for
            // another entry in between is read again on its own event.
            match fstat(fd.as_raw_fd()) {
                Ok(now) if now.st_ino == st.st_ino && now.st_dev == st.st_dev => {}
                Ok(_) => return FimReading::Unreadable("replaced while being read".into()),
                Err(e) => return FimReading::Unreadable(e.to_string()),
            }
            match read_xattrs(fd.as_raw_fd()) {
                Ok(xattrs) => file.xattrs = xattrs,
                Err(e) => file.xattrs_unread = Some(e.to_string()),
            }
            if regular {
                if file.size > max_hash_bytes {
                    file.hash_unread = Some(format!("larger than {max_hash_bytes} bytes"));
                } else {
                    match hash(File::from(fd), max_hash_bytes) {
                        Ok(hashed) => {
                            *spent = spent.saturating_add(hashed.read);
                            file.sha256 = Some(hashed.digest);
                            file.entropy_millibits = hashed.entropy_millibits;
                        }
                        Err(e) => file.hash_unread = Some(e),
                    }
                }
            }
        }
        FimFileType::Other => {
            file.xattrs_unread = Some("not read on a device, a socket or a pipe".into());
        }
    }
    FimReading::Present(file)
}

fn file_from_stat(st: &libc::stat) -> FimFile {
    let file_type = match st.st_mode & libc::S_IFMT {
        libc::S_IFREG => FimFileType::Regular,
        libc::S_IFDIR => FimFileType::Directory,
        libc::S_IFLNK => FimFileType::Symlink,
        _ => FimFileType::Other,
    };
    FimFile {
        file_type,
        size: u64::try_from(st.st_size).unwrap_or(0),
        mtime_ns: st
            .st_mtime
            .saturating_mul(1_000_000_000)
            .saturating_add(st.st_mtime_nsec),
        mode: st.st_mode & 0o7777,
        uid: st.st_uid,
        gid: st.st_gid,
        dev: st.st_dev,
        ino: st.st_ino,
        link_target: None,
        sha256: None,
        hash_unread: None,
        entropy_millibits: None,
        xattrs: Vec::new(),
        xattrs_unread: None,
    }
}

/// What hashing a file read from it.
struct Hashed {
    digest: [u8; 32],
    read: u64,
    entropy_millibits: Option<u16>,
}

/// Byte counts over the first [`FIM_ENTROPY_SAMPLE`] bytes read.
struct Sample {
    counts: [u32; 256],
    taken: usize,
}

impl Sample {
    fn new() -> Self {
        Self {
            counts: [0; 256],
            taken: 0,
        }
    }

    fn take(&mut self, bytes: &[u8]) {
        let room = FIM_ENTROPY_SAMPLE.saturating_sub(self.taken);
        let bytes = &bytes[..bytes.len().min(room)];
        for &b in bytes {
            self.counts[usize::from(b)] = self.counts[usize::from(b)].saturating_add(1);
        }
        self.taken += bytes.len();
    }

    /// Shannon entropy of the sample, in thousandths of a bit per byte;
    /// nothing for an empty sample.
    fn millibits(&self) -> Option<u16> {
        let total = u32::try_from(self.taken).ok().filter(|t| *t > 0)?;
        let total = f64::from(total);
        let bits: f64 = self
            .counts
            .iter()
            .filter(|c| **c > 0)
            .map(|c| {
                let p = f64::from(*c) / total;
                -p * p.log2()
            })
            .sum();
        // Between 0 and 8 bits, so the rounded thousandths fit; the clamp
        // only absorbs floating-point noise.
        let millibits = (bits * 1000.0).round().clamp(0.0, 8000.0) as i32;
        u16::try_from(millibits).ok()
    }
}

/// Hash at most `limit` bytes: a file grown past the limit since it was
/// stat'ed is reported as such rather than hashed in part. The entropy is
/// sampled from the same bytes as they pass.
fn hash(mut file: File, limit: u64) -> Result<Hashed, String> {
    let mut hasher = Sha256::new();
    let mut sample = Sample::new();
    let mut buf = vec![0_u8; HASH_CHUNK];
    let mut read = 0_u64;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        };
        read = read.saturating_add(n as u64);
        if read > limit {
            return Err(format!("grew larger than {limit} bytes while read"));
        }
        hasher.update(&buf[..n]);
        sample.take(&buf[..n]);
    }
    Ok(Hashed {
        digest: hasher.finalize().into(),
        read,
        entropy_millibits: sample.millibits(),
    })
}

fn fstatat(dir: RawFd, name: &CStr) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `dir` is an open directory descriptor, `name` is NUL-terminated
    // and `st` points to a `stat` the call fills in.
    let rc = unsafe {
        libc::fstatat(
            dir,
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstatat` returned 0, so it wrote the whole structure.
    Ok(unsafe { st.assume_init() })
}

fn fstat(fd: RawFd) -> io::Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: `fd` is open and `st` points to a `stat` the call fills in.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstat` returned 0, so it wrote the whole structure.
    Ok(unsafe { st.assume_init() })
}

fn openat(dir: RawFd, name: &CStr, flags: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: `dir` is an open directory descriptor and `name` is
    // NUL-terminated for the duration of the call.
    let fd = unsafe { libc::openat(dir, name.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openat` returned a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn readlinkat(dir: RawFd, name: &CStr) -> io::Result<String> {
    let mut buf = vec![0_u8; libc::PATH_MAX as usize];
    // SAFETY: `dir` is open, `name` is NUL-terminated and `buf` is writable
    // for its length.
    let n = unsafe { libc::readlinkat(dir, name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(usize::try_from(n).unwrap_or(0));
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// The extended attributes of an open entry, sorted by name, each value
/// hashed. A filesystem without extended attributes has none.
fn read_xattrs(fd: RawFd) -> io::Result<Vec<FimXattr>> {
    let mut names = vec![0_u8; XATTR_BYTES_MAX];
    // SAFETY: `fd` is open and `names` is writable for its length.
    let n = unsafe { libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len()) };
    if n < 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::ENOTSUP) => Ok(Vec::new()),
            _ => Err(err),
        };
    }
    names.truncate(usize::try_from(n).unwrap_or(0));
    let mut value = vec![0_u8; XATTR_BYTES_MAX];
    let mut xattrs = Vec::new();
    for raw in names.split(|b| *b == 0).filter(|n| !n.is_empty()) {
        if xattrs.len() == XATTRS_MAX {
            return Err(io::Error::other(format!(
                "more than {XATTRS_MAX} extended attributes"
            )));
        }
        let Ok(cname) = CString::new(raw) else {
            continue;
        };
        // SAFETY: `fd` is open, `cname` is NUL-terminated and `value` is
        // writable for its length.
        let len =
            unsafe { libc::fgetxattr(fd, cname.as_ptr(), value.as_mut_ptr().cast(), value.len()) };
        if len < 0 {
            let err = io::Error::last_os_error();
            // Removed between the listing and the reading.
            if err.raw_os_error() == Some(libc::ENODATA) {
                continue;
            }
            return Err(err);
        }
        let len = usize::try_from(len).unwrap_or(0);
        xattrs.push(FimXattr {
            name: String::from_utf8_lossy(raw).into_owned(),
            sha256: Sha256::digest(&value[..len]).into(),
        });
    }
    xattrs.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(xattrs)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn all(_: [u8; FSID_LEN]) -> bool {
        true
    }

    fn none(_: [u8; FSID_LEN]) -> bool {
        false
    }

    fn one(path: &Path, max: u64) -> FimReading {
        let p = path.to_string_lossy().into_owned();
        read_facts(&[p], max, &all)
            .pop()
            .map_or(FimReading::Gone, |f| f.reading)
    }

    fn present(reading: FimReading) -> FimFile {
        match reading {
            FimReading::Present(f) => f,
            other => panic!("expected an entry, got {other:?}"),
        }
    }

    #[test]
    fn a_regular_file_is_hashed_with_its_mode_and_owner() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("hosts");
        std::fs::write(&path, b"hello").unwrap_or_else(|e| panic!("{e}"));
        let file = present(one(&path, 1024));
        assert_eq!(file.file_type, FimFileType::Regular);
        assert_eq!(file.size, 5);
        assert_eq!(file.sha256, Some(Sha256::digest(b"hello").into()));
        assert!(file.hash_unread.is_none());
        assert_eq!(
            file.mode & !0o7777,
            0,
            "the type bits are not part of the mode"
        );
        // SAFETY: getuid cannot fail.
        assert_eq!(file.uid, unsafe { libc::getuid() });
    }

    #[test]
    fn the_entropy_is_sampled_from_the_bytes_the_hash_reads() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let flat = dir.path().join("flat");
        std::fs::write(&flat, vec![b'a'; 4096]).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(present(one(&flat, 1 << 20)).entropy_millibits, Some(0));
        // Every byte value equally often: eight bits per byte.
        let even: Vec<u8> = (0..=255_u8).cycle().take(8192).collect();
        let full = dir.path().join("full");
        std::fs::write(&full, &even).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(present(one(&full, 1 << 20)).entropy_millibits, Some(8000));
        // Past the sample, the bytes are hashed and not counted.
        let mut tail = vec![b'a'; FIM_ENTROPY_SAMPLE];
        tail.extend_from_slice(&even);
        let late = dir.path().join("late");
        std::fs::write(&late, &tail).unwrap_or_else(|e| panic!("{e}"));
        let file = present(one(&late, 1 << 20));
        assert_eq!(file.entropy_millibits, Some(0));
        assert_eq!(file.sha256, Some(Sha256::digest(&tail).into()));
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(present(one(&empty, 1024)).entropy_millibits, None);
    }

    #[test]
    fn a_file_larger_than_asked_carries_a_reason_and_no_hash() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("big");
        std::fs::write(&path, vec![7_u8; 100]).unwrap_or_else(|e| panic!("{e}"));
        let file = present(one(&path, 99));
        assert!(file.sha256.is_none());
        assert_eq!(file.hash_unread.as_deref(), Some("larger than 99 bytes"));
    }

    #[test]
    fn a_missing_path_or_directory_is_gone() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(one(&dir.path().join("absent"), 1), FimReading::Gone);
        assert_eq!(one(&dir.path().join("no/such/entry"), 1), FimReading::Gone);
    }

    #[test]
    fn a_link_is_read_and_never_followed() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").unwrap_or_else(|e| panic!("{e}"));
        let link = dir.path().join("link");
        symlink(&target, &link).unwrap_or_else(|e| panic!("{e}"));
        let file = present(one(&link, 1024));
        assert_eq!(file.file_type, FimFileType::Symlink);
        assert_eq!(
            file.link_target,
            Some(target.to_string_lossy().into_owned())
        );
        assert!(file.sha256.is_none());
    }

    #[test]
    fn a_pipe_at_a_watched_path_is_never_opened() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("fifo");
        let c = CString::new(path.as_os_str().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        // SAFETY: `c` is a NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let file = present(one(&path, 1024));
        assert_eq!(file.file_type, FimFileType::Other);
        assert!(file.sha256.is_none());
    }

    #[test]
    fn a_path_off_the_watched_filesystems_is_not_read() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap_or_else(|e| panic!("{e}"));
        let facts = read_facts(&[path.to_string_lossy().into_owned()], 1024, &none);
        assert_eq!(
            facts[0].reading,
            FimReading::Unreadable(FIM_NOT_WATCHED.into())
        );
    }

    #[test]
    fn a_relative_path_is_refused() {
        let facts = read_facts(&["etc/hosts".into(), "/".into()], 1, &all);
        assert!(matches!(facts[0].reading, FimReading::Unreadable(_)));
        assert!(matches!(facts[1].reading, FimReading::Unreadable(_)));
    }

    #[test]
    fn a_spent_budget_leaves_the_rest_for_the_next_request() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let mut paths = Vec::new();
        for name in ["a", "b", "c"] {
            let path = dir.path().join(name);
            std::fs::write(&path, b"0123456789").unwrap_or_else(|e| panic!("{e}"));
            paths.push(path.to_string_lossy().into_owned());
        }
        let facts = read_facts_within(&paths, 1024, &all, 15);
        assert_eq!(facts.len(), 2);
        assert_eq!(facts[1].path, paths[1]);
        // A budget spent before the first path still reads one.
        assert_eq!(read_facts_within(&paths, 1024, &all, 0).len(), 1);
    }

    #[test]
    fn an_extended_attribute_is_digested_when_the_filesystem_keeps_them() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
        let path = dir.path().join("f");
        std::fs::write(&path, b"x").unwrap_or_else(|e| panic!("{e}"));
        let c = CString::new(path.as_os_str().as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        let name = c"user.ebpfsentinel";
        // SAFETY: both strings are NUL-terminated and the value is 2 bytes.
        let rc = unsafe { libc::setxattr(c.as_ptr(), name.as_ptr(), b"on".as_ptr().cast(), 2, 0) };
        let file = present(one(&path, 1024));
        if rc == 0 {
            assert_eq!(
                file.xattrs,
                vec![FimXattr {
                    name: "user.ebpfsentinel".into(),
                    sha256: Sha256::digest(b"on").into(),
                }]
            );
        } else {
            assert!(file.xattrs.is_empty());
        }
        assert!(file.xattrs_unread.is_none());
    }
}
