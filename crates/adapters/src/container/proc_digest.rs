#![allow(unsafe_code)] // Required for libc ioctl(FS_IOC_MEASURE_VERITY)

//! The digest of the file a process runs, read through `/proc/<pid>/exe`.
//!
//! Two ways, tried in order:
//!
//! 1. **fs-verity.** `FS_IOC_MEASURE_VERITY` asks the kernel for the digest
//!    of a file that has verity on. Nothing is read: the kernel holds the
//!    digest, the file cannot be written while verity is on, and every page
//!    the process maps is checked against it, so the answer holds for as long
//!    as the process runs. A file without verity answers `ENODATA`, and a
//!    filesystem that does not support it `ENOTTY` or `EOPNOTSUPP`.
//! 2. **The contents.** Otherwise the file is read once and its SHA-256 kept
//!    against the device, the inode, the size and both change times, so the
//!    next exec of the same binary costs one `fstat`, and a binary rewritten
//!    in place is read again rather than answered from the cache.
//!
//! IMA is not used. Its measurement list is a log of what was measured under
//! a policy the host configured, read from securityfs as root, keyed by path
//! and appended to for the life of the boot: answering "what is this pid
//! running" from it means a policy the agent does not control, a parse of a
//! file that only grows, and a path to join on, which is the very thing a
//! digest is meant to stop trusting. fs-verity answers that question about
//! one open file, and the contents answer it everywhere else.
//!
//! The file is opened through the process's own link, so what is hashed is
//! the file the process has mapped, even when its name now points at an
//! upgrade or nowhere at all. A rootless agent cannot open that link for a
//! process outside its user namespace: when `EBPFSENTINEL_WARDEN_SOCK` is set
//! the warden opens it read-only and hands the descriptor over, and the same
//! checks and the same hash run on it. Without a warden such a process carries
//! no digest, and the table holds the path alone.

use std::collections::HashMap;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::process::digest::{DigestSource, ExeHash, SHA256_LEN};
use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::executable_digest_port::ExecutableDigester;
use sha2::{Digest, Sha256};

/// Set to the warden's control socket when the agent runs rootless.
pub(crate) const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// `FS_IOC_MEASURE_VERITY`: `_IOWR('f', 134, struct fsverity_digest)`, the
/// struct being four bytes of header in front of a flexible array.
#[allow(clippy::cast_possible_wrap, clippy::cast_lossless)]
const FS_IOC_MEASURE_VERITY: libc::Ioctl = 0xC004_6686_u32 as libc::Ioctl;

/// `FS_VERITY_HASH_ALG_SHA256`. A file built with SHA-512 is read for its
/// contents instead: one algorithm on the wire keeps a rule comparable.
const FS_VERITY_HASH_ALG_SHA256: u16 = 1;

/// The largest digest the kernel may answer, SHA-512.
const FS_VERITY_MAX_DIGEST: usize = 64;

/// Files larger than this are not read for their contents: a 2 GiB binary
/// would hold the exec path for seconds. fs-verity has no such bound, since
/// it reads nothing.
pub const MAX_CONTENT_BYTES: u64 = 256 * 1024 * 1024;

/// Executables remembered. Past it the memory is dropped whole and rebuilt
/// from the next execs, which on a node is a handful of hundred binaries.
const CACHE_CAPACITY: usize = 4096;

/// `struct fsverity_digest` with room for the largest digest.
#[repr(C)]
struct FsVerityDigest {
    digest_algorithm: u16,
    digest_size: u16,
    digest: [u8; FS_VERITY_MAX_DIGEST],
}

/// What identifies one version of one file, as `fstat` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileVersion {
    dev: u64,
    inode: u64,
    size: u64,
    mtime_ns: i128,
    ctime_ns: i128,
}

impl FileVersion {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            inode: meta.ino(),
            size: meta.size(),
            mtime_ns: i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
            ctime_ns: i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
        }
    }
}

/// Hashes the executable behind a pid, from a configurable proc root.
pub struct ProcExecutableDigester {
    proc_root: PathBuf,
    cache: Mutex<HashMap<FileVersion, ExeHash>>,
    /// The warden, in a rootless deployment. Held behind a `Mutex` because the
    /// client caches its connection and the port reads through `&self`.
    warden: Option<Mutex<ReconnectingClient>>,
}

impl ProcExecutableDigester {
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| Mutex::new(ReconnectingClient::new(p)));
        Self {
            proc_root: proc_root.into(),
            cache: Mutex::new(HashMap::new()),
            warden,
        }
    }

    /// Open through the warden at `sock` whenever the local link is not
    /// openable, whatever the environment says.
    #[cfg(test)]
    fn with_warden(proc_root: impl Into<PathBuf>, sock: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            cache: Mutex::new(HashMap::new()),
            warden: Some(Mutex::new(ReconnectingClient::new(sock))),
        }
    }

    /// The file `pid` runs, opened through its own link, or through the
    /// warden when the agent may not open that link. A process that is gone
    /// costs no round trip.
    fn open_executable(&self, pid: u32) -> Option<File> {
        let link = self.proc_root.join(pid.to_string()).join("exe");
        match File::open(&link) {
            Ok(file) => Some(file),
            Err(e) if e.kind() == ErrorKind::PermissionDenied => self.open_through_warden(pid),
            Err(_) => None,
        }
    }

    /// Ask the warden for a read-only descriptor of the file `pid` runs. A
    /// warden that is down or refuses leaves the process without a digest,
    /// as a local failure does.
    fn open_through_warden(&self, pid: u32) -> Option<File> {
        let warden = self.warden.as_ref()?;
        // The client holds a connection and nothing the digest depends on, so
        // a poisoned lock leaves it usable.
        let mut client = warden
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match client.open_executable(pid) {
            Ok(fd) => Some(File::from(fd)),
            Err(e) => {
                tracing::debug!(pid, error = %e, "warden could not open the executable");
                None
            }
        }
    }

    pub fn proc_path(&self) -> &Path {
        &self.proc_root
    }

    fn remembered(&self, version: &FileVersion) -> Option<ExeHash> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(version)
            .copied()
    }

    fn remember(&self, version: FileVersion, hash: ExeHash) {
        // A map of finished digests stays valid after a partial write: an
        // entry is either inserted whole or not at all.
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(version, hash);
    }
}

/// The kernel's fs-verity digest of `file`, where verity is on and the file
/// was built with SHA-256.
fn measure_verity(file: &File) -> Option<ExeHash> {
    let mut answer = FsVerityDigest {
        digest_algorithm: 0,
        #[allow(clippy::cast_possible_truncation)]
        digest_size: FS_VERITY_MAX_DIGEST as u16,
        digest: [0; FS_VERITY_MAX_DIGEST],
    };
    // SAFETY: the descriptor is open for the duration of the call, and the
    // pointer is to a live, writable `fsverity_digest` whose `digest_size`
    // tells the kernel how many bytes of `digest` it may write, which is the
    // array's own length.
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            FS_IOC_MEASURE_VERITY,
            std::ptr::from_mut(&mut answer),
        )
    };
    if rc != 0
        || answer.digest_algorithm != FS_VERITY_HASH_ALG_SHA256
        || usize::from(answer.digest_size) != SHA256_LEN
    {
        return None;
    }
    let mut digest = [0u8; SHA256_LEN];
    digest.copy_from_slice(&answer.digest[..SHA256_LEN]);
    Some(ExeHash::new(DigestSource::FsVerity, digest))
}

/// The SHA-256 of everything `file` holds, up to `limit` bytes. A file that
/// grew past the limit while it was read is refused rather than cut short.
fn hash_contents(file: &mut File, limit: u64) -> Option<ExeHash> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            break;
        }
        read += n as u64;
        if read > limit {
            return None;
        }
        hasher.update(&buffer[..n]);
    }
    let mut digest = [0u8; SHA256_LEN];
    digest.copy_from_slice(&hasher.finalize());
    Some(ExeHash::new(DigestSource::Content, digest))
}

impl ExecutableDigester for ProcExecutableDigester {
    fn digest(&self, pid: u32, dev: u64, inode: u64) -> Option<ExeHash> {
        let mut file = self.open_executable(pid)?;
        let meta = file.metadata().ok()?;
        let version = FileVersion::of(&meta);
        if (version.dev, version.inode) != (dev, inode) || !meta.is_file() {
            // The pid was reused, or the link names another file than the
            // path the table holds: a digest here would describe the wrong
            // binary.
            return None;
        }
        if let Some(hash) = self.remembered(&version) {
            return Some(hash);
        }
        let hash = match measure_verity(&file) {
            Some(hash) => hash,
            None if version.size <= MAX_CONTENT_BYTES => {
                hash_contents(&mut file, MAX_CONTENT_BYTES)?
            }
            None => return None,
        };
        // A file rewritten while it was read reads as another version now,
        // and the digest of a file in motion is no file's digest.
        let after = FileVersion::of(&file.metadata().ok()?);
        if after != version {
            return None;
        }
        self.remember(version, hash);
        Some(hash)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    /// A fake `/proc/<pid>/exe` pointing at a file holding `bytes`.
    fn fake_proc(pid: u32, bytes: &[u8]) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let binary = dir.path().join("binary");
        fs::write(&binary, bytes).unwrap();
        let pid_dir = dir.path().join("proc").join(pid.to_string());
        fs::create_dir_all(&pid_dir).unwrap();
        std::os::unix::fs::symlink(&binary, pid_dir.join("exe")).unwrap();
        let root = dir.path().join("proc");
        (dir, root, binary)
    }

    fn identity(path: &Path) -> (u64, u64) {
        let meta = fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    #[test]
    fn a_file_without_verity_is_hashed_for_its_contents() {
        let (_dir, root, binary) = fake_proc(10, b"");
        let (dev, ino) = identity(&binary);
        let hash = ProcExecutableDigester::new(&root)
            .digest(10, dev, ino)
            .expect("a readable file has a digest");
        // `sha256sum` of an empty file.
        assert_eq!(
            hash.to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(hash.source(), DigestSource::Content);
    }

    #[test]
    fn another_file_than_the_one_the_table_read_has_no_digest() {
        let (_dir, root, binary) = fake_proc(11, b"\x7fELF");
        let (dev, ino) = identity(&binary);
        let digester = ProcExecutableDigester::new(&root);
        assert!(digester.digest(11, dev, ino + 1).is_none());
        assert!(digester.digest(12, dev, ino).is_none(), "no such pid");
    }

    #[test]
    fn a_rewritten_binary_is_read_again() {
        let (_dir, root, binary) = fake_proc(13, b"first");
        let (dev, ino) = identity(&binary);
        let digester = ProcExecutableDigester::new(&root);
        let first = digester.digest(13, dev, ino).expect("hashed");

        let mut file = fs::OpenOptions::new().append(true).open(&binary).unwrap();
        file.write_all(b" and more").unwrap();
        drop(file);

        let second = digester.digest(13, dev, ino).expect("hashed again");
        assert_ne!(first, second, "the cache is keyed on the file's version");
    }

    #[test]
    fn contents_past_the_limit_are_refused_rather_than_cut() {
        let (_dir, _root, binary) = fake_proc(14, &[0u8; 100]);
        let mut file = File::open(&binary).unwrap();
        assert!(hash_contents(&mut file, 99).is_none());
        let mut file = File::open(&binary).unwrap();
        assert!(hash_contents(&mut file, 100).is_some());
    }

    /// Hand `fd` over `conn` the way the warden does: one sentinel byte
    /// carrying the descriptor in an `SCM_RIGHTS` cmsg.
    pub(in crate::container) fn send_fd(
        conn: &std::os::unix::net::UnixStream,
        fd: std::os::fd::RawFd,
    ) {
        let byte = [0u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        #[allow(clippy::cast_possible_truncation)]
        // SAFETY: CMSG_SPACE only computes a size from its argument.
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) };
        let mut control = vec![0u8; space as usize];
        // SAFETY: an all-zero `msghdr` is a valid empty header.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &raw mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: `msg_control` points at a buffer of `CMSG_SPACE(int)` bytes,
        // so the first header and one `int` of data fit in it.
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            #[allow(clippy::cast_possible_truncation)]
            {
                (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
            }
            std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<libc::c_int>(), fd);
        }
        // SAFETY: the socket is open and `msg` describes live buffers.
        let sent = unsafe { libc::sendmsg(conn.as_raw_fd(), &raw const msg, 0) };
        assert_eq!(sent, 1, "sendmsg");
    }

    /// Answer one connection as the warden would: the handshake, then every
    /// `OpenExecutable` with a descriptor of `binary`. Returns how many opens
    /// it served.
    fn fake_warden(sock: &Path, binary: PathBuf) -> std::thread::JoinHandle<usize> {
        use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response};
        use ebpfsentinel_warden_proto::{read_frame, write_frame};
        let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
        std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let Ok(Command::Hello { .. }) = read_frame::<_, Command>(&mut conn) else {
                return 0;
            };
            write_frame(
                &mut conn,
                &Response::HelloOk {
                    version: PROTOCOL_VERSION,
                },
            )
            .unwrap();
            let mut served = 0;
            while let Ok(cmd) = read_frame::<_, Command>(&mut conn) {
                let Command::OpenExecutable { .. } = cmd else {
                    panic!("unexpected command {cmd:?}");
                };
                served += 1;
                let file = File::open(&binary).unwrap();
                write_frame(&mut conn, &Response::FdReady).unwrap();
                send_fd(&conn, file.as_raw_fd());
            }
            served
        })
    }

    #[test]
    fn a_link_the_agent_may_not_open_is_opened_by_the_warden() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, root, binary) = fake_proc(16, b"");
        let (dev, ino) = identity(&binary);
        let pid_dir = root.join("16");
        fs::set_permissions(&pid_dir, fs::Permissions::from_mode(0o000)).unwrap();
        // A privileged test run opens through the closed directory anyway,
        // and then the warden is never asked.
        let privileged = fs::read_dir(&pid_dir).is_ok();

        let sock = dir.path().join("warden.sock");
        let warden = fake_warden(&sock, binary.clone());
        let digester = ProcExecutableDigester::with_warden(&root, &sock);
        let hash = digester
            .digest(16, dev, ino)
            .expect("the warden's descriptor is hashed");
        assert_eq!(
            hash.to_string(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // The descriptor is checked against the table like a local open: a
        // reused pid naming another file has no digest.
        assert!(digester.digest(16, dev, ino + 1).is_none());

        // A process that is gone is not worth a round trip.
        assert!(digester.digest(999_999, dev, ino).is_none());

        drop(digester);
        if privileged {
            // Nobody connected; unblock the accept so the thread ends.
            drop(std::os::unix::net::UnixStream::connect(&sock));
        }
        let served = warden.join().unwrap();
        fs::set_permissions(&pid_dir, fs::Permissions::from_mode(0o755)).unwrap();
        if !privileged {
            assert_eq!(served, 2);
        }
    }

    #[test]
    fn without_a_warden_an_unopenable_link_has_no_digest() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, root, binary) = fake_proc(17, b"");
        let (dev, ino) = identity(&binary);
        let pid_dir = root.join("17");
        fs::set_permissions(&pid_dir, fs::Permissions::from_mode(0o000)).unwrap();
        let privileged = fs::read_dir(&pid_dir).is_ok();
        let digester = ProcExecutableDigester {
            proc_root: root.clone(),
            cache: Mutex::new(HashMap::new()),
            warden: None,
        };
        let digest = digester.digest(17, dev, ino);
        fs::set_permissions(&pid_dir, fs::Permissions::from_mode(0o755)).unwrap();
        if !privileged {
            assert!(digest.is_none());
        }
    }

    #[test]
    fn a_file_without_verity_answers_no_measurement() {
        let (_dir, _root, binary) = fake_proc(15, b"\x7fELF");
        assert!(measure_verity(&File::open(&binary).unwrap()).is_none());
    }
}
