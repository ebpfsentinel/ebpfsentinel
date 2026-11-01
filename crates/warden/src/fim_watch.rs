//! Watching filesystems for changes, on the agent's behalf.
//!
//! One fanotify notification group, marked on whole filesystems and reporting
//! each change as the directory's file handle plus the entry's name. Marking a
//! filesystem needs `CAP_SYS_ADMIN` and opening a file handle needs
//! `CAP_DAC_READ_SEARCH`; the rootless agent holds neither, so the warden holds
//! the group, resolves every handle to a path it can reach, and hands the agent
//! the writer's pid, the event bits, the directory, the name and the entry's
//! `(dev, ino)`. A handle never leaves this module.
//!
//! The group is a notification group: it reports after the fact and can delay
//! or refuse nothing. An overlay refuses a filesystem mark, so a container's
//! writes are watched on the filesystem under it, where they land in the upper
//! directory under the writer's own host pid.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ebpfsentinel_warden_proto::{FimCanary, FimEvent, FimMark};

/// A file was read.
pub const FAN_ACCESS: u64 = 0x0000_0001;
/// The attributes of an entry changed: mode, owner, times or an extended
/// attribute.
pub const FAN_ATTRIB: u64 = 0x0000_0004;
/// A file opened for writing was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// A file was opened.
pub const FAN_OPEN: u64 = 0x0000_0020;
/// An entry was moved out of the directory.
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;
/// An entry was moved into the directory.
pub const FAN_MOVED_TO: u64 = 0x0000_0080;
/// An entry was created in the directory.
pub const FAN_CREATE: u64 = 0x0000_0100;
/// An entry was deleted from the directory.
pub const FAN_DELETE: u64 = 0x0000_0200;
/// The kernel's queue overflowed and events were dropped.
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
/// An entry was renamed, reported once with both names.
pub const FAN_RENAME: u64 = 0x1000_0000;
/// The entry is a directory.
pub const FAN_ONDIR: u64 = 0x4000_0000;

/// What the group asks for. `FAN_CLOSE_WRITE` rather than `FAN_MODIFY`: one
/// event per write session instead of one per `write(2)`, which is what keeps
/// a log being appended to from drowning every other change. `FAN_RENAME`
/// rides beside the two halves of a move, since it is the one event naming
/// both ends; a filesystem refusing it is marked without it, and its renames
/// read as a disappearance plus an appearance.
pub const FIM_MASK: u64 = FAN_ATTRIB
    | FAN_CLOSE_WRITE
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
    | FAN_CREATE
    | FAN_DELETE
    | FAN_RENAME
    | FAN_ONDIR;

/// What a canary is watched for: any open and any read, whatever the access
/// mode, which only a mark on the file itself can ask for without costing
/// every open on the filesystem.
pub const CANARY_MASK: u64 = FAN_OPEN | FAN_ACCESS;

/// Canaries one watch may plant.
pub const FIM_CANARIES_MAX: usize = 512;

/// What a canary holds. It says what the file is, so an operator who finds
/// one knows to leave it; a process that reads this far has already opened
/// it, which is the event.
pub const CANARY_CONTENT: &[u8] = b"This file is a canary planted by the eBPFsentinel agent.\n\
Any process that opens it is reported. Leave it where it is.\n";

/// The mode a canary is created with: readable by everyone, so a reading
/// process fires whoever it runs as, and writable by its owner only.
const CANARY_MODE: libc::c_uint = 0o644;

/// The longest a read waits for a first event. Below the client's own call
/// timeout, so a quiet filesystem answers with nothing instead of costing the
/// agent its connection.
pub const FIM_READ_WAIT_MAX: Duration = Duration::from_secs(2);

/// Events handed over by one read at most, so one answer stays well inside a
/// frame; whatever is left stays queued in the kernel for the next read.
pub const FIM_READ_EVENTS_MAX: usize = 2_048;

/// Paths one watch may name.
pub const FIM_PATHS_MAX: usize = 64;

/// Resolved directories remembered, by handle.
const DIR_CACHE_MAX: usize = 4_096;

/// Bytes read from the group in one `read(2)`.
const READ_BUF_LEN: usize = 64 * 1024;

const FAN_CLASS_NOTIF: libc::c_uint = 0x0000_0000;
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_NONBLOCK: libc::c_uint = 0x0000_0002;
const FAN_REPORT_DFID_NAME: libc::c_uint = 0x0000_0c00;
const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_MARK_DONT_FOLLOW: libc::c_uint = 0x0000_0004;
const FAN_MARK_FILESYSTEM: libc::c_uint = 0x0000_0100;

const METADATA_LEN: usize = 24;
const METADATA_VERSION: u8 = 3;
const INFO_HEADER_LEN: usize = 4;
const INFO_TYPE_DFID_NAME: u8 = 2;
const INFO_TYPE_DFID: u8 = 3;
const INFO_TYPE_OLD_DFID_NAME: u8 = 10;
const INFO_TYPE_NEW_DFID_NAME: u8 = 12;
pub(crate) const FSID_LEN: usize = 8;
const HANDLE_HEADER_LEN: usize = 8;

/// One event as the kernel queued it, its directory still a handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEvent {
    /// The event bits.
    pub mask: u64,
    /// The writing thread group in the reader's pid namespace, `0` when the
    /// kernel could not name it there.
    pub pid: u32,
    /// The filesystem identifier the handle belongs to.
    pub fsid: [u8; FSID_LEN],
    /// The handle's type, as `name_to_handle_at` would give it.
    pub handle_type: i32,
    /// The handle's opaque bytes.
    pub handle: Vec<u8>,
    /// The entry inside the directory, empty when the record named none.
    pub name: String,
    /// For a rename, the directory and name the entry left, the event itself
    /// naming where it arrived.
    pub from: Option<Box<RawEvent>>,
}

/// What [`parse_events`] found in one buffer.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    /// The events carrying a directory handle.
    pub events: Vec<RawEvent>,
    /// The kernel reported its queue overflowed.
    pub overflowed: bool,
}

fn u16_at(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(buf.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

fn i32_at(buf: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_ne_bytes(buf.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(buf: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(buf.get(at..at + 8)?.try_into().ok()?))
}

/// Parse the events one `read(2)` of a group initialised with
/// `FAN_REPORT_DFID_NAME` returned.
///
/// Pure, so the layout is asserted without a kernel. A record that does not
/// fit its own length ends the parse rather than reading past it, and an event
/// of an unknown metadata version is skipped by its length.
pub fn parse_events(buf: &[u8]) -> Parsed {
    let mut parsed = Parsed::default();
    let mut at = 0;
    while let (Some(event_len), Some(version), Some(meta_len)) = (
        u32_at(buf, at),
        buf.get(at + 4).copied(),
        u16_at(buf, at + 6),
    ) {
        let event_len = event_len as usize;
        let meta_len = usize::from(meta_len);
        let Some(event) = buf.get(at..at + event_len) else {
            break;
        };
        if event_len < METADATA_LEN || meta_len < METADATA_LEN || meta_len > event_len {
            break;
        }
        if version == METADATA_VERSION {
            parse_one(event, meta_len, &mut parsed);
        }
        at += event_len;
    }
    parsed
}

fn parse_one(event: &[u8], meta_len: usize, parsed: &mut Parsed) {
    let (Some(mask), Some(pid)) = (u64_at(event, 8), i32_at(event, 20)) else {
        return;
    };
    if mask & FAN_Q_OVERFLOW != 0 {
        parsed.overflowed = true;
        return;
    }
    let pid = u32::try_from(pid).unwrap_or(0);
    let mut info = meta_len;
    let (mut old, mut new) = (None, None);
    while let (Some(info_type), Some(info_len)) =
        (event.get(info).copied(), u16_at(event, info + 2))
    {
        let info_len = usize::from(info_len);
        let Some(record) = event.get(info..info + info_len) else {
            return;
        };
        if info_len < INFO_HEADER_LEN {
            return;
        }
        match info_type {
            INFO_TYPE_DFID_NAME | INFO_TYPE_DFID if mask & FAN_RENAME == 0 => {
                if let Some(raw) =
                    parse_fid_record(record, mask, pid, info_type == INFO_TYPE_DFID_NAME)
                {
                    parsed.events.push(raw);
                    return;
                }
            }
            INFO_TYPE_OLD_DFID_NAME => old = parse_fid_record(record, mask, pid, true),
            INFO_TYPE_NEW_DFID_NAME => new = parse_fid_record(record, mask, pid, true),
            _ => {}
        }
        info += info_len;
    }
    // A rename is kept where it names its new end; the old end alone says
    // nothing the separate `FAN_MOVED_FROM` does not.
    if let Some(mut raw) = new {
        raw.from = old.map(Box::new);
        parsed.events.push(raw);
    }
}

fn parse_fid_record(record: &[u8], mask: u64, pid: u32, named: bool) -> Option<RawEvent> {
    let fsid: [u8; FSID_LEN] = record
        .get(INFO_HEADER_LEN..INFO_HEADER_LEN + FSID_LEN)?
        .try_into()
        .ok()?;
    let handle_at = INFO_HEADER_LEN + FSID_LEN;
    let handle_bytes = u32_at(record, handle_at)? as usize;
    let handle_type = i32_at(record, handle_at + 4)?;
    let bytes_at = handle_at + HANDLE_HEADER_LEN;
    let handle = record.get(bytes_at..bytes_at + handle_bytes)?.to_vec();
    let name = if named {
        let rest = record.get(bytes_at + handle_bytes..)?;
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        String::from_utf8_lossy(&rest[..end]).into_owned()
    } else {
        String::new()
    };
    Some(RawEvent {
        mask,
        pid,
        fsid,
        handle_type,
        handle,
        name,
        from: None,
    })
}

/// Why a mark was refused, in the words an operator acts on.
fn mark_refusal(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(libc::EOPNOTSUPP) => "this filesystem cannot report file handles (an overlay or a \
             pseudo filesystem): watch the filesystem beneath it"
            .to_owned(),
        Some(libc::EXDEV) => "this path is a subvolume whose identifier differs from its \
             filesystem's: watch the top-level subvolume"
            .to_owned(),
        Some(libc::ENODEV) => {
            "this filesystem has no identifier to report changes under".to_owned()
        }
        Some(libc::EPERM) => {
            "the warden does not hold CAP_SYS_ADMIN in the initial user namespace".to_owned()
        }
        Some(libc::ENOENT) => "no such path".to_owned(),
        _ => err.to_string(),
    }
}

/// The filesystem identifier of the filesystem holding `fd`, in the bytes the
/// kernel puts in an event.
pub(crate) fn fsid_of(fd: RawFd) -> io::Result<[u8; FSID_LEN]> {
    let mut st = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `fd` is an open descriptor owned by the caller and `st` points to
    // a `statfs` the call fills in.
    let rc = unsafe { libc::fstatfs(fd, st.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstatfs` returned 0, so it wrote the whole structure.
    let st = unsafe { st.assume_init() };
    // SAFETY: `fsid_t` is two `c_int`, exactly eight bytes, which the
    // size-checked transmute asserts at compile time; it is the same value the
    // kernel copies into an event's fsid.
    Ok(unsafe { std::mem::transmute::<libc::fsid_t, [u8; FSID_LEN]>(st.f_fsid) })
}

/// Why a canary was not planted, in the words an operator acts on.
fn canary_refusal(err: &io::Error) -> String {
    match err.raw_os_error() {
        Some(libc::ENOENT) => "no such directory".to_owned(),
        Some(libc::EACCES) => "the warden may not create a file in this directory: it holds \
             no CAP_DAC_OVERRIDE, so only a directory its own uid can write to is seeded"
            .to_owned(),
        Some(libc::EROFS) => "the filesystem is read-only".to_owned(),
        Some(libc::ELOOP) => "a symbolic link stands at this path".to_owned(),
        _ => err.to_string(),
    }
}

/// Create the canary at `path`, or accept the one already there.
///
/// # Errors
///
/// The reason no canary stands at `path`: the directory refused the file, or
/// something other than a canary already holds the name.
pub fn place_canary(path: &Path) -> Result<(), String> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| "the path holds a NUL byte".to_owned())?;
    // SAFETY: `c` is a NUL-terminated path that outlives the call, and the
    // mode is passed because `O_CREAT` reads it.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            CANARY_MODE,
        )
    };
    if fd >= 0 {
        // SAFETY: `open` returned a fresh descriptor nothing else owns.
        let mut file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        return file
            .write_all(CANARY_CONTENT)
            .map_err(|e| format!("the canary could not be written: {e}"));
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EEXIST) {
        return Err(canary_refusal(&err));
    }
    // A name already taken is kept only when it holds a canary: a file of the
    // operator's own under that name would otherwise raise an alert each time
    // its owner opened it.
    let fd = open_path(path, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .map_err(|e| canary_refusal(&e))?;
    let mut file = File::from(fd);
    let regular = file.metadata().is_ok_and(|m| m.is_file());
    let mut held = Vec::with_capacity(CANARY_CONTENT.len() + 1);
    let read = (&mut file)
        .take(CANARY_CONTENT.len() as u64 + 1)
        .read_to_end(&mut held);
    if regular && read.is_ok() && held == CANARY_CONTENT {
        Ok(())
    } else {
        Err("a file the agent did not plant already holds this name".to_owned())
    }
}

pub(crate) fn open_path(path: &Path, flags: libc::c_int) -> io::Result<OwnedFd> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: `c` is a NUL-terminated path that outlives the call.
    let fd = unsafe { libc::open(c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `open` returned a fresh descriptor nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// A directory handle as the cache keys it: filesystem, handle type, bytes.
type HandleKey = ([u8; FSID_LEN], i32, Vec<u8>);

/// A fanotify group and the filesystems it is marked on.
pub struct FimWatch {
    group: OwnedFd,
    /// One descriptor per marked filesystem, by its identifier: the mount a
    /// handle on that filesystem is opened against.
    mounts: HashMap<[u8; FSID_LEN], OwnedFd>,
    /// Directories already named, by `(fsid, handle type, handle)`.
    dirs: HashMap<HandleKey, PathBuf>,
    /// The canaries planted, by path. Their opens by this process are its
    /// own reading and planting, never reported.
    canaries: HashSet<PathBuf>,
    /// This process, as the group reports it.
    own_pid: u32,
    buf: Vec<u8>,
}

impl FimWatch {
    /// Open a group and mark the filesystem holding each of `paths`.
    ///
    /// Answers one [`FimMark`] per path, in order, and a watch when at least
    /// one mark took. A path that cannot be marked costs that path only.
    pub fn open(paths: &[String]) -> (Option<Self>, Vec<FimMark>) {
        if paths.len() > FIM_PATHS_MAX {
            let error = Some(format!("at most {FIM_PATHS_MAX} paths may be watched"));
            let marks = paths
                .iter()
                .map(|path| FimMark {
                    path: path.clone(),
                    error: error.clone(),
                    renames: false,
                })
                .collect();
            return (None, marks);
        }
        // SAFETY: plain flags, no pointer.
        let fd = unsafe {
            libc::fanotify_init(
                FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_DFID_NAME,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC).cast_unsigned(),
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            let reason = match err.raw_os_error() {
                Some(libc::EPERM) => {
                    "the warden does not hold CAP_SYS_ADMIN in the initial user namespace"
                        .to_owned()
                }
                Some(libc::EINVAL) => {
                    "this kernel cannot report directory handles with names".to_owned()
                }
                _ => format!("fanotify group refused: {err}"),
            };
            let marks = paths
                .iter()
                .map(|path| FimMark {
                    path: path.clone(),
                    error: Some(reason.clone()),
                    renames: false,
                })
                .collect();
            return (None, marks);
        }
        // SAFETY: `fanotify_init` returned a fresh descriptor nothing else owns.
        let group = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut watch = Self {
            group,
            mounts: HashMap::new(),
            dirs: HashMap::new(),
            canaries: HashSet::new(),
            own_pid: std::process::id(),
            buf: vec![0; READ_BUF_LEN],
        };
        let marks: Vec<FimMark> = paths
            .iter()
            .map(|path| match watch.mark(Path::new(path)) {
                Ok(renames) => FimMark {
                    path: path.clone(),
                    error: None,
                    renames,
                },
                Err(error) => FimMark {
                    path: path.clone(),
                    error: Some(error),
                    renames: false,
                },
            })
            .collect();
        let watch = (!watch.mounts.is_empty()).then_some(watch);
        (watch, marks)
    }

    /// Mark the filesystem holding `path`, answering whether its renames are
    /// reported with both names.
    fn mark(&mut self, path: &Path) -> Result<bool, String> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "the path holds a NUL byte".to_owned())?;
        let renames = match self.mark_with(&c, FIM_MASK) {
            Ok(()) => true,
            // A kernel without `FAN_RENAME` refuses the whole mask as invalid,
            // and the rest of it is still worth having.
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                self.mark_with(&c, FIM_MASK & !FAN_RENAME)
                    .map_err(|e| mark_refusal(&e))?;
                false
            }
            Err(e) => return Err(mark_refusal(&e)),
        };
        let mount = open_path(path, libc::O_PATH).map_err(|e| mark_refusal(&e))?;
        let fsid = fsid_of(mount.as_raw_fd()).map_err(|e| e.to_string())?;
        self.mounts.entry(fsid).or_insert(mount);
        Ok(renames)
    }

    fn mark_with(&self, path: &CString, mask: u64) -> io::Result<()> {
        // SAFETY: the group is open and `path` is a NUL-terminated path that
        // outlives the call.
        let rc = unsafe {
            libc::fanotify_mark(
                self.group.as_raw_fd(),
                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                mask,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// Plant a canary at each of `paths` and mark it for any open or read.
    ///
    /// Answers one [`FimCanary`] per path, in order. A path that cannot be
    /// planted or marked costs that path only.
    pub fn plant(&mut self, paths: &[String]) -> Vec<FimCanary> {
        if paths.len() > FIM_CANARIES_MAX {
            let error = Some(format!(
                "at most {FIM_CANARIES_MAX} canaries may be planted"
            ));
            return paths
                .iter()
                .map(|path| FimCanary {
                    path: path.clone(),
                    error: error.clone(),
                })
                .collect();
        }
        paths
            .iter()
            .map(|path| FimCanary {
                path: path.clone(),
                error: self.plant_one(Path::new(path)).err(),
            })
            .collect()
    }

    fn plant_one(&mut self, path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err("not an absolute path".to_owned());
        }
        let parent = path
            .parent()
            .filter(|p| p.file_name().is_some() || p == &Path::new("/"))
            .ok_or_else(|| "the path names no file".to_owned())?;
        let dir =
            open_path(parent, libc::O_PATH | libc::O_DIRECTORY).map_err(|e| canary_refusal(&e))?;
        let fsid = fsid_of(dir.as_raw_fd()).map_err(|e| e.to_string())?;
        if !self.covers(fsid) {
            return Err("the directory is on a filesystem this watch did not mark".to_owned());
        }
        // Held before the file exists, so its creation, read on this same
        // group, is already known as the warden's own.
        let fresh = self.canaries.insert(path.to_path_buf());
        if let Err(reason) = place_canary(path) {
            if fresh {
                self.canaries.remove(path);
            }
            return Err(reason);
        }
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| "the path holds a NUL byte".to_owned())?;
        // SAFETY: the group is open and `c` is a NUL-terminated path that
        // outlives the call.
        let rc = unsafe {
            libc::fanotify_mark(
                self.group.as_raw_fd(),
                FAN_MARK_ADD | FAN_MARK_DONT_FOLLOW,
                CANARY_MASK,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(mark_refusal(&io::Error::last_os_error()))
        }
    }

    /// Whether `event` is this process reading or planting one of its own
    /// canaries.
    fn own_canary(&self, event: &FimEvent) -> bool {
        event.pid == self.own_pid
            && event
                .directory
                .as_deref()
                .is_some_and(|dir| self.canaries.contains(&Path::new(dir).join(&event.name)))
    }

    /// Whether the filesystem `fsid` names is one this watch marked.
    #[must_use]
    pub fn covers(&self, fsid: [u8; FSID_LEN]) -> bool {
        self.mounts.contains_key(&fsid)
    }

    /// Hand over what the group queued, waiting at most `max_wait` (capped by
    /// [`FIM_READ_WAIT_MAX`]) for a first event.
    ///
    /// # Errors
    ///
    /// Returns the reason when the group itself cannot be read.
    pub fn read(&mut self, max_wait: Duration) -> Result<(Vec<FimEvent>, bool), String> {
        let wait = max_wait.min(FIM_READ_WAIT_MAX);
        let mut pfd = libc::pollfd {
            fd: self.group.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
        // SAFETY: `pfd` is one valid pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, millis) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok((Vec::new(), false));
            }
            return Err(format!("waiting on the file watch failed: {err}"));
        }
        let mut events = Vec::new();
        let mut overflowed = false;
        while events.len() < FIM_READ_EVENTS_MAX {
            // SAFETY: the group is open and `buf` is writable for its length.
            let n = unsafe {
                libc::read(
                    self.group.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EAGAIN | libc::EINTR) => break,
                    _ => return Err(format!("reading the file watch failed: {err}")),
                }
            }
            let len = usize::try_from(n).unwrap_or(0);
            if len == 0 {
                break;
            }
            let parsed = parse_events(&self.buf[..len]);
            overflowed |= parsed.overflowed;
            for raw in parsed.events {
                let event = self.resolve(&raw);
                if !self.own_canary(&event) {
                    events.push(event);
                }
            }
        }
        Ok((events, overflowed))
    }

    fn resolve(&mut self, raw: &RawEvent) -> FimEvent {
        let directory = self.directory(raw);
        let renamed_from = raw.from.as_deref().and_then(|old| {
            self.directory(old)
                .ok()
                .map(|dir| dir.join(&old.name).to_string_lossy().into_owned())
        });
        // A directory moved or deleted renames everything cached beneath it.
        if raw.mask & FAN_ONDIR != 0
            && raw.mask & (FAN_MOVED_FROM | FAN_MOVED_TO | FAN_DELETE | FAN_RENAME) != 0
        {
            self.dirs.clear();
        }
        let (dev, ino) = match &directory {
            Ok(dir) if !raw.name.is_empty() => std::fs::symlink_metadata(dir.join(&raw.name))
                .map_or((None, None), |m| (Some(m.dev()), Some(m.ino()))),
            _ => (None, None),
        };
        let (directory, unresolved) = match directory {
            Ok(dir) => (Some(dir.to_string_lossy().into_owned()), None),
            Err(reason) => (None, Some(reason)),
        };
        FimEvent {
            mask: raw.mask,
            pid: raw.pid,
            directory,
            name: raw.name.clone(),
            dev,
            ino,
            unresolved,
            renamed_from,
        }
    }

    fn directory(&mut self, raw: &RawEvent) -> Result<PathBuf, String> {
        let key = (raw.fsid, raw.handle_type, raw.handle.clone());
        if let Some(hit) = self.dirs.get(&key) {
            return Ok(hit.clone());
        }
        let resolved = self.open_handle(raw);
        // A directory that could not be named now may be nameable on the next
        // event, so only a success is remembered.
        if let Ok(dir) = &resolved {
            if self.dirs.len() >= DIR_CACHE_MAX {
                self.dirs.clear();
            }
            self.dirs.insert(key, dir.clone());
        }
        resolved
    }

    fn open_handle(&self, raw: &RawEvent) -> Result<PathBuf, String> {
        let Some(mount) = self.mounts.get(&raw.fsid) else {
            return Err("the change is on a filesystem this watch did not mark".to_owned());
        };
        let handle_bytes = u32::try_from(raw.handle.len())
            .map_err(|_| "the file handle is too large".to_owned())?;
        // `struct file_handle` is two 32-bit words then the bytes, so the
        // buffer is built in words to carry the structure's alignment.
        let mut words = vec![0u32; 2 + raw.handle.len().div_ceil(4)];
        words[0] = handle_bytes;
        words[1] = raw.handle_type.cast_unsigned();
        for (word, chunk) in words[2..].iter_mut().zip(raw.handle.chunks(4)) {
            let mut four = [0u8; 4];
            four[..chunk.len()].copy_from_slice(chunk);
            *word = u32::from_ne_bytes(four);
        }
        // SAFETY: `words` is a 4-byte aligned buffer laid out as a
        // `file_handle` whose `handle_bytes` matches the bytes that follow it,
        // and the mount descriptor is open for the call.
        let fd = unsafe {
            libc::open_by_handle_at(
                mount.as_raw_fd(),
                words.as_mut_ptr().cast::<libc::file_handle>(),
                libc::O_PATH | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = io::Error::last_os_error();
            return Err(match err.raw_os_error() {
                Some(libc::ESTALE) => "the directory is gone".to_owned(),
                Some(libc::EPERM) => {
                    "the warden does not hold CAP_DAC_READ_SEARCH to open the handle".to_owned()
                }
                _ => format!("the directory handle did not open: {err}"),
            });
        }
        // SAFETY: `open_by_handle_at` returned a fresh descriptor nothing else
        // owns.
        let dir = unsafe { OwnedFd::from_raw_fd(fd) };
        let link = format!("/proc/self/fd/{}", dir.as_raw_fd());
        std::fs::read_link(&link).map_err(|e| format!("the directory could not be named: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        info_type: u8,
        fsid: [u8; 8],
        handle_type: i32,
        handle: &[u8],
        name: &str,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&fsid);
        body.extend_from_slice(&u32::try_from(handle.len()).expect("small").to_ne_bytes());
        body.extend_from_slice(&handle_type.to_ne_bytes());
        body.extend_from_slice(handle);
        if info_type != INFO_TYPE_DFID {
            body.extend_from_slice(name.as_bytes());
            body.push(0);
        }
        while !(body.len() + INFO_HEADER_LEN).is_multiple_of(4) {
            body.push(0);
        }
        let mut rec = vec![info_type, 0];
        rec.extend_from_slice(
            &u16::try_from(body.len() + INFO_HEADER_LEN)
                .expect("small")
                .to_ne_bytes(),
        );
        rec.extend_from_slice(&body);
        rec
    }

    fn event(version: u8, mask: u64, pid: i32, info: &[u8]) -> Vec<u8> {
        let len = METADATA_LEN + info.len();
        let mut ev = Vec::new();
        ev.extend_from_slice(&u32::try_from(len).expect("small").to_ne_bytes());
        ev.push(version);
        ev.push(0);
        ev.extend_from_slice(&u16::try_from(METADATA_LEN).expect("small").to_ne_bytes());
        ev.extend_from_slice(&mask.to_ne_bytes());
        ev.extend_from_slice(&(-1i32).to_ne_bytes());
        ev.extend_from_slice(&pid.to_ne_bytes());
        ev.extend_from_slice(info);
        ev
    }

    #[test]
    fn a_named_record_carries_the_writer_the_handle_and_the_name() {
        let fsid = [1, 2, 3, 4, 5, 6, 7, 8];
        let rec = record(
            INFO_TYPE_DFID_NAME,
            fsid,
            1,
            &[9, 9, 9, 9, 9, 9, 9, 9],
            "passwd",
        );
        let buf = event(METADATA_VERSION, FAN_CLOSE_WRITE, 4242, &rec);
        let parsed = parse_events(&buf);
        assert!(!parsed.overflowed);
        assert_eq!(
            parsed.events,
            vec![RawEvent {
                mask: FAN_CLOSE_WRITE,
                pid: 4242,
                fsid,
                handle_type: 1,
                handle: vec![9; 8],
                name: "passwd".to_owned(),
                from: None,
            }]
        );
    }

    #[test]
    fn a_rename_carries_the_name_it_left_and_the_name_it_took() {
        let old = record(INFO_TYPE_OLD_DFID_NAME, [0; 8], 1, &[1; 8], "report.docx");
        let new = record(
            INFO_TYPE_NEW_DFID_NAME,
            [0; 8],
            1,
            &[2; 8],
            "report.docx.locked",
        );
        let mut info = old;
        info.extend(new);
        let buf = event(METADATA_VERSION, FAN_RENAME, 77, &info);
        let parsed = parse_events(&buf);
        assert_eq!(parsed.events.len(), 1);
        let raw = &parsed.events[0];
        assert_eq!(raw.name, "report.docx.locked");
        assert_eq!(raw.handle, vec![2; 8]);
        let from = raw.from.as_deref().expect("the old end");
        assert_eq!(from.name, "report.docx");
        assert_eq!(from.handle, vec![1; 8]);
        // A rename naming only where it left is the separate move-out's to
        // report, and is not kept.
        let only_old = record(INFO_TYPE_OLD_DFID_NAME, [0; 8], 1, &[1; 8], "a");
        assert!(
            parse_events(&event(METADATA_VERSION, FAN_RENAME, 1, &only_old))
                .events
                .is_empty()
        );
    }

    #[test]
    fn several_events_in_one_buffer_are_read_in_order() {
        let a = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[1; 8], "a");
        let b = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[2; 12], "bb");
        let mut buf = event(METADATA_VERSION, FAN_CREATE, 1, &a);
        buf.extend(event(METADATA_VERSION, FAN_DELETE | FAN_ONDIR, 2, &b));
        let parsed = parse_events(&buf);
        let names: Vec<_> = parsed.events.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["a", "bb"]);
        assert_eq!(parsed.events[1].mask, FAN_DELETE | FAN_ONDIR);
        assert_eq!(parsed.events[1].handle.len(), 12);
    }

    #[test]
    fn an_overflow_is_reported_and_carries_no_event() {
        let buf = event(METADATA_VERSION, FAN_Q_OVERFLOW, 0, &[]);
        let parsed = parse_events(&buf);
        assert!(parsed.overflowed);
        assert!(parsed.events.is_empty());
    }

    #[test]
    fn a_pid_the_reader_cannot_see_is_zero() {
        let rec = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[1; 8], "x");
        let buf = event(METADATA_VERSION, FAN_ATTRIB, 0, &rec);
        assert_eq!(parse_events(&buf).events[0].pid, 0);
    }

    #[test]
    fn a_directory_record_without_a_name_is_kept_with_an_empty_name() {
        let rec = record(INFO_TYPE_DFID, [0; 8], 1, &[1; 8], "");
        let buf = event(METADATA_VERSION, FAN_ATTRIB | FAN_ONDIR, 7, &rec);
        let parsed = parse_events(&buf);
        assert_eq!(parsed.events.len(), 1);
        assert!(parsed.events[0].name.is_empty());
    }

    #[test]
    fn an_unknown_version_is_skipped_by_its_length() {
        let rec = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[1; 8], "skipped");
        let kept = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[1; 8], "kept");
        let mut buf = event(METADATA_VERSION + 1, FAN_CREATE, 1, &rec);
        buf.extend(event(METADATA_VERSION, FAN_CREATE, 1, &kept));
        let names: Vec<_> = parse_events(&buf)
            .events
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(names, ["kept"]);
    }

    #[test]
    fn a_truncated_buffer_ends_the_parse_without_reading_past_it() {
        let rec = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[1; 8], "whole");
        let mut buf = event(METADATA_VERSION, FAN_CREATE, 1, &rec);
        let second = event(METADATA_VERSION, FAN_CREATE, 1, &rec);
        buf.extend_from_slice(&second[..second.len() - 3]);
        let parsed = parse_events(&buf);
        assert_eq!(parsed.events.len(), 1);
        // A handle length past the record is refused rather than trusted.
        let mut lying = record(INFO_TYPE_DFID_NAME, [0; 8], 1, &[1; 8], "x");
        lying[INFO_HEADER_LEN + FSID_LEN..INFO_HEADER_LEN + FSID_LEN + 4]
            .copy_from_slice(&4096u32.to_ne_bytes());
        assert!(
            parse_events(&event(METADATA_VERSION, FAN_CREATE, 1, &lying))
                .events
                .is_empty()
        );
    }

    #[test]
    fn a_length_shorter_than_the_metadata_stops_the_parse() {
        let mut buf = event(METADATA_VERSION, FAN_CREATE, 1, &[]);
        buf[0..4].copy_from_slice(&8u32.to_ne_bytes());
        assert_eq!(parse_events(&buf), Parsed::default());
        assert_eq!(parse_events(&[]), Parsed::default());
    }

    #[test]
    fn every_refusal_names_what_to_do() {
        let overlay = mark_refusal(&io::Error::from_raw_os_error(libc::EOPNOTSUPP));
        assert!(overlay.contains("beneath"));
        let subvolume = mark_refusal(&io::Error::from_raw_os_error(libc::EXDEV));
        assert!(subvolume.contains("top-level"));
        let perm = mark_refusal(&io::Error::from_raw_os_error(libc::EPERM));
        assert!(perm.contains("CAP_SYS_ADMIN"));
    }

    #[test]
    fn too_many_paths_are_refused_whole_before_a_group_exists() {
        let paths: Vec<String> = (0..=FIM_PATHS_MAX).map(|i| format!("/p{i}")).collect();
        let (watch, marks) = FimWatch::open(&paths);
        assert!(watch.is_none());
        assert_eq!(marks.len(), paths.len());
        assert!(marks.iter().all(|m| m.error.is_some()));
    }

    #[test]
    fn a_missing_path_costs_that_path_only() {
        let (_, marks) = FimWatch::open(&["/no/such/path/anywhere".to_owned()]);
        assert_eq!(marks.len(), 1);
        assert!(marks[0].error.is_some());
    }

    #[test]
    fn a_canary_is_planted_once_and_a_foreign_file_is_never_taken() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("0000-archive.docx");
        place_canary(&path).expect("planted");
        assert_eq!(std::fs::read(&path).expect("read"), CANARY_CONTENT);
        // Planting again accepts the canary already there.
        place_canary(&path).expect("kept");
        let foreign = dir.path().join("notes.txt");
        std::fs::write(&foreign, b"the operator's own").expect("write");
        assert!(place_canary(&foreign).is_err());
        let link = dir.path().join("link.docx");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(place_canary(&link).is_err());
        assert_eq!(
            place_canary(&dir.path().join("missing/x.docx")),
            Err("no such directory".to_owned())
        );
    }

    #[test]
    fn a_canary_is_watched_for_any_open_or_read_and_nothing_on_the_filesystem_is() {
        assert_eq!(CANARY_MASK, FAN_OPEN | FAN_ACCESS);
        assert_eq!(FIM_MASK & CANARY_MASK, 0);
    }

    #[test]
    fn the_mask_asks_for_one_event_per_write_session() {
        assert_eq!(FIM_MASK & FAN_CLOSE_WRITE, FAN_CLOSE_WRITE);
        // FAN_MODIFY fires on every write(2).
        assert_eq!(FIM_MASK & 0x2, 0);
    }
}
