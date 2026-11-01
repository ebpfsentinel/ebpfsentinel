//! The write refusal where the BPF LSM is not active: a fanotify permission
//! group on a bounded set of inodes.
//!
//! One group of class `FAN_CLASS_CONTENT`, apart from the notification group
//! the file watch runs, since the permission classes refuse the reporting
//! flags. Every mark is an inode mark on a watched file or on a directory
//! beneath a watched path, never a filesystem or a mount mark, which would
//! put the agent in the path of every open on the node. The set is walked,
//! counted against [`WRITE_REFUSAL_FALLBACK_MARKS`] and against the kernel's
//! own per-user ceiling before the first mark is placed.
//!
//! A permission class needs `CAP_SYS_ADMIN` in the initial user namespace
//! and the opener's pending system call sits behind a ptrace check, so a
//! rootless agent asks the warden for both: the warden opens the group and
//! hands over its only descriptor, and reads each batch of openers in one
//! round trip. An agent holding the privilege does both in-process with the
//! same code.
//!
//! An open on a marked inode waits for the agent's answer. To decide, the
//! handler reads `/proc` and `/sys/fs/cgroup` and nothing else, and refuses
//! to watch a path under either, because a handler that opened a watched
//! file would wait on its own answer. What it reads: the opener's pending
//! system call, which carries the open flags the event does not, its thread
//! group, its executable and its cgroup. The answers to everything read at
//! once are bounded by [`WRITE_REFUSAL_REPLY_BUDGET_MS`]; past it the rest
//! are allowed undecided.
//!
//! The group's descriptor belongs to the handler's thread alone. Stopping the
//! thread closes it, and the kernel then allows every open still waiting:
//! the route fails open, the same way the agent's death does.

#![allow(unsafe_code)] // fanotify has no safe binding: init, mark, read and the reply are raw syscalls

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use domain::ransom::{
    CountBy, WRITE_REFUSAL_FALLBACK_MARKS, WRITE_REFUSAL_REPLY_BUDGET_MS, WRITE_REFUSAL_WRITERS,
    WriteCount, WriteOpenCounter, WriteRefusalHook, WriteRefusalRecord, WriteRefusalRegime,
    WriteRefusalRoute,
};
pub use ebpfsentinel_warden_client::OpenerReading;
use ebpfsentinel_warden_client::{OpenIntent, ReconnectingClient, WardenClient};
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::ebpf::ringbuf_observer::boottime_now_ns;
use crate::ebpf::write_refusal::{WriteRefusalPolicy, WriteRefusalSet, WriteRefusalStatus};

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The interface label the route's counters are recorded under.
pub const FALLBACK_METRICS: &str = "WRITE_REFUSAL_FALLBACK";

/// What the handler reads to decide. A watched path under one of these
/// would make the handler wait on its own answer.
pub const HANDLER_READS: [&str; 2] = ["/proc", "/sys/fs/cgroup"];

/// How a mark is placed: on the inode named, and only on it.
const MARK_FLAGS: libc::c_uint = libc::FAN_MARK_ADD;

/// What a marked file asks for.
const FILE_MASK: u64 = libc::FAN_OPEN_PERM;

/// What a marked directory asks for: the opens of the files directly in it.
/// Without `FAN_ONDIR`, opening the directory itself is not asked about.
const DIR_MASK: u64 = libc::FAN_OPEN_PERM | libc::FAN_EVENT_ON_CHILD;

/// How long the handler waits for an event before looking at its stop flag
/// and at a new set.
const POLL_MS: libc::c_int = 200;

/// Where the kernel's per-user ceiling on marks is read.
const MAX_USER_MARKS: &str = "/proc/sys/fs/fanotify/max_user_marks";

/// A watched path as the handler compares it: the canonical form an open
/// file's link reads as, beside the form it was configured as.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FallbackPath {
    canonical: PathBuf,
    configured: String,
    regime: WriteRefusalRegime,
}

/// The marks one set needs and what the handler compares an open against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FallbackPlan {
    marks: Vec<(PathBuf, bool)>,
    watched: Vec<FallbackPath>,
    writers: HashSet<(u64, u64)>,
    /// The paths and writers that do not exist here, named.
    pub missing: Vec<String>,
}

impl FallbackPlan {
    /// Walk `set` into the inode marks it needs, at most `bound` of them.
    ///
    /// # Errors
    ///
    /// Returns why the set cannot be held by this route: a path the handler
    /// reads to decide, or more marks than `bound`.
    pub fn walk(set: &WriteRefusalSet, bound: usize) -> Result<Self, String> {
        let mut plan = Self::default();
        let regimes = [
            (WriteRefusalRegime::Data, &set.data),
            (WriteRefusalRegime::System, &set.system),
        ];
        for (regime, paths) in regimes {
            for path in paths {
                let canonical = match std::fs::canonicalize(path) {
                    Ok(c) => c,
                    Err(e) => {
                        plan.missing.push(format!("{path}: {e}"));
                        continue;
                    }
                };
                if let Some(read) = read_by_handler(&canonical) {
                    return Err(format!(
                        "`{path}` lies under {read}, which the fanotify route reads to decide and cannot watch"
                    ));
                }
                plan.mark_tree(&canonical, bound)?;
                plan.watched.push(FallbackPath {
                    canonical,
                    configured: path.clone(),
                    regime,
                });
            }
        }
        for path in &set.writers {
            match std::fs::metadata(path) {
                Ok(meta) if meta.is_file() => {
                    plan.writers.insert((meta.dev(), meta.ino()));
                }
                Ok(_) => plan
                    .missing
                    .push(format!("expected writer {path}: not a regular file")),
                Err(e) => plan.missing.push(format!("expected writer {path}: {e}")),
            }
        }
        plan.marks.sort();
        plan.marks.dedup();
        if plan.marks.len() > bound {
            return Err(too_many(plan.marks.len(), bound));
        }
        Ok(plan)
    }

    /// Mark a watched file, or a watched directory and every directory
    /// beneath it on the same filesystem, symlinks not followed.
    fn mark_tree(&mut self, root: &Path, bound: usize) -> Result<(), String> {
        let meta = std::fs::metadata(root).map_err(|e| format!("{}: {e}", root.display()))?;
        if meta.is_file() {
            self.marks.push((root.to_path_buf(), false));
            return Ok(());
        }
        if !meta.is_dir() {
            return Err(format!(
                "`{}` is neither a directory nor a file",
                root.display()
            ));
        }
        let dev = meta.dev();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            self.marks.push((dir.clone(), true));
            if self.marks.len() > bound {
                return Err(too_many(self.marks.len(), bound));
            }
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else {
                    continue;
                };
                if meta.is_dir() && meta.dev() == dev {
                    stack.push(entry.path());
                }
            }
        }
        Ok(())
    }

    /// How many inode marks the plan places.
    #[must_use]
    pub fn marks(&self) -> usize {
        self.marks.len()
    }

    /// The watched path an opened file lies under, the system regime
    /// winning where both claim it, and the nearest path within a regime.
    fn regime_of(&self, file: &Path) -> Option<&FallbackPath> {
        self.watched
            .iter()
            .filter(|w| file.starts_with(&w.canonical))
            .max_by_key(|w| {
                (
                    w.regime == WriteRefusalRegime::System,
                    w.canonical.as_os_str().len(),
                )
            })
    }

    fn status(&self, enforcing: bool) -> WriteRefusalStatus {
        WriteRefusalStatus {
            attached: true,
            enforcing,
            directories: self.watched.len(),
            system: self
                .watched
                .iter()
                .filter(|w| w.regime == WriteRefusalRegime::System)
                .count(),
            writers: self.writers.len(),
            route: Some(WriteRefusalRoute::Fanotify),
            marks: self.marks.len(),
            reason: None,
        }
    }
}

fn too_many(marks: usize, bound: usize) -> String {
    format!(
        "the watched paths need more than {bound} inode marks ({marks} counted); name narrower paths for the fanotify route"
    )
}

/// Which of the handler's own reads `path` lies under, if any.
#[must_use]
fn read_by_handler(path: &Path) -> Option<&'static str> {
    HANDLER_READS
        .iter()
        .find(|read| path.starts_with(read) || Path::new(read).starts_with(path))
        .copied()
}

/// How many marks this host lets one user place, `None` when it does not
/// say.
fn max_user_marks() -> Option<usize> {
    std::fs::read_to_string(MAX_USER_MARKS)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// The bound a plan is walked against: the route's own, or the kernel's
/// ceiling when that is lower.
#[must_use]
pub fn mark_bound() -> usize {
    max_user_marks().map_or(WRITE_REFUSAL_FALLBACK_MARKS, |kernel| {
        WRITE_REFUSAL_FALLBACK_MARKS.min(kernel)
    })
}

/// Place one inode mark.
fn mark(group: &OwnedFd, path: &Path, dir: bool) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::other("a path holding a NUL byte"))?;
    let mask = if dir { DIR_MASK } else { FILE_MASK };
    // SAFETY: the group is open and `c` is a NUL-terminated path for the
    // duration of the call.
    let rc = unsafe {
        libc::fanotify_mark(
            group.as_raw_fd(),
            MARK_FLAGS,
            mask,
            libc::AT_FDCWD,
            c.as_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replace every inode mark the group holds with the plan's.
fn place(group: &OwnedFd, plan: &FallbackPlan) -> Vec<String> {
    // SAFETY: the group is open; a flush takes no path.
    let rc = unsafe {
        libc::fanotify_mark(
            group.as_raw_fd(),
            libc::FAN_MARK_FLUSH,
            0,
            libc::AT_FDCWD,
            std::ptr::null(),
        )
    };
    let mut failed = Vec::new();
    if rc < 0 {
        failed.push(format!(
            "flushing the previous marks: {}",
            io::Error::last_os_error()
        ));
    }
    for (path, dir) in &plan.marks {
        if let Err(e) = mark(group, path, *dir) {
            failed.push(format!("{}: {e}", path.display()));
        }
    }
    failed
}

/// The counters the route keeps, by the label they are recorded under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Count {
    Checked,
    Watched,
    Refused,
    WouldRefuse,
    Unresolved,
    TableFull,
    Expected,
    Own,
    OverBudget,
}

impl Count {
    fn label(self) -> &'static str {
        match self {
            Self::Checked => "checked",
            Self::Watched => "watched",
            Self::Refused => "refused",
            Self::WouldRefuse => "would_refuse",
            Self::Unresolved => "unresolved",
            Self::TableFull => "table_full",
            Self::Expected => "expected",
            Self::Own => "own",
            Self::OverBudget => "over_budget",
        }
    }
}

/// The labels the route records, every one of them from the first poll.
pub const FALLBACK_LABELS: [&str; 9] = [
    "checked",
    "watched",
    "refused",
    "would_refuse",
    "unresolved",
    "table_full",
    "expected",
    "own",
    "over_budget",
];

/// One permission event as the handler reads it.
#[derive(Debug, Clone, Copy)]
struct PermissionEvent {
    fd: RawFd,
    tid: u32,
}

/// The decision the handler runs per event, apart from the descriptor
/// plumbing so it can be read and tested alone.
struct Decider {
    plan: FallbackPlan,
    counter: WriteOpenCounter,
    enforce: bool,
    count_by: CountBy,
    own_tgid: u32,
}

/// What the handler answers, what it counts and what it reports.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Decision {
    allow: bool,
    counts: Vec<Count>,
    record: Option<WriteRefusalRecord>,
}

impl Decision {
    fn allow(counts: Vec<Count>) -> Self {
        Self {
            allow: true,
            counts,
            record: None,
        }
    }
}

/// The opened file as the event's own descriptor names it.
struct OpenedFile {
    path: PathBuf,
    dev: u64,
    ino: u64,
}

impl Decider {
    fn decide(
        &mut self,
        tid: u32,
        file: Option<&OpenedFile>,
        read: &dyn Fn(u32) -> OpenerReading,
        now_ns: u64,
    ) -> Decision {
        let Some(file) = file else {
            return Decision::allow(vec![Count::Checked, Count::Unresolved]);
        };
        let Some(watched) = self.plan.regime_of(&file.path).cloned() else {
            return Decision::allow(vec![Count::Checked]);
        };
        let opener = read(tid);
        if opener.tgid == 0 {
            return Decision::allow(vec![Count::Checked, Count::Unresolved]);
        }
        if opener.tgid == self.own_tgid {
            return Decision::allow(vec![Count::Checked, Count::Own]);
        }
        match opener.intent {
            OpenIntent::Read => return Decision::allow(vec![Count::Checked]),
            OpenIntent::Unknown => {
                return Decision::allow(vec![Count::Checked, Count::Watched, Count::Unresolved]);
            }
            OpenIntent::Write => {}
        }
        let (refuse, count, report) = match watched.regime {
            WriteRefusalRegime::System => match opener.exe {
                Some(exe) if self.plan.writers.contains(&exe) => {
                    return Decision::allow(vec![Count::Checked, Count::Watched, Count::Expected]);
                }
                Some(_) => (true, 1, true),
                None => {
                    return Decision::allow(vec![
                        Count::Checked,
                        Count::Watched,
                        Count::Unresolved,
                    ]);
                }
            },
            WriteRefusalRegime::Data => {
                let writer = match self.count_by {
                    CountBy::Cgroup if opener.cgroup_id != 0 => opener.cgroup_id,
                    CountBy::Cgroup | CountBy::Process => u64::from(opener.tgid),
                };
                match self.counter.count(writer, now_ns) {
                    WriteCount::Under(_) => {
                        return Decision::allow(vec![Count::Checked, Count::Watched]);
                    }
                    WriteCount::TableFull => {
                        return Decision::allow(vec![
                            Count::Checked,
                            Count::Watched,
                            Count::TableFull,
                        ]);
                    }
                    WriteCount::Reached { count, first } => (true, count, first),
                }
            }
        };
        let refused = refuse && self.enforce;
        let verdict = if refused {
            Count::Refused
        } else {
            Count::WouldRefuse
        };
        let record = report.then(|| WriteRefusalRecord {
            at_ns: now_ns,
            tgid: opener.tgid,
            cgroup_id: opener.cgroup_id,
            file: (file.dev, file.ino),
            name: file
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            directory: Some(watched.configured.clone()),
            count,
            hook: WriteRefusalHook::Open,
            regime: watched.regime,
            refused,
        });
        Decision {
            allow: !refused,
            counts: vec![Count::Checked, Count::Watched, verdict],
            record,
        }
    }
}

/// The opened file, named by the event's descriptor through
/// `/proc/self/fd`, which the kernel opened without asking the group.
fn opened_file(fd: RawFd) -> Option<OpenedFile> {
    let path = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fd` is the event's open descriptor and `st` is writable.
    let rc = unsafe { libc::fstat(fd, st.as_mut_ptr()) };
    if rc < 0 {
        return None;
    }
    // SAFETY: `fstat` succeeded, so it filled `st`.
    let st = unsafe { st.assume_init() };
    Some(OpenedFile {
        path,
        dev: st.st_dev,
        ino: st.st_ino,
    })
}

/// Read the events the group holds; the second half is whether the group
/// can still be read.
fn read_events(group: &OwnedFd, buf: &mut [u8]) -> (Vec<PermissionEvent>, bool) {
    // SAFETY: the group is open and `buf` is writable for its length.
    let n = unsafe { libc::read(group.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        let err = io::Error::last_os_error();
        return (
            Vec::new(),
            matches!(err.raw_os_error(), Some(libc::EAGAIN | libc::EINTR)),
        );
    }
    let len = usize::try_from(n).unwrap_or(0);
    let header = size_of::<libc::fanotify_event_metadata>();
    let mut events = Vec::new();
    let mut at = 0usize;
    while at + header <= len {
        // SAFETY: `header` bytes from `at` lie inside what the kernel wrote,
        // the struct is plain data, and the read is unaligned.
        let meta = unsafe {
            buf.as_ptr()
                .add(at)
                .cast::<libc::fanotify_event_metadata>()
                .read_unaligned()
        };
        let step = usize::try_from(meta.event_len).unwrap_or(0);
        if step < header || meta.vers != libc::FANOTIFY_METADATA_VERSION {
            break;
        }
        if meta.mask & libc::FAN_OPEN_PERM != 0 && meta.fd >= 0 {
            events.push(PermissionEvent {
                fd: meta.fd,
                tid: u32::try_from(meta.pid).unwrap_or(0),
            });
        } else if meta.fd >= 0 {
            // SAFETY: a descriptor the kernel handed over with the event.
            drop(unsafe { OwnedFd::from_raw_fd(meta.fd) });
        }
        at += step;
    }
    (events, true)
}

/// Answer one event and close its descriptor.
fn reply(group: &OwnedFd, fd: RawFd, allow: bool) {
    let response = libc::fanotify_response {
        fd,
        response: if allow {
            libc::FAN_ALLOW
        } else {
            libc::FAN_DENY
        },
    };
    // SAFETY: the group is open and `response` is one plain struct read for
    // its size.
    let rc = unsafe {
        libc::write(
            group.as_raw_fd(),
            (&raw const response).cast(),
            size_of::<libc::fanotify_response>(),
        )
    };
    if rc < 0 {
        debug!(
            "write refusal: answering an open failed: {}",
            io::Error::last_os_error()
        );
    }
    // SAFETY: the event's descriptor, owned by the handler from the read.
    drop(unsafe { OwnedFd::from_raw_fd(fd) });
}

/// The two privileged halves an agent holding `CAP_SYS_ADMIN` runs
/// in-process, with the same code the warden runs for a rootless one.
#[derive(Clone, Copy)]
pub struct LocalRefusal {
    /// Opens the permission group.
    pub group: fn() -> Result<OwnedFd, String>,
    /// Reads the threads blocked on permission events.
    pub read: fn(&[u32]) -> Vec<OpenerReading>,
}

/// Where the handler reads the openers from.
enum Openers {
    Local(fn(&[u32]) -> Vec<OpenerReading>),
    Warden(Box<ReconnectingClient>),
}

impl Openers {
    /// One reading per thread, in order; a warden that cannot answer leaves
    /// every one of them unread, and an unread opener is allowed.
    fn read(&mut self, tids: &[u32]) -> Vec<OpenerReading> {
        if tids.is_empty() {
            return Vec::new();
        }
        match self {
            Self::Local(read) => read(tids),
            Self::Warden(client) => client.opener_readings(tids).unwrap_or_else(|e| {
                debug!("write refusal: the warden could not read the openers: {e}");
                vec![OpenerReading::GONE; tids.len()]
            }),
        }
    }
}

/// Open the group where this agent can: through the warden when it runs
/// rootless, in-process otherwise.
fn open_group(local: LocalRefusal) -> Result<(OwnedFd, Openers), String> {
    match std::env::var_os(WARDEN_SOCK_ENV) {
        Some(sock) => {
            let group = WardenClient::connect(&sock)
                .and_then(|mut c| c.write_refusal_group())
                .map_err(|e| format!("the warden could not open the fanotify group: {e}"))?;
            Ok((
                group,
                Openers::Warden(Box::new(ReconnectingClient::new(sock))),
            ))
        }
        None => Ok(((local.group)()?, Openers::Local(local.read))),
    }
}

/// Where the handler's counters and records go.
pub struct FallbackSinks {
    /// Where the counters are recorded.
    pub metrics: Arc<dyn MetricsPort>,
    /// Where a writer that reached the refusal is reported.
    pub records: mpsc::Sender<WriteRefusalRecord>,
    /// Whether to refuse, followed between two reads so a promotion takes
    /// effect without a restart.
    pub mode: tokio::sync::watch::Receiver<bool>,
}

/// A running fanotify refusal. Dropping it stops the handler and closes the
/// group, which allows every open still waiting.
pub struct FanotifyRefusal {
    stop: Arc<AtomicBool>,
    plans: std_mpsc::Sender<FallbackPlan>,
    thread: Option<JoinHandle<()>>,
}

impl FanotifyRefusal {
    /// Open the group, place the plan's marks and start the handler.
    ///
    /// # Errors
    ///
    /// Returns why the route cannot run here, in one sentence.
    pub fn start(
        plan: FallbackPlan,
        policy: &WriteRefusalPolicy,
        sinks: FallbackSinks,
        local: LocalRefusal,
    ) -> Result<Self, String> {
        let (group, openers) = open_group(local)?;
        let failed = place(&group, &plan);
        if !failed.is_empty() && failed.len() >= plan.marks.len() {
            return Err(format!(
                "no inode mark could be placed: {}",
                failed.first().cloned().unwrap_or_default()
            ));
        }
        for entry in &failed {
            warn!("write refusal: mark not placed, {entry}");
        }
        for label in FALLBACK_LABELS {
            sinks.metrics.record_packets_by(FALLBACK_METRICS, label, 0);
        }
        crate::ebpf::write_refusal::publish_status(plan.status(policy.enforce));
        let decider = Decider {
            plan,
            counter: WriteOpenCounter::new(
                policy.threshold,
                policy.window_ns,
                WRITE_REFUSAL_WRITERS,
            ),
            enforce: policy.enforce,
            count_by: policy.count_by,
            own_tgid: std::process::id(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (plans, next) = std_mpsc::channel();
        let flag = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("write-refusal-fanotify".to_string())
            .spawn(move || handle(group, decider, openers, &sinks, &flag, &next))
            .map_err(|e| format!("the fanotify handler could not start: {e}"))?;
        Ok(Self {
            stop,
            plans,
            thread: Some(thread),
        })
    }

    /// Where a new plan is handed to the handler, which replaces the marks
    /// between two reads.
    #[must_use]
    pub fn plans(&self) -> std_mpsc::Sender<FallbackPlan> {
        self.plans.clone()
    }
}

impl Drop for FanotifyRefusal {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            warn!("write refusal: the fanotify handler ended abnormally");
        }
    }
}

/// The handler's loop: wait, read what is queued, answer everything inside
/// the reply budget, apply a new plan between two reads.
fn handle(
    group: OwnedFd,
    mut decider: Decider,
    mut openers: Openers,
    sinks: &FallbackSinks,
    stop: &AtomicBool,
    next: &std_mpsc::Receiver<FallbackPlan>,
) {
    let budget = Duration::from_millis(WRITE_REFUSAL_REPLY_BUDGET_MS);
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_sweep = Instant::now();
    while !stop.load(Ordering::Acquire) {
        if let Ok(plan) = next.try_recv() {
            for entry in place(&group, &plan) {
                debug!("write refusal: mark not placed, {entry}");
            }
            crate::ebpf::write_refusal::publish_status(plan.status(decider.enforce));
            decider.plan = plan;
        }
        let enforce = *sinks.mode.borrow();
        if enforce != decider.enforce {
            decider.enforce = enforce;
            crate::ebpf::write_refusal::publish_status(decider.plan.status(enforce));
        }
        if last_sweep.elapsed() >= Duration::from_secs(30) {
            decider.counter.sweep(boottime_now_ns());
            last_sweep = Instant::now();
        }
        let mut pfd = libc::pollfd {
            fd: group.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` is one valid pollfd for the duration of the call.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, POLL_MS) };
        if rc <= 0 {
            continue;
        }
        let started = Instant::now();
        let (events, readable) = read_events(&group, &mut buf);
        let files: Vec<Option<OpenedFile>> = events.iter().map(|e| opened_file(e.fd)).collect();
        // One read for the whole batch, of the openers of watched files only:
        // through the warden that is one round trip rather than one per open.
        let asked: Vec<u32> = events
            .iter()
            .zip(&files)
            .filter(|(_, f)| {
                f.as_ref()
                    .is_some_and(|f| decider.plan.regime_of(&f.path).is_some())
            })
            .map(|(e, _)| e.tid)
            .collect();
        let readings: HashMap<u32, OpenerReading> =
            asked.iter().copied().zip(openers.read(&asked)).collect();
        let read = |tid: u32| readings.get(&tid).copied().unwrap_or(OpenerReading::GONE);
        for (event, file) in events.into_iter().zip(files) {
            if started.elapsed() > budget {
                reply(&group, event.fd, true);
                record(sinks, &[Count::Checked, Count::OverBudget]);
                continue;
            }
            let decision = decider.decide(event.tid, file.as_ref(), &read, boottime_now_ns());
            reply(&group, event.fd, decision.allow);
            record(sinks, &decision.counts);
            if let Some(found) = decision.record
                && sinks.records.try_send(found).is_err()
            {
                debug!("write refusal: a record was dropped, the channel is full");
            }
        }
        if !readable {
            warn!("write refusal: the fanotify group cannot be read, the route stops");
            break;
        }
    }
    // Closing the group is what allows every open still waiting.
    drop(group);
}

fn record(sinks: &FallbackSinks, counts: &[Count]) {
    for count in counts {
        sinks
            .metrics
            .record_packets_by(FALLBACK_METRICS, count.label(), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(dir: &Path, system: bool, writers: &[(u64, u64)]) -> FallbackPlan {
        FallbackPlan {
            marks: vec![(dir.to_path_buf(), true)],
            watched: vec![FallbackPath {
                canonical: dir.to_path_buf(),
                configured: dir.display().to_string(),
                regime: if system {
                    WriteRefusalRegime::System
                } else {
                    WriteRefusalRegime::Data
                },
            }],
            writers: writers.iter().copied().collect(),
            missing: Vec::new(),
        }
    }

    fn decider(plan: FallbackPlan, threshold: u32, enforce: bool) -> Decider {
        Decider {
            plan,
            counter: WriteOpenCounter::new(threshold, 60_000_000_000, 16),
            enforce,
            count_by: CountBy::Process,
            own_tgid: 1,
        }
    }

    fn file(path: &str) -> OpenedFile {
        OpenedFile {
            path: PathBuf::from(path),
            dev: 8,
            ino: 9,
        }
    }

    fn writer(tgid: u32, exe: (u64, u64)) -> impl Fn(u32) -> OpenerReading {
        move |_| OpenerReading {
            intent: OpenIntent::Write,
            tgid,
            cgroup_id: 0,
            exe: Some(exe),
        }
    }

    #[test]
    fn a_mark_is_an_inode_mark_and_never_a_filesystem_or_mount_mark() {
        assert_eq!(
            MARK_FLAGS & (libc::FAN_MARK_FILESYSTEM | libc::FAN_MARK_MOUNT),
            0
        );
        assert_eq!(DIR_MASK & libc::FAN_ONDIR, 0);
    }

    #[test]
    fn a_path_the_handler_reads_is_never_watched() {
        for path in [
            "/proc",
            "/proc/1",
            "/sys/fs/cgroup/system.slice",
            "/sys",
            "/",
        ] {
            assert!(read_by_handler(Path::new(path)).is_some(), "{path}");
        }
        assert!(read_by_handler(Path::new("/srv/data")).is_none());
        let set = WriteRefusalSet {
            data: vec!["/proc/sys".to_string()],
            ..WriteRefusalSet::default()
        };
        assert!(
            FallbackPlan::walk(&set, 16)
                .unwrap_err()
                .contains("reads to decide")
        );
    }

    #[test]
    fn the_handler_reads_only_under_proc_and_the_cgroup_tree() {
        // Every path the handler opens is built by one of these, each rooted
        // under what `HANDLER_READS` names; a watched path is refused there.
        for built in [
            format!("/proc/{}/syscall", 7),
            format!("/proc/{}/status", 7),
            format!("/proc/{}/exe", 7),
            format!("/proc/{}/cgroup", 7),
            format!("/proc/{}/mem", 7),
            format!("/proc/self/fd/{}", 3),
            format!("/sys/fs/cgroup{}", "/system.slice"),
            MAX_USER_MARKS.to_string(),
        ] {
            assert!(read_by_handler(Path::new(&built)).is_some(), "{built}");
        }
    }

    #[test]
    fn a_tree_is_walked_into_directory_marks_and_refused_past_the_bound() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("a/b")).unwrap();
        std::fs::write(root.path().join("a/f"), b"x").unwrap();
        let set = WriteRefusalSet {
            data: vec![root.path().display().to_string()],
            system: vec![root.path().join("a/f").display().to_string()],
            writers: vec!["/nonexistent/writer".to_string()],
        };
        let plan = FallbackPlan::walk(&set, 16).unwrap();
        assert_eq!(plan.marks(), 4);
        assert_eq!(plan.missing.len(), 1);
        let held = std::fs::canonicalize(root.path().join("a/f")).unwrap();
        assert_eq!(
            plan.regime_of(&held).unwrap().regime,
            WriteRefusalRegime::System
        );
        assert!(
            FallbackPlan::walk(&set, 2)
                .unwrap_err()
                .contains("more than 2")
        );
    }

    #[test]
    fn a_data_path_refuses_at_the_threshold_and_reports_once() {
        let mut d = decider(plan(Path::new("/srv/data"), false, &[]), 3, true);
        let f = file("/srv/data/x");
        let w = writer(42, (1, 1));
        assert!(d.decide(42, Some(&f), &w, 0).allow);
        assert!(d.decide(42, Some(&f), &w, 1).allow);
        let third = d.decide(42, Some(&f), &w, 2);
        assert!(!third.allow);
        let record = third.record.unwrap();
        assert_eq!(record.count, 3);
        assert!(record.refused);
        assert_eq!(record.directory.as_deref(), Some("/srv/data"));
        let fourth = d.decide(42, Some(&f), &w, 3);
        assert!(!fourth.allow);
        assert!(fourth.record.is_none());
    }

    #[test]
    fn a_system_path_refuses_an_unexpected_executable_at_its_first_write() {
        let mut d = decider(plan(Path::new("/etc/ssh"), true, &[(5, 5)]), 100, true);
        let f = file("/etc/ssh/sshd_config");
        let expected = d.decide(42, Some(&f), &writer(42, (5, 5)), 0);
        assert!(expected.allow);
        assert!(expected.counts.contains(&Count::Expected));
        let other = d.decide(43, Some(&f), &writer(43, (6, 6)), 0);
        assert!(!other.allow);
        assert_eq!(other.record.unwrap().regime, WriteRefusalRegime::System);
    }

    #[test]
    fn shadow_answers_allow_and_reports_what_it_would_have_refused() {
        let mut d = decider(plan(Path::new("/etc/ssh"), true, &[]), 100, false);
        let f = file("/etc/ssh/sshd_config");
        let decision = d.decide(43, Some(&f), &writer(43, (6, 6)), 0);
        assert!(decision.allow);
        assert!(decision.counts.contains(&Count::WouldRefuse));
        assert!(!decision.record.unwrap().refused);
    }

    #[test]
    fn reads_the_agent_itself_and_what_cannot_be_read_are_allowed() {
        let mut d = decider(plan(Path::new("/etc/ssh"), true, &[]), 1, true);
        let f = file("/etc/ssh/sshd_config");
        let read = |_| OpenerReading {
            intent: OpenIntent::Read,
            tgid: 43,
            cgroup_id: 0,
            exe: Some((6, 6)),
        };
        assert!(d.decide(43, Some(&f), &read, 0).allow);
        let own = d.decide(1, Some(&f), &writer(1, (6, 6)), 0);
        assert!(own.allow);
        assert!(own.counts.contains(&Count::Own));
        let gone = |_| OpenerReading::GONE;
        assert!(d.decide(44, Some(&f), &gone, 0).allow);
        assert!(d.decide(44, None, &gone, 0).allow);
        let outside = file("/srv/other");
        assert!(d.decide(43, Some(&outside), &writer(43, (6, 6)), 0).allow);
    }
}
