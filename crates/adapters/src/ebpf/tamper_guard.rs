#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)

//! Loading, arming and reading the tamper guard.
//!
//! The object is the community agent's and carries no licence check of its
//! own: it refuses nothing until a caller writes the configuration slot, and
//! only the licensed build calls [`TamperGuardMaps::arm`]. The links are held
//! by the agent and never pinned, so the protection ends with the process
//! that holds them; a process that is gone was either stopped through the
//! window or by something the hooks do not see, and the fleet raises the
//! silence either way.

use std::collections::HashMap;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::Duration;

use aya::maps::{Array, HashMap as AyaHashMap, MapData, RingBuf};
use domain::tamper::{TamperKind, TamperRefusal};
use ebpf_common::bpf_guard::BpfGuardTask;
use ebpf_common::tamper_guard::{
    TAMPER_GUARD_CONFIG_SLOT, TAMPER_GUARD_INODE_CGROUP, TAMPER_GUARD_INODE_DIRECTORY,
    TAMPER_GUARD_INODE_FILE, TAMPER_GUARD_MAX_INODES, TamperGuardConfig, TamperGuardEvent,
    TamperGuardInode,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

use super::event_reader::{drain_tick, watch_ringbuf};
use super::kfunc;
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;
use super::process_attach::resolve_walk_offsets;
use super::ringbuf_observer::{DrainTrigger, RingBufObserver, boottime_now_ns};
use super::write_refusal::{key_from_stat, resolve_offsets, stat_dev};

/// The object's file name.
pub const TAMPER_GUARD_OBJECT: &str = "lsm-tamper-guard";

/// The kfunc the cgroup hook compares a file name with.
pub const NAME_COMPARISON: &str = "bpf_strcmp";

/// Each program, the hook function the kernel's BTF names for it, and the
/// parameters the program reads that hook with.
pub const TAMPER_GUARD_PROGRAMS: [(&str, &str, u32); 5] = [
    ("tamper_guard_task_kill", "bpf_lsm_task_kill", 4),
    ("tamper_guard_ptrace", "bpf_lsm_ptrace_access_check", 2),
    ("tamper_guard_unlink", "bpf_lsm_inode_unlink", 2),
    ("tamper_guard_rename", "bpf_lsm_inode_rename", 4),
    ("tamper_guard_file_open", "bpf_lsm_file_open", 1),
];

/// What the agent can say about the tamper guard, for the start-up log and
/// the kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TamperGuardStatus {
    /// Every hook is attached and the slot is armed.
    pub protected: bool,
    /// How many thread groups are protected.
    pub tasks: usize,
    /// How many inodes are protected.
    pub inodes: usize,
    /// Why the agent can be stopped like any process here, in one sentence.
    /// `None` when it is protected, and before anything tried.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<TamperGuardStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<TamperGuardStatus> {
    STATUS.get_or_init(|| Mutex::new(TamperGuardStatus::default()))
}

/// Publish what the agent can say about the tamper guard.
pub fn publish_status(status: TamperGuardStatus) {
    let mut held = status_cell().lock().unwrap_or_else(PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the tamper guard.
#[must_use]
pub fn status() -> TamperGuardStatus {
    status_cell()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// Read the offsets every hook needs off the running kernel's BTF, and check
/// each hook still takes the parameters its program reads.
///
/// # Errors
///
/// Returns the hook whose arity moved, or the member the BTF does not
/// describe. All or nothing: a hook reading a moved verdict would turn
/// another module's refusal into an admission.
pub fn resolve_layout() -> Result<TamperGuardConfig, String> {
    for (program, hook, params) in TAMPER_GUARD_PROGRAMS {
        let found = kfunc::vmlinux_func_param_count(hook)
            .map_err(|e| format!("the kernel BTF is unreadable: {e}"))?
            .ok_or_else(|| format!("the kernel BTF has no `{hook}` hook"))?;
        if found != params {
            return Err(format!(
                "the kernel's `{hook}` takes {found} arguments where `{program}` reads {params}"
            ));
        }
    }
    // The cgroup hook compares the file name with the kernel's own string
    // comparison. Every kernel from the floor on declares it for every
    // program type, so its absence means a kernel that is not what its
    // release says, and the guard is not attached rather than loaded to fail.
    match kfunc::vmlinux_func_param_count(NAME_COMPARISON)
        .map_err(|e| format!("the kernel BTF is unreadable: {e}"))?
    {
        Some(2) => {}
        Some(found) => {
            return Err(format!(
                "the kernel's `{NAME_COMPARISON}` takes {found} arguments where the guard passes 2"
            ));
        }
        None => return Err(format!("the kernel declares no `{NAME_COMPARISON}`")),
    }
    let [
        task_group_leader,
        task_thread_pid,
        pid_level,
        pid_numbers,
        upid_ns,
        pid_namespace_inum,
    ] = resolve_walk_offsets()?;
    let files = resolve_offsets()?;
    Ok(TamperGuardConfig {
        task_group_leader,
        task_thread_pid,
        pid_level,
        pid_numbers,
        upid_ns,
        pid_namespace_inum,
        file_mode: files.file_mode,
        file_dentry: files.file_path + files.path_dentry,
        dentry_parent: files.dentry_parent,
        dentry_inode: files.dentry_inode,
        dentry_name: files.dentry_name,
        inode_ino: files.inode_ino,
        inode_sb: files.inode_sb,
        sb_dev: files.sb_dev,
        ..TamperGuardConfig::default()
    })
}

/// One inode the guard protects, with the path it was found at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedInode {
    pub key: TamperGuardInode,
    /// One of the `TAMPER_GUARD_INODE_*` values.
    pub kind: u8,
    pub path: String,
}

fn inode_of(path: &Path, kind: u8) -> std::io::Result<ProtectedInode> {
    let meta = std::fs::metadata(path)?;
    let key = key_from_stat(meta.dev(), meta.ino());
    Ok(ProtectedInode {
        key: TamperGuardInode {
            ino: key.ino,
            dev: key.dev,
            _pad: 0,
        },
        kind,
        path: path.display().to_string(),
    })
}

/// The cgroup directories that hold `cgroup_line`'s task, from its own up to
/// but not including the root, which has no `cgroup.kill`.
#[must_use]
pub fn cgroup_directories(cgroup_file: &str, cgroup_root: &Path) -> Vec<PathBuf> {
    let Some(relative) = cgroup_file.lines().find_map(|l| l.strip_prefix("0::")) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut current = PathBuf::from(relative.trim().trim_start_matches('/'));
    while !current.as_os_str().is_empty() {
        out.push(cgroup_root.join(&current));
        if !current.pop() {
            break;
        }
    }
    out
}

/// What the guard is told to protect.
#[derive(Debug, Clone, Default)]
pub struct TamperGuardTargets {
    /// Directories whose entries are protected: the link pins.
    pub directories: Vec<PathBuf>,
    /// Files protected themselves: the configuration and the licence.
    pub files: Vec<PathBuf>,
    /// Where the unified cgroup hierarchy is mounted, for the agent's cgroup.
    /// `None` leaves cgroup kill and freeze undecided.
    pub cgroup_root: Option<PathBuf>,
}

impl TamperGuardTargets {
    /// Every inode the targets resolve to now. A path that does not exist is
    /// skipped and named in the second list, for the log.
    #[must_use]
    pub fn resolve(&self) -> (Vec<ProtectedInode>, Vec<String>) {
        let mut found = Vec::new();
        let mut missing = Vec::new();
        let mut take = |path: &Path, kind: u8| match inode_of(path, kind) {
            Ok(inode) => found.push(inode),
            Err(e) => missing.push(format!("{}: {e}", path.display())),
        };
        for dir in &self.directories {
            take(dir, TAMPER_GUARD_INODE_DIRECTORY);
        }
        for file in &self.files {
            take(file, TAMPER_GUARD_INODE_FILE);
        }
        if let Some(root) = &self.cgroup_root {
            match std::fs::read_to_string("/proc/self/cgroup") {
                Ok(text) => {
                    for dir in cgroup_directories(&text, root) {
                        take(&dir, TAMPER_GUARD_INODE_CGROUP);
                    }
                }
                Err(e) => missing.push(format!("/proc/self/cgroup: {e}")),
            }
        }
        (found, missing)
    }
}

/// The paths a refusal's inode is reported under.
pub type ProtectedPaths = HashMap<TamperGuardInode, String>;

/// The guard's four writable maps.
pub struct TamperGuardMaps {
    config: Array<MapData, TamperGuardConfig>,
    tasks: Array<MapData, BpfGuardTask>,
    inodes: AyaHashMap<MapData, TamperGuardInode, u8>,
    window: Array<MapData, u64>,
    held: Vec<TamperGuardInode>,
    paths: Arc<RwLock<ProtectedPaths>>,
    task_count: usize,
}

impl TamperGuardMaps {
    /// Take the maps out of a loaded guard object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or carries another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        Ok(Self {
            config: Array::try_from(take("TAMPER_GUARD_CONFIG")?)?,
            tasks: Array::try_from(take("TAMPER_GUARD_TASKS")?)?,
            inodes: AyaHashMap::try_from(take("TAMPER_GUARD_INODES")?)?,
            window: Array::try_from(take("TAMPER_GUARD_WINDOW")?)?,
            held: Vec::new(),
            paths: Arc::new(RwLock::new(ProtectedPaths::new())),
            task_count: 0,
        })
    }

    /// The paths the reader names a refused inode with.
    #[must_use]
    pub fn paths(&self) -> Arc<RwLock<ProtectedPaths>> {
        Arc::clone(&self.paths)
    }

    /// Write the protected tasks, every slot.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn set_tasks(&mut self, tasks: &[BpfGuardTask]) -> Result<(), anyhow::Error> {
        let capacity = self.tasks.len();
        if u32::try_from(tasks.len()).map_or(true, |n| n > capacity) {
            anyhow::bail!("{} protected tasks, where {capacity} fit", tasks.len());
        }
        let empty = BpfGuardTask {
            ns_dev: 0,
            ns_ino: 0,
            tgid: 0,
            _pad: 0,
        };
        for slot in 0..capacity {
            let task = usize::try_from(slot)
                .ok()
                .and_then(|i| tasks.get(i))
                .unwrap_or(&empty);
            self.tasks
                .set(slot, task, 0)
                .map_err(|e| anyhow::anyhow!("TAMPER_GUARD_TASKS write failed: {e}"))?;
        }
        self.task_count = tasks.len();
        Ok(())
    }

    /// Make the protected inodes exactly `inodes`, new ones in before stale
    /// ones out.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused, or that there are more
    /// than the map holds.
    pub fn set_inodes(&mut self, inodes: &[ProtectedInode]) -> Result<(), anyhow::Error> {
        if inodes.len() > TAMPER_GUARD_MAX_INODES as usize {
            anyhow::bail!(
                "{} protected inodes, where {TAMPER_GUARD_MAX_INODES} fit",
                inodes.len()
            );
        }
        for inode in inodes {
            self.inodes
                .insert(&inode.key, &inode.kind, 0)
                .map_err(|e| anyhow::anyhow!("TAMPER_GUARD_INODES write failed: {e}"))?;
        }
        let wanted: Vec<TamperGuardInode> = inodes.iter().map(|i| i.key).collect();
        for stale in self.held.iter().filter(|k| !wanted.contains(k)) {
            if let Err(e) = self.inodes.remove(stale) {
                debug!("TAMPER_GUARD_INODES entry already gone: {e}");
            }
        }
        self.held = wanted;
        let mut paths = self.paths.write().unwrap_or_else(PoisonError::into_inner);
        *paths = inodes.iter().map(|i| (i.key, i.path.clone())).collect();
        Ok(())
    }

    /// Turn the guard on with the signals in `signals` refused.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn arm(&mut self, layout: TamperGuardConfig, signals: u64) -> Result<(), anyhow::Error> {
        let slot = TamperGuardConfig {
            signals,
            valid: 1,
            ..layout
        };
        self.config
            .set(TAMPER_GUARD_CONFIG_SLOT, &slot, 0)
            .map_err(|e| anyhow::anyhow!("TAMPER_GUARD_CONFIG write failed: {e}"))
    }

    /// Turn the guard off: every hook lets everything through again.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn disarm(&mut self) -> Result<(), anyhow::Error> {
        self.config
            .set(TAMPER_GUARD_CONFIG_SLOT, &TamperGuardConfig::default(), 0)
            .map_err(|e| anyhow::anyhow!("TAMPER_GUARD_CONFIG write failed: {e}"))
    }

    /// Open the stop window for `length` from now: signals, unlinks and
    /// renames from any task pass until it closes.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn open_window(&mut self, length: Duration) -> Result<(), anyhow::Error> {
        let until =
            boottime_now_ns().saturating_add(u64::try_from(length.as_nanos()).unwrap_or(u64::MAX));
        self.window
            .set(TAMPER_GUARD_CONFIG_SLOT, &until, 0)
            .map_err(|e| anyhow::anyhow!("TAMPER_GUARD_WINDOW write failed: {e}"))
    }

    /// Close the stop window now.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn close_window(&mut self) -> Result<(), anyhow::Error> {
        self.window
            .set(TAMPER_GUARD_CONFIG_SLOT, &0, 0)
            .map_err(|e| anyhow::anyhow!("TAMPER_GUARD_WINDOW write failed: {e}"))
    }

    /// The status to publish once armed.
    #[must_use]
    pub fn status(&self) -> TamperGuardStatus {
        TamperGuardStatus {
            protected: true,
            tasks: self.task_count,
            inodes: self.held.len(),
            reason: None,
        }
    }
}

/// Holds the five LSM links. Dropping it detaches them.
#[derive(Default)]
pub struct TamperGuardAttacher {
    links: Vec<OwnedFd>,
}

impl TamperGuardAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach every hook of `loader`, or none.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel gave for the program it refused to load
    /// or the hook it refused to attach.
    pub fn attach(&mut self, loader: &EbpfLoader) -> Result<(), String> {
        let mut links = Vec::with_capacity(TAMPER_GUARD_PROGRAMS.len());
        for (program, _, _) in TAMPER_GUARD_PROGRAMS {
            if let Some(refusal) = loader.refused_program(program) {
                return Err(format!("the kernel refused `{program}`: {refusal}"));
            }
            let prog_fd: RawFd = loader
                .program_fd(program)
                .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
            links.push(kfunc_attach::attach_lsm(program, prog_fd).map_err(|e| e.to_string())?);
        }
        self.links = links;
        info!(
            "tamper guard attached on task_kill, ptrace_access_check, inode_unlink, inode_rename and file_open"
        );
        Ok(())
    }

    /// Whether every link is held.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.links.len() == TAMPER_GUARD_PROGRAMS.len()
    }
}

/// Reads the refusals off `TAMPER_GUARD_EVENTS`.
pub struct TamperGuardEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
    paths: Arc<RwLock<ProtectedPaths>>,
}

impl TamperGuardEventReader {
    /// Take the ring from the loaded object.
    ///
    /// # Errors
    ///
    /// Returns an error when the map is missing or cannot be polled.
    pub fn new(
        ebpf: &mut dyn MapStore,
        paths: Arc<RwLock<ProtectedPaths>>,
    ) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("TAMPER_GUARD_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'TAMPER_GUARD_EVENTS' not found"))?;
        let ring_buf = RingBuf::try_from(map)?;
        Ok(Self {
            ring_buf: watch_ringbuf(ring_buf)?,
            paths,
        })
    }

    /// Drain the ring into `tx` until `cancel` fires or the ring errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<TamperRefusal>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let Self {
            ring_buf: mut async_fd,
            paths,
        } = self;
        let mut tick = drain_tick();
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            let drained = drain(guard.get_inner_mut(), &paths, &tx, &observer);
                            guard.clear_ready();
                            observer.drain_pass(DrainTrigger::Wakeup, drained);
                        }
                        Err(e) => {
                            error!("tamper guard RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    let drained = drain(async_fd.get_mut(), &paths, &tx, &observer);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

fn drain(
    rb: &mut RingBuf<MapData>,
    paths: &RwLock<ProtectedPaths>,
    tx: &mpsc::Sender<TamperRefusal>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<TamperGuardEvent>() {
            observer.dropped("truncated_record");
            continue;
        }
        // SAFETY: the length was checked above, `TamperGuardEvent` is
        // `repr(C)` plain data valid for any bit pattern, and the read is
        // unaligned because the ring buffer guarantees no alignment.
        let raw = unsafe { bytes.as_ptr().cast::<TamperGuardEvent>().read_unaligned() };
        let path = {
            let held = paths.read().unwrap_or_else(PoisonError::into_inner);
            held.get(&TamperGuardInode {
                ino: raw.ino,
                dev: raw.dev,
                _pad: 0,
            })
            .cloned()
        };
        let Some(record) = parse(&raw, path) else {
            observer.dropped("unknown_kind");
            continue;
        };
        observer.drained(now_ns, raw.at_ns);
        if tx.try_send(record).is_err() {
            observer.dropped("channel_full");
        }
    }
    drained
}

fn text(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).into_owned()
}

/// Turn a kernel record into the domain record.
#[must_use]
pub fn parse(raw: &TamperGuardEvent, path: Option<String>) -> Option<TamperRefusal> {
    let kind = TamperKind::from_kernel(raw.kind)?;
    Some(TamperRefusal {
        at_ns: raw.at_ns,
        kind,
        caller_tgid: raw.caller_tgid,
        caller_comm: text(&raw.comm),
        target_tgid: (raw.target_tgid != 0).then_some(raw.target_tgid),
        detail: raw.detail,
        file: (raw.ino != 0).then(|| (stat_dev(raw.dev), raw.ino)),
        name: text(&raw.name),
        path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::tamper_guard::{TAMPER_GUARD_KIND_SIGNAL, TAMPER_GUARD_KIND_UNLINK};

    fn event(kind: u8) -> TamperGuardEvent {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"kill");
        let mut name = [0u8; 16];
        name[..3].copy_from_slice(b"xdp");
        TamperGuardEvent {
            at_ns: 5,
            ino: 0,
            caller_tgid: 4242,
            target_tgid: 7,
            dev: 0,
            detail: 9,
            kind,
            _pad: [0; 7],
            comm,
            name,
        }
    }

    #[test]
    fn a_signal_record_names_the_caller_and_the_target() {
        let record = parse(&event(TAMPER_GUARD_KIND_SIGNAL), None).expect("a known kind");
        assert_eq!(record.kind, TamperKind::Signal);
        assert_eq!(record.caller_comm, "kill");
        assert_eq!(record.target_tgid, Some(7));
        assert_eq!(record.file, None);
    }

    #[test]
    fn an_unlink_record_carries_the_file_and_its_path() {
        let mut raw = event(TAMPER_GUARD_KIND_UNLINK);
        raw.ino = 12;
        raw.target_tgid = 0;
        let record = parse(&raw, Some("/sys/fs/bpf/x".to_string())).expect("a known kind");
        assert_eq!(record.file.map(|f| f.1), Some(12));
        assert_eq!(record.target_tgid, None);
        assert_eq!(record.name, "xdp");
        assert_eq!(record.path.as_deref(), Some("/sys/fs/bpf/x"));
    }

    #[test]
    fn an_unknown_kind_is_dropped() {
        assert!(parse(&event(0), None).is_none());
        assert!(parse(&event(9), None).is_none());
    }

    #[test]
    fn the_cgroup_walk_stops_below_the_root() {
        let dirs = cgroup_directories(
            "0::/system.slice/ebpfsentinel.service\n",
            Path::new("/sys/fs/cgroup"),
        );
        assert_eq!(
            dirs,
            vec![
                PathBuf::from("/sys/fs/cgroup/system.slice/ebpfsentinel.service"),
                PathBuf::from("/sys/fs/cgroup/system.slice"),
            ]
        );
        assert!(cgroup_directories("0::/\n", Path::new("/sys/fs/cgroup")).is_empty());
        assert!(cgroup_directories("1:name=x:/\n", Path::new("/sys/fs/cgroup")).is_empty());
    }

    #[test]
    fn a_missing_target_is_named_not_fatal() {
        let targets = TamperGuardTargets {
            directories: vec![PathBuf::from("/nonexistent/pins")],
            files: vec![PathBuf::from("/")],
            cgroup_root: None,
        };
        let (found, missing) = targets.resolve();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, TAMPER_GUARD_INODE_FILE);
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn the_running_kernel_describes_what_the_guard_reads() {
        // Only meaningful where the kernel publishes its BTF.
        if !Path::new("/sys/kernel/btf/vmlinux").exists() {
            return;
        }
        let layout = resolve_layout().expect("every hook and member resolves");
        assert!(layout.task_thread_pid > 0);
        assert!(layout.file_dentry > 0);
        assert_eq!(layout.valid, 0, "the layout is never armed by itself");
    }

    #[test]
    fn the_built_guard_compares_names_with_the_kernel_and_nothing_else() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../target/bpfel-unknown-none/release/lsm-tamper-guard"
        );
        // The object exists only once the eBPF programs were built.
        let Ok(elf) = std::fs::read(path) else {
            return;
        };
        let called = super::super::kfunc_loader::called_kfuncs(&elf).expect("kfunc sites parse");
        assert_eq!(called, vec![NAME_COMPARISON.to_string()]);
    }
}
