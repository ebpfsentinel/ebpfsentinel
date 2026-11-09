#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)

use std::collections::HashMap;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};

use aya::maps::{Array, HashMap as AyaHashMap, MapData, RingBuf};
use domain::ransom::{
    CountBy, WriteRefusalHook, WriteRefusalRecord, WriteRefusalRegime, WriteRefusalRoute,
};
use ebpf_common::exec_network::kernel_dev;
use ebpf_common::write_refusal::{
    WRITE_REFUSAL_BY_CGROUP, WRITE_REFUSAL_BY_PROCESS, WRITE_REFUSAL_CONFIG_SLOT,
    WRITE_REFUSAL_MODE_ENFORCE, WRITE_REFUSAL_MODE_SHADOW, WriteRefusalConfig, WriteRefusalCount,
    WriteRefusalDir, WriteRefusalEvent, write_refusal_expired,
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
use super::ringbuf_observer::{DrainTrigger, RingBufObserver, boottime_now_ns};

/// The object the refusal is loaded from, and the source its records are
/// counted under.
pub const WRITE_REFUSAL_OBJECT: &str = "lsm-write-refusal";
/// The program deciding a write-open.
pub const WRITE_REFUSAL_OPEN_PROGRAM: &str = "write_refusal_file_open";
/// The program deciding a truncation by path.
pub const WRITE_REFUSAL_TRUNCATE_PROGRAM: &str = "write_refusal_path_truncate";

/// What the agent can say about the refusal, for the start-up log and the
/// kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteRefusalStatus {
    /// Both hooks are attached and deciding.
    pub attached: bool,
    /// The kernel refuses the write past the threshold rather than counting
    /// it.
    pub enforcing: bool,
    /// How many watched paths the kernel holds, both regimes.
    pub directories: usize,
    /// How many of them are system paths.
    pub system: usize,
    /// How many expected writers of the system paths the kernel holds.
    pub writers: usize,
    /// Which mechanism refuses, `None` while nothing does.
    pub route: Option<WriteRefusalRoute>,
    /// How many inode marks the fanotify fallback holds; zero on the BPF
    /// LSM route, which places none.
    pub marks: usize,
    /// Why the refusal is not in force, in one sentence. `None` when it is.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<WriteRefusalStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<WriteRefusalStatus> {
    STATUS.get_or_init(|| Mutex::new(WriteRefusalStatus::default()))
}

/// Publish what the agent can say about the refusal.
pub fn publish_status(status: WriteRefusalStatus) {
    let mut held = status_cell().lock().unwrap_or_else(PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the refusal.
#[must_use]
pub fn status() -> WriteRefusalStatus {
    status_cell()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The offsets the hooks walk, read off the running kernel's BTF.
///
/// All or an error: a hook handed a partial layout would read some other
/// field as a parent and count writes against whatever it found there.
///
/// # Errors
///
/// Returns the struct or member the kernel's BTF does not describe.
pub fn resolve_offsets() -> Result<WriteRefusalConfig, String> {
    let members = |structure: &str, names: &[&str]| -> Result<Vec<u32>, String> {
        let found = kfunc::vmlinux_struct_member_offsets(structure, names)
            .map_err(|e| format!("the kernel BTF does not describe `{structure}`: {e}"))?;
        names
            .iter()
            .zip(found)
            .map(|(name, offset)| {
                offset.ok_or_else(|| format!("the kernel BTF has no `{structure}.{name}`"))
            })
            .collect()
    };
    let file = members("file", &["f_mode", "f_path"])?;
    let path = members("path", &["dentry"])?;
    let dentry = members("dentry", &["d_parent", "d_inode", "d_name"])?;
    let qstr = members("qstr", &["name"])?;
    let inode = members("inode", &["i_ino", "i_sb"])?;
    let sb = members("super_block", &["s_dev"])?;
    let task = members("task_struct", &["mm"])?;
    let mm = members("mm_struct", &["exe_file"])?;
    let exe = members("file", &["f_inode"])?;
    Ok(WriteRefusalConfig {
        file_mode: file[0],
        file_path: file[1],
        path_dentry: path[0],
        dentry_parent: dentry[0],
        dentry_inode: dentry[1],
        dentry_name: dentry[2] + qstr[0],
        inode_ino: inode[0],
        inode_sb: inode[1],
        sb_dev: sb[0],
        task_mm: task[0],
        mm_exe_file: mm[0],
        file_inode: exe[0],
        ..WriteRefusalConfig::default()
    })
}

/// The key the kernel compares for the watched path at `path`, a directory
/// and everything beneath it or a single file, following symlinks.
///
/// # Errors
///
/// Returns the I/O error of the `stat`, or one saying the path is neither a
/// directory nor a regular file.
pub fn path_key(path: &str) -> std::io::Result<WriteRefusalDir> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_dir() && !meta.is_file() {
        return Err(std::io::Error::other("neither a directory nor a file"));
    }
    Ok(key_from_stat(meta.dev(), meta.ino()))
}

/// The key the kernel compares for the executable at `path`, following
/// symlinks, so `/usr/bin/python3` names the interpreter it points at.
///
/// # Errors
///
/// Returns the I/O error of the `stat`, or one saying the path is not a
/// regular file.
pub fn executable_key(path: &str) -> std::io::Result<WriteRefusalDir> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    Ok(key_from_stat(meta.dev(), meta.ino()))
}

/// Convert the `stat(2)` device encoding into the kernel's.
#[must_use]
pub fn key_from_stat(dev: u64, ino: u64) -> WriteRefusalDir {
    WriteRefusalDir {
        ino,
        dev: kernel_dev(libc::major(dev), libc::minor(dev)),
        _pad: 0,
    }
}

/// The kernel encoding of a device back into the `stat(2)` one.
#[must_use]
pub fn stat_dev(kernel: u32) -> u64 {
    libc::makedev(kernel >> 20, kernel & 0x000f_ffff)
}

/// A watched path as configured, with its regime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedPath {
    /// The path as configured.
    pub path: String,
    /// How it is refused.
    pub regime: WriteRefusalRegime,
}

/// The watched paths by key.
pub type WatchedDirectories = HashMap<WriteRefusalDir, WatchedPath>;

/// The expected writers by key, each with the path it was configured as.
pub type ExpectedWriters = HashMap<WriteRefusalDir, String>;

/// The watched paths of both regimes and the executables expected to write
/// the system ones, as the configuration and any content composed them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriteRefusalSet {
    /// Refused at the threshold.
    pub data: Vec<String>,
    /// Refused at the first unexpected write.
    pub system: Vec<String>,
    /// Executables whose writes under a system path are expected.
    pub writers: Vec<String>,
}

impl WriteRefusalSet {
    /// The keys of the watched paths.
    ///
    /// A path that does not resolve is left out and named in the second
    /// half of the answer rather than failing the set: a list shared across
    /// a fleet names paths one node does not carry, and the set is read
    /// again on a timer so the day one is created it is picked up. A key
    /// named in both regimes is a system path: the stricter regime wins.
    #[must_use]
    pub fn watched_keys(&self) -> (WatchedDirectories, Vec<String>) {
        let mut keys = HashMap::with_capacity(self.data.len() + self.system.len());
        let mut missing = Vec::new();
        let regimes = [
            (WriteRefusalRegime::Data, &self.data),
            (WriteRefusalRegime::System, &self.system),
        ];
        for (regime, paths) in regimes {
            for path in paths {
                match path_key(path) {
                    Ok(key) => {
                        keys.insert(
                            key,
                            WatchedPath {
                                path: path.clone(),
                                regime,
                            },
                        );
                    }
                    Err(e) => missing.push(format!("{path}: {e}")),
                }
            }
        }
        (keys, missing)
    }

    /// The keys of the expected writers, read again on the same timer: an
    /// upgrade replaces the executable's file, and with it the inode.
    #[must_use]
    pub fn writer_keys(&self) -> (ExpectedWriters, Vec<String>) {
        let mut keys = HashMap::with_capacity(self.writers.len());
        let mut missing = Vec::new();
        for path in &self.writers {
            match executable_key(path) {
                Ok(key) => {
                    keys.insert(key, path.clone());
                }
                Err(e) => missing.push(format!("expected writer {path}: {e}")),
            }
        }
        (keys, missing)
    }
}

/// What the program decides with, beside the offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteRefusalPolicy {
    /// Refuse rather than count.
    pub enforce: bool,
    /// The write-open reaching this count is the first refused.
    pub threshold: u32,
    /// Length of the window, in nanoseconds.
    pub window_ns: u64,
    /// What a writer is counted as.
    pub count_by: CountBy,
}

impl WriteRefusalPolicy {
    /// The complete configuration slot for `offsets`.
    #[must_use]
    pub fn slot(&self, offsets: WriteRefusalConfig, agent_tgid: u32) -> WriteRefusalConfig {
        WriteRefusalConfig {
            window_ns: self.window_ns,
            threshold: self.threshold,
            mode: if self.enforce {
                WRITE_REFUSAL_MODE_ENFORCE
            } else {
                WRITE_REFUSAL_MODE_SHADOW
            },
            count_by: match self.count_by {
                CountBy::Process => WRITE_REFUSAL_BY_PROCESS,
                CountBy::Cgroup => WRITE_REFUSAL_BY_CGROUP,
            },
            agent_tgid,
            valid: 1,
            ..offsets
        }
    }
}

/// The configuration slot, the watched set and the counters.
pub struct WriteRefusalMaps {
    config: Array<MapData, WriteRefusalConfig>,
    dirs: AyaHashMap<MapData, WriteRefusalDir, u8>,
    writers: AyaHashMap<MapData, WriteRefusalDir, u8>,
    held_writers: ExpectedWriters,
    counts: AyaHashMap<MapData, u64, WriteRefusalCount>,
    held: Arc<RwLock<WatchedDirectories>>,
    window_ns: u64,
}

impl WriteRefusalMaps {
    /// Take the four maps out of a loaded refusal object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or carries another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| anyhow::anyhow!("map '{name}' not found"))
        };
        let config = Array::try_from(take("WRITE_REFUSAL_CONFIG")?)?;
        let dirs = AyaHashMap::try_from(take("WRITE_REFUSAL_DIRS")?)?;
        let writers = AyaHashMap::try_from(take("WRITE_REFUSAL_WRITERS")?)?;
        let counts = AyaHashMap::try_from(take("WRITE_REFUSAL_COUNTS")?)?;
        Ok(Self {
            config,
            dirs,
            writers,
            held_writers: HashMap::new(),
            counts,
            held: Arc::new(RwLock::new(HashMap::new())),
            window_ns: 0,
        })
    }

    /// The watched set as last written, shared with the event reader so a
    /// record names its directory the way it was configured.
    #[must_use]
    pub fn watched(&self) -> Arc<RwLock<WatchedDirectories>> {
        Arc::clone(&self.held)
    }

    /// Make the kernel's watched set exactly `keys`, new keys and changed
    /// regimes first.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn replace(&mut self, keys: &WatchedDirectories) -> Result<(), anyhow::Error> {
        let mut held = self.held.write().unwrap_or_else(PoisonError::into_inner);
        for (key, watched) in keys {
            if held.get(key).map(|h| h.regime) == Some(watched.regime) {
                continue;
            }
            self.dirs
                .insert(key, &watched.regime.kernel(), 0)
                .map_err(|e| anyhow::anyhow!("WRITE_REFUSAL_DIRS write failed: {e}"))?;
        }
        for key in held.keys().filter(|k| !keys.contains_key(k)) {
            if let Err(e) = self.dirs.remove(key) {
                debug!("WRITE_REFUSAL_DIRS entry already gone: {e}");
            }
        }
        held.clone_from(keys);
        Ok(())
    }

    /// Make the kernel's expected writers exactly `keys`, new keys first.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn replace_writers(&mut self, keys: &ExpectedWriters) -> Result<(), anyhow::Error> {
        for key in keys.keys().filter(|k| !self.held_writers.contains_key(k)) {
            self.writers
                .insert(key, &1, 0)
                .map_err(|e| anyhow::anyhow!("WRITE_REFUSAL_WRITERS write failed: {e}"))?;
        }
        for key in self.held_writers.keys().filter(|k| !keys.contains_key(k)) {
            if let Err(e) = self.writers.remove(key) {
                debug!("WRITE_REFUSAL_WRITERS entry already gone: {e}");
            }
        }
        self.held_writers.clone_from(keys);
        Ok(())
    }

    /// Write the watched paths and the expected writers `set` names now,
    /// returning what did not resolve, each in one phrase.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn apply(&mut self, set: &WriteRefusalSet) -> Result<Vec<String>, anyhow::Error> {
        let (keys, mut missing) = set.watched_keys();
        let (writers, missing_writers) = set.writer_keys();
        missing.extend(missing_writers);
        // Writers first: a system path is never live before the executables
        // expected to write it are.
        self.replace_writers(&writers)?;
        self.replace(&keys)?;
        Ok(missing)
    }

    /// The status the held set gives, for a refusal attached and deciding.
    #[must_use]
    pub fn status(&self, enforcing: bool) -> WriteRefusalStatus {
        let held = self.held.read().unwrap_or_else(PoisonError::into_inner);
        WriteRefusalStatus {
            attached: true,
            enforcing,
            directories: held.len(),
            system: held
                .values()
                .filter(|w| w.regime == WriteRefusalRegime::System)
                .count(),
            writers: self.held_writers.len(),
            route: Some(WriteRefusalRoute::BpfLsm),
            marks: 0,
            reason: None,
        }
    }

    /// Write the complete slot, which is what turns the hooks on.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn arm(
        &mut self,
        offsets: WriteRefusalConfig,
        policy: &WriteRefusalPolicy,
    ) -> Result<(), anyhow::Error> {
        self.window_ns = policy.window_ns;
        let slot = policy.slot(offsets, std::process::id());
        self.config
            .set(WRITE_REFUSAL_CONFIG_SLOT, &slot, 0)
            .map_err(|e| anyhow::anyhow!("WRITE_REFUSAL_CONFIG write failed: {e}"))
    }

    /// Turn the armed slot from counting to refusing, or back, leaving the
    /// rest of it as written.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the read or the write.
    pub fn set_enforce(&mut self, enforce: bool) -> Result<(), anyhow::Error> {
        let mut slot = self
            .config
            .get(&WRITE_REFUSAL_CONFIG_SLOT, 0)
            .map_err(|e| anyhow::anyhow!("WRITE_REFUSAL_CONFIG read failed: {e}"))?;
        slot.mode = if enforce {
            WRITE_REFUSAL_MODE_ENFORCE
        } else {
            WRITE_REFUSAL_MODE_SHADOW
        };
        self.config
            .set(WRITE_REFUSAL_CONFIG_SLOT, &slot, 0)
            .map_err(|e| anyhow::anyhow!("WRITE_REFUSAL_CONFIG write failed: {e}"))
    }

    /// Remove every writer whose window has passed, so the map holds the
    /// writers of the last window and not of the node's whole uptime.
    /// Returns how many went.
    pub fn sweep(&mut self) -> usize {
        let now_ns = boottime_now_ns();
        let expired: Vec<u64> = self
            .counts
            .iter()
            .filter_map(Result::ok)
            .filter(|(_, count)| write_refusal_expired(count, now_ns, self.window_ns))
            .map(|(writer, _)| writer)
            .collect();
        let mut removed = 0;
        for writer in &expired {
            if self.counts.remove(writer).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

/// Holds the two LSM links. Dropping it detaches both, which is the whole of
/// how the refusal fails open: the links are never pinned, so an agent that
/// is gone leaves nothing deciding.
#[derive(Default)]
pub struct WriteRefusalAttacher {
    links: Vec<OwnedFd>,
}

impl WriteRefusalAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach both hooks of `loader`, or neither.
    ///
    /// # Errors
    ///
    /// Returns the reason the kernel gave for the hook it refused.
    pub fn attach(&mut self, loader: &EbpfLoader) -> Result<(), String> {
        let mut links = Vec::with_capacity(2);
        for program in [WRITE_REFUSAL_OPEN_PROGRAM, WRITE_REFUSAL_TRUNCATE_PROGRAM] {
            let prog_fd: RawFd = loader
                .program_fd(program)
                .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
            links.push(kfunc_attach::attach_lsm(program, prog_fd).map_err(|e| e.to_string())?);
        }
        self.links = links;
        info!("write refusal attached on file_open and path_truncate");
        Ok(())
    }

    /// Whether both links are held.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.links.len() == 2
    }
}

/// Reads the writers that reached the threshold from `WRITE_REFUSAL_EVENTS`.
pub struct WriteRefusalEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
    watched: Arc<RwLock<WatchedDirectories>>,
}

impl WriteRefusalEventReader {
    /// Take the `WRITE_REFUSAL_EVENTS` map from the loaded object.
    ///
    /// # Errors
    ///
    /// Returns an error when the map is missing or cannot be polled.
    pub fn new(
        ebpf: &mut dyn MapStore,
        watched: Arc<RwLock<WatchedDirectories>>,
    ) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("WRITE_REFUSAL_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'WRITE_REFUSAL_EVENTS' not found"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = watch_ringbuf(ring_buf)?;
        Ok(Self {
            ring_buf: async_fd,
            watched,
        })
    }

    /// Drain the ring into `tx` until `cancel` fires or the ring errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<WriteRefusalRecord>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let Self {
            ring_buf: mut async_fd,
            watched,
        } = self;
        let mut tick = drain_tick();
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            let drained = drain(guard.get_inner_mut(), &watched, &tx, &observer);
                            guard.clear_ready();
                            observer.drain_pass(DrainTrigger::Wakeup, drained);
                        }
                        Err(e) => {
                            error!("write refusal RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    let drained = drain(async_fd.get_mut(), &watched, &tx, &observer);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

fn drain(
    rb: &mut RingBuf<MapData>,
    watched: &RwLock<WatchedDirectories>,
    tx: &mpsc::Sender<WriteRefusalRecord>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<WriteRefusalEvent>() {
            observer.dropped("truncated_record");
            continue;
        }
        // SAFETY: the length was checked above, `WriteRefusalEvent` is
        // `repr(C)` plain data valid for any bit pattern, and the read is
        // unaligned because the ring buffer guarantees no alignment.
        let raw = unsafe { bytes.as_ptr().cast::<WriteRefusalEvent>().read_unaligned() };
        let directory = {
            let held = watched.read().unwrap_or_else(PoisonError::into_inner);
            held.get(&WriteRefusalDir {
                ino: raw.dir_ino,
                dev: raw.dir_dev,
                _pad: 0,
            })
            .map(|w| w.path.clone())
        };
        let Some(record) = parse(&raw, directory) else {
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

/// Turn a kernel record into the domain record, converting the device back
/// into the encoding `stat(2)` and the rest of the alerts use.
#[must_use]
pub fn parse(raw: &WriteRefusalEvent, directory: Option<String>) -> Option<WriteRefusalRecord> {
    let hook = WriteRefusalHook::from_kernel(raw.hook)?;
    let regime = WriteRefusalRegime::from_kernel(raw.regime)?;
    let len = raw
        .name
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(raw.name.len());
    Some(WriteRefusalRecord {
        at_ns: raw.at_ns,
        tgid: raw.tgid,
        cgroup_id: raw.cgroup_id,
        file: (stat_dev(raw.file_dev), raw.file_ino),
        name: String::from_utf8_lossy(&raw.name[..len]).into_owned(),
        directory,
        count: raw.count,
        hook,
        regime,
        refused: raw.refused != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::write_refusal::{
        WRITE_REFUSAL_HOOK_TRUNCATE, WRITE_REFUSAL_NAME_BYTES, WRITE_REFUSAL_REGIME_SYSTEM,
    };

    #[test]
    fn the_stat_device_is_written_in_the_kernel_encoding_and_read_back() {
        let dev = libc::makedev(259, 3);
        let key = key_from_stat(dev, 42);
        assert_eq!(key.dev, kernel_dev(259, 3));
        assert_eq!(stat_dev(key.dev), dev);
    }

    #[test]
    fn a_record_names_its_file_and_directory_and_an_unknown_hook_is_dropped() {
        let mut name = [0u8; WRITE_REFUSAL_NAME_BYTES];
        name[..9].copy_from_slice(b"notes.txt");
        let mut raw = WriteRefusalEvent {
            at_ns: 7,
            tgid: 12,
            file_dev: kernel_dev(8, 1),
            file_ino: 99,
            count: 100,
            hook: WRITE_REFUSAL_HOOK_TRUNCATE,
            refused: 1,
            name,
            ..WriteRefusalEvent::default()
        };
        let record = parse(&raw, Some("/srv".into())).expect("a known hook parses");
        assert_eq!(record.name, "notes.txt");
        assert_eq!(record.file, (libc::makedev(8, 1), 99));
        assert_eq!(record.directory.as_deref(), Some("/srv"));
        assert_eq!(record.hook, WriteRefusalHook::Truncate);
        assert!(record.refused);
        assert_eq!(record.regime, WriteRefusalRegime::Data);
        raw.regime = WRITE_REFUSAL_REGIME_SYSTEM;
        let system = parse(&raw, None).expect("a known regime parses");
        assert_eq!(system.regime, WriteRefusalRegime::System);
        raw.regime = 7;
        assert!(parse(&raw, None).is_none());
        raw.regime = 0;
        raw.name = [b'a'; WRITE_REFUSAL_NAME_BYTES];
        let cut = parse(&raw, None).expect("parses");
        assert_eq!(cut.name.len(), WRITE_REFUSAL_NAME_BYTES);
        raw.hook = 9;
        assert!(parse(&raw, None).is_none());
    }

    #[test]
    fn each_regime_resolves_its_paths_and_a_missing_one_is_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data = dir.path().join("data");
        let etc = dir.path().join("etc");
        std::fs::create_dir(&data).expect("mkdir");
        std::fs::create_dir(&etc).expect("mkdir");
        let passwd = etc.join("passwd");
        std::fs::write(&passwd, b"x").expect("write");
        let s = |p: &std::path::Path| p.to_str().expect("utf8").to_string();
        let set = WriteRefusalSet {
            data: vec![s(&data), "/nonexistent/dir".to_string()],
            system: vec![s(&etc), s(&passwd)],
            writers: vec![s(&passwd), s(&etc)],
        };
        let (keys, missing) = set.watched_keys();
        assert_eq!(keys.len(), 3);
        assert_eq!(missing.len(), 1);
        let regime_of =
            |p: &std::path::Path| keys.get(&path_key(&s(p)).expect("stat")).map(|w| w.regime);
        assert_eq!(regime_of(&data), Some(WriteRefusalRegime::Data));
        assert_eq!(regime_of(&etc), Some(WriteRefusalRegime::System));
        assert_eq!(regime_of(&passwd), Some(WriteRefusalRegime::System));
        let (writers, missing) = set.writer_keys();
        assert_eq!(writers.len(), 1);
        assert!(missing[0].contains("not a regular file"), "{missing:?}");
    }

    #[test]
    fn a_path_named_in_both_regimes_is_a_system_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().expect("utf8").to_string();
        let set = WriteRefusalSet {
            data: vec![path.clone()],
            system: vec![path],
            writers: Vec::new(),
        };
        let (keys, _) = set.watched_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(
            keys.values().next().map(|w| w.regime),
            Some(WriteRefusalRegime::System)
        );
    }

    #[test]
    fn the_slot_carries_the_policy_and_is_marked_complete() {
        let policy = WriteRefusalPolicy {
            enforce: true,
            threshold: 5,
            window_ns: 1_000,
            count_by: CountBy::Cgroup,
        };
        let offsets = WriteRefusalConfig {
            file_mode: 20,
            ..WriteRefusalConfig::default()
        };
        let slot = policy.slot(offsets, 77);
        assert_eq!(slot.valid, 1);
        assert_eq!(slot.mode, WRITE_REFUSAL_MODE_ENFORCE);
        assert_eq!(slot.count_by, WRITE_REFUSAL_BY_CGROUP);
        assert_eq!(slot.agent_tgid, 77);
        assert_eq!(slot.threshold, 5);
        assert_eq!(slot.file_mode, 20);
        let shadow = WriteRefusalPolicy {
            enforce: false,
            count_by: CountBy::Process,
            ..policy
        }
        .slot(offsets, 1);
        assert_eq!(shadow.mode, WRITE_REFUSAL_MODE_SHADOW);
        assert_eq!(shadow.count_by, WRITE_REFUSAL_BY_PROCESS);
    }

    #[test]
    fn the_offsets_come_from_the_running_kernel_or_name_what_is_missing() {
        match resolve_offsets() {
            Ok(offsets) => {
                assert_eq!(offsets.valid, 0);
                assert_ne!(offsets.task_mm, 0);
                assert_ne!(offsets.file_inode, 0);
                assert_ne!(offsets.dentry_parent, offsets.dentry_inode);
                assert_ne!(offsets.inode_sb, offsets.inode_ino);
                assert!(offsets.dentry_name > 0);
            }
            Err(reason) => assert!(reason.contains("BTF"), "{reason}"),
        }
    }

    #[test]
    fn the_default_status_says_nothing_is_attached() {
        let s = WriteRefusalStatus::default();
        assert!(!s.attached);
        assert!(!s.enforcing);
        assert!(s.reason.is_none());
    }
}
