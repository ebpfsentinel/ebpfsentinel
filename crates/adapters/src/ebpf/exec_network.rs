#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)
//! The allow-list of executables that reach the network: the maps it is
//! written through, the two LSM links that decide it, and the ring its
//! refusals come back on.
//!
//! Order is what makes it safe. The executables and the offsets are written
//! before either hook is attached, so the first call the kernel decides is
//! decided against the list as configured rather than against an empty set,
//! and the two hooks are attached together or not at all: a node refusing
//! `socket_create` and not `connect` would be an allow-list a parent process
//! walks around by handing a socket down.
//!
//! The identity written is the `(device, inode)` the agent reads by stat-ing
//! each path from its own mount view. An agent in a container sees the host's
//! binaries only through what is mounted into it, so a path that resolves to
//! another file there names another file to the kernel too.

use std::collections::HashSet;
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::sync::{Mutex, OnceLock};

use aya::maps::{Array, HashMap as AyaHashMap, MapData, RingBuf};
use domain::firewall::exec_network::{ExecNetworkHook, ExecNetworkRecord};
use ebpf_common::exec_network::{
    EXEC_NET_AF_INET6, EXEC_NET_CONFIG_SLOT, EXEC_NET_MODE_ENFORCE, EXEC_NET_MODE_OBSERVE,
    ExecNetConfig, ExecNetEvent, ExecNetKey, kernel_dev,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use super::event_reader::{drain_tick, watch_ringbuf};
use super::kfunc;
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;
use super::ringbuf_observer::{DrainTrigger, RingBufObserver};

/// The object the allow-list is loaded from, and the source its records are
/// counted under.
pub const EXEC_NETWORK_OBJECT: &str = "lsm-exec-network";
/// The program deciding socket creation.
pub const EXEC_NETWORK_CREATE_PROGRAM: &str = "exec_network_socket_create";
/// The program deciding a connection.
pub const EXEC_NETWORK_CONNECT_PROGRAM: &str = "exec_network_socket_connect";

/// What the agent can say about the allow-list, for the start-up log and the
/// kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExecNetworkStatus {
    /// Both hooks are attached and deciding.
    pub attached: bool,
    /// The kernel refuses calls outside the list rather than reporting them.
    pub enforcing: bool,
    /// How many distinct executables the kernel holds in the set, the agent
    /// itself included.
    pub executables: usize,
    /// Why the list is not in force, in one sentence. `None` when it is, and
    /// when it is off in the configuration.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<ExecNetworkStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<ExecNetworkStatus> {
    STATUS.get_or_init(|| Mutex::new(ExecNetworkStatus::default()))
}

/// Publish what the agent can say about the allow-list.
pub fn publish_status(status: ExecNetworkStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the allow-list.
#[must_use]
pub fn status() -> ExecNetworkStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The six offsets the hooks walk, read off the running kernel's BTF.
///
/// All six or an error: a hook handed a partial layout would read some other
/// field as an inode and refuse whatever that field happened to hold.
///
/// # Errors
///
/// Returns the struct or member the kernel's BTF does not describe.
pub fn resolve_offsets() -> Result<ExecNetConfig, String> {
    let one = |structure: &str, member: &str| -> Result<u32, String> {
        let found = kfunc::vmlinux_struct_member_offsets(structure, &[member])
            .map_err(|e| format!("the kernel BTF does not describe `{structure}`: {e}"))?;
        found
            .first()
            .copied()
            .flatten()
            .ok_or_else(|| format!("the kernel BTF has no `{structure}.{member}`"))
    };
    let inode = kfunc::vmlinux_struct_member_offsets("inode", &["i_ino", "i_sb"])
        .map_err(|e| format!("the kernel BTF does not describe `inode`: {e}"))?;
    let (Some(inode_ino), Some(inode_sb)) = (
        inode.first().copied().flatten(),
        inode.get(1).copied().flatten(),
    ) else {
        return Err("the kernel BTF has no `inode.i_ino` or no `inode.i_sb`".to_string());
    };
    Ok(ExecNetConfig {
        task_mm: one("task_struct", "mm")?,
        mm_exe_file: one("mm_struct", "exe_file")?,
        file_inode: one("file", "f_inode")?,
        inode_ino,
        inode_sb,
        sb_dev: one("super_block", "s_dev")?,
        mode: EXEC_NET_MODE_OBSERVE,
        valid: 0,
    })
}

/// The key the kernel compares for the file at `path`, following symlinks.
///
/// # Errors
///
/// Returns the I/O error of the `stat`, a missing file being the common one.
pub fn key_of(path: &str) -> std::io::Result<ExecNetKey> {
    let meta = std::fs::metadata(path)?;
    Ok(key_from_stat(meta.dev(), meta.ino()))
}

/// Convert the `stat(2)` device encoding into the kernel's.
#[must_use]
fn key_from_stat(dev: u64, ino: u64) -> ExecNetKey {
    ExecNetKey {
        ino,
        dev: kernel_dev(libc::major(dev), libc::minor(dev)),
        _pad: 0,
    }
}

/// The keys for `paths`, plus the agent's own executable.
///
/// A path that does not resolve is left out and named in the second half of
/// the answer rather than failing the set: a list shared across a fleet names
/// binaries one node does not carry, and the set is re-read on a timer so the
/// day one is installed it is picked up.
#[must_use]
pub fn allowed_keys(paths: &[String]) -> (HashSet<ExecNetKey>, Vec<String>) {
    let mut keys = HashSet::with_capacity(paths.len() + 1);
    let mut missing = Vec::new();
    // The agent never refuses itself: an enforcing list without it would cut
    // the agent off from its own exporters and feeds.
    match key_of("/proc/self/exe") {
        Ok(key) => {
            keys.insert(key);
        }
        Err(e) => warn!("the agent's own executable is unreadable, so it is not in the set: {e}"),
    }
    for path in paths {
        match key_of(path) {
            Ok(key) => {
                keys.insert(key);
            }
            Err(e) => missing.push(format!("{path}: {e}")),
        }
    }
    (keys, missing)
}

/// The configuration slot and the allowed set.
pub struct ExecNetworkMaps {
    config: Array<MapData, ExecNetConfig>,
    allowed: AyaHashMap<MapData, ExecNetKey, u8>,
    held: HashSet<ExecNetKey>,
}

impl ExecNetworkMaps {
    /// Take the two maps out of a loaded allow-list object.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or carries another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let config = Array::try_from(
            ebpf.take_map("EXEC_NET_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'EXEC_NET_CONFIG' not found"))?,
        )?;
        let allowed = AyaHashMap::try_from(
            ebpf.take_map("EXEC_NET_ALLOWED")
                .ok_or_else(|| anyhow::anyhow!("map 'EXEC_NET_ALLOWED' not found"))?,
        )?;
        Ok(Self {
            config,
            allowed,
            held: HashSet::new(),
        })
    }

    /// Make the kernel's set exactly `keys`.
    ///
    /// New keys go in before stale ones come out, so a binary replaced on
    /// disk is never in neither state: for one write the old inode and the
    /// new are both allowed, which costs nothing, where the other order would
    /// refuse the new one for as long as the gap lasts.
    ///
    /// # Errors
    ///
    /// Returns the first write the kernel refused.
    pub fn replace(&mut self, keys: &HashSet<ExecNetKey>) -> Result<(), anyhow::Error> {
        for key in keys.difference(&self.held) {
            self.allowed
                .insert(*key, 1, 0)
                .map_err(|e| anyhow::anyhow!("EXEC_NET_ALLOWED write failed: {e}"))?;
        }
        for key in self.held.difference(keys) {
            if let Err(e) = self.allowed.remove(key) {
                debug!("EXEC_NET_ALLOWED entry already gone: {e}");
            }
        }
        self.held.clone_from(keys);
        Ok(())
    }

    /// How many executables the kernel holds.
    #[must_use]
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Write the offsets and the mode, which is what turns the hooks on.
    ///
    /// # Errors
    ///
    /// Returns the kernel's refusal of the write.
    pub fn arm(&mut self, offsets: ExecNetConfig, enforce: bool) -> Result<(), anyhow::Error> {
        let slot = ExecNetConfig {
            mode: if enforce {
                EXEC_NET_MODE_ENFORCE
            } else {
                EXEC_NET_MODE_OBSERVE
            },
            valid: 1,
            ..offsets
        };
        self.config
            .set(EXEC_NET_CONFIG_SLOT, slot, 0)
            .map_err(|e| anyhow::anyhow!("EXEC_NET_CONFIG write failed: {e}"))
    }
}

/// Holds the two LSM links. Dropping it detaches both.
#[derive(Default)]
pub struct ExecNetworkAttacher {
    links: Vec<OwnedFd>,
}

impl ExecNetworkAttacher {
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
        for program in [EXEC_NETWORK_CREATE_PROGRAM, EXEC_NETWORK_CONNECT_PROGRAM] {
            let prog_fd: RawFd = loader
                .program_fd(program)
                .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
            // A refusal here drops the links already taken, which is the
            // "neither" half of the promise.
            links.push(kfunc_attach::attach_lsm(program, prog_fd).map_err(|e| e.to_string())?);
        }
        self.links = links;
        info!("network executables attached on socket_create and socket_connect");
        Ok(())
    }

    /// Whether both links are held.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.links.len() == 2
    }
}

/// Reads the calls outside the list from `EXEC_NET_EVENTS`.
pub struct ExecNetworkEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl ExecNetworkEventReader {
    /// Take the `EXEC_NET_EVENTS` map from the loaded object.
    ///
    /// # Errors
    ///
    /// Returns an error when the map is missing or cannot be polled.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf
            .take_map("EXEC_NET_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("map 'EXEC_NET_EVENTS' not found"))?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = watch_ringbuf(ring_buf)?;
        Ok(Self { ring_buf: async_fd })
    }

    /// Drain the ring into `tx` until `cancel` fires or the ring errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<ExecNetworkRecord>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let mut async_fd = self.ring_buf;
        let mut tick = drain_tick();
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            let drained = drain(guard.get_inner_mut(), &tx, &observer);
                            guard.clear_ready();
                            observer.drain_pass(DrainTrigger::Wakeup, drained);
                        }
                        Err(e) => {
                            error!("network executables RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    let drained = drain(async_fd.get_mut(), &tx, &observer);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

fn drain(
    rb: &mut RingBuf<MapData>,
    tx: &mpsc::Sender<ExecNetworkRecord>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<ExecNetEvent>() {
            observer.dropped("truncated_record");
            continue;
        }
        // SAFETY: the length was checked against `size_of::<ExecNetEvent>()` above, the type is
        // `#[repr(C)]` integers only so every bit pattern is a value, and `read_unaligned` asks
        // nothing of the ring's alignment.
        let raw = unsafe { bytes.as_ptr().cast::<ExecNetEvent>().read_unaligned() };
        let Some(record) = parse(&raw) else {
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
fn parse(raw: &ExecNetEvent) -> Option<ExecNetworkRecord> {
    let hook = ExecNetworkHook::from_kernel(raw.hook)?;
    let executable = (raw.ino != 0 || raw.dev != 0)
        .then(|| (libc::makedev(raw.dev >> 20, raw.dev & 0x000f_ffff), raw.ino));
    Some(ExecNetworkRecord {
        at_ns: raw.at_ns,
        tgid: raw.tgid,
        executable,
        hook,
        ipv6: raw.family == EXEC_NET_AF_INET6,
        refused: raw.refused != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::exec_network::{EXEC_NET_AF_INET, EXEC_NET_HOOK_CONNECT};

    #[test]
    fn the_stat_device_is_written_in_the_kernel_encoding_and_read_back() {
        let dev = libc::makedev(259, 3);
        let key = key_from_stat(dev, 42);
        assert_eq!(key.dev, kernel_dev(259, 3));
        let raw = ExecNetEvent {
            at_ns: 5,
            ino: key.ino,
            tgid: 900,
            dev: key.dev,
            hook: EXEC_NET_HOOK_CONNECT,
            refused: 1,
            family: EXEC_NET_AF_INET,
            _pad: 0,
        };
        let record = parse(&raw).expect("a known hook parses");
        assert_eq!(record.executable, Some((dev, 42)));
        assert_eq!(record.hook, ExecNetworkHook::Connect);
        assert!(record.refused);
        assert!(!record.ipv6);
    }

    #[test]
    fn an_unread_executable_parses_as_none_and_an_unknown_hook_is_dropped() {
        let mut raw = ExecNetEvent {
            family: EXEC_NET_AF_INET6,
            ..ExecNetEvent::default()
        };
        let record = parse(&raw).expect("the create hook parses");
        assert_eq!(record.executable, None);
        assert!(record.ipv6);
        raw.hook = 9;
        assert!(parse(&raw).is_none());
    }

    #[test]
    fn the_agent_is_always_in_its_own_set_and_a_missing_path_is_named() {
        let (keys, missing) = allowed_keys(&["/nonexistent/binary".to_string()]);
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&key_of("/proc/self/exe").expect("self is readable")));
        assert_eq!(missing.len(), 1);
        assert!(missing[0].starts_with("/nonexistent/binary: "));
    }

    #[test]
    fn a_symlink_names_the_file_it_points_at() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("tool");
        std::fs::write(&target, b"#!/bin/true\n").expect("write");
        let link = dir.path().join("alias");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let a = key_of(target.to_str().expect("utf8")).expect("target");
        let b = key_of(link.to_str().expect("utf8")).expect("link");
        assert_eq!(a, b);
    }

    #[test]
    fn the_offsets_come_from_the_running_kernel_or_name_what_is_missing() {
        // A host without BTF answers with the missing piece rather than a
        // layout of zeros.
        match resolve_offsets() {
            Ok(offsets) => {
                assert_eq!(offsets.valid, 0);
                assert_ne!(offsets.task_mm, 0);
                assert_ne!(offsets.inode_sb, offsets.inode_ino);
            }
            Err(reason) => assert!(reason.contains("BTF"), "{reason}"),
        }
    }

    #[test]
    fn the_default_status_says_nothing_is_attached() {
        let s = ExecNetworkStatus::default();
        assert!(!s.attached);
        assert!(!s.enforcing);
        assert!(s.reason.is_none());
    }
}
