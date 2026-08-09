//! Container-aware DLP uprobe target discovery, attach, and lifecycle.
//!
//! TLS plaintext only exists inside a userspace `libssl`/`BoringSSL`, so DLP is a
//! uprobe on `SSL_write`/`SSL_read`. A uprobe fires only for processes that map
//! the exact target inode, so to inspect every container's TLS the agent must
//! attach to each container's own SSL library — not a single library on its own
//! rootfs. This module resolves the SSL library every process actually maps
//! (parsing `/proc/<pid>/maps`), deduplicates by `(dev, ino)` so processes that
//! share a file — e.g. pods of the same image over a shared overlayfs lower
//! layer — get a single probe set, and attaches the uprobes per unique inode.
//!
//! Containers come and go, so the attach is not one-shot: [`DlpUprobeAttacher`]
//! holds the link fds keyed by `(dev, ino)` and a [`watch`](DlpUprobeAttacher::watch)
//! loop polls periodically, attaching probes to libraries newly mapped by any
//! process and detaching a library's probes once no process maps it any more.
//! The poll/diff/`CancellationToken` shape mirrors the netkit device watcher.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;

/// Poll interval of the DLP target watcher. Container lifecycle events do not
/// need sub-second reaction; this matches the netkit device watcher cadence.
pub const DLP_ATTACH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// SSL library basename markers whose mappings export `SSL_write`/`SSL_read`.
/// OpenSSL exports them from `libssl`; `BoringSSL` from `libssl`/`libboringssl`.
/// `libcrypto` is intentionally excluded — it carries the primitives, not the
/// `SSL_*` record functions the DLP uprobes hook.
const SSL_LIB_MARKERS: &[&str] = &["libssl.so", "libboringssl.so"];

/// Marker the kernel appends to a mapping whose backing file was unlinked after
/// the process mapped it. The inode stays alive and mapped; only its name is
/// gone, so the mapping is still a valid — and still interesting — uprobe target.
const DELETED_MARKER: &str = " (deleted)";

/// SSL uprobe attach points: (loader program name, exported symbol, `is_uretprobe`).
const SSL_UPROBES: &[(&str, &str, bool)] = &[
    ("ssl_write", "SSL_write", false),
    ("ssl_read_entry", "SSL_read", false),
    ("ssl_read_ret", "SSL_read", true),
];

/// A unique SSL library to attach the DLP uprobe set to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UprobeTarget {
    /// Path the loader opens to resolve symbols and attach — the library seen
    /// through the owning process's root (`/proc/<pid>/root/<lib>`), so it
    /// resolves inside that process's mount namespace, or the mapping's
    /// `/proc/<pid>/map_files` entry when the file has been unlinked.
    pub attach_path: PathBuf,
    /// Library basename, for logging.
    pub lib: String,
    /// Block device of the resolved file — first half of the dedup key.
    pub dev: u64,
    /// Inode of the resolved file — second half of the dedup key.
    pub ino: u64,
    /// `SSL_write` offset pre-resolved by the warden scan (`0` = resolve locally).
    ssl_write_offset: u64,
    /// `SSL_read` offset pre-resolved by the warden scan (`0` = resolve locally).
    ssl_read_offset: u64,
    /// When `true` the offsets are authoritative and the agent must NOT read the
    /// ELF (a neighbour container's library it cannot access) — a `0` offset then
    /// means the symbol is absent and its probe is skipped. When `false` (local
    /// scan or system fallback, a library the agent can read) offsets are
    /// resolved on demand.
    preresolved: bool,
}

impl UprobeTarget {
    /// Build a target from a warden `/proc` scan result — offsets are
    /// authoritative (the agent cannot read the neighbour's ELF itself).
    fn from_warden(t: ebpfsentinel_warden_client::DlpTarget) -> Self {
        let lib = t.path.rsplit('/').next().unwrap_or(&t.path).to_owned();
        Self {
            attach_path: PathBuf::from(t.path),
            lib,
            dev: t.dev,
            ino: t.ino,
            ssl_write_offset: t.ssl_write_offset,
            ssl_read_offset: t.ssl_read_offset,
            preresolved: true,
        }
    }
}

/// The uprobe links attached to one SSL library inode, held for their lifetime
/// (dropping the fds detaches the probes).
struct Attachment {
    /// Owned uprobe link fds — one per [`SSL_UPROBES`] entry.
    links: Vec<OwnedFd>,
    /// Sticky attachments survive a reconcile even when no process maps the
    /// inode. The cold-start system-library fallback is sticky so its probe
    /// stays armed before any workload maps the library.
    sticky: bool,
}

/// Outcome of one [`DlpUprobeAttacher::reconcile`] pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReconcileOutcome {
    /// SSL libraries newly attached this pass.
    pub attached: usize,
    /// SSL libraries detached this pass (no process maps them any more).
    pub detached: usize,
    /// The pass did no work because the warden could not be reached, so the
    /// live set is unknown. Distinct from a pass that found nothing to change:
    /// here the existing attachments were deliberately left in place.
    pub skipped: bool,
}

/// One file-backed SSL library mapping found in a `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SslMapping {
    /// Absolute path as seen inside the mapping process's mount namespace, with
    /// the kernel's `(deleted)` marker stripped off.
    path: String,
    /// Name of this mapping's `/proc/<pid>/map_files` entry.
    map_file: String,
    /// The backing file was unlinked after the process mapped it, so `path` no
    /// longer names this inode — and may since name a different one.
    deleted: bool,
}

/// Split a maps line into its five fixed columns and the pathname remainder.
///
/// The pathname is deliberately taken as *the rest of the line* rather than as a
/// sixth whitespace-delimited field: it can legitimately contain spaces, and the
/// kernel appends `" (deleted)"` to it for an unlinked file. Splitting on
/// whitespace truncates both cases at the first space.
fn split_maps_line(line: &str) -> Option<([&str; 5], &str)> {
    let mut cols = [""; 5];
    let mut rest = line.trim_start();
    for col in &mut cols {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        if end == 0 {
            return None; // fewer columns than a maps line has
        }
        *col = &rest[..end];
        rest = rest[end..].trim_start();
    }
    Some((cols, rest))
}

/// Translate a maps address column into the corresponding `map_files` entry name.
///
/// The two are formatted differently: `maps` zero-pads each address to eight hex
/// digits, `map_files` does not, so the mapping printed as `00400000-00401000` is
/// named `400000-401000`. Re-format instead of reusing the column verbatim.
fn map_files_name(range: &str) -> Option<String> {
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    Some(format!("{start:x}-{end:x}"))
}

/// Extract the distinct SSL library mappings from the contents of a
/// `/proc/<pid>/maps` file, one entry per (path, deleted) pair — a process that
/// maps both a replaced library and its replacement holds two live inodes and
/// both are probe targets.
fn ssl_mappings_in_maps(maps: &str) -> Vec<SslMapping> {
    let mut out: BTreeMap<(String, bool), SslMapping> = BTreeMap::new();
    for line in maps.lines() {
        // maps line: "addr perms offset dev inode pathname".
        let Some(([range, _perms, _offset, _dev, inode], rest)) = split_maps_line(line) else {
            continue;
        };
        // Anonymous mappings and pseudo mappings ("[heap]", "[stack]") are not
        // backed by a file, so they carry inode 0 and can never host a uprobe.
        if inode == "0" {
            continue;
        }
        let (path, deleted) = match rest.strip_suffix(DELETED_MARKER) {
            Some(p) => (p, true),
            None => (rest, false),
        };
        if !path.starts_with('/') {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or(path);
        if !SSL_LIB_MARKERS.iter().any(|m| base.starts_with(m)) {
            continue;
        }
        let Some(map_file) = map_files_name(range) else {
            continue;
        };
        // A library occupies several consecutive mappings (text, rodata, data);
        // they all name one inode, so the first one carries the whole library.
        out.entry((path.to_owned(), deleted))
            .or_insert_with(|| SslMapping {
                path: path.to_owned(),
                map_file,
                deleted,
            });
    }
    out.into_values().collect()
}

/// `(inodes_to_attach, inodes_to_detach)` — the result of one reconcile diff,
/// each inode keyed by `(dev, ino)`.
type ReconcilePlan = (Vec<(u64, u64)>, Vec<(u64, u64)>);

/// Split the live and attached inode sets into the inodes to attach (live, not
/// yet attached) and the inodes to detach (attached, non-sticky, no longer
/// live). Pure set algebra, factored out so the lifecycle diff is unit-testable
/// without issuing any BPF syscall.
fn plan_reconcile(
    live: &BTreeSet<(u64, u64)>,
    attached: &BTreeMap<(u64, u64), bool>,
) -> ReconcilePlan {
    let to_attach = live
        .iter()
        .filter(|k| !attached.contains_key(k))
        .copied()
        .collect();
    let to_detach = attached
        .iter()
        .filter(|&(k, &sticky)| !sticky && !live.contains(k))
        .map(|(k, _)| *k)
        .collect();
    (to_attach, to_detach)
}

/// Discovers SSL libraries mapped across processes and attaches the DLP uprobe
/// set once per unique `(dev, ino)`, then keeps that set in step with the live
/// process population. Holds the link fds so a library's probes can be detached
/// when it is no longer mapped.
pub struct DlpUprobeAttacher {
    /// Proc filesystem root (`/proc`, or `/host/proc` when the host proc is
    /// bind-mounted into the agent container).
    proc_root: PathBuf,
    /// Raw fds of the DLP uprobe programs, aligned with [`SSL_UPROBES`]. Valid
    /// for the life of the owning [`EbpfLoader`]; `-1` for a scan-only attacher.
    fds: [RawFd; SSL_UPROBES.len()],
    /// Warden control socket. When set (rootless posture), the privileged
    /// `BPF_LINK_CREATE` is brokered to the warden; when `None`, the agent
    /// attaches directly (bare-metal / single privileged container).
    warden_sock: Option<PathBuf>,
    /// Currently-attached libraries keyed by `(dev, ino)` — dedup, idempotency,
    /// and the owning handle whose drop detaches.
    attached: HashMap<(u64, u64), Attachment>,
}

impl DlpUprobeAttacher {
    /// Build a scan-only attacher over an explicit proc root. The uprobe program
    /// fds are unset, so it can discover targets but not attach — used in tests.
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            fds: [-1; SSL_UPROBES.len()],
            warden_sock: None,
            attached: HashMap::new(),
        }
    }

    /// Build an attacher bound to the DLP uprobe programs of `loader`, resolving
    /// each program's fd up front. Fails if a program was not loaded.
    pub fn with_programs(
        proc_root: impl Into<PathBuf>,
        loader: &EbpfLoader,
    ) -> anyhow::Result<Self> {
        let mut fds: [RawFd; SSL_UPROBES.len()] = [-1; SSL_UPROBES.len()];
        for (i, (prog, _, _)) in SSL_UPROBES.iter().enumerate() {
            fds[i] = loader.program_fd(prog).ok_or_else(|| {
                anyhow::anyhow!("DLP uprobe program '{prog}' was not loaded through the BPF token")
            })?;
        }
        Ok(Self {
            proc_root: proc_root.into(),
            fds,
            warden_sock: None,
            attached: HashMap::new(),
        })
    }

    /// Route the privileged `BPF_LINK_CREATE` through the warden at `sock`. Set in
    /// the rootless posture where the agent dropped the tracing capability; the
    /// agent still resolves the symbol offset itself (a plain ELF read).
    #[must_use]
    pub fn with_warden_socket(mut self, sock: impl Into<PathBuf>) -> Self {
        self.warden_sock = Some(sock.into());
        self
    }

    /// Number of distinct SSL libraries currently attached.
    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    /// Resolve every distinct SSL library currently mapped by any process under
    /// `proc_root`, deduplicated by `(dev, ino)` within the pass. Returns the
    /// full live set (not just new libraries) so the reconcile can also detach.
    fn scan_live_targets(&self) -> Vec<UprobeTarget> {
        let mut seen: HashSet<(u64, u64)> = HashSet::new();
        let mut targets = Vec::new();

        let Ok(entries) = std::fs::read_dir(&self.proc_root) else {
            warn!(proc_root = %self.proc_root.display(), "DLP attach: cannot read proc root");
            return targets;
        };

        for entry in entries.flatten() {
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let maps_path = self.proc_root.join(pid.to_string()).join("maps");
            let Ok(maps) = std::fs::read_to_string(&maps_path) else {
                continue; // process gone or unreadable — skip
            };
            for m in ssl_mappings_in_maps(&maps) {
                let Some((attach_path, meta)) = self.resolve_mapping(pid, &m) else {
                    continue; // not reachable from the agent — skip
                };
                let key = (meta.dev(), meta.ino());
                if !seen.insert(key) {
                    continue; // same inode already collected this pass
                }
                let base = m.path.rsplit('/').next().unwrap_or(&m.path).to_owned();
                targets.push(UprobeTarget {
                    attach_path,
                    lib: base,
                    dev: key.0,
                    ino: key.1,
                    ssl_write_offset: 0,
                    ssl_read_offset: 0,
                    preresolved: false,
                });
            }
        }
        targets
    }

    /// Resolve one SSL mapping to a path the loader can open, together with that
    /// file's metadata.
    ///
    /// A live mapping is opened through the owning process's root, so the path
    /// resolves inside that process's mount namespace. An unlinked mapping has no
    /// name left there, and worse, the name it used to have may since have been
    /// taken by a *replacement* library — an in-place package upgrade unlinks the
    /// old file and renames the new one over it, while every already-running
    /// process keeps the old inode mapped. Resolving such a mapping by name would
    /// silently probe the wrong file, so it goes through `/proc/<pid>/map_files`
    /// instead: those entries are magic links to the mapped inode itself and stay
    /// openable after the file is gone.
    ///
    /// Looking an entry up under `map_files` requires `CAP_SYS_ADMIN` (readdir
    /// alone does not). Every posture that can scan at all holds it - the warden
    /// carries it for bpffs delegation, and the direct posture is privileged - so
    /// the fallback is available wherever it is reachable. Where it is not, the
    /// mapping is skipped exactly as it was before.
    fn resolve_mapping(&self, pid: u32, m: &SslMapping) -> Option<(PathBuf, std::fs::Metadata)> {
        let pid_dir = self.proc_root.join(pid.to_string());
        if !m.deleted {
            let by_name = pid_dir.join("root").join(m.path.trim_start_matches('/'));
            if let Ok(meta) = std::fs::metadata(&by_name) {
                return Some((by_name, meta));
            }
        }
        let by_map_file = pid_dir.join("map_files").join(&m.map_file);
        let meta = std::fs::metadata(&by_map_file).ok()?;
        Some((by_map_file, meta))
    }

    /// One lifecycle pass: attach the DLP uprobe set to SSL libraries newly
    /// mapped by any process, and detach a library's probes once no process maps
    /// it any more (sticky fallback attachments excluded). Per-library attach
    /// failures are logged and skipped so one bad library never blocks the rest.
    pub fn reconcile(&mut self) -> ReconcileOutcome {
        // Rootless posture: the agent cannot read other processes' `/proc`
        // (`CAP_SYS_PTRACE`), so it delegates discovery to the warden, which
        // returns deduped targets with offsets pre-resolved. Direct posture (the
        // agent is privileged) scans `/proc` itself.
        let live: Vec<UprobeTarget> = match &self.warden_sock {
            Some(sock) => match crate::warden::uprobe::scan_via_warden(sock) {
                Ok(targets) => targets.into_iter().map(UprobeTarget::from_warden).collect(),
                Err(e) => {
                    // The broker is down, which says nothing about what is
                    // mapped. Treating it as "nothing is live" would detach
                    // every probe now and re-create them on the next tick, so
                    // a warden restart would churn the whole link set for no
                    // reason. Hold what we have and try again next tick.
                    warn!(
                        error = %e,
                        held = self.attached.len(),
                        "warden unreachable; holding the current DLP uprobe set"
                    );
                    return ReconcileOutcome {
                        attached: 0,
                        detached: 0,
                        skipped: true,
                    };
                }
            },
            None => self.scan_live_targets(),
        };
        let live_map: BTreeMap<(u64, u64), UprobeTarget> =
            live.into_iter().map(|t| ((t.dev, t.ino), t)).collect();
        let live_keys: BTreeSet<(u64, u64)> = live_map.keys().copied().collect();
        let attached_sticky: BTreeMap<(u64, u64), bool> =
            self.attached.iter().map(|(k, a)| (*k, a.sticky)).collect();

        let (to_attach, to_detach) = plan_reconcile(&live_keys, &attached_sticky);

        for k in &to_detach {
            if let Some(att) = self.attached.remove(k) {
                debug!(
                    dev = k.0,
                    ino = k.1,
                    links = att.links.len(),
                    "DLP uprobe detached (SSL library no longer mapped)"
                );
            }
        }

        let mut attached = 0usize;
        for k in to_attach {
            let Some(t) = live_map.get(&k) else {
                continue;
            };
            match self.attach_target_links(t) {
                Ok(links) => {
                    self.attached.insert(
                        k,
                        Attachment {
                            links,
                            sticky: false,
                        },
                    );
                    attached += 1;
                    debug!(
                        lib = %t.lib,
                        path = %t.attach_path.display(),
                        dev = k.0,
                        ino = k.1,
                        "DLP uprobe attached to SSL library"
                    );
                }
                Err(e) => warn!(
                    lib = %t.lib,
                    path = %t.attach_path.display(),
                    error = %e,
                    "DLP uprobe attach failed; skipping library"
                ),
            }
        }

        ReconcileOutcome {
            attached,
            detached: to_detach.len(),
            skipped: false,
        }
    }

    /// Attach the DLP uprobe set to one explicit library path as a **sticky**
    /// attachment. Used for the cold-start fallback when no process maps an SSL
    /// library yet; the inode-wide probe arms and fires once a process maps the
    /// library, and the sticky flag keeps a later reconcile from tearing it down.
    pub fn attach_fallback_path(&mut self, path: &str) -> anyhow::Result<()> {
        let meta = std::fs::metadata(path)
            .map_err(|e| anyhow::anyhow!("stat fallback SSL library '{path}': {e}"))?;
        let key = (meta.dev(), meta.ino());
        let base = path.rsplit('/').next().unwrap_or(path).to_owned();
        let target = UprobeTarget {
            attach_path: PathBuf::from(path),
            lib: base,
            dev: key.0,
            ino: key.1,
            // A system library the agent can read itself — resolve offsets on
            // demand (works in both postures).
            ssl_write_offset: 0,
            ssl_read_offset: 0,
            preresolved: false,
        };
        let links = self.attach_target_links(&target)?;
        self.attached.insert(
            key,
            Attachment {
                links,
                sticky: true,
            },
        );
        Ok(())
    }

    /// Attach the full SSL uprobe set (`SSL_write`, `SSL_read` entry + ret) to one
    /// resolved target, returning the owned link fds. A partial failure drops the
    /// links already created, detaching them, so no half-attached set lingers.
    fn attach_target_links(&self, t: &UprobeTarget) -> anyhow::Result<Vec<OwnedFd>> {
        let path = t
            .attach_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 library path"))?;
        let mut links = Vec::with_capacity(SSL_UPROBES.len());
        for (i, (prog, sym, is_ret)) in SSL_UPROBES.iter().enumerate() {
            if let Some(sock) = &self.warden_sock {
                // Rootless: the warden — which holds the tracing capability and
                // can read the target — creates the link and passes back its fd.
                let preset = if *sym == "SSL_write" {
                    t.ssl_write_offset
                } else {
                    t.ssl_read_offset
                };
                let offset = if t.preresolved {
                    // Authoritative: the agent cannot read this neighbour's ELF.
                    // A `0` offset means the symbol is absent — skip its probe.
                    if preset == 0 {
                        continue;
                    }
                    preset
                } else {
                    // A library the agent itself can read (system fallback).
                    kfunc_attach::resolve_symbol_offset(path, sym)?
                };
                let link = crate::warden::uprobe::attach_via_warden(
                    sock,
                    self.fds[i],
                    path,
                    offset,
                    *is_ret,
                )?;
                // The warden created the link, so the direct path's log line
                // never fires here. Say the same thing anyway: an operator
                // debugging a rootless deployment needs the same evidence
                // that a probe attached, whoever issued BPF_LINK_CREATE.
                let probe = if *is_ret { "uretprobe" } else { "uprobe" };
                tracing::info!(
                    program = prog,
                    target = path,
                    symbol = sym,
                    probe,
                    "uprobe kfunc program attached (uprobe_multi link) via warden"
                );
                links.push(link);
            } else {
                // Direct: the agent creates the link itself (bare-metal / single
                // privileged container).
                let link = kfunc_attach::attach_uprobe_raw(prog, self.fds[i], path, sym, *is_ret)?;
                links.push(link);
            }
        }
        Ok(links)
    }

    /// Long-running watcher: reconcile the attached SSL library set every
    /// `poll_interval` until `cancel` fires. Attaches probes to libraries newly
    /// mapped by appearing containers and detaches them on teardown. Consumes the
    /// attacher; on cancellation the held link fds drop and every probe detaches.
    pub async fn watch(mut self, poll_interval: Duration, cancel: CancellationToken) {
        info!(
            initial_targets = self.attached_count(),
            poll_secs = poll_interval.as_secs(),
            "DLP uprobe target watcher started"
        );
        let mut ticker = tokio::time::interval(poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    debug!("DLP uprobe target watcher cancelled");
                    break;
                }
                _ = ticker.tick() => {
                    let outcome = self.reconcile();
                    if outcome.attached > 0 || outcome.detached > 0 {
                        info!(
                            attached = outcome.attached,
                            detached = outcome.detached,
                            total = self.attached_count(),
                            "DLP uprobe targets reconciled"
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS_FIXTURE: &str = "\
55a0c0000000-55a0c0021000 r-xp 00000000 fd:01 100 /usr/bin/curl
7f1000000000-7f1000100000 r-xp 00000000 fd:01 200 /usr/lib/x86_64-linux-gnu/libssl.so.3
7f1000100000-7f1000200000 r--p 00100000 fd:01 200 /usr/lib/x86_64-linux-gnu/libssl.so.3
7f1000200000-7f1000300000 r-xp 00000000 fd:01 201 /usr/lib/x86_64-linux-gnu/libcrypto.so.3
7f1000300000-7f1000400000 rw-p 00000000 00:00 0 \n\
7f1000400000-7f1000500000 r-xp 00000000 fd:01 202 [heap]
7f1000500000-7f1000600000 r-xp 00000000 fd:01 203 /lib/libboringssl.so";

    /// Paths of the SSL mappings parsed out of a maps fixture.
    fn ssl_paths(maps: &str) -> Vec<String> {
        ssl_mappings_in_maps(maps)
            .into_iter()
            .map(|m| m.path)
            .collect()
    }

    #[test]
    fn parses_libssl_and_boringssl_only() {
        let paths = ssl_paths(MAPS_FIXTURE);
        assert!(
            paths
                .iter()
                .any(|p| p == "/usr/lib/x86_64-linux-gnu/libssl.so.3")
        );
        assert!(paths.iter().any(|p| p == "/lib/libboringssl.so"));
        // libcrypto, the binary, anonymous + pseudo mappings excluded.
        assert!(!paths.iter().any(|p| p.contains("libcrypto")));
        assert!(!paths.iter().any(|p| p.contains("curl")));
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn dedups_same_library_mapped_twice() {
        // libssl.so.3 appears in two mappings (r-xp + r--p) but resolves once.
        let paths = ssl_paths(MAPS_FIXTURE);
        let ssl = paths.iter().filter(|p| p.contains("libssl.so.3")).count();
        assert_eq!(ssl, 1);
    }

    #[test]
    fn versioned_and_unversioned_names_match() {
        let maps = "\
0-1 r-xp 0 fd:01 1 /a/libssl.so
0-1 r-xp 0 fd:01 2 /b/libssl.so.1.1
0-1 r-xp 0 fd:01 3 /c/libboringssl.so.0";
        assert_eq!(ssl_paths(maps).len(), 3);
    }

    #[test]
    fn empty_and_anonymous_maps_yield_nothing() {
        assert!(ssl_mappings_in_maps("").is_empty());
        assert!(ssl_mappings_in_maps("0-1 rw-p 0 00:00 0 \n0-1 r-xp 0 fd:01 9 [stack]").is_empty());
    }

    #[test]
    fn strips_the_deleted_marker_and_flags_the_mapping() {
        let maps = "7f10-7f20 r-xp 0 fd:01 7 /usr/lib/libssl.so.3 (deleted)\n";
        let mappings = ssl_mappings_in_maps(maps);
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].path, "/usr/lib/libssl.so.3");
        assert!(mappings[0].deleted);
        assert_eq!(mappings[0].map_file, "7f10-7f20");
    }

    #[test]
    fn a_replaced_library_and_its_replacement_are_two_targets() {
        // An in-place upgrade: the running process still maps the old inode
        // (marked deleted) while a freshly dlopen'd copy occupies the same path.
        let maps = "\
7f10-7f20 r-xp 0 fd:01 7 /usr/lib/libssl.so.3 (deleted)
7f30-7f40 r-xp 0 fd:01 9 /usr/lib/libssl.so.3";
        let mappings = ssl_mappings_in_maps(maps);
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings.iter().filter(|m| m.deleted).count(), 1);
    }

    #[test]
    fn a_path_containing_spaces_survives_parsing() {
        // Splitting on whitespace would truncate this to "/opt/my", which then
        // fails the SSL basename match and the library goes unprobed.
        let maps = "7f10-7f20 r-xp 0 fd:01 7 /opt/my app/libssl.so.3\n";
        assert_eq!(ssl_paths(maps), vec!["/opt/my app/libssl.so.3".to_owned()]);
    }

    #[test]
    fn map_files_names_drop_the_zero_padding_maps_adds() {
        // maps pads to eight hex digits, map_files does not.
        assert_eq!(
            map_files_name("00400000-00401000").unwrap(),
            "400000-401000"
        );
        assert_eq!(
            map_files_name("7f1000000000-7f1000100000").unwrap(),
            "7f1000000000-7f1000100000"
        );
        assert!(map_files_name("not-hex").is_none());
        assert!(map_files_name("0").is_none());
    }

    #[test]
    fn missing_lib_proc_root_scans_nothing() {
        // Pointing at a proc root with no SSL-mapping processes returns no targets.
        let dir = tempfile::tempdir().unwrap();
        let attacher = DlpUprobeAttacher::new(dir.path());
        assert!(attacher.scan_live_targets().is_empty());
        assert_eq!(attacher.attached_count(), 0);
    }

    #[test]
    fn scans_target_from_synthetic_proc() {
        use std::fs;
        // Build a fake proc: /<tmp>/1234/{maps,root/lib/libssl.so.3}
        let dir = tempfile::tempdir().unwrap();
        let pid_dir = dir.path().join("1234");
        let lib_dir = pid_dir.join("root").join("lib");
        fs::create_dir_all(&lib_dir).unwrap();
        let lib = lib_dir.join("libssl.so.3");
        fs::write(&lib, b"\x7fELF").unwrap();
        fs::write(
            pid_dir.join("maps"),
            "0-1 r-xp 0 fd:01 7 /lib/libssl.so.3\n",
        )
        .unwrap();

        let attacher = DlpUprobeAttacher::new(dir.path());
        let targets = attacher.scan_live_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].lib, "libssl.so.3");
        assert_eq!(targets[0].attach_path, lib);
    }

    #[test]
    fn dedups_targets_by_inode_across_pids() {
        use std::fs;
        // Two pids whose root/lib/libssl.so.3 is the SAME underlying file (hard
        // link → same inode) resolves to a single target.
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared-libssl.so.3");
        fs::write(&shared, b"\x7fELF").unwrap();
        for pid in ["100", "200"] {
            let lib_dir = dir.path().join(pid).join("root").join("lib");
            fs::create_dir_all(&lib_dir).unwrap();
            fs::hard_link(&shared, lib_dir.join("libssl.so.3")).unwrap();
            fs::write(
                dir.path().join(pid).join("maps"),
                "0-1 r-xp 0 fd:01 7 /lib/libssl.so.3\n",
            )
            .unwrap();
        }
        let attacher = DlpUprobeAttacher::new(dir.path());
        assert_eq!(attacher.scan_live_targets().len(), 1);
    }

    #[test]
    fn deleted_mapping_resolves_to_the_mapped_inode_not_its_replacement() {
        use std::fs;
        // A library unlinked out from under a running process, whose old path has
        // since been taken by a replacement. Resolving by name would probe the
        // replacement - a different inode the process does not map - so the scan
        // must go through map_files and land on the inode still mapped.
        let dir = tempfile::tempdir().unwrap();
        let mapped = dir.path().join("mapped-libssl.so.3");
        fs::write(&mapped, b"\x7fELF").unwrap();
        let mapped_ino = fs::metadata(&mapped).unwrap().ino();

        let pid_dir = dir.path().join("1234");
        let lib_dir = pid_dir.join("root").join("lib");
        fs::create_dir_all(&lib_dir).unwrap();
        let replacement = lib_dir.join("libssl.so.3");
        fs::write(&replacement, b"\x7fELF-new").unwrap();
        let replacement_ino = fs::metadata(&replacement).unwrap().ino();
        assert_ne!(mapped_ino, replacement_ino);

        let map_files = pid_dir.join("map_files");
        fs::create_dir_all(&map_files).unwrap();
        // Stands in for the kernel's magic link, which stays resolvable after the
        // file it points at is unlinked. A unit test cannot hold an unlinked file
        // reachable by path; the genuinely-unlinked case is covered on the VM.
        std::os::unix::fs::symlink(&mapped, map_files.join("7f1000000000-7f1000100000")).unwrap();
        fs::write(
            pid_dir.join("maps"),
            "7f1000000000-7f1000100000 r-xp 0 fd:01 7 /lib/libssl.so.3 (deleted)\n",
        )
        .unwrap();

        let attacher = DlpUprobeAttacher::new(dir.path());
        let targets = attacher.scan_live_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].lib, "libssl.so.3");
        assert_eq!(targets[0].ino, mapped_ino);
        assert_ne!(targets[0].ino, replacement_ino);
        assert_eq!(
            targets[0].attach_path,
            map_files.join("7f1000000000-7f1000100000")
        );
    }

    #[test]
    fn live_mapping_falls_back_to_map_files_when_the_root_path_is_unreachable() {
        use std::fs;
        // No `root/` at all - the agent cannot traverse into this process's mount
        // namespace - but the mapping is still discoverable through map_files.
        let dir = tempfile::tempdir().unwrap();
        let mapped = dir.path().join("mapped-libssl.so.3");
        fs::write(&mapped, b"\x7fELF").unwrap();

        let map_files = dir.path().join("1234").join("map_files");
        fs::create_dir_all(&map_files).unwrap();
        std::os::unix::fs::symlink(&mapped, map_files.join("400000-401000")).unwrap();
        fs::write(
            dir.path().join("1234").join("maps"),
            "00400000-00401000 r-xp 0 fd:01 7 /lib/libssl.so.3\n",
        )
        .unwrap();

        let attacher = DlpUprobeAttacher::new(dir.path());
        let targets = attacher.scan_live_targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].attach_path, map_files.join("400000-401000"));
    }

    #[test]
    fn plan_reconcile_attaches_new_and_detaches_vanished() {
        let live: BTreeSet<(u64, u64)> = [(1, 10), (1, 20)].into_iter().collect();
        // (1,30) was attached but is no longer live → detach; (1,10) stays;
        // (1,20) is new → attach.
        let attached: BTreeMap<(u64, u64), bool> =
            [((1, 10), false), ((1, 30), false)].into_iter().collect();
        let (to_attach, to_detach) = plan_reconcile(&live, &attached);
        assert_eq!(to_attach, vec![(1, 20)]);
        assert_eq!(to_detach, vec![(1, 30)]);
    }

    #[test]
    fn plan_reconcile_keeps_sticky_when_not_live() {
        // A sticky fallback inode no process maps must NOT be detached.
        let live: BTreeSet<(u64, u64)> = BTreeSet::new();
        let attached: BTreeMap<(u64, u64), bool> = [((1, 99), true)].into_iter().collect();
        let (to_attach, to_detach) = plan_reconcile(&live, &attached);
        assert!(to_attach.is_empty());
        assert!(to_detach.is_empty());
    }

    #[test]
    fn plan_reconcile_stable_set_is_noop() {
        let live: BTreeSet<(u64, u64)> = [(1, 10), (1, 20)].into_iter().collect();
        let attached: BTreeMap<(u64, u64), bool> =
            [((1, 10), false), ((1, 20), false)].into_iter().collect();
        let (to_attach, to_detach) = plan_reconcile(&live, &attached);
        assert!(to_attach.is_empty());
        assert!(to_detach.is_empty());
    }

    #[test]
    fn an_unreachable_warden_holds_the_link_set_instead_of_rebuilding_it() {
        // A warden bounce must not look like "no library is mapped any more".
        // If it did, the pass would detach every probe and the next pass would
        // attach them again - a full teardown and rebuild of the link set,
        // triggered by the broker restarting rather than by anything on the
        // host changing.
        let dir = tempfile::tempdir().unwrap();
        let mut attacher =
            DlpUprobeAttacher::new(dir.path()).with_warden_socket(dir.path().join("absent.sock"));
        attacher.attached.insert(
            (1, 10),
            Attachment {
                links: Vec::new(),
                sticky: false,
            },
        );

        let outcome = attacher.reconcile();

        assert!(outcome.skipped, "the pass must declare itself skipped");
        assert_eq!(outcome.attached, 0);
        assert_eq!(outcome.detached, 0);
        assert_eq!(
            attacher.attached_count(),
            1,
            "the existing attachment survives the broker being down"
        );

        // Repeating the pass is equally inert: no second link for the same
        // inode, which is the duplicate this guards against.
        let again = attacher.reconcile();
        assert!(again.skipped);
        assert_eq!(attacher.attached_count(), 1);
    }
}
