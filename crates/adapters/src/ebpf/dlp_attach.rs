//! Container-aware DLP uprobe target discovery and attach.
//!
//! TLS plaintext only exists inside a userspace `libssl`/`BoringSSL`, so DLP is a
//! uprobe on `SSL_write`/`SSL_read`. A uprobe fires only for processes that map
//! the exact target inode, so to inspect every container's TLS the agent must
//! attach to each container's own SSL library — not a single library on its own
//! rootfs. This module resolves the SSL library every process actually maps
//! (parsing `/proc/<pid>/maps`), deduplicates by `(dev, ino)` so processes that
//! share a file — e.g. pods of the same image over a shared overlayfs lower
//! layer — get a single probe set, and attaches the uprobes per unique inode.

use std::collections::{BTreeSet, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use super::loader::EbpfLoader;

/// SSL library basename markers whose mappings export `SSL_write`/`SSL_read`.
/// OpenSSL exports them from `libssl`; `BoringSSL` from `libssl`/`libboringssl`.
/// `libcrypto` is intentionally excluded — it carries the primitives, not the
/// `SSL_*` record functions the DLP uprobes hook.
const SSL_LIB_MARKERS: &[&str] = &["libssl.so", "libboringssl.so"];

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
    /// resolves inside that process's mount namespace.
    pub attach_path: PathBuf,
    /// Library basename, for logging.
    pub lib: String,
    /// Block device of the resolved file — first half of the dedup key.
    pub dev: u64,
    /// Inode of the resolved file — second half of the dedup key.
    pub ino: u64,
}

/// Extract the distinct in-container absolute paths of mapped SSL libraries from
/// the contents of a `/proc/<pid>/maps` file.
fn ssl_paths_in_maps(maps: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in maps.lines() {
        // maps line: "addr perms offset dev inode pathname". The pathname is the
        // 6th field and the only one that can begin with '/'; anonymous and
        // pseudo mappings ("[heap]", "[stack]") are dropped by the '/' guard.
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or(path);
        if SSL_LIB_MARKERS.iter().any(|m| base.starts_with(m)) {
            out.insert(path.to_string());
        }
    }
    out
}

/// Discovers SSL libraries mapped across processes and attaches the DLP uprobe
/// set once per unique `(dev, ino)`. Holds the dedup/idempotency set so repeated
/// passes (the lifecycle watcher) never double-attach a library already covered.
pub struct DlpUprobeAttacher {
    /// Proc filesystem root (`/proc`, or `/host/proc` when the host proc is
    /// bind-mounted into the agent container).
    proc_root: PathBuf,
    /// `(dev, ino)` of libraries already attached — dedup + idempotency set.
    attached: HashSet<(u64, u64)>,
}

impl DlpUprobeAttacher {
    /// Build an attacher over an explicit proc root.
    pub fn new(proc_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            attached: HashSet::new(),
        }
    }

    /// Build an attacher over the default `/proc`.
    pub fn with_default_proc() -> Self {
        Self::new(Path::new("/proc"))
    }

    /// Number of distinct SSL libraries currently attached.
    pub fn attached_count(&self) -> usize {
        self.attached.len()
    }

    /// Resolve every distinct, not-yet-attached SSL library mapped by any process
    /// under `proc_root`, deduplicated by `(dev, ino)` against the attached set.
    fn discover_new_targets(&self) -> Vec<UprobeTarget> {
        let mut seen: HashSet<(u64, u64)> = self.attached.clone();
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
            for lib in ssl_paths_in_maps(&maps) {
                // Open the library through the owning process's root so the path
                // resolves inside that process's mount namespace.
                let attach_path = self
                    .proc_root
                    .join(pid.to_string())
                    .join("root")
                    .join(lib.trim_start_matches('/'));
                let Ok(meta) = std::fs::metadata(&attach_path) else {
                    continue; // not reachable from the agent — skip
                };
                let key = (meta.dev(), meta.ino());
                if !seen.insert(key) {
                    continue; // already attached, or already queued this pass
                }
                let base = lib.rsplit('/').next().unwrap_or(&lib).to_owned();
                targets.push(UprobeTarget {
                    attach_path,
                    lib: base,
                    dev: key.0,
                    ino: key.1,
                });
            }
        }
        targets
    }

    /// Discover and attach the DLP uprobe set to every new SSL library. Returns
    /// the count of libraries newly attached. Per-library failures are logged and
    /// skipped so one bad library never blocks the rest.
    pub fn attach_new(&mut self, loader: &mut EbpfLoader) -> usize {
        let mut attached = 0usize;
        for t in self.discover_new_targets() {
            match Self::attach_target(loader, &t) {
                Ok(()) => {
                    self.attached.insert((t.dev, t.ino));
                    attached += 1;
                    debug!(
                        lib = %t.lib,
                        path = %t.attach_path.display(),
                        dev = t.dev,
                        ino = t.ino,
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
        attached
    }

    /// Attach the SSL uprobe set to one explicit library path. Used for the
    /// system-library fallback when no process maps an SSL library yet; bypasses
    /// inode dedup.
    pub fn attach_path(loader: &mut EbpfLoader, path: &str) -> anyhow::Result<()> {
        for (prog, sym, is_ret) in SSL_UPROBES {
            loader.attach_uprobe(prog, sym, path, *is_ret)?;
        }
        Ok(())
    }

    /// Attach the full SSL uprobe set (`SSL_write`, `SSL_read` entry + ret) to one
    /// resolved target.
    fn attach_target(loader: &mut EbpfLoader, t: &UprobeTarget) -> anyhow::Result<()> {
        let path = t
            .attach_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-UTF-8 library path"))?;
        Self::attach_path(loader, path)
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

    #[test]
    fn parses_libssl_and_boringssl_only() {
        let paths = ssl_paths_in_maps(MAPS_FIXTURE);
        assert!(paths.contains("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
        assert!(paths.contains("/lib/libboringssl.so"));
        // libcrypto, the binary, anonymous + pseudo mappings excluded.
        assert!(!paths.iter().any(|p| p.contains("libcrypto")));
        assert!(!paths.iter().any(|p| p.contains("curl")));
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn dedups_same_library_mapped_twice() {
        // libssl.so.3 appears in two mappings (r-xp + r--p) but resolves once.
        let paths = ssl_paths_in_maps(MAPS_FIXTURE);
        let ssl = paths.iter().filter(|p| p.contains("libssl.so.3")).count();
        assert_eq!(ssl, 1);
    }

    #[test]
    fn versioned_and_unversioned_names_match() {
        let maps = "\
0-1 r-xp 0 fd:01 1 /a/libssl.so
0-1 r-xp 0 fd:01 2 /b/libssl.so.1.1
0-1 r-xp 0 fd:01 3 /c/libboringssl.so.0";
        let paths = ssl_paths_in_maps(maps);
        assert_eq!(paths.len(), 3);
    }

    #[test]
    fn empty_and_anonymous_maps_yield_nothing() {
        assert!(ssl_paths_in_maps("").is_empty());
        assert!(ssl_paths_in_maps("0-1 rw-p 0 00:00 0 \n0-1 r-xp 0 fd:01 9 [stack]").is_empty());
    }

    #[test]
    fn missing_lib_proc_root_discovers_nothing() {
        // Pointing at a proc root with no SSL-mapping processes returns no targets.
        let dir = tempfile::tempdir().unwrap();
        let attacher = DlpUprobeAttacher::new(dir.path());
        assert!(attacher.discover_new_targets().is_empty());
        assert_eq!(attacher.attached_count(), 0);
    }

    #[test]
    fn discovers_target_from_synthetic_proc() {
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
        let targets = attacher.discover_new_targets();
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
        assert_eq!(attacher.discover_new_targets().len(), 1);
    }
}
