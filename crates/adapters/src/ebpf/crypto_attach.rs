//! Calls into the system cryptographic libraries, counted per process.
//!
//! One uprobe program sits on the symmetric encryption entry point of every
//! crypto library a running process maps, found the way the DLP probes find
//! TLS libraries: each `/proc/<pid>/maps` is read, each library is opened
//! through the process's own root and probed once per inode. The program
//! counts calls per thread group and reads no argument, so what reaches the
//! agent is a number per process and nothing else.
//!
//! What is not counted is said rather than implied: a binary carrying its own
//! cipher or linked statically calls none of these symbols, and a library the
//! agent cannot open, because it runs without the right to read another
//! process's root, is not probed. The status names how many libraries hold.

use std::collections::{HashMap, HashSet};
use std::os::fd::{OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock, PoisonError};

use aya::maps::{MapData, PerCpuHashMap, PerCpuValues};
use ebpf_common::crypto::{CRYPTO_CALLS_MAP, CRYPTO_ENTRY_POINTS, CRYPTO_PROGRAM};
use tracing::{debug, info};

use super::dlp_attach::{library_mappings_in_maps, resolve_mapping_in};
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;

/// Directories a host keeps its shared libraries in, read when no running
/// process maps a crypto library yet, so the first process that does is
/// counted from its first call.
const SYSTEM_LIBRARY_DIRS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib64",
    "/lib64",
    "/usr/lib",
    "/lib",
];

/// What the agent can say about the crypto call counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CryptoStatus {
    /// At least one library is probed and calls are counted.
    pub attached: bool,
    /// Distinct library files probed now.
    pub libraries: usize,
    /// Why nothing is counted, in one sentence. `None` when something is.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<CryptoStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<CryptoStatus> {
    STATUS.get_or_init(|| Mutex::new(CryptoStatus::default()))
}

/// Publish what the agent can say about the crypto call counter.
pub fn publish_status(status: CryptoStatus) {
    *status_cell().lock().unwrap_or_else(PoisonError::into_inner) = status;
}

/// What the agent can currently say about the crypto call counter.
#[must_use]
pub fn status() -> CryptoStatus {
    status_cell()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The symbols to probe in a library file named `base`, or `None` when it is
/// not a crypto library this counter reads.
fn entry_points_of(base: &str) -> Option<&'static [&'static str]> {
    CRYPTO_ENTRY_POINTS
        .iter()
        .find(|(library, _)| base.starts_with(library))
        .map(|(_, symbols)| *symbols)
}

fn library_markers() -> Vec<&'static str> {
    CRYPTO_ENTRY_POINTS
        .iter()
        .map(|(library, _)| *library)
        .collect()
}

/// New calls per thread group between two readings. A count lower than the
/// last one means the slot was evicted and taken again, so the whole count
/// is new; a thread group missing from `now` is gone and forgotten.
fn deltas_between(last: &HashMap<u32, u64>, now: &HashMap<u32, u64>) -> Vec<(u32, u64)> {
    let mut out: Vec<(u32, u64)> = now
        .iter()
        .filter_map(|(tgid, calls)| {
            let before = last.get(tgid).copied().unwrap_or(0);
            let delta = if *calls >= before {
                calls - before
            } else {
                *calls
            };
            (delta > 0).then_some((*tgid, delta))
        })
        .collect();
    out.sort_unstable();
    out
}

/// The map of the crypto object the agent reads, and the last reading.
pub struct CryptoCallCounter {
    calls: PerCpuHashMap<MapData, u32, u64>,
    last: HashMap<u32, u64>,
}

impl CryptoCallCounter {
    /// Take the counter map out of a loaded object.
    ///
    /// # Errors
    ///
    /// Returns an error when the map is missing or of the wrong type.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let calls = PerCpuHashMap::try_from(
            ebpf.take_map(CRYPTO_CALLS_MAP)
                .ok_or_else(|| anyhow::anyhow!("map '{CRYPTO_CALLS_MAP}' not found"))?,
        )?;
        Ok(Self {
            calls,
            last: HashMap::new(),
        })
    }

    /// Calls per thread group since the previous reading, in tgid order. A
    /// map read error ends the reading at that entry: what was read stands,
    /// and the rest is read next time.
    pub fn deltas(&mut self) -> Vec<(u32, u64)> {
        let mut now = HashMap::new();
        for entry in &self.calls {
            let Ok((tgid, values)) = entry else {
                break;
            };
            let values: PerCpuValues<u64> = values;
            now.insert(tgid, values.iter().copied().fold(0_u64, u64::wrapping_add));
        }
        let deltas = deltas_between(&self.last, &now);
        self.last = now;
        deltas
    }
}

/// Holds the links on every probed library, keyed by inode.
pub struct CryptoAttacher {
    proc_root: PathBuf,
    prog_fd: RawFd,
    warden: Option<Mutex<ebpfsentinel_warden_client::ReconnectingClient>>,
    attached: HashMap<(u64, u64), Vec<OwnedFd>>,
    /// Inodes found to carry none of the symbols, not opened again.
    refused: HashSet<(u64, u64)>,
}

impl CryptoAttacher {
    /// An attacher for the program of `loader`, scanning processes under
    /// `proc_root`.
    ///
    /// # Errors
    ///
    /// Returns an error when the program is not in the loaded object.
    pub fn new(proc_root: impl Into<PathBuf>, loader: &EbpfLoader) -> anyhow::Result<Self> {
        let prog_fd = loader
            .program_fd(CRYPTO_PROGRAM)
            .ok_or_else(|| anyhow::anyhow!("program `{CRYPTO_PROGRAM}` is not in the object"))?;
        Ok(Self {
            proc_root: proc_root.into(),
            prog_fd,
            warden: None,
            attached: HashMap::new(),
            refused: HashSet::new(),
        })
    }

    /// Have the warden create the links, for the posture where the agent
    /// holds no tracing capability of its own.
    #[must_use]
    pub fn with_warden_socket(mut self, sock: &Path) -> Self {
        self.warden = Some(crate::warden::uprobe::client_for(sock));
        self
    }

    /// Distinct library files probed now.
    #[must_use]
    pub fn libraries(&self) -> usize {
        self.attached.len()
    }

    /// Probe every crypto library a process maps and the host's own copies,
    /// once per inode, and publish the result. Returns how many libraries
    /// were probed by this pass.
    pub fn reconcile(&mut self) -> usize {
        let mut added = 0;
        for (path, meta) in self.candidates() {
            let key = (meta.dev(), meta.ino());
            if self.attached.contains_key(&key) || self.refused.contains(&key) {
                continue;
            }
            let base = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(str::to_owned)
                .unwrap_or_default();
            let Some(symbols) = entry_points_of(&base) else {
                continue;
            };
            let links = self.attach_library(&path, symbols);
            if links.is_empty() {
                self.refused.insert(key);
            } else {
                info!(
                    library = %path.display(),
                    probes = links.len(),
                    "encryption calls counted in this library"
                );
                self.attached.insert(key, links);
                added += 1;
            }
        }
        self.publish();
        added
    }

    fn publish(&self) {
        let libraries = self.attached.len();
        publish_status(CryptoStatus {
            attached: libraries > 0,
            libraries,
            reason: (libraries == 0).then(|| {
                "no crypto library this agent can open carries an encryption entry point"
                    .to_string()
            }),
        });
    }

    /// Library files to consider: those running processes map, opened
    /// through each process's root, then the host's library directories.
    fn candidates(&self) -> Vec<(AttachPath, std::fs::Metadata)> {
        let markers = library_markers();
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.proc_root) {
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
                    continue;
                };
                for mapping in library_mappings_in_maps(&maps, &markers) {
                    let Some((path, meta)) = resolve_mapping_in(&self.proc_root, pid, &mapping)
                    else {
                        continue;
                    };
                    // A `map_files` entry is named by its address range, so
                    // the library's own name decides the symbols.
                    let named = PathBuf::from(&mapping.path);
                    out.push((attach_name(&path, &named), meta));
                }
            }
        }
        for dir in SYSTEM_LIBRARY_DIRS {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if !markers.iter().any(|m| name.starts_with(m)) {
                    continue;
                }
                let path = entry.path();
                if let Ok(meta) = std::fs::metadata(&path) {
                    out.push((attach_name(&path, &path), meta));
                }
            }
        }
        out
    }

    /// Attach the program at every symbol of `symbols` the library carries.
    /// A symbol absent from this build is skipped; a link refused is logged
    /// and skipped, so one library never blocks the rest.
    fn attach_library(&self, path: &AttachPath, symbols: &[&str]) -> Vec<OwnedFd> {
        let Some(target) = path.open.to_str() else {
            return Vec::new();
        };
        let mut links = Vec::new();
        for symbol in symbols {
            let offset = match kfunc_attach::resolve_symbol_offset(target, symbol) {
                Ok(offset) if offset > 0 => offset,
                Ok(_) | Err(_) => continue,
            };
            let link = if let Some(client) = &self.warden {
                crate::warden::uprobe::attach_via_warden(
                    client,
                    self.prog_fd,
                    target,
                    offset,
                    false,
                )
                .map_err(|e| e.to_string())
            } else {
                kfunc_attach::attach_uprobe_at_offset(
                    CRYPTO_PROGRAM,
                    self.prog_fd,
                    target,
                    symbol,
                    offset,
                    false,
                )
                .map_err(|e| e.to_string())
            };
            match link {
                Ok(link) => links.push(link),
                Err(reason) => debug!(target, symbol, reason, "crypto probe refused"),
            }
        }
        links
    }
}

/// A library file as the probe opens it and as its own name reads.
pub struct AttachPath {
    open: PathBuf,
    named: PathBuf,
}

impl AttachPath {
    fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.named.file_name()
    }

    fn display(&self) -> std::path::Display<'_> {
        self.named.display()
    }
}

fn attach_name(open: &Path, named: &Path) -> AttachPath {
    AttachPath {
        open: open.to_path_buf(),
        named: named.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_library_is_read_for_the_symbols_its_name_carries() {
        assert_eq!(
            entry_points_of("libcrypto.so.3"),
            Some(&["EVP_EncryptUpdate"][..])
        );
        assert_eq!(
            entry_points_of("libgcrypt.so.20.4.3"),
            Some(&["gcry_cipher_encrypt"][..])
        );
        assert_eq!(entry_points_of("libsodium.so.23").map(<[_]>::len), Some(2));
        assert_eq!(entry_points_of("libssl.so.3"), None);
    }

    #[test]
    fn a_reading_is_the_calls_since_the_last_one() {
        let last = HashMap::from([(10, 5), (11, 7), (12, 3)]);
        let now = HashMap::from([(10, 9), (11, 7), (12, 2), (13, 4)]);
        // 11 made no call; 12 was evicted and came back, so its count is all
        // new; 13 is new.
        assert_eq!(deltas_between(&last, &now), vec![(10, 4), (12, 2), (13, 4)]);
        assert!(deltas_between(&now, &now).is_empty());
    }

    #[test]
    fn a_library_mapped_by_a_process_is_named_by_its_own_path() {
        let maps = "7f00-7f10 r-xp 0 fd:01 42 /usr/lib/libcrypto.so.3\n\
                    7f10-7f20 r--p 0 fd:01 42 /usr/lib/libcrypto.so.3\n\
                    7f20-7f30 r-xp 0 fd:01 43 /usr/lib/libssl.so.3\n";
        let found = library_mappings_in_maps(maps, &library_markers());
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].path, "/usr/lib/libcrypto.so.3");
    }
}
