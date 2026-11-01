//! The package databases of every filesystem root, read through the warden.
//!
//! The roots are listed once per sweep, and in each the rpm, dpkg and Alpine
//! databases are looked for and read in pieces. A database is stamped by its
//! `(dev, ino, size, mtime)` before it is read, and one whose stamp has not
//! moved since the last sweep is not read again, so a quiet node costs a
//! handful of `stat` calls a root.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use domain::common::error::DomainError;
use domain::inventory::{
    DatabaseReading, InventorySweep, PackageManager, RootInventory, apk_reading, dpkg_reading,
    rpm_sqlite_reading, scope_of, unreadable,
};
use ebpfsentinel_warden_client::{
    FileRoot, ROOTED_CHUNK_MAX, ReconnectingClient, RootedFile, RootedRead,
};
use ports::secondary::package_inventory_port::PackageInventoryReader;

/// Set to the warden's control socket when the agent runs rootless.
const WARDEN_SOCK_ENV: &str = "EBPFSENTINEL_WARDEN_SOCK";

/// The most roots one sweep reads; a node past it reports how many it left.
pub const MAX_ROOTS: usize = 1024;
/// The largest database read: past it, it is reported unreadable.
pub const MAX_DATABASE_BYTES: u64 = 256 * 1024 * 1024;

/// The in-process listing of roots, given the procfs to read.
pub type LocalRoots = fn(&Path) -> Vec<FileRoot>;
/// The in-process read of a piece of a database inside a root.
pub type LocalRead = fn(&Path, u32, &RootedFile, u64, u32) -> RootedRead;

enum Source {
    /// A rootless agent cannot follow another process's root, so the warden
    /// reads for it.
    Warden(Mutex<ReconnectingClient>),
    /// An agent in the host's namespaces reads in-process.
    Local {
        roots: LocalRoots,
        read: LocalRead,
        proc_root: PathBuf,
    },
}

/// What identifies one reading of one database in one root.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Stamp {
    root: (u64, u64),
    path: String,
    dev: u64,
    ino: u64,
    size: u64,
    mtime_ns: i64,
}

/// A file read whole, or why it was not.
enum Whole {
    Absent,
    Unreadable(String),
    Read { stamp: Stamp, bytes: Vec<u8> },
    Unchanged(Stamp),
}

/// Reads through the warden when `EBPFSENTINEL_WARDEN_SOCK` is set,
/// in-process otherwise.
pub struct WardenPackageReader {
    source: Source,
    cache: Mutex<HashMap<Stamp, DatabaseReading>>,
}

impl WardenPackageReader {
    /// The warden when the environment names one, else `roots` and `read`
    /// over `proc_root`.
    pub fn new(roots: LocalRoots, read: LocalRead, proc_root: impl Into<PathBuf>) -> Self {
        let warden = std::env::var_os(WARDEN_SOCK_ENV)
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty());
        let source = match warden {
            Some(sock) => Source::Warden(Mutex::new(ReconnectingClient::new(sock))),
            None => Source::Local {
                roots,
                read,
                proc_root: proc_root.into(),
            },
        };
        Self {
            source,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn roots(&self) -> Result<Vec<FileRoot>, DomainError> {
        match &self.source {
            Source::Warden(client) => client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .file_roots()
                .map_err(|e| {
                    DomainError::EngineError(format!("warden could not list the roots: {e}"))
                }),
            Source::Local {
                roots, proc_root, ..
            } => Ok(roots(proc_root)),
        }
    }

    fn piece(
        &self,
        pid: u32,
        file: &RootedFile,
        offset: u64,
        len: u32,
    ) -> Result<RootedRead, DomainError> {
        match &self.source {
            Source::Warden(client) => client
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .read_rooted_file(pid, file, offset, len)
                .map_err(|e| {
                    DomainError::EngineError(format!("warden could not read a database: {e}"))
                }),
            Source::Local {
                read, proc_root, ..
            } => Ok(read(proc_root, pid, file, offset, len)),
        }
    }

    /// Read `file` in `root` whole, or say it is unchanged since `known`
    /// held it.
    fn whole(
        &self,
        root: &FileRoot,
        file: &RootedFile,
        known: Option<&HashMap<Stamp, DatabaseReading>>,
    ) -> Result<Whole, DomainError> {
        let (path, dev, ino, size, mtime_ns, mut bytes) = match self.piece(root.pid, file, 0, 0)? {
            RootedRead::Absent => return Ok(Whole::Absent),
            RootedRead::Unreadable { reason } => return Ok(Whole::Unreadable(reason)),
            RootedRead::Chunk {
                path,
                dev,
                ino,
                size,
                mtime_ns,
                data,
            } => (path, dev, ino, size, mtime_ns, data),
        };
        let stamp = Stamp {
            root: (root.dev, root.ino),
            path,
            dev,
            ino,
            size,
            mtime_ns,
        };
        if known.is_some_and(|k| k.contains_key(&stamp)) {
            return Ok(Whole::Unchanged(stamp));
        }
        if size > MAX_DATABASE_BYTES {
            return Ok(Whole::Unreadable(format!(
                "/{} is {size} bytes, past the {MAX_DATABASE_BYTES} read",
                stamp.path
            )));
        }
        bytes.reserve(usize::try_from(size).unwrap_or(0));
        while (bytes.len() as u64) < size {
            match self.piece(root.pid, file, bytes.len() as u64, ROOTED_CHUNK_MAX)? {
                RootedRead::Chunk {
                    dev,
                    ino,
                    size: now,
                    mtime_ns: then,
                    data,
                    ..
                } if (dev, ino, now, then) == (stamp.dev, stamp.ino, size, stamp.mtime_ns)
                    && !data.is_empty() =>
                {
                    bytes.extend_from_slice(&data);
                }
                _ => {
                    return Ok(Whole::Unreadable(format!(
                        "/{} changed while it was read",
                        stamp.path
                    )));
                }
            }
        }
        Ok(Whole::Read { stamp, bytes })
    }

    /// The rpm database of `root`, in whichever of its three forms is there.
    fn rpm(
        &self,
        root: &FileRoot,
        known: &HashMap<Stamp, DatabaseReading>,
        fresh: &mut HashMap<Stamp, DatabaseReading>,
    ) -> Result<Option<DatabaseReading>, DomainError> {
        match self.whole(root, &RootedFile::RpmSqlite, Some(known))? {
            Whole::Absent => {}
            Whole::Unreadable(reason) => {
                return Ok(Some(unreadable(
                    PackageManager::Rpm,
                    "rpmdb.sqlite",
                    reason,
                )));
            }
            Whole::Unchanged(stamp) => return Ok(Some(keep(stamp, known, fresh))),
            Whole::Read { stamp, bytes } => {
                let reading = rpm_sqlite_reading(&format!("/{}", stamp.path), &bytes);
                fresh.insert(stamp, reading.clone());
                return Ok(Some(reading));
            }
        }
        for (file, format) in [
            (RootedFile::RpmNdb, "ndb"),
            (RootedFile::RpmBerkeley, "Berkeley DB"),
        ] {
            match self.piece(root.pid, &file, 0, 0)? {
                RootedRead::Absent => {}
                RootedRead::Unreadable { reason } => {
                    return Ok(Some(unreadable(PackageManager::Rpm, format, reason)));
                }
                RootedRead::Chunk { path, .. } => {
                    return Ok(Some(unreadable(
                        PackageManager::Rpm,
                        &format!("/{path}"),
                        format!("the rpm database is in its {format} format, which is not read"),
                    )));
                }
            }
        }
        Ok(None)
    }

    /// The dpkg database of `root`: its status file and each package's list.
    fn dpkg(
        &self,
        root: &FileRoot,
        known: &HashMap<Stamp, DatabaseReading>,
        fresh: &mut HashMap<Stamp, DatabaseReading>,
    ) -> Result<Option<DatabaseReading>, DomainError> {
        let (stamp, status) = match self.whole(root, &RootedFile::DpkgStatus, Some(known))? {
            Whole::Absent => return Ok(None),
            Whole::Unreadable(reason) => {
                return Ok(Some(unreadable(
                    PackageManager::Dpkg,
                    domain::inventory::DPKG_STATUS_PATH,
                    reason,
                )));
            }
            Whole::Unchanged(stamp) => return Ok(Some(keep(stamp, known, fresh))),
            Whole::Read { stamp, bytes } => (stamp, bytes),
        };
        let mut failed: Option<DomainError> = None;
        let reading = dpkg_reading(&status, |name| {
            if failed.is_some() {
                return None;
            }
            let file = RootedFile::DpkgList {
                name: name.to_string(),
            };
            match self.whole(root, &file, None) {
                Ok(Whole::Read { bytes, .. }) => Some(bytes),
                Ok(_) => None,
                Err(e) => {
                    failed = Some(e);
                    None
                }
            }
        });
        if let Some(e) = failed {
            return Err(e);
        }
        fresh.insert(stamp, reading.clone());
        Ok(Some(reading))
    }

    /// The Alpine database of `root`.
    fn apk(
        &self,
        root: &FileRoot,
        known: &HashMap<Stamp, DatabaseReading>,
        fresh: &mut HashMap<Stamp, DatabaseReading>,
    ) -> Result<Option<DatabaseReading>, DomainError> {
        Ok(
            match self.whole(root, &RootedFile::ApkInstalled, Some(known))? {
                Whole::Absent => None,
                Whole::Unreadable(reason) => Some(unreadable(
                    PackageManager::Apk,
                    "lib/apk/db/installed",
                    reason,
                )),
                Whole::Unchanged(stamp) => Some(keep(stamp, known, fresh)),
                Whole::Read { stamp, bytes } => {
                    let reading = apk_reading(&format!("/{}", stamp.path), &bytes);
                    fresh.insert(stamp, reading.clone());
                    Some(reading)
                }
            },
        )
    }
}

/// Carry a reading whose database has not moved into this sweep's cache.
fn keep(
    stamp: Stamp,
    known: &HashMap<Stamp, DatabaseReading>,
    fresh: &mut HashMap<Stamp, DatabaseReading>,
) -> DatabaseReading {
    let reading = known.get(&stamp).cloned().unwrap_or_else(|| {
        unreadable(
            PackageManager::Dpkg,
            &stamp.path,
            "the earlier reading was lost",
        )
    });
    fresh.insert(stamp, reading.clone());
    reading
}

impl PackageInventoryReader for WardenPackageReader {
    fn read(&self) -> Result<InventorySweep, DomainError> {
        let mut roots = self.roots()?;
        let roots_not_read =
            u32::try_from(roots.len().saturating_sub(MAX_ROOTS)).unwrap_or(u32::MAX);
        roots.truncate(MAX_ROOTS);
        let known = std::mem::take(
            &mut *self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let mut fresh = HashMap::new();
        let mut out = Vec::with_capacity(roots.len());
        for root in &roots {
            let mut databases = Vec::new();
            let mut error = None;
            for read in [Self::rpm, Self::dpkg, Self::apk] {
                match read(self, root, &known, &mut fresh) {
                    Ok(Some(db)) => databases.push(db),
                    Ok(None) => {}
                    Err(e) => {
                        error = Some(e.to_string());
                        break;
                    }
                }
            }
            out.push(RootInventory {
                scope: scope_of(root.host, &root.cgroup, root.pid),
                pid: root.pid,
                databases,
                error,
            });
        }
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
        Ok(InventorySweep {
            roots: out,
            roots_not_read,
        })
    }

    fn source(&self) -> &'static str {
        match self.source {
            Source::Warden(_) => "warden",
            Source::Local { .. } => "local",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Pieces read on this test's thread; the local source reads on the
        /// caller's.
        static READS: Cell<usize> = const { Cell::new(0) };
    }

    fn reads() -> usize {
        READS.with(Cell::get)
    }

    const STATUS: &[u8] = b"Package: libc6\nStatus: install ok installed\n\
        Architecture: amd64\nMulti-Arch: same\nVersion: 2.41-12\n\n\
        Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n";
    const APK: &[u8] = b"P:musl\nV:1.2.5-r10\nA:x86_64\nF:lib\nR:ld-musl-x86_64.so.1\n";

    fn roots(_: &Path) -> Vec<FileRoot> {
        vec![
            FileRoot {
                pid: 1,
                dev: 1,
                ino: 2,
                host: true,
                cgroup: "0::/init.scope\n".into(),
            },
            FileRoot {
                pid: 40,
                dev: 9,
                ino: 2,
                host: false,
                cgroup: format!("0::/system.slice/docker-{}.scope\n", "ab".repeat(32)),
            },
        ]
    }

    fn chunk(path: &str, all: &[u8], offset: u64, len: u32) -> RootedRead {
        READS.with(|r| r.set(r.get() + 1));
        let start = usize::try_from(offset).unwrap_or(usize::MAX).min(all.len());
        let end = (start + len as usize).min(all.len());
        RootedRead::Chunk {
            path: path.into(),
            dev: 1,
            ino: 77,
            size: all.len() as u64,
            mtime_ns: 5,
            data: all[start..end].to_vec(),
        }
    }

    fn read(_: &Path, pid: u32, file: &RootedFile, offset: u64, len: u32) -> RootedRead {
        // Pieces of at most three bytes, so every database spans many.
        let len = len.min(3);
        match (pid, file) {
            (1, RootedFile::DpkgStatus) => chunk("var/lib/dpkg/status", STATUS, offset, len),
            (1, RootedFile::DpkgList { name }) if name == "libc6:amd64" => chunk(
                "var/lib/dpkg/info/libc6:amd64.list",
                b"/.\n/usr/lib/libc.so.6\n",
                offset,
                len,
            ),
            (1, RootedFile::RpmBerkeley) => chunk("var/lib/rpm/Packages", b"bdb", offset, len),
            (40, RootedFile::ApkInstalled) => chunk("lib/apk/db/installed", APK, offset, len),
            _ => RootedRead::Absent,
        }
    }

    fn reader() -> WardenPackageReader {
        WardenPackageReader {
            source: Source::Local {
                roots,
                read,
                proc_root: PathBuf::from("/proc"),
            },
            cache: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn every_root_is_read_and_named_and_an_unread_format_says_so() {
        let reader = reader();
        assert_eq!(reader.source(), "local");
        let Ok(sweep) = reader.read() else {
            panic!("the sweep was taken");
        };
        assert_eq!(sweep.roots.len(), 2);
        let host = &sweep.roots[0];
        assert_eq!(host.scope, domain::inventory::RootScope::Host);
        let packages: Vec<_> = host.packages().collect();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "libc6");
        assert_eq!(
            packages[0].files.as_deref(),
            Some(&["/usr/lib/libc.so.6".to_string()][..])
        );
        assert!(host.databases.iter().any(|d| matches!(
            &d.outcome,
            domain::inventory::DatabaseOutcome::Unreadable { reason } if reason.contains("Berkeley DB")
        )));
        let container = &sweep.roots[1];
        assert!(matches!(
            container.scope,
            domain::inventory::RootScope::Container { .. }
        ));
        assert_eq!(
            container.packages().next().map(|p| p.name.as_str()),
            Some("musl")
        );
    }

    #[test]
    fn an_unchanged_database_is_not_read_twice() {
        let reader = reader();
        let before = reads();
        let first = reader.read().ok();
        let between = reads();
        let second = reader.read().ok();
        let after = reads();
        assert_eq!(first, second);
        // The second sweep only stats: one call per database found, where
        // the first read every three-byte piece of every one of them.
        assert!(
            after - between < (between - before) / 4,
            "{before} {between} {after}"
        );
    }

    #[test]
    fn an_unreachable_warden_fails_the_sweep() {
        let reader = WardenPackageReader {
            source: Source::Warden(Mutex::new(ReconnectingClient::new(
                "/nonexistent/warden.sock",
            ))),
            cache: Mutex::new(HashMap::new()),
        };
        assert_eq!(reader.source(), "warden");
        assert!(reader.read().is_err());
    }
}
