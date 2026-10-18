//! Privileged DLP target discovery.
//!
//! Scans `/proc` for SSL libraries mapped by any process and resolves the
//! `SSL_write` / `SSL_read` offsets - both of which require reading another
//! process's `/proc/<pid>/maps` and ELF, gated by `CAP_SYS_PTRACE`. The rootless
//! agent dropped that capability, so it asks the warden (which holds it) for the
//! result and keeps only the attach lifecycle.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use ebpfsentinel_warden_proto::DlpTarget;
use object::{Object, ObjectSegment, ObjectSymbol};

/// SSL library basename markers whose mappings export `SSL_write`/`SSL_read`.
const SSL_LIB_MARKERS: &[&str] = &["libssl.so", "libboringssl.so"];

/// Marker the kernel appends to a mapping whose backing file was unlinked after
/// the process mapped it. The inode stays alive and mapped, so the mapping is
/// still a valid uprobe target - only its name is gone.
const DELETED_MARKER: &str = " (deleted)";

/// Scan the procfs rooted at `proc_root` and return one [`DlpTarget`] per unique
/// `(dev, ino)` SSL library any process maps, with offsets pre-resolved.
/// Unreadable processes / files are skipped silently (they vanish between
/// listing and reading, or are simply not SSL). A library whose `SSL_write`
/// cannot be resolved is dropped - there is no DLP value without the write
/// probe.
///
/// `proc_root` is `/proc` on a host and the read-only bind mount (`/host/proc`)
/// in a container that was not given the host pid namespace. Nothing below is
/// keyed on a pid being visible in the warden's own namespace: a uprobe link is
/// created by path and offset over the whole system, and the identity a target
/// carries is the `(dev, ino)` of the inode, so the scan sees everything a host
/// procfs lists whether or not the pids in it are the warden's own.
pub fn scan_dlp_targets(proc_root: &Path) -> Vec<DlpTarget> {
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut targets = Vec::new();

    // Every suffix built below is absolute, so the root is concatenated rather
    // than `Path::join`ed - `join` would throw the root away. A root that is not
    // UTF-8 cannot be concatenated with the paths the protocol carries as
    // `String`, and scanning it would produce targets the agent could not name.
    let Some(root) = proc_root.to_str() else {
        eprintln!("[warden] procfs root is not valid UTF-8; DLP scan skipped");
        return targets;
    };
    let root = root.strip_suffix('/').unwrap_or(root);

    let Ok(entries) = std::fs::read_dir(proc_root) else {
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
        let Ok(maps) = std::fs::read_to_string(format!("{root}/{pid}/maps")) else {
            continue;
        };
        for m in ssl_mappings_in_maps(&maps) {
            let Some((attach_path, meta)) = resolve_mapping(root, pid, &m) else {
                continue;
            };
            let key = (meta.dev(), meta.ino());
            if !seen.insert(key) {
                continue;
            }
            // The ELF is read where it is needed rather than copied whole: a
            // `ReadCache` over the open file hands `object` the headers and the
            // symbol tables it asks for, so resolving two symbols in a 400 MiB
            // image costs the pages those tables sit on and not the image. That
            // is also why no size ceiling is left here: nothing is held.
            let Ok(image) = std::fs::File::open(&attach_path) else {
                continue;
            };
            let cache = object::read::ReadCache::new(image);
            let Ok(file) = object::File::parse(&cache) else {
                continue;
            };
            let write_off = symbol_offset(&file, "SSL_write").unwrap_or(0);
            if write_off == 0 {
                continue; // no write probe → no DLP coverage; skip
            }
            let read_off = symbol_offset(&file, "SSL_read").unwrap_or(0);
            targets.push(DlpTarget {
                path: attach_path,
                dev: key.0,
                ino: key.1,
                ssl_write_offset: write_off,
                ssl_read_offset: read_off,
            });
        }
    }
    targets
}

/// One file-backed SSL library mapping found in a `/proc/<pid>/maps`.
///
/// Mirrors the agent-side scanner in `adapters::ebpf::dlp_attach`: the warden is
/// deliberately kept to three dependencies so a privileged binary stays cheap to
/// audit, which rules out sharing a crate with the agent for this. Keep the two
/// parsers in step.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SslMapping {
    /// Absolute path inside the mapping process's mount namespace, with the
    /// kernel's `(deleted)` marker stripped off.
    path: String,
    /// Name of this mapping's `/proc/<pid>/map_files` entry.
    map_file: String,
    /// The backing file was unlinked after the process mapped it, so `path` no
    /// longer names this inode - and may since name a different one.
    deleted: bool,
}

/// Split a maps line into its five fixed columns and the pathname remainder. The
/// pathname is the rest of the line, not a sixth whitespace-delimited field: it
/// can contain spaces, and the kernel appends `" (deleted)"` to it for an
/// unlinked file.
fn split_maps_line(line: &str) -> Option<([&str; 5], &str)> {
    let mut cols = [""; 5];
    let mut rest = line.trim_start();
    for col in &mut cols {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        if end == 0 {
            return None;
        }
        *col = &rest[..end];
        rest = rest[end..].trim_start();
    }
    Some((cols, rest))
}

/// Translate a maps address column into the corresponding `map_files` entry
/// name. `maps` zero-pads each address to eight hex digits and `map_files` does
/// not, so `00400000-00401000` is named `400000-401000` there.
fn map_files_name(range: &str) -> Option<String> {
    let (start, end) = range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    Some(format!("{start:x}-{end:x}"))
}

/// Distinct SSL library mappings in a `/proc/<pid>/maps`, one per (path, deleted)
/// pair - a process that maps both a replaced library and its replacement holds
/// two live inodes and both are probe targets.
fn ssl_mappings_in_maps(maps: &str) -> Vec<SslMapping> {
    let mut out: Vec<SslMapping> = Vec::new();
    for line in maps.lines() {
        let Some(([range, _perms, _offset, _dev, inode], rest)) = split_maps_line(line) else {
            continue;
        };
        // Anonymous and pseudo mappings ("[heap]", "[stack]") are not backed by a
        // file, so they carry inode 0 and can never host a uprobe.
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
        // A library occupies several consecutive mappings (text, rodata, data);
        // they all name one inode, so the first one carries the whole library.
        if out.iter().any(|e| e.path == path && e.deleted == deleted) {
            continue;
        }
        let Some(map_file) = map_files_name(range) else {
            continue;
        };
        out.push(SslMapping {
            path: path.to_string(),
            map_file,
            deleted,
        });
    }
    out
}

/// Resolve one SSL mapping to a path the warden can read and the agent can
/// attach to, with that file's metadata.
///
/// A live mapping is opened through the owning process's root so the path
/// resolves inside its mount namespace. An unlinked mapping has no name left
/// there, and the name it had may since belong to a replacement library - an
/// in-place upgrade unlinks the old file and renames the new one over it while
/// running processes keep the old inode mapped. Resolving by name would hand back
/// offsets from the wrong ELF, so it goes through `/proc/<pid>/map_files`, whose
/// entries are magic links to the mapped inode itself.
///
/// Looking an entry up there requires `CAP_SYS_ADMIN` (readdir alone does not),
/// which the warden already holds for bpffs delegation.
///
/// `root` is the procfs root with any trailing slash already removed. Both paths
/// are rooted on it, so a warden reading a bind-mounted host procfs hands back a
/// path that resolves in its own mount namespace rather than one that only
/// resolves in the host's.
fn resolve_mapping(root: &str, pid: u32, m: &SslMapping) -> Option<(String, std::fs::Metadata)> {
    if !m.deleted {
        let by_name = format!("{root}/{pid}/root{}", m.path);
        if let Ok(meta) = std::fs::metadata(&by_name) {
            return Some((by_name, meta));
        }
    }
    let by_map_file = format!("{root}/{pid}/map_files/{}", m.map_file);
    let meta = std::fs::metadata(&by_map_file).ok()?;
    Some((by_map_file, meta))
}

/// Resolve a symbol to its file offset within an ELF (dynamic table first, then
/// static). Returns `None` if the symbol is absent.
fn symbol_offset<'d, R: object::ReadRef<'d>>(
    file: &object::File<'d, R>,
    symbol: &str,
) -> Option<u64> {
    let addr = file
        .dynamic_symbols()
        .chain(file.symbols())
        .find(|s| s.address() != 0 && s.name().is_ok_and(|n| n == symbol))
        .map(|s| s.address())?;
    for seg in file.segments() {
        let start = seg.address();
        if addr >= start && addr < start + seg.size() {
            let (file_off, _) = seg.file_range();
            return Some(addr - start + file_off);
        }
    }
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths of the SSL mappings parsed out of a maps fixture.
    fn ssl_paths(maps: &str) -> Vec<String> {
        ssl_mappings_in_maps(maps)
            .into_iter()
            .map(|m| m.path)
            .collect()
    }

    #[test]
    fn parses_libssl_and_boringssl_only() {
        let maps = "\
0-1 r-xp 0 fd:01 1 /usr/bin/curl
0-1 r-xp 0 fd:01 2 /usr/lib/libssl.so.3
0-1 r--p 0 fd:01 2 /usr/lib/libssl.so.3
0-1 r-xp 0 fd:01 3 /usr/lib/libcrypto.so.3
0-1 r-xp 0 fd:01 4 /lib/libboringssl.so";
        let paths = ssl_paths(maps);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| p == "/usr/lib/libssl.so.3"));
        assert!(paths.iter().any(|p| p == "/lib/libboringssl.so"));
        assert!(!paths.iter().any(|p| p.contains("libcrypto")));
    }

    #[test]
    fn anonymous_and_pseudo_maps_yield_nothing() {
        assert!(ssl_mappings_in_maps("0-1 rw-p 0 00:00 0 \n0-1 r-xp 0 fd:01 9 [stack]").is_empty());
    }

    #[test]
    fn strips_the_deleted_marker_and_flags_the_mapping() {
        let m = ssl_mappings_in_maps("7f10-7f20 r-xp 0 fd:01 7 /usr/lib/libssl.so.3 (deleted)\n");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].path, "/usr/lib/libssl.so.3");
        assert!(m[0].deleted);
        assert_eq!(m[0].map_file, "7f10-7f20");
    }

    #[test]
    fn a_replaced_library_and_its_replacement_are_two_targets() {
        let maps = "\
7f10-7f20 r-xp 0 fd:01 7 /usr/lib/libssl.so.3 (deleted)
7f30-7f40 r-xp 0 fd:01 9 /usr/lib/libssl.so.3";
        let m = ssl_mappings_in_maps(maps);
        assert_eq!(m.len(), 2);
        assert_eq!(m.iter().filter(|e| e.deleted).count(), 1);
    }

    #[test]
    fn a_path_containing_spaces_survives_parsing() {
        // Splitting on whitespace would truncate this to "/opt/my", which fails
        // the SSL basename match and leaves the library unprobed.
        let maps = "7f10-7f20 r-xp 0 fd:01 7 /opt/my app/libssl.so.3\n";
        assert_eq!(ssl_paths(maps), vec!["/opt/my app/libssl.so.3".to_string()]);
    }

    #[test]
    fn map_files_names_drop_the_zero_padding_maps_adds() {
        assert_eq!(
            map_files_name("00400000-00401000").unwrap(),
            "400000-401000"
        );
        assert_eq!(
            map_files_name("7f1000000000-7f1000100000").unwrap(),
            "7f1000000000-7f1000100000"
        );
        assert!(map_files_name("not-hex").is_none());
    }

    #[test]
    fn scan_runs_without_panicking() {
        // On the host the agent's own process maps libssl; on a minimal CI box it
        // may not. Either way the scan must not panic.
        let _ = scan_dlp_targets(Path::new("/proc"));
    }

    /// Build `<root>/<pid>/maps` plus the file its line names, as a procfs bind
    /// mount looks to a container that was not given the host pid namespace.
    fn fixture_proc(pid: u32, mapped: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let proc_pid = dir.path().join(pid.to_string());
        let target = proc_pid.join("root").join(mapped.trim_start_matches('/'));
        std::fs::create_dir_all(target.parent().expect("parent")).expect("mkdir");
        std::fs::write(&target, b"not an elf").expect("write library");
        std::fs::write(
            proc_pid.join("maps"),
            format!("7f10-7f20 r-xp 00000000 fd:01 7 {mapped}\n"),
        )
        .expect("write maps");
        dir
    }

    #[test]
    fn a_non_default_root_is_what_every_path_is_built_on() {
        let dir = fixture_proc(4242, "/usr/lib/libssl.so.3");
        let m = SslMapping {
            path: "/usr/lib/libssl.so.3".to_string(),
            map_file: "7f10-7f20".to_string(),
            deleted: false,
        };
        let root = dir.path().to_str().expect("a utf-8 tempdir");
        let (path, meta) =
            resolve_mapping(root, 4242, &m).expect("resolved under the fixture root");
        assert_eq!(path, format!("{root}/4242/root/usr/lib/libssl.so.3"));
        assert!(!path.starts_with("/proc/"));

        // The identity stays the inode's, read through the rooted path.
        let direct = std::fs::metadata(&path).expect("stat");
        assert_eq!((meta.dev(), meta.ino()), (direct.dev(), direct.ino()));
    }

    #[test]
    fn a_fixture_root_is_walked_and_its_unparseable_library_dropped() {
        let dir = fixture_proc(4242, "/usr/lib/libssl.so.3");
        // The scan reaches the mapped file - it is rooted correctly - and drops
        // it for exporting no `SSL_write`, which is what a non-ELF payload means.
        assert!(scan_dlp_targets(dir.path()).is_empty());
    }

    #[test]
    fn a_root_listing_no_process_yields_no_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(scan_dlp_targets(dir.path()).is_empty());
        assert!(scan_dlp_targets(Path::new("/nonexistent-proc-root")).is_empty());
    }
}
