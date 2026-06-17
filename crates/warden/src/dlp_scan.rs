//! Privileged DLP target discovery.
//!
//! Scans `/proc` for SSL libraries mapped by any process and resolves the
//! `SSL_write` / `SSL_read` offsets — both of which require reading another
//! process's `/proc/<pid>/maps` and ELF, gated by `CAP_SYS_PTRACE`. The rootless
//! agent dropped that capability, so it asks the warden (which holds it) for the
//! result and keeps only the attach lifecycle.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;

use ebpfsentinel_warden_proto::DlpTarget;
use object::{Object, ObjectSegment, ObjectSymbol};

/// SSL library basename markers whose mappings export `SSL_write`/`SSL_read`.
const SSL_LIB_MARKERS: &[&str] = &["libssl.so", "libboringssl.so"];

/// Scan `/proc` and return one [`DlpTarget`] per unique `(dev, ino)` SSL library
/// any process maps, with offsets pre-resolved. Unreadable processes / files are
/// skipped silently (they vanish between listing and reading, or are simply not
/// SSL). A library whose `SSL_write` cannot be resolved is dropped — there is no
/// DLP value without the write probe.
pub fn scan_dlp_targets() -> Vec<DlpTarget> {
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut targets = Vec::new();

    let Ok(entries) = std::fs::read_dir("/proc") else {
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
        let Ok(maps) = std::fs::read_to_string(format!("/proc/{pid}/maps")) else {
            continue;
        };
        for lib in ssl_paths_in_maps(&maps) {
            let attach_path = format!("/proc/{pid}/root{lib}");
            let Ok(meta) = std::fs::metadata(&attach_path) else {
                continue;
            };
            let key = (meta.dev(), meta.ino());
            if !seen.insert(key) {
                continue;
            }
            let Ok(data) = std::fs::read(&attach_path) else {
                continue;
            };
            let Ok(file) = object::File::parse(&*data) else {
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

/// Distinct in-container absolute paths of mapped SSL libraries in a `/proc/<pid>/maps`.
fn ssl_paths_in_maps(maps: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in maps.lines() {
        let Some(path) = line.split_whitespace().nth(5) else {
            continue;
        };
        if !path.starts_with('/') {
            continue;
        }
        let base = path.rsplit('/').next().unwrap_or(path);
        if SSL_LIB_MARKERS.iter().any(|m| base.starts_with(m)) && !out.iter().any(|p| p == path) {
            out.push(path.to_string());
        }
    }
    out
}

/// Resolve a symbol to its file offset within an ELF (dynamic table first, then
/// static). Returns `None` if the symbol is absent.
fn symbol_offset(file: &object::File, symbol: &str) -> Option<u64> {
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

    #[test]
    fn parses_libssl_and_boringssl_only() {
        let maps = "\
0-1 r-xp 0 fd:01 1 /usr/bin/curl
0-1 r-xp 0 fd:01 2 /usr/lib/libssl.so.3
0-1 r--p 0 fd:01 2 /usr/lib/libssl.so.3
0-1 r-xp 0 fd:01 3 /usr/lib/libcrypto.so.3
0-1 r-xp 0 fd:01 4 /lib/libboringssl.so";
        let paths = ssl_paths_in_maps(maps);
        assert_eq!(paths.len(), 2);
        assert!(paths.iter().any(|p| p == "/usr/lib/libssl.so.3"));
        assert!(paths.iter().any(|p| p == "/lib/libboringssl.so"));
        assert!(!paths.iter().any(|p| p.contains("libcrypto")));
    }

    #[test]
    fn anonymous_and_pseudo_maps_yield_nothing() {
        assert!(ssl_paths_in_maps("0-1 rw-p 0 00:00 0 \n0-1 r-xp 0 fd:01 9 [stack]").is_empty());
    }

    #[test]
    fn scan_runs_without_panicking() {
        // On the host the agent's own process maps libssl; on a minimal CI box it
        // may not. Either way the scan must not panic.
        let _ = scan_dlp_targets();
    }
}
