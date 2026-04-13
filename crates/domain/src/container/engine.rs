use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;

use crate::container::entity::{ContainerInfo, ContainerRuntime};

/// Abstraction over the source of cgroup data. The domain crate cannot
/// depend on `ports`, so it defines its own minimal reader trait; the
/// `ports::secondary::container_resolver_port::ContainerResolverPort`
/// trait is API-compatible and can be plugged via a thin wrapper in
/// the application layer.
pub trait CgroupReader: Send + Sync {
    fn read_cgroup(&self, pid: u32) -> std::io::Result<String>;
}

/// Default LRU capacity if no configuration override is provided.
pub const DEFAULT_CACHE_CAPACITY: usize = 4096;

/// Pure parser for a cgroup v2 line (`0::/...`). Returns `None` for
/// malformed input, `ContainerInfo::Host` for non-container paths, or
/// `ContainerInfo::Container { .. }` with the extracted ID.
pub fn parse_cgroup_v2(line: &str, pid: u32) -> Option<ContainerInfo> {
    // cgroup v2 line shape: `0::/<path>`
    let rest = line.strip_prefix("0::")?;
    let path = rest.trim();
    if path.is_empty() {
        return None;
    }
    Some(resolve_path_to_info(path, pid))
}

/// Parser for legacy cgroup v1 output — multiple lines of
/// `<hierarchy>:<controller_list>:<path>`. We look at the `memory` or
/// `pids` controller (or the first non-empty line) and parse the path.
pub fn parse_cgroup_v1(lines: &[&str], pid: u32) -> Option<ContainerInfo> {
    let preferred = lines
        .iter()
        .copied()
        .find(|l| {
            let mut parts = l.split(':');
            let _ = parts.next();
            let controllers = parts.next().unwrap_or("");
            controllers.split(',').any(|c| c == "memory" || c == "pids")
        })
        .or_else(|| lines.iter().copied().find(|l| !l.is_empty()))?;

    let mut parts = preferred.splitn(3, ':');
    let _ = parts.next()?;
    let _ = parts.next()?;
    let path = parts.next()?.trim();
    if path.is_empty() {
        return None;
    }
    Some(resolve_path_to_info(path, pid))
}

/// Detect which runtime owns a cgroup path by inspecting its segments.
pub fn detect_runtime(cgroup_path: &str) -> ContainerRuntime {
    for segment in cgroup_path.split('/').rev() {
        if segment.starts_with("cri-containerd-") {
            return ContainerRuntime::Containerd;
        }
        if segment.starts_with("crio-") {
            return ContainerRuntime::CriO;
        }
        if segment.starts_with("libpod-") {
            return ContainerRuntime::Podman;
        }
        if segment.starts_with("docker-") || segment.contains("/docker/") {
            return ContainerRuntime::Docker;
        }
    }
    if cgroup_path.contains("/docker/") {
        return ContainerRuntime::Docker;
    }
    ContainerRuntime::Unknown
}

/// Extract the 64-character hex ID from a path segment matching the
/// selected runtime. Returns `None` if no valid ID can be recovered.
pub fn extract_container_id(cgroup_path: &str, runtime: ContainerRuntime) -> Option<String> {
    let prefix = match runtime {
        ContainerRuntime::Docker => "docker-",
        ContainerRuntime::Containerd => "cri-containerd-",
        ContainerRuntime::CriO => "crio-",
        ContainerRuntime::Podman => "libpod-",
        ContainerRuntime::Unknown => return docker_legacy_id(cgroup_path),
    };

    for segment in cgroup_path.split('/') {
        if let Some(rest) = segment.strip_prefix(prefix) {
            let hex = rest
                .strip_suffix(".scope")
                .unwrap_or(rest)
                .split('.')
                .next()
                .unwrap_or(rest);
            if is_valid_container_id(hex) {
                return Some(hex.to_string());
            }
        }
    }

    if matches!(runtime, ContainerRuntime::Docker) {
        return docker_legacy_id(cgroup_path);
    }
    None
}

fn resolve_path_to_info(path: &str, pid: u32) -> ContainerInfo {
    let runtime = detect_runtime(path);
    if let Some(container_id) = extract_container_id(path, runtime) {
        ContainerInfo::Container {
            container_id,
            runtime,
            cgroup_path: path.to_string(),
            pid,
        }
    } else {
        ContainerInfo::Host
    }
}

fn docker_legacy_id(cgroup_path: &str) -> Option<String> {
    // Legacy Docker (cgroup v1) paths: `/docker/<id>` or
    // `/system.slice/docker-<id>.scope` already handled above; this
    // variant covers plain `/<id>` under a `/docker/` parent.
    let mut segments = cgroup_path.split('/').rev();
    let last = segments.next()?;
    if is_valid_container_id(last) {
        for parent in segments {
            if parent == "docker" {
                return Some(last.to_string());
            }
        }
    }
    None
}

fn is_valid_container_id(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// LRU cache mapping `cgroup_id` to resolved `ContainerInfo`.
/// Guarded by a `Mutex` so it can live behind an `Arc` shared across
/// async pipeline tasks. The hot path is read-mostly and the cache is
/// sized for the number of live containers on a host, so contention is
/// negligible.
pub struct CgroupCache {
    inner: Mutex<LruCache<u64, ContainerInfo>>,
}

impl CgroupCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    pub fn with_default_capacity() -> Self {
        Self::new(DEFAULT_CACHE_CAPACITY)
    }

    pub fn get(&self, cgroup_id: u64) -> Option<ContainerInfo> {
        self.inner.lock().ok()?.get(&cgroup_id).cloned()
    }

    pub fn insert(&self, cgroup_id: u64, info: ContainerInfo) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.put(cgroup_id, info);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Outcome of a resolution attempt — used by services to update
/// hit/miss/error counters without re-matching on `ContainerInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveOutcome {
    CacheHit,
    CacheMiss,
    ReadError,
}

/// Stateless resolver that combines a `CgroupCache` with a
/// `CgroupReader` port. Resolution is O(1) on cache hit; on miss, it
/// reads `/proc/{pid}/cgroup` via the port, parses the line(s), and
/// populates the cache.
pub struct ContainerResolverEngine {
    cache: CgroupCache,
    reader: Arc<dyn CgroupReader>,
}

impl ContainerResolverEngine {
    pub fn new(reader: Arc<dyn CgroupReader>, cache_capacity: usize) -> Self {
        Self {
            cache: CgroupCache::new(cache_capacity),
            reader,
        }
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }

    /// Resolve `(pid, cgroup_id)` to a `ContainerInfo`. Cache is keyed
    /// on `cgroup_id`; `cgroup_id == 0` is treated as an unknown key
    /// so every call falls through to a proc read. Returns the
    /// resolved info together with the outcome for metrics bookkeeping.
    pub fn resolve(&self, pid: u32, cgroup_id: u64) -> (ContainerInfo, ResolveOutcome) {
        if cgroup_id != 0
            && let Some(cached) = self.cache.get(cgroup_id)
        {
            return (cached, ResolveOutcome::CacheHit);
        }

        match self.reader.read_cgroup(pid) {
            Ok(raw) => {
                let info = parse_cgroup_payload(&raw, pid).unwrap_or(ContainerInfo::Host);
                if cgroup_id != 0 {
                    self.cache.insert(cgroup_id, info.clone());
                }
                (info, ResolveOutcome::CacheMiss)
            }
            Err(_) => (ContainerInfo::Host, ResolveOutcome::ReadError),
        }
    }
}

/// Parse raw `/proc/{pid}/cgroup` contents. Tries cgroup v2 first
/// (single `0::/...` line), falls back to cgroup v1 multi-line format.
pub fn parse_cgroup_payload(raw: &str, pid: u32) -> Option<ContainerInfo> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(line) = trimmed.lines().find(|l| l.starts_with("0::"))
        && let Some(info) = parse_cgroup_v2(line, pid)
    {
        return Some(info);
    }
    let lines: Vec<&str> = trimmed.lines().collect();
    parse_cgroup_v1(&lines, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn parse_v2_docker_scope() {
        let line = format!("0::/system.slice/docker-{HEX64}.scope");
        let info = parse_cgroup_v2(&line, 42).unwrap();
        match info {
            ContainerInfo::Container {
                container_id,
                runtime,
                pid,
                ..
            } => {
                assert_eq!(container_id, HEX64);
                assert_eq!(runtime, ContainerRuntime::Docker);
                assert_eq!(pid, 42);
            }
            _ => panic!("expected container info"),
        }
    }

    #[test]
    fn parse_v2_kubepods_containerd() {
        let line = format!(
            "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poduid.slice/cri-containerd-{HEX64}.scope"
        );
        let info = parse_cgroup_v2(&line, 99).unwrap();
        assert_eq!(info.runtime(), ContainerRuntime::Containerd);
        assert_eq!(info.container_id(), Some(HEX64));
    }

    #[test]
    fn parse_v2_kubepods_crio() {
        let line = format!(
            "0::/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poduid.slice/crio-{HEX64}.scope"
        );
        let info = parse_cgroup_v2(&line, 1).unwrap();
        assert_eq!(info.runtime(), ContainerRuntime::CriO);
        assert_eq!(info.container_id(), Some(HEX64));
    }

    #[test]
    fn parse_v2_podman() {
        let line = format!(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/libpod-{HEX64}.scope"
        );
        let info = parse_cgroup_v2(&line, 2).unwrap();
        assert_eq!(info.runtime(), ContainerRuntime::Podman);
        assert_eq!(info.container_id(), Some(HEX64));
    }

    #[test]
    fn parse_v2_host_init_scope() {
        let info = parse_cgroup_v2("0::/init.scope", 1).unwrap();
        assert!(info.is_host());
    }

    #[test]
    fn parse_v2_host_user_slice() {
        let info = parse_cgroup_v2("0::/user.slice/user-1000.slice/session-1.scope", 10).unwrap();
        assert!(info.is_host());
    }

    #[test]
    fn parse_v2_malformed_missing_prefix() {
        assert!(parse_cgroup_v2("0:/broken", 1).is_none());
    }

    #[test]
    fn parse_v2_empty_path() {
        assert!(parse_cgroup_v2("0::", 1).is_none());
    }

    #[test]
    fn parse_v1_picks_memory_controller() {
        let docker_line = format!("11:memory:/docker/{HEX64}");
        let lines = ["12:freezer:/", docker_line.as_str(), "10:cpuset:/"];
        let info = parse_cgroup_v1(&lines, 7).unwrap();
        assert_eq!(info.runtime(), ContainerRuntime::Docker);
        assert_eq!(info.container_id(), Some(HEX64));
    }

    #[test]
    fn parse_v1_host_process() {
        let lines = [
            "12:memory:/user.slice/user-1000.slice",
            "11:pids:/user.slice",
        ];
        let info = parse_cgroup_v1(&lines, 11).unwrap();
        assert!(info.is_host());
    }

    #[test]
    fn parse_v1_empty_input() {
        assert!(parse_cgroup_v1(&[], 1).is_none());
    }

    #[test]
    fn detect_runtime_variants() {
        assert_eq!(
            detect_runtime("/system.slice/docker-x.scope"),
            ContainerRuntime::Docker
        );
        assert_eq!(
            detect_runtime("/kubepods/.../cri-containerd-x.scope"),
            ContainerRuntime::Containerd
        );
        assert_eq!(
            detect_runtime("/kubepods/.../crio-x.scope"),
            ContainerRuntime::CriO
        );
        assert_eq!(
            detect_runtime("/user.slice/libpod-x.scope"),
            ContainerRuntime::Podman
        );
        assert_eq!(detect_runtime("/init.scope"), ContainerRuntime::Unknown);
    }

    #[test]
    fn extract_rejects_short_id() {
        assert!(extract_container_id("/docker-beef.scope", ContainerRuntime::Docker).is_none());
    }

    #[test]
    fn extract_legacy_docker_v1() {
        let path = format!("/docker/{HEX64}");
        let id = extract_container_id(&path, ContainerRuntime::Unknown).unwrap();
        assert_eq!(id, HEX64);
    }

    #[test]
    fn cache_insert_and_get() {
        let cache = CgroupCache::new(2);
        let info = ContainerInfo::Container {
            container_id: HEX64.to_string(),
            runtime: ContainerRuntime::Docker,
            cgroup_path: "/docker/x".to_string(),
            pid: 1,
        };
        cache.insert(1, info.clone());
        assert_eq!(cache.get(1), Some(info));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_evicts_oldest_at_capacity() {
        let cache = CgroupCache::new(2);
        cache.insert(1, ContainerInfo::Host);
        cache.insert(2, ContainerInfo::Host);
        cache.insert(3, ContainerInfo::Host);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(1).is_none());
        assert!(cache.get(2).is_some());
        assert!(cache.get(3).is_some());
    }

    #[test]
    fn cache_get_refreshes_recency() {
        let cache = CgroupCache::new(2);
        cache.insert(1, ContainerInfo::Host);
        cache.insert(2, ContainerInfo::Host);
        let _ = cache.get(1);
        cache.insert(3, ContainerInfo::Host);
        // 2 should be evicted (it was the LRU after touching 1).
        assert!(cache.get(1).is_some());
        assert!(cache.get(2).is_none());
        assert!(cache.get(3).is_some());
    }

    use std::collections::HashMap;
    use std::io;

    struct FakeReader {
        entries: Mutex<HashMap<u32, String>>,
        fail: Mutex<bool>,
    }

    impl FakeReader {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
                fail: Mutex::new(false),
            }
        }

        fn insert(&self, pid: u32, payload: &str) {
            self.entries
                .lock()
                .unwrap()
                .insert(pid, payload.to_string());
        }

        fn fail_all(&self) {
            *self.fail.lock().unwrap() = true;
        }
    }

    impl CgroupReader for FakeReader {
        fn read_cgroup(&self, pid: u32) -> io::Result<String> {
            if *self.fail.lock().unwrap() {
                return Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));
            }
            self.entries
                .lock()
                .unwrap()
                .get(&pid)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }
    }

    #[test]
    fn engine_cache_miss_then_hit() {
        let reader = Arc::new(FakeReader::new());
        reader.insert(42, &format!("0::/system.slice/docker-{HEX64}.scope"));
        let engine = ContainerResolverEngine::new(reader.clone(), 16);

        let (info1, outcome1) = engine.resolve(42, 0x1234);
        assert_eq!(outcome1, ResolveOutcome::CacheMiss);
        assert_eq!(info1.container_id(), Some(HEX64));

        let (info2, outcome2) = engine.resolve(42, 0x1234);
        assert_eq!(outcome2, ResolveOutcome::CacheHit);
        assert_eq!(info2.container_id(), Some(HEX64));
    }

    #[test]
    fn engine_zero_cgroup_id_bypasses_cache() {
        let reader = Arc::new(FakeReader::new());
        reader.insert(1, "0::/init.scope");
        let engine = ContainerResolverEngine::new(reader, 16);

        let (_, outcome_a) = engine.resolve(1, 0);
        let (_, outcome_b) = engine.resolve(1, 0);
        assert_eq!(outcome_a, ResolveOutcome::CacheMiss);
        assert_eq!(outcome_b, ResolveOutcome::CacheMiss);
        assert_eq!(engine.cache_len(), 0);
    }

    #[test]
    fn engine_read_error_returns_host() {
        let reader = Arc::new(FakeReader::new());
        reader.fail_all();
        let engine = ContainerResolverEngine::new(reader, 16);

        let (info, outcome) = engine.resolve(99, 0xdead);
        assert!(info.is_host());
        assert_eq!(outcome, ResolveOutcome::ReadError);
    }

    #[test]
    fn parse_payload_multiline_v2_first() {
        let raw = format!("0::/system.slice/docker-{HEX64}.scope\n");
        let info = parse_cgroup_payload(&raw, 1).unwrap();
        assert_eq!(info.runtime(), ContainerRuntime::Docker);
    }

    #[test]
    fn parse_payload_v1_fallback() {
        let raw = format!("12:freezer:/\n11:memory:/docker/{HEX64}\n10:cpuset:/\n");
        let info = parse_cgroup_payload(&raw, 1).unwrap();
        assert_eq!(info.runtime(), ContainerRuntime::Docker);
    }

    #[test]
    fn parse_payload_empty_is_none() {
        assert!(parse_cgroup_payload("", 1).is_none());
    }
}
