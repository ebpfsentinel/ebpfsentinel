use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use domain::container::engine::CgroupIdResolver;

/// Maximum directory depth walked under the cgroup root. Container cgroup
/// paths sit a handful of levels down (e.g.
/// `/system.slice/docker-<id>.scope` or
/// `/kubepods.slice/.../<id>.scope`); the bound stops a pathological
/// hierarchy from turning a cache miss into an unbounded walk.
const MAX_DEPTH: usize = 16;

/// Resolves a kernel cgroup v2 id to its path by scanning the cgroup v2
/// mount and matching directory inode numbers. On cgroup v2 the id
/// returned by `bpf_get_current_cgroup_id` is the cgroup directory's
/// kernfs id, which equals its `st_ino` on the kernels this agent targets
/// (>= 6.9). Resolution is only hit on a resolver cache miss, so the walk
/// cost is amortised across the lifetime of each container.
pub struct CgroupfsResolver {
    root: PathBuf,
}

impl CgroupfsResolver {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Convenience constructor for the conventional unified mount.
    pub fn with_default_root() -> Self {
        Self::new("/sys/fs/cgroup")
    }

    /// Depth-first search for the directory whose inode equals `cgroup_id`.
    /// Returns the path relative to the root, with a leading `/`, so the
    /// domain parser sees the same shape as a `/proc/<pid>/cgroup` line
    /// (e.g. `/system.slice/docker-<id>.scope`).
    fn find(&self, dir: &Path, cgroup_id: u64, depth: usize) -> Option<String> {
        if depth > MAX_DEPTH {
            return None;
        }
        let entries = std::fs::read_dir(dir).ok()?;
        for entry in entries.flatten() {
            // Use symlink_metadata so we never follow a symlink out of the
            // cgroup hierarchy; cgroupfs has no symlinks between cgroups.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let path = entry.path();
            if meta.ino() == cgroup_id {
                return Some(self.relative_path(&path));
            }
            if let Some(found) = self.find(&path, cgroup_id, depth + 1) {
                return Some(found);
            }
        }
        None
    }

    fn relative_path(&self, path: &Path) -> String {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        let rel = rel.to_string_lossy();
        if rel.is_empty() {
            "/".to_string()
        } else {
            format!("/{rel}")
        }
    }
}

impl CgroupIdResolver for CgroupfsResolver {
    fn path_for_id(&self, cgroup_id: u64) -> Option<String> {
        if cgroup_id == 0 {
            return None;
        }
        self.find(&self.root, cgroup_id, 0)
    }
}

/// The id the kernel would report for the root of the unified hierarchy.
///
/// The walk above answers id to path, and a fence has to answer the other way
/// round: the two cgroups a response must never act on are this hierarchy's
/// root and the agent's own cgroup, and both are known as paths.
#[must_use]
pub fn root_cgroup_id(root: &str) -> Option<u64> {
    std::fs::metadata(root).ok().map(|meta| meta.ino())
}

/// The id of the cgroup this process is in, or `None` on a host whose
/// `/proc/self/cgroup` is not the unified one.
///
/// Read from `/proc/self/cgroup` rather than from a helper, because the
/// userspace side has no eBPF context to call `bpf_get_current_cgroup_id` in.
/// The unified hierarchy writes one line, `0::<path>`, and a v1-only host
/// writes none of that shape: a `None` there is a fence that could not be
/// built, which the caller reports rather than treating as "nothing to
/// protect".
#[must_use]
pub fn self_cgroup_id(root: &str) -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let relative = contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim();
    let path = Path::new(root).join(relative.trim_start_matches('/'));
    std::fs::metadata(path).ok().map(|meta| meta.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use tempfile::tempdir;

    const HEX64: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    #[test]
    fn resolves_id_to_relative_cgroup_path() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let scope = root
            .join("system.slice")
            .join(format!("docker-{HEX64}.scope"));
        fs::create_dir_all(&scope).unwrap();
        let ino = fs::metadata(&scope).unwrap().ino();

        let resolver = CgroupfsResolver::new(root);
        let path = resolver.path_for_id(ino).unwrap();
        assert_eq!(path, format!("/system.slice/docker-{HEX64}.scope"));
    }

    #[test]
    fn unknown_id_returns_none() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("system.slice")).unwrap();
        let resolver = CgroupfsResolver::new(dir.path());
        // Inode 1 is never a real cgroup dir in the temp tree.
        assert!(resolver.path_for_id(1).is_none());
    }

    #[test]
    fn zero_id_returns_none() {
        let dir = tempdir().unwrap();
        let resolver = CgroupfsResolver::new(dir.path());
        assert!(resolver.path_for_id(0).is_none());
    }

    #[test]
    fn matches_root_itself() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let ino = fs::metadata(root).unwrap().ino();
        // The root inode is reachable only via a nested match; ensure a
        // nested dir carrying the same scheme still resolves.
        let nested = root
            .join("kubepods.slice")
            .join(format!("crio-{HEX64}.scope"));
        fs::create_dir_all(&nested).unwrap();
        let nested_ino = fs::metadata(&nested).unwrap().ino();
        let resolver = CgroupfsResolver::new(root);
        assert_eq!(
            resolver.path_for_id(nested_ino).unwrap(),
            format!("/kubepods.slice/crio-{HEX64}.scope")
        );
        // The root's own inode is not returned (search starts in its children).
        assert!(resolver.path_for_id(ino).is_none());
    }

    #[test]
    fn the_root_id_is_the_roots_own_inode() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        assert_eq!(
            root_cgroup_id(root.to_str().unwrap()),
            Some(fs::metadata(root).unwrap().ino())
        );
        assert!(root_cgroup_id("/nonexistent/cgroup-root").is_none());
    }

    #[test]
    fn the_agents_own_cgroup_is_read_or_reported_missing() {
        // Against a tree that holds no cgroup of this process, the answer is
        // None rather than the root or a guess: a fence built on a wrong id
        // would protect a cgroup nobody asked about and leave the agent's own
        // open.
        let dir = tempdir().unwrap();
        assert!(self_cgroup_id(dir.path().to_str().unwrap()).is_none());
        // On a unified host the agent's own cgroup resolves under the real
        // mount; on a v1-only one there is no `0::` line and None is correct.
        match self_cgroup_id("/sys/fs/cgroup") {
            Some(id) => assert_ne!(id, 0),
            None => assert!(
                std::fs::read_to_string("/proc/self/cgroup").map_or(true, |c| !c.contains("0::"))
            ),
        }
    }
}
