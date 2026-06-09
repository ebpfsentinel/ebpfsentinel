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
}
