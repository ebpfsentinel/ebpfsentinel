//! Cgroup scope for the DLP probes.
//!
//! A uprobe is placed on an inode, so one `libssl.so.3` layer shared by every
//! container on a node arms one probe that fires for all of them. On a host
//! agent that is the whole point. On a node agent next to somebody else's
//! workload it means reading a neighbour's plaintext, and filtering the events
//! once they reach userspace is too late: they have already crossed into the
//! agent's address space and its ring buffer.
//!
//! So the scope is enforced in the probe, from two maps written here:
//! `DLP_SCOPE` holds the mode and `DLP_CGROUP_ALLOW` the cgroups in scope. A
//! cgroup v2 id is the inode number of its directory under the cgroup mount,
//! which is what `bpf_get_current_cgroup_id` answers with, so resolving a
//! configured path is a `stat` and nothing more.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ebpf_common::dlp::{DLP_SCOPE_MAX_CGROUPS, DLP_SCOPE_MODE_ALL, DLP_SCOPE_MODE_WORKLOADS};

use crate::ebpf::map_store::MapStore;

/// One configured cgroup path and the id the kernel knows it by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedCgroup {
    /// Path as configured, for logs and for the error naming what is missing.
    pub path: PathBuf,
    /// cgroup v2 id, the directory's inode number.
    pub id: u64,
}

/// What a configured DLP scope resolved to on this node.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedScope {
    /// Cgroups that exist and are in scope.
    pub cgroups: Vec<ScopedCgroup>,
    /// Configured paths that do not exist on this node, kept so the caller can
    /// say which ones rather than only how many.
    pub missing: Vec<PathBuf>,
}

/// Resolve configured cgroup paths, relative to `cgroup_root`, into ids.
///
/// A path that does not exist is reported rather than dropped: a scope of three
/// workloads where only two resolve reads as working DLP while one workload is
/// unwatched.
#[must_use]
pub fn resolve_cgroup_scope(cgroup_root: &Path, paths: &[String]) -> ResolvedScope {
    let mut out = ResolvedScope::default();
    for path in paths {
        let relative = path.trim_start_matches('/');
        let full = cgroup_root.join(relative);
        match std::fs::metadata(&full) {
            Ok(meta) if meta.is_dir() => out.cgroups.push(ScopedCgroup {
                path: PathBuf::from(path),
                id: meta.ino(),
            }),
            _ => out.missing.push(full),
        }
    }
    out
}

/// Write the scope the probes enforce: the mode in `DLP_SCOPE`, the cgroup ids
/// in `DLP_CGROUP_ALLOW`.
///
/// # Errors
///
/// Returns an error when either map is absent - the object was built without
/// the scope maps - when a write fails, when the scope names more cgroups than
/// the map holds, or when a workload scope resolved to nothing. The last one is
/// a refusal rather than a warning: arming the probes with an empty allow list
/// captures nothing at all, which reads as DLP being on.
pub fn push_dlp_scope(ebpf: &mut dyn MapStore, scope: &ResolvedScope) -> anyhow::Result<()> {
    if scope.cgroups.is_empty() {
        if !scope.missing.is_empty() {
            anyhow::bail!(
                "DLP scope resolved to no cgroup on this node; none of these paths exist: {}",
                scope
                    .missing
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        return write_mode(ebpf, DLP_SCOPE_MODE_ALL);
    }

    if scope.cgroups.len() > DLP_SCOPE_MAX_CGROUPS as usize {
        anyhow::bail!(
            "DLP scope names {} cgroups, more than the {DLP_SCOPE_MAX_CGROUPS} the map holds",
            scope.cgroups.len()
        );
    }

    let map = ebpf
        .map_mut("DLP_CGROUP_ALLOW")
        .ok_or_else(|| anyhow::anyhow!("DLP_CGROUP_ALLOW map not found"))?;
    let mut allow = aya::maps::HashMap::<_, u64, u8>::try_from(map)?;
    for cgroup in &scope.cgroups {
        allow.insert(cgroup.id, 1u8, 0)?;
    }

    // The mode goes in last: until it does, the probes read every cgroup, and a
    // half-written allow list that is already enforced is a workload silently
    // out of scope.
    write_mode(ebpf, DLP_SCOPE_MODE_WORKLOADS)
}

fn write_mode(ebpf: &mut dyn MapStore, mode: u32) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("DLP_SCOPE")
        .ok_or_else(|| anyhow::anyhow!("DLP_SCOPE map not found"))?;
    let mut arr = aya::maps::Array::<_, u32>::try_from(map)?;
    arr.set(0, mode, 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_path_is_reported_rather_than_dropped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let present = dir.path().join("kubepods.slice");
        std::fs::create_dir(&present).unwrap();

        let resolved = resolve_cgroup_scope(
            dir.path(),
            &[
                "kubepods.slice".to_string(),
                "/kubepods.slice/gone.scope".to_string(),
            ],
        );

        assert_eq!(resolved.cgroups.len(), 1);
        assert_eq!(resolved.cgroups[0].path, PathBuf::from("kubepods.slice"));
        assert_eq!(
            resolved.cgroups[0].id,
            std::fs::metadata(&present).unwrap().ino()
        );
        assert_eq!(resolved.missing.len(), 1);
    }

    #[test]
    fn a_leading_slash_is_read_against_the_cgroup_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("system.slice")).unwrap();
        let resolved = resolve_cgroup_scope(dir.path(), &["/system.slice".to_string()]);
        assert_eq!(resolved.cgroups.len(), 1);
        assert!(resolved.missing.is_empty());
    }

    #[test]
    fn a_file_is_not_a_cgroup() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("cgroup.procs"), b"1\n").unwrap();
        let resolved = resolve_cgroup_scope(dir.path(), &["cgroup.procs".to_string()]);
        assert!(resolved.cgroups.is_empty());
        assert_eq!(resolved.missing.len(), 1);
    }
}
