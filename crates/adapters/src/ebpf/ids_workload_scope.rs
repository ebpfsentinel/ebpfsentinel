use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use aya::maps::{HashMap as AyaHashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::ids::{
    IDS_WORKLOAD_SCOPE_MAX_ENTRIES, IdsWorkloadScopeKey, WORKLOAD_LINK_MAX_ENTRIES,
};
use ports::secondary::ids_workload_scope_port::IdsWorkloadScopeMapPort;
use tracing::info;

use crate::ebpf::map_store::MapStore;

/// The cgroup v2 id of `cgroup_path`, which is the inode number of its
/// directory under `cgroup_root`.
///
/// `None` when the directory is gone, which is routine: a container that
/// stopped between the read of its cgroup and this call has no id left to
/// name.
#[must_use]
pub fn cgroup_id_of(cgroup_root: &Path, cgroup_path: &str) -> Option<u64> {
    let full = cgroup_root.join(cgroup_path.trim_start_matches('/'));
    std::fs::metadata(full)
        .ok()
        .filter(std::fs::Metadata::is_dir)
        .map(|meta| meta.ino())
}

/// Holds the two maps of a loaded tc-ids object that decide a rule scoped to
/// workloads: `WORKLOAD_LINKS`, the cgroup behind each container link, and
/// `IDS_WORKLOAD_SCOPE`, the cgroups each scoped rule covers.
///
/// Owned rather than borrowed for the reason the DLP scope manager gives:
/// workloads come and go long after the load, and a borrowed map cannot
/// outlive the loader.
pub struct IdsWorkloadScopeMaps {
    links: AyaHashMap<MapData, u32, u64>,
    scope: AyaHashMap<MapData, IdsWorkloadScopeKey, u8>,
}

impl IdsWorkloadScopeMaps {
    /// Take both maps out of a loaded tc-ids object.
    ///
    /// # Errors
    ///
    /// Returns an error when either map is missing, which means the object
    /// predates scoped rules, or when a map has another shape than the one
    /// declared here.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let links = AyaHashMap::try_from(
            ebpf.take_map("WORKLOAD_LINKS")
                .ok_or_else(|| anyhow::anyhow!("map 'WORKLOAD_LINKS' not found"))?,
        )?;
        let scope = AyaHashMap::try_from(
            ebpf.take_map("IDS_WORKLOAD_SCOPE")
                .ok_or_else(|| anyhow::anyhow!("map 'IDS_WORKLOAD_SCOPE' not found"))?,
        )?;
        info!("IDS workload scope tables acquired");
        Ok(Self { links, scope })
    }
}

impl IdsWorkloadScopeMapPort for IdsWorkloadScopeMaps {
    fn publish_links(&mut self, links: &[(u32, u64)]) -> Result<(), DomainError> {
        if links.len() > WORKLOAD_LINK_MAX_ENTRIES as usize {
            return Err(DomainError::InvalidConfig(format!(
                "{} container links, more than the {WORKLOAD_LINK_MAX_ENTRIES} the link table holds",
                links.len()
            )));
        }
        let wanted: HashMap<u32, u64> = links.iter().copied().collect();
        // Collected before the first removal because the iterator borrows the
        // map. A removal that fails is a key already gone, which is what the
        // removal was for.
        let present: Vec<u32> = self.links.keys().filter_map(Result::ok).collect();
        for ifindex in present {
            if !wanted.contains_key(&ifindex) {
                let _ = self.links.remove(&ifindex);
            }
        }
        for (ifindex, cgroup_id) in &wanted {
            self.links.insert(ifindex, cgroup_id, 0).map_err(|e| {
                DomainError::EngineError(format!("WORKLOAD_LINKS write failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn publish_scope(&mut self, entries: &[(u64, u32)]) -> Result<(), DomainError> {
        if entries.len() > IDS_WORKLOAD_SCOPE_MAX_ENTRIES as usize {
            return Err(DomainError::InvalidConfig(format!(
                "{} workload scope entries, more than the {IDS_WORKLOAD_SCOPE_MAX_ENTRIES} the scope table holds",
                entries.len()
            )));
        }
        let wanted: HashSet<IdsWorkloadScopeKey> = entries
            .iter()
            .map(|&(cgroup_id, rule_id)| IdsWorkloadScopeKey {
                cgroup_id,
                rule_id,
                _padding: 0,
            })
            .collect();
        let present: Vec<IdsWorkloadScopeKey> = self.scope.keys().filter_map(Result::ok).collect();
        for key in present {
            if !wanted.contains(&key) {
                let _ = self.scope.remove(&key);
            }
        }
        for key in &wanted {
            self.scope.insert(key, 1u8, 0).map_err(|e| {
                DomainError::EngineError(format!("IDS_WORKLOAD_SCOPE write failed: {e}"))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cgroup_id_is_the_directory_inode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cgroup = dir.path().join("system.slice/docker-abc.scope");
        std::fs::create_dir_all(&cgroup).expect("mkdir");
        let expected = std::fs::metadata(&cgroup).expect("stat").ino();

        assert_eq!(
            cgroup_id_of(dir.path(), "/system.slice/docker-abc.scope"),
            Some(expected)
        );
        assert_eq!(
            cgroup_id_of(dir.path(), "system.slice/docker-abc.scope"),
            Some(expected)
        );
    }

    #[test]
    fn a_cgroup_that_is_gone_has_no_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(cgroup_id_of(dir.path(), "/system.slice/gone.scope"), None);
        let file = dir.path().join("cgroup.procs");
        std::fs::write(&file, b"").expect("write");
        assert_eq!(cgroup_id_of(dir.path(), "/cgroup.procs"), None);
    }
}
