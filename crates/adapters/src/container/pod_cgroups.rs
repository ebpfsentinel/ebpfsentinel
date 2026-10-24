//! Which cgroups of this node belong to which pod.
//!
//! The kubelet names a pod's cgroup after the pod's uid, `pod<uid>` with the
//! cgroupfs driver and `kubepods-<class>-pod<uid_with_underscores>.slice` with
//! the systemd one, and puts each container's cgroup beneath it. The id the
//! hooks read is the cgroup directory's inode, so one walk of the kubelet's
//! part of the hierarchy maps every container cgroup to its pod.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use ports::secondary::netpol_map_port::PodCgroupPort;

/// How deep the walk goes. A container cgroup sits a few levels below the
/// kubelet's root even when the node itself runs in a container.
const MAX_DEPTH: usize = 12;

/// The length of a pod uid as the API writes it.
const UID_LEN: usize = 36;

/// Walks the cgroup v2 mount for the kubelet's pods.
pub struct PodCgroupScanner {
    root: PathBuf,
}

impl PodCgroupScanner {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn walk(dir: &Path, pod: Option<&str>, depth: usize, found: &mut BTreeMap<u64, String>) {
        if depth > MAX_DEPTH {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let uid = pod.map(str::to_string).or_else(|| pod_uid(&name));
            match uid {
                Some(uid) => {
                    found.insert(meta.ino(), uid.clone());
                    Self::walk(&entry.path(), Some(&uid), depth + 1, found);
                }
                // Outside a pod only the kubelet's own part of the tree is
                // worth descending into; the rest of a host is not pods.
                None if leads_to_pods(&name) => {
                    Self::walk(&entry.path(), None, depth + 1, found);
                }
                None => {}
            }
        }
    }
}

impl PodCgroupPort for PodCgroupScanner {
    fn scan(&self) -> BTreeMap<u64, String> {
        let mut found = BTreeMap::new();
        Self::walk(&self.root, None, 0, &mut found);
        found
    }
}

/// Whether a directory outside any pod can hold pods below it: the kubelet's
/// slices, and the slices and scopes a containerised node nests them in.
fn leads_to_pods(name: &str) -> bool {
    name.contains("kubepods")
        || name.starts_with("kubelet")
        || std::path::Path::new(name)
            .extension()
            .is_some_and(|extension| extension == "slice" || extension == "scope")
}

/// The pod uid a cgroup directory is named after, if it is a pod's.
pub fn pod_uid(name: &str) -> Option<String> {
    // The last one: `kubepods` carries the word too, and a uid cannot.
    let start = name.rfind("pod")? + 3;
    let candidate = name.get(start..start + UID_LEN)?;
    let rest = &name[start + UID_LEN..];
    if !(rest.is_empty() || rest == ".slice") {
        return None;
    }
    let uid = candidate.replace('_', "-");
    let well_formed = uid.char_indices().all(|(index, c)| match index {
        8 | 13 | 18 | 23 => c == '-',
        _ => c.is_ascii_hexdigit(),
    });
    well_formed.then_some(uid)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const UID: &str = "6f1c2d3e-4a5b-4c6d-8e7f-0123456789ab";

    #[test]
    fn both_kubelet_drivers_name_the_pod_uid() {
        assert_eq!(pod_uid(&format!("pod{UID}")).unwrap(), UID);
        let systemd = format!("kubepods-burstable-pod{}.slice", UID.replace('-', "_"));
        assert_eq!(pod_uid(&systemd).unwrap(), UID);
        assert!(pod_uid("kubepods-burstable.slice").is_none());
        assert!(pod_uid("podman-1234.scope").is_none());
        assert!(pod_uid(&format!("pod{UID}x")).is_none());
    }

    #[test]
    fn every_cgroup_below_a_pod_maps_to_it() {
        let root = std::env::temp_dir().join(format!("netpol-cgroups-{}", std::process::id()));
        let pod = root
            .join("kubepods.slice")
            .join("kubepods-besteffort.slice")
            .join(format!(
                "kubepods-besteffort-pod{}.slice",
                UID.replace('-', "_")
            ));
        let container = pod.join("cri-containerd-abc.scope");
        std::fs::create_dir_all(&container).unwrap();
        std::fs::create_dir_all(root.join("user.slice").join("user-1000.slice")).unwrap();
        std::fs::create_dir_all(root.join("dev-hugepages.mount")).unwrap();

        let found = PodCgroupScanner::new(&root).scan();
        let pod_ino = std::fs::metadata(&pod).unwrap().ino();
        let container_ino = std::fs::metadata(&container).unwrap().ino();
        assert_eq!(found.len(), 2);
        assert_eq!(found[&pod_ino], UID);
        assert_eq!(found[&container_ino], UID);
        std::fs::remove_dir_all(&root).unwrap();
    }
}
