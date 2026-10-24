use std::collections::BTreeMap;

use domain::common::error::DomainError;
use domain::netpol::{ClusterView, CompiledPolicy};

/// What one write of the policy maps left in the kernel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetpolApplied {
    /// Prefixes held across every slot.
    pub entries: usize,
    /// cgroups answering to a slot.
    pub cgroups: usize,
    /// cgroups of selected pods that found no room in the map and are
    /// therefore not enforced. Zero on any node with fewer containers than
    /// the map holds.
    pub cgroups_dropped: usize,
}

/// Secondary port for the maps the cgroup hooks read a `NetworkPolicy` from.
///
/// Every write is the whole policy: the implementation diffs it against what
/// it wrote last, so a recompile that changed one pod costs one pod's entries
/// and a cgroup never sees its table emptied on the way to the new one.
///
/// Implemented by `NetpolMapManager` in the adapter layer.
pub trait NetpolMapPort: Send + Sync {
    /// Make the kernel hold `policy`, each cgroup of `cgroups` answering to
    /// the slot of the pod (by uid) it belongs to. A cgroup whose pod no
    /// policy selects is left out, which is the open answer. `enforce` false
    /// is observe mode: the hooks count what they would refuse and let it
    /// through.
    fn apply(
        &mut self,
        policy: &CompiledPolicy,
        cgroups: &BTreeMap<u64, String>,
        enforce: bool,
    ) -> Result<NetpolApplied, DomainError>;
}

/// Secondary port for the scan finding which cgroups belong to which pod.
///
/// The cgroups of this node's pods are also how the agent knows which pods
/// are local: a pod is enforced here exactly when its cgroups are here.
///
/// Implemented by `PodCgroupScanner` in the adapter layer.
pub trait PodCgroupPort: Send + Sync {
    /// Every cgroup id of a pod on this node, with the pod's uid.
    fn scan(&self) -> BTreeMap<u64, String>;
}

/// Secondary port for the cluster a `NetworkPolicy` is read against.
///
/// Implemented by the cache the Kubernetes watchers keep, in the adapter
/// layer.
pub trait ClusterViewPort: Send + Sync {
    /// The policies, pods, namespaces and services as they stand now.
    fn view(&self) -> ClusterView;
}
