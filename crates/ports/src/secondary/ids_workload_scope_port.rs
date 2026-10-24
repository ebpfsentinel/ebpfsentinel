use domain::common::error::DomainError;

/// Secondary port for the two maps the IDS classifier reads to decide a rule
/// scoped to workloads: which cgroup owns each container link, and which
/// cgroups each scoped rule covers.
///
/// A packet on the host side of a container's veth has no socket, so the
/// kernel cannot ask it for a cgroup: the link is what names the workload,
/// and the first map is how the classifier learns which one. The second map
/// is the decision itself, one entry per cgroup and rule that matched.
///
/// Both are replaced whole rather than edited, for the reason the DLP scope
/// gives: cgroup ids and interface indexes are reused, so an entry left
/// behind is a future workload nobody selected being inspected.
///
/// Implemented by `IdsWorkloadScopeMaps` in the adapter layer.
pub trait IdsWorkloadScopeMapPort: Send + Sync {
    /// Replace the link table with exactly these `(ifindex, cgroup id)`
    /// pairs.
    ///
    /// # Errors
    ///
    /// Whatever the map insert or removal refused, or more links than the
    /// map holds.
    fn publish_links(&mut self, links: &[(u32, u64)]) -> Result<(), DomainError>;

    /// Replace the scope table with exactly these `(cgroup id, rule index)`
    /// pairs.
    ///
    /// # Errors
    ///
    /// Whatever the map insert or removal refused, or more entries than the
    /// map holds.
    fn publish_scope(&mut self, entries: &[(u64, u32)]) -> Result<(), DomainError>;
}

/// Told when a container link appears or goes, with the cgroup that owns it.
///
/// The link watcher is what sees a veth or a netkit device arrive and
/// resolves the process holding its far end; whatever decides scoped rules
/// is what needs to know. Called from the watcher's own task, so an
/// implementation does its work inline and never blocks on the network.
///
/// Implemented by `IdsWorkloadScopeService` in the application layer.
pub trait WorkloadLinkSink: Send + Sync {
    /// The link at `ifindex` leads into the workload whose cgroup id is
    /// `cgroup_id`.
    fn link_owned(&self, ifindex: u32, cgroup_id: u64);

    /// The link at `ifindex` is gone.
    fn link_gone(&self, ifindex: u32);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_workload_scope_map_port_is_object_safe() {
        fn _check(port: &mut dyn IdsWorkloadScopeMapPort) {
            let _ = port.publish_links(&[]);
        }
    }

    #[test]
    fn workload_link_sink_is_object_safe() {
        fn _check(sink: &dyn WorkloadLinkSink) {
            sink.link_gone(1);
        }
    }
}
