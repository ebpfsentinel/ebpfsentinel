use domain::common::error::DomainError;

/// Secondary port for the two maps the DLP uprobes read before they copy a
/// byte of plaintext: the scope mode, and the cgroups the scope allows.
///
/// The two are written together or not at all. A mode set to `workloads`
/// over an empty allow-list arms the probes and drops every event, which
/// reads as DLP being on while nothing is inspected; an allow-list written
/// under mode `all` is a fence nothing consults. Either half alone is a
/// misconfiguration the kernel cannot report, so the trait never offers one
/// without the other.
///
/// Implemented by `DlpScopeMapManager` in the adapter layer.
pub trait DlpScopeMapPort: Send + Sync {
    /// Replace the allow-list with exactly these cgroup ids, and set the
    /// mode to match: scoped when the policy says so, which is the only
    /// thing that makes the probes consult the list at all.
    ///
    /// The whole list is replaced rather than added to, because a cgroup
    /// that went away must stop being allowed: cgroup ids are reused, so an
    /// entry left behind is a future workload nobody selected being read.
    ///
    /// # Errors
    ///
    /// Whatever the map insert, the removal or the mode write refused.
    fn publish_scope(&mut self, scoped: bool, cgroup_ids: &[u64]) -> Result<(), DomainError>;

    /// How many cgroup ids the allow-list currently carries.
    fn allowed_cgroups(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dlp_scope_map_port_is_object_safe() {
        fn _check(port: &mut dyn DlpScopeMapPort) {
            let _ = port.allowed_cgroups();
        }
    }
}
