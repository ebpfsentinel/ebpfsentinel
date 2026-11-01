use std::net::IpAddr;

use domain::common::error::DomainError;
use domain::firewall::fqdn::FqdnGrantKey;
use domain::firewall::workload::WorkloadPolicy;

/// Secondary port for the workload policy the cgroup socket hooks read.
///
/// Three maps behind one trait, because the three are written together or
/// not at all: the rules the kernel walks, the selectors a cgroup satisfies
/// and the selectors a task satisfies. Splitting them would let a caller
/// publish rules that name bits nothing sets, which is a policy that decides
/// nothing while reporting that it is loaded.
///
/// Implemented by `WorkloadPolicyMapManager` in the adapter layer.
pub trait WorkloadPolicyMapPort: Send + Sync {
    /// Replace the kernel's rule array with this policy.
    ///
    /// The whole array is rewritten and the slots past the last rule are
    /// disabled, because the kernel stops its walk at the first disabled
    /// slot: a leftover rule behind a shorter policy would be a rule nobody
    /// configured, still in force.
    ///
    /// Every address opened by name goes with it, since a grant is keyed by
    /// the slot of the rule that named it and the slots are numbered afresh,
    /// and the capture of DNS packets is turned on exactly when an enabled
    /// rule names a destination by DNS name.
    ///
    /// The tables naming remote workloads by address are emptied with it,
    /// for the same reason: their masks are slots.
    fn publish_policy(&mut self, policy: &WorkloadPolicy) -> Result<(), DomainError>;

    /// Replace both address tables of the rules naming a remote workload.
    ///
    /// `destinations` holds, per remote address, the slots whose remote
    /// workload the list names there; `sources`, the slots decided at the
    /// destination whose source half the workload there satisfies. Each is
    /// written whole: an address not in the new table is removed, so a
    /// workload that moved off an address stops being named at it.
    ///
    /// # Errors
    ///
    /// Whatever writing a map refused other than a full table. The number
    /// returned is how many entries a full table refused: those addresses
    /// stay unnamed, so a rule naming the workload behind them does not
    /// apply to them.
    fn replace_peer_addresses(
        &mut self,
        destinations: &[(IpAddr, u64)],
        sources: &[(IpAddr, u64)],
    ) -> Result<usize, DomainError>;

    /// Record which slots decided at the destination name the workload in
    /// this cgroup as their remote workload. Zero removes the entry.
    fn set_peer_targets(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError>;

    /// Record which selectors a cgroup satisfies, by bit.
    ///
    /// A mask of zero removes the entry rather than storing it: a cgroup in
    /// no selector is a cgroup the kernel never needs to look up.
    fn set_cgroup_selectors(&mut self, cgroup_id: u64, mask: u64) -> Result<(), DomainError>;

    /// Record which selectors one task satisfies, by bit. Zero removes it.
    fn set_task_selectors(&mut self, tgid: u32, mask: u64) -> Result<(), DomainError>;

    /// Forget a task, which is what an exit means.
    fn forget_task(&mut self, tgid: u32) -> Result<(), DomainError>;

    /// How many times each kernel slot refused, summed across CPUs.
    ///
    /// Slot order, which is the order the enabled rules were published in,
    /// so the caller names them by asking the policy what sits in each slot.
    /// This is the exact figure: the ring buffer that carries the detail can
    /// drop a record under load, and a security count that quietly loses one
    /// is worse than no count at all.
    ///
    /// # Errors
    ///
    /// Whatever reading the counter array refused.
    fn rule_denials(&self) -> Result<Vec<u64>, DomainError>;

    /// Forget every recorded cgroup and task.
    ///
    /// Called when the policy's selectors change, because a bit means a
    /// different workload after that and every recorded mask is about the
    /// old numbering.
    fn clear_selectors(&mut self) -> Result<(), DomainError>;

    /// Open one address for one cgroup under one rule until `expires_ns`,
    /// on the `CLOCK_BOOTTIME` the hooks read.
    ///
    /// # Errors
    ///
    /// Whatever writing the map refused, a full map among them: the address
    /// then stays closed, which is the direction a failure here must go.
    fn grant_fqdn(&mut self, key: &FqdnGrantKey, expires_ns: u64) -> Result<(), DomainError>;

    /// Close one address opened by name. A miss is not an error.
    fn revoke_fqdn(&mut self, key: &FqdnGrantKey) -> Result<(), DomainError>;

    /// A process was seen running `path`, read as the file `dev`/`inode`.
    ///
    /// The kernel recognises a parent or an ancestor by the inode its
    /// address space maps, and the publish resolved each named path once. An
    /// upgrade replaces the file under the path and a parent started after
    /// it runs an inode the publish never saw, so every exec of a path a
    /// lineage rule names offers its inode here. A path no rule names, or an
    /// inode already known, changes nothing; an old inode is kept, since the
    /// parents started before the upgrade still run it.
    ///
    /// # Errors
    ///
    /// Whatever writing the map refused, a full table among them: the new
    /// inode then names no parent, and the processes it starts are not under
    /// it until the next publish.
    fn note_lineage_executable(
        &mut self,
        path: &str,
        dev: u64,
        inode: u64,
    ) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_policy_map_port_is_object_safe() {
        fn _check(port: &mut dyn WorkloadPolicyMapPort) {
            let _ = port.forget_task(1);
        }
    }
}
