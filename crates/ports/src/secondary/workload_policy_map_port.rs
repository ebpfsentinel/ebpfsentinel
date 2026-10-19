use domain::common::error::DomainError;
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
    fn publish_policy(&mut self, policy: &WorkloadPolicy) -> Result<(), DomainError>;

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
