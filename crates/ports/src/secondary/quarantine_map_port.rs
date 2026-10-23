use domain::common::error::DomainError;
use ebpf_common::quarantine::{QuarantineEntry, QuarantineEvent};

/// Secondary port for the maps behind the cgroup quarantine.
///
/// Two maps written together: the quarantined cgroups themselves and the ring
/// their decisions come back on. They sit in the workload firewall's object
/// rather than in one of their own, because the hooks that answer the question
/// are the ones already attached there - so a node that loaded the workload
/// firewall gained the quarantine with it, and a node that could not attach
/// those hooks has no quarantine to offer either.
///
/// The program's counters are not here. They are read by the agent's kernel
/// metrics loop like every other program's, so a figure an operator reads on a
/// dashboard comes from one path rather than two.
///
/// Implemented by `QuarantineMapManager` in the adapter layer.
pub trait QuarantineMapPort: Send + Sync {
    /// Cut `cgroup_id` off for the next `window_ns` nanoseconds.
    ///
    /// A window rather than an instant: the kernel compares against its own
    /// boot clock, and the implementation is the only layer that can read the
    /// same clock without inventing an offset. Re-arming a cgroup that is
    /// already quarantined replaces the entry, which is how a quarantine is
    /// extended and how its mode is changed.
    fn arm(&mut self, cgroup_id: u64, mode: u32, window_ns: u64) -> Result<(), DomainError>;

    /// Let `cgroup_id` reach the network again.
    ///
    /// Returns whether an entry was there to remove, so a release can tell an
    /// operator that nothing was quarantined rather than reporting a success
    /// that did nothing.
    fn release(&mut self, cgroup_id: u64) -> Result<bool, DomainError>;

    /// The entry for `cgroup_id`, whether or not it has expired.
    ///
    /// Expired entries are returned rather than hidden: the sweep is the only
    /// thing that removes them, and a reader that could not see one would read
    /// a map the kernel has already stopped acting on as an empty one.
    fn entry(&self, cgroup_id: u64) -> Result<Option<QuarantineEntry>, DomainError>;

    /// Every quarantined cgroup the map holds, expired ones included.
    fn entries(&self) -> Result<Vec<(u64, QuarantineEntry)>, DomainError>;

    /// Remove every entry whose expiry has passed, returning what went.
    ///
    /// The kernel has already stopped refusing on them, so this is bookkeeping
    /// rather than enforcement: it is what keeps the map from filling with the
    /// lapsed and what lets the endpoint answer with what is actually cut off.
    fn sweep_expired(&mut self) -> Result<Vec<u64>, DomainError>;

    /// Take whatever decisions the kernel has written since the last call.
    ///
    /// Drains without blocking: an empty vector means a quarantined workload
    /// has not tried anything since, which is the normal answer for one that
    /// gave up.
    fn drain_events(&mut self) -> Result<Vec<QuarantineEvent>, DomainError>;

    /// The clock the deadlines in these entries are on.
    ///
    /// Here rather than in the caller because the deadline is the kernel's
    /// boot clock: a reader that subtracted a wall clock from it would print a
    /// remaining time off by however long the node has been up.
    fn now_ns(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_map_port_is_object_safe() {
        fn takes_dyn(_: &dyn QuarantineMapPort) {}
        struct Nothing;
        impl QuarantineMapPort for Nothing {
            fn arm(
                &mut self,
                _cgroup_id: u64,
                _mode: u32,
                _window_ns: u64,
            ) -> Result<(), DomainError> {
                Ok(())
            }
            fn release(&mut self, _cgroup_id: u64) -> Result<bool, DomainError> {
                Ok(false)
            }
            fn entry(&self, _cgroup_id: u64) -> Result<Option<QuarantineEntry>, DomainError> {
                Ok(None)
            }
            fn entries(&self) -> Result<Vec<(u64, QuarantineEntry)>, DomainError> {
                Ok(Vec::new())
            }
            fn sweep_expired(&mut self) -> Result<Vec<u64>, DomainError> {
                Ok(Vec::new())
            }
            fn drain_events(&mut self) -> Result<Vec<QuarantineEvent>, DomainError> {
                Ok(Vec::new())
            }
            fn now_ns(&self) -> u64 {
                0
            }
        }
        takes_dyn(&Nothing);
    }
}
