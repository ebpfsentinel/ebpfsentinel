use domain::common::error::DomainError;
use domain::qos::cgroup_shaping::{CgroupShapingCounters, QdiscEntry};

/// Secondary port for the maps the egress shaper reads and writes: which
/// cgroup owns each container link, the rate each shaped cgroup is held to,
/// the interfaces a departure time is honoured on, and what the datapath
/// counted per cgroup.
///
/// The link and shape tables are replaced whole rather than edited, for the
/// reason every workload-keyed table here gives: cgroup ids and interface
/// indexes are reused, so an entry left behind is a workload nobody
/// selected being held to somebody else's rate.
///
/// Implemented by `QosCgroupShapingMaps` in the adapter layer.
pub trait QosCgroupShapingMapPort: Send + Sync {
    /// Replace the link table with exactly these `(ifindex, cgroup id)`
    /// pairs.
    ///
    /// # Errors
    ///
    /// Whatever the map insert or removal refused, or more links than the
    /// map holds.
    fn publish_links(&mut self, links: &[(u32, u64)]) -> Result<(), DomainError>;

    /// Replace the shape table with exactly these
    /// `(cgroup id, rate in bps, horizon in ns)` entries.
    ///
    /// # Errors
    ///
    /// Whatever the map insert or removal refused, or more entries than the
    /// map holds.
    fn publish_shapes(&mut self, shapes: &[(u64, u64, u64)]) -> Result<(), DomainError>;

    /// Replace the interfaces, by index, the shaper acts on. A packet
    /// leaving any other interface is not shaped, so an empty list is the
    /// shaper off.
    ///
    /// # Errors
    ///
    /// Whatever the map insert or removal refused, or more interfaces than
    /// the map holds.
    fn publish_interfaces(&mut self, ifindexes: &[u32]) -> Result<(), DomainError>;

    /// What the datapath counted for each cgroup it shaped, summed across
    /// CPUs.
    ///
    /// # Errors
    ///
    /// Whatever the map read refused.
    fn read_counters(&self) -> Result<Vec<(u64, CgroupShapingCounters)>, DomainError>;
}

/// Reads the qdiscs attached to an interface, so the agent can say whether
/// a departure time set on a packet leaving it is honoured.
///
/// Implemented by a netlink dump in the adapter layer.
pub trait QdiscReaderPort: Send + Sync {
    /// The index of the interface named `interface` and every qdisc
    /// attached to it.
    ///
    /// # Errors
    ///
    /// An interface that does not exist, or a dump the kernel refused.
    fn qdiscs(&self, interface: &str) -> Result<(u32, Vec<QdiscEntry>), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qos_cgroup_shaping_map_port_is_object_safe() {
        fn _check(port: &mut dyn QosCgroupShapingMapPort) {
            let _ = port.publish_interfaces(&[]);
        }
    }

    #[test]
    fn qdisc_reader_port_is_object_safe() {
        fn _check(port: &dyn QdiscReaderPort) {
            let _ = port.qdiscs("eth0");
        }
    }
}
