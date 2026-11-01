//! Where the cluster address table for the opted-in workloads is written.

use std::collections::BTreeMap;

use domain::clusterip::ClusterIpPlan;
use domain::common::error::DomainError;

/// What one write put in the table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClusterIpApplied {
    /// Cluster address, port and protocol entries now resolved at connect.
    pub services: usize,
    /// Backends across those entries.
    pub backends: usize,
    /// Cgroups whose connections are resolved.
    pub cgroups: usize,
    /// Selected cgroups the table had no room for, whose connections stay
    /// with kube-proxy.
    pub cgroups_dropped: usize,
}

/// The kernel side of the cluster address load balancer.
pub trait ClusterIpMapPort: Send + Sync {
    /// Make the table say exactly what `plan` says, for the cgroups of
    /// `cgroups` (cgroup id to pod uid) whose pod `plan` selects. A Service
    /// is replaced so that a connection never reads half of one backend list
    /// and half of another, and one that left the plan is removed before its
    /// backends are.
    ///
    /// # Errors
    ///
    /// Returns the map write that was refused. Whatever was written before it
    /// stays, and every connection the table does not answer for still goes
    /// through kube-proxy.
    fn apply(
        &mut self,
        plan: &ClusterIpPlan,
        cgroups: &BTreeMap<u64, String>,
    ) -> Result<ClusterIpApplied, DomainError>;
}
