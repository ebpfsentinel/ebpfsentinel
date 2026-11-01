//! Resolving a Service's cluster address at `connect()` for the workloads an
//! operator named, and saying which Services stay with kube-proxy and why.
//!
//! This is an optional load balancer for a chosen set of pods and never a
//! replacement for kube-proxy: every connection it does not translate, from a
//! pod it does not select or to a Service it does not hold, reaches the
//! cluster address unchanged and kube-proxy routes it as it always did.

pub mod plan;

pub use plan::{
    BACKEND_BUDGET, ClusterIpEntry, ClusterIpPlan, LeftReason, LeftToKubeProxy, WorkloadSelector,
    plan,
};
