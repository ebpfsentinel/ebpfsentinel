use async_trait::async_trait;

use domain::common::error::DomainError;
use domain::dlp::scope::DlpObservedWorkload;

/// Secondary port answering "which workloads are on this node right now".
///
/// A DLP scope selector is written against names - a pod, a container, a
/// unit, a tenant - and the kernel allow-list is keyed on cgroup ids that
/// change every time a pod restarts. Something has to turn the first into
/// the second, repeatedly, and that something is this port: it walks the
/// cgroup tree, resolves what it can about each entry, and hands back one
/// record per workload.
///
/// It answers for cgroups rather than for tasks on purpose. The fence the
/// probes enforce is a cgroup fence, so the unit of the answer is the unit
/// of the enforcement; the executable half of a selector arrives separately,
/// from the exec events the process table already receives.
///
/// Implemented by `CgroupWorkloadScanner` in the adapter layer.
#[async_trait]
pub trait DlpWorkloadSourcePort: Send + Sync {
    /// Every workload the source can see, with whatever it could resolve.
    ///
    /// A field it could not resolve is absent rather than guessed, because a
    /// selector matching on a guess reads a neighbour's plaintext.
    ///
    /// # Errors
    ///
    /// Whatever reading the cgroup tree refused. A single unreadable entry
    /// is skipped rather than failing the whole pass: a scope that collapses
    /// because one cgroup disappeared mid-walk would be a fence that opens
    /// under churn.
    async fn observe(&self) -> Result<Vec<DlpObservedWorkload>, DomainError>;

    /// Stable name of this source for logs and metrics.
    fn name(&self) -> &'static str;
}
