//! Pod coverage secondary ports.
//!
//! Two halves meet to say what the node agent sees of each pod: the link
//! watcher reports every workload link it attached to or left alone, and the
//! pod inventory lists the pods scheduled on this node. Neither half knows
//! the other; the verdict is computed where both are read.

use async_trait::async_trait;

use domain::coverage::PodSubject;
use domain::coverage::WorkloadLink;

/// Where the link watcher reports what became of each workload link.
pub trait LinkCoverageSink: Send + Sync {
    /// The link was attached to, or left alone for the reason it carries.
    /// A second report for the same interface index replaces the first.
    fn link_seen(&self, link: WorkloadLink);

    /// The link at `ifindex` is gone, or no longer a workload's.
    fn link_forgotten(&self, ifindex: u32);

    /// Whether the node carries an encapsulating device, read from the whole
    /// link table each time it is read.
    fn node_encapsulates(&self, encapsulated: bool);
}

/// The pods scheduled on this node.
#[async_trait]
pub trait PodInventoryPort: Send + Sync {
    /// Every pod the inventory holds for this node.
    async fn pods(&self) -> Vec<PodSubject>;
}
