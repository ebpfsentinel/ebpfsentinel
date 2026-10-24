//! What the node agent sees of each pod on this node.
//!
//! The link watcher reports into this service as links come and go, and the
//! pod inventory is installed once the cluster is watched. A verdict is
//! computed when asked, from the links held at that moment, so it never
//! outlives what it was computed from.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use domain::coverage::{NodeView, PodCoverage, WorkloadLink, node_verdicts};
use ports::secondary::pod_coverage_port::{LinkCoverageSink, PodInventoryPort};

/// Verdicts for one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCoverage {
    /// What the node contributes whatever the pod.
    pub node: NodeView,
    /// Workload links whose owner names no pod: Docker containers, or a pod
    /// whose cgroup was gone before its link was read.
    pub links_without_pod: usize,
    /// One verdict per pod, uncovered first.
    pub pods: Vec<PodCoverage>,
}

/// Holds the workload links and computes each pod's verdict on demand.
#[derive(Default)]
pub struct PodCoverageService {
    links: Mutex<HashMap<u32, WorkloadLink>>,
    uplinks_attached: AtomicBool,
    encapsulated: AtomicBool,
    inventory: Mutex<Option<Arc<dyn PodInventoryPort>>>,
}

impl PodCoverageService {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record whether the agent's chain went on the node's configured
    /// interfaces.
    pub fn set_uplinks_attached(&self, attached: bool) {
        self.uplinks_attached.store(attached, Ordering::Relaxed);
    }

    /// Hand the pod inventory over, once the cluster is watched.
    pub fn install_inventory(&self, inventory: Arc<dyn PodInventoryPort>) {
        *self
            .inventory
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(inventory);
    }

    /// Whether a pod inventory is installed: without one there is no pod to
    /// give a verdict for.
    #[must_use]
    pub fn has_inventory(&self) -> bool {
        self.inventory
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// The verdicts for every pod the inventory lists, or `None` when no
    /// inventory is installed.
    pub async fn verdicts(&self) -> Option<NodeCoverage> {
        let inventory = self
            .inventory
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()?;
        let pods = inventory.pods().await;
        let links: Vec<WorkloadLink> = self
            .links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let node = NodeView {
            uplinks_attached: self.uplinks_attached.load(Ordering::Relaxed),
            encapsulated: self.encapsulated.load(Ordering::Relaxed),
        };
        let links_without_pod = links
            .iter()
            .filter(|l| {
                l.pod_uid
                    .as_deref()
                    .is_none_or(|uid| !pods.iter().any(|p| p.uid == uid))
            })
            .count();
        Some(NodeCoverage {
            node,
            links_without_pod,
            pods: node_verdicts(&pods, &links, node),
        })
    }
}

impl LinkCoverageSink for PodCoverageService {
    fn link_seen(&self, link: WorkloadLink) {
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(link.ifindex, link);
    }

    fn link_forgotten(&self, ifindex: u32) {
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ifindex);
    }

    fn node_encapsulates(&self, encapsulated: bool) {
        self.encapsulated.store(encapsulated, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use domain::coverage::{CoverageLevel, LinkAttachment, LinkRefusal, PodSubject};

    struct Pods(Vec<PodSubject>);

    #[async_trait]
    impl PodInventoryPort for Pods {
        async fn pods(&self) -> Vec<PodSubject> {
            self.0.clone()
        }
    }

    fn pod(uid: &str) -> PodSubject {
        PodSubject {
            uid: uid.into(),
            name: uid.into(),
            namespace: "shop".into(),
            host_network: false,
        }
    }

    fn link(ifindex: u32, uid: Option<&str>, attachment: LinkAttachment) -> WorkloadLink {
        WorkloadLink {
            ifindex,
            name: format!("veth{ifindex}"),
            kind: "veth".into(),
            attachment,
            pod_uid: uid.map(Into::into),
        }
    }

    #[tokio::test]
    async fn no_inventory_is_no_verdict() {
        let svc = PodCoverageService::new();
        assert!(!svc.has_inventory());
        assert!(svc.verdicts().await.is_none());
    }

    #[tokio::test]
    async fn links_reported_and_forgotten_drive_the_verdict() {
        let svc = PodCoverageService::new();
        svc.install_inventory(Arc::new(Pods(vec![pod("a"), pod("b")])));
        svc.link_seen(link(1, Some("a"), LinkAttachment::Attached));
        svc.link_seen(link(
            2,
            Some("b"),
            LinkAttachment::Refused(LinkRefusal::UnknownKind("tun".into())),
        ));
        svc.link_seen(link(3, None, LinkAttachment::Attached));

        let report = svc.verdicts().await.unwrap_or_else(|| unreachable!());
        assert_eq!(report.links_without_pod, 1);
        assert_eq!(report.pods[0].uid, "b");
        assert_eq!(report.pods[0].level, CoverageLevel::None);
        assert_eq!(report.pods[1].level, CoverageLevel::Full);

        svc.link_forgotten(1);
        svc.set_uplinks_attached(true);
        let report = svc.verdicts().await.unwrap_or_else(|| unreachable!());
        assert!(report.node.uplinks_attached);
        assert!(
            report
                .pods
                .iter()
                .all(|p| p.level == CoverageLevel::Partial)
        );
    }

    #[tokio::test]
    async fn encapsulation_is_carried_into_the_node_view() {
        let svc = PodCoverageService::new();
        svc.install_inventory(Arc::new(Pods(vec![])));
        svc.node_encapsulates(true);
        let report = svc.verdicts().await.unwrap_or_else(|| unreachable!());
        assert!(report.node.encapsulated);
    }
}
