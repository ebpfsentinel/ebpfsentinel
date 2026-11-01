//! The cluster address loop: read the cluster, plan the table for the pods an
//! operator opted in, and hand it to the connect hooks.
//!
//! A new plan follows every change the watchers report, a second after the
//! last of a burst, and a rescan of the node's cgroups runs on a timer
//! besides, because a container starting is a cgroup appearing and no
//! Kubernetes event says so. Which Services stay with kube-proxy, and why, is
//! logged each time that list changes, not on every pass.

use std::sync::Arc;
use std::time::Duration;

use domain::clusterip::{ClusterIpPlan, LeftToKubeProxy, WorkloadSelector, plan};
use domain::common::error::DomainError;
use ports::secondary::clusterip_map_port::{ClusterIpApplied, ClusterIpMapPort};
use ports::secondary::netpol_map_port::{ClusterViewPort, PodCgroupPort};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// How long a burst of cluster changes is let settle before the next plan.
pub const CLUSTERIP_SETTLE: Duration = Duration::from_secs(1);

/// How often the node's cgroups are rescanned when nothing else changed.
pub const CLUSTERIP_RESCAN: Duration = Duration::from_secs(10);

/// Plans and applies the cluster address table for the opted-in pods of this node.
pub struct ClusterIpService {
    cluster: Arc<dyn ClusterViewPort>,
    cgroups: Arc<dyn PodCgroupPort>,
    maps: Box<dyn ClusterIpMapPort>,
    workloads: Vec<WorkloadSelector>,
    last_left: Option<Vec<LeftToKubeProxy>>,
    last_applied: Option<ClusterIpApplied>,
}

impl ClusterIpService {
    /// Wires the loop to its ports and the workloads it resolves for.
    #[must_use]
    pub fn new(
        cluster: Arc<dyn ClusterViewPort>,
        cgroups: Arc<dyn PodCgroupPort>,
        maps: Box<dyn ClusterIpMapPort>,
        workloads: Vec<WorkloadSelector>,
    ) -> Self {
        Self {
            cluster,
            cgroups,
            maps,
            workloads,
            last_left: None,
            last_applied: None,
        }
    }

    /// One pass: scan, plan, apply.
    ///
    /// # Errors
    ///
    /// Returns whatever the map write was refused with. Connections the
    /// table does not answer for keep going through kube-proxy.
    pub fn sync_once(&mut self) -> Result<ClusterIpApplied, DomainError> {
        let cgroups = self.cgroups.scan();
        let planned = plan(&self.cluster.view(), &self.workloads);
        let applied = self.maps.apply(&planned, &cgroups)?;
        self.report(planned, applied);
        Ok(applied)
    }

    fn report(&mut self, planned: ClusterIpPlan, applied: ClusterIpApplied) {
        if self.last_left.as_ref() != Some(&planned.left_to_kube_proxy) {
            for left in &planned.left_to_kube_proxy {
                info!(
                    service = %format!("{}/{}", left.namespace, left.name),
                    cluster_ip = %left.cluster_ip,
                    port = left.port,
                    reason = %left.reason,
                    "cluster ip: this service port stays with kube-proxy"
                );
            }
            self.last_left = Some(planned.left_to_kube_proxy);
        }
        if self.last_applied != Some(applied) {
            if applied.cgroups_dropped > 0 {
                warn!(
                    dropped = applied.cgroups_dropped,
                    "cluster ip: the cgroup map is full, these containers stay with kube-proxy"
                );
            }
            info!(
                services = applied.services,
                backends = applied.backends,
                cgroups = applied.cgroups,
                "cluster ip table applied"
            );
            self.last_applied = Some(applied);
        }
    }

    /// Runs until the agent shuts down.
    pub async fn run(mut self, mut changes: watch::Receiver<u64>, cancel: CancellationToken) {
        info!(
            workloads = self.workloads.len(),
            "cluster ip resolution at connect started"
        );
        let mut watching = true;
        loop {
            if let Err(e) = self.sync_once() {
                warn!("cluster ip apply failed: {e}");
            }

            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(CLUSTERIP_RESCAN) => {}
                changed = changes.changed(), if watching => {
                    if changed.is_err() {
                        // The watchers are gone; the timer alone keeps the
                        // node's own containers current against the last view.
                        watching = false;
                        continue;
                    }
                    tokio::select! {
                        () = cancel.cancelled() => return,
                        () = tokio::time::sleep(CLUSTERIP_SETTLE) => {}
                    }
                    changes.mark_unchanged();
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::netpol::{
        ClusterView, LabelSelector, NamedPort, PodView, Protocol, ServiceBackend, ServicePort,
        ServiceRouting, ServiceView,
    };
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    struct Cluster(ClusterView);
    impl ClusterViewPort for Cluster {
        fn view(&self) -> ClusterView {
            self.0.clone()
        }
    }

    struct Cgroups(BTreeMap<u64, String>);
    impl PodCgroupPort for Cgroups {
        fn scan(&self) -> BTreeMap<u64, String> {
            self.0.clone()
        }
    }

    type Writes = Arc<Mutex<Vec<(usize, Vec<u64>)>>>;

    #[derive(Default)]
    struct Maps {
        writes: Writes,
    }
    impl ClusterIpMapPort for Maps {
        fn apply(
            &mut self,
            plan: &ClusterIpPlan,
            cgroups: &BTreeMap<u64, String>,
        ) -> Result<ClusterIpApplied, DomainError> {
            let selected: Vec<u64> = cgroups
                .iter()
                .filter(|(_, uid)| plan.selected_pods.contains(*uid))
                .map(|(id, _)| *id)
                .collect();
            self.writes
                .lock()
                .unwrap()
                .push((plan.entries.len(), selected.clone()));
            Ok(ClusterIpApplied {
                services: plan.entries.len(),
                backends: plan.entries.iter().map(|entry| entry.backends.len()).sum(),
                cgroups: selected.len(),
                cgroups_dropped: 0,
            })
        }
    }

    fn pod(uid: &str, app: &str) -> PodView {
        PodView {
            uid: uid.into(),
            namespace: "shop".into(),
            name: uid.into(),
            labels: [("app".to_string(), app.to_string())].into(),
            ips: Vec::new(),
            ports: Vec::new(),
            host_ips: Vec::new(),
            host_network: false,
            terminal: false,
        }
    }

    fn view() -> ClusterView {
        ClusterView {
            pods: vec![pod("web-1", "web"), pod("db-1", "db")],
            services: vec![ServiceView {
                namespace: "shop".into(),
                name: "api".into(),
                cluster_ips: vec!["10.96.0.10".parse().unwrap()],
                ports: vec![ServicePort {
                    name: "http".into(),
                    port: 80,
                    protocol: Protocol::Tcp,
                }],
                backends: vec![ServiceBackend {
                    ip: "10.244.1.3".parse().unwrap(),
                    ports: vec![NamedPort {
                        name: "http".into(),
                        port: 8080,
                        protocol: Protocol::Tcp,
                    }],
                }],
                routing: ServiceRouting::default(),
            }],
            ..ClusterView::default()
        }
    }

    fn web_only() -> Vec<WorkloadSelector> {
        vec![WorkloadSelector {
            pods: Some(LabelSelector {
                match_labels: [("app".to_string(), "web".to_string())].into(),
                ..LabelSelector::default()
            }),
            namespaces: None,
        }]
    }

    #[test]
    fn only_the_cgroups_of_opted_in_pods_are_selected() {
        let maps = Maps::default();
        let writes = Arc::clone(&maps.writes);
        let mut service = ClusterIpService::new(
            Arc::new(Cluster(view())),
            Arc::new(Cgroups(
                [(7, "web-1".to_string()), (9, "db-1".to_string())].into(),
            )),
            Box::new(maps),
            web_only(),
        );
        let applied = service.sync_once().unwrap();
        assert_eq!(applied.services, 1);
        assert_eq!(applied.cgroups, 1);
        assert_eq!(*writes.lock().unwrap(), vec![(1, vec![7])]);
    }

    #[tokio::test]
    async fn a_cluster_change_replans_and_cancel_stops_the_loop() {
        let maps = Maps::default();
        let writes = Arc::clone(&maps.writes);
        let service = ClusterIpService::new(
            Arc::new(Cluster(view())),
            Arc::new(Cgroups(BTreeMap::new())),
            Box::new(maps),
            web_only(),
        );
        let (tx, rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(service.run(rx, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(writes.lock().unwrap().len(), 1);
        tx.send_modify(|generation| *generation += 1);
        tokio::time::sleep(CLUSTERIP_SETTLE + Duration::from_millis(300)).await;
        assert_eq!(writes.lock().unwrap().len(), 2);
        cancel.cancel();
        handle.await.unwrap();
    }
}
