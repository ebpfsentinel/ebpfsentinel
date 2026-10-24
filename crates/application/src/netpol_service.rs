//! The `NetworkPolicy` loop: read the cluster, compile it for this node's
//! pods, and hand the result to the cgroup hooks.
//!
//! A recompile follows every change the watchers report, a second after the
//! last of a burst so a rollout costs one compile rather than one per pod,
//! and a rescan of the node's cgroups runs on a timer besides, because a
//! container starting is a cgroup appearing and no Kubernetes event says so.
//! What the compile could not honour is logged once each time it changes,
//! not on every pass.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use domain::common::error::DomainError;
use domain::netpol::{CompileReport, NodeContext, compile};
use ports::secondary::netpol_map_port::{
    ClusterViewPort, NetpolApplied, NetpolMapPort, PodCgroupPort,
};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// How long a burst of cluster changes is let settle before the recompile.
pub const NETPOL_SETTLE: Duration = Duration::from_secs(1);

/// How often the node's cgroups are rescanned when nothing else changed.
pub const NETPOL_RESCAN: Duration = Duration::from_secs(10);

/// Compiles and applies `NetworkPolicy` for the pods of this node.
pub struct NetpolService {
    cluster: Arc<dyn ClusterViewPort>,
    cgroups: Arc<dyn PodCgroupPort>,
    maps: Box<dyn NetpolMapPort>,
    enforce: bool,
    last_report: Option<CompileReport>,
    last_applied: Option<NetpolApplied>,
}

impl NetpolService {
    /// Wires the loop to its ports. `enforce` false counts what would be
    /// refused and lets it through.
    #[must_use]
    pub fn new(
        cluster: Arc<dyn ClusterViewPort>,
        cgroups: Arc<dyn PodCgroupPort>,
        maps: Box<dyn NetpolMapPort>,
        enforce: bool,
    ) -> Self {
        Self {
            cluster,
            cgroups,
            maps,
            enforce,
            last_report: None,
            last_applied: None,
        }
    }

    /// One pass: scan, compile, apply.
    ///
    /// # Errors
    ///
    /// Returns whatever the map write was refused with. The maps keep what
    /// the last successful pass wrote.
    pub fn sync_once(&mut self) -> Result<NetpolApplied, DomainError> {
        let cgroups = self.cgroups.scan();
        let local: HashSet<String> = cgroups.values().cloned().collect();
        let view = self.cluster.view();
        let node = NodeContext::from_pods(&view, &local);
        let compiled = compile(&view, &local, &node);
        let applied = self.maps.apply(&compiled, &cgroups, self.enforce)?;

        if self.last_report.as_ref() != Some(&compiled.report) {
            log_report(&compiled.report);
            self.last_report = Some(compiled.report);
        }
        if self.last_applied != Some(applied) {
            if applied.cgroups_dropped > 0 {
                warn!(
                    dropped = applied.cgroups_dropped,
                    "network policy: the cgroup map is full, these containers are not enforced"
                );
            }
            info!(
                entries = applied.entries,
                cgroups = applied.cgroups,
                enforce = self.enforce,
                "network policy applied"
            );
            self.last_applied = Some(applied);
        }
        Ok(applied)
    }

    /// Runs until the agent shuts down.
    pub async fn run(mut self, mut changes: watch::Receiver<u64>, cancel: CancellationToken) {
        info!(
            mode = if self.enforce { "enforce" } else { "observe" },
            "network policy enforcement started"
        );
        let mut watching = true;
        loop {
            if let Err(e) = self.sync_once() {
                warn!("network policy apply failed: {e}");
            }

            tokio::select! {
                () = cancel.cancelled() => return,
                () = tokio::time::sleep(NETPOL_RESCAN) => {}
                changed = changes.changed(), if watching => {
                    if changed.is_err() {
                        // The watchers are gone; the timer alone keeps the
                        // node's own pods current against the last view.
                        watching = false;
                        continue;
                    }
                    tokio::select! {
                        () = cancel.cancelled() => return,
                        () = tokio::time::sleep(NETPOL_SETTLE) => {}
                    }
                    changes.mark_unchanged();
                }
            }
        }
    }
}

fn log_report(report: &CompileReport) {
    info!(
        selected_pods = report.selected_pods,
        "network policy compiled"
    );
    for truncation in &report.truncated {
        warn!(
            pod = %truncation.pod,
            direction = truncation.direction.as_str(),
            prefix = ?truncation.prefix,
            dropped = truncation.dropped,
            "network policy: more port ranges than one peer can carry, the extra ones stay closed"
        );
    }
    for refused in &report.refused_services {
        warn!(
            pod = %refused.pod,
            service = %refused.service,
            port = refused.port,
            protocol = ?refused.protocol,
            allowed = refused.allowed_backends,
            backends = refused.backends,
            "network policy: a service address stays closed because only some of its backends are allowed"
        );
    }
    for pod in &report.closed {
        warn!(
            %pod,
            "network policy: the rule set does not fit the table, the pod is closed where it is isolated"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::netpol::{ClusterView, CompiledPolicy, LabelSelector, NetworkPolicy, PodView};
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

    #[derive(Default)]
    struct Maps {
        writes: Arc<Mutex<Vec<(usize, usize, bool)>>>,
    }
    impl NetpolMapPort for Maps {
        fn apply(
            &mut self,
            policy: &CompiledPolicy,
            cgroups: &BTreeMap<u64, String>,
            enforce: bool,
        ) -> Result<NetpolApplied, DomainError> {
            self.writes
                .lock()
                .unwrap()
                .push((policy.pods.len(), cgroups.len(), enforce));
            Ok(NetpolApplied {
                entries: policy.slots.iter().map(|slot| slot.entries.len()).sum(),
                cgroups: cgroups
                    .values()
                    .filter(|uid| policy.pods.contains_key(*uid))
                    .count(),
                cgroups_dropped: 0,
            })
        }
    }

    fn pod(uid: &str, ip: &str, node: &str) -> PodView {
        PodView {
            uid: uid.into(),
            namespace: "shop".into(),
            name: uid.into(),
            labels: [("app".to_string(), uid.to_string())].into(),
            ips: vec![ip.parse().unwrap()],
            ports: Vec::new(),
            host_ips: vec![node.parse().unwrap()],
            host_network: false,
            terminal: false,
        }
    }

    fn deny_all_ingress() -> NetworkPolicy {
        NetworkPolicy {
            namespace: "shop".into(),
            name: "deny".into(),
            pod_selector: LabelSelector::default(),
            ingress: Vec::new(),
            egress: Vec::new(),
            policy_types: None,
        }
    }

    #[test]
    fn only_the_pods_whose_cgroups_are_here_are_compiled() {
        let view = ClusterView {
            policies: vec![deny_all_ingress()],
            pods: vec![
                pod("local", "10.0.0.5", "192.168.1.10"),
                pod("remote", "10.0.1.5", "192.168.1.11"),
            ],
            ..ClusterView::default()
        };
        let maps = Maps::default();
        let writes = Arc::clone(&maps.writes);
        let mut service = NetpolService::new(
            Arc::new(Cluster(view)),
            Arc::new(Cgroups([(7, "local".to_string())].into())),
            Box::new(maps),
            true,
        );
        let applied = service.sync_once().unwrap();
        assert_eq!(applied.cgroups, 1);
        assert_eq!(*writes.lock().unwrap(), vec![(1, 1, true)]);
    }

    #[test]
    fn observe_mode_reaches_the_maps_as_observe() {
        let view = ClusterView {
            policies: vec![deny_all_ingress()],
            pods: vec![pod("local", "10.0.0.5", "192.168.1.10")],
            ..ClusterView::default()
        };
        let maps = Maps::default();
        let writes = Arc::clone(&maps.writes);
        let mut service = NetpolService::new(
            Arc::new(Cluster(view)),
            Arc::new(Cgroups([(7, "local".to_string())].into())),
            Box::new(maps),
            false,
        );
        service.sync_once().unwrap();
        service.sync_once().unwrap();
        assert!(
            writes
                .lock()
                .unwrap()
                .iter()
                .all(|(_, _, enforce)| !enforce)
        );
        assert_eq!(writes.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_cluster_change_recompiles_and_cancel_stops_the_loop() {
        let maps = Maps::default();
        let writes = Arc::clone(&maps.writes);
        let service = NetpolService::new(
            Arc::new(Cluster(ClusterView::default())),
            Arc::new(Cgroups(BTreeMap::new())),
            Box::new(maps),
            true,
        );
        let (tx, rx) = watch::channel(0u64);
        let cancel = CancellationToken::new();
        let handle = tokio::spawn(service.run(rx, cancel.clone()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(writes.lock().unwrap().len(), 1);
        tx.send_modify(|generation| *generation += 1);
        tokio::time::sleep(NETPOL_SETTLE + Duration::from_millis(300)).await;
        assert_eq!(writes.lock().unwrap().len(), 2);
        cancel.cancel();
        handle.await.unwrap();
    }
}
