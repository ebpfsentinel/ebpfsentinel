//! What a proposed `NetworkPolicy` would have refused, asked of the flows
//! the connection table holds now.
//!
//! The cluster is read from the same cache the enforcement loop compiles
//! from, and the proposal is read with the same translation the watchers
//! apply, so the answer is the one the hooks would give once it is applied.

use std::net::IpAddr;
use std::sync::Arc;

use domain::common::error::DomainError;
use domain::conntrack::entity::Connection;
use domain::netpol::{Delivery, ObservedFlow, ReplayReport, replay};
use ports::secondary::netpol_map_port::{ClusterViewPort, NetworkPolicyManifestPort};

/// Replays proposed policies against observed connections.
pub struct NetpolReplayService {
    cluster: Arc<dyn ClusterViewPort>,
    manifests: Box<dyn NetworkPolicyManifestPort>,
}

impl NetpolReplayService {
    pub fn new(
        cluster: Arc<dyn ClusterViewPort>,
        manifests: Box<dyn NetworkPolicyManifestPort>,
    ) -> Self {
        Self { cluster, manifests }
    }

    /// Replay the policies in `manifests` against `connections`.
    ///
    /// # Errors
    ///
    /// Returns the reason the manifests were refused, and replays nothing:
    /// an answer for part of a proposal would be an answer for a set nobody
    /// proposed.
    pub fn replay(
        &self,
        manifests: &str,
        connections: &[Connection],
    ) -> Result<ReplayReport, DomainError> {
        let proposed = self.manifests.parse(manifests)?;
        if proposed.is_empty() {
            return Err(DomainError::InvalidConfig(
                "the manifests carry no network policy".to_string(),
            ));
        }
        let flows: Vec<ObservedFlow> = connections.iter().filter_map(observed).collect();
        let mut report = replay(&self.cluster.view(), &proposed, &flows);
        // A connection whose addresses do not read is still a flow seen.
        report.flows = connections.len();
        Ok(report)
    }
}

/// One connection as the replay reads it, or `None` when its addresses do
/// not parse.
fn observed(connection: &Connection) -> Option<ObservedFlow> {
    let src: IpAddr = connection.src_ip.parse().ok()?;
    let dst: IpAddr = connection.dst_ip.parse().ok()?;
    let delivered = connection.reply.as_ref().and_then(|reply| {
        Some(Delivery {
            to: reply.src_ip.parse().ok()?,
            port: reply.src_port,
            seen_from: reply.dst_ip.parse().ok()?,
        })
    });
    Some(ObservedFlow {
        src,
        dst,
        protocol: connection.protocol,
        dst_port: connection.dst_port,
        delivered,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::conntrack::entity::{ConnectionState, ReplyTuple};
    use domain::netpol::{
        ClusterView, Direction, LabelSelector, NetworkPolicy, PodView, PolicyRule,
    };

    struct Fixed(ClusterView);

    impl ClusterViewPort for Fixed {
        fn view(&self) -> ClusterView {
            self.0.clone()
        }
    }

    /// Hands back a deny-all-ingress for `api`, or nothing for an empty
    /// stream, whatever the text says.
    struct Canned;

    impl NetworkPolicyManifestPort for Canned {
        fn parse(&self, manifests: &str) -> Result<Vec<NetworkPolicy>, DomainError> {
            if manifests.is_empty() {
                return Ok(Vec::new());
            }
            Ok(vec![NetworkPolicy {
                namespace: "shop".into(),
                name: "deny".into(),
                pod_selector: LabelSelector {
                    match_labels: [("app".to_string(), "api".to_string())].into(),
                    match_expressions: Vec::new(),
                },
                ingress: Vec::<PolicyRule>::new(),
                egress: Vec::new(),
                policy_types: None,
            }])
        }
    }

    fn pod(name: &str, app: &str, ip: &str) -> PodView {
        PodView {
            uid: name.into(),
            namespace: "shop".into(),
            name: name.into(),
            labels: [("app".to_string(), app.to_string())].into(),
            ips: vec![ip.parse().unwrap()],
            ports: Vec::new(),
            host_ips: vec!["192.168.1.10".parse().unwrap()],
            host_network: false,
            terminal: false,
        }
    }

    fn connection(src: &str, dst: &str, reply: Option<ReplyTuple>) -> Connection {
        Connection {
            src_ip: src.into(),
            dst_ip: dst.into(),
            src_port: 40000,
            dst_port: 80,
            protocol: 6,
            state: ConnectionState::Established,
            packets_fwd: 0,
            packets_rev: 0,
            bytes_fwd: 0,
            bytes_rev: 0,
            workload: None,
            reply,
        }
    }

    fn service() -> NetpolReplayService {
        NetpolReplayService::new(
            Arc::new(Fixed(ClusterView {
                pods: vec![
                    pod("web-1", "web", "10.244.1.2"),
                    pod("api-1", "api", "10.244.1.3"),
                ],
                ..ClusterView::default()
            })),
            Box::new(Canned),
        )
    }

    #[test]
    fn a_connection_through_a_service_is_put_to_the_backend() {
        let through_service = connection(
            "10.244.1.2",
            "10.96.0.20",
            Some(ReplyTuple {
                src_ip: "10.244.1.3".into(),
                dst_ip: "10.244.1.2".into(),
                src_port: 8080,
                dst_port: 40000,
            }),
        );
        let report = service()
            .replay(
                "proposal",
                &[through_service, connection("bogus", "10.0.0.1", None)],
            )
            .unwrap();
        assert_eq!(report.flows, 2);
        assert_eq!(report.newly_refused, 1);
        let refused = &report.workloads[0].refused[0];
        assert_eq!(report.workloads[0].pod, "api-1");
        assert_eq!(refused.direction, Direction::Ingress);
        assert_eq!(refused.port, 8080);
    }

    #[test]
    fn a_stream_without_a_policy_replays_nothing() {
        let error = service().replay("", &[]).unwrap_err();
        assert!(error.to_string().contains("no network policy"));
    }
}
