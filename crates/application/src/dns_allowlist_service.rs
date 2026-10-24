//! The decision behind the agent's resolver: which container asked, and
//! whether its DNS allow-list carries the name.
//!
//! The container is found by the address the query came from, read off the
//! runtime's bridge networks. That reading is kept and refreshed on a clock,
//! and sooner when an address nobody holds asks, so a container started a
//! moment ago is known by its second query at the latest.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use domain::common::entity::Severity;
use domain::dns::allowlist::{AllowListDecision, DnsAllowList, refused_response};
use domain::dns::entity::{DnsAlert, DnsAlertReason};
use domain::dns::parser::first_question;
use ports::secondary::bridge_network_port::BridgeNetworkPort;
use ports::secondary::dns_upstream_port::{DnsTransport, DnsUpstreamPort};
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::{Mutex, mpsc};

use crate::alert_event::AlertEvent;

/// How long a reading of who holds which address is trusted.
const HOLDERS_TTL: Duration = Duration::from_secs(30);

/// The least time between two readings forced by an unknown address, so a
/// stranger sending queries cannot turn each one into a Docker call.
const MISS_REFRESH: Duration = Duration::from_secs(1);

/// What the resolver does with one query.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolverVerdict {
    /// Send it upstream and relay the answer.
    Forward,
    /// Answer it with these bytes; nothing goes upstream.
    Answer(Vec<u8>),
    /// Not a query that can be answered at all; drop it.
    Drop,
}

#[derive(Default)]
struct Holders {
    by_address: HashMap<IpAddr, (String, String)>,
    read_at: Option<Instant>,
}

/// Decides each query the agent's resolver receives.
pub struct DnsAllowListService {
    list: DnsAllowList,
    bridges: Arc<dyn BridgeNetworkPort>,
    upstream: Arc<dyn DnsUpstreamPort>,
    metrics: Arc<dyn MetricsPort>,
    alert_tx: Option<mpsc::Sender<AlertEvent>>,
    holders: Mutex<Holders>,
}

impl DnsAllowListService {
    pub fn new(
        list: DnsAllowList,
        bridges: Arc<dyn BridgeNetworkPort>,
        upstream: Arc<dyn DnsUpstreamPort>,
        metrics: Arc<dyn MetricsPort>,
    ) -> Self {
        Self {
            list,
            bridges,
            upstream,
            metrics,
            alert_tx: None,
            holders: Mutex::new(Holders::default()),
        }
    }

    #[must_use]
    pub fn with_alert_tx(mut self, tx: mpsc::Sender<AlertEvent>) -> Self {
        self.alert_tx = Some(tx);
        self
    }

    /// How many containers the allow-list names.
    pub fn governed(&self) -> usize {
        self.list.len()
    }

    /// The answer to one query that arrived from `source` over `transport`:
    /// the refusal, the upstream's answer, or nothing when the query cannot
    /// be read or no upstream answered, in which case the client times out
    /// and retries as it would against any resolver.
    pub async fn answer(
        &self,
        source: IpAddr,
        query: &[u8],
        transport: DnsTransport,
        now_ns: u64,
    ) -> Option<Vec<u8>> {
        match self.admit(source, query, now_ns).await {
            ResolverVerdict::Answer(answer) => Some(answer),
            ResolverVerdict::Drop => None,
            ResolverVerdict::Forward => match self.upstream.resolve(query, transport).await {
                Ok(answer) => Some(answer),
                Err(e) => {
                    tracing::debug!(error = %e, "DNS allow-list resolver got no upstream answer");
                    None
                }
            },
        }
    }

    /// Decide one query that arrived from `source`.
    async fn admit(&self, source: IpAddr, query: &[u8], now_ns: u64) -> ResolverVerdict {
        let Ok((domain, question_end)) = first_question(query) else {
            return ResolverVerdict::Drop;
        };
        let Some(container) = self.governing_name(source).await else {
            return ResolverVerdict::Forward;
        };
        match self.list.decide(Some(&container), &domain) {
            AllowListDecision::Ungoverned => ResolverVerdict::Forward,
            AllowListDecision::Allowed => {
                self.metrics.record_dns_allowlist_query(&container, false);
                ResolverVerdict::Forward
            }
            AllowListDecision::Refused => {
                self.metrics.record_dns_allowlist_query(&container, true);
                self.alert(&container, source, &domain, now_ns);
                ResolverVerdict::Answer(refused_response(query, question_end))
            }
        }
    }

    /// The name, or failing that the id, under which the allow-list governs
    /// the container holding `source`; `None` when no list governs it.
    async fn governing_name(&self, source: IpAddr) -> Option<String> {
        let mut holders = self.holders.lock().await;
        let age = holders.read_at.map(|at| at.elapsed());
        let stale = age.is_none_or(|age| age >= HOLDERS_TTL);
        let unknown = !holders.by_address.contains_key(&source);
        if stale || (unknown && age.is_none_or(|age| age >= MISS_REFRESH)) {
            self.refresh(&mut holders).await;
        }
        let (name, id) = holders.by_address.get(&source)?;
        [name, id]
            .into_iter()
            .find(|candidate| self.list.governs(candidate))
            .cloned()
    }

    async fn refresh(&self, holders: &mut Holders) {
        holders.read_at = Some(Instant::now());
        match self.bridges.bridge_networks().await {
            Ok(networks) => {
                holders.by_address = networks
                    .into_iter()
                    .flat_map(|network| network.members)
                    .flat_map(|member| {
                        member
                            .addresses
                            .into_iter()
                            .map(move |address| (address, (member.name.clone(), member.id.clone())))
                    })
                    .collect();
            }
            Err(e) => {
                // The last reading stays: a Docker socket that stops answering
                // must not turn every governed container into a stranger.
                tracing::warn!(error = %e, "DNS allow-list could not read the bridge networks");
            }
        }
    }

    fn alert(&self, container: &str, source: IpAddr, domain: &str, now_ns: u64) {
        let Some(tx) = &self.alert_tx else {
            return;
        };
        let alert = DnsAlert {
            domain: domain.to_string(),
            resolved_ips: Vec::new(),
            reason: DnsAlertReason::AllowList {
                container: container.to_string(),
                source,
            },
            severity: Severity::Medium,
            timestamp_ns: now_ns,
            container: None,
        };
        if tx.try_send(AlertEvent::Dns(alert)).is_err() {
            tracing::debug!(
                container,
                domain,
                "DNS allow-list alert dropped, channel full"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Mutex as StdMutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use domain::container::error::ContainerError;
    use domain::learning::segmentation::{BridgeMember, BridgeNetwork};
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, ContainerMetrics, CtMetrics,
        DdosMetrics, DlpMetrics, DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics,
        FirewallMetrics, IpsMetrics, LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
        ThreatIntelMetrics, ZoneMetrics,
    };

    use super::*;

    struct FakeBridges {
        members: Vec<(String, IpAddr)>,
        reads: AtomicUsize,
    }

    #[async_trait]
    impl BridgeNetworkPort for FakeBridges {
        async fn bridge_networks(&self) -> Result<Vec<BridgeNetwork>, ContainerError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(vec![BridgeNetwork {
                name: "app".to_string(),
                subnets: Vec::new(),
                embedded_dns: true,
                members: self
                    .members
                    .iter()
                    .map(|(name, address)| BridgeMember {
                        id: format!("{name}-id"),
                        name: name.clone(),
                        addresses: vec![*address],
                    })
                    .collect(),
            }])
        }
    }

    struct EchoUpstream;

    #[async_trait]
    impl DnsUpstreamPort for EchoUpstream {
        async fn resolve(
            &self,
            query: &[u8],
            _transport: DnsTransport,
        ) -> Result<Vec<u8>, domain::dns::error::DnsError> {
            let mut answer = query.to_vec();
            answer[2] |= 0x80;
            Ok(answer)
        }
    }

    #[derive(Default)]
    struct CountingMetrics {
        seen: StdMutex<Vec<(String, bool)>>,
    }

    impl PacketMetrics for CountingMetrics {}
    impl FirewallMetrics for CountingMetrics {}
    impl AlertMetrics for CountingMetrics {}
    impl IpsMetrics for CountingMetrics {}
    impl ConfigMetrics for CountingMetrics {}
    impl SystemMetrics for CountingMetrics {}
    impl EventMetrics for CountingMetrics {}
    impl DomainMetrics for CountingMetrics {}
    impl LbMetrics for CountingMetrics {}
    impl DlpMetrics for CountingMetrics {}
    impl DdosMetrics for CountingMetrics {}
    impl ConntrackMetrics for CountingMetrics {}
    impl RoutingMetrics for CountingMetrics {}
    impl AuditMetrics for CountingMetrics {}
    impl FingerprintMetrics for CountingMetrics {}
    impl ContainerMetrics for CountingMetrics {}
    impl CtMetrics for CountingMetrics {}
    impl ThreatIntelMetrics for CountingMetrics {}
    impl ZoneMetrics for CountingMetrics {}
    impl DnsMetrics for CountingMetrics {
        fn record_dns_allowlist_query(&self, container: &str, refused: bool) {
            self.seen
                .lock()
                .unwrap()
                .push((container.to_string(), refused));
        }
    }

    fn query(name: &str) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.extend_from_slice(&[0, 0, 1, 0, 1]);
        out
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn service(
        metrics: Arc<CountingMetrics>,
    ) -> (
        DnsAllowListService,
        Arc<FakeBridges>,
        mpsc::Receiver<AlertEvent>,
    ) {
        let bridges = Arc::new(FakeBridges {
            members: vec![
                ("web".to_string(), ip("172.18.0.2")),
                ("cache".to_string(), ip("172.18.0.3")),
            ],
            reads: AtomicUsize::new(0),
        });
        let list = DnsAllowList::new([("web", vec!["api.github.com"])]).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let service = DnsAllowListService::new(
            list,
            Arc::clone(&bridges) as Arc<dyn BridgeNetworkPort>,
            Arc::new(EchoUpstream),
            metrics as Arc<dyn MetricsPort>,
        )
        .with_alert_tx(tx);
        (service, bridges, rx)
    }

    #[tokio::test]
    async fn a_governed_container_is_refused_a_name_off_its_list_and_alerted() {
        let metrics = Arc::new(CountingMetrics::default());
        let (service, _, mut rx) = service(Arc::clone(&metrics));
        let asked = query("evil.example");
        let ResolverVerdict::Answer(answer) = service.admit(ip("172.18.0.2"), &asked, 7).await
        else {
            panic!("a refusal is answered by the resolver");
        };
        assert_eq!(answer[3] & 0x0f, 5);
        match rx.try_recv().unwrap() {
            AlertEvent::Dns(alert) => {
                assert_eq!(alert.domain, "evil.example");
                assert!(matches!(
                    alert.reason,
                    DnsAlertReason::AllowList { ref container, .. } if container == "web"
                ));
            }
            _ => panic!("a DNS alert"),
        }
        assert_eq!(
            metrics.seen.lock().unwrap().as_slice(),
            &[("web".to_string(), true)]
        );
    }

    #[tokio::test]
    async fn a_listed_name_is_forwarded_and_counted() {
        let metrics = Arc::new(CountingMetrics::default());
        let (service, _, mut rx) = service(Arc::clone(&metrics));
        assert_eq!(
            service
                .admit(ip("172.18.0.2"), &query("api.github.com"), 7)
                .await,
            ResolverVerdict::Forward
        );
        assert!(rx.try_recv().is_err(), "an allowed name raises nothing");
        assert_eq!(
            metrics.seen.lock().unwrap().as_slice(),
            &[("web".to_string(), false)]
        );
    }

    #[tokio::test]
    async fn an_unlisted_container_and_a_stranger_are_forwarded_uncounted() {
        let metrics = Arc::new(CountingMetrics::default());
        let (service, bridges, _rx) = service(Arc::clone(&metrics));
        let asked = query("evil.example");
        assert_eq!(
            service.admit(ip("172.18.0.3"), &asked, 7).await,
            ResolverVerdict::Forward
        );
        assert_eq!(
            service.admit(ip("10.9.9.9"), &asked, 7).await,
            ResolverVerdict::Forward
        );
        assert!(metrics.seen.lock().unwrap().is_empty());
        assert_eq!(
            bridges.reads.load(Ordering::SeqCst),
            1,
            "a stranger right after a reading does not force another"
        );
    }

    #[tokio::test]
    async fn the_answer_is_the_refusal_or_what_the_upstream_said() {
        let (service, _, _rx) = service(Arc::new(CountingMetrics::default()));
        let refused = service
            .answer(
                ip("172.18.0.2"),
                &query("evil.example"),
                DnsTransport::Udp,
                7,
            )
            .await
            .unwrap();
        assert_eq!(refused[3] & 0x0f, 5);
        let forwarded = service
            .answer(
                ip("172.18.0.2"),
                &query("api.github.com"),
                DnsTransport::Tcp,
                7,
            )
            .await
            .unwrap();
        assert_eq!(forwarded[3] & 0x0f, 0, "the upstream's own answer");
        assert!(
            service
                .answer(ip("172.18.0.2"), &[1, 2], DnsTransport::Udp, 7)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn something_that_is_not_a_query_is_dropped() {
        let (service, _, _rx) = service(Arc::new(CountingMetrics::default()));
        assert_eq!(
            service.admit(ip("172.18.0.2"), &[0, 1, 2], 7).await,
            ResolverVerdict::Drop
        );
    }
}
