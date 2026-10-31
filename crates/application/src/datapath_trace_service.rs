//! "Why is this packet dropped", asked of the programs that are loaded.
//!
//! The request is a five-tuple, or a pod and the rest of one. The packet is
//! crafted from it, run through the programs of the direction asked about,
//! and each stage's record is read back and named: the firewall's through the
//! slot or fast-path key its rule went to, the IDS's through its rule list,
//! threat intelligence's through the feed that listed the address.

use std::net::IpAddr;
use std::sync::Arc;

use domain::common::entity::RuleId;
use domain::ids::entity::IdsRule;
use domain::trace::{
    FirewallTraceIndex, Stage, TraceError, TraceReport, TraceRequest, packet::craft,
};
use ports::secondary::datapath_trace_port::DatapathTracePort;
use ports::secondary::netpol_map_port::ClusterViewPort;

/// Runs traces against the loaded datapath.
pub struct DatapathTraceService {
    port: Arc<dyn DatapathTracePort>,
    cluster: Option<Arc<dyn ClusterViewPort>>,
}

/// The feed that lists an address, if any does.
pub type FeedLookup<'a> = dyn Fn(&IpAddr) -> Option<String> + 'a;

/// What names a rule identifier, read once a trace has run.
#[derive(Default)]
pub struct TraceNames<'a> {
    /// Where the firewall put each rule at its last sync.
    pub firewall: Option<&'a FirewallTraceIndex>,
    /// The IDS rules in the order their identifiers count them.
    pub ids_rules: &'a [IdsRule],
    /// The feed that lists an address, if any does.
    pub threat_feed: Option<&'a FeedLookup<'a>>,
}

impl DatapathTraceService {
    /// `cluster` is where a workload named as the source is looked up;
    /// `None` where the agent does not watch the cluster.
    pub fn new(
        port: Arc<dyn DatapathTracePort>,
        cluster: Option<Arc<dyn ClusterViewPort>>,
    ) -> Self {
        Self { port, cluster }
    }

    /// Run `request` through the datapath. Blocks for the length of the
    /// test runs, a few microseconds a program.
    ///
    /// # Errors
    ///
    /// [`TraceError::Invalid`] for a request that is not one packet,
    /// [`TraceError::Workload`] for a workload that names no address, and
    /// [`TraceError::Unavailable`] when the kernel refuses the run.
    pub fn trace(&self, request: TraceRequest) -> Result<TraceReport, TraceError> {
        let request = resolve_workload(request, self.cluster.as_deref())?;
        let src = request.validate()?;
        let packet = craft(
            src,
            request.dst_ip,
            request.effective_src_port(),
            request.effective_dst_port(),
            request.protocol,
        );
        let answer = self.port.run(&packet, request.direction)?;
        Ok(TraceReport::assemble(
            request,
            src,
            &answer.runs,
            answer.not_loaded,
        ))
    }
}

/// Put the pod's address in the request as its source, when it names one.
///
/// # Errors
///
/// [`TraceError::Invalid`] when both a source address and a workload are
/// given, and [`TraceError::Workload`] when the workload cannot be read as
/// `namespace/name`, the cluster is not watched, or the pod has no address
/// of the destination's family.
pub fn resolve_workload(
    mut request: TraceRequest,
    cluster: Option<&dyn ClusterViewPort>,
) -> Result<TraceRequest, TraceError> {
    let Some(workload) = request.workload.clone() else {
        return Ok(request);
    };
    if request.src_ip.is_some() {
        return Err(TraceError::Invalid(
            "give a source address or a workload, not both".to_string(),
        ));
    }
    let fail = |reason: &str| TraceError::Workload {
        workload: workload.clone(),
        reason: reason.to_string(),
    };
    let Some((namespace, name)) = workload
        .split_once('/')
        .filter(|(ns, name)| !ns.is_empty() && !name.is_empty())
    else {
        return Err(fail("a workload is written namespace/pod"));
    };
    let Some(cluster) = cluster else {
        return Err(fail(
            "this agent does not watch the cluster: Kubernetes network policy is off",
        ));
    };
    let view = cluster.view();
    let Some(pod) = view
        .pods
        .iter()
        .find(|pod| pod.namespace == namespace && pod.name == name && !pod.terminal)
    else {
        return Err(fail("no running pod of that name"));
    };
    let v4 = request.dst_ip.is_ipv4();
    let Some(ip) = pod.ips.iter().find(|ip| ip.is_ipv4() == v4) else {
        return Err(fail(if v4 {
            "the pod has no IPv4 address"
        } else {
            "the pod has no IPv6 address"
        }));
    };
    request.src_ip = Some(*ip);
    Ok(request)
}

/// Name the rule behind each stage that reported one.
pub fn name_rules(report: &mut TraceReport, names: &TraceNames<'_>) {
    let src = report.src_ip;
    let dst = report.request.dst_ip;
    let sport = report.request.effective_src_port();
    let dport = report.request.effective_dst_port();
    let proto = report.request.protocol.number(dst.is_ipv6());
    for stage in &mut report.stages {
        stage.rule = match stage.stage {
            Stage::Firewall => stage.rule_id.and_then(|id| {
                names
                    .firewall
                    .and_then(|index| index.name(id, src, dst, sport, dport, proto))
                    .map(|RuleId(name)| name.clone())
            }),
            Stage::Ids => stage.rule_id.and_then(|id| {
                usize::try_from(id)
                    .ok()
                    .and_then(|i| names.ids_rules.get(i))
                    .map(|rule| rule.id.0.clone())
            }),
            Stage::ThreatIntel if stage.reason == domain::trace::Reason::List => names
                .threat_feed
                .and_then(|feed| feed(&src).or_else(|| feed(&dst)))
                .map(|feed| format!("feed {feed}")),
            _ => None,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use domain::netpol::entity::{ClusterView, PodView};
    use domain::trace::{ProgramRun, TraceDirection, TraceHook, TraceProtocol, Verdict};
    use ebpf_common::trace::{NO_RULE, TraceRecord, reason, stage};
    use ports::secondary::datapath_trace_port::DatapathRuns;

    struct Scripted {
        runs: Vec<ProgramRun>,
        seen: Mutex<Vec<(Vec<u8>, TraceDirection)>>,
    }

    impl DatapathTracePort for Scripted {
        fn run(
            &self,
            packet: &[u8],
            direction: TraceDirection,
        ) -> Result<DatapathRuns, TraceError> {
            self.seen.lock().unwrap().push((packet.to_vec(), direction));
            Ok(DatapathRuns {
                runs: self.runs.clone(),
                not_loaded: vec!["tc_qos_ingress".to_string()],
            })
        }
    }

    struct Cluster(ClusterView);

    impl ClusterViewPort for Cluster {
        fn view(&self) -> ClusterView {
            self.0.clone()
        }
    }

    fn request() -> TraceRequest {
        TraceRequest {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 0,
            dst_port: 22,
            protocol: TraceProtocol::Tcp,
            direction: TraceDirection::Ingress,
            workload: None,
        }
    }

    fn record(stage: u8, action: u32, why: u8, rule_id: u32) -> TraceRecord {
        TraceRecord {
            stage,
            action,
            reason: why,
            rule_id,
            detail: 1,
        }
    }

    fn pod(namespace: &str, name: &str, ips: &[&str], terminal: bool) -> PodView {
        PodView {
            uid: format!("{namespace}-{name}"),
            namespace: namespace.to_string(),
            name: name.to_string(),
            labels: BTreeMap::new(),
            ips: ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            ports: Vec::new(),
            host_ips: Vec::new(),
            host_network: false,
            terminal,
        }
    }

    fn cluster(pods: Vec<PodView>) -> Cluster {
        Cluster(ClusterView {
            pods,
            ..ClusterView::default()
        })
    }

    #[test]
    fn a_trace_runs_the_crafted_packet_and_reports_where_it_stopped() {
        let port = Arc::new(Scripted {
            runs: vec![
                ProgramRun {
                    program: "xdp_firewall".into(),
                    hook: TraceHook::Xdp,
                    retval: 2,
                    records: vec![record(stage::FIREWALL, 0, reason::DEFAULT, NO_RULE)],
                },
                ProgramRun {
                    program: "tc_ids".into(),
                    hook: TraceHook::TcIngress,
                    retval: 2,
                    records: vec![record(stage::IDS, 2, reason::RULE, 0)],
                },
            ],
            seen: Mutex::new(Vec::new()),
        });
        let service = DatapathTraceService::new(port.clone(), None);
        let report = service.trace(request()).unwrap();
        assert_eq!(report.stopped_at, Some(Stage::Ids));
        assert_eq!(report.verdict, Verdict::Drop);
        assert_eq!(report.not_loaded, vec!["tc_qos_ingress".to_string()]);
        let seen = port.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, TraceDirection::Ingress);
        assert_eq!(&seen[0].0[14 + 12..14 + 16], &[10, 0, 0, 1]);
    }

    #[test]
    fn an_invalid_request_reaches_no_program() {
        let port = Arc::new(Scripted {
            runs: Vec::new(),
            seen: Mutex::new(Vec::new()),
        });
        let service = DatapathTraceService::new(port.clone(), None);
        let mut bad = request();
        bad.dst_port = 0;
        assert!(matches!(service.trace(bad), Err(TraceError::Invalid(_))));
        assert!(port.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn a_workload_becomes_the_source_of_its_family() {
        let mut asked = request();
        asked.src_ip = None;
        asked.workload = Some("shop/web-0".to_string());
        let pods = cluster(vec![
            pod("shop", "web-0", &["fd00::5", "10.1.2.3"], false),
            pod("shop", "web-1", &["10.1.2.4"], false),
        ]);
        let resolved = resolve_workload(asked.clone(), Some(&pods)).unwrap();
        assert_eq!(resolved.src_ip, Some("10.1.2.3".parse().unwrap()));

        let mut v6 = asked.clone();
        v6.dst_ip = "fd00::9".parse().unwrap();
        let resolved = resolve_workload(v6, Some(&pods)).unwrap();
        assert_eq!(resolved.src_ip, Some("fd00::5".parse().unwrap()));
    }

    #[test]
    fn a_workload_that_cannot_be_resolved_says_why() {
        let mut asked = request();
        asked.src_ip = None;
        asked.workload = Some("shop/gone".to_string());
        let pods = cluster(vec![pod("shop", "gone", &["10.1.2.3"], true)]);
        assert!(matches!(
            resolve_workload(asked.clone(), Some(&pods)),
            Err(TraceError::Workload { .. })
        ));
        assert!(matches!(
            resolve_workload(asked.clone(), None),
            Err(TraceError::Workload { .. })
        ));
        let mut unparsed = asked.clone();
        unparsed.workload = Some("no-namespace".to_string());
        assert!(matches!(
            resolve_workload(unparsed, Some(&pods)),
            Err(TraceError::Workload { .. })
        ));
        let mut both = asked;
        both.src_ip = Some("10.9.9.9".parse().unwrap());
        assert!(matches!(
            resolve_workload(both, Some(&pods)),
            Err(TraceError::Invalid(_))
        ));
    }

    #[test]
    fn a_traced_workload_sends_from_its_pod() {
        let port = Arc::new(Scripted {
            runs: Vec::new(),
            seen: Mutex::new(Vec::new()),
        });
        let pods: Arc<dyn ClusterViewPort> =
            Arc::new(cluster(vec![pod("shop", "web-0", &["10.1.2.3"], false)]));
        let service = DatapathTraceService::new(port.clone(), Some(pods));
        let mut asked = request();
        asked.src_ip = None;
        asked.workload = Some("shop/web-0".to_string());
        let report = service.trace(asked).unwrap();
        assert_eq!(report.src_ip, "10.1.2.3".parse::<IpAddr>().unwrap());
        assert_eq!(
            &port.seen.lock().unwrap()[0].0[14 + 12..14 + 16],
            &[10, 1, 2, 3]
        );
    }

    #[test]
    fn a_request_without_a_workload_is_left_alone() {
        assert_eq!(resolve_workload(request(), None).unwrap(), request());
    }

    #[test]
    fn rules_are_named_from_the_stage_that_reported_them() {
        let runs = vec![
            ProgramRun {
                program: "xdp_firewall".into(),
                hook: TraceHook::Xdp,
                retval: 2,
                records: vec![record(stage::FIREWALL, 0, reason::RULE, 0)],
            },
            ProgramRun {
                program: "tc_threatintel".into(),
                hook: TraceHook::TcIngress,
                retval: u32::MAX,
                records: vec![record(stage::THREATINTEL, u32::MAX, reason::LIST, 7)],
            },
            ProgramRun {
                program: "tc_ids".into(),
                hook: TraceHook::TcIngress,
                retval: 2,
                records: vec![record(stage::IDS, 2, reason::RULE, 1)],
            },
        ];
        let req = request();
        let src = req.src_ip.unwrap();
        let mut report = TraceReport::assemble(req, src, &runs, Vec::new());

        let mut index = FirewallTraceIndex::default();
        index.record_v6(
            RuleId("v6-only".into()),
            domain::trace::RulePlacement::Array(1),
        );
        let ids_rules = vec![ids_rule("ssh-scan-0"), ids_rule("ssh-scan-1")];
        let feed = |ip: &IpAddr| (ip.to_string() == "10.0.0.2").then(|| "abuse-ch".to_string());
        let names = TraceNames {
            firewall: Some(&index),
            ids_rules: &ids_rules,
            threat_feed: Some(&feed),
        };
        name_rules(&mut report, &names);
        assert_eq!(report.stages[0].rule, None, "slot 0 holds no v4 rule");
        assert_eq!(report.stages[1].rule.as_deref(), Some("feed abuse-ch"));
        assert_eq!(report.stages[2].rule.as_deref(), Some("ssh-scan-1"));
    }

    fn ids_rule(id: &str) -> IdsRule {
        IdsRule {
            id: RuleId(id.to_string()),
            description: String::new(),
            severity: domain::common::entity::Severity::Medium,
            mode: domain::common::entity::DomainMode::Block,
            protocol: domain::common::entity::Protocol::Tcp,
            dst_port: Some(22),
            src_port: None,
            pattern: String::new(),
            enabled: true,
            threshold: None,
            domain_pattern: None,
            domain_match_mode: None,
            country_thresholds: None,
            group_mask: 0,
            tenant_id: 0,
            workload: None,
            kill_process: false,
            imported: None,
        }
    }
}
