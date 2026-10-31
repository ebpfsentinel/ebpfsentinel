//! What a trace is asked with, what each stage answered, and the answer.

use std::net::IpAddr;

use ebpf_common::trace::{NO_RULE, TraceRecord, fast_path, reason, stage};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Which side of the node the crafted packet is presented on.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceDirection {
    /// Arriving on an interface: the XDP chain, then the tc ingress chain.
    #[default]
    Ingress,
    /// Leaving through an interface: the tc egress chain. XDP sees no
    /// outgoing packet.
    Egress,
}

/// The transport the crafted packet carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceProtocol {
    /// A TCP segment opening a connection: SYN, no payload.
    Tcp,
    /// A UDP datagram with no payload.
    Udp,
    /// An echo request, ICMP or `ICMPv6` after the address family.
    Icmp,
}

impl TraceProtocol {
    /// The IP protocol number, which for ICMP depends on the family.
    #[must_use]
    pub fn number(self, v6: bool) -> u8 {
        match (self, v6) {
            (Self::Tcp, _) => 6,
            (Self::Udp, _) => 17,
            (Self::Icmp, false) => 1,
            (Self::Icmp, true) => 58,
        }
    }

    /// Whether the transport carries ports.
    #[must_use]
    pub fn has_ports(self) -> bool {
        !matches!(self, Self::Icmp)
    }
}

/// A packet to trace, as a person asks about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceRequest {
    /// Source address. Left out when [`Self::workload`] names the source.
    pub src_ip: Option<IpAddr>,
    /// Destination address.
    pub dst_ip: IpAddr,
    /// Source port; ignored for ICMP. Zero picks an ephemeral port.
    #[serde(default)]
    pub src_port: u16,
    /// Destination port; ignored for ICMP.
    #[serde(default)]
    pub dst_port: u16,
    /// Transport of the crafted packet.
    pub protocol: TraceProtocol,
    /// Ingress by default.
    #[serde(default)]
    pub direction: TraceDirection,
    /// A pod as `namespace/name`, whose address becomes the source.
    #[serde(default)]
    pub workload: Option<String>,
}

/// The source port a request without one is sent from, inside the range
/// Linux hands out to outgoing connections.
pub const EPHEMERAL_PORT: u16 = 40_000;

/// Why a trace was not run.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TraceError {
    /// The request does not describe one packet.
    #[error("invalid trace request: {0}")]
    Invalid(String),
    /// The workload named as the source could not be turned into an address.
    #[error("workload {workload}: {reason}")]
    Workload { workload: String, reason: String },
    /// The kernel could not run the programs.
    #[error("the datapath could not be traced: {0}")]
    Unavailable(String),
}

impl TraceRequest {
    /// Check the request describes one packet, its source already resolved.
    ///
    /// # Errors
    ///
    /// [`TraceError::Invalid`] for a missing source, two address families,
    /// or a TCP or UDP packet with no destination port.
    pub fn validate(&self) -> Result<IpAddr, TraceError> {
        let Some(src) = self.src_ip else {
            return Err(TraceError::Invalid(
                "a source address or a workload is required".to_string(),
            ));
        };
        if src.is_ipv4() != self.dst_ip.is_ipv4() {
            return Err(TraceError::Invalid(
                "source and destination are not of the same address family".to_string(),
            ));
        }
        if self.protocol.has_ports() && self.dst_port == 0 {
            return Err(TraceError::Invalid(
                "a TCP or UDP packet needs a destination port".to_string(),
            ));
        }
        Ok(src)
    }

    /// The source port the crafted packet carries.
    #[must_use]
    pub fn effective_src_port(&self) -> u16 {
        if !self.protocol.has_ports() {
            0
        } else if self.src_port == 0 {
            EPHEMERAL_PORT
        } else {
            self.src_port
        }
    }

    /// The destination port the crafted packet carries.
    #[must_use]
    pub fn effective_dst_port(&self) -> u16 {
        if self.protocol.has_ports() {
            self.dst_port
        } else {
            0
        }
    }
}

/// A program of the datapath, as a trace names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Firewall,
    RateLimit,
    LoadBalancer,
    Conntrack,
    Scrub,
    Ids,
    ThreatIntel,
    Dns,
    NatIngress,
    NatEgress,
    Qos,
}

impl Stage {
    /// The stage a record's code names, if any.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            stage::FIREWALL => Self::Firewall,
            stage::RATELIMIT => Self::RateLimit,
            stage::LOADBALANCER => Self::LoadBalancer,
            stage::CONNTRACK => Self::Conntrack,
            stage::SCRUB => Self::Scrub,
            stage::IDS => Self::Ids,
            stage::THREATINTEL => Self::ThreatIntel,
            stage::DNS => Self::Dns,
            stage::NAT_INGRESS => Self::NatIngress,
            stage::NAT_EGRESS => Self::NatEgress,
            stage::QOS => Self::Qos,
            _ => return None,
        })
    }

    /// Whether the stage runs at XDP, where a record's action is the
    /// program's own action code rather than the tc return value.
    #[must_use]
    pub fn is_xdp(self) -> bool {
        matches!(self, Self::Firewall | Self::RateLimit | Self::LoadBalancer)
    }
}

/// Why a stage decided what it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// Nothing configured matched: the stage's default applied.
    Default,
    /// A configured rule matched.
    Rule,
    /// The flow is already established, so the rules were not consulted.
    Established,
    /// A rate or a budget was exceeded at the moment of the trace.
    Rate,
    /// An address or a name is on a list.
    List,
    /// The packet is malformed or not something the stage classifies.
    Malformed,
    /// The stage is switched off.
    Disabled,
    /// The packet would be rewritten: translated, normalised or marked.
    Rewrite,
    /// The program returned without saying why.
    Unrecorded,
}

impl Reason {
    fn from_code(code: u8) -> Self {
        match code {
            reason::DEFAULT => Self::Default,
            reason::RULE => Self::Rule,
            reason::ESTABLISHED => Self::Established,
            reason::RATE => Self::Rate,
            reason::LIST => Self::List,
            reason::MALFORMED => Self::Malformed,
            reason::DISABLED => Self::Disabled,
            reason::REWRITE => Self::Rewrite,
            _ => Self::Unrecorded,
        }
    }
}

/// What a stage did with the packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The packet goes on to the next stage.
    Pass,
    /// The packet goes on, and the match is logged.
    Log,
    /// The packet is dropped.
    Drop,
    /// The packet is dropped and refused: a reset or an unreachable goes back.
    Reject,
    /// The packet is sent back out of the interface it came in on.
    Bounce,
    /// The packet is sent to another interface or another host.
    Redirect,
    /// The program failed and the kernel dropped the packet.
    Abort,
    /// A return code the trace does not read.
    Other,
}

impl Verdict {
    /// Whether the packet goes no further on this path.
    #[must_use]
    pub fn stops(self) -> bool {
        !matches!(self, Self::Pass | Self::Log)
    }

    /// The verdict an XDP program's return code stands for.
    #[must_use]
    pub fn from_xdp(code: u32) -> Self {
        match code {
            0 => Self::Abort,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Bounce,
            4 => Self::Redirect,
            _ => Self::Other,
        }
    }

    /// The verdict a tc classifier's return code stands for. `TCX_NEXT`,
    /// `-1` read unsigned, hands the packet on like `TC_ACT_OK`.
    #[must_use]
    pub fn from_tc(code: u32) -> Self {
        match code {
            0 | 3 | u32::MAX => Self::Pass,
            2 => Self::Drop,
            7 => Self::Redirect,
            _ => Self::Other,
        }
    }

    /// The verdict a firewall rule's action stands for.
    #[must_use]
    pub fn from_firewall(action: u32) -> Self {
        match action {
            0 => Self::Pass,
            1 => Self::Drop,
            2 => Self::Log,
            3 => Self::Reject,
            _ => Self::Other,
        }
    }
}

/// Where a program runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceHook {
    Xdp,
    TcIngress,
    TcEgress,
}

/// One program run on the crafted packet, as the kernel handed it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRun {
    /// The program's name.
    pub program: String,
    /// Where it runs.
    pub hook: TraceHook,
    /// What it returned.
    pub retval: u32,
    /// The records it left, in the order the stages wrote them. An XDP run
    /// carries one per stage the tail calls reached.
    pub records: Vec<TraceRecord>,
}

/// What one stage did with the crafted packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageReport {
    pub stage: Stage,
    pub hook: TraceHook,
    pub verdict: Verdict,
    pub reason: Reason,
    /// The identifier of the rule that decided, as the stage numbers its
    /// rules. Absent when no rule decided.
    pub rule_id: Option<u32>,
    /// The rule's name, where the agent could name it.
    pub rule: Option<String>,
    /// What the stage adds in its own terms: a connection state, a `QoS`
    /// queue, a fast-path map.
    pub detail: Option<String>,
}

/// A verdict that holds for this packet now and not for every packet of
/// the five-tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateDependence {
    pub stage: Stage,
    /// The state the verdict depends on, in a sentence.
    pub depends_on: String,
}

/// The answer to a trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceReport {
    pub request: TraceRequest,
    /// The source address the packet was crafted from.
    pub src_ip: IpAddr,
    /// Each stage the packet crossed, in the order it crossed them.
    pub stages: Vec<StageReport>,
    /// The stage the packet stopped at, absent when it went through.
    pub stopped_at: Option<Stage>,
    /// The verdict at that stage, or `pass` when the packet went through.
    pub verdict: Verdict,
    /// Verdicts that depend on state the crafted packet does not carry.
    pub state_dependent: Vec<StateDependence>,
    /// Programs of this direction that are not loaded, so the trace could
    /// not ask them.
    pub not_loaded: Vec<String>,
}

impl StageReport {
    /// Read one record. The rule's name is left for the caller to fill in.
    #[must_use]
    pub fn from_record(record: &TraceRecord, hook: TraceHook) -> Option<Self> {
        let stage = Stage::from_code(record.stage)?;
        let reason = Reason::from_code(record.reason);
        let verdict = match stage {
            Stage::Firewall => Verdict::from_firewall(record.action),
            Stage::RateLimit | Stage::LoadBalancer => Verdict::from_xdp(record.action),
            _ => Verdict::from_tc(record.action),
        };
        let rule = (record.rule_id != NO_RULE).then_some(record.rule_id);
        let (rule_id, detail) = match stage {
            Stage::Firewall => match rule {
                Some(fast_path::LPM_SRC) => (
                    None,
                    Some("source address prefix (GeoIP country)".to_string()),
                ),
                Some(fast_path::LPM_DST) => (
                    None,
                    Some("destination address prefix (GeoIP country)".to_string()),
                ),
                Some(fast_path::HASH_5TUPLE) => (
                    Some(fast_path::HASH_5TUPLE),
                    Some("exact five-tuple fast path".to_string()),
                ),
                Some(fast_path::HASH_PORT) => (
                    Some(fast_path::HASH_PORT),
                    Some("protocol and port fast path".to_string()),
                ),
                Some(index) => (Some(index), None),
                None if reason == Reason::List => (
                    None,
                    Some("source on the overload or address set list".to_string()),
                ),
                None => (None, None),
            },
            Stage::Ids if reason == Reason::Rule => (rule, None),
            Stage::ThreatIntel if reason == Reason::List => (None, None),
            Stage::Conntrack => (None, conntrack_state(record.detail)),
            Stage::Qos if matches!(reason, Reason::Rate | Reason::Rewrite) => {
                (rule, Some(format!("queue {}", record.detail)))
            }
            _ => (None, None),
        };
        Some(Self {
            stage,
            hook,
            verdict,
            reason,
            rule_id,
            rule: None,
            detail,
        })
    }

    /// The state this verdict depends on, when it depends on one.
    #[must_use]
    pub fn state_dependence(&self) -> Option<StateDependence> {
        let depends_on = match self.reason {
            Reason::Established => {
                "a connection already tracked for this five-tuple; a first packet would be \
                 decided by the rules"
            }
            Reason::Rate => {
                "a rate or a state budget exceeded at the moment of the trace; the same packet \
                 under the limit is decided otherwise"
            }
            _ => return None,
        };
        Some(StateDependence {
            stage: self.stage,
            depends_on: depends_on.to_string(),
        })
    }
}

fn conntrack_state(state: u32) -> Option<String> {
    let name = match state {
        0 => "untracked",
        1 => "new",
        2 => "established",
        3 => "related",
        4 => "invalid",
        5 => "unreadable",
        _ => return None,
    };
    Some(format!("connection state {name}"))
}

impl TraceReport {
    /// Assemble the answer from the programs run, in order.
    ///
    /// An XDP run whose return stops the packet but whose records do not say
    /// so (a program that failed, a tail call that returned without a
    /// record) is reported at the last stage it recorded, with the verdict
    /// the kernel saw.
    #[must_use]
    pub fn assemble(
        request: TraceRequest,
        src_ip: IpAddr,
        runs: &[ProgramRun],
        not_loaded: Vec<String>,
    ) -> Self {
        let mut stages = Vec::new();
        let mut stopped_at = None;
        let mut verdict = Verdict::Pass;

        'runs: for run in runs {
            let first = stages.len();
            for record in &run.records {
                let Some(report) = StageReport::from_record(record, run.hook) else {
                    continue;
                };
                let stops = report.verdict.stops();
                let (stage, stage_verdict) = (report.stage, report.verdict);
                stages.push(report);
                if stops {
                    stopped_at = Some(stage);
                    verdict = stage_verdict;
                    break 'runs;
                }
            }
            let returned = if run.hook == TraceHook::Xdp {
                Verdict::from_xdp(run.retval)
            } else {
                Verdict::from_tc(run.retval)
            };
            if returned.stops() {
                let stage = match stages.get(first..).and_then(<[StageReport]>::last) {
                    Some(last) => last.stage,
                    None => match program_stage(&run.program) {
                        Some(stage) => {
                            stages.push(StageReport {
                                stage,
                                hook: run.hook,
                                verdict: returned,
                                reason: Reason::Unrecorded,
                                rule_id: None,
                                rule: None,
                                detail: None,
                            });
                            stage
                        }
                        None => continue,
                    },
                };
                stopped_at = Some(stage);
                verdict = returned;
                break;
            }
        }

        let state_dependent = stages
            .iter()
            .filter_map(StageReport::state_dependence)
            .collect();
        Self {
            request,
            src_ip,
            stages,
            stopped_at,
            verdict,
            state_dependent,
            not_loaded,
        }
    }
}

/// The stage a program stands for, by the name the loader gives it.
#[must_use]
pub fn program_stage(program: &str) -> Option<Stage> {
    Some(match program {
        "xdp_firewall" => Stage::Firewall,
        "xdp_ratelimit" => Stage::RateLimit,
        "xdp_loadbalancer" => Stage::LoadBalancer,
        "tc_conntrack" => Stage::Conntrack,
        "tc_scrub" => Stage::Scrub,
        "tc_ids" => Stage::Ids,
        "tc_threatintel" => Stage::ThreatIntel,
        "tc_dns" => Stage::Dns,
        "tc_nat_ingress" => Stage::NatIngress,
        "tc_nat_egress" => Stage::NatEgress,
        "tc_qos" | "tc_qos_ingress" => Stage::Qos,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn request() -> TraceRequest {
        TraceRequest {
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 0,
            dst_port: 443,
            protocol: TraceProtocol::Tcp,
            direction: TraceDirection::Ingress,
            workload: None,
        }
    }

    fn rec(stage: u8, action: u32, why: u8, rule_id: u32, detail: u32) -> TraceRecord {
        TraceRecord {
            stage,
            action,
            reason: why,
            rule_id,
            detail,
        }
    }

    fn src() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    }

    #[test]
    fn a_request_needs_a_source_one_family_and_a_port() {
        assert!(request().validate().is_ok());
        let mut no_src = request();
        no_src.src_ip = None;
        assert!(matches!(no_src.validate(), Err(TraceError::Invalid(_))));
        let mut mixed = request();
        mixed.dst_ip = "2001:db8::1".parse().unwrap();
        assert!(matches!(mixed.validate(), Err(TraceError::Invalid(_))));
        let mut no_port = request();
        no_port.dst_port = 0;
        assert!(matches!(no_port.validate(), Err(TraceError::Invalid(_))));
        let mut icmp = no_port;
        icmp.protocol = TraceProtocol::Icmp;
        assert!(icmp.validate().is_ok());
        assert_eq!(icmp.effective_src_port(), 0);
        assert_eq!(request().effective_src_port(), EPHEMERAL_PORT);
    }

    #[test]
    fn a_firewall_record_reads_the_rule_action_not_the_xdp_code() {
        let report =
            StageReport::from_record(&rec(stage::FIREWALL, 1, reason::RULE, 4, 0), TraceHook::Xdp)
                .unwrap();
        assert_eq!(report.verdict, Verdict::Drop);
        assert_eq!(report.rule_id, Some(4));
        let ratelimit = StageReport::from_record(
            &rec(stage::RATELIMIT, 2, reason::DEFAULT, NO_RULE, 0),
            TraceHook::Xdp,
        )
        .unwrap();
        assert_eq!(ratelimit.verdict, Verdict::Pass);
        assert_eq!(ratelimit.rule_id, None);
    }

    #[test]
    fn a_fast_path_hit_says_which_map_answered() {
        let geo = StageReport::from_record(
            &rec(stage::FIREWALL, 1, reason::RULE, fast_path::LPM_SRC, 0),
            TraceHook::Xdp,
        )
        .unwrap();
        assert_eq!(geo.rule_id, None);
        assert!(geo.detail.unwrap().contains("GeoIP"));
        let port = StageReport::from_record(
            &rec(stage::FIREWALL, 0, reason::RULE, fast_path::HASH_PORT, 0),
            TraceHook::Xdp,
        )
        .unwrap();
        assert_eq!(port.rule_id, Some(fast_path::HASH_PORT));
    }

    #[test]
    fn tc_stages_read_the_return_code() {
        let next = StageReport::from_record(
            &rec(stage::CONNTRACK, u32::MAX, reason::ESTABLISHED, 0, 2),
            TraceHook::TcIngress,
        )
        .unwrap();
        assert_eq!(next.verdict, Verdict::Pass);
        assert_eq!(next.detail.as_deref(), Some("connection state established"));
        assert!(next.state_dependence().is_some());
        let shot = StageReport::from_record(
            &rec(stage::IDS, 2, reason::RULE, 9, 1),
            TraceHook::TcIngress,
        )
        .unwrap();
        assert_eq!(shot.verdict, Verdict::Drop);
        assert_eq!(shot.rule_id, Some(9));
    }

    #[test]
    fn an_unknown_stage_code_is_not_a_stage() {
        assert!(StageReport::from_record(&rec(99, 0, 0, 0, 0), TraceHook::Xdp).is_none());
    }

    #[test]
    fn the_report_stops_at_the_first_stage_that_stops() {
        let runs = vec![
            ProgramRun {
                program: "xdp_firewall".into(),
                hook: TraceHook::Xdp,
                retval: 2,
                records: vec![
                    rec(stage::FIREWALL, 0, reason::DEFAULT, NO_RULE, 0),
                    rec(stage::RATELIMIT, 2, reason::DEFAULT, NO_RULE, 0),
                ],
            },
            ProgramRun {
                program: "tc_ids".into(),
                hook: TraceHook::TcIngress,
                retval: 2,
                records: vec![rec(stage::IDS, 2, reason::RULE, 3, 1)],
            },
            ProgramRun {
                program: "tc_conntrack".into(),
                hook: TraceHook::TcIngress,
                retval: u32::MAX,
                records: vec![rec(stage::CONNTRACK, u32::MAX, reason::DEFAULT, 0, 1)],
            },
        ];
        let report = TraceReport::assemble(request(), src(), &runs, vec!["tc_dns".into()]);
        assert_eq!(report.stages.len(), 3);
        assert_eq!(report.stopped_at, Some(Stage::Ids));
        assert_eq!(report.verdict, Verdict::Drop);
        assert_eq!(report.not_loaded, vec!["tc_dns".to_string()]);
        assert!(report.state_dependent.is_empty());
    }

    #[test]
    fn a_packet_that_goes_through_reports_pass() {
        let runs = vec![ProgramRun {
            program: "xdp_firewall".into(),
            hook: TraceHook::Xdp,
            retval: 2,
            records: vec![rec(stage::FIREWALL, 0, reason::ESTABLISHED, NO_RULE, 0)],
        }];
        let report = TraceReport::assemble(request(), src(), &runs, Vec::new());
        assert_eq!(report.stopped_at, None);
        assert_eq!(report.verdict, Verdict::Pass);
        assert_eq!(report.state_dependent.len(), 1);
        assert_eq!(report.state_dependent[0].stage, Stage::Firewall);
    }

    #[test]
    fn a_drop_nobody_recorded_is_reported_at_the_program_that_returned_it() {
        let runs = vec![ProgramRun {
            program: "tc_scrub".into(),
            hook: TraceHook::TcIngress,
            retval: 2,
            records: Vec::new(),
        }];
        let report = TraceReport::assemble(request(), src(), &runs, Vec::new());
        assert_eq!(report.stopped_at, Some(Stage::Scrub));
        assert_eq!(report.stages[0].reason, Reason::Unrecorded);
        assert_eq!(report.verdict, Verdict::Drop);
    }

    #[test]
    fn an_xdp_drop_after_a_passing_record_stops_at_that_stage() {
        let runs = vec![ProgramRun {
            program: "xdp_firewall".into(),
            hook: TraceHook::Xdp,
            retval: 1,
            records: vec![rec(stage::FIREWALL, 0, reason::DEFAULT, NO_RULE, 0)],
        }];
        let report = TraceReport::assemble(request(), src(), &runs, Vec::new());
        assert_eq!(report.stopped_at, Some(Stage::Firewall));
        assert_eq!(report.verdict, Verdict::Drop);
    }

    #[test]
    fn every_program_name_the_loader_uses_is_a_stage() {
        for name in [
            "xdp_firewall",
            "xdp_ratelimit",
            "xdp_loadbalancer",
            "tc_conntrack",
            "tc_scrub",
            "tc_ids",
            "tc_threatintel",
            "tc_dns",
            "tc_nat_ingress",
            "tc_nat_egress",
            "tc_qos",
            "tc_qos_ingress",
        ] {
            assert!(program_stage(name).is_some(), "{name}");
        }
    }
}
