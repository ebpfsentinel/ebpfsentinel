//! A port the kernel will not let anybody bind and no listing admits to.
//!
//! The listing is read twice over, from `/proc/net/{tcp,tcp6,udp,udp6}` and
//! from `sock_diag`, in each network namespace the scanner can enter. Every
//! port of the probed set is then bound once over each transport and family,
//! with no reuse option, and the bind is released at once. A refusal with
//! `EADDRINUSE` means some socket holds the port; a socket either reading
//! lists explains it. A refusal neither reading explains is read again: the
//! listing is taken a second time and the refused ports are probed a second
//! time, and only a port refused both times and listed neither time is
//! hidden.
//!
//! What explains a refusal is counted by its kind, so a clean result says
//! how it was reached:
//!
//! - a listener, including every member of an `SO_REUSEPORT` group, since
//!   the probe sets no reuse option and each member is listed;
//! - a TCP socket in `TIME_WAIT`, which holds its local port until it
//!   expires and refuses a bind that sets no `SO_REUSEADDR`;
//! - any other socket bound to the port, such as an outgoing connection;
//! - a refusal the second probe did not repeat, or a port the second listing
//!   showed, which is a socket that opened or closed between the readings.
//!
//! A namespace the scanner could not enter is counted and named, and the
//! ports it could not probe at all are counted too, so a sweep that was not
//! complete never reads as clean.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component the alert is raised under.
pub const HIDDEN_PORT_COMPONENT: &str = "hidden_port";

/// The rule id of the alert raised for a hidden port.
pub const HIDDEN_PORT_RULE_ID: &str = "port-hidden";

/// `TCP_LISTEN` in the kernel's state numbering.
const TCP_LISTEN: u8 = 10;
/// `TCP_TIME_WAIT` in the kernel's state numbering.
const TCP_TIME_WAIT: u8 = 6;

/// The transport a port belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// The name a rule and an operator write.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The address family a probe was bound in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortFamily {
    V4,
    V6,
}

impl PortFamily {
    /// The wildcard address the probe binds.
    #[must_use]
    pub fn wildcard(self) -> &'static str {
        match self {
            Self::V4 => "0.0.0.0",
            Self::V6 => "::",
        }
    }
}

/// Which reading listed a socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Listing {
    /// `/proc/net/tcp`, `tcp6`, `udp` or `udp6`.
    Proc,
    /// A `sock_diag` dump.
    SockDiag,
}

/// One socket a listing showed, reduced to what explains a refused bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListedPort {
    pub transport: Transport,
    /// The local port, in host order.
    pub port: u16,
    /// The kernel's state number for the socket.
    pub state: u8,
    pub listing: Listing,
}

/// One bind the probe made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PortProbe {
    pub transport: Transport,
    pub family: PortFamily,
    pub port: u16,
}

/// What the scanner read inside one network namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortReading {
    /// Both listings, taken before the first probe.
    pub first_listing: Vec<ListedPort>,
    /// Both listings, taken again before the second probe.
    pub second_listing: Vec<ListedPort>,
    /// How many binds the first pass attempted.
    pub probed: u32,
    /// Binds the kernel refused for another reason than the port being in
    /// use, a missing privilege most often, so the port was not asked.
    pub unprobed: u32,
    /// The binds the first pass saw refused as in use.
    pub refused_first: Vec<PortProbe>,
    /// The first pass's refusals the second pass saw refused again.
    pub refused_second: Vec<PortProbe>,
}

/// One network namespace and what came of reading it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespacePorts {
    /// The namespace's inode.
    pub netns: u64,
    /// Whether it is the host's.
    pub host_netns: bool,
    /// The reading, or why the namespace could not be entered.
    pub reading: Result<PortReading, String>,
}

/// A port the kernel holds and no listing shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HiddenPort {
    pub netns: u64,
    pub host_netns: bool,
    pub transport: Transport,
    pub family: PortFamily,
    pub port: u16,
}

impl HiddenPort {
    /// The rule id of the alert it raises.
    #[must_use]
    pub fn rule_id() -> RuleId {
        RuleId(HIDDEN_PORT_RULE_ID.to_string())
    }

    /// A port hidden from the listings is a rootkit concealing its own
    /// channel, which is concealment of an artifact.
    #[must_use]
    pub fn mitre() -> MitreAttackInfo {
        MitreAttackInfo {
            technique_id: "T1014".to_string(),
            technique_name: "Rootkit".to_string(),
            tactic: "defense-evasion".to_string(),
        }
    }

    /// The alert's sentence, naming the ordinary causes before the
    /// malicious one so the reader weighs them in that order.
    #[must_use]
    pub fn message(&self) -> String {
        let namespace = if self.host_netns {
            "the host network namespace".to_string()
        } else {
            format!("network namespace {}", self.netns)
        };
        format!(
            "{} port {} on {} in {namespace} refused a bind twice and appeared in neither \
             /proc/net nor sock_diag; ordinary causes are a namespace torn down between the \
             readings or a listing the scanner could not read, otherwise the kernel is \
             hiding a socket from its own listings",
            self.transport,
            self.port,
            self.family.wildcard(),
        )
    }
}

/// How a sweep reached its result.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSweepCounts {
    /// Network namespaces found.
    pub namespaces: u32,
    /// Namespaces the scanner could not enter, so nothing in them was asked.
    pub unreachable_namespaces: u32,
    /// Binds attempted in the first pass.
    pub probed: u32,
    /// Binds refused for another reason than the port being in use.
    pub unprobed: u32,
    /// Binds refused as in use in the first pass.
    pub refused: u32,
    /// Refusals a listed listener explains.
    pub explained_by_listener: u32,
    /// Refusals only a TCP socket in `TIME_WAIT` explains.
    pub explained_by_time_wait: u32,
    /// Refusals only another bound socket explains.
    pub explained_by_other_socket: u32,
    /// Refusals the second probe did not repeat, or that the second listing
    /// explained: a socket that came or went between the readings.
    pub unconfirmed: u32,
    /// Ports reported hidden.
    pub hidden: u32,
}

/// The result of one sweep over every namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSweep {
    pub hidden: Vec<HiddenPort>,
    pub counts: PortSweepCounts,
    /// The namespaces that could not be entered, with the reason.
    pub unreachable: Vec<(u64, String)>,
}

/// The strongest explanation the listing gives for a port on a transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Explanation {
    Other,
    TimeWait,
    Listener,
}

fn explanation(entry: ListedPort) -> Explanation {
    match entry.transport {
        // A bound UDP socket is what a UDP bind conflicts with, connected or
        // not.
        Transport::Udp => Explanation::Listener,
        Transport::Tcp => match entry.state {
            TCP_LISTEN => Explanation::Listener,
            TCP_TIME_WAIT => Explanation::TimeWait,
            _ => Explanation::Other,
        },
    }
}

/// The strongest explanation each `(transport, port)` has in `listing`.
/// Both families explain each other: a dual-stack listener on `::` refuses a
/// bind on `0.0.0.0` and is listed only under `tcp6`.
fn explanations(listing: &[ListedPort]) -> BTreeMap<(Transport, u16), Explanation> {
    let mut out = BTreeMap::new();
    for entry in listing {
        let kind = explanation(*entry);
        out.entry((entry.transport, entry.port))
            .and_modify(|e: &mut Explanation| *e = (*e).max(kind))
            .or_insert(kind);
    }
    out
}

/// Compare every namespace's listings with its probes and report the ports
/// held and not listed, each counted cause excluded.
#[must_use]
pub fn sweep_ports(namespaces: &[NamespacePorts]) -> PortSweep {
    let mut sweep = PortSweep::default();
    for namespace in namespaces {
        sweep.counts.namespaces += 1;
        let reading = match &namespace.reading {
            Ok(reading) => reading,
            Err(reason) => {
                sweep.counts.unreachable_namespaces += 1;
                sweep.unreachable.push((namespace.netns, reason.clone()));
                continue;
            }
        };
        sweep.counts.probed += reading.probed;
        sweep.counts.unprobed += reading.unprobed;
        let first = explanations(&reading.first_listing);
        let second = explanations(&reading.second_listing);
        let confirmed: BTreeSet<PortProbe> = reading.refused_second.iter().copied().collect();
        let refused: BTreeSet<PortProbe> = reading.refused_first.iter().copied().collect();
        for probe in refused {
            sweep.counts.refused += 1;
            match first.get(&(probe.transport, probe.port)) {
                Some(Explanation::Listener) => sweep.counts.explained_by_listener += 1,
                Some(Explanation::TimeWait) => sweep.counts.explained_by_time_wait += 1,
                Some(Explanation::Other) => sweep.counts.explained_by_other_socket += 1,
                None if !confirmed.contains(&probe)
                    || second.contains_key(&(probe.transport, probe.port)) =>
                {
                    sweep.counts.unconfirmed += 1;
                }
                None => {
                    sweep.counts.hidden += 1;
                    sweep.hidden.push(HiddenPort {
                        netns: namespace.netns,
                        host_netns: namespace.host_netns,
                        transport: probe.transport,
                        family: probe.family,
                        port: probe.port,
                    });
                }
            }
        }
    }
    sweep
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed(transport: Transport, port: u16, state: u8) -> ListedPort {
        ListedPort {
            transport,
            port,
            state,
            listing: Listing::Proc,
        }
    }

    fn probe(transport: Transport, family: PortFamily, port: u16) -> PortProbe {
        PortProbe {
            transport,
            family,
            port,
        }
    }

    fn namespace(reading: PortReading) -> NamespacePorts {
        NamespacePorts {
            netns: 4_026_531_840,
            host_netns: true,
            reading: Ok(reading),
        }
    }

    /// A reader that omits port 31337 while the bind probe refuses it, on
    /// both passes: the shape a rootkit filtering `/proc/net` leaves.
    fn concealed() -> PortReading {
        let tcp = |port| probe(Transport::Tcp, PortFamily::V4, port);
        PortReading {
            first_listing: vec![listed(Transport::Tcp, 22, TCP_LISTEN)],
            second_listing: vec![listed(Transport::Tcp, 22, TCP_LISTEN)],
            probed: 4096,
            unprobed: 0,
            refused_first: vec![tcp(22), tcp(31337)],
            refused_second: vec![tcp(31337)],
        }
    }

    #[test]
    fn a_port_refused_twice_and_listed_nowhere_is_hidden() {
        let sweep = sweep_ports(&[namespace(concealed())]);
        assert_eq!(sweep.hidden.len(), 1);
        let hidden = &sweep.hidden[0];
        assert_eq!(
            (hidden.transport, hidden.family, hidden.port),
            (Transport::Tcp, PortFamily::V4, 31337)
        );
        assert_eq!(sweep.counts.refused, 2);
        assert_eq!(sweep.counts.explained_by_listener, 1);
        assert_eq!(sweep.counts.hidden, 1);
        assert!(hidden.message().contains("tcp port 31337 on 0.0.0.0"));
    }

    #[test]
    fn a_listing_from_sock_diag_alone_explains_the_refusal() {
        let mut reading = concealed();
        reading.first_listing.push(ListedPort {
            listing: Listing::SockDiag,
            ..listed(Transport::Tcp, 31337, TCP_LISTEN)
        });
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.explained_by_listener, 2);
    }

    #[test]
    fn a_reuseport_group_is_a_listed_listener() {
        // Four members of one SO_REUSEPORT group, each listed: the probe sets
        // no reuse option, so the group refuses it and explains the refusal.
        let mut reading = concealed();
        reading.first_listing = (0..4)
            .map(|_| listed(Transport::Tcp, 31337, TCP_LISTEN))
            .collect();
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.explained_by_listener, 1);
        assert_eq!(sweep.counts.unconfirmed, 1, "port 22 left the listing");
    }

    #[test]
    fn a_port_held_only_by_time_wait_is_excluded_and_counted() {
        let mut reading = concealed();
        reading
            .first_listing
            .push(listed(Transport::Tcp, 31337, TCP_TIME_WAIT));
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.explained_by_time_wait, 1);
    }

    #[test]
    fn an_outgoing_connection_on_the_port_explains_it() {
        let mut reading = concealed();
        // TCP_ESTABLISHED: a client whose local port is the probed one.
        reading.first_listing.push(listed(Transport::Tcp, 31337, 1));
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.explained_by_other_socket, 1);
    }

    #[test]
    fn a_listener_outranks_time_wait_on_the_same_port() {
        let mut reading = concealed();
        reading
            .first_listing
            .push(listed(Transport::Tcp, 31337, TCP_TIME_WAIT));
        reading
            .first_listing
            .push(listed(Transport::Tcp, 31337, TCP_LISTEN));
        let sweep = sweep_ports(&[namespace(reading)]);
        assert_eq!(sweep.counts.explained_by_listener, 2);
        assert_eq!(sweep.counts.explained_by_time_wait, 0);
    }

    #[test]
    fn a_dual_stack_listener_explains_the_other_family() {
        let mut reading = concealed();
        // Listed under tcp6 only, refusing the IPv4 probe as well.
        reading
            .first_listing
            .push(listed(Transport::Tcp, 31337, TCP_LISTEN));
        reading
            .refused_first
            .push(probe(Transport::Tcp, PortFamily::V6, 31337));
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
    }

    #[test]
    fn a_refusal_the_second_probe_does_not_repeat_is_unconfirmed() {
        let mut reading = concealed();
        reading.refused_second.clear();
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.unconfirmed, 1);
    }

    #[test]
    fn a_socket_that_opened_between_the_readings_is_unconfirmed() {
        let mut reading = concealed();
        reading
            .second_listing
            .push(listed(Transport::Tcp, 31337, TCP_LISTEN));
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.unconfirmed, 1);
    }

    #[test]
    fn a_udp_port_is_explained_by_any_bound_socket() {
        let udp = probe(Transport::Udp, PortFamily::V4, 5353);
        let reading = PortReading {
            first_listing: vec![listed(Transport::Udp, 5353, 1)],
            refused_first: vec![udp],
            refused_second: vec![udp],
            ..PortReading::default()
        };
        let sweep = sweep_ports(&[namespace(reading)]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.explained_by_listener, 1);
    }

    #[test]
    fn a_tcp_listing_does_not_explain_a_udp_refusal() {
        let udp = probe(Transport::Udp, PortFamily::V4, 53);
        let reading = PortReading {
            first_listing: vec![listed(Transport::Tcp, 53, TCP_LISTEN)],
            refused_first: vec![udp],
            refused_second: vec![udp],
            ..PortReading::default()
        };
        let sweep = sweep_ports(&[namespace(reading)]);
        assert_eq!(sweep.hidden.len(), 1);
        assert_eq!(sweep.hidden[0].transport, Transport::Udp);
    }

    #[test]
    fn an_unreachable_namespace_is_counted_and_named_not_read_as_clean() {
        let sweep = sweep_ports(&[
            namespace(PortReading::default()),
            NamespacePorts {
                netns: 4_026_532_999,
                host_netns: false,
                reading: Err("setns refused: operation not permitted".to_string()),
            },
        ]);
        assert!(sweep.hidden.is_empty());
        assert_eq!(sweep.counts.namespaces, 2);
        assert_eq!(sweep.counts.unreachable_namespaces, 1);
        assert_eq!(sweep.unreachable[0].0, 4_026_532_999);
    }

    #[test]
    fn unprobed_ports_and_probes_are_summed_across_namespaces() {
        let reading = PortReading {
            probed: 100,
            unprobed: 3,
            ..PortReading::default()
        };
        let sweep = sweep_ports(&[namespace(reading.clone()), namespace(reading)]);
        assert_eq!(sweep.counts.probed, 200);
        assert_eq!(sweep.counts.unprobed, 6);
    }

    #[test]
    fn a_container_namespace_is_named_by_its_inode() {
        let mut ns = namespace(concealed());
        ns.host_netns = false;
        ns.netns = 4_026_532_777;
        let sweep = sweep_ports(&[ns]);
        assert!(
            sweep.hidden[0]
                .message()
                .contains("network namespace 4026532777")
        );
    }
}
