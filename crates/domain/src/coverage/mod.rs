//! What the node agent sees of each pod, and why it misses what it misses.
//!
//! An agent on the host network sees what crosses the links it attached to.
//! A pod's traffic crosses its own host-side link when it leaves the pod, and
//! the node's uplink when it leaves the node; it crosses neither when it stays
//! on the pod's loopback. Which of those the agent holds is a fact about each
//! pod, so the verdict is computed per pod from the links actually attached,
//! never from what the configuration asked for: the two differ exactly when a
//! link kind is not understood, an attach mode leaves a kind alone or a
//! program ahead of the agent refuses it a place.

use std::cmp::Ordering;

/// The classes of traffic a pod can carry, each crossing different links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TrafficClass {
    /// To and from outside the cluster.
    NorthSouth,
    /// To and from a pod on another node.
    EastWestAcrossNodes,
    /// To and from a pod on this node.
    EastWestOnNode,
    /// Inside the pod, between its own containers.
    Loopback,
}

impl TrafficClass {
    /// Every class, in the order a verdict lists them.
    pub const ALL: [Self; 4] = [
        Self::NorthSouth,
        Self::EastWestAcrossNodes,
        Self::EastWestOnNode,
        Self::Loopback,
    ];

    /// The word the API and the CLI use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NorthSouth => "north_south",
            Self::EastWestAcrossNodes => "east_west_across_nodes",
            Self::EastWestOnNode => "east_west_on_node",
            Self::Loopback => "loopback",
        }
    }
}

/// Why a link of a pod carries no part of the agent's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRefusal {
    /// A link kind the agent has no rule for.
    UnknownKind(String),
    /// The configured attach mode leaves links of this kind alone.
    AttachMode(String),
    /// Some programs went on and others were refused, by the kernel or by a
    /// program ahead of the agent on the same hook.
    ProgramsRefused {
        /// Programs that went on.
        attached: u32,
        /// Programs the agent tried.
        of: u32,
    },
}

/// What became of one link a workload brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkAttachment {
    /// Every program of the chain is on the link.
    Attached,
    /// The chain is not, or not all of it is.
    Refused(LinkRefusal),
}

/// One link on the host side of a workload, as the link watcher left it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadLink {
    /// Kernel interface index.
    pub ifindex: u32,
    /// Interface name in the host namespace.
    pub name: String,
    /// `veth`, `netkit`, `macvlan`, `ipvlan`, `bridge-member`, or the kernel's
    /// own word for a kind the agent does not understand.
    pub kind: String,
    /// Whether the chain is on it.
    pub attachment: LinkAttachment,
    /// The pod whose namespace the link leads into, when its owner's cgroup
    /// names one.
    pub pod_uid: Option<String>,
}

/// A pod scheduled on this node, as the pod inventory reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodSubject {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    /// The pod shares the node's network namespace and brings no link.
    pub host_network: bool,
}

/// What the node itself contributes, whatever the pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NodeView {
    /// The agent's chain is on the node's configured interfaces.
    pub uplinks_attached: bool,
    /// The node carries an encapsulating device (VXLAN, Geneve, `WireGuard`,
    /// IP-in-IP, GRE): traffic between nodes may cross the uplink inside an
    /// outer header the chain reads instead of the pod's.
    pub encapsulated: bool,
}

/// Why a class of a pod's traffic is not observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GapReason {
    /// Loopback inside the pod never crosses a host link.
    LoopbackStaysInPod,
    /// A host-network pod has no link of its own, and traffic to a pod on
    /// the same node stays on the host's own stack.
    HostNetworkStaysOnHost,
    /// No link leading into this pod was found on the host.
    NoLinkFound,
    /// The pod's link carries no chain, for this reason.
    LinkRefused(LinkRefusal),
    /// The pod's link is not attached and the node's uplinks are not either.
    NoUplinkAttached,
    /// Only the uplink carries it, and the node encapsulates traffic between
    /// nodes, so the chain reads the outer header.
    EncapsulatedOnUplink,
}

impl GapReason {
    /// A stable code a screen keys its translation on.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::LoopbackStaysInPod => "loopback_stays_in_pod",
            Self::HostNetworkStaysOnHost => "host_network_stays_on_host",
            Self::NoLinkFound => "no_link_found",
            Self::LinkRefused(LinkRefusal::UnknownKind(_)) => "link_kind_unknown",
            Self::LinkRefused(LinkRefusal::AttachMode(_)) => "attach_mode_skips_kind",
            Self::LinkRefused(LinkRefusal::ProgramsRefused { .. }) => "programs_refused",
            Self::NoUplinkAttached => "no_uplink_attached",
            Self::EncapsulatedOnUplink => "encapsulated_on_uplink",
        }
    }

    /// The reason in a sentence, for the CLI and the logs.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::LoopbackStaysInPod => {
                "loopback inside the pod never crosses a link on the host".to_string()
            }
            Self::HostNetworkStaysOnHost => "a host-network pod has no link of its own, and \
                traffic to a pod on this node stays on the host's stack"
                .to_string(),
            Self::NoLinkFound => "no link leading into this pod was found on the host".to_string(),
            Self::LinkRefused(LinkRefusal::UnknownKind(kind)) => {
                format!("the pod's link is of kind {kind}, which the agent does not attach to")
            }
            Self::LinkRefused(LinkRefusal::AttachMode(mode)) => {
                format!("attach mode {mode} leaves the pod's link kind alone")
            }
            Self::LinkRefused(LinkRefusal::ProgramsRefused { attached, of }) => format!(
                "only {attached} of {of} programs went on the pod's link, the rest were refused"
            ),
            Self::NoUplinkAttached => {
                "the pod's link carries no chain and neither do the node's uplinks".to_string()
            }
            Self::EncapsulatedOnUplink => "only the uplink carries it, inside an outer header \
                the node adds between nodes"
                .to_string(),
        }
    }
}

/// Whether one class of a pod's traffic is observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassCoverage {
    pub class: TrafficClass,
    pub observed: bool,
    /// Present exactly when `observed` is false.
    pub gap: Option<GapReason>,
}

/// How much of a pod the agent sees, loopback aside: loopback is never seen
/// by a node agent, so counting it would mark every pod partial and tell
/// nobody anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoverageLevel {
    /// No class crossing a host link is observed.
    None,
    /// Some are.
    Partial,
    /// Every class crossing a host link is observed.
    Full,
}

impl CoverageLevel {
    /// The word the API and the CLI use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Partial => "partial",
            Self::Full => "full",
        }
    }
}

/// One link of a pod, as the verdict reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceCoverage {
    pub name: String,
    pub kind: String,
    pub attached: bool,
    /// Present exactly when `attached` is false.
    pub refusal: Option<LinkRefusal>,
}

/// The verdict for one pod.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodCoverage {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    pub host_network: bool,
    pub level: CoverageLevel,
    pub interfaces: Vec<InterfaceCoverage>,
    pub classes: Vec<ClassCoverage>,
}

impl PodCoverage {
    /// Uncovered pods first, then partial, then full; by namespace and name
    /// within each.
    #[must_use]
    pub fn worst_first(a: &Self, b: &Self) -> Ordering {
        a.level
            .cmp(&b.level)
            .then_with(|| a.namespace.cmp(&b.namespace))
            .then_with(|| a.name.cmp(&b.name))
    }
}

fn observed(class: TrafficClass) -> ClassCoverage {
    ClassCoverage {
        class,
        observed: true,
        gap: None,
    }
}

fn missed(class: TrafficClass, gap: GapReason) -> ClassCoverage {
    ClassCoverage {
        class,
        observed: false,
        gap: Some(gap),
    }
}

/// What the uplink alone gives a class leaving the node.
fn via_uplink(class: TrafficClass, node: NodeView, fallback: &GapReason) -> ClassCoverage {
    match (node.uplinks_attached, class) {
        (false, _) => missed(
            class,
            if matches!(fallback, GapReason::HostNetworkStaysOnHost) {
                GapReason::NoUplinkAttached
            } else {
                fallback.clone()
            },
        ),
        (true, TrafficClass::EastWestAcrossNodes) if node.encapsulated => {
            missed(class, GapReason::EncapsulatedOnUplink)
        }
        (true, _) => observed(class),
    }
}

/// The verdict for `pod`, given the links found leading into it.
#[must_use]
pub fn pod_verdict(pod: &PodSubject, links: &[&WorkloadLink], node: NodeView) -> PodCoverage {
    let interfaces: Vec<InterfaceCoverage> = links
        .iter()
        .map(|link| InterfaceCoverage {
            name: link.name.clone(),
            kind: link.kind.clone(),
            attached: link.attachment == LinkAttachment::Attached,
            refusal: match &link.attachment {
                LinkAttachment::Attached => None,
                LinkAttachment::Refused(refusal) => Some(refusal.clone()),
            },
        })
        .collect();
    let own_link = interfaces.iter().any(|i| i.attached);
    let classes: Vec<ClassCoverage> = if own_link {
        TrafficClass::ALL
            .into_iter()
            .map(|class| match class {
                TrafficClass::Loopback => missed(class, GapReason::LoopbackStaysInPod),
                _ => observed(class),
            })
            .collect()
    } else {
        let link_gap = if pod.host_network {
            GapReason::HostNetworkStaysOnHost
        } else {
            interfaces
                .iter()
                .find_map(|i| i.refusal.clone())
                .map_or(GapReason::NoLinkFound, GapReason::LinkRefused)
        };
        TrafficClass::ALL
            .into_iter()
            .map(|class| match class {
                TrafficClass::Loopback => missed(class, GapReason::LoopbackStaysInPod),
                TrafficClass::EastWestOnNode => missed(class, link_gap.clone()),
                _ => via_uplink(class, node, &link_gap),
            })
            .collect()
    };
    let seen = classes
        .iter()
        .filter(|c| c.class != TrafficClass::Loopback && c.observed)
        .count();
    let level = match seen {
        0 => CoverageLevel::None,
        3 => CoverageLevel::Full,
        _ => CoverageLevel::Partial,
    };
    PodCoverage {
        uid: pod.uid.clone(),
        name: pod.name.clone(),
        namespace: pod.namespace.clone(),
        host_network: pod.host_network,
        level,
        interfaces,
        classes,
    }
}

/// The verdict for every pod in `pods`, worst first.
#[must_use]
pub fn node_verdicts(
    pods: &[PodSubject],
    links: &[WorkloadLink],
    node: NodeView,
) -> Vec<PodCoverage> {
    let mut verdicts: Vec<PodCoverage> = pods
        .iter()
        .map(|pod| {
            let mine: Vec<&WorkloadLink> = links
                .iter()
                .filter(|l| l.pod_uid.as_deref() == Some(pod.uid.as_str()))
                .collect();
            pod_verdict(pod, &mine, node)
        })
        .collect();
    verdicts.sort_by(PodCoverage::worst_first);
    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pod(uid: &str, host_network: bool) -> PodSubject {
        PodSubject {
            uid: uid.into(),
            name: format!("pod-{uid}"),
            namespace: "shop".into(),
            host_network,
        }
    }

    fn link(uid: &str, attachment: LinkAttachment) -> WorkloadLink {
        WorkloadLink {
            ifindex: 7,
            name: "veth1".into(),
            kind: "veth".into(),
            attachment,
            pod_uid: Some(uid.into()),
        }
    }

    fn gap_of(v: &PodCoverage, class: TrafficClass) -> Option<&'static str> {
        v.classes
            .iter()
            .find(|c| c.class == class)
            .and_then(|c| c.gap.as_ref().map(GapReason::code))
    }

    const NODE: NodeView = NodeView {
        uplinks_attached: true,
        encapsulated: false,
    };

    #[test]
    fn an_attached_link_sees_everything_but_loopback() {
        let l = link("a", LinkAttachment::Attached);
        let v = pod_verdict(&pod("a", false), &[&l], NODE);
        assert_eq!(v.level, CoverageLevel::Full);
        assert_eq!(
            gap_of(&v, TrafficClass::Loopback),
            Some("loopback_stays_in_pod")
        );
        assert!(v.classes.iter().all(|c| c.observed == c.gap.is_none()));
    }

    #[test]
    fn a_refused_link_leaves_the_uplink_and_says_why_for_the_node() {
        let l = link(
            "a",
            LinkAttachment::Refused(LinkRefusal::UnknownKind("tun".into())),
        );
        let v = pod_verdict(&pod("a", false), &[&l], NODE);
        assert_eq!(v.level, CoverageLevel::Partial);
        assert_eq!(gap_of(&v, TrafficClass::NorthSouth), None);
        assert_eq!(gap_of(&v, TrafficClass::EastWestAcrossNodes), None);
        assert_eq!(
            gap_of(&v, TrafficClass::EastWestOnNode),
            Some("link_kind_unknown")
        );
        assert!(!v.interfaces[0].attached);
    }

    #[test]
    fn an_overlay_hides_traffic_between_nodes_from_the_uplink() {
        let v = pod_verdict(
            &pod("a", false),
            &[],
            NodeView {
                uplinks_attached: true,
                encapsulated: true,
            },
        );
        assert_eq!(
            gap_of(&v, TrafficClass::EastWestAcrossNodes),
            Some("encapsulated_on_uplink")
        );
        assert_eq!(
            gap_of(&v, TrafficClass::EastWestOnNode),
            Some("no_link_found")
        );
    }

    #[test]
    fn nothing_attached_anywhere_is_no_coverage() {
        let l = link(
            "a",
            LinkAttachment::Refused(LinkRefusal::AttachMode("netkit".into())),
        );
        let v = pod_verdict(&pod("a", false), &[&l], NodeView::default());
        assert_eq!(v.level, CoverageLevel::None);
        assert_eq!(
            gap_of(&v, TrafficClass::NorthSouth),
            Some("attach_mode_skips_kind")
        );
    }

    #[test]
    fn a_host_network_pod_is_seen_on_the_uplink_only() {
        let v = pod_verdict(&pod("h", true), &[], NODE);
        assert_eq!(v.level, CoverageLevel::Partial);
        assert_eq!(
            gap_of(&v, TrafficClass::EastWestOnNode),
            Some("host_network_stays_on_host")
        );
        let off = pod_verdict(&pod("h", true), &[], NodeView::default());
        assert_eq!(
            gap_of(&off, TrafficClass::NorthSouth),
            Some("no_uplink_attached")
        );
    }

    #[test]
    fn verdicts_list_the_uncovered_first() {
        let links = vec![link("b", LinkAttachment::Attached)];
        let pods = vec![pod("b", false), pod("a", false)];
        let v = node_verdicts(&pods, &links, NodeView::default());
        assert_eq!(v[0].uid, "a");
        assert_eq!(v[0].level, CoverageLevel::None);
        assert_eq!(v[1].level, CoverageLevel::Full);
    }

    #[test]
    fn every_reason_has_a_sentence_and_a_code() {
        for gap in [
            GapReason::LoopbackStaysInPod,
            GapReason::HostNetworkStaysOnHost,
            GapReason::NoLinkFound,
            GapReason::LinkRefused(LinkRefusal::ProgramsRefused { attached: 3, of: 7 }),
            GapReason::NoUplinkAttached,
            GapReason::EncapsulatedOnUplink,
        ] {
            assert!(!gap.describe().is_empty());
            assert!(!gap.code().contains(' '));
        }
    }
}
