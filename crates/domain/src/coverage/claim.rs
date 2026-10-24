//! Which agent inspects a pod's traffic when a node agent and a pod profile
//! agent both could.
//!
//! The two agents see a pod from opposite sides of one link: the pod agent on
//! the pod's own interfaces, the node agent on the host side. A packet of the
//! pod crosses both, so left alone it is alerted, recorded and counted twice.
//! Telling one sighting from the other per packet is not possible on the host
//! side: a forwarded packet carries no socket there, so the socket cookie that
//! would key it is zero, and the namespace it came from is not in the packet
//! either. The decision is therefore taken per link, before any packet: the
//! link leads into one pod's network namespace, and whichever agent holds that
//! namespace is the one that reads it.
//!
//! The rule is that the pod agent wins, for exactly as long as it says so. It
//! sees everything the node agent would on that link plus the pod's loopback,
//! so standing the node agent back loses nothing. Its word is a claim naming
//! the namespace it attached in, refreshed on every pass; a claim that names
//! another namespace (the pod's sandbox was recreated) or that stopped being
//! refreshed (the pod agent went) is no claim, and the node agent takes the
//! link back. A lapsed claim costs a window where nobody reads the link, which
//! is bounded by [`CLAIM_LAPSES_AFTER_SECS`]; a claim the node agent has not
//! read yet costs a window where both do, which is what the overlap metric
//! counts.

/// How long a claim holds without being refreshed: three passes of a pod
/// agent reconciling every fifteen seconds, so one slow pass does not hand
/// the link back.
pub const CLAIM_LAPSES_AFTER_SECS: u64 = 45;

/// A pod profile agent's statement that its chain is inside one pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodClaim {
    /// Inode of the network namespace the chain was attached in.
    pub netns: u64,
    /// When the chain went on, in seconds since the Unix epoch.
    pub since_secs: u64,
    /// When the claim was last refreshed, in seconds since the Unix epoch.
    pub refreshed_secs: u64,
}

/// The agent that reads a pod's link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inspector {
    /// The node agent, on the host side of the link.
    Node,
    /// The pod profile agent, inside the pod.
    Pod,
}

/// Who reads the link leading into namespace `link_netns`, given the claim
/// held for the pod it belongs to, at `now_secs`.
///
/// A link whose namespace is not known yet is the node agent's: standing back
/// on a guess would leave a pod nobody reads.
#[must_use]
pub fn link_inspector(
    claim: Option<&PodClaim>,
    link_netns: Option<u64>,
    now_secs: u64,
) -> Inspector {
    match (claim, link_netns) {
        (Some(claim), Some(netns))
            if claim.netns == netns
                && now_secs.saturating_sub(claim.refreshed_secs) <= CLAIM_LAPSES_AFTER_SECS =>
        {
            Inspector::Pod
        }
        _ => Inspector::Node,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLAIM: PodClaim = PodClaim {
        netns: 4_026_532_001,
        since_secs: 1_000,
        refreshed_secs: 1_000,
    };

    #[test]
    fn a_fresh_claim_on_the_same_namespace_hands_the_link_to_the_pod_agent() {
        assert_eq!(
            link_inspector(Some(&CLAIM), Some(CLAIM.netns), 1_010),
            Inspector::Pod
        );
        assert_eq!(
            link_inspector(
                Some(&CLAIM),
                Some(CLAIM.netns),
                1_000 + CLAIM_LAPSES_AFTER_SECS
            ),
            Inspector::Pod
        );
    }

    #[test]
    fn no_claim_leaves_the_link_to_the_node_agent() {
        assert_eq!(link_inspector(None, Some(1), 0), Inspector::Node);
    }

    #[test]
    fn a_claim_on_another_namespace_is_a_recreated_sandbox_and_no_claim() {
        assert_eq!(
            link_inspector(Some(&CLAIM), Some(CLAIM.netns + 1), 1_010),
            Inspector::Node
        );
    }

    #[test]
    fn a_claim_nobody_refreshed_lapses_back_to_the_node_agent() {
        assert_eq!(
            link_inspector(
                Some(&CLAIM),
                Some(CLAIM.netns),
                1_001 + CLAIM_LAPSES_AFTER_SECS
            ),
            Inspector::Node
        );
    }

    #[test]
    fn a_link_whose_namespace_is_unknown_stays_with_the_node_agent() {
        assert_eq!(link_inspector(Some(&CLAIM), None, 1_010), Inspector::Node);
    }

    #[test]
    fn a_claim_from_a_clock_ahead_still_holds() {
        assert_eq!(
            link_inspector(Some(&CLAIM), Some(CLAIM.netns), 900),
            Inspector::Pod
        );
    }
}
