use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// Where on the network path a program runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkHook {
    /// In the driver, before the kernel builds a socket buffer.
    Xdp,
    /// A legacy `tc` classifier on ingress.
    TcIngress,
    /// A legacy `tc` classifier on egress.
    TcEgress,
    /// A TCX program on ingress.
    TcxIngress,
    /// A TCX program on egress.
    TcxEgress,
    /// A netkit device's primary side.
    NetkitPrimary,
    /// A netkit device's peer side, inside a pod.
    NetkitPeer,
    /// A cgroup hook on sockets or on the traffic of a cgroup.
    Cgroup,
    /// A netfilter hook.
    Netfilter,
    /// A network namespace's flow dissector or socket lookup.
    Netns,
    /// A program of a network type found on no hook this agent can read: a
    /// legacy cgroup attachment, a socket filter, a tail-call target, or a
    /// program loaded and not attached.
    Unplaced,
}

impl NetworkHook {
    /// The hook behind its slug, `Unplaced` for one this agent does not name.
    #[must_use]
    pub fn from_slug(slug: &str) -> Self {
        match slug {
            "xdp" => Self::Xdp,
            "tc_ingress" => Self::TcIngress,
            "tc_egress" => Self::TcEgress,
            "tcx_ingress" => Self::TcxIngress,
            "tcx_egress" => Self::TcxEgress,
            "netkit_primary" => Self::NetkitPrimary,
            "netkit_peer" => Self::NetkitPeer,
            "cgroup" => Self::Cgroup,
            "netfilter" => Self::Netfilter,
            "netns" => Self::Netns,
            _ => Self::Unplaced,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xdp => "xdp",
            Self::TcIngress => "tc_ingress",
            Self::TcEgress => "tc_egress",
            Self::TcxIngress => "tcx_ingress",
            Self::TcxEgress => "tcx_egress",
            Self::NetkitPrimary => "netkit_primary",
            Self::NetkitPeer => "netkit_peer",
            Self::Cgroup => "cgroup",
            Self::Netfilter => "netfilter",
            Self::Netns => "netns",
            Self::Unplaced => "unplaced",
        }
    }
}

/// One eBPF program on the network path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkProgram {
    pub prog_id: u32,
    /// The program type, as the kernel names it.
    pub prog_type: String,
    /// The name the loader gave it, at most fifteen bytes.
    pub name: String,
    /// The hash of its instructions, in hex: two loads of the same program
    /// share it.
    pub tag: String,
    /// The link attaching it, absent for a legacy attachment or none.
    pub link_id: Option<u32>,
    pub hook: NetworkHook,
    /// The interface index the attachment names.
    pub ifindex: Option<u32>,
    /// The interface's name, only where the host's own interface of that
    /// index carries the program: an index from a pod's namespace names a
    /// different interface on the host.
    pub interface: Option<String>,
    /// Where it runs among the programs on the same hook of the same host
    /// interface, the first being `0`, for the hooks that run several in
    /// turn.
    pub position: Option<u32>,
    /// The cgroup a cgroup link sits on, by its id.
    pub cgroup_id: Option<u64>,
    /// What the hook does not say alone: the cgroup attach point, the
    /// netfilter family, hook and priority, the namespace hook.
    pub detail: Option<String>,
    /// The uid that loaded it.
    pub created_by_uid: Option<u32>,
    /// The processes holding a descriptor on it or on its link.
    pub holders: Vec<u32>,
}

impl NetworkProgram {
    /// Whether the agent holds this program or the link attaching it.
    #[must_use]
    pub fn is_own(&self, own: &OwnBpfObjects) -> bool {
        own.prog_ids.contains(&self.prog_id)
            || self
                .link_id
                .is_some_and(|link| own.link_ids.contains(&link))
    }

    /// Where it runs, as a person reads it.
    #[must_use]
    pub fn place(&self) -> String {
        let mut place = self.hook.as_str().to_string();
        match (&self.interface, self.ifindex) {
            (Some(name), _) => place = format!("{place} on {name}"),
            (None, Some(index)) => place = format!("{place} on #{index} (another namespace)"),
            (None, None) => {}
        }
        if let Some(cgroup) = self.cgroup_id {
            place = format!("{place} cgroup {cgroup}");
        }
        if let Some(detail) = &self.detail {
            place = format!("{place} {detail}");
        }
        place
    }
}

/// The programs and links the agent holds a descriptor on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnBpfObjects {
    pub prog_ids: HashSet<u32>,
    pub link_ids: HashSet<u32>,
}

/// Split `programs` into those the agent does not own and those it does.
#[must_use]
pub fn split_own(
    programs: Vec<NetworkProgram>,
    own: &OwnBpfObjects,
) -> (Vec<NetworkProgram>, Vec<NetworkProgram>) {
    let (mine, foreign): (Vec<_>, Vec<_>) = programs.into_iter().partition(|p| p.is_own(own));
    (foreign, mine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(prog_id: u32, link_id: Option<u32>, hook: &str) -> NetworkProgram {
        NetworkProgram {
            prog_id,
            prog_type: "sched_cls".to_string(),
            name: "cil_from_netdev".to_string(),
            tag: "0a1b2c3d4e5f6071".to_string(),
            link_id,
            hook: NetworkHook::from_slug(hook),
            ifindex: Some(2),
            interface: Some("eth0".to_string()),
            position: None,
            cgroup_id: None,
            detail: None,
            created_by_uid: Some(0),
            holders: vec![1312],
        }
    }

    #[test]
    fn every_slug_reads_back_into_its_hook() {
        for hook in [
            NetworkHook::Xdp,
            NetworkHook::TcIngress,
            NetworkHook::TcEgress,
            NetworkHook::TcxIngress,
            NetworkHook::TcxEgress,
            NetworkHook::NetkitPrimary,
            NetworkHook::NetkitPeer,
            NetworkHook::Cgroup,
            NetworkHook::Netfilter,
            NetworkHook::Netns,
            NetworkHook::Unplaced,
        ] {
            assert_eq!(NetworkHook::from_slug(hook.as_str()), hook);
        }
        assert_eq!(NetworkHook::from_slug("lsm"), NetworkHook::Unplaced);
    }

    #[test]
    fn a_program_held_by_the_agent_or_attached_by_its_link_is_its_own() {
        let own = OwnBpfObjects {
            prog_ids: HashSet::from([10]),
            link_ids: HashSet::from([7]),
        };
        let programs = vec![
            program(10, None, "xdp"),
            program(11, Some(7), "tcx_ingress"),
            program(12, Some(8), "tcx_ingress"),
        ];
        let (foreign, mine) = split_own(programs, &own);
        assert_eq!(mine.len(), 2);
        assert_eq!(foreign.len(), 1);
        assert_eq!(foreign[0].prog_id, 12);
    }

    #[test]
    fn the_place_names_the_interface_or_says_it_is_elsewhere() {
        assert_eq!(program(1, None, "tc_ingress").place(), "tc_ingress on eth0");
        let mut pod = program(1, Some(3), "netkit_peer");
        pod.interface = None;
        pod.ifindex = Some(14);
        assert_eq!(pod.place(), "netkit_peer on #14 (another namespace)");
        let mut cgroup = program(1, Some(4), "cgroup");
        cgroup.interface = None;
        cgroup.ifindex = None;
        cgroup.cgroup_id = Some(4242);
        cgroup.detail = Some("inet4_connect".to_string());
        assert_eq!(cgroup.place(), "cgroup cgroup 4242 inet4_connect");
    }
}
