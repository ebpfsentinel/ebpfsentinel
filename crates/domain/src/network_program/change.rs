use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::entity::{NetworkHook, NetworkProgram};
use crate::alert::mitre::MitreAttackInfo;
use crate::common::entity::RuleId;

/// The component of the alerts raised for a change on the network path.
pub const NETWORK_PATH_COMPONENT: &str = "network_path";

/// What changed on the network path, as it bears on the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathChangeKind {
    /// Another program now runs before one of the agent's on the same hook
    /// of the same interface, and sees every packet first.
    Ahead,
    /// The agent's program is no longer where it was and another program
    /// sits there now.
    Replaced,
    /// The agent's program is no longer where it was, while the agent still
    /// holds it: somebody else took it off.
    Detached,
}

impl PathChangeKind {
    #[must_use]
    pub fn rule_id(self) -> RuleId {
        RuleId(
            match self {
                Self::Ahead => "network-path-program-ahead",
                Self::Replaced => "network-path-program-replaced",
                Self::Detached => "network-path-link-detached",
            }
            .to_string(),
        )
    }

    /// A program ahead of the agent's hides traffic from it the way a
    /// rootkit does; taking the agent's program off is turning a defence
    /// off without stopping it.
    #[must_use]
    pub fn mitre(self) -> MitreAttackInfo {
        let (technique_id, technique_name) = match self {
            Self::Ahead => ("T1014", "Rootkit"),
            Self::Replaced | Self::Detached => {
                ("T1562.001", "Impair Defenses: Disable or Modify Tools")
            }
        };
        MitreAttackInfo {
            technique_id: technique_id.to_string(),
            technique_name: technique_name.to_string(),
            tactic: "defense-evasion".to_string(),
        }
    }
}

/// One change on the network path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathChange {
    pub kind: PathChangeKind,
    /// The agent's program the change concerns, where it was before for a
    /// replaced or detached one.
    pub ours: NetworkProgram,
    /// The other program: the one ahead, or the one sitting where the
    /// agent's was.
    pub other: Option<NetworkProgram>,
}

impl PathChange {
    /// The alert's sentence.
    #[must_use]
    pub fn message(&self) -> String {
        let ours = describe(&self.ours);
        let place = self.ours.place();
        match (self.kind, &self.other) {
            (PathChangeKind::Ahead, Some(other)) => format!(
                "{} attached ahead of the agent's {ours} on {place}: it sees, drops or rewrites every packet before the agent does",
                describe(other)
            ),
            (PathChangeKind::Replaced, Some(other)) => format!(
                "the agent's {ours} was replaced on {place} by {}",
                describe(other)
            ),
            _ => format!(
                "the agent's {ours} was detached from {place} while the agent still holds it"
            ),
        }
    }
}

fn describe(program: &NetworkProgram) -> String {
    let name = if program.name.is_empty() {
        "unnamed program"
    } else {
        program.name.as_str()
    };
    format!(
        "eBPF program {name} (id {}, {})",
        program.prog_id, program.prog_type
    )
}

/// One reading of the network path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathReading {
    /// The agent's programs, wherever they are.
    pub own: Vec<NetworkProgram>,
    /// Everybody else's.
    pub foreign: Vec<NetworkProgram>,
    /// The links the agent held a descriptor on.
    pub own_links: HashSet<u32>,
}

/// Where a program runs, as two readings compare it.
type Slot<'a> = (
    NetworkHook,
    Option<u32>,
    Option<&'a str>,
    Option<u64>,
    Option<&'a str>,
);

fn slot(program: &NetworkProgram) -> Slot<'_> {
    (
        program.hook,
        program.ifindex,
        program.interface.as_deref(),
        program.cgroup_id,
        program.detail.as_deref(),
    )
}

fn runs_in_turn(hook: NetworkHook) -> bool {
    matches!(
        hook,
        NetworkHook::TcIngress
            | NetworkHook::TcEgress
            | NetworkHook::TcxIngress
            | NetworkHook::TcxEgress
            | NetworkHook::NetkitPrimary
            | NetworkHook::NetkitPeer
    )
}

/// Each foreign program running before one of the agent's on the same hook
/// of the same host interface, with the first of the agent's it precedes.
fn ahead(reading: &PathReading) -> Vec<(&NetworkProgram, &NetworkProgram)> {
    reading
        .foreign
        .iter()
        .filter(|f| runs_in_turn(f.hook) && f.interface.is_some())
        .filter_map(|f| {
            let at = f.position?;
            let first_of_ours = reading
                .own
                .iter()
                .filter(|o| slot(o) == slot(f))
                .filter(|o| o.position.is_some_and(|p| p > at))
                .min_by_key(|o| o.position)?;
            Some((f, first_of_ours))
        })
        .collect()
}

/// What changed on the network path between two readings.
///
/// The agent's own reload is told apart by what it still holds: a program
/// the agent closed is gone from the reading, and a link it dropped is gone
/// from its descriptors, so neither is a change somebody else made. A
/// program still held and no longer where it was has been moved by another
/// task.
#[must_use]
pub fn path_changes(previous: &PathReading, current: &PathReading) -> Vec<PathChange> {
    let mut changes = Vec::new();

    let was_ahead: HashSet<(u32, Slot<'_>)> = ahead(previous)
        .into_iter()
        .map(|(f, _)| (f.prog_id, slot(f)))
        .collect();
    for (other, ours) in ahead(current) {
        if !was_ahead.contains(&(other.prog_id, slot(other))) {
            changes.push(PathChange {
                kind: PathChangeKind::Ahead,
                ours: ours.clone(),
                other: Some(other.clone()),
            });
        }
    }

    let now: Vec<&NetworkProgram> = current.own.iter().chain(&current.foreign).collect();
    let before: Vec<&NetworkProgram> = previous.own.iter().chain(&previous.foreign).collect();
    for ours in previous
        .own
        .iter()
        .filter(|o| o.hook != NetworkHook::Unplaced)
    {
        let still_there = current
            .own
            .iter()
            .any(|o| o.prog_id == ours.prog_id && slot(o) == slot(ours));
        let still_held = now.iter().any(|p| p.prog_id == ours.prog_id);
        let link_dropped = ours.link_id.is_some_and(|link| {
            previous.own_links.contains(&link) && !current.own_links.contains(&link)
        });
        if still_there || !still_held || link_dropped {
            continue;
        }
        let newcomer = now
            .iter()
            .filter(|p| p.prog_id != ours.prog_id && slot(p) == slot(ours))
            .find(|p| {
                !before
                    .iter()
                    .any(|b| b.prog_id == p.prog_id && slot(b) == slot(p))
            });
        changes.push(PathChange {
            kind: if newcomer.is_some() {
                PathChangeKind::Replaced
            } else {
                PathChangeKind::Detached
            },
            ours: ours.clone(),
            other: newcomer.map(|p| (*p).clone()),
        });
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program(prog_id: u32, link_id: Option<u32>, position: Option<u32>) -> NetworkProgram {
        NetworkProgram {
            prog_id,
            prog_type: "sched_cls".to_string(),
            name: format!("prog{prog_id}"),
            tag: "00".to_string(),
            link_id,
            hook: NetworkHook::TcxIngress,
            ifindex: Some(2),
            interface: Some("eth0".to_string()),
            position,
            cgroup_id: None,
            detail: None,
            created_by_uid: Some(0),
            holders: vec![4242],
        }
    }

    fn reading(own: Vec<NetworkProgram>, foreign: Vec<NetworkProgram>) -> PathReading {
        let own_links = own.iter().filter_map(|p| p.link_id).collect();
        PathReading {
            own,
            foreign,
            own_links,
        }
    }

    #[test]
    fn a_program_attached_before_ours_is_ahead_once() {
        let before = reading(vec![program(1, Some(10), Some(0))], vec![]);
        let after = reading(
            vec![program(1, Some(10), Some(1))],
            vec![program(2, Some(20), Some(0))],
        );
        let changes = path_changes(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, PathChangeKind::Ahead);
        assert_eq!(changes[0].ours.prog_id, 1);
        assert_eq!(changes[0].other.as_ref().map(|p| p.prog_id), Some(2));
        assert!(changes[0].message().contains("ahead of the agent's"));
        assert!(path_changes(&after, &after).is_empty());
    }

    #[test]
    fn a_program_attached_after_ours_or_elsewhere_is_no_change() {
        let before = reading(vec![program(1, Some(10), Some(0))], vec![]);
        let mut elsewhere = program(3, Some(30), Some(0));
        elsewhere.interface = Some("eth1".to_string());
        elsewhere.ifindex = Some(3);
        let after = reading(
            vec![program(1, Some(10), Some(0))],
            vec![program(2, Some(20), Some(1)), elsewhere],
        );
        assert!(path_changes(&before, &after).is_empty());
    }

    #[test]
    fn a_link_detached_while_the_agent_holds_it_is_a_change() {
        let before = reading(vec![program(1, Some(10), Some(0))], vec![]);
        let mut detached = program(1, Some(10), None);
        detached.ifindex = Some(0);
        detached.interface = None;
        let after = reading(vec![detached], vec![]);
        let changes = path_changes(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, PathChangeKind::Detached);
        assert!(
            changes[0]
                .message()
                .contains("detached from tcx_ingress on eth0")
        );
    }

    #[test]
    fn a_program_put_in_place_of_ours_is_a_replacement() {
        let mut ours = program(1, None, None);
        ours.hook = NetworkHook::Xdp;
        let before = reading(vec![ours.clone()], vec![]);
        let mut unplaced = ours.clone();
        unplaced.hook = NetworkHook::Unplaced;
        unplaced.ifindex = None;
        unplaced.interface = None;
        let mut theirs = program(5, None, None);
        theirs.hook = NetworkHook::Xdp;
        let after = reading(vec![unplaced], vec![theirs]);
        let changes = path_changes(&before, &after);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].kind, PathChangeKind::Replaced);
        assert_eq!(changes[0].other.as_ref().map(|p| p.prog_id), Some(5));
        assert_eq!(changes[0].kind.rule_id().0, "network-path-program-replaced");
    }

    #[test]
    fn the_agent_own_reload_is_no_change() {
        let before = reading(vec![program(1, Some(10), Some(0))], vec![]);
        let closed = reading(vec![program(7, Some(11), Some(0))], vec![]);
        assert!(path_changes(&before, &closed).is_empty());
        let mut dropped = reading(vec![program(1, Some(10), None)], vec![]);
        dropped.own[0].interface = None;
        dropped.own_links.clear();
        assert!(path_changes(&before, &dropped).is_empty());
    }
}
