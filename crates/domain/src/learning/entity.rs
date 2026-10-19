use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::common::entity::Protocol;
use crate::firewall::workload::{WORKLOAD_MATCHER_MAX_LEN, WorkloadFacts, WorkloadSelector};

use super::error::LearningError;

/// Shortest window the agent accepts.
///
/// A minute is already short enough to be useless as a policy and long enough
/// to prove the plumbing works, which is the only thing a one-minute window is
/// good for.
pub const LEARNING_MIN_DURATION_SECS: u64 = 60;

/// Longest window the agent accepts, thirty days.
///
/// Past that the aggregate is describing a node that has been redeployed under
/// it, and the session's own gap record stops meaning anything.
pub const LEARNING_MAX_DURATION_SECS: u64 = 30 * 86_400;

/// How many distinct edges an aggregate holds before it stops taking new ones.
pub const LEARNING_DEFAULT_MAX_EDGES: usize = 8_192;

/// Hard ceiling on the configurable edge capacity.
pub const LEARNING_MAX_EDGES_CEILING: usize = 131_072;

/// How many selectors a scope may name.
///
/// The same figure the kernel policy accepts, so a scope can never name more
/// workloads than a policy written from it could carry.
pub const LEARNING_MAX_SCOPE_SELECTORS: usize = 64;

/// What a session is allowed to watch.
///
/// Scope is decided per observation and never retrofitted: a flow outside the
/// scope is counted as out of scope and dropped, so the aggregate holds only
/// what the operator asked to learn about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LearningScope {
    /// Every workload on the node that a flow can be attributed to.
    Node,
    /// One cgroup v2 subtree, by absolute path: that cgroup and everything
    /// under it.
    Cgroup { path: String },
    /// A set of workloads, named with the same selectors a rule uses.
    Workloads { selectors: Vec<WorkloadSelector> },
}

impl LearningScope {
    /// Refuse a scope no observation could ever be decided against.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::InvalidScope`] when a cgroup path is blank,
    /// not absolute or longer than [`WORKLOAD_MATCHER_MAX_LEN`], when a
    /// workload set is empty or longer than
    /// [`LEARNING_MAX_SCOPE_SELECTORS`], or when one of its selectors is not
    /// a selector.
    pub fn validate(&self) -> Result<(), LearningError> {
        match self {
            Self::Node => Ok(()),
            Self::Cgroup { path } => {
                if path.trim().is_empty() {
                    return Err(LearningError::InvalidScope {
                        reason: "cgroup path is blank".to_string(),
                    });
                }
                if !path.starts_with('/') {
                    return Err(LearningError::InvalidScope {
                        reason: format!("cgroup path '{path}' is not absolute"),
                    });
                }
                if path.len() > WORKLOAD_MATCHER_MAX_LEN {
                    return Err(LearningError::InvalidScope {
                        reason: format!(
                            "cgroup path is longer than {WORKLOAD_MATCHER_MAX_LEN} characters"
                        ),
                    });
                }
                Ok(())
            }
            Self::Workloads { selectors } => {
                if selectors.is_empty() {
                    return Err(LearningError::InvalidScope {
                        reason: "a workload scope names no workload".to_string(),
                    });
                }
                if selectors.len() > LEARNING_MAX_SCOPE_SELECTORS {
                    return Err(LearningError::InvalidScope {
                        reason: format!(
                            "a scope names at most {LEARNING_MAX_SCOPE_SELECTORS} workloads"
                        ),
                    });
                }
                for selector in selectors {
                    selector
                        .validate()
                        .map_err(|e| LearningError::InvalidScope {
                            reason: e.to_string(),
                        })?;
                }
                Ok(())
            }
        }
    }

    /// Whether a task's facts fall inside the scope.
    pub fn admits(&self, facts: &WorkloadFacts<'_>) -> bool {
        match self {
            Self::Node => true,
            Self::Cgroup { path } => facts.cgroup.is_some_and(|c| {
                c == path
                    || (c.starts_with(path.as_str()) && c.as_bytes().get(path.len()) == Some(&b'/'))
            }),
            Self::Workloads { selectors } => selectors.iter().any(|s| s.matches(facts)),
        }
    }

    /// One line naming the scope, for the header of the document the session
    /// produces and for the progress view.
    pub fn describe(&self) -> String {
        match self {
            Self::Node => "the whole node".to_string(),
            Self::Cgroup { path } => format!("the cgroup subtree {path}"),
            Self::Workloads { selectors } => {
                let named: Vec<String> = selectors.iter().map(describe_selector).collect();
                format!("{} workloads: {}", selectors.len(), named.join(", "))
            }
        }
    }
}

fn describe_selector(selector: &WorkloadSelector) -> String {
    let mut parts = Vec::new();
    if let Some(exe) = selector.exe.as_deref() {
        parts.push(format!("exe {exe}"));
    }
    if let Some(unit) = selector.unit.as_deref() {
        parts.push(format!("unit {unit}"));
    }
    if let Some(cgroup) = selector.cgroup.as_deref() {
        parts.push(format!("cgroup {cgroup}"));
    }
    if let Some(container) = selector.container.as_deref() {
        parts.push(format!("container {container}"));
    }
    parts.join(" and ")
}

/// Where a session is in its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LearningStatus {
    /// The window is open and observations are being folded in.
    Running,
    /// The window elapsed on its own.
    Completed,
    /// An operator ended the window early.
    Stopped,
    /// The agent went down while the window was open.
    ///
    /// The session is kept and says so rather than being silently resumed as
    /// if nothing had happened: a window with a hole in it produces a policy
    /// missing whatever ran during the hole.
    Interrupted,
}

impl LearningStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Stopped => "stopped",
            Self::Interrupted => "interrupted",
        }
    }

    /// Whether the session is still taking observations.
    pub fn is_running(self) -> bool {
        self == Self::Running
    }
}

/// The facts about a task, owned, as the observation side could read them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedWorkload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
}

impl ObservedWorkload {
    /// Borrow the facts in the shape a selector decides against.
    pub fn facts(&self) -> WorkloadFacts<'_> {
        WorkloadFacts {
            exe: self.exe.as_deref(),
            unit: self.unit.as_deref(),
            cgroup: self.cgroup.as_deref(),
            container_id: self.container_id.as_deref(),
            container_name: self.container_name.as_deref(),
        }
    }
}

/// How the aggregate names the workload on one side of an edge.
///
/// One observed task resolves to exactly one key, so that the document the
/// session produces carries one rule per workload rather than one rule per
/// way of naming the same workload. The order is the order of how long the
/// name survives: a container name outlives the id the runtime gave it, an id
/// outlives a restart of the process, a unit outlives a path change, and a
/// path is what is left when nothing else is known.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum WorkloadKey {
    /// Container name, or the full id where the runtime enricher read no name.
    Container(String),
    /// systemd unit.
    Unit(String),
    /// Absolute executable path.
    Executable(String),
}

impl WorkloadKey {
    /// The key a set of facts resolves to, or `None` when the facts name no
    /// workload at all.
    ///
    /// A flow nothing can be said about is never given a key: it is counted
    /// as unattributed instead, so the operator can see how much of the node
    /// the document cannot speak for.
    pub fn from_facts(facts: &WorkloadFacts<'_>) -> Option<Self> {
        if let Some(name) = facts.container_name.filter(|n| !n.is_empty()) {
            return Some(Self::Container(name.to_string()));
        }
        if let Some(id) = facts.container_id.filter(|i| !i.is_empty()) {
            return Some(Self::Container(id.to_string()));
        }
        if let Some(unit) = facts.unit.filter(|u| !u.is_empty()) {
            return Some(Self::Unit(unit.to_string()));
        }
        if let Some(exe) = facts.exe.filter(|e| e.starts_with('/')) {
            return Some(Self::Executable(exe.to_string()));
        }
        None
    }

    /// The selector a rule written for this workload carries.
    ///
    /// # Errors
    ///
    /// Returns [`LearningError::InvalidScope`] when the key cannot be written
    /// as a selector, which is a container id shorter than the prefix the
    /// language accepts or a path that stopped being absolute.
    pub fn to_selector(&self) -> Result<WorkloadSelector, LearningError> {
        let built = match self {
            Self::Container(c) => WorkloadSelector::new(None, None, None, Some(c.clone())),
            Self::Unit(u) => WorkloadSelector::new(None, Some(u.clone()), None, None),
            Self::Executable(e) => WorkloadSelector::new(Some(e.clone()), None, None, None),
        };
        built.map_err(|e| LearningError::InvalidScope {
            reason: e.to_string(),
        })
    }

    /// What the key is, for a comment or a progress line.
    pub fn describe(&self) -> String {
        match self {
            Self::Container(c) => format!("container {c}"),
            Self::Unit(u) => format!("unit {u}"),
            Self::Executable(e) => format!("executable {e}"),
        }
    }
}

/// One flow, as the observation side hands it to the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedFlow {
    /// What the agent could resolve about the local task.
    pub workload: ObservedWorkload,
    /// The address the task reached.
    pub destination: IpAddr,
    /// The port it reached, host order.
    pub port: u16,
    /// The protocol of the flow.
    pub protocol: Protocol,
}

/// What one observation did to the aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    /// An edge the aggregate did not hold.
    NewEdge,
    /// An edge it already held, whose last-seen time moved.
    KnownEdge,
    /// The task falls outside the declared scope.
    OutOfScope,
    /// Nothing about the local task could be resolved, so no rule could ever
    /// name it.
    Unattributed,
    /// The aggregate is full and refused a new edge.
    Dropped,
    /// No session is open.
    Ignored,
}

/// A stretch of the window during which nothing was observed because the
/// agent was not running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningGap {
    /// Last moment the session is known to have been observing.
    pub from_ns: u64,
    /// Moment it started observing again.
    pub to_ns: u64,
}

impl LearningGap {
    pub fn seconds(&self) -> u64 {
        self.to_ns.saturating_sub(self.from_ns) / 1_000_000_000
    }
}

/// What a session reports about itself.
///
/// Everything here is a figure an operator needs before deciding the window
/// was long enough: how long it ran, how much of it was a hole, how many
/// edges it holds, how much it could not attribute, and how long it has been
/// since the last new edge appeared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearningProgress {
    pub id: String,
    pub status: LearningStatus,
    pub scope: LearningScope,
    pub scope_description: String,
    pub requested_duration_secs: u64,
    pub started_at_ns: u64,
    pub ended_at_ns: Option<u64>,
    /// Wall-clock seconds since the window opened.
    pub elapsed_secs: u64,
    /// Seconds of the window during which the agent was not running.
    pub gap_secs: u64,
    /// Seconds left before the window closes on its own, zero once it has.
    pub remaining_secs: u64,
    /// Distinct edges held.
    pub edges: usize,
    /// How many the aggregate can hold.
    pub capacity: usize,
    /// Edges refused because the aggregate was full. Any value but zero means
    /// the document is incomplete and says so.
    pub dropped_edges: u64,
    /// Observations folded in, which counts a long-lived flow once per sample
    /// rather than once per connection.
    pub observations: u64,
    /// Observations whose local task could not be resolved to any name a rule
    /// could carry.
    pub unattributed: u64,
    /// Observations the scope refused.
    pub out_of_scope: u64,
    /// When the last new edge appeared.
    pub last_new_edge_ns: Option<u64>,
    /// Seconds since the last new edge appeared. The figure that says the
    /// window was long enough: a session still finding edges has not finished
    /// describing the node.
    pub secs_since_new_edge: Option<u64>,
    /// Whether the agent has been continuously up for the whole window.
    pub continuous: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts<'a>(
        exe: Option<&'a str>,
        unit: Option<&'a str>,
        cgroup: Option<&'a str>,
    ) -> WorkloadFacts<'a> {
        WorkloadFacts {
            exe,
            unit,
            cgroup,
            container_id: None,
            container_name: None,
        }
    }

    #[test]
    fn the_node_scope_admits_everything() {
        assert!(LearningScope::Node.admits(&facts(Some("/usr/bin/curl"), None, None)));
        assert!(LearningScope::Node.admits(&facts(None, None, None)));
    }

    #[test]
    fn a_cgroup_scope_admits_the_subtree_and_not_a_sibling_sharing_its_prefix() {
        let scope = LearningScope::Cgroup {
            path: "/sys/fs/cgroup/system.slice".to_string(),
        };
        assert!(scope.admits(&facts(None, None, Some("/sys/fs/cgroup/system.slice"))));
        assert!(scope.admits(&facts(
            None,
            None,
            Some("/sys/fs/cgroup/system.slice/nginx.service")
        )));
        assert!(
            !scope.admits(&facts(
                None,
                None,
                Some("/sys/fs/cgroup/system.slice-other")
            )),
            "a prefix match is not a subtree match"
        );
        assert!(!scope.admits(&facts(None, None, None)));
    }

    #[test]
    fn a_workload_scope_admits_what_one_of_its_selectors_matches() {
        let scope = LearningScope::Workloads {
            selectors: vec![
                WorkloadSelector::new(None, Some("nginx.service".to_string()), None, None).unwrap(),
            ],
        };
        assert!(scope.admits(&facts(None, Some("nginx.service"), None)));
        assert!(!scope.admits(&facts(None, Some("sshd.service"), None)));
    }

    #[test]
    fn a_scope_naming_nothing_is_refused() {
        assert!(matches!(
            LearningScope::Workloads { selectors: vec![] }.validate(),
            Err(LearningError::InvalidScope { .. })
        ));
        assert!(matches!(
            LearningScope::Cgroup {
                path: "system.slice".to_string()
            }
            .validate(),
            Err(LearningError::InvalidScope { .. })
        ));
        assert!(LearningScope::Node.validate().is_ok());
    }

    #[test]
    fn a_workload_resolves_to_the_longest_lived_name_it_carries() {
        let full = WorkloadFacts {
            exe: Some("/usr/sbin/nginx"),
            unit: Some("docker.service"),
            cgroup: Some("/sys/fs/cgroup/docker"),
            container_id: Some("abcdef0123456789"),
            container_name: Some("web"),
        };
        assert_eq!(
            WorkloadKey::from_facts(&full),
            Some(WorkloadKey::Container("web".to_string()))
        );

        let no_name = WorkloadFacts {
            container_name: None,
            ..full
        };
        assert_eq!(
            WorkloadKey::from_facts(&no_name),
            Some(WorkloadKey::Container("abcdef0123456789".to_string()))
        );

        let host = facts(Some("/usr/sbin/nginx"), Some("nginx.service"), None);
        assert_eq!(
            WorkloadKey::from_facts(&host),
            Some(WorkloadKey::Unit("nginx.service".to_string()))
        );

        let bare = facts(Some("/usr/bin/curl"), None, None);
        assert_eq!(
            WorkloadKey::from_facts(&bare),
            Some(WorkloadKey::Executable("/usr/bin/curl".to_string()))
        );
    }

    #[test]
    fn a_flow_naming_no_workload_gets_no_key() {
        assert_eq!(WorkloadKey::from_facts(&facts(None, None, None)), None);
        assert_eq!(
            WorkloadKey::from_facts(&facts(Some("curl"), None, None)),
            None,
            "a relative path is not a matcher the rule language accepts"
        );
    }

    #[test]
    fn a_key_becomes_the_selector_a_rule_carries() {
        let selector = WorkloadKey::Unit("nginx.service".to_string())
            .to_selector()
            .unwrap();
        assert_eq!(selector.unit.as_deref(), Some("nginx.service"));
        assert!(selector.exe.is_none());

        let refused = WorkloadKey::Container("abc".to_string()).to_selector();
        assert!(
            refused.is_err(),
            "a container id shorter than the accepted prefix cannot become a rule"
        );
    }

    #[test]
    fn a_gap_is_counted_in_seconds() {
        let gap = LearningGap {
            from_ns: 1_000_000_000,
            to_ns: 61_000_000_000,
        };
        assert_eq!(gap.seconds(), 60);
    }
}
