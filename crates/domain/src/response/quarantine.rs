//! Which cgroups a response may never cut off the network, and what came of
//! the ones it did.
//!
//! Quarantine is the response an operator reaches for when killing is too
//! much: the workload keeps running, so the memory, the open files and the
//! process tree are all still there to be looked at, and it reaches nothing
//! while they are. That makes it the safer of the two in every way but one -
//! it is the one that can be pointed at a cgroup holding something the whole
//! node depends on.
//!
//! So the same shape as the kill guard, for the same reason: the list of what
//! may never be cut off is code. [`HARD_PROTECTED_CGROUP_PATHS`] is compiled
//! in, a configured list is added to it, and nothing subtracts from it. Three
//! groups are on it and no fourth - the root of the hierarchy, the slices that
//! run containers, and the way back in. Cutting a container runtime off the
//! network stops every image pull on the node; cutting the remote-access slice
//! off strands the operator outside the machine they were about to investigate
//! from, which is the one failure that cannot be undone remotely.
//!
//! The match is on the cgroup path as the kernel names it, by prefix, because
//! a slice holds a tree: `/system.slice/containerd.service` protects the shims
//! underneath it without the list having to name a shim. A cgroup whose path
//! cannot be read is refused rather than guessed at, which costs a quarantine
//! on a cgroup that went away and buys never quarantining one by accident.

use serde::{Deserialize, Serialize};

/// cgroup paths a response may never cut off, whatever the configuration says.
///
/// Prefixes rather than exact paths: each one protects the tree beneath it, so
/// a container shim under `containerd.service` is covered without the list
/// naming it, and so is the next runtime version's.
pub const HARD_PROTECTED_CGROUP_PATHS: &[&str] = &[
    "/init.scope",
    "/system.slice/containerd.service",
    "/system.slice/docker.service",
    "/system.slice/crio.service",
    "/system.slice/podman.service",
    "/system.slice/kubelet.service",
    "/system.slice/ebpfsentinel-agent.service",
    "/system.slice/ebpfsentinel-warden.service",
    "/system.slice/sshd.service",
    "/system.slice/ssh.service",
    "/system.slice/teleport.service",
];

/// Why a cgroup was refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProtectedCgroupReason {
    /// cgroup id zero is no cgroup: a hook that could not read one reports it,
    /// and arming on it would quarantine whatever the map's zero key reached.
    NotACgroup,
    /// The root of the hierarchy, which every task on the node is inside.
    RootCgroup,
    /// The cgroup the agent itself runs in. Cutting it off would cost the
    /// agent its own portal, SIEM and alert transports, so a quarantine would
    /// silence the report of itself.
    TheAgentItself,
    /// The path could not be read, so nothing about the cgroup can be checked.
    NotIdentified,
    /// The path is under a compiled-in protected prefix.
    HardProtected { path: String },
    /// The path is under a configured protected prefix.
    ConfiguredPath { path: String },
    /// The cgroup id is on the configured list.
    ConfiguredId { cgroup_id: u64 },
}

impl ProtectedCgroupReason {
    /// One sentence for the audit record and the API answer.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::NotACgroup => "cgroup 0 is no cgroup and is never quarantined".to_string(),
            Self::RootCgroup => {
                "the root cgroup holds every task on the node and is never quarantined".to_string()
            }
            Self::TheAgentItself => "the agent does not quarantine itself".to_string(),
            Self::NotIdentified => {
                "the cgroup's path could not be read, so it was not quarantined".to_string()
            }
            Self::HardProtected { path } => {
                format!("`{path}` is protected and configuration cannot override it")
            }
            Self::ConfiguredPath { path } => {
                format!("`{path}` is on the configured protected list")
            }
            Self::ConfiguredId { cgroup_id } => {
                format!("cgroup {cgroup_id} is on the configured protected list")
            }
        }
    }
}

/// Whether a cgroup may be quarantined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineVerdict {
    /// Nothing protects this cgroup.
    Allowed,
    /// It is protected, for this reason.
    Protected(ProtectedCgroupReason),
}

impl QuarantineVerdict {
    /// Whether the quarantine may be armed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }

    /// The reason, where there is one.
    #[must_use]
    pub fn reason(&self) -> Option<&ProtectedCgroupReason> {
        match self {
            Self::Allowed => None,
            Self::Protected(reason) => Some(reason),
        }
    }
}

/// Whether a quarantine refuses the workload's sockets or only records them.
///
/// Report-only is the same arming on the same map with the same expiry, so an
/// operator sizing the blast radius of cutting a production workload off gets
/// the answer from the capability rather than from a guess. It is also why the
/// mode is part of the quarantine and not a separate dry-run switch: the thing
/// being measured has to be the thing that will run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineMode {
    /// Refuse the socket operation. The workload sees `EPERM`.
    #[default]
    Enforce,
    /// Allow it and record what would have been refused.
    Report,
}

impl QuarantineMode {
    /// Whether this mode refuses anything.
    #[must_use]
    pub fn enforces(self) -> bool {
        matches!(self, Self::Enforce)
    }
}

/// What came of one decision to quarantine.
///
/// The torn-down flow count is part of the outcome rather than a side effect,
/// because a quarantine that armed and tore nothing down is a workload whose
/// established connections are still carrying traffic, and an operator reading
/// "quarantined" has to be able to tell the two apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum QuarantineOutcome {
    /// The cgroup was protected, so nothing was armed.
    Refused { reason: ProtectedCgroupReason },
    /// The cgroup is cut off until the given boot-clock instant.
    Armed {
        cgroup_id: u64,
        mode: QuarantineMode,
        /// Flows the teardown deleted.
        flows_torn_down: u64,
        /// Flows whose owning cgroup the socket table could not name, so they
        /// were left alone. Reported rather than swallowed: it is the
        /// difference between a clean cut and one with holes in it.
        flows_unresolved: u64,
    },
    /// The cgroup was quarantined and is not any more.
    Released { cgroup_id: u64 },
    /// A release naming a cgroup that was not quarantined. Not an error: an
    /// operator releasing twice, or releasing something that already expired,
    /// gets told so rather than getting a failure.
    NotQuarantined { cgroup_id: u64 },
}

impl QuarantineOutcome {
    /// Whether the cgroup is cut off as a result of this decision.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        matches!(self, Self::Armed { .. })
    }

    /// One sentence for the audit record.
    #[must_use]
    pub fn as_sentence(&self) -> String {
        match self {
            Self::Refused { reason } => reason.as_sentence(),
            Self::Armed {
                cgroup_id,
                mode: QuarantineMode::Enforce,
                flows_torn_down,
                flows_unresolved,
            } => format!(
                "cgroup {cgroup_id} is cut off from the network, {flows_torn_down} flows torn down, {flows_unresolved} left unresolved"
            ),
            Self::Armed {
                cgroup_id,
                mode: QuarantineMode::Report,
                ..
            } => format!(
                "cgroup {cgroup_id} is recorded as quarantined in report-only mode and reaches the network as before"
            ),
            Self::Released { cgroup_id } => {
                format!("cgroup {cgroup_id} reaches the network again")
            }
            Self::NotQuarantined { cgroup_id } => {
                format!("cgroup {cgroup_id} was not quarantined")
            }
        }
    }
}

/// One quarantine as a reader sees it.
///
/// The remaining time is a duration rather than the boot-clock deadline the
/// map holds, because a deadline on that clock means nothing to anybody
/// outside this kernel and would be read as a timestamp by everybody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveQuarantine {
    pub cgroup_id: u64,
    /// The cgroup's path, where it is still there to be read. A quarantined
    /// workload that has since been removed keeps its entry until the expiry,
    /// and reports no path rather than a stale one.
    pub path: Option<String>,
    pub mode: QuarantineMode,
    /// Milliseconds until the kernel stops refusing.
    pub remaining_ms: u64,
}

/// Decides which cgroups are off limits.
///
/// Built once from the configuration, the root cgroup id and the agent's own,
/// so the decision is the same wherever it is asked.
#[derive(Debug, Clone)]
pub struct CgroupQuarantineGuard {
    self_cgroup: u64,
    root_cgroup: u64,
    paths: Vec<String>,
    ids: Vec<u64>,
}

impl CgroupQuarantineGuard {
    /// Build the guard.
    ///
    /// `self_cgroup` and `root_cgroup` may be zero on a node where the agent
    /// could not read them, and a zero is simply not added to the fence: the
    /// `NotACgroup` verdict covers the key itself, and the other checks still
    /// apply.
    #[must_use]
    pub fn new(
        self_cgroup: u64,
        root_cgroup: u64,
        protected_paths: &[String],
        protected_ids: &[u64],
    ) -> Self {
        let mut paths: Vec<String> = protected_paths
            .iter()
            .map(|p| normalise(p))
            .filter(|p| p != "/" && !p.is_empty())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        let mut ids = protected_ids.to_vec();
        ids.retain(|id| *id != 0);
        ids.sort_unstable();
        ids.dedup();
        Self {
            self_cgroup,
            root_cgroup,
            paths,
            ids,
        }
    }

    /// Whether `cgroup_id`, sitting at `path`, may be quarantined.
    ///
    /// `path` is what the agent could resolve at this instant; `None` is
    /// either a cgroup that has already gone or one the hierarchy would not
    /// name, and both are refusals.
    #[must_use]
    pub fn verdict(&self, cgroup_id: u64, path: Option<&str>) -> QuarantineVerdict {
        if cgroup_id == 0 {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::NotACgroup);
        }
        if self.root_cgroup != 0 && cgroup_id == self.root_cgroup {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::RootCgroup);
        }
        if self.self_cgroup != 0 && cgroup_id == self.self_cgroup {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::TheAgentItself);
        }
        if self.ids.binary_search(&cgroup_id).is_ok() {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::ConfiguredId { cgroup_id });
        }
        let Some(raw) = path else {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::NotIdentified);
        };
        let path = normalise(raw);
        if path.is_empty() {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::NotIdentified);
        }
        if path == "/" {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::RootCgroup);
        }
        if let Some(hard) = hard_protected_cgroup(&path) {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::HardProtected {
                path: hard.to_string(),
            });
        }
        if let Some(configured) = self.paths.iter().find(|prefix| under(&path, prefix)) {
            return QuarantineVerdict::Protected(ProtectedCgroupReason::ConfiguredPath {
                path: configured.clone(),
            });
        }
        QuarantineVerdict::Allowed
    }

    /// The configured prefixes this guard holds, normalised and deduplicated.
    #[must_use]
    pub fn configured_paths(&self) -> &[String] {
        &self.paths
    }

    /// How many fences this guard carries, for the capability report.
    ///
    /// Never zero on a running node: the compiled-in list is part of the
    /// count, so a reader seeing a zero is reading something other than a
    /// guard.
    #[must_use]
    pub fn protected_count(&self) -> usize {
        HARD_PROTECTED_CGROUP_PATHS.len() + self.paths.len() + self.ids.len()
    }
}

/// The compiled-in prefix `path` sits under, where it sits under one.
#[must_use]
pub fn hard_protected_cgroup(path: &str) -> Option<&'static str> {
    HARD_PROTECTED_CGROUP_PATHS
        .iter()
        .find(|prefix| under(path, prefix))
        .copied()
}

/// Whether `path` is `prefix` or sits in the tree below it.
///
/// Comparing the whole component rather than the string is what stops
/// `/system.slice/sshd.service.d.evil` inheriting the protection of
/// `/system.slice/sshd.service`.
fn under(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    path.strip_prefix(prefix)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// A cgroup path as the hierarchy names it: one leading slash, no trailing
/// one, and whatever mount point the reader prefixed stripped off.
fn normalise(path: &str) -> String {
    let trimmed = path.trim();
    let without_mount = trimmed
        .strip_prefix("/sys/fs/cgroup")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    if without_mount.is_empty() {
        return if trimmed.is_empty() {
            String::new()
        } else {
            "/".to_string()
        };
    }
    if without_mount.starts_with('/') {
        without_mount.to_string()
    } else {
        format!("/{without_mount}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> CgroupQuarantineGuard {
        CgroupQuarantineGuard::new(
            77,
            1,
            &[
                "/system.slice/postgresql.service".to_string(),
                " ".to_string(),
            ],
            &[4242, 0],
        )
    }

    #[test]
    fn cgroup_zero_is_never_quarantined() {
        assert_eq!(
            guard().verdict(0, Some("/payload.slice")),
            QuarantineVerdict::Protected(ProtectedCgroupReason::NotACgroup)
        );
    }

    #[test]
    fn the_root_is_refused_by_id_and_by_path() {
        assert_eq!(
            guard().verdict(1, Some("/payload.slice")),
            QuarantineVerdict::Protected(ProtectedCgroupReason::RootCgroup)
        );
        assert_eq!(
            guard().verdict(500, Some("/sys/fs/cgroup")),
            QuarantineVerdict::Protected(ProtectedCgroupReason::RootCgroup)
        );
    }

    #[test]
    fn the_agent_does_not_quarantine_itself() {
        assert_eq!(
            guard().verdict(77, Some("/system.slice/whatever.service")),
            QuarantineVerdict::Protected(ProtectedCgroupReason::TheAgentItself)
        );
    }

    #[test]
    fn the_hard_list_holds_the_runtimes_and_the_way_back_in() {
        for path in [
            "/init.scope",
            "/system.slice/containerd.service",
            "/system.slice/containerd.service/kubepods-besteffort.slice",
            "/system.slice/kubelet.service",
            "/system.slice/sshd.service",
            "/system.slice/teleport.service",
            "/sys/fs/cgroup/system.slice/docker.service",
        ] {
            let verdict = guard().verdict(5000, Some(path));
            assert!(
                matches!(
                    verdict,
                    QuarantineVerdict::Protected(ProtectedCgroupReason::HardProtected { .. })
                ),
                "{path} was not protected: {verdict:?}"
            );
        }
    }

    #[test]
    fn a_sibling_sharing_a_prefix_is_not_protected_by_it() {
        // `/system.slice/sshd.service.evil` is a different unit, and a string
        // prefix test would have handed it the protection of the real one.
        let verdict = guard().verdict(5000, Some("/system.slice/sshd.service.evil"));
        assert!(verdict.is_allowed(), "{verdict:?}");
    }

    #[test]
    fn a_configured_path_widens_the_fence_and_covers_its_tree() {
        assert_eq!(
            guard().verdict(5000, Some("/system.slice/postgresql.service/worker")),
            QuarantineVerdict::Protected(ProtectedCgroupReason::ConfiguredPath {
                path: "/system.slice/postgresql.service".to_string()
            })
        );
    }

    #[test]
    fn a_configured_path_cannot_narrow_the_hard_list() {
        // There is no spelling of the configuration that removes an entry:
        // the guard only ever adds to what is compiled in, and a configured
        // root is dropped rather than protecting everything.
        let permissive = CgroupQuarantineGuard::new(0, 0, &["/".to_string()], &[]);
        assert!(
            !permissive
                .verdict(5000, Some("/system.slice/kubelet.service"))
                .is_allowed()
        );
        assert!(permissive.configured_paths().is_empty());
        assert!(
            permissive
                .verdict(5000, Some("/payload.slice"))
                .is_allowed()
        );
    }

    #[test]
    fn a_configured_id_is_refused_before_its_path_is_read() {
        assert_eq!(
            guard().verdict(4242, None),
            QuarantineVerdict::Protected(ProtectedCgroupReason::ConfiguredId { cgroup_id: 4242 })
        );
    }

    #[test]
    fn a_cgroup_with_no_readable_path_is_refused() {
        assert_eq!(
            guard().verdict(5000, None),
            QuarantineVerdict::Protected(ProtectedCgroupReason::NotIdentified)
        );
        assert_eq!(
            guard().verdict(5000, Some("   ")),
            QuarantineVerdict::Protected(ProtectedCgroupReason::NotIdentified)
        );
    }

    #[test]
    fn an_ordinary_workload_is_allowed() {
        let verdict = guard().verdict(5000, Some("/kubepods.slice/pod-abc/container-def"));
        assert!(verdict.is_allowed());
        assert!(verdict.reason().is_none());
    }

    #[test]
    fn the_fence_is_never_empty_and_counts_both_halves() {
        assert_eq!(
            guard().protected_count(),
            HARD_PROTECTED_CGROUP_PATHS.len() + 2
        );
    }

    #[test]
    fn enforcing_is_the_default_mode() {
        assert_eq!(QuarantineMode::default(), QuarantineMode::Enforce);
        assert!(QuarantineMode::Enforce.enforces());
        assert!(!QuarantineMode::Report.enforces());
    }

    #[test]
    fn every_outcome_says_what_happened_in_one_sentence() {
        let refused = QuarantineOutcome::Refused {
            reason: ProtectedCgroupReason::RootCgroup,
        };
        assert!(!refused.is_armed());
        assert!(refused.as_sentence().contains("root cgroup"));

        let armed = QuarantineOutcome::Armed {
            cgroup_id: 9,
            mode: QuarantineMode::Enforce,
            flows_torn_down: 3,
            flows_unresolved: 1,
        };
        assert!(armed.is_armed());
        assert!(armed.as_sentence().contains("3 flows torn down"));
        assert!(armed.as_sentence().contains("1 left unresolved"));

        let reported = QuarantineOutcome::Armed {
            cgroup_id: 9,
            mode: QuarantineMode::Report,
            flows_torn_down: 0,
            flows_unresolved: 0,
        };
        assert!(reported.as_sentence().contains("report-only"));

        assert!(
            QuarantineOutcome::Released { cgroup_id: 9 }
                .as_sentence()
                .contains("again")
        );
        assert!(
            QuarantineOutcome::NotQuarantined { cgroup_id: 9 }
                .as_sentence()
                .contains("was not quarantined")
        );
    }

    #[test]
    fn the_hard_list_names_nothing_twice_and_nothing_under_another_entry() {
        let mut sorted = HARD_PROTECTED_CGROUP_PATHS.to_vec();
        sorted.sort_unstable();
        let total = sorted.len();
        sorted.dedup();
        assert_eq!(sorted.len(), total);
        for (i, entry) in sorted.iter().enumerate() {
            for other in &sorted[i + 1..] {
                assert!(
                    !under(other, entry),
                    "{other} is already covered by {entry}"
                );
            }
        }
    }
}
