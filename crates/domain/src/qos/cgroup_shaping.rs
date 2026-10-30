//! Shaping a workload's egress to a rate, keyed on its cgroup.
//!
//! The datapath gives each packet of a shaped cgroup an earliest departure
//! time spaced from the previous one by the time its bytes take at the rate,
//! and the `fq` qdisc holds the packet until then. Two things decide whether
//! that does anything: a rule selecting the workload, and an `fq` qdisc on
//! the interface the packet leaves through, since every other qdisc sends a
//! packet as soon as it is dequeued whatever its timestamp says. The second
//! one is a property of the host, so it is read from the host and reported
//! per interface rather than assumed.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::error::QosError;
use crate::firewall::workload::{WorkloadFacts, WorkloadSelector};

/// Longest horizon a rule may ask for. A packet scheduled further ahead than
/// this is a queue an operator no longer reads as shaping.
pub const MAX_HORIZON_MS: u32 = 60_000;

/// Horizon a rule gets when it names none: two seconds of queue, the same
/// order as `fq`'s own default horizon of ten.
pub const DEFAULT_HORIZON_MS: u32 = 2_000;

/// Lowest rate a rule may ask for, 8 kbps: one byte per millisecond.
pub const MIN_RATE_BPS: u64 = 8_000;

/// The parent a root qdisc carries in the kernel's netlink dump.
pub const TC_H_ROOT: u32 = 0xFFFF_FFFF;

/// One rule: the workloads it selects and the rate each of them is held to.
///
/// The rate applies to each cgroup the selector matches on its own, not to
/// their sum: two replicas of a workload selected by one rule are each held
/// to the rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupShapingRule {
    pub id: String,
    pub selector: WorkloadSelector,
    pub rate_bps: u64,
    pub horizon_ms: u32,
}

impl CgroupShapingRule {
    /// Check one rule on its own.
    ///
    /// # Errors
    ///
    /// Returns [`QosError::InvalidCgroupShaping`] for a blank id, a rate
    /// below [`MIN_RATE_BPS`], a horizon of zero or above
    /// [`MAX_HORIZON_MS`], and a selector naming an executable, since a
    /// cgroup holds tasks of more than one executable and the rate is the
    /// cgroup's.
    pub fn validate(&self) -> Result<(), QosError> {
        if self.id.trim().is_empty() {
            return Err(QosError::InvalidCgroupShaping(
                "a rule needs a non-empty id".to_string(),
            ));
        }
        if self.rate_bps < MIN_RATE_BPS {
            return Err(QosError::InvalidCgroupShaping(format!(
                "rule {}: rate must be at least {MIN_RATE_BPS} bps, got {}",
                self.id, self.rate_bps
            )));
        }
        if self.horizon_ms == 0 || self.horizon_ms > MAX_HORIZON_MS {
            return Err(QosError::InvalidCgroupShaping(format!(
                "rule {}: horizon must be 1 to {MAX_HORIZON_MS} ms, got {}",
                self.id, self.horizon_ms
            )));
        }
        if self.selector.names_executable() {
            return Err(QosError::InvalidCgroupShaping(format!(
                "rule {}: the rate belongs to a cgroup, so the selector names a unit, a \
                 cgroup, a container or pods rather than an executable",
                self.id
            )));
        }
        self.selector
            .validate()
            .map_err(|e| QosError::InvalidCgroupShaping(format!("rule {}: {e}", self.id)))
    }

    /// The horizon in nanoseconds, as the datapath reads it.
    #[must_use]
    pub fn horizon_ns(&self) -> u64 {
        u64::from(self.horizon_ms) * 1_000_000
    }
}

/// Check a whole rule set: every rule on its own, and no id twice.
///
/// # Errors
///
/// The first refusal [`CgroupShapingRule::validate`] returns, or
/// [`QosError::DuplicateCgroupShaping`].
pub fn validate_rules(rules: &[CgroupShapingRule]) -> Result<(), QosError> {
    let mut seen = HashSet::new();
    for rule in rules {
        rule.validate()?;
        if !seen.insert(rule.id.as_str()) {
            return Err(QosError::DuplicateCgroupShaping {
                id: rule.id.clone(),
            });
        }
    }
    Ok(())
}

/// The rule a workload falls under: the first one in file order whose
/// selector matches, so a narrow rule written above a wide one wins.
#[must_use]
pub fn rule_for<'a>(
    rules: &'a [CgroupShapingRule],
    facts: &WorkloadFacts<'_>,
) -> Option<&'a CgroupShapingRule> {
    rules.iter().find(|rule| rule.selector.matches(facts))
}

/// One qdisc of an interface, as the kernel's dump lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QdiscEntry {
    pub handle: u32,
    pub parent: u32,
    pub kind: String,
}

/// Whether departure times are honoured on one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdtSupport {
    /// The root qdisc's kind, `none` when the dump listed no root.
    pub root: String,
    /// Whether every packet leaving the interface goes through an `fq`
    /// qdisc, which is the one that holds a packet until its departure time.
    pub honoured: bool,
}

/// Read whether an interface's qdiscs honour a departure time.
///
/// They do when the root is `fq`, or when the root is `mq` and every one of
/// its children is `fq`, which is how a multi-queue NIC carries it. Any
/// other root sends the packet when it is dequeued, so a timestamp shapes
/// nothing there.
#[must_use]
pub fn edt_support(entries: &[QdiscEntry]) -> EdtSupport {
    let Some(root) = entries.iter().find(|entry| entry.parent == TC_H_ROOT) else {
        return EdtSupport {
            root: "none".to_string(),
            honoured: false,
        };
    };
    let honoured = match root.kind.as_str() {
        "fq" => true,
        "mq" => {
            let major = root.handle >> 16;
            let mut children = entries
                .iter()
                .filter(|entry| entry.parent != TC_H_ROOT && entry.parent >> 16 == major)
                .peekable();
            children.peek().is_some() && children.all(|child| child.kind == "fq")
        }
        _ => false,
    };
    EdtSupport {
        root: root.kind.clone(),
        honoured,
    }
}

/// What the datapath counted for one cgroup, summed across CPUs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupShapingCounters {
    pub bytes: u64,
    pub packets: u64,
    pub dropped_horizon: u64,
}

/// The rate a cgroup achieved between two readings, in bits per second.
///
/// `None` when the second reading is not later than the first, and when the
/// byte count went backwards, which is a cgroup whose entry was removed and
/// created again rather than one that sent a negative amount.
#[must_use]
pub fn achieved_bps(
    before_bytes: u64,
    before_ns: u64,
    after_bytes: u64,
    after_ns: u64,
) -> Option<u64> {
    if after_ns <= before_ns || after_bytes < before_bytes {
        return None;
    }
    let bits = u128::from(after_bytes - before_bytes) * 8;
    let elapsed = u128::from(after_ns - before_ns);
    u64::try_from(bits * 1_000_000_000 / elapsed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::workload::KubernetesMatchers;

    fn rule(id: &str, cgroup: &str, rate_bps: u64) -> CgroupShapingRule {
        CgroupShapingRule {
            id: id.to_string(),
            selector: WorkloadSelector::with_kubernetes(
                None,
                None,
                Some(cgroup.to_string()),
                None,
                KubernetesMatchers::default(),
            )
            .unwrap_or_default(),
            rate_bps,
            horizon_ms: DEFAULT_HORIZON_MS,
        }
    }

    fn entry(handle: u32, parent: u32, kind: &str) -> QdiscEntry {
        QdiscEntry {
            handle,
            parent,
            kind: kind.to_string(),
        }
    }

    #[test]
    fn a_rule_with_a_rate_and_a_cgroup_is_accepted() {
        assert!(
            rule("api", "/system.slice/api.service", 100_000_000)
                .validate()
                .is_ok()
        );
    }

    #[test]
    fn a_rate_below_one_byte_per_millisecond_is_refused() {
        let err = rule("api", "/x", MIN_RATE_BPS - 1).validate();
        assert!(matches!(err, Err(QosError::InvalidCgroupShaping(_))));
    }

    #[test]
    fn a_horizon_of_zero_or_past_the_ceiling_is_refused() {
        let mut r = rule("api", "/x", MIN_RATE_BPS);
        r.horizon_ms = 0;
        assert!(r.validate().is_err());
        r.horizon_ms = MAX_HORIZON_MS + 1;
        assert!(r.validate().is_err());
        r.horizon_ms = MAX_HORIZON_MS;
        assert!(r.validate().is_ok());
    }

    #[test]
    fn a_selector_naming_an_executable_is_refused() {
        let mut r = rule("api", "/x", MIN_RATE_BPS);
        r.selector = WorkloadSelector::with_kubernetes(
            Some("/usr/bin/curl".to_string()),
            None,
            None,
            None,
            KubernetesMatchers::default(),
        )
        .unwrap_or_default();
        let err = r.validate().map_err(|e| e.to_string());
        assert!(err.is_err_and(|e| e.contains("executable")));
    }

    #[test]
    fn an_empty_selector_is_refused() {
        let mut r = rule("api", "/x", MIN_RATE_BPS);
        r.selector = WorkloadSelector::default();
        assert!(r.validate().is_err());
    }

    #[test]
    fn the_same_id_twice_is_refused() {
        let rules = [rule("a", "/x", MIN_RATE_BPS), rule("a", "/y", MIN_RATE_BPS)];
        assert!(matches!(
            validate_rules(&rules),
            Err(QosError::DuplicateCgroupShaping { .. })
        ));
    }

    #[test]
    fn the_first_matching_rule_wins() {
        let rules = [
            rule("narrow", "/kubepods/burstable/pod1", 1_000_000),
            rule("wide", "/kubepods", 10_000_000),
        ];
        let facts = WorkloadFacts {
            cgroup: Some("/kubepods/burstable/pod1/abc"),
            ..WorkloadFacts::default()
        };
        assert_eq!(
            rule_for(&rules, &facts).map(|r| r.id.as_str()),
            Some("narrow")
        );
        let other = WorkloadFacts {
            cgroup: Some("/system.slice/sshd.service"),
            ..WorkloadFacts::default()
        };
        assert!(rule_for(&rules, &other).is_none());
    }

    #[test]
    fn the_horizon_reads_in_nanoseconds() {
        assert_eq!(rule("a", "/x", MIN_RATE_BPS).horizon_ns(), 2_000_000_000);
    }

    #[test]
    fn an_fq_root_honours_departure_times() {
        let support = edt_support(&[entry(0x8001_0000, TC_H_ROOT, "fq")]);
        assert_eq!(
            support,
            EdtSupport {
                root: "fq".to_string(),
                honoured: true
            }
        );
    }

    #[test]
    fn an_mq_root_honours_them_only_when_every_child_is_fq() {
        let all_fq = [
            entry(0x8001_0000, TC_H_ROOT, "mq"),
            entry(0, 0x8001_0001, "fq"),
            entry(0, 0x8001_0002, "fq"),
        ];
        assert!(edt_support(&all_fq).honoured);

        let mixed = [
            entry(0x8001_0000, TC_H_ROOT, "mq"),
            entry(0, 0x8001_0001, "fq"),
            entry(0, 0x8001_0002, "fq_codel"),
        ];
        assert!(!edt_support(&mixed).honoured);

        let childless = [entry(0x8001_0000, TC_H_ROOT, "mq")];
        assert!(!edt_support(&childless).honoured);
    }

    #[test]
    fn the_clsact_hook_is_not_a_child_of_the_root() {
        let entries = [
            entry(0x8001_0000, TC_H_ROOT, "mq"),
            entry(0, 0x8001_0001, "fq"),
            entry(0xFFFF_0000, 0xFFFF_FFF1, "clsact"),
        ];
        assert!(edt_support(&entries).honoured);
    }

    #[test]
    fn any_other_root_or_none_at_all_sends_without_waiting() {
        let codel = edt_support(&[entry(0, TC_H_ROOT, "fq_codel")]);
        assert_eq!(codel.root, "fq_codel");
        assert!(!codel.honoured);
        let none = edt_support(&[]);
        assert_eq!(none.root, "none");
        assert!(!none.honoured);
    }

    #[test]
    fn the_achieved_rate_is_the_byte_delta_over_the_time_delta() {
        // 12.5 MB in one second is 100 Mbps.
        assert_eq!(
            achieved_bps(0, 0, 12_500_000, 1_000_000_000),
            Some(100_000_000)
        );
        assert_eq!(
            achieved_bps(1_000, 5_000_000_000, 1_000 + 1_250_000, 7_000_000_000),
            Some(5_000_000)
        );
    }

    #[test]
    fn no_rate_is_read_from_a_reset_or_from_no_time_at_all() {
        assert_eq!(achieved_bps(10, 1, 5, 2), None);
        assert_eq!(achieved_bps(0, 5, 10, 5), None);
    }
}
