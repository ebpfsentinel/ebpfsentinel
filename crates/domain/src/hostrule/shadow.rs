//! What a host rule in shadow mode would have done.
//!
//! A rule is in shadow unless it says otherwise: it is evaluated like any
//! other, and where it would have raised an alert or stopped a process it
//! does neither and counts instead, per workload it would have hit. That
//! reading is what an operator weighs before trusting the rule, and the
//! firewall's shadow rules and these share the mode.

use std::collections::BTreeMap;

use serde::Serialize;

use super::rule::HostRuleSet;
use crate::firewall::entity::RuleMode;

/// The most workloads one rule's reading names; events about any other are
/// counted without a name.
pub const HOST_RULE_SHADOW_WORKLOADS_MAX: usize = 32;

/// How far apart two starts may be and still name one reading.
///
/// A browser reads the figure as a double, which holds a nanosecond count of
/// today to within a few hundred nanoseconds, so an exact comparison would
/// refuse every promotion made from a console. The readings start once per
/// rule set, which no two loads share within a microsecond.
pub const HOST_RULE_SAME_READING_NS: u64 = 1_000;

/// Why a rule was not put in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromotionRefused {
    /// No rule carries the identifier.
    Unknown,
    /// The rule already acts.
    AlreadyInForce,
    /// The readings started at another time than the one the caller weighed.
    StaleReading { since_ns: u64 },
}

impl std::fmt::Display for PromotionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unknown => f.write_str("no host rule carries this identifier"),
            Self::AlreadyInForce => f.write_str("the rule is already in force"),
            Self::StaleReading { since_ns } => write!(
                f,
                "the readings started afresh at {since_ns} since that reading; read them again"
            ),
        }
    }
}

/// Events a shadow rule matched about one workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkloadHits {
    /// The container, else the cgroup, else the systemd unit; `None` for a
    /// process in none of them.
    pub workload: Option<String>,
    pub events: u64,
}

/// What one shadow rule would have done since the reading started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostShadowReading {
    /// Events on which the rule would have acted.
    pub events: u64,
    /// Those events by workload, the first ones seen, bounded.
    pub workloads: Vec<WorkloadHits>,
    /// Events about a workload that came after the sample was full.
    pub unsampled: u64,
}

impl HostShadowReading {
    /// Count one event about `workload`, in the bounded sample when it fits.
    pub fn record(&mut self, workload: Option<&str>) {
        self.events += 1;
        if let Some(hits) = self
            .workloads
            .iter_mut()
            .find(|h| h.workload.as_deref() == workload)
        {
            hits.events += 1;
        } else if self.workloads.len() < HOST_RULE_SHADOW_WORKLOADS_MAX {
            self.workloads.push(WorkloadHits {
                workload: workload.map(str::to_owned),
                events: 1,
            });
        } else {
            self.unsampled += 1;
        }
    }
}

/// Every rule's mode, and the reading of each one in shadow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostShadowBook {
    since_ns: u64,
    readings: BTreeMap<String, Option<HostShadowReading>>,
}

impl HostShadowBook {
    /// The modes `rules` were written with, the readings starting at
    /// `since_ns`.
    #[must_use]
    pub fn new(rules: &HostRuleSet, since_ns: u64) -> Self {
        let readings = rules
            .rules()
            .iter()
            .map(|rule| {
                let reading = (rule.spec.mode == RuleMode::Shadow).then(HostShadowReading::default);
                (rule.id().to_owned(), reading)
            })
            .collect();
        Self { since_ns, readings }
    }

    /// The book for `next`, which replaces `previous`, the readings starting
    /// again at `since_ns`.
    ///
    /// A rule promoted here stays in force when `next` carries it written
    /// exactly as it was; a rule that changed starts in the mode it is written
    /// with, because a promotion was decided on a reading of the rule as it
    /// stood. Every reading restarts: one taken of the old set says nothing of
    /// what the new one would have done.
    #[must_use]
    pub fn renewed(&self, previous: &HostRuleSet, next: &HostRuleSet, since_ns: u64) -> Self {
        let mut book = Self::new(next, since_ns);
        for rule in next.rules() {
            let promoted_here = self.mode(rule.id()) == Some(RuleMode::Enforce)
                && previous
                    .rules()
                    .iter()
                    .any(|old| old.id() == rule.id() && old.spec == rule.spec);
            if promoted_here && let Some(slot) = book.readings.get_mut(rule.id()) {
                *slot = None;
            }
        }
        book
    }

    /// When the readings started.
    #[must_use]
    pub fn since_ns(&self) -> u64 {
        self.since_ns
    }

    /// The mode `id` is in now, `None` for no such rule.
    #[must_use]
    pub fn mode(&self, id: &str) -> Option<RuleMode> {
        self.readings.get(id).map(|reading| match reading {
            Some(_) => RuleMode::Shadow,
            None => RuleMode::Enforce,
        })
    }

    /// The reading of `id`, `None` for a rule in force or no such rule.
    #[must_use]
    pub fn reading(&self, id: &str) -> Option<&HostShadowReading> {
        self.readings.get(id).and_then(Option::as_ref)
    }

    /// Put `id` in force, on the reading that started at `seen_since_ns`.
    ///
    /// Returns the reading as it stood when the rule stopped counting, which
    /// is the one the decision is recorded against.
    ///
    /// # Errors
    ///
    /// [`PromotionRefused`] for an unknown rule, a rule already in force, or
    /// readings that started at another time than `seen_since_ns`.
    pub fn promote(
        &mut self,
        id: &str,
        seen_since_ns: u64,
    ) -> Result<HostShadowReading, PromotionRefused> {
        let since_ns = self.since_ns;
        let slot = self.readings.get_mut(id).ok_or(PromotionRefused::Unknown)?;
        if slot.is_none() {
            return Err(PromotionRefused::AlreadyInForce);
        }
        if since_ns.abs_diff(seen_since_ns) >= HOST_RULE_SAME_READING_NS {
            return Err(PromotionRefused::StaleReading { since_ns });
        }
        slot.take().ok_or(PromotionRefused::AlreadyInForce)
    }

    /// Count an event `id` would have acted on, when it is in shadow.
    /// `false` for a rule in force, which acts.
    pub fn record(&mut self, id: &str, workload: Option<&str>) -> bool {
        match self.readings.get_mut(id) {
            Some(Some(reading)) => {
                reading.record(workload);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostrule::HostRuleSpec;

    fn rules(json: &str) -> HostRuleSet {
        let specs: Vec<HostRuleSpec> = serde_json::from_str(json).unwrap();
        HostRuleSet::compile(specs).unwrap()
    }

    const TWO: &str = r#"[
        {"id":"quiet","when":{"process.starts":{"exe":"/bin/sh"}}},
        {"id":"loud","mode":"enforce","when":{"process.starts":{"exe":"/bin/sh"}}}
    ]"#;

    #[test]
    fn a_promotion_survives_a_new_set_only_for_the_rule_as_it_was_written() {
        let before = rules(
            r#"[
            {"id":"kept","when":{"process.starts":{"exe":"/bin/sh"}}},
            {"id":"changed","when":{"process.starts":{"exe":"/bin/sh"}}},
            {"id":"untouched","when":{"process.starts":{"exe":"/bin/sh"}}}
        ]"#,
        );
        let mut book = HostShadowBook::new(&before, 5);
        book.record("untouched", None);
        book.promote("kept", 5).unwrap();
        book.promote("changed", 5).unwrap();
        let after = rules(
            r#"[
            {"id":"kept","when":{"process.starts":{"exe":"/bin/sh"}}},
            {"id":"changed","when":{"process.starts":{"exe":"/bin/bash"}}},
            {"id":"untouched","when":{"process.starts":{"exe":"/bin/sh"}}},
            {"id":"new","when":{"process.starts":{"exe":"/bin/sh"}}}
        ]"#,
        );
        let renewed = book.renewed(&before, &after, 9);
        assert_eq!(renewed.since_ns(), 9);
        assert_eq!(renewed.mode("kept"), Some(RuleMode::Enforce));
        assert_eq!(renewed.mode("changed"), Some(RuleMode::Shadow));
        assert_eq!(renewed.mode("new"), Some(RuleMode::Shadow));
        assert_eq!(renewed.reading("untouched").unwrap().events, 0);
    }

    #[test]
    fn a_rule_is_in_shadow_unless_it_says_otherwise() {
        let book = HostShadowBook::new(&rules(TWO), 7);
        assert_eq!(book.mode("quiet"), Some(RuleMode::Shadow));
        assert_eq!(book.mode("loud"), Some(RuleMode::Enforce));
        assert_eq!(book.mode("nope"), None);
        assert_eq!(book.since_ns(), 7);
    }

    #[test]
    fn a_shadow_rule_counts_by_workload_and_a_rule_in_force_does_not() {
        let mut book = HostShadowBook::new(&rules(TWO), 0);
        assert!(book.record("quiet", Some("web")));
        assert!(book.record("quiet", Some("web")));
        assert!(book.record("quiet", None));
        assert!(!book.record("loud", Some("web")), "a rule in force acts");
        assert!(!book.record("nope", None));
        let reading = book.reading("quiet").unwrap();
        assert_eq!(reading.events, 3);
        assert_eq!(
            reading.workloads,
            vec![
                WorkloadHits {
                    workload: Some("web".into()),
                    events: 2
                },
                WorkloadHits {
                    workload: None,
                    events: 1
                },
            ]
        );
        assert!(book.reading("loud").is_none());
    }

    #[test]
    fn the_workloads_named_are_bounded_and_the_rest_counted() {
        let mut book = HostShadowBook::new(&rules(TWO), 0);
        for n in 0..HOST_RULE_SHADOW_WORKLOADS_MAX + 5 {
            book.record("quiet", Some(&format!("c{n}")));
        }
        book.record("quiet", Some("c0"));
        let reading = book.reading("quiet").unwrap();
        assert_eq!(reading.workloads.len(), HOST_RULE_SHADOW_WORKLOADS_MAX);
        assert_eq!(reading.unsampled, 5);
        assert_eq!(
            reading.workloads[0].events, 2,
            "a named workload keeps counting"
        );
        assert_eq!(reading.events, HOST_RULE_SHADOW_WORKLOADS_MAX as u64 + 6);
    }

    #[test]
    fn a_promotion_names_the_reading_and_the_rule_then_acts() {
        let mut book = HostShadowBook::new(&rules(TWO), 1_000_000);
        book.record("quiet", Some("web"));
        assert_eq!(
            book.promote("quiet", 5_000),
            Err(PromotionRefused::StaleReading {
                since_ns: 1_000_000
            })
        );
        assert_eq!(
            book.promote("nope", 1_000_000),
            Err(PromotionRefused::Unknown)
        );
        assert_eq!(
            book.promote("loud", 1_000_000),
            Err(PromotionRefused::AlreadyInForce)
        );
        let reading = book.promote("quiet", 1_000_400).unwrap();
        assert_eq!(reading.events, 1);
        assert_eq!(book.mode("quiet"), Some(RuleMode::Enforce));
        assert!(!book.record("quiet", Some("web")), "a promoted rule acts");
        assert_eq!(
            book.promote("quiet", 1_000_000),
            Err(PromotionRefused::AlreadyInForce)
        );
    }
}
