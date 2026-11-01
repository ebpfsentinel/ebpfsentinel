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
    fn record(&mut self, workload: Option<&str>) {
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
}
