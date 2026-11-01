//! Exceptions: the workloads a host rule leaves alone.
//!
//! A rule written for the whole host meets the one workload that does the
//! thing on purpose - the backup job that reads every file, the build pod that
//! starts compilers - and the choice without an exception is between editing
//! the rule, which forks it from the library it came from, and turning it off.
//! An exception names the workload with the same selector a rule uses and the
//! rules it silences, and leaves the rule as written.
//!
//! A silenced match is neither an alert nor a shadow reading: the reading is
//! what a rule would do once enforced, and an exempted workload is exactly
//! what enforcing it will not touch.

use crate::firewall::workload::{WorkloadFacts, WorkloadSelector};

use super::HostRuleError;
use super::rule::{HOST_RULE_LIST_MAX, check_id};

/// The most exceptions one agent carries, so a list read from a file cannot
/// make every match walk an unbounded loop.
pub const HOST_RULE_EXCEPTIONS_MAX: usize = 256;

/// A workload one or more host rules leave alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRuleException {
    id: String,
    rules: Vec<String>,
    selector: WorkloadSelector,
}

impl HostRuleException {
    /// An exception named `id`, silencing `rules` - every rule when the list
    /// is empty - for the workloads `selector` matches.
    ///
    /// # Errors
    ///
    /// Refuses an identifier a rule could not carry, a list of rules longer
    /// than a rule's own lists, and a selector a host rule would refuse.
    pub fn new(
        id: impl Into<String>,
        rules: Vec<String>,
        selector: WorkloadSelector,
    ) -> Result<Self, HostRuleError> {
        let id = id.into();
        let refuse = |reason: String| HostRuleError::Exception {
            id: id.clone(),
            reason,
        };
        check_id(&id).map_err(refuse)?;
        if rules.len() > HOST_RULE_LIST_MAX {
            return Err(refuse(format!(
                "it names {} rules, and the most it may name is {HOST_RULE_LIST_MAX}",
                rules.len()
            )));
        }
        if let Some(rule) = rules.iter().find(|rule| check_id(rule).is_err()) {
            return Err(refuse(format!("`{rule}` is not a host rule identifier")));
        }
        if selector.guest.is_some() {
            return Err(refuse(
                "a guest runs its own kernel, so no host rule ever matches one to silence"
                    .to_string(),
            ));
        }
        selector
            .validate()
            .map_err(|e| refuse(format!("workload: {e}")))?;
        Ok(Self {
            id,
            rules,
            selector,
        })
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The rules it silences; empty for every rule.
    #[must_use]
    pub fn rules(&self) -> &[String] {
        &self.rules
    }

    #[must_use]
    pub fn selector(&self) -> &WorkloadSelector {
        &self.selector
    }

    /// Whether a match of `rule` by the workload `facts` describes is left
    /// alone.
    #[must_use]
    pub fn silences(&self, rule: &str, facts: &WorkloadFacts<'_>) -> bool {
        (self.rules.is_empty() || self.rules.iter().any(|named| named == rule))
            && self.selector.matches(facts)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn selector(yaml: &str) -> WorkloadSelector {
        serde_json::from_str(yaml).unwrap()
    }

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn it_silences_the_rules_it_names_for_the_workloads_it_selects() {
        let exception = HostRuleException::new(
            "backup",
            vec!["mass-read".into()],
            selector(r#"{"namespaces":{"match_labels":{"kubernetes.io/metadata.name":"backup"}}}"#),
        )
        .unwrap();
        let backup = labels(&[("kubernetes.io/metadata.name", "backup")]);
        let web = labels(&[("kubernetes.io/metadata.name", "web")]);
        let facts = |ns| WorkloadFacts {
            namespace_labels: Some(ns),
            ..WorkloadFacts::default()
        };
        assert!(exception.silences("mass-read", &facts(&backup)));
        assert!(!exception.silences("mass-read", &facts(&web)));
        assert!(!exception.silences("web-shell", &facts(&backup)));
    }

    #[test]
    fn an_empty_list_silences_every_rule() {
        let exception =
            HostRuleException::new("ci", Vec::new(), selector(r#"{"exe":"/usr/bin/make"}"#))
                .unwrap();
        let facts = WorkloadFacts {
            exe: Some("/usr/bin/make"),
            ..WorkloadFacts::default()
        };
        assert!(exception.silences("anything", &facts));
    }

    #[test]
    fn what_could_never_silence_anything_is_refused() {
        let pod = selector(r#"{"exe":"/bin/sh"}"#);
        for (id, rules, selector) in [
            ("", Vec::new(), pod.clone()),
            ("bad id", Vec::new(), pod.clone()),
            ("ok", vec!["not a rule".to_string()], pod.clone()),
            ("ok", Vec::new(), WorkloadSelector::default()),
            ("ok", Vec::new(), selector(r#"{"guest":"vm-1"}"#)),
        ] {
            assert!(
                matches!(
                    HostRuleException::new(id, rules, selector),
                    Err(HostRuleError::Exception { .. })
                ),
                "{id}"
            );
        }
        let many = (0..=HOST_RULE_LIST_MAX).map(|i| format!("r{i}")).collect();
        assert!(HostRuleException::new("ok", many, pod).is_err());
    }
}
