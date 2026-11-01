//! Host rules: an intention, a map of matchers and what to do.
//!
//! Off until a rule is written: an empty list loads nothing and reads
//! nothing. Every rule is compiled when the file is read, against the
//! intentions and fields the agent ships, so a rule naming a field its
//! intention does not carry fails at boot with the fields that exist rather
//! than never matching.

use domain::hostrule::{HostRuleSet, HostRuleSpec};
use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Most rules one agent loads.
pub const MAX_HOST_RULES: usize = 1_024;

/// The host rules block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HostRulesConfig {
    /// The rules, each evaluated alone against every event of the
    /// intentions it names.
    pub rules: Vec<HostRuleSpec>,
}

impl HostRulesConfig {
    /// The rules, compiled.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] naming the first rule that does
    /// not load and why, or an identifier used twice.
    pub fn compile(&self) -> Result<HostRuleSet, ConfigError> {
        if self.rules.len() > MAX_HOST_RULES {
            return Err(ConfigError::Validation {
                field: "host_rules.rules".to_string(),
                message: format!("{} rules, more than {MAX_HOST_RULES}", self.rules.len()),
            });
        }
        HostRuleSet::compile(self.rules.clone()).map_err(|e| ConfigError::Validation {
            field: "host_rules.rules".to_string(),
            message: e.to_string(),
        })
    }

    /// Checks every rule hard enough that a wrong one fails at boot.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::compile`] refuses.
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.compile().map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use domain::hostrule::HostRuleAction;

    use super::*;

    fn parse(yaml: &str) -> Result<HostRulesConfig, serde_norway::Error> {
        serde_norway::from_str(yaml)
    }

    #[test]
    fn no_rule_by_default() {
        let config = HostRulesConfig::default();
        assert!(config.compile().unwrap().is_empty());
    }

    #[test]
    fn a_rule_reads_from_yaml_the_way_it_is_documented() {
        let config = parse(
            r"
rules:
  - id: shell-from-web-server
    description: a shell started by the web server
    severity: high
    workload:
      parent: /usr/sbin/nginx
    when:
      process.starts:
        exe: [/bin/sh, /bin/bash, /usr/bin/dash]
        uid_ne_field: parent_uid
    then: [alert, kill_process]
  - id: tmp-exec
    when:
      any_of:
        - process.starts:
            exe_matches: ['/tmp/*', '/dev/shm/*']
        - process.starts:
            exe_on_disk: false
",
        )
        .unwrap();
        let set = config.compile().unwrap();
        assert_eq!(set.rules().len(), 2);
        assert_eq!(
            set.rules()[0].spec.then,
            vec![HostRuleAction::Alert, HostRuleAction::KillProcess]
        );
        assert!(set.rules()[0].kills());
    }

    #[test]
    fn a_rule_that_does_not_load_fails_validation_naming_it() {
        let config = parse(
            r"
rules:
  - id: wrong
    when:
      process.starts:
        remote_port: 22
",
        )
        .unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("host rule `wrong`"), "{err}");
        assert!(err.contains("has no field `remote_port`"), "{err}");
    }

    #[test]
    fn an_unknown_key_beside_the_rules_is_refused() {
        assert!(parse("rules: []\nenabled: true\n").is_err());
    }

    #[test]
    fn an_expression_beside_the_rule_is_refused_naming_the_limit() {
        let config =
            parse("rules:\n  - id: x\n    when:\n      process.starts: {}\n    match: 'a && b'\n")
                .unwrap();
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("there is no expression language"), "{err}");
    }
}
