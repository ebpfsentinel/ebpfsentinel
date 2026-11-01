//! Host rules: an intention, a map of matchers and what to do.
//!
//! Off until a rule is written or the shipped rules are asked for: an empty
//! list loads nothing and reads nothing. Every rule is compiled when the file is read, against the
//! intentions and fields the agent ships, so a rule naming a field its
//! intention does not carry fails at boot with the fields that exist rather
//! than never matching.

use domain::hostrule::{HostRuleSet, HostRuleSpec};
use serde::{Deserialize, Serialize};

use super::ConfigError;

/// Most rules one agent loads.
pub const MAX_HOST_RULES: usize = 1_024;

/// The rules the agent ships, in the syntax an operator writes them in.
const SHIPPED_RULES: &str = include_str!("host_rules_shipped.yaml");

/// The shipped rules file: the same block, rules only.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShippedRules {
    rules: Vec<HostRuleSpec>,
}

/// The rules the agent ships, each in shadow until promoted.
///
/// # Errors
///
/// Returns [`ConfigError::Validation`] if the shipped file does not parse,
/// which a test of this module asserts it does.
pub fn shipped_rules() -> Result<Vec<HostRuleSpec>, ConfigError> {
    serde_norway::from_str::<ShippedRules>(SHIPPED_RULES)
        .map(|shipped| shipped.rules)
        .map_err(|e| ConfigError::Validation {
            field: "host_rules.shipped".to_string(),
            message: format!("the shipped rules do not parse: {e}"),
        })
}

/// The host rules block.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct HostRulesConfig {
    /// The rules, each evaluated alone against every event of the
    /// intentions it names.
    pub rules: Vec<HostRuleSpec>,
    /// Load the rules the agent ships beside these, each in shadow.
    pub shipped: bool,
}

impl HostRulesConfig {
    /// The rules, compiled.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] naming the first rule that does
    /// not load and why, or an identifier used twice.
    pub fn compile(&self) -> Result<HostRuleSet, ConfigError> {
        let mut rules = if self.shipped {
            shipped_rules()?
        } else {
            Vec::new()
        };
        rules.extend(self.rules.iter().cloned());
        if rules.len() > MAX_HOST_RULES {
            return Err(ConfigError::Validation {
                field: "host_rules.rules".to_string(),
                message: format!("{} rules, more than {MAX_HOST_RULES}", rules.len()),
            });
        }
        HostRuleSet::compile(rules).map_err(|e| ConfigError::Validation {
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

    /// Whether any rule is asked for, written or shipped.
    #[must_use]
    pub fn any(&self) -> bool {
        self.shipped || !self.rules.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use domain::firewall::entity::RuleMode;
    use domain::hostrule::{FieldValue, HostRuleAction, Intent, IntentEvent};

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
    fn the_shipped_rules_load_in_shadow_and_each_says_what_it_is() {
        let shipped = shipped_rules().unwrap();
        assert_eq!(shipped.len(), 15);
        let config = parse("shipped: true\n").unwrap();
        assert!(config.any());
        let set = config.compile().unwrap();
        assert_eq!(set.rules().len(), 15);
        for rule in set.rules() {
            assert_eq!(rule.spec.mode, RuleMode::Shadow, "{}", rule.spec.id);
            assert!(rule.spec.id.starts_with("shipped-"), "{}", rule.spec.id);
            assert!(rule.spec.description.is_some(), "{}", rule.spec.id);
            assert!(!rule.kills(), "{} stops nothing", rule.spec.id);
        }
    }

    fn starts(exe: &str, parent: &str, on_disk: bool) -> IntentEvent {
        IntentEvent::new(Intent::ProcessStarts)
            .with("exe", FieldValue::Text(exe.to_string()))
            .unwrap()
            .with("parent_exe", FieldValue::Text(parent.to_string()))
            .unwrap()
            .with("exe_on_disk", FieldValue::Boolean(on_disk))
            .unwrap()
    }

    #[test]
    fn the_shipped_single_step_rules_fire_on_their_case_and_not_on_a_daemon() {
        let set = parse("shipped: true\n").unwrap().compile().unwrap();
        let rule = |id: &str| {
            set.rules()
                .iter()
                .find(|r| r.spec.id == id)
                .unwrap_or_else(|| panic!("{id} is shipped"))
        };
        let changes = |path: &str| {
            IntentEvent::new(Intent::FileChanges)
                .with("path", FieldValue::Text(path.to_string()))
                .unwrap()
        };
        let permissions = |previous: i64, mode: i64| {
            IntentEvent::new(Intent::FilePermissionsChange)
                .with("path", FieldValue::Text("/usr/local/bin/x".to_string()))
                .unwrap()
                .with("previous_mode", FieldValue::Integer(previous))
                .unwrap()
                .with("mode", FieldValue::Integer(mode))
                .unwrap()
        };
        let cases = [
            (
                "shipped-shell-from-web-server",
                starts("/bin/bash", "/usr/sbin/nginx", true),
                starts("/bin/bash", "/usr/sbin/sshd", true),
            ),
            (
                "shipped-fileless-exec",
                starts("/memfd:x (deleted)", "/bin/bash", false),
                starts("/usr/bin/ls", "/bin/bash", true),
            ),
            (
                "shipped-exec-from-temporary-directory",
                starts("/dev/shm/.x", "/bin/sh", true),
                starts("/usr/bin/tmpwatch", "/usr/sbin/cron", true),
            ),
            (
                "shipped-ssh-authorized-keys-change",
                changes("/root/.ssh/authorized_keys"),
                changes("/root/.ssh/known_hosts"),
            ),
            (
                "shipped-preload-change",
                changes("/etc/ld.so.preload"),
                changes("/etc/ld.so.conf"),
            ),
            (
                "shipped-setuid-bit-set",
                permissions(0o755, 0o4755),
                permissions(0o4755, 0o4750),
            ),
        ];
        for (id, hit, miss) in &cases {
            assert!(rule(id).matches(hit, None), "{id} fires on its case");
            assert!(!rule(id).matches(miss, None), "{id} stays quiet");
        }
    }

    #[test]
    fn written_rules_sit_beside_the_shipped_ones_and_may_not_take_their_names() {
        let config =
            parse("shipped: true\nrules:\n  - id: mine\n    when:\n      process.starts: {}\n")
                .unwrap();
        assert_eq!(config.compile().unwrap().rules().len(), 16);
        let clash = parse(
            "shipped: true\nrules:\n  - id: shipped-hidden-port\n    when:\n      port.hidden: {}\n",
        )
        .unwrap();
        assert!(clash.validate().is_err());
    }

    #[test]
    fn nothing_is_shipped_unless_asked_for() {
        let config = parse("rules: []\n").unwrap();
        assert!(!config.any());
        assert!(config.compile().unwrap().is_empty());
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
