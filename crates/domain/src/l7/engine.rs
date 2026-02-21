use crate::common::entity::RuleId;
use crate::common::error::DomainError;
use ebpf_common::event::PacketEvent;

use super::entity::{L7Rule, ParsedProtocol};
use super::error::L7Error;

/// In-memory L7 firewall rule engine.
///
/// Rules are stored sorted by ascending priority (lowest number = highest priority).
/// Evaluation returns the first matching enabled rule.
#[derive(Debug)]
pub struct L7Engine {
    rules: Vec<L7Rule>,
}

impl L7Engine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Evaluate a parsed L7 event against all loaded rules.
    ///
    /// Filters enabled rules, checks L3/L4 headers then L7 content.
    /// Returns the index and reference to the first matching rule, or `None`.
    pub fn evaluate(
        &self,
        header: &PacketEvent,
        parsed: &ParsedProtocol,
    ) -> Option<(usize, &L7Rule)> {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.enabled)
            .find(|(_, r)| r.matches_l3l4(header) && r.matches_l7(parsed))
    }

    /// Add a rule. Validates the rule and rejects duplicates.
    pub fn add_rule(&mut self, rule: L7Rule) -> Result<(), DomainError> {
        rule.validate()?;

        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(L7Error::DuplicateRule {
                id: rule.id.to_string(),
            }
            .into());
        }

        self.rules.push(rule);
        self.sort_rules();
        Ok(())
    }

    /// Remove a rule by ID.
    pub fn remove_rule(&mut self, id: &RuleId) -> Result<(), DomainError> {
        let pos = self
            .rules
            .iter()
            .position(|r| r.id == *id)
            .ok_or_else(|| L7Error::RuleNotFound { id: id.to_string() })?;
        self.rules.remove(pos);
        Ok(())
    }

    /// Replace all rules atomically. Validates all rules before replacing.
    pub fn reload(&mut self, rules: Vec<L7Rule>) -> Result<(), DomainError> {
        for rule in &rules {
            rule.validate()?;
        }

        // Check for duplicate IDs
        for (i, rule) in rules.iter().enumerate() {
            if rules[i + 1..].iter().any(|r| r.id == rule.id) {
                return Err(L7Error::DuplicateRule {
                    id: rule.id.to_string(),
                }
                .into());
            }
        }

        self.rules = rules;
        self.sort_rules();
        Ok(())
    }

    /// Return a slice of all loaded rules (sorted by priority).
    pub fn rules(&self) -> &[L7Rule] {
        &self.rules
    }

    /// Return the number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    fn sort_rules(&mut self) {
        self.rules.sort_by_key(|r| r.priority);
    }
}

impl Default for L7Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::RuleId;
    use crate::firewall::entity::{FirewallAction, PortRange};
    use crate::l7::domain_matcher::DomainMatcher;
    use crate::l7::entity::{HttpRequest, L7Matcher, ParsedProtocol, SmtpCommand, TlsClientHello};

    fn make_l7_rule(id: &str, priority: u32, action: FirewallAction) -> L7Rule {
        L7Rule {
            id: RuleId(id.to_string()),
            priority,
            action,
            matcher: L7Matcher::Http {
                method: None,
                path_pattern: None,
                host_pattern: None,
                content_type: None,
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        }
    }

    fn make_header() -> PacketEvent {
        PacketEvent {
            timestamp_ns: 0,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 80,
            protocol: 6,
            event_type: 6,
            action: 0,
            flags: 0,
            rule_id: 0,
            vlan_id: 0,
            cpu_id: 0,
            socket_cookie: 0,
        }
    }

    fn make_http_parsed() -> ParsedProtocol {
        ParsedProtocol::Http(HttpRequest {
            method: "GET".to_string(),
            path: "/api/users".to_string(),
            version: "HTTP/1.1".to_string(),
            host: Some("example.com".to_string()),
            content_type: None,
            headers: vec![],
        })
    }

    // ── Empty engine ───────────────────────────────────────────────

    #[test]
    fn empty_engine_returns_none() {
        let engine = L7Engine::new();
        assert!(
            engine
                .evaluate(&make_header(), &make_http_parsed())
                .is_none()
        );
    }

    #[test]
    fn default_is_empty() {
        let engine = L7Engine::default();
        assert_eq!(engine.rule_count(), 0);
    }

    // ── Single rule match ──────────────────────────────────────────

    #[test]
    fn single_http_rule_match() {
        let mut engine = L7Engine::new();
        let mut rule = make_l7_rule("r1", 10, FirewallAction::Deny);
        rule.matcher = L7Matcher::Http {
            method: Some("GET".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };
        engine.add_rule(rule).unwrap();

        let result = engine.evaluate(&make_header(), &make_http_parsed());
        assert!(result.is_some());
        let (idx, matched) = result.unwrap();
        assert_eq!(idx, 0);
        assert_eq!(matched.action, FirewallAction::Deny);
    }

    // ── Priority ordering ──────────────────────────────────────────

    #[test]
    fn priority_ordering_first_match_wins() {
        let mut engine = L7Engine::new();

        let mut deny = make_l7_rule("deny", 1, FirewallAction::Deny);
        deny.matcher = L7Matcher::Http {
            method: Some("GET".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };
        engine.add_rule(deny).unwrap();

        let mut allow = make_l7_rule("allow", 100, FirewallAction::Allow);
        allow.matcher = L7Matcher::Http {
            method: Some("GET".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };
        engine.add_rule(allow).unwrap();

        let (_, matched) = engine
            .evaluate(&make_header(), &make_http_parsed())
            .unwrap();
        assert_eq!(matched.action, FirewallAction::Deny);
    }

    // ── Disabled rule skipped ──────────────────────────────────────

    #[test]
    fn disabled_rule_skipped() {
        let mut engine = L7Engine::new();
        let mut rule = make_l7_rule("r1", 10, FirewallAction::Deny);
        rule.enabled = false;
        engine.add_rule(rule).unwrap();

        assert!(
            engine
                .evaluate(&make_header(), &make_http_parsed())
                .is_none()
        );
    }

    // ── L3+L7 combined ────────────────────────────────────────────

    #[test]
    fn l3l4_combined_with_l7() {
        let mut engine = L7Engine::new();
        let mut rule = make_l7_rule("r1", 10, FirewallAction::Deny);
        rule.matcher = L7Matcher::Http {
            method: Some("GET".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };
        rule.dst_port = Some(PortRange {
            start: 8080,
            end: 8080,
        });
        engine.add_rule(rule).unwrap();

        // Port 80 doesn't match dst_port constraint 8080
        assert!(
            engine
                .evaluate(&make_header(), &make_http_parsed())
                .is_none()
        );

        // Port 8080 matches
        let mut header = make_header();
        header.dst_port = 8080;
        assert!(engine.evaluate(&header, &make_http_parsed()).is_some());
    }

    // ── CRUD ───────────────────────────────────────────────────────

    #[test]
    fn add_and_remove_rule() {
        let mut engine = L7Engine::new();
        engine
            .add_rule(make_l7_rule("r1", 10, FirewallAction::Deny))
            .unwrap();
        assert_eq!(engine.rule_count(), 1);

        engine.remove_rule(&RuleId("r1".to_string())).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn duplicate_rejected() {
        let mut engine = L7Engine::new();
        engine
            .add_rule(make_l7_rule("r1", 10, FirewallAction::Deny))
            .unwrap();
        assert!(
            engine
                .add_rule(make_l7_rule("r1", 20, FirewallAction::Allow))
                .is_err()
        );
        assert_eq!(engine.rule_count(), 1);
    }

    #[test]
    fn remove_nonexistent_fails() {
        let mut engine = L7Engine::new();
        assert!(engine.remove_rule(&RuleId("nope".to_string())).is_err());
    }

    // ── Reload ─────────────────────────────────────────────────────

    #[test]
    fn reload_replaces_all() {
        let mut engine = L7Engine::new();
        engine
            .add_rule(make_l7_rule("old", 10, FirewallAction::Deny))
            .unwrap();

        let new_rules = vec![
            make_l7_rule("new1", 10, FirewallAction::Allow),
            make_l7_rule("new2", 20, FirewallAction::Log),
        ];
        engine.reload(new_rules).unwrap();
        assert_eq!(engine.rule_count(), 2);
        assert_eq!(engine.rules()[0].id.0, "new1");
    }

    #[test]
    fn reload_atomic_on_failure() {
        let mut engine = L7Engine::new();
        engine
            .add_rule(make_l7_rule("old", 10, FirewallAction::Deny))
            .unwrap();

        let bad_rules = vec![
            make_l7_rule("ok", 10, FirewallAction::Allow),
            make_l7_rule("bad", 0, FirewallAction::Deny), // invalid priority
        ];
        assert!(engine.reload(bad_rules).is_err());
        // Old rules preserved
        assert_eq!(engine.rule_count(), 1);
        assert_eq!(engine.rules()[0].id.0, "old");
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = L7Engine::new();
        let rules = vec![
            make_l7_rule("dup", 10, FirewallAction::Allow),
            make_l7_rule("dup", 20, FirewallAction::Deny),
        ];
        assert!(engine.reload(rules).is_err());
    }

    // ── Multi-protocol ─────────────────────────────────────────────

    #[test]
    fn tls_rule_does_not_match_http() {
        let mut engine = L7Engine::new();
        let rule = L7Rule {
            id: RuleId("tls-rule".to_string()),
            priority: 10,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Tls {
                sni_pattern: Some(DomainMatcher::new("evil.com").unwrap()),
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };
        engine.add_rule(rule).unwrap();

        // HTTP parsed should not match TLS rule
        assert!(
            engine
                .evaluate(&make_header(), &make_http_parsed())
                .is_none()
        );

        // TLS parsed should match
        let tls_parsed = ParsedProtocol::Tls(TlsClientHello {
            sni: Some("evil.com".to_string()),
        });
        assert!(engine.evaluate(&make_header(), &tls_parsed).is_some());
    }

    #[test]
    fn multiple_protocol_rules() {
        let mut engine = L7Engine::new();

        // HTTP deny at priority 10
        let mut http_rule = make_l7_rule("http-deny", 10, FirewallAction::Deny);
        http_rule.matcher = L7Matcher::Http {
            method: Some("DELETE".to_string()),
            path_pattern: None,
            host_pattern: None,
            content_type: None,
        };
        engine.add_rule(http_rule).unwrap();

        // SMTP deny at priority 20
        let smtp_rule = L7Rule {
            id: RuleId("smtp-deny".to_string()),
            priority: 20,
            action: FirewallAction::Deny,
            matcher: L7Matcher::Smtp {
                command: Some("VRFY".to_string()),
            },
            src_ip: None,
            dst_ip: None,
            dst_port: None,
            enabled: true,
        };
        engine.add_rule(smtp_rule).unwrap();

        // HTTP GET should not match either
        assert!(
            engine
                .evaluate(&make_header(), &make_http_parsed())
                .is_none()
        );

        // SMTP VRFY should match smtp-deny
        let smtp_parsed = ParsedProtocol::Smtp(SmtpCommand {
            command: "VRFY".to_string(),
            params: "user".to_string(),
        });
        let (_, matched) = engine.evaluate(&make_header(), &smtp_parsed).unwrap();
        assert_eq!(matched.id.0, "smtp-deny");
    }
}
