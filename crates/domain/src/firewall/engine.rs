use crate::common::entity::RuleId;
use crate::common::error::DomainError;

use super::entity::{FirewallAction, FirewallRule, PacketInfo, Scope};
use super::error::FirewallError;

/// In-memory firewall rule engine.
///
/// Rules are stored sorted by ascending priority (lowest number = highest priority).
/// Evaluation returns the action of the first matching enabled rule.
#[derive(Debug)]
pub struct FirewallEngine {
    rules: Vec<FirewallRule>,
}

impl FirewallEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Evaluate a packet against all loaded rules.
    /// Returns the action of the first matching enabled rule (lowest priority number wins).
    /// Returns `None` if no rule matches.
    pub fn evaluate(&self, packet: &PacketInfo) -> Option<FirewallAction> {
        self.rules
            .iter()
            .filter(|r| r.enabled)
            .filter(|r| Self::matches_scope(r, packet))
            .find(|r| Self::matches_packet(r, packet))
            .map(|r| r.action)
    }

    /// Add a rule. Validates the rule and rejects duplicates.
    pub fn add_rule(&mut self, rule: FirewallRule) -> Result<(), DomainError> {
        rule.validate()?;

        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(FirewallError::DuplicateRule {
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
            .position(|r| &r.id == id)
            .ok_or_else(|| FirewallError::RuleNotFound { id: id.to_string() })?;
        self.rules.remove(pos);
        Ok(())
    }

    /// Replace all rules atomically. Validates all rules before replacing.
    pub fn reload(&mut self, rules: Vec<FirewallRule>) -> Result<(), DomainError> {
        // Validate all rules first
        for rule in &rules {
            rule.validate()?;
        }

        // Check for duplicate IDs
        for (i, rule) in rules.iter().enumerate() {
            if rules[i + 1..].iter().any(|r| r.id == rule.id) {
                return Err(FirewallError::DuplicateRule {
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
    pub fn rules(&self) -> &[FirewallRule] {
        &self.rules
    }

    // ── Private helpers ────────────────────────────────────────────────

    fn sort_rules(&mut self) {
        self.rules.sort_by_key(|r| r.priority);
    }

    /// Check if the rule's scope matches the packet's interface.
    fn matches_scope(rule: &FirewallRule, packet: &PacketInfo) -> bool {
        match &rule.scope {
            Scope::Global => true,
            Scope::Interface(iface) => iface == &packet.interface,
            Scope::Namespace(ns) => packet.interface.starts_with(ns.as_str()),
        }
    }

    /// Check if a rule matches a packet on IP, port, protocol, and VLAN.
    fn matches_packet(rule: &FirewallRule, packet: &PacketInfo) -> bool {
        // Protocol match (Any matches everything)
        if !Self::matches_protocol(rule, packet) {
            return false;
        }

        // Address family: rule with IPv6 IPs only matches IPv6 packets and vice versa
        let rule_is_v6 = rule.is_v6();
        if rule_is_v6 != packet.is_ipv6 {
            // IPv4 rules don't match IPv6 packets and vice versa.
            // Exception: rules with no IP filters match both.
            if rule.src_ip.is_some() || rule.dst_ip.is_some() {
                return false;
            }
        }

        // Source IP match (None = wildcard)
        if let Some(ref cidr) = rule.src_ip
            && !cidr.contains_addr(&packet.src_addr, packet.is_ipv6)
        {
            return false;
        }

        // Destination IP match (None = wildcard)
        if let Some(ref cidr) = rule.dst_ip
            && !cidr.contains_addr(&packet.dst_addr, packet.is_ipv6)
        {
            return false;
        }

        // Source port match (None = wildcard)
        if let Some(ref range) = rule.src_port
            && !range.contains(packet.src_port)
        {
            return false;
        }

        // Destination port match (None = wildcard)
        if let Some(ref range) = rule.dst_port
            && !range.contains(packet.dst_port)
        {
            return false;
        }

        // VLAN match (None = wildcard, Some(vid) = exact match)
        if let Some(rule_vid) = rule.vlan_id
            && packet.vlan_id != Some(rule_vid)
        {
            return false;
        }

        true
    }

    fn matches_protocol(rule: &FirewallRule, packet: &PacketInfo) -> bool {
        use crate::common::entity::Protocol;
        match rule.protocol {
            Protocol::Any => true,
            _ => rule.protocol == packet.protocol,
        }
    }
}

impl Default for FirewallEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::{Protocol, RuleId};
    use crate::firewall::entity::{FirewallAction, IpNetwork, PortRange};

    // ── Test helpers ───────────────────────────────────────────────

    fn make_rule(id: &str, priority: u32, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: RuleId(id.to_string()),
            priority,
            action,
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
        }
    }

    fn make_packet() -> PacketInfo {
        PacketInfo {
            src_addr: [0xC0A8_0001, 0, 0, 0], // 192.168.0.1
            dst_addr: [0x0A00_0001, 0, 0, 0], // 10.0.0.1
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            interface: "eth0".to_string(),
            is_ipv6: false,
            vlan_id: None,
        }
    }

    // ── Engine lifecycle tests ─────────────────────────────────────

    #[test]
    fn new_engine_is_empty() {
        let engine = FirewallEngine::new();
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn default_is_same_as_new() {
        let engine = FirewallEngine::default();
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn add_rule_succeeds() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("r1", 10, FirewallAction::Allow);
        assert!(engine.add_rule(rule).is_ok());
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn add_rule_validates() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("", 10, FirewallAction::Allow); // empty ID
        assert!(engine.add_rule(rule).is_err());
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn add_rule_rejects_zero_priority() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("r1", 0, FirewallAction::Allow);
        assert!(engine.add_rule(rule).is_err());
    }

    #[test]
    fn add_duplicate_rule_fails() {
        let mut engine = FirewallEngine::new();
        let r1 = make_rule("r1", 10, FirewallAction::Allow);
        let r1_dup = make_rule("r1", 20, FirewallAction::Deny);
        assert!(engine.add_rule(r1).is_ok());
        assert!(engine.add_rule(r1_dup).is_err());
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn remove_rule_succeeds() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("r1", 10, FirewallAction::Allow))
            .unwrap();
        assert!(engine.remove_rule(&RuleId("r1".to_string())).is_ok());
        assert!(engine.rules().is_empty());
    }

    #[test]
    fn remove_nonexistent_rule_fails() {
        let mut engine = FirewallEngine::new();
        assert!(engine.remove_rule(&RuleId("nope".to_string())).is_err());
    }

    // ── Reload tests ──────────────────────────────────────────────

    #[test]
    fn reload_replaces_all_rules() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("old", 10, FirewallAction::Allow))
            .unwrap();

        let new_rules = vec![
            make_rule("new1", 10, FirewallAction::Deny),
            make_rule("new2", 20, FirewallAction::Allow),
        ];
        assert!(engine.reload(new_rules).is_ok());
        assert_eq!(engine.rules().len(), 2);
        assert_eq!(engine.rules()[0].id.0, "new1");
    }

    #[test]
    fn reload_validates_all_rules() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("old", 10, FirewallAction::Allow))
            .unwrap();

        let new_rules = vec![
            make_rule("ok", 10, FirewallAction::Deny),
            make_rule("bad", 0, FirewallAction::Allow), // invalid priority
        ];
        assert!(engine.reload(new_rules).is_err());
        // Old rules should be preserved on failure
        assert_eq!(engine.rules().len(), 1);
        assert_eq!(engine.rules()[0].id.0, "old");
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = FirewallEngine::new();
        let rules = vec![
            make_rule("dup", 10, FirewallAction::Allow),
            make_rule("dup", 20, FirewallAction::Deny),
        ];
        assert!(engine.reload(rules).is_err());
    }

    #[test]
    fn reload_empty_clears_all() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("r1", 10, FirewallAction::Allow))
            .unwrap();
        assert!(engine.reload(vec![]).is_ok());
        assert!(engine.rules().is_empty());
    }

    // ── Priority ordering tests ───────────────────────────────────

    #[test]
    fn rules_sorted_by_priority() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("low", 100, FirewallAction::Allow))
            .unwrap();
        engine
            .add_rule(make_rule("high", 1, FirewallAction::Deny))
            .unwrap();
        engine
            .add_rule(make_rule("mid", 50, FirewallAction::Log))
            .unwrap();

        let rules = engine.rules();
        assert_eq!(rules[0].id.0, "high");
        assert_eq!(rules[1].id.0, "mid");
        assert_eq!(rules[2].id.0, "low");
    }

    #[test]
    fn priority_determines_evaluation_order() {
        let mut engine = FirewallEngine::new();
        // Both rules match everything — highest priority (lowest number) wins
        engine
            .add_rule(make_rule("allow-all", 100, FirewallAction::Allow))
            .unwrap();
        engine
            .add_rule(make_rule("deny-all", 1, FirewallAction::Deny))
            .unwrap();

        let packet = make_packet();
        assert_eq!(engine.evaluate(&packet), Some(FirewallAction::Deny));
    }

    // ── Evaluation: no rules ──────────────────────────────────────

    #[test]
    fn evaluate_empty_engine_returns_none() {
        let engine = FirewallEngine::new();
        assert_eq!(engine.evaluate(&make_packet()), None);
    }

    // ── Evaluation: disabled rules ────────────────────────────────

    #[test]
    fn disabled_rules_are_skipped() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.enabled = false;
        engine.add_rule(rule).unwrap();

        assert_eq!(engine.evaluate(&make_packet()), None);
    }

    // ── Evaluation: protocol matching ─────────────────────────────

    #[test]
    fn protocol_any_matches_all() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.protocol = Protocol::Any;
        engine.add_rule(rule).unwrap();

        let mut pkt = make_packet();
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));

        pkt.protocol = Protocol::Udp;
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));

        pkt.protocol = Protocol::Icmp;
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn protocol_mismatch_skips_rule() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("udp-only", 1, FirewallAction::Deny);
        rule.protocol = Protocol::Udp;
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // TCP
        assert_eq!(engine.evaluate(&pkt), None);
    }

    #[test]
    fn protocol_exact_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("tcp-only", 1, FirewallAction::Deny);
        rule.protocol = Protocol::Tcp;
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // TCP
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    // ── Evaluation: IP matching ───────────────────────────────────

    #[test]
    fn src_ip_exact_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A8_0001, // 192.168.0.1
            prefix_len: 32,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // src = 192.168.0.1
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn src_ip_no_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0x0A00_0001, // 10.0.0.1
            prefix_len: 32,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // src = 192.168.0.1
        assert_eq!(engine.evaluate(&pkt), None);
    }

    #[test]
    fn dst_ip_cidr_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.dst_ip = Some(IpNetwork::V4 {
            addr: 0x0A00_0000, // 10.0.0.0/8
            prefix_len: 8,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // dst = 10.0.0.1
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn wildcard_ip_matches_all() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("r1", 1, FirewallAction::Deny); // no src_ip/dst_ip
        engine.add_rule(rule).unwrap();

        let pkt = make_packet();
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    // ── Evaluation: port matching ─────────────────────────────────

    #[test]
    fn dst_port_range_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.dst_port = Some(PortRange {
            start: 80,
            end: 443,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // dst_port = 80
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn dst_port_out_of_range() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.dst_port = Some(PortRange {
            start: 443,
            end: 443,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // dst_port = 80
        assert_eq!(engine.evaluate(&pkt), None);
    }

    #[test]
    fn src_port_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.src_port = Some(PortRange {
            start: 10000,
            end: 20000,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // src_port = 12345
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    // ── Evaluation: scope matching ────────────────────────────────

    #[test]
    fn scope_global_matches_all() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("r1", 1, FirewallAction::Deny); // Global scope
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // interface = "eth0"
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn scope_interface_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.scope = Scope::Interface("eth0".to_string());
        engine.add_rule(rule).unwrap();

        let pkt = make_packet();
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn scope_interface_mismatch() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.scope = Scope::Interface("wlan0".to_string());
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // interface = "eth0"
        assert_eq!(engine.evaluate(&pkt), None);
    }

    #[test]
    fn scope_namespace_prefix_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.scope = Scope::Namespace("eth".to_string());
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // interface = "eth0"
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn scope_namespace_no_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("r1", 1, FirewallAction::Deny);
        rule.scope = Scope::Namespace("prod-".to_string());
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // interface = "eth0"
        assert_eq!(engine.evaluate(&pkt), None);
    }

    // ── Evaluation: combined criteria ─────────────────────────────

    #[test]
    fn combined_criteria_all_match() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("strict", 1, FirewallAction::Deny);
        rule.protocol = Protocol::Tcp;
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A8_0000, // 192.168.0.0/16
            prefix_len: 16,
        });
        rule.dst_port = Some(PortRange { start: 80, end: 80 });
        rule.scope = Scope::Interface("eth0".to_string());
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // TCP, 192.168.0.1 -> 10.0.0.1:80, eth0
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn combined_criteria_one_fails() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("strict", 1, FirewallAction::Deny);
        rule.protocol = Protocol::Tcp;
        rule.src_ip = Some(IpNetwork::V4 {
            addr: 0xC0A8_0000,
            prefix_len: 16,
        });
        rule.dst_port = Some(PortRange {
            start: 443,
            end: 443,
        }); // port 443 only
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // dst_port = 80 -> doesn't match 443
        assert_eq!(engine.evaluate(&pkt), None);
    }

    // ── Evaluation: first-match semantics ─────────────────────────

    #[test]
    fn first_match_wins() {
        let mut engine = FirewallEngine::new();

        // Priority 1: deny traffic to port 80
        let mut deny_http = make_rule("deny-http", 1, FirewallAction::Deny);
        deny_http.dst_port = Some(PortRange { start: 80, end: 80 });
        engine.add_rule(deny_http).unwrap();

        // Priority 2: allow all (catch-all)
        engine
            .add_rule(make_rule("allow-all", 100, FirewallAction::Allow))
            .unwrap();

        let pkt = make_packet(); // dst_port = 80
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn fallthrough_to_lower_priority() {
        let mut engine = FirewallEngine::new();

        // Priority 1: deny UDP (won't match TCP packets)
        let mut deny_udp = make_rule("deny-udp", 1, FirewallAction::Deny);
        deny_udp.protocol = Protocol::Udp;
        engine.add_rule(deny_udp).unwrap();

        // Priority 100: allow all
        engine
            .add_rule(make_rule("allow-all", 100, FirewallAction::Allow))
            .unwrap();

        let pkt = make_packet(); // TCP
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Allow));
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn multiple_disabled_then_one_enabled() {
        let mut engine = FirewallEngine::new();

        let mut r1 = make_rule("r1", 1, FirewallAction::Deny);
        r1.enabled = false;
        let mut r2 = make_rule("r2", 2, FirewallAction::Deny);
        r2.enabled = false;
        let r3 = make_rule("r3", 3, FirewallAction::Allow);

        engine.add_rule(r1).unwrap();
        engine.add_rule(r2).unwrap();
        engine.add_rule(r3).unwrap();

        assert_eq!(engine.evaluate(&make_packet()), Some(FirewallAction::Allow));
    }

    #[test]
    fn remove_then_evaluate() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("r1", 1, FirewallAction::Deny))
            .unwrap();
        engine.remove_rule(&RuleId("r1".to_string())).unwrap();
        assert_eq!(engine.evaluate(&make_packet()), None);
    }

    #[test]
    fn reload_then_evaluate() {
        let mut engine = FirewallEngine::new();
        engine
            .add_rule(make_rule("old", 1, FirewallAction::Deny))
            .unwrap();

        engine
            .reload(vec![make_rule("new", 1, FirewallAction::Allow)])
            .unwrap();

        assert_eq!(engine.evaluate(&make_packet()), Some(FirewallAction::Allow));
    }

    // ── VLAN matching ─────────────────────────────────────────────

    #[test]
    fn vlan_rule_matches_exact_vlan() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("vlan-100", 1, FirewallAction::Deny);
        rule.vlan_id = Some(100);
        engine.add_rule(rule).unwrap();

        let mut pkt = make_packet();
        pkt.vlan_id = Some(100);
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn vlan_rule_does_not_match_different_vlan() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("vlan-100", 1, FirewallAction::Deny);
        rule.vlan_id = Some(100);
        engine.add_rule(rule).unwrap();

        let mut pkt = make_packet();
        pkt.vlan_id = Some(200);
        assert_eq!(engine.evaluate(&pkt), None);
    }

    #[test]
    fn no_vlan_rule_matches_any_vlan() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("any-vlan", 1, FirewallAction::Deny);
        engine.add_rule(rule).unwrap();

        let mut pkt = make_packet();
        pkt.vlan_id = Some(100);
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    // ── IPv6 matching ─────────────────────────────────────────────

    #[test]
    fn ipv6_rule_matches_ipv6_packet() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("v6-deny", 1, FirewallAction::Deny);
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        rule.src_ip = Some(IpNetwork::V6 {
            addr,
            prefix_len: 32,
        });
        engine.add_rule(rule).unwrap();

        let pkt = PacketInfo {
            src_addr: [0x2001_0db8, 0, 0, 1],
            dst_addr: [0xfe80_0000, 0, 0, 1],
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            interface: "eth0".to_string(),
            is_ipv6: true,
            vlan_id: None,
        };
        assert_eq!(engine.evaluate(&pkt), Some(FirewallAction::Deny));
    }

    #[test]
    fn ipv6_rule_does_not_match_ipv4_packet() {
        let mut engine = FirewallEngine::new();
        let mut rule = make_rule("v6-deny", 1, FirewallAction::Deny);
        rule.src_ip = Some(IpNetwork::V6 {
            addr: [0u8; 16],
            prefix_len: 0,
        });
        engine.add_rule(rule).unwrap();

        let pkt = make_packet(); // IPv4
        assert_eq!(engine.evaluate(&pkt), None);
    }

    #[test]
    fn wildcard_rule_matches_both_v4_and_v6() {
        let mut engine = FirewallEngine::new();
        let rule = make_rule("catch-all", 1, FirewallAction::Deny);
        engine.add_rule(rule).unwrap();

        let v4 = make_packet();
        assert_eq!(engine.evaluate(&v4), Some(FirewallAction::Deny));

        let v6 = PacketInfo {
            src_addr: [0x2001_0db8, 0, 0, 1],
            dst_addr: [0xfe80_0000, 0, 0, 1],
            src_port: 12345,
            dst_port: 80,
            protocol: Protocol::Tcp,
            interface: "eth0".to_string(),
            is_ipv6: true,
            vlan_id: None,
        };
        assert_eq!(engine.evaluate(&v6), Some(FirewallAction::Deny));
    }
}
