use crate::common::entity::RuleId;
use crate::common::error::DomainError;

use super::entity::RateLimitPolicy;
use super::error::RateLimitError;

/// In-memory rate limit policy engine.
///
/// Policies are stored sorted by ID for deterministic iteration.
/// CRUD operations validate policies and reject duplicates.
#[derive(Debug)]
pub struct RateLimitEngine {
    policies: Vec<RateLimitPolicy>,
}

impl RateLimitEngine {
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
        }
    }

    /// Add a policy. Validates the policy and rejects duplicates.
    pub fn add_policy(&mut self, policy: RateLimitPolicy) -> Result<(), DomainError> {
        policy.validate()?;

        if self.policies.iter().any(|p| p.id == policy.id) {
            return Err(RateLimitError::DuplicatePolicy {
                id: policy.id.to_string(),
            }
            .into());
        }

        self.policies.push(policy);
        self.sort_policies();
        Ok(())
    }

    /// Remove a policy by ID.
    pub fn remove_policy(&mut self, id: &RuleId) -> Result<(), DomainError> {
        let pos = self
            .policies
            .iter()
            .position(|p| &p.id == id)
            .ok_or_else(|| RateLimitError::PolicyNotFound { id: id.to_string() })?;
        self.policies.remove(pos);
        Ok(())
    }

    /// Replace all policies atomically. Validates all policies before replacing.
    pub fn reload(&mut self, policies: Vec<RateLimitPolicy>) -> Result<(), DomainError> {
        for policy in &policies {
            policy.validate()?;
        }

        // Check for duplicate IDs
        for (i, policy) in policies.iter().enumerate() {
            if policies[i + 1..].iter().any(|p| p.id == policy.id) {
                return Err(RateLimitError::DuplicatePolicy {
                    id: policy.id.to_string(),
                }
                .into());
            }
        }

        self.policies = policies;
        self.sort_policies();
        Ok(())
    }

    /// Return a slice of all loaded policies (sorted by ID).
    pub fn policies(&self) -> &[RateLimitPolicy] {
        &self.policies
    }

    /// Return the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    fn sort_policies(&mut self) {
        self.policies.sort_by(|a, b| a.id.0.cmp(&b.id.0));
    }
}

impl Default for RateLimitEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::entity::IpNetwork;
    use crate::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitScope};

    fn make_policy(id: &str, rate: u64, burst: u64) -> RateLimitPolicy {
        RateLimitPolicy {
            id: RuleId(id.to_string()),
            scope: RateLimitScope::SourceIp,
            rate,
            burst,
            action: RateLimitAction::Drop,
            src_ip: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::default(),
        }
    }

    // ── Lifecycle tests ──────────────────────────────────────────────

    #[test]
    fn new_engine_is_empty() {
        let engine = RateLimitEngine::new();
        assert!(engine.policies().is_empty());
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn default_is_same_as_new() {
        let engine = RateLimitEngine::default();
        assert!(engine.policies().is_empty());
    }

    // ── Add policy tests ─────────────────────────────────────────────

    #[test]
    fn add_policy_succeeds() {
        let mut engine = RateLimitEngine::new();
        assert!(engine.add_policy(make_policy("rl-001", 1000, 2000)).is_ok());
        assert_eq!(engine.policy_count(), 1);
    }

    #[test]
    fn add_policy_validates() {
        let mut engine = RateLimitEngine::new();
        assert!(engine.add_policy(make_policy("", 1000, 2000)).is_err());
        assert_eq!(engine.policy_count(), 0);
    }

    #[test]
    fn add_policy_rejects_zero_rate() {
        let mut engine = RateLimitEngine::new();
        assert!(engine.add_policy(make_policy("rl-001", 0, 2000)).is_err());
    }

    #[test]
    fn add_policy_rejects_zero_burst() {
        let mut engine = RateLimitEngine::new();
        assert!(engine.add_policy(make_policy("rl-001", 1000, 0)).is_err());
    }

    #[test]
    fn add_duplicate_policy_fails() {
        let mut engine = RateLimitEngine::new();
        assert!(engine.add_policy(make_policy("rl-001", 1000, 2000)).is_ok());
        assert!(engine.add_policy(make_policy("rl-001", 500, 1000)).is_err());
        assert_eq!(engine.policy_count(), 1);
    }

    // ── Remove policy tests ──────────────────────────────────────────

    #[test]
    fn remove_policy_succeeds() {
        let mut engine = RateLimitEngine::new();
        engine
            .add_policy(make_policy("rl-001", 1000, 2000))
            .unwrap();
        assert!(engine.remove_policy(&RuleId("rl-001".to_string())).is_ok());
        assert!(engine.policies().is_empty());
    }

    #[test]
    fn remove_nonexistent_policy_fails() {
        let mut engine = RateLimitEngine::new();
        assert!(engine.remove_policy(&RuleId("nope".to_string())).is_err());
    }

    // ── Reload tests ─────────────────────────────────────────────────

    #[test]
    fn reload_replaces_all_policies() {
        let mut engine = RateLimitEngine::new();
        engine.add_policy(make_policy("old", 100, 200)).unwrap();

        let new_policies = vec![
            make_policy("new1", 1000, 2000),
            make_policy("new2", 500, 1000),
        ];
        assert!(engine.reload(new_policies).is_ok());
        assert_eq!(engine.policy_count(), 2);
        assert_eq!(engine.policies()[0].id.0, "new1");
        assert_eq!(engine.policies()[1].id.0, "new2");
    }

    #[test]
    fn reload_validates_all_policies() {
        let mut engine = RateLimitEngine::new();
        engine.add_policy(make_policy("old", 100, 200)).unwrap();

        let new_policies = vec![
            make_policy("ok", 1000, 2000),
            make_policy("bad", 0, 2000), // invalid rate
        ];
        assert!(engine.reload(new_policies).is_err());
        // Old policy preserved on failure
        assert_eq!(engine.policy_count(), 1);
        assert_eq!(engine.policies()[0].id.0, "old");
    }

    #[test]
    fn reload_rejects_duplicates() {
        let mut engine = RateLimitEngine::new();
        let policies = vec![
            make_policy("dup", 1000, 2000),
            make_policy("dup", 500, 1000),
        ];
        assert!(engine.reload(policies).is_err());
    }

    #[test]
    fn reload_empty_clears_all() {
        let mut engine = RateLimitEngine::new();
        engine
            .add_policy(make_policy("rl-001", 1000, 2000))
            .unwrap();
        assert!(engine.reload(vec![]).is_ok());
        assert!(engine.policies().is_empty());
    }

    // ── Sorting tests ────────────────────────────────────────────────

    #[test]
    fn policies_sorted_by_id() {
        let mut engine = RateLimitEngine::new();
        engine.add_policy(make_policy("rl-003", 100, 200)).unwrap();
        engine.add_policy(make_policy("rl-001", 100, 200)).unwrap();
        engine.add_policy(make_policy("rl-002", 100, 200)).unwrap();

        assert_eq!(engine.policies()[0].id.0, "rl-001");
        assert_eq!(engine.policies()[1].id.0, "rl-002");
        assert_eq!(engine.policies()[2].id.0, "rl-003");
    }

    // ── Policy with CIDR ─────────────────────────────────────────────

    #[test]
    fn policy_with_valid_cidr() {
        let mut engine = RateLimitEngine::new();
        let mut policy = make_policy("rl-cidr", 1000, 2000);
        policy.src_ip = Some(IpNetwork::V4 {
            addr: 0x0A00_0000,
            prefix_len: 8,
        });
        assert!(engine.add_policy(policy).is_ok());
    }

    #[test]
    fn policy_with_invalid_cidr() {
        let mut engine = RateLimitEngine::new();
        let mut policy = make_policy("rl-bad", 1000, 2000);
        policy.src_ip = Some(IpNetwork::V4 {
            addr: 0,
            prefix_len: 33,
        });
        assert!(engine.add_policy(policy).is_err());
    }

    // ── Edge cases ───────────────────────────────────────────────────

    #[test]
    fn add_remove_add_same_id() {
        let mut engine = RateLimitEngine::new();
        engine
            .add_policy(make_policy("rl-001", 1000, 2000))
            .unwrap();
        engine.remove_policy(&RuleId("rl-001".to_string())).unwrap();
        assert!(engine.add_policy(make_policy("rl-001", 500, 1000)).is_ok());
        assert_eq!(engine.policy_count(), 1);
        assert_eq!(engine.policies()[0].rate, 500);
    }

    #[test]
    fn reload_then_add() {
        let mut engine = RateLimitEngine::new();
        engine
            .reload(vec![make_policy("rl-001", 100, 200)])
            .unwrap();
        engine.add_policy(make_policy("rl-002", 500, 1000)).unwrap();
        assert_eq!(engine.policy_count(), 2);
    }
}
