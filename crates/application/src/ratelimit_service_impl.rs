use std::sync::Arc;

use domain::common::entity::RuleId;
use domain::common::error::DomainError;
use domain::ratelimit::engine::RateLimitEngine;
use domain::ratelimit::entity::RateLimitPolicy;
use ports::secondary::metrics_port::MetricsPort;

/// Application-level rate limit service.
///
/// Orchestrates the rate limit domain engine and metrics updates.
/// Designed to be wrapped in `RwLock` for shared access.
pub struct RateLimitAppService {
    engine: RateLimitEngine,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl RateLimitAppService {
    pub fn new(engine: RateLimitEngine, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine,
            metrics,
            enabled: true,
        }
    }

    /// Reload all policies atomically.
    pub fn reload_policies(&mut self, policies: Vec<RateLimitPolicy>) -> Result<(), DomainError> {
        self.engine.reload(policies)?;
        self.update_metrics();
        Ok(())
    }

    /// Add a rate limit policy.
    pub fn add_policy(&mut self, policy: RateLimitPolicy) -> Result<(), DomainError> {
        self.engine.add_policy(policy)?;
        self.update_metrics();
        Ok(())
    }

    /// Remove a policy by ID.
    pub fn remove_policy(&mut self, id: &RuleId) -> Result<(), DomainError> {
        self.engine.remove_policy(id)?;
        self.update_metrics();
        Ok(())
    }

    /// Return a slice of all loaded policies.
    pub fn policies(&self) -> &[RateLimitPolicy] {
        self.engine.policies()
    }

    /// Return the number of loaded policies.
    pub fn policy_count(&self) -> usize {
        self.engine.policy_count()
    }

    /// Return whether the rate limit service is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("ratelimit", self.engine.policy_count() as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitScope};
    use ports::test_utils::NoopMetrics;

    fn make_service() -> RateLimitAppService {
        RateLimitAppService::new(RateLimitEngine::new(), Arc::new(NoopMetrics))
    }

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

    #[test]
    fn add_policy_succeeds() {
        let mut svc = make_service();
        assert!(svc.add_policy(make_policy("rl-001", 1000, 2000)).is_ok());
        assert_eq!(svc.policy_count(), 1);
    }

    #[test]
    fn remove_policy_succeeds() {
        let mut svc = make_service();
        svc.add_policy(make_policy("rl-001", 1000, 2000)).unwrap();
        assert!(svc.remove_policy(&RuleId("rl-001".to_string())).is_ok());
        assert_eq!(svc.policy_count(), 0);
    }

    #[test]
    fn reload_updates_policies() {
        let mut svc = make_service();
        svc.add_policy(make_policy("rl-001", 1000, 2000)).unwrap();
        assert_eq!(svc.policy_count(), 1);

        svc.reload_policies(vec![]).unwrap();
        assert_eq!(svc.policy_count(), 0);
    }

    #[test]
    fn enabled_toggle() {
        let mut svc = make_service();
        assert!(svc.enabled());

        svc.set_enabled(false);
        assert!(!svc.enabled());

        svc.set_enabled(true);
        assert!(svc.enabled());
    }

    #[test]
    fn policies_returns_correct_slice() {
        let mut svc = make_service();
        svc.add_policy(make_policy("rl-002", 500, 1000)).unwrap();
        svc.add_policy(make_policy("rl-001", 1000, 2000)).unwrap();

        let policies = svc.policies();
        assert_eq!(policies.len(), 2);
        // Sorted by ID
        assert_eq!(policies[0].id.0, "rl-001");
        assert_eq!(policies[1].id.0, "rl-002");
    }

    #[test]
    fn add_duplicate_fails() {
        let mut svc = make_service();
        svc.add_policy(make_policy("rl-001", 1000, 2000)).unwrap();
        assert!(svc.add_policy(make_policy("rl-001", 500, 1000)).is_err());
    }
}
