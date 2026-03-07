use std::sync::{Arc, PoisonError, RwLock};

use crate::reputation_enforcement::ReputationEnforcementService;
use domain::dns::entity::{DomainReputation, ReputationConfig, ReputationFactor, ReputationStats};
use domain::dns::reputation::DomainReputationEngine;
use ports::secondary::domain_reputation_port::DomainReputationPort;
use ports::secondary::metrics_port::MetricsPort;

/// Application service wrapping the domain reputation engine.
pub struct DomainReputationAppService {
    engine: RwLock<DomainReputationEngine>,
    metrics: Arc<dyn MetricsPort>,
    enforcement: Option<Arc<ReputationEnforcementService>>,
}

impl DomainReputationAppService {
    pub fn new(config: ReputationConfig, metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            engine: RwLock::new(DomainReputationEngine::new(config)),
            metrics,
            enforcement: None,
        }
    }

    /// Attach the reputation enforcement service for auto-blocking.
    #[must_use]
    pub fn with_enforcement(mut self, svc: Arc<ReputationEnforcementService>) -> Self {
        self.enforcement = Some(svc);
        self
    }

    fn now_ns() -> u64 {
        #[allow(clippy::cast_possible_truncation)]
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        ns
    }
}

impl DomainReputationPort for DomainReputationAppService {
    fn get_reputation(&self, domain: &str) -> Option<DomainReputation> {
        let engine = self.engine.read().unwrap_or_else(PoisonError::into_inner);
        engine.get(domain).cloned()
    }

    fn get_score(&self, domain: &str) -> Option<f64> {
        let engine = self.engine.read().unwrap_or_else(PoisonError::into_inner);
        let rep = engine.get(domain)?;
        let now = Self::now_ns();
        Some(rep.effective_score(now, 24 * 3600 * 1_000_000_000))
    }

    fn update_reputation(&self, domain: &str, factor: ReputationFactor) {
        let mut engine = self.engine.write().unwrap_or_else(PoisonError::into_inner);
        let now = Self::now_ns();
        let score = engine.update(domain, factor, now);
        let stats = engine.stats(now);
        drop(engine);

        self.metrics
            .set_domain_reputation_high_risk(stats.high_risk_count as u64);

        if score >= 0.8 {
            tracing::debug!(domain, score, "domain reputation high risk");
        }

        if let Some(ref enforcement) = self.enforcement {
            enforcement.on_reputation_change(domain, score);
        }
    }

    fn list_high_risk(&self, min_score: f64) -> Vec<(DomainReputation, f64)> {
        let engine = self.engine.read().unwrap_or_else(PoisonError::into_inner);
        let now = Self::now_ns();
        engine
            .list_high_risk(min_score, now)
            .into_iter()
            .map(|(rep, score)| (rep.clone(), score))
            .collect()
    }

    fn list_all(&self, page: usize, page_size: usize) -> Vec<(DomainReputation, f64)> {
        let engine = self.engine.read().unwrap_or_else(PoisonError::into_inner);
        let now = Self::now_ns();
        engine
            .list_all(page, page_size, now)
            .into_iter()
            .map(|(rep, score)| (rep.clone(), score))
            .collect()
    }

    fn stats(&self) -> ReputationStats {
        let engine = self.engine.read().unwrap_or_else(PoisonError::into_inner);
        let now = Self::now_ns();
        engine.stats(now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ports::test_utils::NoopMetrics;

    fn make_service() -> DomainReputationAppService {
        DomainReputationAppService::new(ReputationConfig::default(), Arc::new(NoopMetrics))
    }

    #[test]
    fn get_reputation_returns_none_for_unknown() {
        let svc = make_service();
        assert!(svc.get_reputation("unknown.com").is_none());
    }

    #[test]
    fn get_score_returns_none_for_unknown() {
        let svc = make_service();
        assert!(svc.get_score("unknown.com").is_none());
    }

    #[test]
    fn update_then_get_reputation() {
        let svc = make_service();
        svc.update_reputation(
            "bad.com",
            ReputationFactor::BlocklistHit {
                list_name: "test-list".to_string(),
            },
        );
        let rep = svc.get_reputation("bad.com");
        assert!(rep.is_some());
        assert_eq!(rep.unwrap().domain, "bad.com");
    }

    #[test]
    fn update_then_get_score() {
        let svc = make_service();
        svc.update_reputation(
            "evil.com",
            ReputationFactor::CtiMatch {
                feed_name: "feed-1".to_string(),
                threat_type: "malware".to_string(),
            },
        );
        let score = svc.get_score("evil.com");
        assert!(score.is_some());
        assert!(score.unwrap() > 0.0);
    }

    #[test]
    fn list_high_risk_empty_initially() {
        let svc = make_service();
        assert!(svc.list_high_risk(0.5).is_empty());
    }

    #[test]
    fn list_high_risk_after_update() {
        let svc = make_service();
        // Add multiple factors to push score high
        for _ in 0..5 {
            svc.update_reputation(
                "malware.com",
                ReputationFactor::BlocklistHit {
                    list_name: "bl".to_string(),
                },
            );
        }
        let high = svc.list_high_risk(0.1);
        assert!(!high.is_empty());
        assert_eq!(high[0].0.domain, "malware.com");
    }

    #[test]
    fn list_all_paginated() {
        let svc = make_service();
        svc.update_reputation(
            "a.com",
            ReputationFactor::HighEntropy { entropy: 4.5 },
        );
        svc.update_reputation(
            "b.com",
            ReputationFactor::ShortTtl { avg_ttl: 5 },
        );
        let page0 = svc.list_all(0, 1);
        assert_eq!(page0.len(), 1);
        let page1 = svc.list_all(1, 1);
        assert_eq!(page1.len(), 1);
        let all = svc.list_all(0, 100);
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn stats_reflects_tracked_domains() {
        let svc = make_service();
        let stats = svc.stats();
        assert_eq!(stats.tracked_domains, 0);

        svc.update_reputation(
            "tracked.com",
            ReputationFactor::FrequentQueries { rate_per_min: 100.0 },
        );
        let stats = svc.stats();
        assert_eq!(stats.tracked_domains, 1);
    }
}
