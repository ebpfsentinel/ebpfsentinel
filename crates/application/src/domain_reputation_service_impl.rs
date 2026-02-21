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
