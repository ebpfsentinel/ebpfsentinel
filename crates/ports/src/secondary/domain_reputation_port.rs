use domain::dns::entity::{DomainReputation, ReputationFactor, ReputationStats};

/// Secondary port for querying and updating domain reputation data.
pub trait DomainReputationPort: Send + Sync {
    /// Get the reputation entry for a specific domain.
    fn get_reputation(&self, domain: &str) -> Option<DomainReputation>;

    /// Get the effective score for a domain (with time decay).
    fn get_score(&self, domain: &str) -> Option<f64>;

    /// Update reputation by adding a factor.
    fn update_reputation(&self, domain: &str, factor: ReputationFactor);

    /// List domains above a minimum score threshold.
    fn list_high_risk(&self, min_score: f64) -> Vec<(DomainReputation, f64)>;

    /// Get all reputations paginated.
    fn list_all(&self, page: usize, page_size: usize) -> Vec<(DomainReputation, f64)>;

    /// Aggregated statistics.
    fn stats(&self) -> ReputationStats;
}
