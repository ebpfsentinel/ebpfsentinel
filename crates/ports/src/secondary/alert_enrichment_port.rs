use domain::alert::entity::Alert;

/// Secondary port for enriching alerts with additional context.
///
/// Implementations may add DNS reverse-lookup data, reputation scores,
/// or other contextual information to an alert before dispatch.
pub trait AlertEnrichmentPort: Send + Sync {
    /// Enrich an alert in place with additional context.
    ///
    /// Best-effort: if enrichment data is unavailable, fields remain `None`.
    fn enrich_alert(&self, alert: &mut Alert);
}
