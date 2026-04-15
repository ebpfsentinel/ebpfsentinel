//! Metadata enricher secondary port.
//!
//! Enrichers consume a resolved [`ContainerInfo`] and return runtime-specific
//! [`ContainerMetadata`] (Docker engine API, Kubernetes API, etc.). Missing
//! metadata is not an error — enrichers return `Ok(None)` when the runtime
//! is unreachable or the container ID cannot be resolved in the upstream API.

use async_trait::async_trait;

use domain::container::entity::{ContainerInfo, ContainerMetadata};
use domain::container::error::ContainerError;

#[async_trait]
pub trait MetadataEnricher: Send + Sync {
    /// Enrich the given container info with runtime-specific metadata.
    ///
    /// Returns `Ok(None)` if the enricher does not handle this runtime, if
    /// the container is not found, or if the runtime backend is unavailable
    /// (graceful degradation — alerts are still generated without metadata).
    async fn enrich(
        &self,
        info: &ContainerInfo,
    ) -> Result<Option<ContainerMetadata>, ContainerError>;

    /// Stable name of this enricher for metrics and logging.
    fn name(&self) -> &'static str;
}
