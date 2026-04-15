//! Docker metadata enricher.
//!
//! Implements [`MetadataEnricher`] by querying the Docker Engine API over a
//! Unix socket for each container ID. Results are cached in an LRU with TTL,
//! and the enricher transparently disables itself after a Docker error until
//! a periodic recheck re-enables it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use tracing::{debug, warn};

use domain::container::entity::{ContainerInfo, ContainerMetadata, ContainerRuntime};
use domain::container::error::ContainerError;
use ports::secondary::metadata_enricher_port::MetadataEnricher;

use super::docker_cache::DockerCache;
use super::docker_client::DockerClient;

/// Re-check Docker availability at least every 60s after a failure.
const RECHECK_INTERVAL_SECS: u64 = 60;

pub struct DockerEnricher {
    client: DockerClient,
    cache: DockerCache,
    available: AtomicBool,
    /// Seconds since `base` at which the enricher was disabled. 0 = never.
    disabled_at_secs: AtomicU64,
    base: Instant,
}

impl DockerEnricher {
    pub fn new(client: DockerClient, cache: DockerCache) -> Self {
        Self {
            client,
            cache,
            available: AtomicBool::new(true),
            disabled_at_secs: AtomicU64::new(0),
            base: Instant::now(),
        }
    }

    fn now_secs(&self) -> u64 {
        self.base.elapsed().as_secs()
    }

    fn maybe_recheck(&self) {
        if !self.available.load(Ordering::Relaxed) {
            let disabled_at = self.disabled_at_secs.load(Ordering::Relaxed);
            let elapsed = self.now_secs().saturating_sub(disabled_at);
            if elapsed >= RECHECK_INTERVAL_SECS {
                self.available.store(true, Ordering::Relaxed);
                debug!("docker enricher re-enabled after recheck interval");
            }
        }
    }

    fn disable(&self) {
        if self.available.swap(false, Ordering::Relaxed) {
            self.disabled_at_secs
                .store(self.now_secs(), Ordering::Relaxed);
            warn!(
                socket = %self.client.socket_path().display(),
                "docker engine unavailable, enricher disabled until periodic recheck"
            );
        }
    }
}

#[async_trait]
impl MetadataEnricher for DockerEnricher {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn enrich(
        &self,
        info: &ContainerInfo,
    ) -> Result<Option<ContainerMetadata>, ContainerError> {
        let ContainerInfo::Container {
            container_id,
            runtime,
            ..
        } = info
        else {
            return Ok(None);
        };
        if *runtime != ContainerRuntime::Docker {
            return Ok(None);
        }

        self.maybe_recheck();
        if !self.available.load(Ordering::Relaxed) {
            return Ok(None);
        }

        if let Some(md) = self.cache.get(container_id) {
            return Ok(Some(ContainerMetadata::Docker(md)));
        }

        match self.client.inspect_container(container_id).await {
            Ok(md) => {
                self.cache.insert(container_id.clone(), md.clone());
                Ok(Some(ContainerMetadata::Docker(md)))
            }
            Err(ContainerError::ContainerNotFound { .. }) => Ok(None),
            Err(
                err @ (ContainerError::DockerUnavailable { .. }
                | ContainerError::DockerTimeout { .. }),
            ) => {
                self.disable();
                debug!(error = %err, "docker enricher disabled");
                Ok(None)
            }
            Err(err) => {
                debug!(error = %err, "docker inspect failed");
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn host_info() -> ContainerInfo {
        ContainerInfo::Host
    }

    fn non_docker_info() -> ContainerInfo {
        ContainerInfo::Container {
            container_id: "abc".into(),
            runtime: ContainerRuntime::Podman,
            cgroup_path: "/libpod-abc.scope".into(),
            pid: 1,
        }
    }

    fn unreachable_enricher() -> DockerEnricher {
        let client = DockerClient::new("/nonexistent/docker.sock", 10);
        let cache = DockerCache::new(4, Duration::from_secs(60));
        DockerEnricher::new(client, cache)
    }

    #[tokio::test]
    async fn host_returns_none() {
        let e = unreachable_enricher();
        let md = e.enrich(&host_info()).await.unwrap();
        assert!(md.is_none());
    }

    #[tokio::test]
    async fn non_docker_runtime_returns_none() {
        let e = unreachable_enricher();
        let md = e.enrich(&non_docker_info()).await.unwrap();
        assert!(md.is_none());
    }

    #[tokio::test]
    async fn unreachable_socket_disables_enricher() {
        let e = unreachable_enricher();
        let info = ContainerInfo::Container {
            container_id: "deadbeef".into(),
            runtime: ContainerRuntime::Docker,
            cgroup_path: "/docker/deadbeef".into(),
            pid: 1,
        };
        let md = e.enrich(&info).await.unwrap();
        assert!(md.is_none());
        assert!(!e.available.load(Ordering::Relaxed));
        // subsequent call skips directly
        let md2 = e.enrich(&info).await.unwrap();
        assert!(md2.is_none());
    }
}
