//! Docker metadata enricher.
//!
//! Implements [`MetadataEnricher`] by querying the Docker Engine API over a
//! Unix socket for each container ID. Results are cached in an LRU with TTL,
//! and the enricher transparently disables itself after a Docker error until
//! a periodic recheck re-enables it.
//!
//! The cache is shared with
//! [`DockerEventWatcher`](super::docker_events::DockerEventWatcher), which
//! writes it from Docker's own event stream, so most lookups are answered
//! without an inspect at all. An entry the stream wrote carries no creation
//! time, because only an inspect knows it: the enricher completes such an
//! entry once, and falls back to what the stream gave it when the inspect
//! fails.

use std::sync::Arc;
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
    cache: Arc<DockerCache>,
    available: AtomicBool,
    /// Seconds since `base` at which the enricher was disabled. 0 = never.
    disabled_at_secs: AtomicU64,
    base: Instant,
}

impl DockerEnricher {
    pub fn new(client: DockerClient, cache: Arc<DockerCache>) -> Self {
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

        let from_stream = match self.cache.get(container_id) {
            // Complete in one inspect what the event stream could not know.
            Some(md) if md.created_at.is_empty() => Some(md),
            Some(md) => return Ok(Some(ContainerMetadata::Docker(md))),
            None => None,
        };

        match self.client.inspect_container(container_id).await {
            Ok(md) => {
                self.cache.insert(container_id.clone(), md.clone());
                Ok(Some(ContainerMetadata::Docker(md)))
            }
            Err(ContainerError::ContainerNotFound { .. }) => {
                Ok(from_stream.map(ContainerMetadata::Docker))
            }
            Err(
                err @ (ContainerError::DockerUnavailable { .. }
                | ContainerError::DockerTimeout { .. }),
            ) => {
                self.disable();
                debug!(error = %err, "docker enricher disabled");
                Ok(from_stream.map(ContainerMetadata::Docker))
            }
            Err(err) => {
                debug!(error = %err, "docker inspect failed");
                Ok(from_stream.map(ContainerMetadata::Docker))
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
        unreachable_enricher_with(Arc::new(DockerCache::new(4, Duration::from_mins(1))))
    }

    fn unreachable_enricher_with(cache: Arc<DockerCache>) -> DockerEnricher {
        let client = DockerClient::new("/nonexistent/docker.sock", 10);
        DockerEnricher::new(client, cache)
    }

    fn docker_info(id: &str) -> ContainerInfo {
        ContainerInfo::Container {
            container_id: id.into(),
            runtime: ContainerRuntime::Docker,
            cgroup_path: format!("/docker/{id}"),
            pid: 1,
        }
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
    async fn an_entry_written_by_the_event_stream_enriches_without_an_inspect() {
        // The socket does not exist, so nothing here can have come from an
        // inspect: what the enricher returns is what the stream wrote.
        let cache = Arc::new(DockerCache::new(4, Duration::from_mins(1)));
        cache.insert(
            "abc".into(),
            domain::container::entity::DockerMetadata {
                name: "web".into(),
                image: "nginx:1.25".into(),
                labels: vec![],
                created_at: String::new(),
                status: "running".into(),
            },
        );
        let enricher = unreachable_enricher_with(Arc::clone(&cache));

        let md = enricher.enrich(&docker_info("abc")).await.unwrap();
        let Some(ContainerMetadata::Docker(md)) = md else {
            panic!("expected docker metadata");
        };
        assert_eq!(md.name, "web");
        assert_eq!(md.status, "running");
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
