//! Reading the cgroup tree as a list of workloads, for the DLP scope.
//!
//! A DLP selector is written in names an operator knows - a pod, a
//! container, a unit - and the probes enforce a fence keyed on cgroup ids,
//! which change on every restart. This walk is what connects the two: one
//! record per cgroup, carrying the path, the id, the container id parsed out
//! of the path, the systemd unit it sits under, and whatever a metadata
//! enricher could add about the container.
//!
//! What it deliberately does not carry is an executable: a cgroup is not a
//! process, and the exec half of a selector arrives from the exec events the
//! process table already receives. A field nothing could resolve stays
//! absent rather than becoming an empty string, because a selector matching
//! on a blank is a selector reading a neighbour's plaintext.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use domain::common::error::DomainError;
use domain::container::engine::{detect_runtime, extract_container_id};
use domain::container::entity::{ContainerInfo, ContainerMetadata, ContainerRuntime};
use domain::dlp::scope::DlpObservedWorkload;
use ports::secondary::dlp_workload_source_port::DlpWorkloadSourcePort;
use ports::secondary::metadata_enricher_port::MetadataEnricher;
use tracing::debug;

/// Maximum directory depth walked under the cgroup root, the same bound the
/// cgroup id resolver uses: container cgroups sit a handful of levels down,
/// and the bound stops a pathological hierarchy from turning one scope
/// refresh into an unbounded walk.
const MAX_DEPTH: usize = 16;

/// Maximum number of cgroups one pass reports. The allow-list the kernel
/// reads holds far fewer, so a node with more cgroups than this cannot have
/// them all in scope anyway; the bound is what keeps the walk's cost flat on
/// a node running tens of thousands of short-lived cgroups.
const MAX_WORKLOADS: usize = 8192;

/// Walks a cgroup v2 mount and reports one workload per cgroup.
pub struct CgroupWorkloadScanner {
    root: PathBuf,
    enrichers: Vec<Arc<dyn MetadataEnricher>>,
}

impl CgroupWorkloadScanner {
    /// Scanner over `root`, with no metadata enricher.
    ///
    /// Without one, a container is reported by its id and its path and never
    /// by a pod or a container name, so a selector written on a name reports
    /// itself unmatched rather than matching the wrong workload.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            enrichers: Vec::new(),
        }
    }

    /// Scanner over the conventional unified mount.
    #[must_use]
    pub fn with_default_root() -> Self {
        Self::new("/sys/fs/cgroup")
    }

    /// Add an enricher, consulted in registration order until one answers.
    #[must_use]
    pub fn with_enricher(mut self, enricher: Arc<dyn MetadataEnricher>) -> Self {
        self.enrichers.push(enricher);
        self
    }

    /// Every cgroup under the root, as a path and an id.
    fn walk(&self, dir: &Path, depth: usize, out: &mut Vec<(String, u64)>) {
        if depth > MAX_DEPTH || out.len() >= MAX_WORKLOADS {
            return;
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            if out.len() >= MAX_WORKLOADS {
                return;
            }
            // `metadata` rather than a followed symlink: cgroupfs has none
            // between cgroups, and a followed one would leave the hierarchy.
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            let path = entry.path();
            out.push((self.relative_path(&path), meta.ino()));
            self.walk(&path, depth + 1, out);
        }
    }

    fn relative_path(&self, path: &Path) -> String {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        let rel = rel.to_string_lossy();
        if rel.is_empty() {
            "/".to_string()
        } else {
            format!("/{rel}")
        }
    }

    /// The innermost systemd unit a cgroup path sits under, where there is
    /// one. `/system.slice/nginx.service/app` is `nginx.service`.
    fn unit_of(path: &str) -> Option<String> {
        path.split('/')
            .rfind(|segment| segment.ends_with(".service"))
            .map(ToString::to_string)
    }

    async fn metadata_for(&self, info: &ContainerInfo) -> Option<ContainerMetadata> {
        for enricher in &self.enrichers {
            match enricher.enrich(info).await {
                Ok(Some(metadata)) => return Some(metadata),
                Ok(None) => {}
                Err(e) => {
                    debug!(enricher = enricher.name(), error = %e, "DLP scope enrichment failed");
                }
            }
        }
        None
    }
}

#[async_trait]
impl DlpWorkloadSourcePort for CgroupWorkloadScanner {
    async fn observe(&self) -> Result<Vec<DlpObservedWorkload>, DomainError> {
        let mut cgroups = Vec::new();
        self.walk(&self.root, 0, &mut cgroups);

        let mut out = Vec::with_capacity(cgroups.len());
        for (path, id) in cgroups {
            let runtime = detect_runtime(&path);
            let container_id = if runtime == ContainerRuntime::Unknown {
                None
            } else {
                extract_container_id(&path, runtime)
            };

            let mut workload = DlpObservedWorkload {
                cgroup: Some(path.clone()),
                cgroup_id: Some(id),
                unit: Self::unit_of(&path),
                container_id: container_id.clone(),
                ..DlpObservedWorkload::default()
            };

            if let Some(container_id) = container_id {
                let info = ContainerInfo::Container {
                    container_id,
                    runtime,
                    cgroup_path: path,
                    // The scan answers for a cgroup, not for a task, so there
                    // is no pid to report. No enricher reads it: both of them
                    // key on the container id.
                    pid: 0,
                };
                match self.metadata_for(&info).await {
                    Some(ContainerMetadata::Kubernetes(pod)) => {
                        workload.pod = Some(pod.pod_name);
                        workload.namespace = Some(pod.namespace);
                        workload.container_name = Some(pod.container_name);
                    }
                    Some(ContainerMetadata::Docker(container)) => {
                        workload.container_name = Some(container.name);
                    }
                    _ => {}
                }
            }

            out.push(workload);
        }
        Ok(out)
    }

    fn name(&self) -> &'static str {
        "cgroupfs"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("system.slice/nginx.service")).unwrap();
        std::fs::create_dir_all(
            dir.path()
                .join("system.slice/docker-1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff.scope"),
        )
        .unwrap();
        std::fs::write(dir.path().join("cgroup.procs"), b"1\n").unwrap();
        dir
    }

    #[tokio::test]
    async fn every_cgroup_is_reported_with_its_id() {
        let dir = tree();
        let scanner = CgroupWorkloadScanner::new(dir.path());
        let seen = scanner.observe().await.expect("observe");

        let slice = seen
            .iter()
            .find(|w| w.cgroup.as_deref() == Some("/system.slice"))
            .expect("the slice is reported");
        assert_eq!(
            slice.cgroup_id,
            Some(
                std::fs::metadata(dir.path().join("system.slice"))
                    .unwrap()
                    .ino()
            )
        );
        // A file in the hierarchy is not a cgroup.
        assert!(
            seen.iter()
                .all(|w| w.cgroup.as_deref() != Some("/cgroup.procs"))
        );
    }

    #[tokio::test]
    async fn a_unit_is_read_off_the_path() {
        let dir = tree();
        let seen = CgroupWorkloadScanner::new(dir.path())
            .observe()
            .await
            .expect("observe");
        let unit = seen
            .iter()
            .find(|w| w.cgroup.as_deref() == Some("/system.slice/nginx.service"))
            .expect("the unit is reported");
        assert_eq!(unit.unit.as_deref(), Some("nginx.service"));
        assert!(unit.container_id.is_none());
    }

    #[tokio::test]
    async fn a_container_id_is_parsed_out_of_the_path() {
        let dir = tree();
        let seen = CgroupWorkloadScanner::new(dir.path())
            .observe()
            .await
            .expect("observe");
        let container = seen
            .iter()
            .find(|w| w.container_id.is_some())
            .expect("the container is reported");
        assert!(
            container
                .container_id
                .as_deref()
                .is_some_and(|id| id.starts_with("1111222233334444"))
        );
        // No enricher is registered, so no name is invented for it.
        assert!(container.container_name.is_none());
        assert!(container.pod.is_none());
    }

    #[tokio::test]
    async fn a_name_comes_from_an_enricher_and_never_from_the_path() {
        struct Pod;
        #[async_trait]
        impl MetadataEnricher for Pod {
            async fn enrich(
                &self,
                info: &ContainerInfo,
            ) -> Result<Option<ContainerMetadata>, domain::container::error::ContainerError>
            {
                assert!(info.container_id().is_some());
                Ok(Some(ContainerMetadata::Kubernetes(
                    domain::container::entity::KubernetesMetadata {
                        pod_name: "api-7c9".to_string(),
                        namespace: "payments".to_string(),
                        container_name: "api".to_string(),
                        labels: Vec::new(),
                        annotations: Vec::new(),
                        service_account: String::new(),
                        owner_kind: None,
                        owner_name: None,
                        node_name: String::new(),
                    },
                )))
            }
            fn name(&self) -> &'static str {
                "test"
            }
        }

        let dir = tree();
        let seen = CgroupWorkloadScanner::new(dir.path())
            .with_enricher(Arc::new(Pod))
            .observe()
            .await
            .expect("observe");
        let container = seen
            .iter()
            .find(|w| w.container_id.is_some())
            .expect("the container is reported");
        assert_eq!(container.pod.as_deref(), Some("api-7c9"));
        assert_eq!(container.namespace.as_deref(), Some("payments"));
        assert_eq!(container.container_name.as_deref(), Some("api"));
        // The unit and the path are still what the walk read.
        assert!(
            container
                .cgroup
                .as_deref()
                .is_some_and(|p| p.contains("docker-"))
        );
    }

    #[test]
    fn the_innermost_unit_wins() {
        assert_eq!(
            CgroupWorkloadScanner::unit_of("/system.slice/a.service/b.service/x"),
            Some("b.service".to_string())
        );
        assert_eq!(CgroupWorkloadScanner::unit_of("/kubepods.slice"), None);
    }
}
