//! Kubernetes metadata enricher.
//!
//! Runs a `kube-rs` reflector on the `Pod` resource scoped to the current
//! node and maintains a reverse index from container ID (as seen in
//! `status.containerStatuses[].containerID`) to the owning pod. On lookup
//! it returns a [`KubernetesMetadata`] value from the local cache — no API
//! call per alert.
//!
//! When the agent is not running inside a Kubernetes cluster (no
//! `KUBERNETES_SERVICE_HOST` env var) or the API is unreachable at startup,
//! the enricher disables itself: `enrich()` returns `Ok(None)` and all
//! subsequent calls short-circuit.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{
    Api, Client,
    runtime::watcher::{self, Event},
};
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use domain::container::entity::{
    ContainerInfo, ContainerMetadata, ContainerRuntime, KubernetesMetadata,
};
use domain::container::error::ContainerError;
use ports::secondary::metadata_enricher_port::{MetadataEnricher, NamespaceHook};

/// Prefixes used by the CRI in `containerID` strings.
const CRI_PREFIXES: &[&str] = &[
    "containerd://",
    "cri-o://",
    "docker://",
    "crio://",
];

/// Cached pod metadata. `Arc`-wrapped so the reverse index can share it
/// without cloning strings on every lookup.
#[derive(Debug, Clone)]
pub struct PodInfo {
    pub uid: String,
    pub name: String,
    pub namespace: String,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
    pub service_account: String,
    pub owner_kind: Option<String>,
    pub owner_name: Option<String>,
    pub node_name: String,
    pub container_ids: Vec<String>,
    /// Map of container id → container name (within this pod).
    pub container_names: BTreeMap<String, String>,
}

impl PodInfo {
    fn to_metadata(&self, container_id: &str) -> KubernetesMetadata {
        KubernetesMetadata {
            pod_name: self.name.clone(),
            namespace: self.namespace.clone(),
            container_name: self
                .container_names
                .get(container_id)
                .cloned()
                .unwrap_or_default(),
            labels: self.labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            annotations: self
                .annotations
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            service_account: self.service_account.clone(),
            owner_kind: self.owner_kind.clone(),
            owner_name: self.owner_name.clone(),
            node_name: self.node_name.clone(),
        }
    }
}

/// Thread-safe pod cache with a reverse index from container id → pod uid.
#[derive(Default)]
pub struct PodCache {
    /// `pod_uid` → `PodInfo`
    pods: RwLock<HashMap<String, Arc<PodInfo>>>,
    /// `container_id` → `pod_uid`
    reverse_index: RwLock<HashMap<String, String>>,
}

impl PodCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn len(&self) -> usize {
        self.pods.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.pods.read().await.is_empty()
    }

    /// Insert or update a pod in the cache. Existing container ids belonging
    /// to the same pod uid are removed before re-indexing the new ones.
    pub async fn upsert(&self, info: PodInfo) {
        let info = Arc::new(info);
        let mut pods = self.pods.write().await;
        let mut index = self.reverse_index.write().await;

        if let Some(existing) = pods.remove(&info.uid) {
            for cid in &existing.container_ids {
                index.remove(cid);
            }
        }
        for cid in &info.container_ids {
            index.insert(cid.clone(), info.uid.clone());
        }
        pods.insert(info.uid.clone(), info);
    }

    /// Remove a pod and all its container ids from the cache.
    pub async fn delete(&self, uid: &str) {
        let mut pods = self.pods.write().await;
        let mut index = self.reverse_index.write().await;
        if let Some(existing) = pods.remove(uid) {
            for cid in &existing.container_ids {
                index.remove(cid);
            }
        }
    }

    /// Look up a container id in the cache. Returns the matching pod
    /// wrapped in an `Arc` for cheap cloning.
    pub async fn get(&self, container_id: &str) -> Option<Arc<PodInfo>> {
        let uid = self.reverse_index.read().await.get(container_id).cloned()?;
        self.pods.read().await.get(&uid).cloned()
    }
}

/// Convert a raw `Pod` into a [`PodInfo`], extracting container IDs.
pub fn pod_info_from(pod: &Pod) -> Option<PodInfo> {
    let metadata = &pod.metadata;
    let uid = metadata.uid.clone()?;
    let name = metadata.name.clone()?;
    let namespace = metadata.namespace.clone()?;

    let labels: BTreeMap<String, String> = metadata
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let annotations: BTreeMap<String, String> = metadata
        .annotations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let spec = pod.spec.as_ref();
    let service_account = spec
        .and_then(|s| s.service_account_name.clone())
        .unwrap_or_default();
    let node_name = spec.and_then(|s| s.node_name.clone()).unwrap_or_default();

    let owner = metadata.owner_references.as_ref().and_then(|refs| refs.first());
    let owner_kind = owner.map(|o| o.kind.clone());
    let owner_name = owner.map(|o| o.name.clone());

    let mut container_ids = Vec::new();
    let mut container_names = BTreeMap::new();
    if let Some(status) = pod.status.as_ref() {
        let all = status
            .container_statuses
            .iter()
            .flatten()
            .chain(status.init_container_statuses.iter().flatten())
            .chain(status.ephemeral_container_statuses.iter().flatten());
        for cs in all {
            if let Some(raw) = cs.container_id.as_deref() {
                let id = strip_cri_prefix(raw).to_string();
                if !id.is_empty() {
                    container_names.insert(id.clone(), cs.name.clone());
                    container_ids.push(id);
                }
            }
        }
    }

    Some(PodInfo {
        uid,
        name,
        namespace,
        labels,
        annotations,
        service_account,
        owner_kind,
        owner_name,
        node_name,
        container_ids,
        container_names,
    })
}

/// Strip the known CRI runtime prefixes from a containerID string.
pub fn strip_cri_prefix(raw: &str) -> &str {
    for prefix in CRI_PREFIXES {
        if let Some(rest) = raw.strip_prefix(prefix) {
            return rest;
        }
    }
    raw
}

/// Returns `true` if the agent appears to be running inside a Kubernetes pod.
pub fn is_running_in_kubernetes() -> bool {
    std::env::var("KUBERNETES_SERVICE_HOST").is_ok()
}

/// Resolve the local node name from env or hostname.
///
/// Lookup order: `EBPFSENTINEL_NODE_NAME` → `HOSTNAME` →
/// `/proc/sys/kernel/hostname`. Returns an empty string when none of these
/// yields a non-empty value.
pub fn resolve_node_name() -> String {
    if let Ok(name) = std::env::var("EBPFSENTINEL_NODE_NAME")
        && !name.is_empty()
    {
        return name;
    }
    if let Ok(name) = std::env::var("HOSTNAME")
        && !name.is_empty()
    {
        return name;
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Metrics counters maintained by the enricher.
#[derive(Debug, Default)]
pub struct K8sEnricherMetrics {
    pub pods_cached: std::sync::atomic::AtomicU64,
    pub lookups_total: std::sync::atomic::AtomicU64,
    pub misses_total: std::sync::atomic::AtomicU64,
    pub api_errors_total: std::sync::atomic::AtomicU64,
}

/// Kubernetes metadata enricher.
pub struct KubernetesEnricher {
    cache: Arc<PodCache>,
    available: AtomicBool,
    namespace_hook: Mutex<Option<Arc<dyn NamespaceHook>>>,
    metrics: Arc<K8sEnricherMetrics>,
}

impl KubernetesEnricher {
    pub fn new_disabled() -> Self {
        Self {
            cache: Arc::new(PodCache::new()),
            available: AtomicBool::new(false),
            namespace_hook: Mutex::new(None),
            metrics: Arc::new(K8sEnricherMetrics::default()),
        }
    }

    pub fn with_cache(cache: Arc<PodCache>) -> Self {
        Self {
            cache,
            available: AtomicBool::new(true),
            namespace_hook: Mutex::new(None),
            metrics: Arc::new(K8sEnricherMetrics::default()),
        }
    }

    pub fn metrics(&self) -> Arc<K8sEnricherMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn cache(&self) -> Arc<PodCache> {
        Arc::clone(&self.cache)
    }

    pub async fn set_namespace_hook(&self, hook: Arc<dyn NamespaceHook>) {
        *self.namespace_hook.lock().await = Some(hook);
    }

    fn is_k8s_runtime(runtime: ContainerRuntime) -> bool {
        matches!(
            runtime,
            ContainerRuntime::Containerd
                | ContainerRuntime::CriO
                | ContainerRuntime::Docker
        )
    }
}

#[async_trait]
impl MetadataEnricher for KubernetesEnricher {
    fn name(&self) -> &'static str {
        "kubernetes"
    }

    async fn enrich(
        &self,
        info: &ContainerInfo,
    ) -> Result<Option<ContainerMetadata>, ContainerError> {
        if !self.available.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let ContainerInfo::Container {
            container_id,
            runtime,
            ..
        } = info
        else {
            return Ok(None);
        };
        if !Self::is_k8s_runtime(*runtime) {
            return Ok(None);
        }
        self.metrics
            .lookups_total
            .fetch_add(1, Ordering::Relaxed);
        let Some(pod) = self.cache.get(container_id).await else {
            self.metrics.misses_total.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        // Fire the namespace hook (best-effort — enterprise multi-tenancy).
        if let Some(hook) = self.namespace_hook.lock().await.as_ref() {
            let _ = hook.on_namespace_resolved(&pod.namespace);
        }
        let metadata = pod.to_metadata(container_id);
        Ok(Some(ContainerMetadata::Kubernetes(metadata)))
    }
}

/// Build a [`kube::Client`] from the in-cluster config. Returns `None` when
/// no cluster is reachable (non-K8s deployment).
pub async fn try_build_client() -> Option<Client> {
    if !is_running_in_kubernetes() {
        return None;
    }
    match Client::try_default().await {
        Ok(c) => Some(c),
        Err(err) => {
            warn!(error = %err, "failed to build kube client — enricher disabled");
            None
        }
    }
}

/// Spawn a background task that watches pods on the given node and keeps
/// the [`PodCache`] in sync. The returned [`JoinHandle`] can be used to
/// cancel the watcher (via the wrapping cancellation token in the agent).
pub fn spawn_pod_watcher(
    client: Client,
    node_name: String,
    cache: Arc<PodCache>,
    metrics: Arc<K8sEnricherMetrics>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let pods: Api<Pod> = Api::all(client);
        let config = if node_name.is_empty() {
            watcher::Config::default()
        } else {
            watcher::Config::default().fields(&format!("spec.nodeName={node_name}"))
        };
        info!(
            node = %node_name,
            "kubernetes pod watcher started"
        );
        let mut stream = watcher::watcher(pods, config).boxed();
        while let Some(event) = stream.next().await {
            match event {
                Ok(Event::Apply(pod) | Event::InitApply(pod)) => {
                    if let Some(info) = pod_info_from(&pod) {
                        cache.upsert(info).await;
                        let current = cache.len().await as u64;
                        metrics.pods_cached.store(current, Ordering::Relaxed);
                    }
                }
                Ok(Event::Delete(pod)) => {
                    if let Some(uid) = pod.metadata.uid.as_deref() {
                        cache.delete(uid).await;
                        let current = cache.len().await as u64;
                        metrics.pods_cached.store(current, Ordering::Relaxed);
                    }
                }
                Ok(Event::Init | Event::InitDone) => {}
                Err(err) => {
                    metrics
                        .api_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(error = %err, "kube pod watcher error, backing off 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
        debug!("kubernetes pod watcher stream closed");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{
        ContainerStatus, Pod, PodSpec, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};

    fn pod(
        uid: &str,
        name: &str,
        namespace: &str,
        node: &str,
        containers: &[(&str, &str)],
    ) -> Pod {
        Pod {
            metadata: ObjectMeta {
                uid: Some(uid.into()),
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                labels: Some(
                    [("app".to_string(), name.to_string())]
                        .into_iter()
                        .collect(),
                ),
                annotations: Some(
                    [("note".to_string(), "ok".to_string())]
                        .into_iter()
                        .collect(),
                ),
                owner_references: Some(vec![OwnerReference {
                    api_version: "apps/v1".into(),
                    kind: "ReplicaSet".into(),
                    name: format!("{name}-rs"),
                    uid: "ignored".into(),
                    controller: Some(true),
                    block_owner_deletion: None,
                }]),
                ..Default::default()
            },
            spec: Some(PodSpec {
                node_name: Some(node.into()),
                service_account_name: Some("sa".into()),
                ..Default::default()
            }),
            status: Some(PodStatus {
                container_statuses: Some(
                    containers
                        .iter()
                        .map(|(cname, cid)| ContainerStatus {
                            name: (*cname).to_string(),
                            container_id: Some((*cid).to_string()),
                            image: "img".into(),
                            image_id: "img".into(),
                            ready: true,
                            restart_count: 0,
                            started: Some(true),
                            ..Default::default()
                        })
                        .collect(),
                ),
                ..Default::default()
            }),
        }
    }

    #[tokio::test]
    async fn pod_cache_upsert_and_get() {
        let cache = PodCache::new();
        let p = pod(
            "uid-1",
            "app",
            "default",
            "node-a",
            &[("c1", "containerd://abc")],
        );
        let info = pod_info_from(&p).unwrap();
        cache.upsert(info).await;
        let got = cache.get("abc").await.unwrap();
        assert_eq!(got.name, "app");
        assert_eq!(got.namespace, "default");
        assert_eq!(got.node_name, "node-a");
        assert_eq!(got.owner_kind.as_deref(), Some("ReplicaSet"));
        assert_eq!(got.service_account, "sa");
    }

    #[tokio::test]
    async fn pod_cache_delete_removes_reverse_index() {
        let cache = PodCache::new();
        let p = pod(
            "uid-1",
            "app",
            "default",
            "node-a",
            &[("c1", "containerd://abc")],
        );
        cache.upsert(pod_info_from(&p).unwrap()).await;
        assert!(cache.get("abc").await.is_some());
        cache.delete("uid-1").await;
        assert!(cache.get("abc").await.is_none());
        assert!(cache.is_empty().await);
    }

    #[tokio::test]
    async fn pod_cache_multiple_containers_per_pod() {
        let cache = PodCache::new();
        let p = pod(
            "uid-1",
            "app",
            "prod",
            "node-b",
            &[
                ("app", "containerd://c1"),
                ("sidecar", "containerd://c2"),
            ],
        );
        cache.upsert(pod_info_from(&p).unwrap()).await;
        assert!(cache.get("c1").await.is_some());
        assert!(cache.get("c2").await.is_some());
    }

    #[tokio::test]
    async fn pod_cache_restart_replaces_container_id() {
        let cache = PodCache::new();
        let p1 = pod("uid-1", "app", "prod", "n", &[("app", "containerd://old")]);
        cache.upsert(pod_info_from(&p1).unwrap()).await;
        let p2 = pod("uid-1", "app", "prod", "n", &[("app", "containerd://new")]);
        cache.upsert(pod_info_from(&p2).unwrap()).await;
        assert!(cache.get("old").await.is_none());
        assert!(cache.get("new").await.is_some());
        assert_eq!(cache.len().await, 1);
    }

    #[tokio::test]
    async fn pod_cache_returns_none_for_unknown_id() {
        let cache = PodCache::new();
        assert!(cache.get("no-such-id").await.is_none());
    }

    #[test]
    fn strip_prefix_all_runtimes() {
        assert_eq!(strip_cri_prefix("containerd://abc"), "abc");
        assert_eq!(strip_cri_prefix("cri-o://def"), "def");
        assert_eq!(strip_cri_prefix("docker://xyz"), "xyz");
        assert_eq!(strip_cri_prefix("raw"), "raw");
    }

    #[test]
    fn resolve_node_name_never_panics() {
        let _ = resolve_node_name();
    }

    #[tokio::test]
    async fn disabled_enricher_returns_none() {
        let e = KubernetesEnricher::new_disabled();
        let info = ContainerInfo::Container {
            container_id: "abc".into(),
            runtime: ContainerRuntime::Containerd,
            cgroup_path: "/".into(),
            pid: 1,
        };
        assert!(e.enrich(&info).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn enricher_skips_host_info() {
        let cache = Arc::new(PodCache::new());
        let e = KubernetesEnricher::with_cache(cache);
        assert!(e.enrich(&ContainerInfo::Host).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn enricher_returns_metadata_on_hit() {
        let cache = Arc::new(PodCache::new());
        let p = pod(
            "uid-1",
            "app",
            "prod",
            "node-a",
            &[("app", "containerd://abc")],
        );
        cache.upsert(pod_info_from(&p).unwrap()).await;
        let e = KubernetesEnricher::with_cache(Arc::clone(&cache));
        let info = ContainerInfo::Container {
            container_id: "abc".into(),
            runtime: ContainerRuntime::Containerd,
            cgroup_path: "/".into(),
            pid: 1,
        };
        let md = e.enrich(&info).await.unwrap().unwrap();
        let ContainerMetadata::Kubernetes(k) = md else {
            panic!("expected kubernetes metadata");
        };
        assert_eq!(k.pod_name, "app");
        assert_eq!(k.namespace, "prod");
        assert_eq!(k.container_name, "app");
        assert_eq!(k.node_name, "node-a");
        assert_eq!(k.service_account, "sa");
    }

    #[tokio::test]
    async fn enricher_miss_returns_none_and_increments() {
        let cache = Arc::new(PodCache::new());
        let e = KubernetesEnricher::with_cache(cache);
        let info = ContainerInfo::Container {
            container_id: "missing".into(),
            runtime: ContainerRuntime::CriO,
            cgroup_path: "/".into(),
            pid: 1,
        };
        assert!(e.enrich(&info).await.unwrap().is_none());
        assert_eq!(
            e.metrics.misses_total.load(Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn namespace_hook_invoked_on_hit() {
        use std::sync::Mutex as StdMutex;

        struct CaptureHook(Arc<StdMutex<Vec<String>>>);
        impl NamespaceHook for CaptureHook {
            fn on_namespace_resolved(&self, namespace: &str) -> Option<String> {
                self.0.lock().unwrap().push(namespace.to_string());
                None
            }
        }

        let captured = Arc::new(StdMutex::new(Vec::new()));
        let hook = Arc::new(CaptureHook(Arc::clone(&captured)));

        let cache = Arc::new(PodCache::new());
        let p = pod(
            "uid-1",
            "app",
            "prod",
            "n",
            &[("app", "containerd://abc")],
        );
        cache.upsert(pod_info_from(&p).unwrap()).await;
        let e = KubernetesEnricher::with_cache(cache);
        e.set_namespace_hook(hook).await;
        let info = ContainerInfo::Container {
            container_id: "abc".into(),
            runtime: ContainerRuntime::Containerd,
            cgroup_path: "/".into(),
            pid: 1,
        };
        e.enrich(&info).await.unwrap();
        assert_eq!(captured.lock().unwrap().as_slice(), &["prod".to_string()]);
    }

    #[test]
    fn pod_info_from_missing_uid_returns_none() {
        let mut p = pod("uid-1", "app", "prod", "n", &[]);
        p.metadata.uid = None;
        assert!(pod_info_from(&p).is_none());
    }

    #[test]
    fn pod_info_from_strips_cri_prefix_for_all_runtimes() {
        let p = pod(
            "uid-1",
            "app",
            "prod",
            "n",
            &[
                ("c1", "containerd://a"),
                ("c2", "cri-o://b"),
                ("c3", "docker://c"),
            ],
        );
        let info = pod_info_from(&p).unwrap();
        assert!(info.container_ids.contains(&"a".to_string()));
        assert!(info.container_ids.contains(&"b".to_string()));
        assert!(info.container_ids.contains(&"c".to_string()));
    }
}
