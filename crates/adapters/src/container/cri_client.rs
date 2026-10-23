//! Minimal CRI runtime-service client over a Unix socket.
//!
//! containerd and CRI-O both serve the Kubernetes CRI runtime service, so one
//! client speaks to either: the socket decides which runtime answers, not a
//! configuration switch. Only the four calls the agent makes are generated
//! from `proto/cri/v1/runtime.proto`, which carries the subset of the upstream
//! definition they need.
//!
//! What a caller gets is a label index: container id to the labels that
//! container carries, with the labels of the pod it belongs to merged
//! underneath. The kubelet writes a pod's own labels on the sandbox and only
//! `io.kubernetes.*` labels on the container, so a claim written on a pod is
//! invisible to anyone reading containers alone.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use proto::runtime_service_client::RuntimeServiceClient;
use proto::{
    Container, ContainerEventType, GetEventsRequest, ListContainersRequest, ListPodSandboxRequest,
    PodSandbox, VersionRequest,
};

/// Generated CRI runtime-service types and client stub.
#[allow(clippy::doc_markdown, clippy::default_trait_access)]
pub mod proto {
    tonic::include_proto!("runtime.v1");
}

/// containerd's default CRI socket.
pub const DEFAULT_CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";
/// CRI-O's default socket.
pub const DEFAULT_CRIO_SOCKET: &str = "/run/crio/crio.sock";
/// Default per-call timeout.
pub const DEFAULT_TIMEOUT_MS: u64 = 2_000;
/// The CRI API version this client asks for, echoed back by the runtime.
const CRI_API_VERSION: &str = "v1";
/// The label the kubelet writes the pod's namespace on.
pub const K8S_NAMESPACE_LABEL: &str = "io.kubernetes.pod.namespace";

/// Container id to the labels that container resolves with.
pub type CriLabelIndex = HashMap<String, HashMap<String, String>>;

/// What went wrong talking to a CRI runtime.
#[derive(Debug, thiserror::Error)]
pub enum CriError {
    /// Nothing is listening at that path, which is the ordinary state of a
    /// node that does not run this runtime.
    #[error("no CRI socket at {0}")]
    NoSocket(String),
    /// The runtime answered, with a status that is not success.
    #[error("the CRI runtime on {socket} answered {code:?}: {message}")]
    Rpc {
        /// The socket the call was made on.
        socket: String,
        /// The gRPC status code.
        code: tonic::Code,
        /// The status message, as the runtime wrote it.
        message: String,
    },
    /// The call did not come back inside the configured budget.
    #[error("the CRI runtime on {socket} did not answer within {timeout_ms} ms")]
    Timeout {
        /// The socket the call was made on.
        socket: String,
        /// The budget that elapsed.
        timeout_ms: u64,
    },
}

impl CriError {
    /// Whether the runtime declined because it does not implement the call.
    ///
    /// A runtime without the event stream answers `UNIMPLEMENTED` once, which
    /// is a reason to fall back to polling rather than an error to report on
    /// every pass.
    #[must_use]
    pub fn is_unimplemented(&self) -> bool {
        matches!(
            self,
            Self::Rpc {
                code: tonic::Code::Unimplemented,
                ..
            }
        )
    }
}

/// A container lifecycle event, as the runtime reported it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriEventKind {
    /// The container exists.
    Created,
    /// The container is running.
    Started,
    /// The container stopped.
    Stopped,
    /// The container is gone.
    Deleted,
    /// A type this build does not name.
    Unknown,
}

impl From<i32> for CriEventKind {
    fn from(value: i32) -> Self {
        match ContainerEventType::try_from(value) {
            Ok(ContainerEventType::ContainerCreatedEvent) => Self::Created,
            Ok(ContainerEventType::ContainerStartedEvent) => Self::Started,
            Ok(ContainerEventType::ContainerStoppedEvent) => Self::Stopped,
            Ok(ContainerEventType::ContainerDeletedEvent) => Self::Deleted,
            Err(_) => Self::Unknown,
        }
    }
}

/// One container lifecycle event.
#[derive(Debug, Clone)]
pub struct CriEvent {
    /// The container the event is about.
    pub container_id: String,
    /// What happened to it.
    pub kind: CriEventKind,
}

/// A CRI runtime reached over its own Unix socket.
#[derive(Clone)]
pub struct CriClient {
    socket: PathBuf,
    timeout: Duration,
    timeout_ms: u64,
    channel: Channel,
}

impl CriClient {
    /// Build a client for one socket. Nothing is connected here: the channel
    /// is lazy, so a client for a socket this node does not have costs
    /// nothing until somebody calls it.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>, timeout_ms: u64) -> Self {
        let socket = socket.into();
        let connect_to = socket.clone();
        // The authority is never used: the connector below decides where the
        // bytes go. A static URI is what keeps this constructor infallible.
        let channel = Endpoint::from_static("http://cri.invalid")
            .connect_timeout(Duration::from_millis(timeout_ms))
            .connect_with_connector_lazy(service_fn(move |_: Uri| {
                let path = connect_to.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }));
        Self {
            socket,
            timeout: Duration::from_millis(timeout_ms),
            timeout_ms,
            channel,
        }
    }

    /// The socket this client was built for.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket
    }

    /// Whether that socket is there at all.
    #[must_use]
    pub fn socket_present(&self) -> bool {
        self.socket.exists()
    }

    fn stub(&self) -> RuntimeServiceClient<Channel> {
        RuntimeServiceClient::new(self.channel.clone())
    }

    fn socket_name(&self) -> String {
        self.socket.display().to_string()
    }

    fn rpc_error(&self, status: &tonic::Status) -> CriError {
        CriError::Rpc {
            socket: self.socket_name(),
            code: status.code(),
            message: status.message().to_string(),
        }
    }

    fn timeout_error(&self) -> CriError {
        CriError::Timeout {
            socket: self.socket_name(),
            timeout_ms: self.timeout_ms,
        }
    }

    fn require_socket(&self) -> Result<(), CriError> {
        if self.socket_present() {
            Ok(())
        } else {
            Err(CriError::NoSocket(self.socket_name()))
        }
    }

    /// Which runtime answers on this socket.
    ///
    /// This is the probe the caller selects a resolver with: a node with both
    /// runtimes has both sockets answer, and each is used for the containers
    /// it owns.
    ///
    /// # Errors
    ///
    /// [`CriError::NoSocket`] when the path does not exist, [`CriError::Timeout`]
    /// when nothing answers inside the budget, [`CriError::Rpc`] when the
    /// runtime refuses the call.
    pub async fn runtime_name(&self) -> Result<String, CriError> {
        self.require_socket()?;
        let request = VersionRequest {
            version: CRI_API_VERSION.to_string(),
        };
        let answer = tokio::time::timeout(self.timeout, self.stub().version(request))
            .await
            .map_err(|_| self.timeout_error())?
            .map_err(|status| self.rpc_error(&status))?
            .into_inner();
        if answer.runtime_name.is_empty() {
            Ok("unknown".to_string())
        } else {
            Ok(answer.runtime_name)
        }
    }

    /// Every container on this node, with the labels it resolves with.
    ///
    /// # Errors
    ///
    /// As [`CriClient::runtime_name`].
    pub async fn label_index(&self) -> Result<CriLabelIndex, CriError> {
        self.require_socket()?;
        let mut stub = self.stub();
        let containers = tokio::time::timeout(
            self.timeout,
            stub.list_containers(ListContainersRequest { filter: None }),
        )
        .await
        .map_err(|_| self.timeout_error())?
        .map_err(|status| self.rpc_error(&status))?
        .into_inner()
        .containers;
        let sandboxes = tokio::time::timeout(
            self.timeout,
            stub.list_pod_sandbox(ListPodSandboxRequest { filter: None }),
        )
        .await
        .map_err(|_| self.timeout_error())?
        .map_err(|status| self.rpc_error(&status))?
        .into_inner()
        .items;
        Ok(index_from(containers, &sandboxes))
    }

    /// Follow the runtime's own lifecycle events until the stream ends or the
    /// receiver is dropped.
    ///
    /// This is what makes a container started after the agent resolvable
    /// without waiting for the next pass. A runtime that does not implement
    /// the stream answers `UNIMPLEMENTED`, which the caller reads off
    /// [`CriError::is_unimplemented`] and answers by polling.
    ///
    /// # Errors
    ///
    /// As [`CriClient::runtime_name`]. The stream itself is not under the
    /// per-call budget: it is meant to stay open.
    pub async fn watch_events(&self, events: mpsc::Sender<CriEvent>) -> Result<(), CriError> {
        self.require_socket()?;
        let mut stream = tokio::time::timeout(
            self.timeout,
            self.stub().get_container_events(GetEventsRequest {}),
        )
        .await
        .map_err(|_| self.timeout_error())?
        .map_err(|status| self.rpc_error(&status))?
        .into_inner();
        loop {
            match stream.message().await {
                Ok(Some(event)) => {
                    let event = CriEvent {
                        container_id: event.container_id,
                        kind: CriEventKind::from(event.container_event_type),
                    };
                    if events.send(event).await.is_err() {
                        // Nobody is listening any more, which is a shutdown
                        // rather than a failure.
                        return Ok(());
                    }
                }
                Ok(None) => return Ok(()),
                Err(status) => return Err(self.rpc_error(&status)),
            }
        }
    }
}

/// Merge a node's containers and pods into one label index.
///
/// The pod's labels go in first and the container's own labels on top, so a
/// claim written on a container is the narrower of the two and wins. The
/// sandbox metadata supplies the namespace when no label carries it.
#[must_use]
pub fn index_from(containers: Vec<Container>, sandboxes: &[PodSandbox]) -> CriLabelIndex {
    let pods: HashMap<&str, &PodSandbox> =
        sandboxes.iter().map(|pod| (pod.id.as_str(), pod)).collect();
    let mut index = CriLabelIndex::with_capacity(containers.len());
    for container in containers {
        let mut labels = HashMap::new();
        if let Some(pod) = pods.get(container.pod_sandbox_id.as_str()) {
            for (key, value) in &pod.labels {
                labels.insert(key.clone(), value.clone());
            }
            if let Some(metadata) = pod.metadata.as_ref()
                && !metadata.namespace.is_empty()
            {
                labels
                    .entry(K8S_NAMESPACE_LABEL.to_string())
                    .or_insert_with(|| metadata.namespace.clone());
            }
        }
        for (key, value) in container.labels {
            labels.insert(key, value);
        }
        index.insert(container.id, labels);
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::PodSandboxMetadata;

    fn sandbox(id: &str, namespace: &str, labels: &[(&str, &str)]) -> PodSandbox {
        PodSandbox {
            id: id.to_string(),
            metadata: Some(PodSandboxMetadata {
                name: format!("pod-{id}"),
                uid: format!("uid-{id}"),
                namespace: namespace.to_string(),
                attempt: 0,
            }),
            state: 0,
            created_at: 0,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            annotations: HashMap::new(),
            runtime_handler: String::new(),
        }
    }

    fn container(id: &str, sandbox_id: &str, labels: &[(&str, &str)]) -> Container {
        Container {
            id: id.to_string(),
            pod_sandbox_id: sandbox_id.to_string(),
            metadata: None,
            image: None,
            image_ref: String::new(),
            state: 1,
            created_at: 0,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            annotations: HashMap::new(),
        }
    }

    #[test]
    fn a_pods_own_labels_reach_its_containers() {
        let index = index_from(
            vec![container("c1", "p1", &[])],
            &[sandbox(
                "p1",
                "team-a",
                &[("ebpfsentinel.io/tenant", "blue")],
            )],
        );
        let labels = index.get("c1").expect("the container is indexed");
        assert_eq!(
            labels.get("ebpfsentinel.io/tenant").map(String::as_str),
            Some("blue")
        );
    }

    #[test]
    fn a_container_label_wins_over_the_pods() {
        let index = index_from(
            vec![container(
                "c1",
                "p1",
                &[("ebpfsentinel.io/tenant", "green")],
            )],
            &[sandbox(
                "p1",
                "team-a",
                &[("ebpfsentinel.io/tenant", "blue")],
            )],
        );
        let labels = index.get("c1").expect("the container is indexed");
        assert_eq!(
            labels.get("ebpfsentinel.io/tenant").map(String::as_str),
            Some("green")
        );
    }

    #[test]
    fn the_namespace_falls_back_to_the_sandbox_metadata() {
        let index = index_from(
            vec![container("c1", "p1", &[])],
            &[sandbox("p1", "team-a", &[])],
        );
        let labels = index.get("c1").expect("the container is indexed");
        assert_eq!(
            labels.get(K8S_NAMESPACE_LABEL).map(String::as_str),
            Some("team-a")
        );
    }

    #[test]
    fn a_namespace_label_is_left_as_the_kubelet_wrote_it() {
        let index = index_from(
            vec![container("c1", "p1", &[(K8S_NAMESPACE_LABEL, "team-b")])],
            &[sandbox("p1", "team-a", &[])],
        );
        let labels = index.get("c1").expect("the container is indexed");
        assert_eq!(
            labels.get(K8S_NAMESPACE_LABEL).map(String::as_str),
            Some("team-b")
        );
    }

    #[test]
    fn a_container_without_its_sandbox_is_still_indexed() {
        let index = index_from(vec![container("c1", "gone", &[("app", "web")])], &[]);
        let labels = index.get("c1").expect("the container is indexed");
        assert_eq!(labels.get("app").map(String::as_str), Some("web"));
        assert!(!labels.contains_key(K8S_NAMESPACE_LABEL));
    }

    #[tokio::test]
    async fn an_absent_socket_is_named_rather_than_dialled() {
        let client = CriClient::new("/nonexistent/cri.sock", DEFAULT_TIMEOUT_MS);
        assert!(!client.socket_present());
        let error = client.label_index().await.expect_err("there is no socket");
        assert!(matches!(error, CriError::NoSocket(ref path) if path == "/nonexistent/cri.sock"));
        assert!(!error.is_unimplemented());
        assert_eq!(
            client.socket_path(),
            std::path::Path::new("/nonexistent/cri.sock")
        );
    }

    #[tokio::test]
    async fn an_absent_socket_refuses_the_event_stream_too() {
        let client = CriClient::new(DEFAULT_CRIO_SOCKET, DEFAULT_TIMEOUT_MS);
        if client.socket_present() {
            // This node really runs CRI-O; the path is exercised for real
            // elsewhere and there is nothing to assert about an absent socket.
            return;
        }
        let (tx, _rx) = mpsc::channel(1);
        let error = client
            .watch_events(tx)
            .await
            .expect_err("there is no socket");
        assert!(matches!(error, CriError::NoSocket(_)));
    }

    #[test]
    fn every_event_type_the_runtime_sends_has_a_name() {
        assert_eq!(CriEventKind::from(0), CriEventKind::Created);
        assert_eq!(CriEventKind::from(1), CriEventKind::Started);
        assert_eq!(CriEventKind::from(2), CriEventKind::Stopped);
        assert_eq!(CriEventKind::from(3), CriEventKind::Deleted);
        assert_eq!(CriEventKind::from(99), CriEventKind::Unknown);
    }
}
