use serde::{Deserialize, Serialize};
use std::fmt;

/// Container runtime that owns a given process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContainerRuntime {
    Docker,
    Containerd,
    CriO,
    Podman,
    Unknown,
}

impl fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Docker => "docker",
            Self::Containerd => "containerd",
            Self::CriO => "crio",
            Self::Podman => "podman",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

/// Resolution of a process to either a container or the host namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ContainerInfo {
    /// Process runs in the host cgroup (no container context).
    Host,
    /// Process runs inside a container.
    Container {
        container_id: String,
        runtime: ContainerRuntime,
        cgroup_path: String,
        pid: u32,
    },
}

impl ContainerInfo {
    /// Returns the container ID if this process runs in a container.
    pub fn container_id(&self) -> Option<&str> {
        match self {
            Self::Container { container_id, .. } => Some(container_id),
            Self::Host => None,
        }
    }

    /// Returns the detected runtime.
    pub fn runtime(&self) -> ContainerRuntime {
        match self {
            Self::Container { runtime, .. } => *runtime,
            Self::Host => ContainerRuntime::Unknown,
        }
    }

    /// Returns `true` if this is a host (non-containerised) process.
    pub fn is_host(&self) -> bool {
        matches!(self, Self::Host)
    }
}

impl fmt::Display for ContainerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => f.write_str("host"),
            Self::Container {
                container_id,
                runtime,
                ..
            } => {
                let short = &container_id[..container_id.len().min(12)];
                write!(f, "{runtime}://{short}")
            }
        }
    }
}

/// Enricher-specific metadata attached to a container. Kept in its own
/// enum so OSS agents can work with `Docker(..)` / `Kubernetes(..)` variants
/// populated by optional adapters, and enterprise enrichers can extend the
/// set via a non-exhaustive marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
#[non_exhaustive]
pub enum ContainerMetadata {
    Docker(DockerMetadata),
    Kubernetes(KubernetesMetadata),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerMetadata {
    pub name: String,
    pub image: String,
    pub labels: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubernetesMetadata {
    pub pod_name: String,
    pub namespace: String,
    pub container_name: String,
    pub labels: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub annotations: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub service_account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_name: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_name: String,
}

/// Full container context attached to an event: the cgroup-derived
/// `ContainerInfo` plus any enricher metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerContext {
    pub info: ContainerInfo,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContainerMetadata>,
}

impl ContainerContext {
    pub fn new(info: ContainerInfo) -> Self {
        Self {
            info,
            metadata: None,
        }
    }

    pub fn with_metadata(info: ContainerInfo, metadata: ContainerMetadata) -> Self {
        Self {
            info,
            metadata: Some(metadata),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_host() {
        assert_eq!(ContainerInfo::Host.to_string(), "host");
    }

    #[test]
    fn display_container_truncates_id() {
        let info = ContainerInfo::Container {
            container_id: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                .to_string(),
            runtime: ContainerRuntime::Docker,
            cgroup_path: "/system.slice/docker-abcdef.scope".to_string(),
            pid: 1234,
        };
        assert_eq!(info.to_string(), "docker://abcdef123456");
    }

    #[test]
    fn container_id_accessor() {
        let info = ContainerInfo::Container {
            container_id: "id".to_string(),
            runtime: ContainerRuntime::Podman,
            cgroup_path: "/libpod-id.scope".to_string(),
            pid: 1,
        };
        assert_eq!(info.container_id(), Some("id"));
        assert!(!info.is_host());
        assert_eq!(info.runtime(), ContainerRuntime::Podman);
    }

    #[test]
    fn host_accessor() {
        let info = ContainerInfo::Host;
        assert_eq!(info.container_id(), None);
        assert!(info.is_host());
    }

    #[test]
    fn runtime_display_all() {
        assert_eq!(ContainerRuntime::Docker.to_string(), "docker");
        assert_eq!(ContainerRuntime::Containerd.to_string(), "containerd");
        assert_eq!(ContainerRuntime::CriO.to_string(), "crio");
        assert_eq!(ContainerRuntime::Podman.to_string(), "podman");
        assert_eq!(ContainerRuntime::Unknown.to_string(), "unknown");
    }
}
