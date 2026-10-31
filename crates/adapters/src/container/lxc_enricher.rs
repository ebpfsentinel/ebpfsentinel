//! LXC metadata enricher: Proxmox CTs, Incus instances and plain LXC.
//!
//! An LXC container is a cgroup like any other, so the resolver already
//! files its processes under the container and the name the cgroup carries
//! (see [`domain::container::engine::lxc_name`]). This adds what the cgroup
//! does not say, from whichever source the node has:
//!
//! - a Proxmox CT is a number, and `/etc/pve/lxc/<vmid>.conf` gives its
//!   hostname, its tags and its OS type;
//! - an Incus instance is `<project>_<name>` outside the default project,
//!   and the daemon's socket gives its `user.*` keys, which are the labels
//!   an operator sets on it, and the image it was made from;
//! - anything else is a plain LXC container, whose cgroup name is the name
//!   `lxc-start -n` was given and which has no labels to read.
//!
//! What comes back is filed as [`ContainerMetadata::Docker`], as Podman's is:
//! a name, an image and labels is the shape every consumer already reads,
//! so a workload selector, an alert and a DLP scope name a CT exactly as
//! they name a Docker container, and the container's own runtime field
//! still says `lxc`. A source that is absent or does not answer costs the
//! labels and never the name.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use serde::Deserialize;
use tracing::debug;

use domain::container::entity::{
    ContainerInfo, ContainerMetadata, ContainerRuntime, DockerMetadata,
};
use domain::container::error::ContainerError;
use ports::secondary::metadata_enricher_port::MetadataEnricher;

use super::docker_cache::DockerCache;
use super::docker_client::DockerClient;

/// Where Proxmox keeps one file per CT.
pub const DEFAULT_PROXMOX_DIR: &str = "/etc/pve/lxc";
/// The Incus daemon's socket.
pub const DEFAULT_INCUS_SOCKET: &str = "/var/lib/incus/unix.socket";

/// The label carrying a Proxmox CT's number.
pub const LABEL_PROXMOX_VMID: &str = "proxmox.vmid";
/// The label repeated once per Proxmox tag.
pub const LABEL_PROXMOX_TAG: &str = "proxmox.tag";
/// The label carrying an Incus instance's project.
pub const LABEL_INCUS_PROJECT: &str = "incus.project";

/// Names LXC containers and reads their labels where the node keeps them.
pub struct LxcEnricher {
    proxmox_dir: Option<PathBuf>,
    incus: Option<DockerClient>,
    cache: DockerCache,
}

impl LxcEnricher {
    /// `proxmox_dir` and `incus_socket` are each optional: a node is a
    /// Proxmox host, an Incus host, both, or neither.
    pub fn new(
        proxmox_dir: Option<PathBuf>,
        incus_socket: Option<PathBuf>,
        timeout_ms: u64,
        cache: DockerCache,
    ) -> Self {
        Self {
            proxmox_dir,
            incus: incus_socket.map(|socket| DockerClient::new(socket, timeout_ms)),
            cache,
        }
    }

    async fn describe(&self, name: &str) -> DockerMetadata {
        if let Some(dir) = self.proxmox_dir.as_deref()
            && let Some(md) = proxmox(dir, name).await
        {
            return md;
        }
        if let Some(client) = self.incus.as_ref()
            && client.socket_path().exists()
        {
            let (project, instance) = incus_instance(name);
            let path = format!("/1.0/instances/{instance}?project={project}");
            match client.get_body(&path).await {
                Ok(body) => match parse_incus_instance(&body, project, instance) {
                    Ok(md) => return md,
                    Err(err) => debug!(error = %err, name, "incus answer unreadable"),
                },
                Err(err) => debug!(error = %err, name, "incus did not describe the instance"),
            }
        }
        named_only(name)
    }
}

#[async_trait]
impl MetadataEnricher for LxcEnricher {
    fn name(&self) -> &'static str {
        "lxc"
    }

    async fn enrich(
        &self,
        info: &ContainerInfo,
    ) -> Result<Option<ContainerMetadata>, ContainerError> {
        let ContainerInfo::Container {
            container_id,
            runtime: ContainerRuntime::Lxc,
            ..
        } = info
        else {
            return Ok(None);
        };
        if let Some(md) = self.cache.get(container_id) {
            return Ok(Some(ContainerMetadata::Docker(md)));
        }
        let md = self.describe(container_id).await;
        self.cache.insert(container_id.clone(), md.clone());
        Ok(Some(ContainerMetadata::Docker(md)))
    }
}

/// The name the cgroup gave, and nothing the agent could not read.
fn named_only(name: &str) -> DockerMetadata {
    DockerMetadata {
        name: name.to_string(),
        image: String::new(),
        labels: Vec::new(),
        created_at: String::new(),
        status: String::new(),
    }
}

/// A Proxmox CT, when `name` is a vmid with a configuration file.
async fn proxmox(dir: &Path, name: &str) -> Option<DockerMetadata> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let text = tokio::fs::read_to_string(dir.join(format!("{name}.conf")))
        .await
        .ok()?;
    Some(parse_proxmox_conf(name, &text))
}

/// Reads a CT's current configuration, which ends where its first snapshot
/// section starts.
pub fn parse_proxmox_conf(vmid: &str, text: &str) -> DockerMetadata {
    let mut md = named_only(vmid);
    md.labels
        .push((LABEL_PROXMOX_VMID.to_string(), vmid.to_string()));
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "hostname" if !value.is_empty() => md.name = value.to_string(),
            "ostype" => md.image = value.to_string(),
            "tags" => md.labels.extend(
                value
                    .split([';', ',', ' '])
                    .filter(|tag| !tag.is_empty())
                    .map(|tag| (LABEL_PROXMOX_TAG.to_string(), tag.to_string())),
            ),
            _ => {}
        }
    }
    md
}

/// An Incus cgroup name split into its project and its instance. An
/// instance name may not hold an underscore, so the last one is the join.
pub fn incus_instance(name: &str) -> (&str, &str) {
    name.rsplit_once('_').unwrap_or(("default", name))
}

#[derive(Debug, Deserialize)]
struct IncusEnvelope {
    metadata: IncusInstance,
}

#[derive(Debug, Deserialize)]
struct IncusInstance {
    #[serde(default)]
    name: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    created_at: String,
    #[serde(default)]
    expanded_config: std::collections::BTreeMap<String, String>,
}

/// Reads `GET /1.0/instances/<name>`: the `user.*` keys, profiles included,
/// become labels without their prefix, and the image is the one it was made
/// from.
pub fn parse_incus_instance(
    body: &[u8],
    project: &str,
    instance: &str,
) -> Result<DockerMetadata, ContainerError> {
    let envelope: IncusEnvelope =
        serde_json::from_slice(body).map_err(|e| ContainerError::DockerMalformed {
            reason: format!("incus instance: {e}"),
        })?;
    let found = envelope.metadata;
    let mut labels = vec![(LABEL_INCUS_PROJECT.to_string(), project.to_string())];
    labels.extend(found.expanded_config.iter().filter_map(|(key, value)| {
        key.strip_prefix("user.")
            .map(|label| (label.to_string(), value.clone()))
    }));
    Ok(DockerMetadata {
        name: if found.name.is_empty() {
            instance.to_string()
        } else {
            found.name
        },
        image: found
            .expanded_config
            .get("image.description")
            .cloned()
            .unwrap_or_default(),
        labels,
        created_at: found.created_at,
        status: found.status,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn lxc(name: &str) -> ContainerInfo {
        ContainerInfo::Container {
            container_id: name.to_string(),
            runtime: ContainerRuntime::Lxc,
            cgroup_path: format!("/lxc.payload.{name}"),
            pid: 1,
        }
    }

    fn enricher(proxmox_dir: Option<PathBuf>, incus: Option<PathBuf>) -> LxcEnricher {
        LxcEnricher::new(
            proxmox_dir,
            incus,
            200,
            DockerCache::new(8, Duration::from_mins(1)),
        )
    }

    #[test]
    fn a_proxmox_conf_gives_the_hostname_tags_and_os_and_stops_at_a_snapshot() {
        let md = parse_proxmox_conf(
            "101",
            "arch: amd64\nhostname: web01\nostype: debian\ntags: prod;db\n\
             [before-upgrade]\nhostname: old\ntags: stale\n",
        );
        assert_eq!(md.name, "web01");
        assert_eq!(md.image, "debian");
        assert_eq!(
            md.labels,
            vec![
                ("proxmox.vmid".to_string(), "101".to_string()),
                ("proxmox.tag".to_string(), "prod".to_string()),
                ("proxmox.tag".to_string(), "db".to_string()),
            ]
        );
    }

    #[test]
    fn a_proxmox_conf_without_a_hostname_keeps_the_vmid() {
        assert_eq!(parse_proxmox_conf("102", "memory: 512\n").name, "102");
    }

    #[test]
    fn an_incus_name_splits_into_its_project_and_instance() {
        assert_eq!(incus_instance("web"), ("default", "web"));
        assert_eq!(incus_instance("prod_web"), ("prod", "web"));
        assert_eq!(incus_instance("team_a_web"), ("team_a", "web"));
    }

    #[test]
    fn an_incus_instance_turns_its_user_keys_into_labels() {
        let body = br#"{"type":"sync","status_code":200,"metadata":{
            "name":"web","status":"Running","created_at":"2026-10-01T00:00:00Z",
            "expanded_config":{"user.tier":"front","user.owner":"shop",
              "image.description":"Debian bookworm","limits.cpu":"2"}}}"#;
        let md = parse_incus_instance(body, "prod", "web").unwrap();
        assert_eq!(md.name, "web");
        assert_eq!(md.image, "Debian bookworm");
        assert_eq!(md.status, "Running");
        assert_eq!(
            md.labels,
            vec![
                ("incus.project".to_string(), "prod".to_string()),
                ("owner".to_string(), "shop".to_string()),
                ("tier".to_string(), "front".to_string()),
            ]
        );
        assert!(parse_incus_instance(b"not json", "default", "web").is_err());
    }

    #[tokio::test]
    async fn a_ct_with_a_proxmox_file_is_named_from_it() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("101.conf"), "hostname: web01\ntags: prod\n").unwrap();
        let e = enricher(Some(dir.path().to_path_buf()), None);
        let Some(ContainerMetadata::Docker(md)) = e.enrich(&lxc("101")).await.unwrap() else {
            panic!("a proxmox ct is named");
        };
        assert_eq!(md.name, "web01");
        // Cached: the file going away does not unname a running CT.
        std::fs::remove_file(dir.path().join("101.conf")).unwrap();
        let Some(ContainerMetadata::Docker(md)) = e.enrich(&lxc("101")).await.unwrap() else {
            panic!("still named");
        };
        assert_eq!(md.name, "web01");
    }

    #[tokio::test]
    async fn a_container_no_source_describes_keeps_its_cgroup_name() {
        let dir = tempfile::tempdir().unwrap();
        let e = enricher(
            Some(dir.path().to_path_buf()),
            Some(dir.path().join("absent.socket")),
        );
        let Some(ContainerMetadata::Docker(md)) = e.enrich(&lxc("builder")).await.unwrap() else {
            panic!("a plain lxc container is named");
        };
        assert_eq!(md.name, "builder");
        assert_eq!(md.labels.len(), 0);
    }

    #[tokio::test]
    async fn another_runtime_is_left_to_its_own_enricher() {
        let e = enricher(None, None);
        let docker = ContainerInfo::Container {
            container_id: "a".repeat(64),
            runtime: ContainerRuntime::Docker,
            cgroup_path: String::new(),
            pid: 1,
        };
        assert!(e.enrich(&docker).await.unwrap().is_none());
        assert!(e.enrich(&ContainerInfo::Host).await.unwrap().is_none());
    }
}
