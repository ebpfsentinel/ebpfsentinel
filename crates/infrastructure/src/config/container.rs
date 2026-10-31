//! Container resolver & enrichment configuration.

use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

fn default_cache_size() -> usize {
    domain::container::engine::DEFAULT_CACHE_CAPACITY
}

fn default_proc_path() -> String {
    "/proc".to_string()
}

fn default_cgroup_root() -> String {
    "/sys/fs/cgroup".to_string()
}

fn default_docker_socket() -> String {
    "/var/run/docker.sock".to_string()
}

fn default_docker_cache_size() -> usize {
    1024
}

fn default_docker_cache_ttl_seconds() -> u64 {
    300
}

fn default_docker_timeout_ms() -> u64 {
    2_000
}

fn default_podman_socket() -> String {
    "/run/podman/podman.sock".to_string()
}

fn default_run_user_root() -> String {
    "/run/user".to_string()
}

fn default_proxmox_dir() -> String {
    "/etc/pve/lxc".to_string()
}

fn default_proxmox_qemu_dir() -> String {
    "/etc/pve/qemu-server".to_string()
}

fn default_libvirt_status_dir() -> String {
    "/run/libvirt/qemu".to_string()
}

fn default_incus_socket() -> String {
    "/var/lib/incus/unix.socket".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    #[serde(default)]
    pub resolver: ResolverConfig,

    #[serde(default)]
    pub docker: DockerEnricherConfig,

    #[serde(default)]
    pub podman: PodmanEnricherConfig,

    #[serde(default)]
    pub lxc: LxcEnricherConfig,

    #[serde(default)]
    pub guests: GuestNamingConfig,

    #[serde(default)]
    pub kubernetes: KubernetesEnricherConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_proc_path")]
    pub proc_path: String,

    /// cgroup v2 hierarchy root. The resolver walks it to map a packet's
    /// cgroup id (recovered on the TC egress hook via `bpf_skb_cgroup_id`,
    /// where the originating socket is bound to the skb) to a container.
    #[serde(default = "default_cgroup_root")]
    pub cgroup_root: String,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: default_cache_size(),
            proc_path: default_proc_path(),
            cgroup_root: default_cgroup_root(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerEnricherConfig {
    /// Enables the Docker Engine API enricher. Disabled by default because
    /// it requires mounting `/var/run/docker.sock` into the agent.
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_docker_socket")]
    pub socket: String,

    #[serde(default = "default_docker_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_docker_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,

    #[serde(default = "default_docker_timeout_ms")]
    pub timeout_ms: u64,

    /// Reads each container's `io.ebpfsentinel.policy.*` labels and puts
    /// what they say in force through the workload firewall, followed
    /// through the event stream so a relabelled or recreated container is
    /// policed without a reload.
    #[serde(default)]
    pub label_policy: bool,
}

impl Default for DockerEnricherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: default_docker_socket(),
            cache_size: default_docker_cache_size(),
            cache_ttl_seconds: default_docker_cache_ttl_seconds(),
            timeout_ms: default_docker_timeout_ms(),
            label_policy: false,
        }
    }
}

/// Podman containers, named through the socket of whoever started them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodmanEnricherConfig {
    /// Off by default, like Docker: it needs the runtime's socket mounted
    /// into the agent.
    #[serde(default)]
    pub enabled: bool,

    /// The system socket, serving the containers root started.
    #[serde(default = "default_podman_socket")]
    pub socket: String,

    /// Also name the containers users started, through each user's own
    /// socket under `run_user_root`. Those sockets answer only root and
    /// their owner, and exist only while the user's `podman.socket` unit is
    /// enabled.
    #[serde(default = "default_true")]
    pub rootless: bool,

    /// Where users' runtime directories are mounted in the agent.
    #[serde(default = "default_run_user_root")]
    pub run_user_root: String,

    #[serde(default = "default_docker_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_docker_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,

    #[serde(default = "default_docker_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for PodmanEnricherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: default_podman_socket(),
            rootless: true,
            run_user_root: default_run_user_root(),
            cache_size: default_docker_cache_size(),
            cache_ttl_seconds: default_docker_cache_ttl_seconds(),
            timeout_ms: default_docker_timeout_ms(),
        }
    }
}

/// LXC containers - Proxmox CTs, Incus instances and plain LXC - named from
/// their cgroup, and labelled from whichever source the node keeps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LxcEnricherConfig {
    /// On by default: the name is in the cgroup path and costs no socket,
    /// and each source below is read only where it exists.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Where Proxmox keeps one `<vmid>.conf` per CT, giving its hostname,
    /// tags and OS type. Empty to never read it.
    #[serde(default = "default_proxmox_dir")]
    pub proxmox_dir: String,

    /// The Incus daemon's socket, giving an instance's `user.*` keys as
    /// labels. Empty to never ask it.
    #[serde(default = "default_incus_socket")]
    pub incus_socket: String,

    #[serde(default = "default_docker_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_docker_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,

    #[serde(default = "default_docker_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for LxcEnricherConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proxmox_dir: default_proxmox_dir(),
            incus_socket: default_incus_socket(),
            cache_size: default_docker_cache_size(),
            cache_ttl_seconds: default_docker_cache_ttl_seconds(),
            timeout_ms: default_docker_timeout_ms(),
        }
    }
}

impl LxcEnricherConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            if self.cache_size == 0 {
                return Err(ConfigError::Validation {
                    field: "container.lxc.cache_size".to_string(),
                    message: "cache_size must be at least 1".to_string(),
                });
            }
            if self.timeout_ms == 0 {
                return Err(ConfigError::Validation {
                    field: "container.lxc.timeout_ms".to_string(),
                    message: "timeout_ms must be at least 1".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Virtual machines named from the hypervisor's records, read for each tap
/// or macvtap device the link watcher finds. Each source is read only where
/// it exists, and when asked: nothing is cached, so there is nothing to size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestNamingConfig {
    /// Where Proxmox keeps one `<vmid>.conf` per virtual machine, giving its
    /// name and tags. Empty to never read it.
    #[serde(default = "default_proxmox_qemu_dir")]
    pub proxmox_dir: String,

    /// Where libvirt keeps one status file per running domain, giving its
    /// name, its UUID and the host device behind each interface. Empty to
    /// never read it.
    #[serde(default = "default_libvirt_status_dir")]
    pub libvirt_dir: String,
}

impl Default for GuestNamingConfig {
    fn default() -> Self {
        Self {
            proxmox_dir: default_proxmox_qemu_dir(),
            libvirt_dir: default_libvirt_status_dir(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KubernetesEnricherConfig {
    /// Enables the Kubernetes pod metadata enricher.
    #[serde(default)]
    pub enabled: bool,

    /// Explicit node name. Empty = auto-detect from `EBPFSENTINEL_NODE_NAME`,
    /// `HOSTNAME`, then `/proc/sys/kernel/hostname`.
    #[serde(default)]
    pub node_name: String,

    /// Optional label selector (`k=v` pairs) applied to the pod watcher.
    /// When empty, all pods on the node are cached.
    #[serde(default)]
    pub label_filter: Vec<String>,

    /// Kubernetes `NetworkPolicy`, read from the cluster and enforced on
    /// this node's pods by the cgroup hooks.
    #[serde(default)]
    pub network_policy: NetworkPolicyConfig,
}

/// What the agent does with the cluster's `NetworkPolicy` objects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicyMode {
    /// Not read.
    #[default]
    Off,
    /// Compiled and evaluated on every new connection, refusals counted and
    /// let through.
    Observe,
    /// Refusals carried out.
    Enforce,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkPolicyConfig {
    #[serde(default)]
    pub mode: NetworkPolicyMode,
}

impl PodmanEnricherConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled {
            let empty = [
                ("socket", self.socket.is_empty()),
                (
                    "run_user_root",
                    self.rootless && self.run_user_root.is_empty(),
                ),
            ];
            if let Some((name, _)) = empty.iter().find(|(_, is_empty)| *is_empty) {
                return Err(ConfigError::Validation {
                    field: format!("container.podman.{name}"),
                    message: "path must not be empty".to_string(),
                });
            }
            if self.cache_size == 0 {
                return Err(ConfigError::Validation {
                    field: "container.podman.cache_size".to_string(),
                    message: "cache_size must be at least 1".to_string(),
                });
            }
            if self.timeout_ms == 0 {
                return Err(ConfigError::Validation {
                    field: "container.podman.timeout_ms".to_string(),
                    message: "timeout_ms must be at least 1".to_string(),
                });
            }
        }
        Ok(())
    }
}

impl ContainerConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.resolver.cache_size == 0 {
            return Err(ConfigError::Validation {
                field: "container.resolver.cache_size".to_string(),
                message: "cache_size must be at least 1".to_string(),
            });
        }
        if self.resolver.proc_path.is_empty() {
            return Err(ConfigError::Validation {
                field: "container.resolver.proc_path".to_string(),
                message: "proc_path must not be empty".to_string(),
            });
        }
        if self.resolver.cgroup_root.is_empty() {
            return Err(ConfigError::Validation {
                field: "container.resolver.cgroup_root".to_string(),
                message: "cgroup_root must not be empty".to_string(),
            });
        }
        if self.docker.enabled {
            if self.docker.socket.is_empty() {
                return Err(ConfigError::Validation {
                    field: "container.docker.socket".to_string(),
                    message: "socket path must not be empty".to_string(),
                });
            }
            if self.docker.cache_size == 0 {
                return Err(ConfigError::Validation {
                    field: "container.docker.cache_size".to_string(),
                    message: "cache_size must be at least 1".to_string(),
                });
            }
            if self.docker.timeout_ms == 0 {
                return Err(ConfigError::Validation {
                    field: "container.docker.timeout_ms".to_string(),
                    message: "timeout_ms must be at least 1".to_string(),
                });
            }
        }
        if self.docker.label_policy && !self.docker.enabled {
            return Err(ConfigError::Validation {
                field: "container.docker.label_policy".to_string(),
                message: "labels are read from the Docker socket, so container.docker.enabled \
                          must be true"
                    .to_string(),
            });
        }
        self.podman.validate()?;
        self.lxc.validate()?;
        if self.kubernetes.enabled {
            // The entries are joined into the label selector the API server
            // parses. A malformed one is rejected there, at watch time, in a
            // background task nobody is reading - so reject it here instead.
            for (idx, entry) in self.kubernetes.label_filter.iter().enumerate() {
                let field = format!("container.kubernetes.label_filter[{idx}]");
                let Some((key, _value)) = entry.split_once('=') else {
                    return Err(ConfigError::Validation {
                        field,
                        message: "label filter must be a key=value pair".to_string(),
                    });
                };
                if key.is_empty() {
                    return Err(ConfigError::Validation {
                        field,
                        message: "label filter key must not be empty".to_string(),
                    });
                }
                if entry.contains(',') {
                    return Err(ConfigError::Validation {
                        field,
                        message: "write one key=value pair per entry, not a comma-separated list"
                            .to_string(),
                    });
                }
            }
        }
        if self.kubernetes.network_policy.mode != NetworkPolicyMode::Off && !self.kubernetes.enabled
        {
            return Err(ConfigError::Validation {
                field: "container.kubernetes.network_policy.mode".to_string(),
                message:
                    "network policy is read from the cluster, so container.kubernetes.enabled \
                          must be true"
                        .to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_enabled_with_4096_cache() {
        let cfg = ContainerConfig::default();
        assert!(cfg.resolver.enabled);
        assert_eq!(cfg.resolver.cache_size, 4096);
        assert_eq!(cfg.resolver.proc_path, "/proc");
        assert_eq!(cfg.resolver.cgroup_root, "/sys/fs/cgroup");
        assert!(!cfg.docker.enabled);
        assert_eq!(cfg.docker.cache_size, 1024);
        assert_eq!(cfg.docker.cache_ttl_seconds, 300);
        assert_eq!(cfg.docker.timeout_ms, 2_000);
    }

    #[test]
    fn guests_are_read_from_proxmox_and_libvirt_unless_emptied() {
        let cfg = ContainerConfig::default();
        assert_eq!(cfg.guests.proxmox_dir, "/etc/pve/qemu-server");
        assert_eq!(cfg.guests.libvirt_dir, "/run/libvirt/qemu");
        let cfg: ContainerConfig =
            serde_norway::from_str("guests:\n  proxmox_dir: \"\"\n").unwrap();
        assert_eq!(cfg.guests.proxmox_dir, "");
        assert_eq!(cfg.guests.libvirt_dir, "/run/libvirt/qemu");
    }

    #[test]
    fn podman_is_off_and_rootless_on_once_enabled() {
        let cfg: ContainerConfig = serde_norway::from_str("podman:\n  enabled: true\n").unwrap();
        assert!(cfg.podman.enabled);
        assert!(cfg.podman.rootless);
        assert_eq!(cfg.podman.socket, "/run/podman/podman.sock");
        assert_eq!(cfg.podman.run_user_root, "/run/user");
        assert!(cfg.validate().is_ok());
        assert!(!ContainerConfig::default().podman.enabled);
    }

    #[test]
    fn validate_names_the_podman_field_it_refuses() {
        let mut cfg = ContainerConfig::default();
        cfg.podman.enabled = true;
        cfg.podman.run_user_root = String::new();
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("container.podman.run_user_root"), "{err}");
        cfg.podman.rootless = false;
        assert!(cfg.validate().is_ok());
        cfg.podman.timeout_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_defaults() {
        assert!(ContainerConfig::default().validate().is_ok());
    }

    #[test]
    fn validate_rejects_zero_cache() {
        let mut cfg = ContainerConfig::default();
        cfg.resolver.cache_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_proc_path() {
        let mut cfg = ContainerConfig::default();
        cfg.resolver.proc_path = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_cgroup_root() {
        let mut cfg = ContainerConfig::default();
        cfg.resolver.cgroup_root = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_accepts_a_label_filter_pair() {
        let mut cfg = ContainerConfig::default();
        cfg.kubernetes.enabled = true;
        cfg.kubernetes.label_filter = vec!["app=web".to_string(), "tier=frontend".to_string()];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_a_label_filter_without_a_value() {
        let mut cfg = ContainerConfig::default();
        cfg.kubernetes.enabled = true;
        cfg.kubernetes.label_filter = vec!["app".to_string()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_comma_separated_label_filter() {
        let mut cfg = ContainerConfig::default();
        cfg.kubernetes.enabled = true;
        cfg.kubernetes.label_filter = vec!["app=web,tier=frontend".to_string()];
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_ignores_the_label_filter_when_kubernetes_is_off() {
        let mut cfg = ContainerConfig::default();
        cfg.kubernetes.label_filter = vec!["not-a-pair".to_string()];
        assert!(cfg.validate().is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn network_policy_is_off_by_default_and_reads_its_three_modes() {
        assert_eq!(
            ContainerConfig::default().kubernetes.network_policy.mode,
            NetworkPolicyMode::Off
        );
        for (text, mode) in [
            ("off", NetworkPolicyMode::Off),
            ("observe", NetworkPolicyMode::Observe),
            ("enforce", NetworkPolicyMode::Enforce),
        ] {
            let cfg: NetworkPolicyConfig =
                serde_json::from_value(serde_json::json!({ "mode": text })).unwrap();
            assert_eq!(cfg.mode, mode);
        }
    }

    #[test]
    fn validate_rejects_network_policy_without_kubernetes() {
        let mut cfg = ContainerConfig::default();
        cfg.kubernetes.network_policy.mode = NetworkPolicyMode::Observe;
        assert!(cfg.validate().is_err());
        cfg.kubernetes.enabled = true;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_docker_socket_when_enabled() {
        let mut cfg = ContainerConfig::default();
        cfg.docker.enabled = true;
        cfg.docker.socket = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_docker_cache_when_enabled() {
        let mut cfg = ContainerConfig::default();
        cfg.docker.enabled = true;
        cfg.docker.cache_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_docker_timeout_when_enabled() {
        let mut cfg = ContainerConfig::default();
        cfg.docker.enabled = true;
        cfg.docker.timeout_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_ignores_docker_fields_when_disabled() {
        let mut cfg = ContainerConfig::default();
        cfg.docker.enabled = false;
        cfg.docker.socket = String::new();
        cfg.docker.cache_size = 0;
        cfg.docker.timeout_ms = 0;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn deserializes_from_yaml_with_docker() {
        let yaml = r"
resolver:
  enabled: true
  cache_size: 8192
  proc_path: /host/proc
docker:
  enabled: true
  socket: /var/run/docker.sock
  cache_size: 2048
  cache_ttl_seconds: 600
  timeout_ms: 3000
";
        let cfg: ContainerConfig = serde_norway::from_str(yaml).unwrap();
        assert_eq!(cfg.resolver.cache_size, 8192);
        assert_eq!(cfg.resolver.proc_path, "/host/proc");
        assert!(cfg.docker.enabled);
        assert_eq!(cfg.docker.cache_size, 2048);
        assert_eq!(cfg.docker.cache_ttl_seconds, 600);
        assert_eq!(cfg.docker.timeout_ms, 3_000);
    }

    #[test]
    fn deserializes_from_yaml_without_docker_keeps_default() {
        let yaml = "resolver: { enabled: true }";
        let cfg: ContainerConfig = serde_norway::from_str(yaml).unwrap();
        assert!(!cfg.docker.enabled);
    }

    #[test]
    fn label_policy_needs_the_docker_socket() {
        let mut cfg = ContainerConfig::default();
        cfg.docker.label_policy = true;
        assert!(cfg.validate().is_err());
        cfg.docker.enabled = true;
        assert!(cfg.validate().is_ok());
    }
}
