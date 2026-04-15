//! Container resolver & enrichment configuration.

use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

fn default_cache_size() -> usize {
    domain::container::engine::DEFAULT_CACHE_CAPACITY
}

fn default_proc_path() -> String {
    "/proc".to_string()
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    #[serde(default)]
    pub resolver: ResolverConfig,

    #[serde(default)]
    pub docker: DockerEnricherConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_cache_size")]
    pub cache_size: usize,

    #[serde(default = "default_proc_path")]
    pub proc_path: String,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache_size: default_cache_size(),
            proc_path: default_proc_path(),
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
}

impl Default for DockerEnricherConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket: default_docker_socket(),
            cache_size: default_docker_cache_size(),
            cache_ttl_seconds: default_docker_cache_ttl_seconds(),
            timeout_ms: default_docker_timeout_ms(),
        }
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
        assert!(!cfg.docker.enabled);
        assert_eq!(cfg.docker.cache_size, 1024);
        assert_eq!(cfg.docker.cache_ttl_seconds, 300);
        assert_eq!(cfg.docker.timeout_ms, 2_000);
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
        let cfg: ContainerConfig = serde_yaml_ng::from_str(yaml).unwrap();
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
        let cfg: ContainerConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(!cfg.docker.enabled);
    }
}
