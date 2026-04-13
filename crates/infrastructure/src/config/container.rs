//! Container resolver configuration.

use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

fn default_cache_size() -> usize {
    domain::container::engine::DEFAULT_CACHE_CAPACITY
}

fn default_proc_path() -> String {
    "/proc".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerConfig {
    #[serde(default)]
    pub resolver: ResolverConfig,
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
    fn deserializes_from_yaml() {
        let yaml = r"
resolver:
  enabled: true
  cache_size: 8192
  proc_path: /host/proc
";
        let cfg: ContainerConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.resolver.cache_size, 8192);
        assert_eq!(cfg.resolver.proc_path, "/host/proc");
    }
}
