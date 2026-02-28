//! Load balancer domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::loadbalancer::entity::{LbAlgorithm, LbBackend, LbProtocol, LbService};
use domain::routing::entity::HealthCheck;
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

/// Maximum number of LB services.
pub(super) const MAX_LB_SERVICES: usize = 64;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub services: Vec<LbServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbServiceConfig {
    pub id: String,
    pub name: String,

    /// Protocol: `tcp`, `udp`, or `tls_passthrough`.
    #[serde(default = "default_lb_protocol")]
    pub protocol: String,

    /// Port to listen on for incoming traffic.
    pub listen_port: u16,

    /// Algorithm: `round_robin`, `weighted`, `ip_hash`, `least_conn`.
    #[serde(default = "default_lb_algorithm")]
    pub algorithm: String,

    #[serde(default)]
    pub backends: Vec<LbBackendConfig>,

    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub health_check: Option<LbHealthCheckConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbBackendConfig {
    pub id: String,
    pub addr: String,
    pub port: u16,

    #[serde(default = "default_backend_weight")]
    pub weight: u32,

    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbHealthCheckConfig {
    /// Protocol: `tcp` or `http`.
    #[serde(default = "default_hc_protocol")]
    pub protocol: String,

    /// Check interval in seconds.
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,

    /// Timeout per probe in seconds.
    #[serde(default = "default_hc_timeout")]
    pub timeout_secs: u64,

    /// Failures before marking unhealthy.
    #[serde(default = "default_hc_threshold")]
    pub unhealthy_threshold: u32,

    /// Successes before marking healthy again.
    #[serde(default = "default_hc_threshold")]
    pub healthy_threshold: u32,
}

fn default_lb_protocol() -> String {
    "tcp".to_string()
}
fn default_lb_algorithm() -> String {
    "round_robin".to_string()
}
fn default_backend_weight() -> u32 {
    1
}
fn default_hc_protocol() -> String {
    "tcp".to_string()
}
fn default_hc_interval() -> u64 {
    10
}
fn default_hc_timeout() -> u64 {
    5
}
fn default_hc_threshold() -> u32 {
    3
}

impl LbServiceConfig {
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("loadbalancer.services[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "service ID must not be empty".to_string(),
            });
        }

        if self.name.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.name"),
                message: "service name must not be empty".to_string(),
            });
        }

        if self.listen_port == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.listen_port"),
                message: "listen_port must be > 0".to_string(),
            });
        }

        parse_lb_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.protocol"),
            value: self.protocol.clone(),
            expected: "tcp, udp, tls_passthrough".to_string(),
        })?;

        parse_lb_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.algorithm"),
            value: self.algorithm.clone(),
            expected: "round_robin, weighted, ip_hash, least_conn".to_string(),
        })?;

        if self.backends.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.backends"),
                message: "service must have at least one backend".to_string(),
            });
        }

        for (bidx, backend) in self.backends.iter().enumerate() {
            backend.validate(idx, bidx)?;
        }

        Ok(())
    }

    pub fn to_domain_service(&self) -> Result<LbService, ConfigError> {
        let protocol =
            parse_lb_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
                field: "protocol".to_string(),
                value: self.protocol.clone(),
                expected: "tcp, udp, tls_passthrough".to_string(),
            })?;

        let algorithm =
            parse_lb_algorithm(&self.algorithm).map_err(|()| ConfigError::InvalidValue {
                field: "algorithm".to_string(),
                value: self.algorithm.clone(),
                expected: "round_robin, weighted, ip_hash, least_conn".to_string(),
            })?;

        let backends: Vec<LbBackend> = self
            .backends
            .iter()
            .map(LbBackendConfig::to_domain_backend)
            .collect::<Result<_, _>>()?;

        let health_check = self
            .health_check
            .as_ref()
            .map(LbHealthCheckConfig::to_domain_health_check)
            .transpose()?;

        Ok(LbService {
            id: RuleId(self.id.clone()),
            name: self.name.clone(),
            protocol,
            listen_port: self.listen_port,
            algorithm,
            backends,
            enabled: self.enabled,
            health_check,
        })
    }
}

impl LbBackendConfig {
    fn validate(&self, svc_idx: usize, be_idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("loadbalancer.services[{svc_idx}].backends[{be_idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "backend ID must not be empty".to_string(),
            });
        }

        if self.addr.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.addr"),
                message: "backend address must not be empty".to_string(),
            });
        }

        self.addr
            .parse::<std::net::IpAddr>()
            .map_err(|_| ConfigError::Validation {
                field: format!("{prefix}.addr"),
                message: format!("invalid IP address: {}", self.addr),
            })?;

        if self.port == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.port"),
                message: "port must be > 0".to_string(),
            });
        }

        if self.weight == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.weight"),
                message: "weight must be > 0".to_string(),
            });
        }

        Ok(())
    }

    fn to_domain_backend(&self) -> Result<LbBackend, ConfigError> {
        let addr: std::net::IpAddr = self.addr.parse().map_err(|_| ConfigError::Validation {
            field: "addr".to_string(),
            message: format!("invalid IP address: {}", self.addr),
        })?;

        Ok(LbBackend {
            id: self.id.clone(),
            addr,
            port: self.port,
            weight: self.weight,
            enabled: self.enabled,
        })
    }
}

impl LbHealthCheckConfig {
    fn to_domain_health_check(&self) -> Result<HealthCheck, ConfigError> {
        use domain::routing::entity::HealthCheckProto;

        let protocol = match self.protocol.to_lowercase().as_str() {
            "tcp" => HealthCheckProto::Tcp { port: 0 },
            "icmp" => HealthCheckProto::Icmp,
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "health_check.protocol".to_string(),
                    value: self.protocol.clone(),
                    expected: "tcp, icmp".to_string(),
                });
            }
        };

        #[allow(clippy::cast_possible_truncation)]
        let interval_secs = self.interval_secs.min(u64::from(u32::MAX)) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let timeout_secs = self.timeout_secs.min(u64::from(u32::MAX)) as u32;

        Ok(HealthCheck {
            target: String::new(),
            protocol,
            interval_secs,
            timeout_secs,
            failure_threshold: self.unhealthy_threshold,
            recovery_threshold: self.healthy_threshold,
        })
    }
}

fn parse_lb_protocol(s: &str) -> Result<LbProtocol, ()> {
    match s.to_lowercase().as_str() {
        "tcp" => Ok(LbProtocol::Tcp),
        "udp" => Ok(LbProtocol::Udp),
        "tls_passthrough" | "tls" => Ok(LbProtocol::TlsPassthrough),
        _ => Err(()),
    }
}

fn parse_lb_algorithm(s: &str) -> Result<LbAlgorithm, ()> {
    match s.to_lowercase().as_str() {
        "round_robin" | "roundrobin" | "rr" => Ok(LbAlgorithm::RoundRobin),
        "weighted" => Ok(LbAlgorithm::Weighted),
        "ip_hash" | "iphash" => Ok(LbAlgorithm::IpHash),
        "least_conn" | "leastconn" | "least_connections" => Ok(LbAlgorithm::LeastConn),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend_config(id: &str) -> LbBackendConfig {
        LbBackendConfig {
            id: id.to_string(),
            addr: "10.0.0.1".to_string(),
            port: 8080,
            weight: 1,
            enabled: true,
        }
    }

    fn make_service_config(id: &str) -> LbServiceConfig {
        LbServiceConfig {
            id: id.to_string(),
            name: format!("test-{id}"),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            backends: vec![make_backend_config("be-1")],
            enabled: true,
            health_check: None,
        }
    }

    #[test]
    fn valid_service_config() {
        let cfg = make_service_config("svc-1");
        assert!(cfg.validate(0).is_ok());
    }

    #[test]
    fn reject_empty_id() {
        let mut cfg = make_service_config("svc-1");
        cfg.id = String::new();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_empty_name() {
        let mut cfg = make_service_config("svc-1");
        cfg.name = String::new();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_zero_listen_port() {
        let mut cfg = make_service_config("svc-1");
        cfg.listen_port = 0;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_invalid_protocol() {
        let mut cfg = make_service_config("svc-1");
        cfg.protocol = "http".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_invalid_algorithm() {
        let mut cfg = make_service_config("svc-1");
        cfg.algorithm = "random".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_empty_backends() {
        let mut cfg = make_service_config("svc-1");
        cfg.backends = vec![];
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_invalid_backend_addr() {
        let mut cfg = make_service_config("svc-1");
        cfg.backends[0].addr = "not-an-ip".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_zero_backend_port() {
        let mut cfg = make_service_config("svc-1");
        cfg.backends[0].port = 0;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn reject_zero_weight() {
        let mut cfg = make_service_config("svc-1");
        cfg.backends[0].weight = 0;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn to_domain_service_succeeds() {
        let cfg = make_service_config("svc-1");
        let svc = cfg.to_domain_service().unwrap();
        assert_eq!(svc.id.0, "svc-1");
        assert_eq!(svc.protocol, LbProtocol::Tcp);
        assert_eq!(svc.algorithm, LbAlgorithm::RoundRobin);
        assert_eq!(svc.listen_port, 443);
        assert_eq!(svc.backends.len(), 1);
    }

    #[test]
    fn to_domain_service_udp() {
        let mut cfg = make_service_config("dns");
        cfg.protocol = "udp".to_string();
        cfg.listen_port = 53;
        let svc = cfg.to_domain_service().unwrap();
        assert_eq!(svc.protocol, LbProtocol::Udp);
    }

    #[test]
    fn to_domain_service_tls() {
        let mut cfg = make_service_config("tls-svc");
        cfg.protocol = "tls_passthrough".to_string();
        let svc = cfg.to_domain_service().unwrap();
        assert_eq!(svc.protocol, LbProtocol::TlsPassthrough);
    }

    #[test]
    fn to_domain_service_with_health_check() {
        let mut cfg = make_service_config("svc-1");
        cfg.health_check = Some(LbHealthCheckConfig {
            protocol: "tcp".to_string(),
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        });
        let svc = cfg.to_domain_service().unwrap();
        let hc = svc.health_check.unwrap();
        assert_eq!(hc.failure_threshold, 3);
        assert_eq!(hc.recovery_threshold, 2);
    }

    #[test]
    fn parse_protocols() {
        assert_eq!(parse_lb_protocol("tcp").unwrap(), LbProtocol::Tcp);
        assert_eq!(parse_lb_protocol("udp").unwrap(), LbProtocol::Udp);
        assert_eq!(
            parse_lb_protocol("tls_passthrough").unwrap(),
            LbProtocol::TlsPassthrough
        );
        assert_eq!(
            parse_lb_protocol("tls").unwrap(),
            LbProtocol::TlsPassthrough
        );
        assert!(parse_lb_protocol("http").is_err());
    }

    #[test]
    fn parse_algorithms() {
        assert_eq!(
            parse_lb_algorithm("round_robin").unwrap(),
            LbAlgorithm::RoundRobin
        );
        assert_eq!(parse_lb_algorithm("rr").unwrap(), LbAlgorithm::RoundRobin);
        assert_eq!(
            parse_lb_algorithm("weighted").unwrap(),
            LbAlgorithm::Weighted
        );
        assert_eq!(parse_lb_algorithm("ip_hash").unwrap(), LbAlgorithm::IpHash);
        assert_eq!(
            parse_lb_algorithm("least_conn").unwrap(),
            LbAlgorithm::LeastConn
        );
        assert!(parse_lb_algorithm("random").is_err());
    }

    #[test]
    fn default_config_disabled() {
        let cfg = LoadBalancerConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.services.is_empty());
    }
}
