use std::collections::HashSet;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::common::ConfigError;

/// Top-level routing configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoutingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub gateways: Vec<GatewayConfig>,
}

impl RoutingConfig {
    /// Reject gateways the routing service could never program.
    ///
    /// Failover writes a default route out of these values, so a duplicate id,
    /// an unparsable next hop or a misspelt probe protocol is caught at load
    /// rather than discovered when a WAN link drops.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] naming the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        let mut seen_ids = HashSet::new();
        let mut seen_names = HashSet::new();
        for (index, gw) in self.gateways.iter().enumerate() {
            let at = |field: &str| format!("routing.gateways[{index}].{field}");
            if !seen_ids.insert(gw.id) {
                return Err(ConfigError::Validation {
                    field: at("id"),
                    message: format!("gateway id {} is already used", gw.id),
                });
            }
            if gw.name.trim().is_empty() {
                return Err(ConfigError::Validation {
                    field: at("name"),
                    message: "a gateway needs a name: it is what the alerts and metrics report"
                        .to_string(),
                });
            }
            if !seen_names.insert(gw.name.clone()) {
                return Err(ConfigError::Validation {
                    field: at("name"),
                    message: format!("gateway name '{}' is already used", gw.name),
                });
            }
            if gw.interface.trim().is_empty() {
                return Err(ConfigError::Validation {
                    field: at("interface"),
                    message: "a gateway needs an egress interface to route through".to_string(),
                });
            }
            if gw.gateway_ip.parse::<Ipv4Addr>().is_err() {
                return Err(ConfigError::Validation {
                    field: at("gateway_ip"),
                    message: format!(
                        "'{}' is not an IPv4 next hop: the default route is written from it",
                        gw.gateway_ip
                    ),
                });
            }
            if let Some(hc) = &gw.health_check {
                if hc.target.trim().is_empty() {
                    return Err(ConfigError::Validation {
                        field: at("health_check.target"),
                        message: "a health check needs an address to probe".to_string(),
                    });
                }
                if !is_health_protocol(&hc.protocol) {
                    return Err(ConfigError::Validation {
                        field: at("health_check.protocol"),
                        message: format!(
                            "'{}' is not a probe protocol: use 'icmp' or 'tcp:<port>'",
                            hc.protocol
                        ),
                    });
                }
                if hc.interval_secs == 0 {
                    return Err(ConfigError::Validation {
                        field: at("health_check.interval_secs"),
                        message: "a probe interval of zero would spin the prober".to_string(),
                    });
                }
                if hc.timeout_secs == 0 {
                    return Err(ConfigError::Validation {
                        field: at("health_check.timeout_secs"),
                        message: "a probe timeout of zero fails every probe".to_string(),
                    });
                }
                if hc.failure_threshold == 0 || hc.recovery_threshold == 0 {
                    return Err(ConfigError::Validation {
                        field: at("health_check.failure_threshold"),
                        message: "failure and recovery thresholds count probes, so both need to \
                                  be at least one"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Configuration for a single multi-WAN gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Unique gateway ID (0-255).
    pub id: u8,
    /// Human-readable name.
    pub name: String,
    /// Egress network interface (e.g. `"eth1"`).
    pub interface: String,
    /// Gateway IPv4 address (e.g. `"203.0.113.1"`).
    pub gateway_ip: String,
    /// Priority (lower = preferred).
    #[serde(default = "default_priority")]
    pub priority: u32,
    /// Administratively enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Health-check probe configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
}

/// Health-check probe configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Target address to probe (e.g. `"8.8.8.8"`).
    pub target: String,
    /// Protocol: `"icmp"` or `"tcp:<port>"`.
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// Probe interval in seconds.
    #[serde(default = "default_interval")]
    pub interval_secs: u32,
    /// Probe timeout in seconds.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
    /// Consecutive failures before declaring down.
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Consecutive successes before declaring healthy.
    #[serde(default = "default_recovery_threshold")]
    pub recovery_threshold: u32,
}

fn default_priority() -> u32 {
    100
}
fn default_true() -> bool {
    true
}
fn default_protocol() -> String {
    "icmp".to_string()
}
fn default_interval() -> u32 {
    10
}
fn default_timeout() -> u32 {
    5
}
fn default_failure_threshold() -> u32 {
    3
}
fn default_recovery_threshold() -> u32 {
    2
}

impl GatewayConfig {
    /// Convert to domain entity.
    pub fn to_domain(&self) -> domain::routing::entity::Gateway {
        domain::routing::entity::Gateway {
            id: self.id,
            name: self.name.clone(),
            interface: self.interface.clone(),
            gateway_ip: self.gateway_ip.clone(),
            priority: self.priority,
            enabled: self.enabled,
            health_check: self.health_check.as_ref().map(|hc| {
                domain::routing::entity::HealthCheck {
                    target: hc.target.clone(),
                    protocol: parse_health_protocol(&hc.protocol),
                    interval_secs: hc.interval_secs,
                    timeout_secs: hc.timeout_secs,
                    failure_threshold: hc.failure_threshold,
                    recovery_threshold: hc.recovery_threshold,
                }
            }),
        }
    }
}

/// Whether a probe protocol string is one [`parse_health_protocol`] understands.
fn is_health_protocol(s: &str) -> bool {
    s.eq_ignore_ascii_case("icmp")
        || s.strip_prefix("tcp:")
            .is_some_and(|port| port.parse::<u16>().is_ok_and(|p| p != 0))
}

fn parse_health_protocol(s: &str) -> domain::routing::entity::HealthCheckProto {
    if let Some(port_str) = s.strip_prefix("tcp:")
        && let Ok(port) = port_str.parse()
    {
        return domain::routing::entity::HealthCheckProto::Tcp { port };
    }
    domain::routing::entity::HealthCheckProto::Icmp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_routing_config() {
        let cfg = RoutingConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.gateways.is_empty());
    }

    #[test]
    fn parse_health_protocol_icmp() {
        assert_eq!(
            parse_health_protocol("icmp"),
            domain::routing::entity::HealthCheckProto::Icmp
        );
    }

    #[test]
    fn parse_health_protocol_tcp() {
        assert_eq!(
            parse_health_protocol("tcp:8080"),
            domain::routing::entity::HealthCheckProto::Tcp { port: 8080 }
        );
    }

    #[test]
    fn parse_health_protocol_invalid_falls_back_to_icmp() {
        assert_eq!(
            parse_health_protocol("unknown"),
            domain::routing::entity::HealthCheckProto::Icmp
        );
    }

    #[test]
    fn gateway_config_to_domain() {
        let cfg = GatewayConfig {
            id: 1,
            name: "primary".to_string(),
            interface: "eth1".to_string(),
            gateway_ip: "10.0.1.1".to_string(),
            priority: 10,
            enabled: true,
            health_check: Some(HealthCheckConfig {
                target: "8.8.8.8".to_string(),
                protocol: "icmp".to_string(),
                interval_secs: 10,
                timeout_secs: 5,
                failure_threshold: 3,
                recovery_threshold: 2,
            }),
        };
        let gw = cfg.to_domain();
        assert_eq!(gw.id, 1);
        assert_eq!(gw.name, "primary");
        assert!(gw.health_check.is_some());
    }

    fn gateway(id: u8, name: &str, ip: &str) -> GatewayConfig {
        GatewayConfig {
            id,
            name: name.to_string(),
            interface: "eth1".to_string(),
            gateway_ip: ip.to_string(),
            priority: 10,
            enabled: true,
            health_check: None,
        }
    }

    #[test]
    fn validate_accepts_distinct_gateways() {
        let cfg = RoutingConfig {
            enabled: true,
            gateways: vec![
                gateway(1, "wan1", "203.0.113.1"),
                gateway(2, "wan2", "198.51.100.1"),
            ],
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_a_duplicate_id() {
        let cfg = RoutingConfig {
            enabled: true,
            gateways: vec![
                gateway(1, "wan1", "203.0.113.1"),
                gateway(1, "wan2", "198.51.100.1"),
            ],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_duplicate_name() {
        let cfg = RoutingConfig {
            enabled: true,
            gateways: vec![
                gateway(1, "wan", "203.0.113.1"),
                gateway(2, "wan", "198.51.100.1"),
            ],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_a_next_hop_that_is_not_an_address() {
        let cfg = RoutingConfig {
            enabled: true,
            gateways: vec![gateway(1, "wan1", "203.0.113.0/24")],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_an_unknown_probe_protocol() {
        let mut gw = gateway(1, "wan1", "203.0.113.1");
        gw.health_check = Some(HealthCheckConfig {
            target: "1.1.1.1".to_string(),
            protocol: "udp:53".to_string(),
            interval_secs: 10,
            timeout_secs: 5,
            failure_threshold: 3,
            recovery_threshold: 2,
        });
        let cfg = RoutingConfig {
            enabled: true,
            gateways: vec![gw],
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_skips_a_disabled_section() {
        let cfg = RoutingConfig {
            enabled: false,
            gateways: vec![
                gateway(1, "wan1", "not-an-ip"),
                gateway(1, "wan1", "not-an-ip"),
            ],
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn routing_config_yaml_roundtrip() {
        let yaml = r#"
enabled: true
gateways:
  - id: 1
    name: wan1
    interface: eth1
    gateway_ip: "203.0.113.1"
    priority: 10
  - id: 2
    name: wan2
    interface: eth2
    gateway_ip: "198.51.100.1"
    priority: 20
    health_check:
      target: "1.1.1.1"
      protocol: "tcp:443"
      interval_secs: 5
"#;
        let cfg: RoutingConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.gateways.len(), 2);
        assert_eq!(cfg.gateways[0].id, 1);
        assert_eq!(cfg.gateways[1].id, 2);
        assert!(cfg.gateways[1].health_check.is_some());
    }
}
