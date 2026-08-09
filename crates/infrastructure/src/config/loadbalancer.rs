//! Load balancer domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::loadbalancer::entity::{
    LbAlgorithm, LbBackend, LbForwardingMode, LbProtocol, LbService,
};
use domain::loadbalancer::vip::{AnnounceRole, Vip, VipAnnounceConfig};
use domain::routing::entity::HealthCheck;
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};

/// Maximum number of LB services (matches eBPF `MAX_LB_SERVICES` capacity).
pub(super) const MAX_LB_SERVICES: usize = 4096;

/// Every accepted `algorithm` spelling.
///
/// Single source of truth for what `parse_lb_algorithm` accepts and for
/// what a rejection message advertises, so a value the error offers can
/// never be one the parser refuses. A test walks the list through the
/// parser to keep the two honest.
const LB_ALGORITHM_NAMES: [&str; 5] =
    ["round_robin", "weighted", "ip_hash", "least_conn", "maglev"];

/// Every accepted health-check `protocol` spelling, on the same terms.
const LB_HC_PROTOCOL_NAMES: [&str; 2] = ["tcp", "icmp"];

/// Render an accepted-value list for a rejection message.
fn accepted(names: &[&str]) -> String {
    names.join(", ")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub services: Vec<LbServiceConfig>,

    /// L2 VIP announcer policy (ARP responder + gratuitous ARP failover).
    #[serde(default)]
    pub announce: AnnounceConfig,
}

/// Maximum number of owned VIPs (matches eBPF `MAX_VIPS` capacity).
pub(super) const MAX_VIPS: usize = 256;

/// Node-level VIP announce configuration.
///
/// Single-speaker election is explicit and config-driven: set `role` to
/// `primary` on exactly one node of an L2 failover pair, `standby` on the
/// other. A standby node validates the same VIP set but stays silent
/// until promoted (split-brain safe). The Kubernetes Lease seam that
/// would drive automatic promotion is documented in the operator and
/// deliberately not implemented here. `disabled` (default) turns the
/// announcer off entirely.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnnounceConfig {
    /// `disabled` (default), `primary`, or `standby`.
    #[serde(default = "default_announce_role")]
    pub role: String,

    /// L2 interface the VIPs live on (ARP responder egresses here).
    #[serde(default)]
    pub interface: String,

    /// The set of VIPs this node owns.
    #[serde(default)]
    pub vips: Vec<VipConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VipConfig {
    /// Stable label used as the Prometheus `{vip}` dimension.
    pub name: String,
    /// The virtual IP address this node may claim on the segment.
    pub addr: String,
}

fn default_announce_role() -> String {
    "disabled".to_string()
}

fn parse_announce_role(s: &str) -> Result<AnnounceRole, ()> {
    match s.trim().to_lowercase().as_str() {
        "" | "disabled" | "off" | "none" => Ok(AnnounceRole::Disabled),
        "primary" | "speaker" | "active" => Ok(AnnounceRole::Primary),
        "standby" | "passive" | "backup" => Ok(AnnounceRole::Standby),
        _ => Err(()),
    }
}

impl AnnounceConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let role = parse_announce_role(&self.role).map_err(|()| ConfigError::InvalidValue {
            field: "loadbalancer.announce.role".to_string(),
            value: self.role.clone(),
            expected: "disabled, primary, standby".to_string(),
        })?;

        if self.vips.len() > MAX_VIPS {
            return Err(ConfigError::Validation {
                field: "loadbalancer.announce.vips".to_string(),
                message: format!("at most {MAX_VIPS} VIPs are supported"),
            });
        }

        for (idx, vip) in self.vips.iter().enumerate() {
            let prefix = format!("loadbalancer.announce.vips[{idx}]");
            if vip.name.trim().is_empty() {
                return Err(ConfigError::Validation {
                    field: format!("{prefix}.name"),
                    message: "vip name must not be empty".to_string(),
                });
            }
            vip.addr
                .parse::<std::net::IpAddr>()
                .map_err(|_| ConfigError::Validation {
                    field: format!("{prefix}.addr"),
                    message: format!("invalid IP address: {}", vip.addr),
                })?;
        }

        // Delegate the role-coupled invariants (interface required,
        // non-empty + unique VIP set for primary/standby) to the domain.
        if role != AnnounceRole::Disabled {
            self.to_domain()?
                .validate()
                .map_err(|e| ConfigError::Validation {
                    field: "loadbalancer.announce".to_string(),
                    message: e.to_string(),
                })?;
        }

        Ok(())
    }

    /// Convert to the domain [`VipAnnounceConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the role string or any
    /// VIP address fails to parse.
    pub fn to_domain(&self) -> Result<VipAnnounceConfig, ConfigError> {
        let role = parse_announce_role(&self.role).map_err(|()| ConfigError::Validation {
            field: "loadbalancer.announce.role".to_string(),
            message: format!("invalid announce role: {}", self.role),
        })?;
        let mut vips = Vec::with_capacity(self.vips.len());
        for (idx, v) in self.vips.iter().enumerate() {
            vips.push(Vip {
                name: v.name.clone(),
                addr: v.addr.parse().map_err(|_| ConfigError::Validation {
                    field: format!("loadbalancer.announce.vips[{idx}].addr"),
                    message: format!("invalid IP address: {}", v.addr),
                })?,
            });
        }
        Ok(VipAnnounceConfig {
            role,
            interface: self.interface.clone(),
            vips,
        })
    }
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

    /// Algorithm: see [`LB_ALGORITHM_NAMES`].
    #[serde(default = "default_lb_algorithm")]
    pub algorithm: String,

    /// Forwarding mode: `dnat` (default) or `l2dsr`.
    #[serde(default = "default_lb_mode")]
    pub mode: String,

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

    /// Whether this backend is on the same L2 segment as the LB.
    /// Required `true` for all backends of an `l2dsr` service.
    #[serde(default)]
    pub same_segment: bool,
}

/// Active probing applied to every enabled backend of a service.
///
/// The probe target is the backend's own `addr` and `port`, so there is
/// no target field here: one health check describes how to probe, and
/// the service's backend list describes what to probe. A backend that
/// fails `unhealthy_threshold` probes in a row stops receiving traffic
/// until it passes `healthy_threshold` in a row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbHealthCheckConfig {
    /// Protocol: see [`LB_HC_PROTOCOL_NAMES`].
    #[serde(default = "default_hc_protocol")]
    pub protocol: String,

    /// Check interval in seconds.
    #[serde(default = "default_hc_interval")]
    pub interval_secs: u64,

    /// Timeout per probe in seconds.
    #[serde(default = "default_hc_timeout")]
    pub timeout_secs: u64,

    /// Failures before marking unhealthy.
    #[serde(default = "default_hc_threshold", alias = "failure_threshold")]
    pub unhealthy_threshold: u32,

    /// Successes before marking healthy again.
    #[serde(default = "default_hc_threshold", alias = "recovery_threshold")]
    pub healthy_threshold: u32,
}

fn default_lb_protocol() -> String {
    "tcp".to_string()
}
fn default_lb_algorithm() -> String {
    "round_robin".to_string()
}
fn default_lb_mode() -> String {
    "dnat".to_string()
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
            expected: accepted(&LB_ALGORITHM_NAMES),
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

        let mode = parse_lb_mode(&self.mode).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.mode"),
            value: self.mode.clone(),
            expected: "dnat, l2dsr".to_string(),
        })?;

        if mode == LbForwardingMode::L2Dsr {
            for backend in &self.backends {
                if !backend.same_segment {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.mode"),
                        message: format!(
                            "l2dsr requires all backends on the same L2 segment; \
                             backend '{}' is not flagged same_segment",
                            backend.id
                        ),
                    });
                }
            }
        }

        if let Some(hc) = &self.health_check {
            hc.validate(&prefix)?;
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
                expected: accepted(&LB_ALGORITHM_NAMES),
            })?;

        let mode = parse_lb_mode(&self.mode).map_err(|()| ConfigError::InvalidValue {
            field: "mode".to_string(),
            value: self.mode.clone(),
            expected: "dnat, l2dsr".to_string(),
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
            mode,
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
            same_segment: self.same_segment,
        })
    }
}

impl LbHealthCheckConfig {
    /// Reject a health check the probe loop could not run.
    ///
    /// A zero interval would spin the probe loop, a zero timeout would
    /// fail every probe on the spot, and a zero threshold would never
    /// let a backend change state - each one turns active probing into
    /// something that looks configured and does not work.
    fn validate(&self, prefix: &str) -> Result<(), ConfigError> {
        if parse_lb_hc_protocol(&self.protocol).is_none() {
            return Err(ConfigError::InvalidValue {
                field: format!("{prefix}.health_check.protocol"),
                value: self.protocol.clone(),
                expected: accepted(&LB_HC_PROTOCOL_NAMES),
            });
        }

        for (field, value) in [
            ("interval_secs", self.interval_secs),
            ("timeout_secs", self.timeout_secs),
            ("unhealthy_threshold", u64::from(self.unhealthy_threshold)),
            ("healthy_threshold", u64::from(self.healthy_threshold)),
        ] {
            if value == 0 {
                return Err(ConfigError::Validation {
                    field: format!("{prefix}.health_check.{field}"),
                    message: format!("{field} must be > 0"),
                });
            }
        }

        if self.timeout_secs > self.interval_secs {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.health_check.timeout_secs"),
                message: format!(
                    "timeout_secs ({}) must not exceed interval_secs ({}); \
                     a probe that outlives its interval never settles",
                    self.timeout_secs, self.interval_secs
                ),
            });
        }

        Ok(())
    }

    fn to_domain_health_check(&self) -> Result<HealthCheck, ConfigError> {
        let protocol =
            parse_lb_hc_protocol(&self.protocol).ok_or_else(|| ConfigError::InvalidValue {
                field: "health_check.protocol".to_string(),
                value: self.protocol.clone(),
                expected: accepted(&LB_HC_PROTOCOL_NAMES),
            })?;

        #[allow(clippy::cast_possible_truncation)]
        let interval_secs = self.interval_secs.min(u64::from(u32::MAX)) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let timeout_secs = self.timeout_secs.min(u64::from(u32::MAX)) as u32;

        Ok(HealthCheck {
            // The LB reuses the routing health-check record, whose
            // `target` and TCP `port` address a single gateway. Here the
            // probe fans out over the service's backends instead, so
            // both stay empty and the probe loop reads each backend's
            // own address and port.
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

/// Parse a health-check protocol, accepting exactly [`LB_HC_PROTOCOL_NAMES`].
fn parse_lb_hc_protocol(s: &str) -> Option<domain::routing::entity::HealthCheckProto> {
    use domain::routing::entity::HealthCheckProto;
    match s.to_lowercase().as_str() {
        // Port 0: the probe loop dials each backend's own port.
        "tcp" => Some(HealthCheckProto::Tcp { port: 0 }),
        "icmp" => Some(HealthCheckProto::Icmp),
        _ => None,
    }
}

fn parse_lb_mode(s: &str) -> Result<LbForwardingMode, ()> {
    match s.to_lowercase().as_str() {
        "dnat" => Ok(LbForwardingMode::Dnat),
        "l2dsr" | "l2_dsr" | "dsr" => Ok(LbForwardingMode::L2Dsr),
        _ => Err(()),
    }
}

fn parse_lb_algorithm(s: &str) -> Result<LbAlgorithm, ()> {
    match s.to_lowercase().as_str() {
        "round_robin" | "roundrobin" | "rr" => Ok(LbAlgorithm::RoundRobin),
        "weighted" => Ok(LbAlgorithm::Weighted),
        "ip_hash" | "iphash" => Ok(LbAlgorithm::IpHash),
        "least_conn" | "leastconn" | "least_connections" => Ok(LbAlgorithm::LeastConn),
        "maglev" => Ok(LbAlgorithm::Maglev),
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
            same_segment: false,
        }
    }

    fn make_service_config(id: &str) -> LbServiceConfig {
        LbServiceConfig {
            id: id.to_string(),
            name: format!("test-{id}"),
            protocol: "tcp".to_string(),
            listen_port: 443,
            algorithm: "round_robin".to_string(),
            mode: "dnat".to_string(),
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
    fn default_mode_is_dnat_and_valid() {
        let cfg = make_service_config("svc-1");
        assert_eq!(cfg.mode, "dnat");
        let svc = cfg.to_domain_service().unwrap();
        assert_eq!(svc.mode, LbForwardingMode::Dnat);
    }

    #[test]
    fn reject_invalid_mode() {
        let mut cfg = make_service_config("svc-1");
        cfg.mode = "bridge".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn l2dsr_rejects_backend_not_same_segment() {
        let mut cfg = make_service_config("svc-1");
        cfg.mode = "l2dsr".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn l2dsr_accepts_same_segment_backends() {
        let mut be = make_backend_config("be-1");
        be.same_segment = true;
        let mut cfg = make_service_config("svc-1");
        cfg.mode = "l2dsr".to_string();
        cfg.backends = vec![be];
        assert!(cfg.validate(0).is_ok());
        let svc = cfg.to_domain_service().unwrap();
        assert_eq!(svc.mode, LbForwardingMode::L2Dsr);
        assert!(svc.backends[0].same_segment);
        // Domain-level validation must also accept it.
        assert!(svc.validate().is_ok());
    }

    #[test]
    fn parse_lb_mode_aliases() {
        assert_eq!(parse_lb_mode("dnat"), Ok(LbForwardingMode::Dnat));
        assert_eq!(parse_lb_mode("l2dsr"), Ok(LbForwardingMode::L2Dsr));
        assert_eq!(parse_lb_mode("DSR"), Ok(LbForwardingMode::L2Dsr));
        assert!(parse_lb_mode("nope").is_err());
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

    fn make_health_check() -> LbHealthCheckConfig {
        LbHealthCheckConfig {
            protocol: "tcp".to_string(),
            interval_secs: 10,
            timeout_secs: 5,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }

    fn service_with_health_check(hc: LbHealthCheckConfig) -> LbServiceConfig {
        let mut cfg = make_service_config("svc-1");
        cfg.health_check = Some(hc);
        cfg
    }

    #[test]
    fn health_check_defaults_are_accepted() {
        let cfg = service_with_health_check(make_health_check());
        assert!(cfg.validate(0).is_ok());
    }

    #[test]
    fn health_check_icmp_is_accepted() {
        let mut hc = make_health_check();
        hc.protocol = "icmp".to_string();
        let cfg = service_with_health_check(hc);
        assert!(cfg.validate(0).is_ok());
        let svc = cfg.to_domain_service().unwrap();
        assert_eq!(
            svc.health_check.unwrap().protocol,
            domain::routing::entity::HealthCheckProto::Icmp
        );
    }

    #[test]
    fn health_check_unknown_protocol_reports_every_accepted_value() {
        let mut hc = make_health_check();
        hc.protocol = "http".to_string();
        let err = service_with_health_check(hc).validate(0).unwrap_err();
        let msg = err.to_string();
        for name in LB_HC_PROTOCOL_NAMES {
            assert!(msg.contains(name), "{msg} should list '{name}'");
        }
    }

    #[test]
    fn health_check_zero_interval_rejected() {
        let mut hc = make_health_check();
        hc.interval_secs = 0;
        assert!(service_with_health_check(hc).validate(0).is_err());
    }

    #[test]
    fn health_check_zero_timeout_rejected() {
        let mut hc = make_health_check();
        hc.timeout_secs = 0;
        assert!(service_with_health_check(hc).validate(0).is_err());
    }

    #[test]
    fn health_check_zero_thresholds_rejected() {
        let mut unhealthy = make_health_check();
        unhealthy.unhealthy_threshold = 0;
        assert!(service_with_health_check(unhealthy).validate(0).is_err());

        let mut healthy = make_health_check();
        healthy.healthy_threshold = 0;
        assert!(service_with_health_check(healthy).validate(0).is_err());
    }

    #[test]
    fn health_check_timeout_longer_than_interval_rejected() {
        let mut hc = make_health_check();
        hc.timeout_secs = 11;
        assert!(service_with_health_check(hc).validate(0).is_err());
    }

    #[test]
    fn every_listed_algorithm_parses() {
        for name in LB_ALGORITHM_NAMES {
            assert!(
                parse_lb_algorithm(name).is_ok(),
                "advertised algorithm '{name}' is rejected by the parser"
            );
        }
    }

    #[test]
    fn every_listed_health_check_protocol_parses() {
        for name in LB_HC_PROTOCOL_NAMES {
            assert!(
                parse_lb_hc_protocol(name).is_some(),
                "advertised health-check protocol '{name}' is rejected by the parser"
            );
        }
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
