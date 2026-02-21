//! Firewall domain configuration structs and conversion logic.

use domain::common::entity::RuleId;
use domain::firewall::entity::{FirewallRule, PortRange, Scope as DomainScope};
use serde::{Deserialize, Serialize};

use super::common::{
    ConfigError, default_mode, default_true, parse_action, parse_cidr, parse_protocol,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub default_policy: DefaultPolicy,

    #[serde(default)]
    pub rules: Vec<FirewallRuleConfig>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            default_policy: DefaultPolicy::Pass,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPolicy {
    #[default]
    Pass,
    Drop,
}

// ── Firewall rule config (YAML-friendly) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    pub priority: u32,

    pub action: String,

    #[serde(default = "default_protocol")]
    pub protocol: String,

    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,

    pub src_port: Option<PortRangeConfig>,
    pub dst_port: Option<PortRangeConfig>,

    #[serde(default)]
    pub scope: ScopeConfig,

    /// Optional 802.1Q VLAN ID filter (None = match any VLAN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
}

fn default_protocol() -> String {
    "any".to_string()
}

impl FirewallRuleConfig {
    /// Validate this rule config at the YAML level.
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("firewall.rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        parse_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.action"),
            value: self.action.clone(),
            expected: "allow, deny, log".to_string(),
        })?;

        parse_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.protocol"),
            value: self.protocol.clone(),
            expected: "tcp, udp, icmp, any".to_string(),
        })?;

        if let Some(ref cidr) = self.src_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }
        if let Some(ref cidr) = self.dst_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }

        // Validate VLAN ID (802.1Q range: 0-4094)
        if let Some(vid) = self.vlan_id
            && vid > 4094
        {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.vlan_id"),
                message: format!("VLAN ID {vid} must be 0-4094"),
            });
        }

        Ok(())
    }

    /// Convert to a domain `FirewallRule`.
    pub fn to_domain_rule(&self) -> Result<FirewallRule, ConfigError> {
        let action = parse_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: "action".to_string(),
            value: self.action.clone(),
            expected: "allow, deny, log".to_string(),
        })?;

        let protocol = parse_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: "protocol".to_string(),
            value: self.protocol.clone(),
            expected: "tcp, udp, icmp, any".to_string(),
        })?;

        let src_ip = self
            .src_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.src_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        let dst_ip = self
            .dst_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.dst_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        let src_port = self
            .src_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        let dst_port = self
            .dst_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        let scope = self.scope.to_domain();

        Ok(FirewallRule {
            id: RuleId(self.id.clone()),
            enabled: self.enabled,
            priority: self.priority,
            action,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            scope,
            vlan_id: self.vlan_id,
        })
    }
}

// ── Port range config ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortRangeConfig {
    Single(u16),
    Range(String),
    Explicit { start: u16, end: u16 },
}

impl PortRangeConfig {
    pub fn to_domain(&self) -> Result<PortRange, ConfigError> {
        match self {
            Self::Single(port) => Ok(PortRange {
                start: *port,
                end: *port,
            }),
            Self::Range(s) => {
                // Accept a single port as a string (e.g. "9999") or a range "80-443"
                if let Ok(port) = s.trim().parse::<u16>() {
                    return Ok(PortRange {
                        start: port,
                        end: port,
                    });
                }
                let (start_str, end_str) =
                    s.split_once('-')
                        .ok_or_else(|| ConfigError::InvalidPortRange {
                            value: s.clone(),
                            reason: "expected format 'start-end' (e.g. '80-443')".to_string(),
                        })?;
                let start =
                    start_str
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| ConfigError::InvalidPortRange {
                            value: s.clone(),
                            reason: format!("invalid start port: '{start_str}'"),
                        })?;
                let end =
                    end_str
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| ConfigError::InvalidPortRange {
                            value: s.clone(),
                            reason: format!("invalid end port: '{end_str}'"),
                        })?;
                if start > end {
                    return Err(ConfigError::InvalidPortRange {
                        value: s.clone(),
                        reason: format!("start ({start}) must be <= end ({end})"),
                    });
                }
                Ok(PortRange { start, end })
            }
            Self::Explicit { start, end } => {
                if start > end {
                    return Err(ConfigError::InvalidPortRange {
                        value: format!("{start}-{end}"),
                        reason: format!("start ({start}) must be <= end ({end})"),
                    });
                }
                Ok(PortRange {
                    start: *start,
                    end: *end,
                })
            }
        }
    }
}

// ── Scope config ───────────────────────────────────────────────────

/// Scope supports multiple YAML representations:
///   scope: global
///   scope: { interface: "eth0" }
///   scope: { namespace: "prod" }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeConfig {
    Simple(String),
    Map(ScopeMap),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeMap {
    pub interface: Option<String>,
    pub namespace: Option<String>,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self::Simple("global".to_string())
    }
}

impl ScopeConfig {
    pub fn to_domain(&self) -> DomainScope {
        match self {
            Self::Simple(s) if s.eq_ignore_ascii_case("global") => DomainScope::Global,
            Self::Simple(s) => DomainScope::Interface(s.clone()),
            Self::Map(m) => {
                if let Some(ref iface) = m.interface {
                    DomainScope::Interface(iface.clone())
                } else if let Some(ref ns) = m.namespace {
                    DomainScope::Namespace(ns.clone())
                } else {
                    DomainScope::Global
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Port range config ─────────────────────────────────────────

    #[test]
    fn port_range_single() {
        let pr = PortRangeConfig::Single(80).to_domain().unwrap();
        assert_eq!(pr.start, 80);
        assert_eq!(pr.end, 80);
    }

    #[test]
    fn port_range_string() {
        let pr = PortRangeConfig::Range("80-443".to_string())
            .to_domain()
            .unwrap();
        assert_eq!(pr.start, 80);
        assert_eq!(pr.end, 443);
    }

    #[test]
    fn port_range_explicit() {
        let pr = PortRangeConfig::Explicit {
            start: 1024,
            end: 65535,
        }
        .to_domain()
        .unwrap();
        assert_eq!(pr.start, 1024);
        assert_eq!(pr.end, 65535);
    }

    #[test]
    fn port_range_invalid_inverted() {
        assert!(
            PortRangeConfig::Range("443-80".to_string())
                .to_domain()
                .is_err()
        );
        assert!(
            PortRangeConfig::Explicit {
                start: 443,
                end: 80
            }
            .to_domain()
            .is_err()
        );
    }

    #[test]
    fn port_range_invalid_format() {
        assert!(
            PortRangeConfig::Range("not-a-range".to_string())
                .to_domain()
                .is_err()
        );
    }

    // ── Scope config ──────────────────────────────────────────────

    #[test]
    fn scope_defaults_to_global() {
        let scope = ScopeConfig::default();
        assert!(matches!(scope.to_domain(), DomainScope::Global));
    }
}
