//! NAT configuration parsing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use domain::common::entity::RuleId;
use domain::firewall::entity::PortRange;
use domain::nat::entity::{NatRule, NatType, NptV6Rule};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true};
use super::firewall::PortRangeConfig;

/// Maximum NAT rules per direction.
pub(super) const MAX_NAT_RULES: usize = 256;

/// Maximum `NPTv6` prefix translation rules.
pub(super) const MAX_NPTV6_RULES: usize = 64;

/// Every accepted `match_protocol` spelling.
///
/// `icmp` and `icmpv6` both mean "the ICMP of this rule's family", so either
/// one resolves to the number the matching data plane compares, and `any` is
/// the written form of the protocol match this rule does not make. Anything
/// else is refused here rather than silently dropped when the rule is written
/// to the map, where an unread protocol widens the rule to every protocol.
const NAT_MATCH_PROTOCOLS: [&str; 5] = ["any", "tcp", "udp", "icmp", "icmpv6"];

/// Whether `value` parses as the CIDR or bare address the data plane reads,
/// and which family it belongs to (`true` for IPv6).
///
/// Mirrors the map writers: a value with no `/` is a host address, and a
/// prefix wider than its family is not a prefix at all.
fn match_cidr_family(value: &str) -> Option<bool> {
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (value, None),
    };
    let (is_v6, max) = match addr.parse::<IpAddr>().ok()? {
        IpAddr::V4(_) => (false, 32),
        IpAddr::V6(_) => (true, 128),
    };
    if let Some(prefix) = prefix
        && prefix.parse::<u16>().ok()? > max
    {
        return None;
    }
    Some(is_v6)
}

/// Full NAT configuration section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub snat_rules: Vec<NatRuleConfig>,

    #[serde(default)]
    pub dnat_rules: Vec<NatRuleConfig>,

    /// `NPTv6` (RFC 6296) prefix translation rules.
    #[serde(default)]
    pub nptv6_rules: Vec<NptV6RuleConfig>,

    /// Hairpin NAT (NAT reflection) configuration.
    #[serde(default)]
    pub hairpin: HairpinNatConfig,
}

/// Hairpin NAT (NAT reflection) configuration.
///
/// Allows internal clients to access internal services via the external IP.
/// The firewall applies DNAT + SNAT so return traffic routes back through
/// tc-nat-ingress instead of being routed directly (asymmetric routing).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HairpinNatConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Internal subnet CIDR (e.g., "192.168.1.0/24").
    pub internal_subnet: Option<String>,
    /// Firewall's internal IP for SNAT (e.g., "192.168.1.1").
    pub hairpin_snat_ip: Option<String>,
}

impl NatConfig {
    /// Validate the entire NAT section.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        for (idx, rule_cfg) in self.snat_rules.iter().enumerate() {
            rule_cfg.validate(idx, "nat.snat_rules")?;
        }
        for (idx, rule_cfg) in self.dnat_rules.iter().enumerate() {
            rule_cfg.validate(idx, "nat.dnat_rules")?;
        }
        for (idx, rule_cfg) in self.nptv6_rules.iter().enumerate() {
            rule_cfg.validate(idx)?;
        }
        self.hairpin.validate()?;
        Ok(())
    }
}

impl HairpinNatConfig {
    /// Validate the hairpin NAT config.
    ///
    /// When enabled, both `internal_subnet` (valid CIDR) and
    /// `hairpin_snat_ip` (valid IPv4) must be present.
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        let subnet_str =
            self.internal_subnet
                .as_deref()
                .ok_or_else(|| ConfigError::Validation {
                    field: "nat.hairpin.internal_subnet".to_string(),
                    message: "required when hairpin NAT is enabled".to_string(),
                })?;

        // Must contain '/' for CIDR notation
        let (ip_str, prefix_str) =
            subnet_str
                .split_once('/')
                .ok_or_else(|| ConfigError::InvalidCidr {
                    value: subnet_str.to_string(),
                    reason: "expected CIDR notation (e.g. 192.168.1.0/24)".to_string(),
                })?;

        ip_str
            .parse::<Ipv4Addr>()
            .map_err(|e| ConfigError::InvalidCidr {
                value: subnet_str.to_string(),
                reason: format!("invalid IPv4 address: {e}"),
            })?;

        let prefix_len: u32 = prefix_str.parse().map_err(|e| ConfigError::InvalidCidr {
            value: subnet_str.to_string(),
            reason: format!("invalid prefix length: {e}"),
        })?;

        if prefix_len > 32 {
            return Err(ConfigError::InvalidCidr {
                value: subnet_str.to_string(),
                reason: format!("prefix length must be 0..=32, got {prefix_len}"),
            });
        }

        let snat_ip_str =
            self.hairpin_snat_ip
                .as_deref()
                .ok_or_else(|| ConfigError::Validation {
                    field: "nat.hairpin.hairpin_snat_ip".to_string(),
                    message: "required when hairpin NAT is enabled".to_string(),
                })?;

        snat_ip_str
            .parse::<Ipv4Addr>()
            .map_err(|e| ConfigError::Validation {
                field: "nat.hairpin.hairpin_snat_ip".to_string(),
                message: format!("invalid IPv4 address: {e}"),
            })?;

        Ok(())
    }

    /// Parse to `(subnet_ip, subnet_mask, snat_ip)` as `u32` in host byte order.
    ///
    /// Returns `(0, 0, 0)` when disabled. Call after `validate()`.
    pub fn to_parsed(&self) -> Result<(u32, u32, u32), ConfigError> {
        if !self.enabled {
            return Ok((0, 0, 0));
        }

        let subnet_str = self.internal_subnet.as_deref().unwrap_or("");
        let (ip_str, prefix_str) = subnet_str.split_once('/').unwrap_or((subnet_str, "32"));

        let ip: Ipv4Addr = ip_str.parse().map_err(|e| ConfigError::Validation {
            field: "nat.hairpin.internal_subnet".to_string(),
            message: format!("invalid IPv4: {e}"),
        })?;

        let prefix_len: u32 = prefix_str.parse().map_err(|e| ConfigError::Validation {
            field: "nat.hairpin.internal_subnet".to_string(),
            message: format!("invalid prefix length: {e}"),
        })?;

        // Total over any prefix_len so this `pub fn` never underflows `32 -
        // prefix_len` (debug panic) or over-shifts (release) even if called on a
        // config that skipped `validate()`, which bounds the prefix to 0..=32.
        let mask = match prefix_len {
            0 => 0,
            p if p >= 32 => !0u32,
            p => !0u32 << (32 - p),
        };

        let snat_ip_str = self.hairpin_snat_ip.as_deref().unwrap_or("");
        let snat_ip: Ipv4Addr = snat_ip_str.parse().map_err(|e| ConfigError::Validation {
            field: "nat.hairpin.hairpin_snat_ip".to_string(),
            message: format!("invalid IPv4: {e}"),
        })?;

        Ok((u32::from(ip), mask, u32::from(snat_ip)))
    }
}

/// YAML representation of a single NAT rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRuleConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_priority")]
    pub priority: u32,

    /// NAT type: `snat`, `dnat`, `masquerade`, `one_to_one`, `redirect`, `port_forward`.
    #[serde(rename = "type")]
    pub nat_type: String,

    /// Translated address (for `snat`, `dnat`).
    #[serde(default)]
    pub translated_addr: Option<String>,

    /// Translated port (for `dnat`, `redirect`).
    #[serde(default)]
    pub translated_port: Option<u16>,

    /// Port range (for `snat`, `masquerade`).
    #[serde(default)]
    pub port_range: Option<PortRangeConfig>,

    /// Interface (for `masquerade`).
    #[serde(default)]
    pub interface: Option<String>,

    /// External address (for `one_to_one`).
    #[serde(default)]
    pub external_addr: Option<String>,

    /// Internal address (for `one_to_one`, `port_forward`).
    #[serde(default)]
    pub internal_addr: Option<String>,

    /// External port range (for `port_forward`).
    #[serde(default)]
    pub ext_port: Option<PortRangeConfig>,

    /// Internal port range (for `port_forward`).
    #[serde(default)]
    pub int_port: Option<PortRangeConfig>,

    /// Source CIDR to match (None = any).
    #[serde(default)]
    pub match_src: Option<String>,

    /// Destination CIDR to match (None = any).
    #[serde(default)]
    pub match_dst: Option<String>,

    /// Destination port to match (None = any).
    #[serde(default)]
    pub match_dst_port: Option<PortRangeConfig>,

    /// Protocol to match (None = any).
    #[serde(default)]
    pub match_protocol: Option<String>,

    /// Source IP alias reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_src_alias: Option<String>,

    /// Destination IP alias reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_dst_alias: Option<String>,

    /// Interface groups this rule applies to. Empty = all (floating).
    /// Prefix with "!" for inversion (e.g., `"!lan"` = all except lan).
    #[serde(default)]
    pub interfaces: Vec<String>,

    /// Tenant this rule belongs to. 0 (the default) is global and translates
    /// for every tenant. A non-zero value is what lets two tenants keep
    /// overlapping private ranges behind separate translations.
    #[serde(default)]
    pub tenant_id: u32,
}

fn default_priority() -> u32 {
    100
}

/// YAML representation of an `NPTv6` (RFC 6296) prefix translation rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NptV6RuleConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Internal (site-local) IPv6 prefix, e.g. `fd00:1::`.
    pub internal_prefix: String,

    /// External (provider) IPv6 prefix, e.g. `2001:db8:1::`.
    pub external_prefix: String,

    /// Prefix length in bits (1-64).
    pub prefix_len: u8,

    /// Interface groups this rule applies to. Empty = all (floating).
    /// Prefix with "!" for inversion (e.g., `"!lan"` = all except lan).
    #[serde(default)]
    pub interfaces: Vec<String>,
}

impl NptV6RuleConfig {
    /// Validate this `NPTv6` rule config.
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("nat.nptv6_rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        if self.prefix_len == 0 || self.prefix_len > 64 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.prefix_len"),
                message: format!("prefix_len must be 1..=64, got {}", self.prefix_len),
            });
        }

        self.internal_prefix
            .parse::<Ipv6Addr>()
            .map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.internal_prefix"),
                message: format!("invalid IPv6 address: {e}"),
            })?;

        self.external_prefix
            .parse::<Ipv6Addr>()
            .map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.external_prefix"),
                message: format!("invalid IPv6 address: {e}"),
            })?;

        Ok(())
    }

    /// Convert to a domain `NptV6Rule`. `group_bits` maps every configured
    /// interface-group name to its bit, so `interfaces` can be resolved into
    /// the mask the data plane compares against the arrival interface.
    pub fn to_domain_rule(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<NptV6Rule, ConfigError> {
        let internal_prefix: Ipv6Addr =
            self.internal_prefix
                .parse()
                .map_err(|e| ConfigError::Validation {
                    field: "internal_prefix".to_string(),
                    message: format!("invalid IPv6: {e}"),
                })?;
        let external_prefix: Ipv6Addr =
            self.external_prefix
                .parse()
                .map_err(|e| ConfigError::Validation {
                    field: "external_prefix".to_string(),
                    message: format!("invalid IPv6: {e}"),
                })?;

        Ok(NptV6Rule {
            id: self.id.clone(),
            enabled: self.enabled,
            internal_prefix,
            external_prefix,
            prefix_len: self.prefix_len,
            group_mask: super::parse_group_mask(&self.interfaces, group_bits).map_err(
                |message| ConfigError::Validation {
                    field: "nat.nptv6_rules.interfaces".to_string(),
                    message,
                },
            )?,
        })
    }
}

impl NatRuleConfig {
    /// Validate this rule config.
    pub(super) fn validate(&self, idx: usize, section: &str) -> Result<(), ConfigError> {
        let prefix = format!("{section}[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        if self.priority == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.priority"),
                message: "priority must be > 0".to_string(),
            });
        }

        match self.nat_type.as_str() {
            "snat" | "dnat" => {
                if self.translated_addr.is_none() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.translated_addr"),
                        message: format!("{} requires translated_addr", self.nat_type),
                    });
                }
                // Validate translated_addr is a valid IP
                if let Some(ref addr) = self.translated_addr {
                    addr.parse::<IpAddr>()
                        .map_err(|e| ConfigError::Validation {
                            field: format!("{prefix}.translated_addr"),
                            message: format!("invalid IP address: {e}"),
                        })?;
                }
            }
            "masquerade" => {
                if self.interface.as_deref().unwrap_or("").is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.interface"),
                        message: "masquerade requires interface".to_string(),
                    });
                }
            }
            "one_to_one" => {
                if self.external_addr.is_none() || self.internal_addr.is_none() {
                    return Err(ConfigError::Validation {
                        field: prefix.clone(),
                        message: "one_to_one requires external_addr and internal_addr".to_string(),
                    });
                }
                for (field, value) in [
                    ("external_addr", &self.external_addr),
                    ("internal_addr", &self.internal_addr),
                ] {
                    Self::parse_addr(&prefix, field, value.as_deref())?;
                }
            }
            "redirect" => {
                if self.translated_port.is_none() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.translated_port"),
                        message: "redirect requires translated_port".to_string(),
                    });
                }
            }
            "port_forward" => {
                if self.ext_port.is_none()
                    || self.internal_addr.is_none()
                    || self.int_port.is_none()
                {
                    return Err(ConfigError::Validation {
                        field: prefix.clone(),
                        message: "port_forward requires ext_port, internal_addr, and int_port"
                            .to_string(),
                    });
                }
                Self::parse_addr(&prefix, "internal_addr", self.internal_addr.as_deref())?;
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    field: format!("{prefix}.type"),
                    value: other.to_string(),
                    expected: "snat, dnat, masquerade, one_to_one, redirect, port_forward"
                        .to_string(),
                });
            }
        }

        self.validate_match(&prefix)?;

        Ok(())
    }

    /// Parse an address field, naming it in the error.
    fn parse_addr(prefix: &str, field: &str, value: Option<&str>) -> Result<IpAddr, ConfigError> {
        value
            .unwrap_or("")
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::Validation {
                field: format!("{prefix}.{field}"),
                message: format!("invalid IP address: {e}"),
            })
    }

    /// Validate the match criteria, which the data plane reads by parsing.
    ///
    /// A match it cannot parse is not an error there: the rule is written with
    /// that criterion left out, so a mistyped source CIDR turns a rule meant
    /// for one subnet into one that matches every address. The same is true of
    /// an unknown protocol. Both are refused here instead.
    ///
    /// The family is checked for the same reason: a rule is written to the v4
    /// or the v6 map as a whole, and a match CIDR of one family beside a
    /// translated address of the other lands in the map where the address
    /// cannot be represented, translating to the unspecified address.
    fn validate_match(&self, prefix: &str) -> Result<(), ConfigError> {
        let mut family: Option<(bool, String)> = None;

        for (field, value) in [
            ("match_src", &self.match_src),
            ("match_dst", &self.match_dst),
        ] {
            let Some(cidr) = value.as_deref().filter(|c| !c.is_empty()) else {
                continue;
            };
            let is_v6 = match_cidr_family(cidr).ok_or_else(|| ConfigError::InvalidCidr {
                value: cidr.to_string(),
                reason: format!("{prefix}.{field} expects an address or CIDR"),
            })?;
            Self::merge_family(prefix, &mut family, is_v6, field)?;
        }

        for (field, addr) in self.type_addrs() {
            Self::merge_family(prefix, &mut family, addr.is_ipv6(), field)?;
        }

        if let Some(proto) = self.match_protocol.as_deref().filter(|p| !p.is_empty())
            && !NAT_MATCH_PROTOCOLS.contains(&proto.to_lowercase().as_str())
        {
            return Err(ConfigError::InvalidValue {
                field: format!("{prefix}.match_protocol"),
                value: proto.to_string(),
                expected: NAT_MATCH_PROTOCOLS.join(", "),
            });
        }

        Ok(())
    }

    /// The addresses this rule's type carries, already parsed by `validate`.
    fn type_addrs(&self) -> Vec<(&'static str, IpAddr)> {
        let parse = |field: &'static str, value: &Option<String>| {
            Some((field, value.as_deref()?.parse::<IpAddr>().ok()?))
        };
        match self.nat_type.as_str() {
            "snat" | "dnat" => vec![parse("translated_addr", &self.translated_addr)],
            "one_to_one" => vec![
                parse("external_addr", &self.external_addr),
                parse("internal_addr", &self.internal_addr),
            ],
            "port_forward" => vec![parse("internal_addr", &self.internal_addr)],
            _ => vec![],
        }
        .into_iter()
        .flatten()
        .collect()
    }

    /// Record `is_v6` as the rule's family, or reject the field that disagrees.
    fn merge_family(
        prefix: &str,
        family: &mut Option<(bool, String)>,
        is_v6: bool,
        field: &str,
    ) -> Result<(), ConfigError> {
        match family {
            Some((seen, seen_field)) if *seen != is_v6 => Err(ConfigError::Validation {
                field: format!("{prefix}.{field}"),
                message: format!(
                    "address family disagrees with {seen_field}: a rule is IPv4 or IPv6 as a whole"
                ),
            }),
            Some(_) => Ok(()),
            None => {
                *family = Some((is_v6, field.to_string()));
                Ok(())
            }
        }
    }

    /// Convert to a domain `NatRule`. `group_bits` maps every configured
    /// interface-group name to its bit, so `interfaces` can be resolved into
    /// the mask the data plane compares against the arrival interface.
    #[allow(clippy::too_many_lines)]
    pub fn to_domain_rule(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<NatRule, ConfigError> {
        let nat_type = match self.nat_type.as_str() {
            "snat" => {
                let addr: IpAddr = self
                    .translated_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "translated_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                let port_range = self
                    .port_range
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?;
                NatType::Snat { addr, port_range }
            }
            "dnat" => {
                let addr: IpAddr = self
                    .translated_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "translated_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                NatType::Dnat {
                    addr,
                    port: self.translated_port,
                }
            }
            "masquerade" => {
                let port_range = self
                    .port_range
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?;
                NatType::Masquerade {
                    interface: self.interface.clone().unwrap_or_default(),
                    port_range,
                }
            }
            "one_to_one" => {
                let external: IpAddr = self
                    .external_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "external_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                let internal: IpAddr = self
                    .internal_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "internal_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                NatType::OneToOne { external, internal }
            }
            "redirect" => NatType::Redirect {
                port: self.translated_port.unwrap_or(0),
            },
            "port_forward" => {
                let ext = self
                    .ext_port
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?
                    .unwrap_or(PortRange { start: 0, end: 0 });
                let int_addr: IpAddr = self
                    .internal_addr
                    .as_deref()
                    .unwrap_or("")
                    .parse()
                    .map_err(|e| ConfigError::Validation {
                        field: "internal_addr".to_string(),
                        message: format!("invalid IP: {e}"),
                    })?;
                let int = self
                    .int_port
                    .as_ref()
                    .map(PortRangeConfig::to_domain)
                    .transpose()?
                    .unwrap_or(PortRange { start: 0, end: 0 });
                NatType::PortForward {
                    ext_port: ext,
                    int_addr,
                    int_port: int,
                }
            }
            other => {
                return Err(ConfigError::InvalidValue {
                    field: "type".to_string(),
                    value: other.to_string(),
                    expected: "snat, dnat, masquerade, one_to_one, redirect, port_forward"
                        .to_string(),
                });
            }
        };

        let match_dst_port = self
            .match_dst_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        Ok(NatRule {
            id: RuleId(self.id.clone()),
            priority: self.priority,
            nat_type,
            match_src: self.match_src.clone(),
            match_dst: self.match_dst.clone(),
            match_dst_port,
            match_protocol: self.match_protocol.clone(),
            match_src_alias: self.match_src_alias.clone(),
            match_dst_alias: self.match_dst_alias.clone(),
            enabled: self.enabled,
            group_mask: super::parse_group_mask(&self.interfaces, group_bits).map_err(
                |message| ConfigError::Validation {
                    field: "nat.rules.interfaces".to_string(),
                    message,
                },
            )?,
            tenant_id: self.tenant_id,
            xfrm_if_id: 0,
            xfrm_link: 0,
            fou_sport: 0,
            fou_dport: 0,
            fou_type: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hairpin(subnet: &str) -> HairpinNatConfig {
        HairpinNatConfig {
            enabled: true,
            internal_subnet: Some(subnet.to_string()),
            hairpin_snat_ip: Some("192.168.1.1".to_string()),
        }
    }

    #[test]
    fn hairpin_to_parsed_mask_is_correct() {
        let (_, mask, _) = hairpin("192.168.1.0/24").to_parsed().unwrap();
        assert_eq!(mask, 0xFFFF_FF00);
        let (_, mask, _) = hairpin("10.0.0.1/32").to_parsed().unwrap();
        assert_eq!(mask, 0xFFFF_FFFF);
        let (_, mask, _) = hairpin("0.0.0.0/0").to_parsed().unwrap();
        assert_eq!(mask, 0);
    }

    #[test]
    fn hairpin_to_parsed_never_panics_on_out_of_range_prefix() {
        // `validate()` rejects /99, but `to_parsed` must stay total on its own:
        // no `32 - prefix_len` underflow, clamps to a /32 mask.
        let (_, mask, _) = hairpin("10.0.0.1/99").to_parsed().unwrap();
        assert_eq!(mask, 0xFFFF_FFFF);
    }

    fn snat_config() -> NatRuleConfig {
        NatRuleConfig {
            id: "snat-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "snat".to_string(),
            translated_addr: Some("10.0.0.1".to_string()),
            translated_port: None,
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: Some("192.168.0.0/16".to_string()),
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            match_src_alias: None,
            match_dst_alias: None,
            interfaces: Vec::new(),
            tenant_id: 0,
        }
    }

    #[test]
    fn validate_snat_ok() {
        assert!(snat_config().validate(0, "nat.snat_rules").is_ok());
    }

    #[test]
    fn validate_empty_id() {
        let mut cfg = snat_config();
        cfg.id = String::new();
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_zero_priority() {
        let mut cfg = snat_config();
        cfg.priority = 0;
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_snat_no_addr() {
        let mut cfg = snat_config();
        cfg.translated_addr = None;
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_dnat_ok() {
        let cfg = NatRuleConfig {
            id: "dnat-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "dnat".to_string(),
            translated_addr: Some("10.0.1.10".to_string()),
            translated_port: Some(80),
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: Some("tcp".to_string()),
            match_src_alias: None,
            match_dst_alias: None,
            interfaces: Vec::new(),
            tenant_id: 0,
        };
        assert!(cfg.validate(0, "nat.dnat_rules").is_ok());
    }

    #[test]
    fn validate_masquerade_no_interface() {
        let cfg = NatRuleConfig {
            id: "masq-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "masquerade".to_string(),
            translated_addr: None,
            translated_port: None,
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            match_src_alias: None,
            match_dst_alias: None,
            interfaces: Vec::new(),
            tenant_id: 0,
        };
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_invalid_type() {
        let mut cfg = snat_config();
        cfg.nat_type = "unknown".to_string();
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_masquerade_empty_interface() {
        let mut cfg = snat_config();
        cfg.nat_type = "masquerade".to_string();
        cfg.translated_addr = None;
        cfg.interface = Some(String::new());
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
    }

    #[test]
    fn validate_rejects_unparseable_match_cidr() {
        for bad in ["192.168.0/16", "192.168.0.0/33", "10.0.0.0/", "not-an-ip"] {
            let mut cfg = snat_config();
            cfg.match_src = Some(bad.to_string());
            assert!(
                cfg.validate(0, "nat.snat_rules").is_err(),
                "{bad} should be refused"
            );
        }
    }

    #[test]
    fn validate_accepts_host_and_prefix_matches() {
        for good in ["10.0.0.1", "10.0.0.0/8", "0.0.0.0/0"] {
            let mut cfg = snat_config();
            cfg.match_src = Some(good.to_string());
            assert!(cfg.validate(0, "nat.snat_rules").is_ok(), "{good}");
        }
    }

    #[test]
    fn validate_rejects_mixed_address_families() {
        let mut cfg = snat_config();
        cfg.match_src = Some("2001:db8::/32".to_string());
        let err = cfg.validate(0, "nat.snat_rules").unwrap_err().to_string();
        assert!(err.contains("family"), "{err}");
    }

    #[test]
    fn validate_accepts_a_consistent_v6_rule() {
        let mut cfg = snat_config();
        cfg.translated_addr = Some("2001:db8::1".to_string());
        cfg.match_src = Some("2001:db8:1::/48".to_string());
        cfg.match_dst = Some("2001:db8:2::/48".to_string());
        assert!(cfg.validate(0, "nat.snat_rules").is_ok());
    }

    #[test]
    fn validate_match_protocol_vocabulary() {
        for proto in NAT_MATCH_PROTOCOLS {
            let mut cfg = snat_config();
            cfg.match_protocol = Some(proto.to_uppercase());
            assert!(cfg.validate(0, "nat.snat_rules").is_ok(), "{proto}");
        }
        let mut cfg = snat_config();
        cfg.match_protocol = Some("sctp".to_string());
        let err = cfg.validate(0, "nat.snat_rules").unwrap_err().to_string();
        assert!(err.contains("icmpv6"), "{err}");
    }

    #[test]
    fn validate_one_to_one_addresses_are_parsed() {
        let mut cfg = snat_config();
        cfg.nat_type = "one_to_one".to_string();
        cfg.translated_addr = None;
        cfg.match_src = None;
        cfg.external_addr = Some("203.0.113.10".to_string());
        cfg.internal_addr = Some("10.0.1.300".to_string());
        assert!(cfg.validate(0, "nat.snat_rules").is_err());
        cfg.internal_addr = Some("10.0.1.10".to_string());
        assert!(cfg.validate(0, "nat.snat_rules").is_ok());
    }

    #[test]
    fn validate_port_forward_internal_addr_is_parsed() {
        let mut cfg = snat_config();
        cfg.nat_type = "port_forward".to_string();
        cfg.translated_addr = None;
        cfg.match_src = None;
        cfg.ext_port = Some(PortRangeConfig::Single(443));
        cfg.int_port = Some(PortRangeConfig::Single(8443));
        cfg.internal_addr = Some("10.0.1".to_string());
        assert!(cfg.validate(0, "nat.dnat_rules").is_err());
        cfg.internal_addr = Some("10.0.1.10".to_string());
        assert!(cfg.validate(0, "nat.dnat_rules").is_ok());
    }

    #[test]
    fn to_domain_snat() {
        let rule = snat_config().to_domain_rule(&HashMap::new()).unwrap();
        assert_eq!(rule.id.0, "snat-1");
        assert!(matches!(rule.nat_type, NatType::Snat { .. }));
    }

    #[test]
    fn to_domain_rule_carries_the_configured_tenant() {
        let mut cfg = snat_config();
        cfg.tenant_id = 6;
        assert_eq!(cfg.to_domain_rule(&HashMap::new()).unwrap().tenant_id, 6);
    }

    #[test]
    fn to_domain_rule_without_a_tenant_is_global() {
        let cfg = snat_config();
        assert_eq!(cfg.tenant_id, 0);
        assert_eq!(cfg.to_domain_rule(&HashMap::new()).unwrap().tenant_id, 0);
    }

    #[test]
    fn to_domain_dnat() {
        let cfg = NatRuleConfig {
            id: "dnat-1".to_string(),
            enabled: true,
            priority: 10,
            nat_type: "dnat".to_string(),
            translated_addr: Some("10.0.1.10".to_string()),
            translated_port: Some(80),
            port_range: None,
            interface: None,
            external_addr: None,
            internal_addr: None,
            ext_port: None,
            int_port: None,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: Some("tcp".to_string()),
            match_src_alias: None,
            match_dst_alias: None,
            interfaces: Vec::new(),
            tenant_id: 0,
        };
        let rule = cfg.to_domain_rule(&HashMap::new()).unwrap();
        assert!(matches!(
            rule.nat_type,
            NatType::Dnat { port: Some(80), .. }
        ));
    }

    #[test]
    fn default_nat_config_disabled() {
        let cfg = NatConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.snat_rules.is_empty());
        assert!(cfg.dnat_rules.is_empty());
        assert!(cfg.nptv6_rules.is_empty());
    }

    #[test]
    fn nat_config_yaml_roundtrip() {
        let yaml = r#"
enabled: true
snat_rules:
  - id: snat-1
    type: snat
    priority: 10
    translated_addr: "10.0.0.1"
    match_src: "192.168.0.0/16"
dnat_rules: []
"#;
        let cfg: NatConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.snat_rules.len(), 1);
        assert!(cfg.validate().is_ok());
    }

    // ── NPTv6 config tests ─────────────────────────────────────────

    fn nptv6_config() -> NptV6RuleConfig {
        NptV6RuleConfig {
            id: "nptv6-1".to_string(),
            enabled: true,
            internal_prefix: "fd00:1::".to_string(),
            external_prefix: "2001:db8:1::".to_string(),
            prefix_len: 48,
            interfaces: Vec::new(),
        }
    }

    #[test]
    fn nptv6_validate_ok() {
        assert!(nptv6_config().validate(0).is_ok());
    }

    #[test]
    fn nptv6_validate_empty_id() {
        let mut cfg = nptv6_config();
        cfg.id = String::new();
        assert!(nptv6_config().validate(0).is_ok());
        cfg.id = String::new();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_prefix_len_zero() {
        let mut cfg = nptv6_config();
        cfg.prefix_len = 0;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_prefix_len_65() {
        let mut cfg = nptv6_config();
        cfg.prefix_len = 65;
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_invalid_internal_prefix() {
        let mut cfg = nptv6_config();
        cfg.internal_prefix = "not-an-ip".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_validate_invalid_external_prefix() {
        let mut cfg = nptv6_config();
        cfg.external_prefix = "not-an-ip".to_string();
        assert!(cfg.validate(0).is_err());
    }

    #[test]
    fn nptv6_to_domain_rule() {
        let rule = nptv6_config().to_domain_rule(&HashMap::new()).unwrap();
        assert_eq!(rule.id, "nptv6-1");
        assert_eq!(rule.prefix_len, 48);
        assert!(rule.enabled);
    }

    #[test]
    fn nptv6_yaml_roundtrip() {
        let yaml = r#"
enabled: true
snat_rules: []
dnat_rules: []
nptv6_rules:
  - id: nptv6-site1
    enabled: true
    internal_prefix: "fd00:1::"
    external_prefix: "2001:db8:1::"
    prefix_len: 48
"#;
        let cfg: NatConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.nptv6_rules.len(), 1);
        assert!(cfg.validate().is_ok());
        let rule = cfg.nptv6_rules[0].to_domain_rule(&HashMap::new()).unwrap();
        assert_eq!(rule.id, "nptv6-site1");
        assert_eq!(rule.prefix_len, 48);
    }

    // ── Hairpin NAT config tests ─────────────────────────────────

    #[test]
    fn hairpin_disabled_validates() {
        let cfg = HairpinNatConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn hairpin_enabled_ok() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: Some("192.168.1.0/24".to_string()),
            hairpin_snat_ip: Some("192.168.1.1".to_string()),
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn hairpin_enabled_missing_subnet() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: None,
            hairpin_snat_ip: Some("192.168.1.1".to_string()),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn hairpin_enabled_missing_snat_ip() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: Some("192.168.1.0/24".to_string()),
            hairpin_snat_ip: None,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn hairpin_invalid_subnet() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: Some("not-a-cidr".to_string()),
            hairpin_snat_ip: Some("192.168.1.1".to_string()),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn hairpin_invalid_snat_ip() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: Some("192.168.1.0/24".to_string()),
            hairpin_snat_ip: Some("not-an-ip".to_string()),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn hairpin_to_parsed_disabled() {
        let cfg = HairpinNatConfig::default();
        let (subnet, mask, snat_ip) = cfg.to_parsed().unwrap();
        assert_eq!(subnet, 0);
        assert_eq!(mask, 0);
        assert_eq!(snat_ip, 0);
    }

    #[test]
    fn hairpin_to_parsed_enabled() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: Some("192.168.1.0/24".to_string()),
            hairpin_snat_ip: Some("192.168.1.1".to_string()),
        };
        let (subnet, mask, snat_ip) = cfg.to_parsed().unwrap();
        assert_eq!(subnet, u32::from(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(mask, 0xFFFF_FF00);
        assert_eq!(snat_ip, u32::from(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn hairpin_yaml_roundtrip() {
        let yaml = r#"
enabled: true
snat_rules: []
dnat_rules: []
hairpin:
  enabled: true
  internal_subnet: "192.168.1.0/24"
  hairpin_snat_ip: "192.168.1.1"
"#;
        let cfg: NatConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.hairpin.enabled);
        assert!(cfg.validate().is_ok());
        let (subnet, _mask, _snat_ip) = cfg.hairpin.to_parsed().unwrap();
        assert_ne!(subnet, 0);
    }

    #[test]
    fn hairpin_prefix_len_33_rejected() {
        let cfg = HairpinNatConfig {
            enabled: true,
            internal_subnet: Some("192.168.1.0/33".to_string()),
            hairpin_snat_ip: Some("192.168.1.1".to_string()),
        };
        assert!(cfg.validate().is_err());
    }
}
