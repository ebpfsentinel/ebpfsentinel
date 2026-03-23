//! Agent configuration: structs, parsing, and validation.
//!
//! The config module is split across several sub-modules:
//! - `common`: shared helpers and `ConfigError`
//! - `firewall`, `ids`, `ips`, `l7`, `dlp`, `dns`, `ratelimit`,
//!   `threatintel`, `alerting`, `audit`, `auth`: domain-specific configs

mod alerting;
mod alias;
mod audit;
mod auth;
mod common;
mod conntrack;
mod ddos;
mod dlp;
mod dns;
mod firewall;
mod geoip;
mod ids;
mod ips;
mod l7;
mod loadbalancer;
mod nat;
mod qos;
mod ratelimit;
mod routing;
mod threatintel;
mod zone;

// ── Public re-exports ─────────────────────────────────────────────
//
// Everything that was previously `pub` in config.rs must remain accessible
// as `infrastructure::config::X`.

pub use alerting::{AlertRouteConfig, AlertingConfig, SmtpConfig};
pub use alias::AliasConfig;
pub use audit::AuditConfig;
pub use auth::{ApiKeyConfig, AuthConfig, JwtConfig, OidcConfig};
pub use common::{ConfigError, parse_cidr, parse_domain_mode};
pub use conntrack::ConnTrackSectionConfig;
pub use ddos::{
    AmpPortConfig, AmpProtectionConfig, DdosConfig, DdosPolicyConfig, IcmpProtectionConfig,
    SynProtectionConfig,
};
pub use dlp::{DlpConfig, DlpPatternConfig};
pub use dns::{
    DnsBlocklistFeedConfig, DnsBlocklistSectionConfig, DnsCacheConfig, DnsConfig,
    ReputationSectionConfig,
};
pub use firewall::{
    DefaultPolicy, FirewallConfig, FirewallRuleConfig, PortRangeConfig, ScopeConfig, ScopeMap,
};
pub use geoip::{GeoIpConfig, GeoIpSource};
pub use ids::{IdsConfig, IdsRuleConfig, SamplingConfig, ThresholdRuleConfig};
pub use ips::{IpsConfig, IpsRuleConfig};
pub use l7::{L7Config, L7RuleConfig};
pub use loadbalancer::{LbBackendConfig, LbServiceConfig as LbServiceCfg, LoadBalancerConfig};
pub use nat::{HairpinNatConfig, NatConfig, NatRuleConfig, NptV6RuleConfig};
pub use qos::{QosClassifierConfig, QosPipeConfig, QosQueueConfig, QosSectionConfig};
pub use ratelimit::{RateLimitRuleConfig, RateLimitSectionConfig};
pub use routing::{GatewayConfig, HealthCheckConfig, RoutingConfig};
pub use threatintel::{ThreatIntelConfig, ThreatIntelFeedConfig};
pub use zone::{ZoneEntryConfig, ZonePairConfig, ZoneSectionConfig};

use std::collections::HashMap;
use std::path::Path;

use domain::alert::entity::AlertRoute;
use domain::alias::entity::Alias;
use domain::common::entity::DomainMode;
use domain::conntrack::entity::ConnTrackSettings;
use domain::ddos::entity::DdosPolicy;
use domain::dlp::entity::DlpPattern;
use domain::firewall::entity::FirewallRule;
use domain::ids::entity::{IdsRule, SamplingMode};
use domain::ips::entity::{IpsPolicy, WhitelistEntry};
use domain::l7::entity::L7Rule;
use domain::nat::entity::{NatRule, NptV6Rule};
use domain::ratelimit::entity::RateLimitPolicy;
use domain::threatintel::entity::FeedConfig;
use domain::zone::entity::ZoneConfig;
use serde::{Deserialize, Serialize};

use crate::constants::{DEFAULT_GRPC_PORT, DEFAULT_HTTP_PORT, DEFAULT_METRICS_PORT};
use alias::MAX_ALIASES;
use common::{
    MAX_ALERTING_ROUTES, MAX_DLP_PATTERNS, MAX_FIREWALL_RULES, MAX_IDS_RULES, MAX_IPS_RULES,
    MAX_L7_RULES, MAX_RATELIMIT_RULES, MAX_THREATINTEL_FEEDS, check_limit,
    parse_domain_mode as pdm, warn_if_world_readable,
};
use ddos::MAX_DDOS_POLICIES;
use loadbalancer::MAX_LB_SERVICES;
use nat::{MAX_NAT_RULES, MAX_NPTV6_RULES};
use zone::MAX_ZONES;

// ── Top-level config ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub agent: AgentInfo,

    #[serde(default)]
    pub firewall: FirewallConfig,

    #[serde(default)]
    pub ids: IdsConfig,

    #[serde(default)]
    pub ips: IpsConfig,

    #[serde(default)]
    pub dlp: DlpConfig,

    #[serde(default)]
    pub dns: DnsConfig,

    #[serde(default)]
    pub ratelimit: RateLimitSectionConfig,

    #[serde(default)]
    pub ddos: DdosConfig,

    #[serde(default)]
    pub threatintel: ThreatIntelConfig,

    #[serde(default)]
    pub l7: L7Config,

    #[serde(default)]
    pub alerting: AlertingConfig,

    #[serde(default)]
    pub audit: AuditConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub conntrack: ConnTrackSectionConfig,

    #[serde(default)]
    pub nat: NatConfig,

    #[serde(default)]
    pub zones: ZoneSectionConfig,

    #[serde(default)]
    pub routing: RoutingConfig,

    #[serde(default)]
    pub loadbalancer: LoadBalancerConfig,

    #[serde(default)]
    pub qos: QosSectionConfig,

    #[serde(default)]
    pub geoip: Option<GeoIpConfig>,

    /// Top-level aliases shared across all domains (firewall, NAT, L7, etc.).
    #[serde(default)]
    pub aliases: HashMap<String, alias::AliasConfig>,

    /// Interface groups for multi-interface rule scoping.
    /// Each group maps a name to a set of interfaces. Rules can target
    /// specific groups via the `interfaces` field.
    #[serde(default)]
    pub interface_groups: HashMap<String, InterfaceGroupConfig>,

    /// Simple auto-response: automatic block/throttle on high-severity alerts.
    /// Limited to 3 policies. Enterprise adds unlimited policies, MITRE matching,
    /// SOAR webhooks, cooldowns, and full audit trail.
    #[serde(default)]
    pub auto_response: AutoResponseConfig,
}

/// Maximum number of interface groups (bits 0-30 of `group_mask`).
const MAX_INTERFACE_GROUPS: u32 = 31;

/// Bit 31 of `group_mask`: invert the match.
const GROUP_FLAG_INVERT: u32 = 0x8000_0000;

/// Interface group configuration for multi-interface rule scoping.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceGroupConfig {
    /// List of interface names in this group.
    pub interfaces: Vec<String>,
}

impl AgentConfig {
    /// Load config from a YAML file.
    ///
    /// On Unix, logs a warning if the config file is world-readable
    /// (permissions more permissive than 0o640), since config may
    /// contain sensitive values like auth headers and API keys.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        warn_if_world_readable(path, "config file");
        let content = std::fs::read_to_string(path)?;
        let config = Self::from_yaml(&content)?;

        // Warn if TLS key file is world-readable
        if config.agent.tls.enabled && !config.agent.tls.key_path.is_empty() {
            warn_if_world_readable(Path::new(&config.agent.tls.key_path), "TLS private key");
        }

        // Warn if JWT key file is world-readable
        if config.auth.enabled && !config.auth.jwt.public_key_path.is_empty() {
            warn_if_world_readable(
                Path::new(&config.auth.jwt.public_key_path),
                "JWT public key",
            );
        }

        Ok(config)
    }

    /// Parse config from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, ConfigError> {
        let config: Self = serde_yaml_ng::from_str(yaml)?;
        config.validate()?;
        Ok(config)
    }

    /// Return a copy of the config with sensitive values masked.
    /// Masks: API key secrets, TLS key paths, JWT key paths.
    #[must_use]
    pub fn sanitized(&self) -> Self {
        let mut sanitized = self.clone();
        for key in &mut sanitized.auth.api_keys {
            key.key = "***".to_string();
        }
        if !sanitized.agent.tls.key_path.is_empty() {
            sanitized.agent.tls.key_path = "***".to_string();
        }
        // Mask SMTP password
        if let Some(ref mut smtp) = sanitized.alerting.smtp
            && smtp.password.is_some()
        {
            smtp.password = Some("***".to_string());
        }
        // Mask threat intel feed auth headers
        for feed in &mut sanitized.threatintel.feeds {
            if feed.auth_header.is_some() {
                feed.auth_header = Some("***".to_string());
            }
        }
        // Mask GeoIP license key
        if let Some(ref mut geoip_cfg) = sanitized.geoip
            && let GeoIpSource::MaxMindAccount {
                ref mut license_key,
                ..
            } = geoip_cfg.source
        {
            *license_key = "***".to_string();
        }
        sanitized
    }

    /// Validate the config after deserialization.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.agent.interfaces.is_empty() {
            return Err(ConfigError::Validation {
                field: "agent.interfaces".to_string(),
                message: "at least one interface is required".to_string(),
            });
        }

        // Check port conflicts
        let ports = [
            ("http_port", self.agent.http_port),
            ("grpc_port", self.agent.grpc_port),
            ("metrics_port", self.agent.metrics_port),
        ];
        for i in 0..ports.len() {
            for j in (i + 1)..ports.len() {
                if ports[i].1 == ports[j].1 {
                    return Err(ConfigError::Validation {
                        field: format!("agent.{}", ports[j].0),
                        message: format!("port {} conflicts with agent.{}", ports[j].1, ports[i].0),
                    });
                }
            }
        }

        // ── Security: enforce rule count limits ──────────────────
        check_limit(
            "firewall.rules",
            self.firewall.rules.len(),
            MAX_FIREWALL_RULES,
        )?;
        check_limit("ids.rules", self.ids.rules.len(), MAX_IDS_RULES)?;
        check_limit("ips.rules", self.ips.rules.len(), MAX_IPS_RULES)?;
        check_limit("l7.rules", self.l7.rules.len(), MAX_L7_RULES)?;
        check_limit("dlp.patterns", self.dlp.patterns.len(), MAX_DLP_PATTERNS)?;
        check_limit(
            "threatintel.feeds",
            self.threatintel.feeds.len(),
            MAX_THREATINTEL_FEEDS,
        )?;
        check_limit(
            "ratelimit.rules",
            self.ratelimit.rules.len(),
            MAX_RATELIMIT_RULES,
        )?;
        check_limit(
            "alerting.routes",
            self.alerting.routes.len(),
            MAX_ALERTING_ROUTES,
        )?;

        // Validate TLS config
        if self.agent.tls.enabled {
            if self.agent.tls.cert_path.is_empty() {
                return Err(ConfigError::Validation {
                    field: "agent.tls.cert_path".to_string(),
                    message: "TLS is enabled but cert_path is not set".to_string(),
                });
            }
            if self.agent.tls.key_path.is_empty() {
                return Err(ConfigError::Validation {
                    field: "agent.tls.key_path".to_string(),
                    message: "TLS is enabled but key_path is not set".to_string(),
                });
            }
        }

        // Validate firewall rules
        for (idx, rule_cfg) in self.firewall.rules.iter().enumerate() {
            rule_cfg.validate(idx)?;
        }

        // Validate IDS rules
        for (idx, rule_cfg) in self.ids.rules.iter().enumerate() {
            rule_cfg.validate(idx)?;
        }

        // Validate IDS sampling
        if let Some(ref sampling) = self.ids.sampling {
            sampling.validate("ids")?;
        }

        // Validate IPS sampling
        if let Some(ref sampling) = self.ips.sampling {
            sampling.validate("ips")?;
        }

        // Validate IPS whitelist entries
        for (idx, entry_str) in self.ips.whitelist.iter().enumerate() {
            entry_str
                .parse::<WhitelistEntry>()
                .map_err(|e| ConfigError::Validation {
                    field: format!("ips.whitelist[{idx}]"),
                    message: e.to_string(),
                })?;
        }

        // Validate IPS rules
        for (idx, rule_cfg) in self.ips.rules.iter().enumerate() {
            rule_cfg.validate_ips(idx)?;
        }

        // Validate threat intel feeds
        for (idx, feed_cfg) in self.threatintel.feeds.iter().enumerate() {
            feed_cfg.validate(idx)?;
        }

        // Validate DLP patterns
        for (idx, pattern_cfg) in self.dlp.patterns.iter().enumerate() {
            pattern_cfg.validate(idx)?;
        }

        // Reject custom patterns and block mode (enterprise only)
        {
            use domain::dlp::entity::is_builtin_pattern_id;
            for pattern_cfg in &self.dlp.patterns {
                if !is_builtin_pattern_id(&pattern_cfg.id) {
                    return Err(ConfigError::Validation {
                        field: format!("dlp.patterns (id: {})", pattern_cfg.id),
                        message: "custom DLP patterns require enterprise license; \
                                  OSS supports built-in patterns only (dlp-pci-*, dlp-pii-*, dlp-cred-*)"
                            .to_string(),
                    });
                }
            }
            if self.dlp.mode == "block" || self.dlp.mode == "enforce" {
                return Err(ConfigError::Validation {
                    field: "dlp.mode".to_string(),
                    message: "DLP block/enforce mode requires enterprise license; \
                              OSS supports alert mode only"
                        .to_string(),
                });
            }
            for pattern_cfg in &self.dlp.patterns {
                if pattern_cfg.mode.as_deref() == Some("block")
                    || pattern_cfg.mode.as_deref() == Some("enforce")
                {
                    return Err(ConfigError::Validation {
                        field: format!("dlp.patterns[{}].mode", pattern_cfg.id),
                        message: "per-pattern block mode requires enterprise license".to_string(),
                    });
                }
            }
        }

        // Validate ratelimit rules
        for (idx, rule_cfg) in self.ratelimit.rules.iter().enumerate() {
            rule_cfg.validate(idx)?;
        }

        // Validate ratelimit country tiers
        for (idx, tier_cfg) in self.ratelimit.country_tiers.iter().enumerate() {
            tier_cfg.validate(idx)?;
        }

        // Validate DDoS policies
        check_limit("ddos.policies", self.ddos.policies.len(), MAX_DDOS_POLICIES)?;
        for (idx, policy_cfg) in self.ddos.policies.iter().enumerate() {
            policy_cfg.validate(idx)?;
        }

        // Validate L7 rules
        for (idx, rule_cfg) in self.l7.rules.iter().enumerate() {
            rule_cfg.validate(idx)?;
        }

        // Validate auth config
        if self.auth.enabled {
            let has_jwt = !self.auth.jwt.public_key_path.is_empty();
            let has_oidc = self.auth.oidc.is_some();
            let has_api_keys = !self.auth.api_keys.is_empty();

            if has_jwt && has_oidc {
                return Err(ConfigError::Validation {
                    field: "auth".to_string(),
                    message: "cannot enable both JWT and OIDC auth simultaneously".to_string(),
                });
            }

            if !has_jwt && !has_oidc && !has_api_keys {
                return Err(ConfigError::Validation {
                    field: "auth".to_string(),
                    message:
                        "auth is enabled but no auth method configured (jwt, oidc, or api_keys)"
                            .to_string(),
                });
            }

            // Validate OIDC JWKS URL scheme
            if let Some(ref oidc) = self.auth.oidc
                && !oidc.jwks_url.starts_with("https://")
            {
                tracing::warn!(
                    jwks_url = %oidc.jwks_url,
                    "OIDC JWKS URL does not use HTTPS — tokens may be fetched over an insecure channel"
                );
            }

            // Validate API key entries
            for (idx, key_cfg) in self.auth.api_keys.iter().enumerate() {
                let prefix = format!("auth.api_keys[{idx}]");

                if key_cfg.name.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.name"),
                        message: "API key name must not be empty".to_string(),
                    });
                }
                if key_cfg.key.is_empty() {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.key"),
                        message: "API key value must not be empty".to_string(),
                    });
                }
                if !["admin", "operator", "viewer"].contains(&key_cfg.role.as_str()) {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.role"),
                        message: format!(
                            "invalid role '{}', expected admin, operator, or viewer",
                            key_cfg.role
                        ),
                    });
                }
            }
        }

        // Validate alerting routes
        let smtp_present = self.alerting.smtp.is_some();
        for (idx, route_cfg) in self.alerting.routes.iter().enumerate() {
            route_cfg.validate(idx, smtp_present)?;
        }

        // Validate aliases (top-level + firewall.aliases for backward compat)
        let total_aliases = self.aliases.len() + self.firewall.aliases.len();
        check_limit("aliases", total_aliases, MAX_ALIASES)?;
        for (name, alias_cfg) in &self.aliases {
            alias_cfg.validate(name)?;
        }
        for (name, alias_cfg) in &self.firewall.aliases {
            alias_cfg.validate(name)?;
        }

        // Validate NAT rules
        check_limit("nat.snat_rules", self.nat.snat_rules.len(), MAX_NAT_RULES)?;
        check_limit("nat.dnat_rules", self.nat.dnat_rules.len(), MAX_NAT_RULES)?;
        check_limit(
            "nat.nptv6_rules",
            self.nat.nptv6_rules.len(),
            MAX_NPTV6_RULES,
        )?;
        self.nat.validate()?;

        // Validate zones
        check_limit("zones.zones", self.zones.zones.len(), MAX_ZONES)?;
        if self.zones.enabled {
            self.zones.validate()?;
        }

        // Validate DNS cache config
        self.dns.validate()?;

        // Validate load balancer services
        check_limit(
            "loadbalancer.services",
            self.loadbalancer.services.len(),
            MAX_LB_SERVICES,
        )?;
        for (idx, svc_cfg) in self.loadbalancer.services.iter().enumerate() {
            svc_cfg.validate(idx)?;
        }

        // Validate QoS config
        if self.qos.enabled {
            self.qos.validate()?;
        }

        // Validate GeoIP config
        if let Some(ref geoip_cfg) = self.geoip
            && geoip_cfg.enabled
        {
            geoip_cfg.validate()?;
        }

        // Validate interface groups
        if self.interface_groups.len() > MAX_INTERFACE_GROUPS as usize {
            return Err(ConfigError::Validation {
                field: "interface_groups".to_string(),
                message: format!(
                    "too many interface groups: {} (max {})",
                    self.interface_groups.len(),
                    MAX_INTERFACE_GROUPS
                ),
            });
        }
        for (name, group_cfg) in &self.interface_groups {
            if name.is_empty() {
                return Err(ConfigError::Validation {
                    field: "interface_groups".to_string(),
                    message: "interface group name must not be empty".to_string(),
                });
            }
            for iface in &group_cfg.interfaces {
                if !self.agent.interfaces.contains(iface) {
                    return Err(ConfigError::Validation {
                        field: format!("interface_groups.{name}"),
                        message: format!("interface '{iface}' is not in agent.interfaces"),
                    });
                }
            }
        }

        // Validate auto-response policies
        if self.auto_response.enabled
            && self.auto_response.policies.len() > MAX_AUTO_RESPONSE_POLICIES
        {
            return Err(ConfigError::Validation {
                field: "auto_response.policies".to_string(),
                message: format!(
                    "OSS supports at most {MAX_AUTO_RESPONSE_POLICIES} auto-response policies (found {}). \
                     Upgrade to Enterprise for unlimited policies.",
                    self.auto_response.policies.len()
                ),
            });
        }
        for (i, policy) in self.auto_response.policies.iter().enumerate() {
            let valid_severities = ["low", "medium", "high", "critical"];
            if !valid_severities.contains(&policy.min_severity.as_str()) {
                return Err(ConfigError::Validation {
                    field: format!("auto_response.policies[{i}].min_severity"),
                    message: format!(
                        "invalid severity '{}', expected one of: low, medium, high, critical",
                        policy.min_severity
                    ),
                });
            }
            let valid_actions = ["block", "throttle"];
            if !valid_actions.contains(&policy.action.as_str()) {
                return Err(ConfigError::Validation {
                    field: format!("auto_response.policies[{i}].action"),
                    message: format!(
                        "invalid action '{}', expected one of: block, throttle",
                        policy.action
                    ),
                });
            }
        }

        Ok(())
    }

    /// Parse the firewall mode from config to domain enum.
    pub fn firewall_mode(&self) -> Result<DomainMode, ConfigError> {
        pdm(&self.firewall.mode)
    }

    /// Convert all firewall rule configs to domain rules.
    pub fn firewall_rules(&self) -> Result<Vec<FirewallRule>, ConfigError> {
        self.firewall
            .rules
            .iter()
            .map(FirewallRuleConfig::to_domain_rule)
            .collect()
    }

    /// Parse the IDS mode from config to domain enum.
    pub fn ids_mode(&self) -> Result<DomainMode, ConfigError> {
        pdm(&self.ids.mode)
    }

    /// Convert all IDS rule configs to domain rules.
    pub fn ids_rules(&self) -> Result<Vec<IdsRule>, ConfigError> {
        self.ids
            .rules
            .iter()
            .map(|r| r.to_domain_rule(&self.ids.mode))
            .collect()
    }

    /// Convert IDS sampling config to domain `SamplingMode`.
    pub fn ids_sampling(&self) -> Result<SamplingMode, ConfigError> {
        match &self.ids.sampling {
            Some(cfg) => cfg.to_domain_sampling(),
            None => Ok(SamplingMode::None),
        }
    }

    /// Parse the IPS mode from config to domain enum.
    pub fn ips_mode(&self) -> Result<DomainMode, ConfigError> {
        pdm(&self.ips.mode)
    }

    /// Convert IPS sampling config to domain `SamplingMode`.
    pub fn ips_sampling(&self) -> Result<SamplingMode, ConfigError> {
        match &self.ips.sampling {
            Some(cfg) => cfg.to_domain_sampling(),
            None => Ok(SamplingMode::None),
        }
    }

    /// Convert all IPS rule configs to domain IDS rules (IPS reuses IDS rule format).
    pub fn ips_rules(&self) -> Result<Vec<IdsRule>, ConfigError> {
        self.ips
            .rules
            .iter()
            .map(|r| r.to_domain_rule(&self.ips.mode))
            .collect()
    }

    /// Build an `IpsPolicy` from config values.
    pub fn ips_policy(&self) -> IpsPolicy {
        self.ips.to_domain_policy()
    }

    /// Parse whitelist entries from IPS config strings.
    pub fn ips_whitelist(&self) -> Result<Vec<WhitelistEntry>, ConfigError> {
        self.ips
            .whitelist
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                s.parse::<WhitelistEntry>()
                    .map_err(|e| ConfigError::Validation {
                        field: format!("ips.whitelist[{idx}]"),
                        message: e.to_string(),
                    })
            })
            .collect()
    }

    /// Convert all ratelimit rule configs to domain `RateLimitPolicy` vec.
    pub fn ratelimit_policies(&self) -> Result<Vec<RateLimitPolicy>, ConfigError> {
        self.ratelimit
            .rules
            .iter()
            .map(RateLimitRuleConfig::to_domain_policy)
            .collect()
    }

    /// Convert all ratelimit country tier configs to domain `CountryTierConfig` vec.
    pub fn ratelimit_country_tiers(
        &self,
    ) -> Result<Vec<domain::ratelimit::entity::CountryTierConfig>, ConfigError> {
        self.ratelimit
            .country_tiers
            .iter()
            .map(ratelimit::CountryTierConfigYaml::to_domain_tier)
            .collect()
    }

    /// Convert all `DDoS` policy configs to domain policies.
    pub fn ddos_policies(&self) -> Result<Vec<DdosPolicy>, ConfigError> {
        self.ddos
            .policies
            .iter()
            .map(DdosPolicyConfig::to_domain_policy)
            .collect()
    }

    /// Parse the threat intel mode from config to domain enum.
    pub fn threatintel_mode(&self) -> Result<DomainMode, ConfigError> {
        pdm(&self.threatintel.mode)
    }

    /// Convert all threat intel feed configs to domain `FeedConfig` entries.
    pub fn threatintel_feeds(&self) -> Result<Vec<FeedConfig>, ConfigError> {
        self.threatintel
            .feeds
            .iter()
            .map(|f| f.to_domain_feed_config(&self.threatintel.mode))
            .collect()
    }

    /// Parse the DLP mode from config to domain enum.
    pub fn dlp_mode(&self) -> Result<DomainMode, ConfigError> {
        pdm(&self.dlp.mode)
    }

    /// Convert all DLP pattern configs to domain patterns.
    /// If no custom patterns are defined, returns an empty vec (caller loads defaults).
    pub fn dlp_patterns(&self) -> Result<Vec<DlpPattern>, ConfigError> {
        self.dlp
            .patterns
            .iter()
            .map(|p| p.to_domain_pattern(&self.dlp.mode))
            .collect()
    }

    /// Convert all L7 rule configs to domain L7 rules.
    pub fn l7_rules(&self) -> Result<Vec<L7Rule>, ConfigError> {
        self.l7
            .rules
            .iter()
            .map(L7RuleConfig::to_domain_rule)
            .collect()
    }

    /// Extract the unique set of L7-inspected ports for the eBPF `L7_PORTS` map.
    pub fn l7_ports(&self) -> Vec<u16> {
        let mut ports = self.l7.ports.clone();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    /// Convert alerting route configs to domain `AlertRoute` vec.
    pub fn alerting_routes(&self) -> Result<Vec<AlertRoute>, ConfigError> {
        self.alerting
            .routes
            .iter()
            .map(AlertRouteConfig::to_domain_route)
            .collect()
    }

    /// Convert alias configs to domain `Alias` entities.
    ///
    /// Merges top-level `aliases` with `firewall.aliases` (backward compat).
    /// Top-level aliases take precedence on name conflicts.
    pub fn aliases(&self) -> Result<Vec<Alias>, ConfigError> {
        let mut merged = self.firewall.aliases.clone();
        // Top-level overrides firewall-level on conflict
        merged.extend(self.aliases.clone());
        alias::aliases_to_domain(&merged)
    }

    /// Convert NAT DNAT rule configs to domain `NatRule` entities.
    pub fn nat_dnat_rules(&self) -> Result<Vec<NatRule>, ConfigError> {
        self.nat
            .dnat_rules
            .iter()
            .map(NatRuleConfig::to_domain_rule)
            .collect()
    }

    /// Convert NAT SNAT rule configs to domain `NatRule` entities.
    pub fn nat_snat_rules(&self) -> Result<Vec<NatRule>, ConfigError> {
        self.nat
            .snat_rules
            .iter()
            .map(NatRuleConfig::to_domain_rule)
            .collect()
    }

    /// Convert `NPTv6` rule configs to domain `NptV6Rule` entities.
    pub fn nat_nptv6_rules(&self) -> Result<Vec<NptV6Rule>, ConfigError> {
        self.nat
            .nptv6_rules
            .iter()
            .map(NptV6RuleConfig::to_domain_rule)
            .collect()
    }

    /// Parse hairpin NAT config to `(subnet_ip, subnet_mask, snat_ip)` as host-order `u32`.
    ///
    /// Returns `(0, 0, 0)` when disabled.
    pub fn nat_hairpin_parsed(&self) -> Result<(u32, u32, u32), ConfigError> {
        self.nat.hairpin.to_parsed()
    }

    /// Convert zone section config to domain `ZoneConfig`.
    pub fn zone_config(&self) -> Result<ZoneConfig, ConfigError> {
        self.zones.to_domain_config()
    }

    /// Build conntrack settings from the conntrack section.
    pub fn conntrack_settings(&self) -> ConnTrackSettings {
        ConnTrackSettings {
            enabled: self.conntrack.enabled,
            ..ConnTrackSettings::default()
        }
    }

    /// Convert DNS config to domain `DnsCacheConfig`.
    pub fn dns_cache_config(&self) -> domain::dns::entity::DnsCacheConfig {
        self.dns.to_domain_cache_config()
    }

    /// Convert DNS blocklist config to domain `DomainBlocklistConfig`.
    pub fn dns_blocklist_config(
        &self,
    ) -> Result<domain::dns::entity::DomainBlocklistConfig, ConfigError> {
        self.dns.to_domain_blocklist_config()
    }

    /// Convert all load balancer service configs to domain `LbService` entities.
    pub fn lb_services(&self) -> Result<Vec<domain::loadbalancer::entity::LbService>, ConfigError> {
        self.loadbalancer
            .services
            .iter()
            .map(loadbalancer::LbServiceConfig::to_domain_service)
            .collect()
    }

    /// Convert all `QoS` pipe configs to domain `QosPipe` entities.
    pub fn qos_pipes(&self) -> Result<Vec<domain::qos::entity::QosPipe>, ConfigError> {
        self.qos.to_domain_pipes()
    }

    /// Convert all `QoS` queue configs to domain `QosQueue` entities.
    pub fn qos_queues(&self) -> Result<Vec<domain::qos::entity::QosQueue>, ConfigError> {
        self.qos.to_domain_queues()
    }

    /// Convert all `QoS` classifier configs to domain `QosClassifier` entities.
    pub fn qos_classifiers(&self) -> Result<Vec<domain::qos::entity::QosClassifier>, ConfigError> {
        self.qos.to_domain_classifiers()
    }

    /// Assign a bit position (0-30) to each group name (sorted alphabetically).
    /// Returns mapping from group name to its single-bit bitmask.
    pub fn interface_group_bitmasks(&self) -> HashMap<String, u32> {
        let mut sorted: Vec<_> = self.interface_groups.keys().cloned().collect();
        sorted.sort();
        sorted
            .into_iter()
            .enumerate()
            .map(|(i, name)| (name, 1u32 << i))
            .collect()
    }

    /// Compute per-interface group membership bitmask.
    /// Returns mapping from interface name to its combined group bitmask
    /// (OR of all groups it belongs to).
    pub fn interface_membership(&self) -> HashMap<String, u32> {
        let bits = self.interface_group_bitmasks();
        let mut membership: HashMap<String, u32> = HashMap::new();
        for (group_name, group_cfg) in &self.interface_groups {
            if let Some(&bit) = bits.get(group_name) {
                for iface in &group_cfg.interfaces {
                    *membership.entry(iface.clone()).or_insert(0) |= bit;
                }
            }
        }
        membership
    }
}

/// Convert a list of interface group names (with optional "!" prefix for inversion)
/// to a `group_mask` u32 (bit 31 = invert).
#[allow(clippy::implicit_hasher)]
pub fn parse_group_mask(
    interfaces: &[String],
    group_bits: &HashMap<String, u32>,
) -> Result<u32, String> {
    if interfaces.is_empty() {
        return Ok(0); // floating rule
    }
    let mut mask = 0u32;
    let mut invert = false;
    for name in interfaces {
        if let Some(stripped) = name.strip_prefix('!') {
            invert = true;
            if let Some(&bit) = group_bits.get(stripped) {
                mask |= bit;
            } else {
                return Err(format!("unknown interface group: '{stripped}'"));
            }
        } else if let Some(&bit) = group_bits.get(name.as_str()) {
            mask |= bit;
        } else {
            return Err(format!("unknown interface group: '{name}'"));
        }
    }
    if invert {
        mask |= GROUP_FLAG_INVERT;
    }
    Ok(mask)
}

// ── Auto-response ──────────────────────────────────────────────────

/// Simple auto-response configuration (OSS).
///
/// Automatically blocks or throttles source IPs when alerts match
/// severity-based policies. Limited to 3 policies. Enterprise adds
/// MITRE tactic matching, SOAR webhooks, cooldowns, and audit trail.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoResponseConfig {
    /// Enable auto-response. Default: false.
    #[serde(default)]
    pub enabled: bool,

    /// Policies (max 3 in OSS). Each policy matches alerts by minimum
    /// severity and optional component filter, then executes block or throttle.
    #[serde(default)]
    pub policies: Vec<AutoResponsePolicyConfig>,
}

/// A single auto-response policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoResponsePolicyConfig {
    /// Policy name (for logging).
    pub name: String,

    /// Minimum severity to trigger: low, medium, high, critical.
    #[serde(default = "default_min_severity")]
    pub min_severity: String,

    /// Component filter (e.g. ["ids", "ddos"]).
    /// If empty, matches all components.
    #[serde(default)]
    pub components: Vec<String>,

    /// Action: "block" or "throttle".
    #[serde(default = "default_response_action")]
    pub action: String,

    /// TTL for the response action in seconds.
    #[serde(default = "default_response_ttl")]
    pub ttl_secs: u64,

    /// Rate limit in pps (only for "throttle" action).
    #[serde(default)]
    pub rate_pps: Option<u64>,
}

fn default_min_severity() -> String {
    "high".to_string()
}
fn default_response_action() -> String {
    "block".to_string()
}
fn default_response_ttl() -> u64 {
    3600
}

/// Maximum number of auto-response policies in OSS.
pub const MAX_AUTO_RESPONSE_POLICIES: usize = 3;

// ── Agent info ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub interfaces: Vec<String>,

    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,

    #[serde(default = "default_log_format")]
    pub log_format: LogFormat,

    #[serde(default = "default_http_port")]
    pub http_port: u16,

    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,

    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,

    #[serde(default)]
    pub tls: TlsConfig,

    /// IP address for HTTP/gRPC servers to bind to.
    /// Defaults to `127.0.0.1` (localhost only). Set to `0.0.0.0` to listen
    /// on all interfaces (required for Docker/container deployments).
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// Enable Swagger UI at `/swagger-ui`. Disabled by default in production.
    #[serde(default)]
    pub swagger_ui: bool,

    /// Directory containing compiled eBPF program binaries.
    /// Env `EBPF_PROGRAM_DIR` takes precedence, then this field, then defaults.
    #[serde(default)]
    pub ebpf_program_dir: Option<String>,

    /// XDP attachment mode: auto, native, generic, or offloaded.
    /// `auto` (default) lets the kernel pick the best available mode.
    /// If the requested mode is unsupported, falls back to auto with a warning.
    #[serde(default)]
    pub xdp_mode: XdpMode,
}

/// TLS configuration for HTTP and gRPC servers (NFR9).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS on HTTP and gRPC listeners.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the PEM-encoded server certificate (full chain).
    #[serde(default)]
    pub cert_path: String,

    /// Path to the PEM-encoded private key.
    #[serde(default)]
    pub key_path: String,

    /// Post-quantum key exchange mode: `prefer` (default), `require`, or `disable`.
    ///
    /// - `prefer`: offer `X25519MLKEM768` first, fall back to classical.
    /// - `require`: reject clients without PQ hybrid key exchange.
    /// - `disable`: classical-only (`X25519`, `SECP256R1`).
    #[serde(default)]
    pub pq_mode: PqMode,
}

/// XDP attachment mode for kernel programs.
///
/// Controls how XDP programs are attached to network interfaces:
/// - `auto`: let the kernel pick the best mode (native → generic fallback)
/// - `native`: force driver-mode XDP (fastest, requires driver support)
/// - `generic`: force SKB-mode XDP (universal, slower)
/// - `offloaded`: hardware offload to `SmartNIC` (requires NIC support)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XdpMode {
    /// Let the kernel pick the best available mode (default).
    #[default]
    Auto,
    /// Force driver-mode XDP. Falls back to best available if unsupported.
    Native,
    /// Force generic/SKB-mode XDP. Always works but slower.
    Generic,
    /// Hardware offload to `SmartNIC`. Falls back to best available if unsupported.
    Offloaded,
}

impl XdpMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Native => "native",
            Self::Generic => "generic",
            Self::Offloaded => "offloaded",
        }
    }
}

/// Post-quantum TLS key exchange policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PqMode {
    /// Prefer PQ hybrid, fall back to classical (default).
    #[default]
    Prefer,
    /// Require PQ hybrid — reject clients without support.
    Require,
    /// Classical only — no PQ key exchange offered.
    Disable,
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}
fn default_log_format() -> LogFormat {
    LogFormat::Json
}
fn default_http_port() -> u16 {
    DEFAULT_HTTP_PORT
}
fn default_grpc_port() -> u16 {
    DEFAULT_GRPC_PORT
}
fn default_metrics_port() -> u16 {
    DEFAULT_METRICS_PORT
}
fn default_bind_address() -> String {
    "127.0.0.1".to_string()
}

// ── Log level ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    pub fn to_tracing_level(self) -> tracing::Level {
        match self {
            Self::Error => tracing::Level::ERROR,
            Self::Warn => tracing::Level::WARN,
            Self::Info => tracing::Level::INFO,
            Self::Debug => tracing::Level::DEBUG,
            Self::Trace => tracing::Level::TRACE,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "error" => Ok(Self::Error),
            "warn" | "warning" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(format!(
                "invalid log level '{s}': expected error|warn|info|debug|trace"
            )),
        }
    }
}

// ── Log format ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    Json,
    Text,
}

impl LogFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Text => "text",
        }
    }
}

impl std::fmt::Display for LogFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "text" | "pretty" => Ok(Self::Text),
            _ => Err(format!("invalid log format '{s}': expected json|text")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::alert::entity::AlertDestination;
    use domain::common::entity::{DomainMode, Protocol, Severity};
    use domain::firewall::entity::{FirewallAction, IpNetwork};
    use domain::l7::entity::L7Matcher;
    use domain::ratelimit::entity::{RateLimitAction, RateLimitAlgorithm, RateLimitScope};
    use domain::threatintel::entity::FeedFormat;

    // ── VLAN config validation ─────────────────────────────────────

    #[test]
    fn firewall_rule_vlan_id_valid() {
        let yaml = r"
agent:
  interfaces: [eth0]
firewall:
  rules:
    - id: fw-vlan
      priority: 10
      action: deny
      protocol: tcp
      vlan_id: 100
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let rules = config.firewall_rules().unwrap();
        assert_eq!(rules[0].vlan_id, Some(100));
    }

    #[test]
    fn firewall_rule_vlan_id_too_large() {
        let yaml = r"
agent:
  interfaces: [eth0]
firewall:
  rules:
    - id: fw-vlan-bad
      priority: 10
      action: deny
      protocol: tcp
      vlan_id: 4095
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn firewall_rule_vlan_id_none_by_default() {
        let yaml = r"
agent:
  interfaces: [eth0]
firewall:
  rules:
    - id: fw-no-vlan
      priority: 10
      action: deny
      protocol: tcp
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let rules = config.firewall_rules().unwrap();
        assert_eq!(rules[0].vlan_id, None);
    }

    // ── Minimal config loading ────────────────────────────────────

    #[test]
    fn load_minimal_config() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.interfaces, vec!["eth0"]);
        assert_eq!(config.agent.log_level, LogLevel::Info);
        assert_eq!(config.agent.http_port, DEFAULT_HTTP_PORT);
        assert!(config.firewall.enabled);
        assert_eq!(config.firewall.mode, "alert");
        assert_eq!(config.firewall.default_policy, DefaultPolicy::Pass);
        assert!(config.firewall.rules.is_empty());
        assert!(config.ids.enabled);
        assert_eq!(config.ids.mode, "alert");
        assert_eq!(config.firewall_mode().unwrap(), DomainMode::Alert);
    }

    #[test]
    fn load_missing_interfaces_fails() {
        let yaml = r"
agent:
  interfaces: []
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn load_port_conflict_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
  http_port: 8080
  grpc_port: 8080
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    // ── Full config with firewall rules ───────────────────────────

    #[test]
    fn load_full_firewall_config() {
        let yaml = r#"
agent:
  interfaces: [eth0, wlan0]
  log_level: debug

firewall:
  enabled: true
  default_policy: drop
  rules:
    - id: fw-001
      priority: 10
      action: deny
      protocol: tcp
      src_ip: "192.168.1.0/24"
      dst_port: 22
      scope: global

    - id: fw-002
      priority: 20
      action: allow
      protocol: any
      dst_ip: "10.0.0.1"
      dst_port: "80-443"
      scope:
        interface: eth0
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.interfaces.len(), 2);
        assert_eq!(config.agent.log_level, LogLevel::Debug);
        assert_eq!(config.firewall.default_policy, DefaultPolicy::Drop);
        assert_eq!(config.firewall.rules.len(), 2);

        // Convert to domain rules
        let rules = config.firewall_rules().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id.0, "fw-001");
        assert_eq!(rules[0].action, FirewallAction::Deny);
        assert_eq!(rules[0].protocol, Protocol::Tcp);
        assert!(rules[0].src_ip.is_some());
        assert!(matches!(
            rules[0].src_ip,
            Some(IpNetwork::V4 { prefix_len: 24, .. })
        ));
        assert!(rules[0].dst_port.is_some());
        assert_eq!(rules[0].dst_port.unwrap().start, 22);
        assert_eq!(rules[0].dst_port.unwrap().end, 22);

        assert_eq!(rules[1].id.0, "fw-002");
        assert_eq!(rules[1].action, FirewallAction::Allow);
        assert_eq!(rules[1].protocol, Protocol::Any);
        assert!(rules[1].dst_ip.is_some());
        assert_eq!(rules[1].dst_port.unwrap().start, 80);
        assert_eq!(rules[1].dst_port.unwrap().end, 443);
        matches!(
            rules[1].scope,
            domain::firewall::entity::Scope::Interface(_)
        );
    }

    #[test]
    fn invalid_rule_action_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
firewall:
  rules:
    - id: bad
      priority: 1
      action: invalid_action
      protocol: tcp
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn invalid_rule_cidr_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
firewall:
  rules:
    - id: bad
      priority: 1
      action: deny
      src_ip: "not-a-cidr"
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    // ── LogLevel ──────────────────────────────────────────────────

    #[test]
    fn log_level_as_str() {
        assert_eq!(LogLevel::Info.as_str(), "info");
        assert_eq!(LogLevel::Error.as_str(), "error");
        assert_eq!(LogLevel::Debug.as_str(), "debug");
    }

    #[test]
    fn log_level_to_tracing() {
        assert_eq!(LogLevel::Info.to_tracing_level(), tracing::Level::INFO);
        assert_eq!(LogLevel::Error.to_tracing_level(), tracing::Level::ERROR);
    }

    // ── LogFormat ─────────────────────────────────────────────────

    #[test]
    fn log_format_as_str() {
        assert_eq!(LogFormat::Json.as_str(), "json");
        assert_eq!(LogFormat::Text.as_str(), "text");
    }

    #[test]
    fn log_format_from_str() {
        assert_eq!("json".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert_eq!("text".parse::<LogFormat>().unwrap(), LogFormat::Text);
        assert_eq!("pretty".parse::<LogFormat>().unwrap(), LogFormat::Text);
        assert_eq!("JSON".parse::<LogFormat>().unwrap(), LogFormat::Json);
        assert!("invalid".parse::<LogFormat>().is_err());
    }

    #[test]
    fn log_format_default_is_json() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.log_format, LogFormat::Json);
    }

    #[test]
    fn log_format_from_yaml() {
        let yaml = r"
agent:
  interfaces: [eth0]
  log_format: text
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.log_format, LogFormat::Text);
    }

    // ── DomainMode parsing ───────────────────────────────────────

    #[test]
    fn firewall_mode_from_config() {
        let yaml = r"
agent:
  interfaces: [eth0]
firewall:
  mode: block
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.firewall.mode, "block");
        assert_eq!(config.firewall_mode().unwrap(), DomainMode::Block);
    }

    // ── Alerting config ──────────────────────────────────────────

    #[test]
    fn default_alerting_config_backward_compat() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.alerting.enabled);
        assert_eq!(config.alerting.dedup_window_secs, 60);
        assert_eq!(config.alerting.throttle_window_secs, 300);
        assert_eq!(config.alerting.throttle_max, 100);
        assert_eq!(config.alerting.routes.len(), 1);
        assert_eq!(config.alerting.routes[0].name, "default-log");

        let routes = config.alerting_routes().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].name, "default-log");
        assert!(routes[0].event_types.is_none());
    }

    #[test]
    fn full_alerting_config() {
        let yaml = r#"
agent:
  interfaces: [eth0]
alerting:
  enabled: true
  dedup_window_secs: 120
  throttle_window_secs: 600
  throttle_max: 50
  smtp:
    host: smtp.example.com
    port: 587
    from_address: alerts@example.com
    tls: true
  routes:
    - name: all-to-log
      destination: log
      min_severity: low
    - name: critical-webhook
      destination: webhook
      min_severity: critical
      event_types: [ids]
      webhook_url: "https://hooks.example.com/alerts"
    - name: critical-email
      destination: email
      min_severity: critical
      email_to: admin@example.com
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.alerting.enabled);
        assert_eq!(config.alerting.dedup_window_secs, 120);
        assert_eq!(config.alerting.throttle_window_secs, 600);
        assert_eq!(config.alerting.throttle_max, 50);
        assert!(config.alerting.smtp.is_some());
        let smtp = config.alerting.smtp.as_ref().unwrap();
        assert_eq!(smtp.host, "smtp.example.com");
        assert_eq!(smtp.port, 587);
        assert_eq!(smtp.from_address, "alerts@example.com");
        assert!(smtp.tls);
        assert_eq!(config.alerting.routes.len(), 3);

        let routes = config.alerting_routes().unwrap();
        assert_eq!(routes.len(), 3);
        assert_eq!(routes[0].name, "all-to-log");
        assert!(routes[0].event_types.is_none());
        assert_eq!(routes[1].name, "critical-webhook");
        assert_eq!(
            routes[1].event_types.as_ref().unwrap(),
            &vec!["ids".to_string()]
        );
        assert!(matches!(
            routes[1].destination,
            AlertDestination::Webhook { ref url } if url == "https://hooks.example.com/alerts"
        ));
        assert_eq!(routes[2].name, "critical-email");
        assert!(matches!(
            routes[2].destination,
            AlertDestination::Email { ref to } if to == "admin@example.com"
        ));
    }

    #[test]
    fn email_route_without_smtp_config_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
alerting:
  routes:
    - name: email-route
      destination: email
      min_severity: critical
      email_to: admin@example.com
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("smtp"), "got: {err}");
    }

    #[test]
    fn webhook_route_without_url_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
alerting:
  routes:
    - name: webhook-route
      destination: webhook
      min_severity: high
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("webhook_url"), "got: {err}");
    }

    #[test]
    fn email_route_without_email_to_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
alerting:
  smtp:
    host: smtp.example.com
    from_address: alerts@example.com
  routes:
    - name: email-route
      destination: email
      min_severity: critical
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("email_to"), "got: {err}");
    }

    #[test]
    fn alerting_route_invalid_destination() {
        let yaml = r"
agent:
  interfaces: [eth0]
alerting:
  routes:
    - name: bad
      destination: carrier_pigeon
      min_severity: low
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn alerting_route_invalid_severity() {
        let yaml = r"
agent:
  interfaces: [eth0]
alerting:
  routes:
    - name: bad
      destination: log
      min_severity: extreme
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn alerting_route_empty_name() {
        let yaml = r#"
agent:
  interfaces: [eth0]
alerting:
  routes:
    - name: ""
      destination: log
      min_severity: low
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    // ── IPS config ──────────────────────────────────────────────

    #[test]
    fn default_ips_config_backward_compat() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.ips.enabled);
        assert_eq!(config.ips.mode, "alert");
        assert_eq!(config.ips.max_blacklist_duration_secs, 3600);
        assert_eq!(config.ips.auto_blacklist_threshold, 3);
        assert_eq!(config.ips.max_blacklist_size, 10_000);
        assert!(config.ips.rules.is_empty());
    }

    #[test]
    fn full_ips_config() {
        let yaml = r#"
agent:
  interfaces: [eth0]
ips:
  enabled: true
  mode: block
  max_blacklist_duration_secs: 7200
  auto_blacklist_threshold: 5
  max_blacklist_size: 50000
  rules:
    - id: ips-001
      description: "Block SSH brute force"
      severity: high
      mode: block
      protocol: tcp
      dst_port: 22
      enabled: true
    - id: ips-002
      severity: critical
      protocol: any
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.ips.enabled);
        assert_eq!(config.ips.mode, "block");
        assert_eq!(config.ips.max_blacklist_duration_secs, 7200);
        assert_eq!(config.ips.auto_blacklist_threshold, 5);
        assert_eq!(config.ips.max_blacklist_size, 50000);
        assert_eq!(config.ips.rules.len(), 2);

        let rules = config.ips_rules().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id.0, "ips-001");
        assert_eq!(rules[0].mode, DomainMode::Block);
        assert_eq!(rules[0].dst_port, Some(22));
        assert_eq!(rules[1].id.0, "ips-002");
        assert_eq!(rules[1].mode, DomainMode::Block); // inherits global
    }

    #[test]
    fn ips_policy_extraction() {
        let yaml = r"
agent:
  interfaces: [eth0]
ips:
  max_blacklist_duration_secs: 1800
  auto_blacklist_threshold: 10
  max_blacklist_size: 5000
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let policy = config.ips_policy();
        assert_eq!(
            policy.max_blacklist_duration,
            std::time::Duration::from_secs(1800)
        );
        assert_eq!(policy.auto_blacklist_threshold, 10);
        assert_eq!(policy.max_blacklist_size, 5000);
    }

    #[test]
    fn ips_mode_parsing() {
        let yaml = r"
agent:
  interfaces: [eth0]
ips:
  mode: block
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.ips_mode().unwrap(), DomainMode::Block);
    }

    #[test]
    fn ips_rule_invalid_severity_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
ips:
  rules:
    - id: bad
      severity: extreme
      protocol: tcp
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    // ── IPS whitelist config ──────────────────────────────────────

    #[test]
    fn empty_whitelist_default() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.ips.whitelist.is_empty());
        let wl = config.ips_whitelist().unwrap();
        assert!(wl.is_empty());
    }

    #[test]
    fn whitelist_with_ips() {
        let yaml = r#"
agent:
  interfaces: [eth0]
ips:
  whitelist:
    - "10.0.0.1"
    - "172.16.0.1"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.ips.whitelist.len(), 2);
        let wl = config.ips_whitelist().unwrap();
        assert_eq!(wl.len(), 2);
        assert_eq!(wl[0].cidr_prefix(), None);
    }

    #[test]
    fn whitelist_with_cidrs() {
        let yaml = r#"
agent:
  interfaces: [eth0]
ips:
  whitelist:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let wl = config.ips_whitelist().unwrap();
        assert_eq!(wl.len(), 2);
        assert_eq!(wl[0].cidr_prefix(), Some(24));
        assert_eq!(wl[1].cidr_prefix(), Some(8));
    }

    #[test]
    fn invalid_whitelist_entry_fails_validation() {
        let yaml = r#"
agent:
  interfaces: [eth0]
ips:
  whitelist:
    - "not-an-ip"
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    // ── L7 config ──────────────────────────────────────────────────

    #[test]
    fn default_l7_config() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(!config.l7.enabled);
        assert!(config.l7.ports.is_empty());
        assert!(config.l7.rules.is_empty());
    }

    #[test]
    fn full_l7_config() {
        let yaml = r#"
agent:
  interfaces: [eth0]
l7:
  enabled: true
  ports: [80, 443, 8080, 8443, 25, 21, 445]
  rules:
    - id: l7-001
      priority: 10
      action: deny
      protocol: http
      method: DELETE
      path: "/admin"
      enabled: true
    - id: l7-002
      priority: 20
      action: deny
      protocol: tls
      sni: "malware.example.com"
    - id: l7-003
      priority: 30
      action: log
      protocol: grpc
      service: "admin.AdminService"
      dst_ip: "10.0.0.0/8"
    - id: l7-004
      priority: 40
      action: deny
      protocol: smtp
      command: VRFY
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.l7.enabled);
        assert_eq!(config.l7.ports.len(), 7);
        assert_eq!(config.l7.rules.len(), 4);
    }

    #[test]
    fn l7_http_rule_conversion() {
        let yaml = r#"
agent:
  interfaces: [eth0]
l7:
  enabled: true
  ports: [80]
  rules:
    - id: l7-http
      priority: 10
      action: deny
      protocol: http
      method: POST
      path: "/api"
      host: "evil.com"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let rules = config.l7_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id.0, "l7-http");
        assert_eq!(rules[0].priority, 10);
        assert_eq!(rules[0].action, FirewallAction::Deny);
        assert!(matches!(
            &rules[0].matcher,
            L7Matcher::Http {
                method: Some(m),
                path_pattern: Some(p),
                host_pattern: Some(h),
                content_type: None,
            } if m == "POST" && p == "/api" && h.pattern() == "evil.com"
        ));
    }

    #[test]
    fn l7_tls_rule_conversion() {
        let yaml = r#"
agent:
  interfaces: [eth0]
l7:
  rules:
    - id: l7-tls
      priority: 20
      action: deny
      protocol: tls
      sni: "malware.example.com"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let rules = config.l7_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(matches!(
            &rules[0].matcher,
            L7Matcher::Tls { sni_pattern: Some(s) } if s.pattern() == "malware.example.com"
        ));
    }

    #[test]
    fn l7_invalid_protocol_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
l7:
  rules:
    - id: bad
      priority: 1
      action: deny
      protocol: invalid_proto
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn l7_invalid_action_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
l7:
  rules:
    - id: bad
      priority: 1
      action: nuke
      protocol: http
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn l7_ports_extraction() {
        let yaml = r"
agent:
  interfaces: [eth0]
l7:
  ports: [443, 80, 8080, 80, 443]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let ports = config.l7_ports();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn l7_rule_with_l3l4_fields() {
        let yaml = r#"
agent:
  interfaces: [eth0]
l7:
  rules:
    - id: l7-combined
      priority: 10
      action: deny
      protocol: http
      method: POST
      src_ip: "10.0.0.0/8"
      dst_port: 8080
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let rules = config.l7_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].src_ip.is_some());
        assert!(matches!(
            rules[0].src_ip,
            Some(IpNetwork::V4 { prefix_len: 8, .. })
        ));
        assert!(rules[0].dst_port.is_some());
        assert_eq!(rules[0].dst_port.unwrap().start, 8080);
    }

    // ── Ratelimit config ──────────────────────────────────────────

    #[test]
    fn default_ratelimit_config() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(!config.ratelimit.enabled);
        assert_eq!(config.ratelimit.default_rate, 1000);
        assert_eq!(config.ratelimit.default_burst, 2000);
        assert!(config.ratelimit.rules.is_empty());
    }

    #[test]
    fn full_ratelimit_config() {
        let yaml = r#"
agent:
  interfaces: [eth0]
ratelimit:
  enabled: true
  default_rate: 500
  default_burst: 1000
  rules:
    - id: rl-001
      rate: 100
      burst: 200
      src_ip: "10.0.0.0/8"
      action: drop
      enabled: true
    - id: rl-002
      rate: 50
      burst: 100
      action: pass
      scope: global
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.ratelimit.enabled);
        assert_eq!(config.ratelimit.default_rate, 500);
        assert_eq!(config.ratelimit.default_burst, 1000);
        assert_eq!(config.ratelimit.rules.len(), 2);

        let policies = config.ratelimit_policies().unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0].id.0, "rl-001");
        assert_eq!(policies[0].rate, 100);
        assert_eq!(policies[0].burst, 200);
        assert!(policies[0].src_ip.is_some());
        assert!(matches!(
            policies[0].src_ip,
            Some(IpNetwork::V4 { prefix_len: 8, .. })
        ));
        assert_eq!(policies[0].action, RateLimitAction::Drop);
        assert_eq!(policies[0].scope, RateLimitScope::SourceIp);

        assert_eq!(policies[1].id.0, "rl-002");
        assert_eq!(policies[1].action, RateLimitAction::Pass);
        assert_eq!(policies[1].scope, RateLimitScope::Global);
    }

    #[test]
    fn ratelimit_invalid_zero_rate_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: bad
      rate: 0
      burst: 100
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn ratelimit_invalid_zero_burst_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: bad
      rate: 100
      burst: 0
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn ratelimit_invalid_action_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: bad
      rate: 100
      burst: 200
      action: nuke
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn ratelimit_invalid_cidr_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: bad
      rate: 100
      burst: 200
      src_ip: "not-a-cidr"
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn ratelimit_action_aliases() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: rl-deny
      rate: 100
      burst: 200
      action: deny
    - id: rl-block
      rate: 100
      burst: 200
      action: block
    - id: rl-allow
      rate: 100
      burst: 200
      action: allow
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let policies = config.ratelimit_policies().unwrap();
        assert_eq!(policies[0].action, RateLimitAction::Drop);
        assert_eq!(policies[1].action, RateLimitAction::Drop);
        assert_eq!(policies[2].action, RateLimitAction::Pass);
    }

    #[test]
    fn ratelimit_scope_aliases() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: rl-per-ip
      rate: 100
      burst: 200
      scope: per_ip
    - id: rl-src-ip
      rate: 100
      burst: 200
      scope: src_ip
    - id: rl-global
      rate: 100
      burst: 200
      scope: global
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let policies = config.ratelimit_policies().unwrap();
        assert_eq!(policies[0].scope, RateLimitScope::SourceIp);
        assert_eq!(policies[1].scope, RateLimitScope::SourceIp);
        assert_eq!(policies[2].scope, RateLimitScope::Global);
    }

    // ── Ratelimit algorithm config ───────────────────────────────────

    #[test]
    fn ratelimit_default_algorithm() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: rl-001
      rate: 100
      burst: 200
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.ratelimit.default_algorithm, "token_bucket");
        let policies = config.ratelimit_policies().unwrap();
        assert_eq!(policies[0].algorithm, RateLimitAlgorithm::TokenBucket);
    }

    #[test]
    fn ratelimit_all_algorithms() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: rl-tb
      rate: 100
      burst: 200
      algorithm: token_bucket
    - id: rl-fw
      rate: 100
      burst: 200
      algorithm: fixed_window
    - id: rl-sw
      rate: 100
      burst: 200
      algorithm: sliding_window
    - id: rl-lb
      rate: 100
      burst: 200
      algorithm: leaky_bucket
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let policies = config.ratelimit_policies().unwrap();
        assert_eq!(policies[0].algorithm, RateLimitAlgorithm::TokenBucket);
        assert_eq!(policies[1].algorithm, RateLimitAlgorithm::FixedWindow);
        assert_eq!(policies[2].algorithm, RateLimitAlgorithm::SlidingWindow);
        assert_eq!(policies[3].algorithm, RateLimitAlgorithm::LeakyBucket);
    }

    #[test]
    fn ratelimit_algorithm_aliases() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: rl-tb
      rate: 100
      burst: 200
      algorithm: tokenbucket
    - id: rl-fw
      rate: 100
      burst: 200
      algorithm: fixedwindow
    - id: rl-sw
      rate: 100
      burst: 200
      algorithm: slidingwindow
    - id: rl-lb
      rate: 100
      burst: 200
      algorithm: leakybucket
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let policies = config.ratelimit_policies().unwrap();
        assert_eq!(policies[0].algorithm, RateLimitAlgorithm::TokenBucket);
        assert_eq!(policies[1].algorithm, RateLimitAlgorithm::FixedWindow);
        assert_eq!(policies[2].algorithm, RateLimitAlgorithm::SlidingWindow);
        assert_eq!(policies[3].algorithm, RateLimitAlgorithm::LeakyBucket);
    }

    #[test]
    fn ratelimit_invalid_algorithm_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
ratelimit:
  rules:
    - id: bad
      rate: 100
      burst: 200
      algorithm: random_algo
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    // ── DLP config tests ────────────────────────────────────────────

    #[test]
    fn dlp_defaults_when_absent() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.dlp.enabled);
        assert_eq!(config.dlp.mode, "alert");
        assert!(config.dlp.patterns.is_empty());
    }

    #[test]
    fn dlp_custom_patterns_parsed() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  enabled: true
  patterns:
    - id: dlp-pci-001
      name: Internal ID
      regex: "INT-\\d{6}"
      severity: high
      data_type: custom
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.dlp.patterns.len(), 1);
        assert_eq!(config.dlp.patterns[0].id, "dlp-pci-001");
        assert!(config.dlp.patterns[0].enabled);
    }

    #[test]
    fn dlp_patterns_to_domain() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  mode: alert
  patterns:
    - id: dlp-pii-test
      name: Test
      regex: "\\btest\\b"
      severity: medium
      data_type: custom
      description: A test pattern
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let patterns = config.dlp_patterns().unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id.0, "dlp-pii-test");
        assert_eq!(patterns[0].severity, Severity::Medium);
        assert_eq!(patterns[0].mode, DomainMode::Alert);
        assert_eq!(patterns[0].data_type, "custom");
        assert_eq!(patterns[0].description, "A test pattern");
    }

    #[test]
    fn dlp_pattern_mode_block_rejected() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  mode: alert
  patterns:
    - id: dlp-pci-block
      name: Blocked Pattern
      regex: "\\d+"
      severity: critical
      data_type: pci
      mode: block
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn dlp_block_mode_rejected() {
        let yaml = r"
agent:
  interfaces: [eth0]
dlp:
  mode: block
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn dlp_pattern_empty_id_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  patterns:
    - id: ""
      name: Bad
      regex: "\\d+"
      severity: high
      data_type: custom
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn dlp_pattern_empty_regex_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  patterns:
    - id: dlp-bad
      name: Bad
      regex: ""
      severity: high
      data_type: custom
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn dlp_pattern_invalid_regex_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  patterns:
    - id: dlp-bad
      name: Bad
      regex: "[invalid"
      severity: high
      data_type: custom
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn dlp_pattern_invalid_severity_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  patterns:
    - id: dlp-bad
      name: Bad
      regex: "\\d+"
      severity: extreme
      data_type: custom
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn dlp_pattern_disabled() {
        let yaml = r#"
agent:
  interfaces: [eth0]
dlp:
  patterns:
    - id: dlp-pci-off
      name: Disabled
      regex: "\\d+"
      severity: low
      data_type: custom
      enabled: false
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let patterns = config.dlp_patterns().unwrap();
        assert!(!patterns[0].enabled);
    }

    // ── Threat Intel config tests ───────────────────────────────────

    #[test]
    fn threatintel_defaults_when_absent() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.threatintel.enabled);
        assert_eq!(config.threatintel.mode, "alert");
        assert!(config.threatintel.feeds.is_empty());
    }

    #[test]
    fn threatintel_feed_parsed() {
        let yaml = r#"
agent:
  interfaces: [eth0]
threatintel:
  mode: block
  feeds:
    - id: spamhaus-drop
      name: Spamhaus DROP
      url: https://www.spamhaus.org/drop/drop.txt
      format: plaintext
      comment_prefix: ";"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.threatintel.feeds.len(), 1);
        assert_eq!(config.threatintel.feeds[0].id, "spamhaus-drop");
    }

    #[test]
    fn threatintel_feeds_to_domain() {
        let yaml = r#"
agent:
  interfaces: [eth0]
threatintel:
  mode: alert
  feeds:
    - id: test-feed
      name: Test
      url: https://example.com/iocs.csv
      format: csv
      ip_field: ip_address
      confidence_field: score
      separator: ","
      skip_header: true
      min_confidence: 50
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let feeds = config.threatintel_feeds().unwrap();
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds[0].id, "test-feed");
        assert_eq!(feeds[0].format, FeedFormat::Csv);
        assert_eq!(feeds[0].min_confidence, 50);
        let mapping = feeds[0].field_mapping.as_ref().unwrap();
        assert_eq!(mapping.ip_field, "ip_address");
        assert_eq!(mapping.confidence_field.as_deref(), Some("score"));
        assert!(mapping.skip_header);
    }

    #[test]
    fn threatintel_mode_parsed() {
        let yaml = r"
agent:
  interfaces: [eth0]
threatintel:
  mode: block
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.threatintel_mode().unwrap(), DomainMode::Block);
    }

    #[test]
    fn threatintel_feed_empty_id_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
threatintel:
  feeds:
    - id: ""
      name: Bad
      url: https://example.com
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn threatintel_feed_empty_url_fails() {
        let yaml = r#"
agent:
  interfaces: [eth0]
threatintel:
  feeds:
    - id: bad
      name: Bad
      url: ""
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn threatintel_feed_invalid_format_fails() {
        let yaml = r"
agent:
  interfaces: [eth0]
threatintel:
  feeds:
    - id: bad
      name: Bad
      url: https://example.com
      format: xml
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn threatintel_multiple_feeds() {
        let yaml = r#"
agent:
  interfaces: [eth0]
threatintel:
  feeds:
    - id: feed-a
      name: Feed A
      url: https://a.com/feed.txt
    - id: feed-b
      name: Feed B
      url: https://b.com/feed.json
      format: json
      ip_field: indicator
      auth_header: "X-API-KEY: secret"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.threatintel.feeds.len(), 2);
        let feeds = config.threatintel_feeds().unwrap();
        assert_eq!(feeds[1].format, FeedFormat::Json);
        assert_eq!(feeds[1].auth_header.as_deref(), Some("X-API-KEY: secret"));
    }

    #[test]
    fn threatintel_feed_action_override() {
        let yaml = r"
agent:
  interfaces: [eth0]
threatintel:
  mode: alert
  feeds:
    - id: blocked-feed
      name: Blocked
      url: https://example.com/block.txt
      default_action: block
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let feeds = config.threatintel_feeds().unwrap();
        assert_eq!(feeds[0].default_action.as_deref(), Some("block"));
    }

    // ── Auth config ──────────────────────────────────────────────────

    #[test]
    fn auth_defaults_when_absent() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(!config.auth.enabled);
        assert!(config.auth.jwt.public_key_path.is_empty());
        assert!(!config.auth.metrics_auth_required);
        assert!(config.auth.jwt.issuer.is_none());
        assert!(config.auth.jwt.audience.is_none());
    }

    #[test]
    fn auth_enabled_requires_some_method() {
        let yaml = r"
agent:
  interfaces: [eth0]
auth:
  enabled: true
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("no auth method configured"), "error: {msg}");
    }

    #[test]
    fn auth_enabled_with_key_path_ok() {
        let yaml = r"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  jwt:
    public_key_path: /etc/ebpfsentinel/jwt-pub.pem
    issuer: https://idp.example.com
    audience: ebpfsentinel
  metrics_auth_required: true
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.auth.enabled);
        assert_eq!(
            config.auth.jwt.public_key_path,
            "/etc/ebpfsentinel/jwt-pub.pem"
        );
        assert_eq!(
            config.auth.jwt.issuer.as_deref(),
            Some("https://idp.example.com")
        );
        assert_eq!(config.auth.jwt.audience.as_deref(), Some("ebpfsentinel"));
        assert!(config.auth.metrics_auth_required);
    }

    #[test]
    fn auth_disabled_no_key_path_ok() {
        let yaml = r"
agent:
  interfaces: [eth0]
auth:
  enabled: false
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(!config.auth.enabled);
    }

    #[test]
    fn auth_oidc_config_parsing() {
        let yaml = r"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  oidc:
    jwks_url: https://kubernetes.default.svc/openid/v1/jwks
    issuer: https://kubernetes.default.svc
    audience: ebpfsentinel
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.auth.enabled);
        let oidc = config.auth.oidc.unwrap();
        assert_eq!(
            oidc.jwks_url,
            "https://kubernetes.default.svc/openid/v1/jwks"
        );
        assert_eq!(
            oidc.issuer.as_deref(),
            Some("https://kubernetes.default.svc")
        );
        assert_eq!(oidc.audience.as_deref(), Some("ebpfsentinel"));
    }

    #[test]
    fn auth_both_jwt_and_oidc_rejected() {
        let yaml = r"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  jwt:
    public_key_path: /some/key.pem
  oidc:
    jwks_url: https://kubernetes.default.svc/openid/v1/jwks
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("both"), "error: {msg}");
    }

    #[test]
    fn auth_oidc_defaults() {
        let config: AuthConfig = serde_yaml_ng::from_str("enabled: false\n").unwrap();
        assert!(config.oidc.is_none());
    }

    #[test]
    fn auth_api_keys_only() {
        let yaml = r#"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  api_keys:
    - name: admin
      key: "sk-admin-secret"
      role: admin
    - name: monitoring
      key: "sk-monitoring"
      role: viewer
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.auth.enabled);
        assert_eq!(config.auth.api_keys.len(), 2);
        assert_eq!(config.auth.api_keys[0].name, "admin");
        assert_eq!(config.auth.api_keys[0].key, "sk-admin-secret");
        assert_eq!(config.auth.api_keys[0].role, "admin");
        assert!(config.auth.api_keys[0].namespaces.is_empty());
        assert_eq!(config.auth.api_keys[1].role, "viewer");
    }

    #[test]
    fn auth_api_keys_with_namespaces() {
        let yaml = r#"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  api_keys:
    - name: ops
      key: "sk-ops"
      role: operator
      namespaces: [prod, staging]
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.auth.api_keys[0].namespaces, vec!["prod", "staging"]);
    }

    #[test]
    fn auth_api_key_default_role_is_viewer() {
        let yaml = r#"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  api_keys:
    - name: default-role
      key: "sk-default"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.auth.api_keys[0].role, "viewer");
    }

    #[test]
    fn auth_api_key_empty_name_rejected() {
        let yaml = r#"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  api_keys:
    - name: ""
      key: "sk-test"
      role: admin
"#;
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("name"), "error: {err}");
    }

    #[test]
    fn auth_api_key_empty_key_rejected() {
        let yaml = r#"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  api_keys:
    - name: test
      key: ""
      role: admin
"#;
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("key"), "error: {err}");
    }

    #[test]
    fn auth_api_key_invalid_role_rejected() {
        let yaml = r#"
agent:
  interfaces: [eth0]
auth:
  enabled: true
  api_keys:
    - name: test
      key: "sk-test"
      role: superadmin
"#;
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("invalid role"), "error: {err}");
    }

    // ── TLS config ────────────────────────────────────────────────

    #[test]
    fn tls_disabled_by_default() {
        let yaml = "agent:\n  interfaces: [eth0]\n";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(!config.agent.tls.enabled);
        assert!(config.agent.tls.cert_path.is_empty());
        assert!(config.agent.tls.key_path.is_empty());
    }

    #[test]
    fn tls_enabled_requires_cert_path() {
        let yaml = r"
agent:
  interfaces: [eth0]
  tls:
    enabled: true
    key_path: /etc/tls/key.pem
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("cert_path"), "error: {err}");
    }

    #[test]
    fn tls_enabled_requires_key_path() {
        let yaml = r"
agent:
  interfaces: [eth0]
  tls:
    enabled: true
    cert_path: /etc/tls/cert.pem
";
        let err = AgentConfig::from_yaml(yaml).unwrap_err();
        assert!(err.to_string().contains("key_path"), "error: {err}");
    }

    #[test]
    fn tls_enabled_with_both_paths_ok() {
        let yaml = r"
agent:
  interfaces: [eth0]
  tls:
    enabled: true
    cert_path: /etc/tls/cert.pem
    key_path: /etc/tls/key.pem
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.agent.tls.enabled);
        assert_eq!(config.agent.tls.cert_path, "/etc/tls/cert.pem");
        assert_eq!(config.agent.tls.key_path, "/etc/tls/key.pem");
        assert_eq!(config.agent.tls.pq_mode, PqMode::Prefer);
    }

    #[test]
    fn tls_pq_mode_require() {
        let yaml = r"
agent:
  interfaces: [eth0]
  tls:
    enabled: true
    cert_path: /etc/tls/cert.pem
    key_path: /etc/tls/key.pem
    pq_mode: require
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.tls.pq_mode, PqMode::Require);
    }

    #[test]
    fn tls_pq_mode_disable() {
        let yaml = r"
agent:
  interfaces: [eth0]
  tls:
    enabled: true
    cert_path: /etc/tls/cert.pem
    key_path: /etc/tls/key.pem
    pq_mode: disable
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.tls.pq_mode, PqMode::Disable);
    }

    #[test]
    fn tls_pq_mode_defaults_to_prefer() {
        let yaml = r"
agent:
  interfaces: [eth0]
  tls:
    enabled: false
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert_eq!(config.agent.tls.pq_mode, PqMode::Prefer);
    }

    #[test]
    fn sanitized_masks_smtp_password() {
        let yaml = r"
agent:
  interfaces: [eth0]
alerting:
  smtp:
    host: smtp.example.com
    from_address: alerts@example.com
    password: super-secret-password
    username: admin
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let sanitized = config.sanitized();
        let smtp = sanitized.alerting.smtp.as_ref().unwrap();
        assert_eq!(smtp.password.as_deref(), Some("***"));
        // username is NOT masked
        assert_eq!(smtp.username.as_deref(), Some("admin"));
        assert_eq!(smtp.host, "smtp.example.com");
    }

    #[test]
    fn sanitized_masks_feed_auth_header() {
        let yaml = r#"
agent:
  interfaces: [eth0]
threatintel:
  enabled: true
  feeds:
    - id: feed-1
      name: test-feed
      url: "https://example.com/feed.txt"
      auth_header: "X-API-KEY: secret-token-123"
"#;
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let sanitized = config.sanitized();
        assert_eq!(
            sanitized.threatintel.feeds[0].auth_header.as_deref(),
            Some("***")
        );
        // URL is NOT masked
        assert_eq!(
            sanitized.threatintel.feeds[0].url,
            "https://example.com/feed.txt"
        );
    }

    #[test]
    fn sanitized_no_smtp_no_panic() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let sanitized = config.sanitized();
        assert!(sanitized.alerting.smtp.is_none());
    }

    // ── YAML → domain round-trip integration tests ────────────────

    #[test]
    fn ddos_yaml_to_domain_policies() {
        let yaml = r"
agent:
  interfaces: [eth0]
ddos:
  enabled: true
  policies:
    - id: syn-1
      attack_type: syn_flood
      detection_threshold_pps: 5000
      mitigation_action: block
      auto_block_duration_secs: 600
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let policies = config.ddos_policies().unwrap();
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].id.0, "syn-1");
        assert_eq!(
            policies[0].attack_type,
            domain::ddos::entity::DdosAttackType::SynFlood
        );
        assert_eq!(policies[0].detection_threshold_pps, 5000);
        assert_eq!(
            policies[0].mitigation_action,
            domain::ddos::entity::DdosMitigationAction::Block
        );
        assert_eq!(policies[0].auto_block_duration_secs, 600);
    }

    #[test]
    fn lb_yaml_to_domain_services() {
        let yaml = r"
agent:
  interfaces: [eth0]
loadbalancer:
  enabled: true
  services:
    - id: lb-web
      name: web
      listen_port: 80
      algorithm: round_robin
      backends:
        - id: be-1
          addr: 10.0.1.1
          port: 8080
          weight: 1
        - id: be-2
          addr: 10.0.1.2
          port: 8080
          weight: 2
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let services = config.lb_services().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].name, "web");
        assert_eq!(services[0].backends.len(), 2);
        assert_eq!(services[0].backends[1].weight, 2);
    }

    #[test]
    fn zone_yaml_to_domain_config() {
        let yaml = r"
agent:
  interfaces: [eth0]
zones:
  enabled: true
  zones:
    - id: internal
      interfaces: [eth1, eth2]
    - id: external
      interfaces: [eth0]
  policies:
    - from: external
      to: internal
      policy: deny
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let zone_cfg = config.zone_config().unwrap();
        assert_eq!(zone_cfg.zones.len(), 2);
        assert_eq!(zone_cfg.zones[0].id, "internal");
        assert_eq!(zone_cfg.zones[0].interfaces.len(), 2);
        assert_eq!(zone_cfg.zone_policies.len(), 1);
        assert_eq!(zone_cfg.zone_policies[0].from, "external");
        assert_eq!(zone_cfg.zone_policies[0].to, "internal");
    }

    #[test]
    fn conntrack_yaml_to_settings() {
        let yaml = r"
agent:
  interfaces: [eth0]
conntrack:
  enabled: true
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let settings = config.conntrack_settings();
        assert!(settings.enabled);
    }

    #[test]
    fn dns_yaml_to_domain_configs() {
        let yaml = r"
agent:
  interfaces: [eth0]
dns:
  cache:
    max_entries: 5000
  blocklist:
    action: block
    inject_target: threatintel
    domains:
      - '*.malware.example.com'
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let cache_cfg = config.dns_cache_config();
        assert_eq!(cache_cfg.max_entries, 5000);

        let blocklist_cfg = config.dns_blocklist_config().unwrap();
        assert_eq!(blocklist_cfg.patterns.len(), 1);
    }

    #[test]
    fn nat_yaml_to_domain_rules() {
        let yaml = r"
agent:
  interfaces: [eth0]
nat:
  enabled: true
  dnat_rules:
    - id: dnat-web
      type: dnat
      translated_addr: 192.168.1.10
      translated_port: 8080
  snat_rules:
    - id: snat-out
      type: snat
      translated_addr: 10.0.0.1
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let dnat = config.nat_dnat_rules().unwrap();
        assert_eq!(dnat.len(), 1);
        assert_eq!(dnat[0].id.0, "dnat-web");

        let snat = config.nat_snat_rules().unwrap();
        assert_eq!(snat.len(), 1);
        assert_eq!(snat[0].id.0, "snat-out");
    }

    // ── Interface groups ────────────────────────────────────────────

    #[test]
    fn interface_groups_empty_by_default() {
        let yaml = r"
agent:
  interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        assert!(config.interface_groups.is_empty());
        assert!(config.interface_group_bitmasks().is_empty());
        assert!(config.interface_membership().is_empty());
    }

    #[test]
    fn interface_groups_bitmask_assignment() {
        let yaml = r"
agent:
  interfaces: [eth0, eth1, eth2]
interface_groups:
  dmz:
    interfaces: [eth2]
  lan:
    interfaces: [eth0, eth1]
  wan:
    interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let bits = config.interface_group_bitmasks();
        // Sorted alphabetically: dmz=0, lan=1, wan=2
        assert_eq!(bits["dmz"], 1);
        assert_eq!(bits["lan"], 2);
        assert_eq!(bits["wan"], 4);
    }

    #[test]
    fn interface_membership_computed_correctly() {
        let yaml = r"
agent:
  interfaces: [eth0, eth1, eth2]
interface_groups:
  dmz:
    interfaces: [eth2]
  lan:
    interfaces: [eth0, eth1]
  wan:
    interfaces: [eth0]
";
        let config = AgentConfig::from_yaml(yaml).unwrap();
        let membership = config.interface_membership();
        let bits = config.interface_group_bitmasks();
        // eth0 is in lan + wan
        assert_eq!(membership["eth0"], bits["lan"] | bits["wan"]);
        // eth1 is in lan only
        assert_eq!(membership["eth1"], bits["lan"]);
        // eth2 is in dmz only
        assert_eq!(membership["eth2"], bits["dmz"]);
    }

    #[test]
    fn interface_group_validation_unknown_interface() {
        let yaml = r"
agent:
  interfaces: [eth0]
interface_groups:
  lan:
    interfaces: [eth0, eth1]
";
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn interface_group_validation_empty_name() {
        let yaml = r#"
agent:
  interfaces: [eth0]
interface_groups:
  "":
    interfaces: [eth0]
"#;
        assert!(AgentConfig::from_yaml(yaml).is_err());
    }

    #[test]
    fn parse_group_mask_empty() {
        let bits = HashMap::new();
        assert_eq!(parse_group_mask(&[], &bits).unwrap(), 0);
    }

    #[test]
    fn parse_group_mask_single_group() {
        let mut bits = HashMap::new();
        bits.insert("lan".to_string(), 1u32);
        bits.insert("wan".to_string(), 2u32);
        let mask = parse_group_mask(&["lan".to_string()], &bits).unwrap();
        assert_eq!(mask, 1);
    }

    #[test]
    fn parse_group_mask_multiple_groups() {
        let mut bits = HashMap::new();
        bits.insert("lan".to_string(), 1u32);
        bits.insert("wan".to_string(), 2u32);
        let mask = parse_group_mask(&["lan".to_string(), "wan".to_string()], &bits).unwrap();
        assert_eq!(mask, 3); // 1 | 2
    }

    #[test]
    fn parse_group_mask_inverted() {
        let mut bits = HashMap::new();
        bits.insert("lan".to_string(), 1u32);
        bits.insert("wan".to_string(), 2u32);
        let mask = parse_group_mask(&["!lan".to_string()], &bits).unwrap();
        assert_eq!(mask, 1 | GROUP_FLAG_INVERT);
    }

    #[test]
    fn parse_group_mask_unknown_group() {
        let bits = HashMap::new();
        assert!(parse_group_mask(&["unknown".to_string()], &bits).is_err());
    }

    #[test]
    fn parse_group_mask_unknown_inverted_group() {
        let bits = HashMap::new();
        assert!(parse_group_mask(&["!unknown".to_string()], &bits).is_err());
    }
}
