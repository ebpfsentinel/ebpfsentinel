//! DNS domain configuration structs and conversion logic.

use serde::{Deserialize, Serialize};

use super::common::{ConfigError, check_limit, default_true};

/// Maximum blocklist domains (across inline + feeds).
const MAX_BLOCKLIST_DOMAINS: usize = 50_000;
/// Maximum blocklist feeds.
const MAX_BLOCKLIST_FEEDS: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default)]
    pub cache: DnsCacheConfig,

    #[serde(default)]
    pub blocklist: DnsBlocklistSectionConfig,

    #[serde(default)]
    pub reputation: ReputationSectionConfig,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            cache: DnsCacheConfig::default(),
            blocklist: DnsBlocklistSectionConfig::default(),
            reputation: ReputationSectionConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationSectionConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_max_tracked_domains")]
    pub max_tracked_domains: usize,

    #[serde(default = "default_auto_block_threshold")]
    pub auto_block_threshold: f64,

    #[serde(default)]
    pub auto_block_enabled: bool,

    #[serde(default = "default_auto_block_ttl")]
    pub auto_block_ttl_secs: u64,

    #[serde(default = "default_decay_half_life_hours")]
    pub decay_half_life_hours: u64,
}

fn default_max_tracked_domains() -> usize {
    50_000
}
fn default_auto_block_threshold() -> f64 {
    0.8
}
fn default_auto_block_ttl() -> u64 {
    3600
}
fn default_decay_half_life_hours() -> u64 {
    24
}

impl Default for ReputationSectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_tracked_domains: default_max_tracked_domains(),
            auto_block_threshold: default_auto_block_threshold(),
            auto_block_enabled: false,
            auto_block_ttl_secs: default_auto_block_ttl(),
            decay_half_life_hours: default_decay_half_life_hours(),
        }
    }
}

impl ReputationSectionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(0.0..=1.0).contains(&self.auto_block_threshold) {
            return Err(ConfigError::Validation {
                field: "dns.reputation.auto_block_threshold".to_string(),
                message: "must be between 0.0 and 1.0".to_string(),
            });
        }
        if self.max_tracked_domains < 1_000 || self.max_tracked_domains > 100_000 {
            return Err(ConfigError::Validation {
                field: "dns.reputation.max_tracked_domains".to_string(),
                message: "must be between 1,000 and 100,000".to_string(),
            });
        }
        if self.auto_block_ttl_secs == 0 {
            return Err(ConfigError::Validation {
                field: "dns.reputation.auto_block_ttl_secs".to_string(),
                message: "must be >= 1".to_string(),
            });
        }
        if self.decay_half_life_hours == 0 {
            return Err(ConfigError::Validation {
                field: "dns.reputation.decay_half_life_hours".to_string(),
                message: "must be >= 1".to_string(),
            });
        }
        Ok(())
    }

    pub fn to_domain_config(&self) -> domain::dns::entity::ReputationConfig {
        domain::dns::entity::ReputationConfig {
            enabled: self.enabled,
            max_tracked_domains: self.max_tracked_domains,
            auto_block_threshold: self.auto_block_threshold,
            auto_block_enabled: self.auto_block_enabled,
            auto_block_ttl_secs: self.auto_block_ttl_secs,
            decay_half_life_hours: self.decay_half_life_hours,
        }
    }
}

impl DnsConfig {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        self.cache.validate()?;
        self.blocklist.validate()?;
        self.reputation.validate()?;
        Ok(())
    }

    pub fn to_domain_cache_config(&self) -> domain::dns::entity::DnsCacheConfig {
        domain::dns::entity::DnsCacheConfig {
            max_entries: self.cache.max_entries,
            min_ttl_secs: self.cache.min_ttl_secs,
            purge_interval_secs: self.cache.purge_interval_secs,
        }
    }

    pub fn to_domain_blocklist_config(
        &self,
    ) -> Result<domain::dns::entity::DomainBlocklistConfig, ConfigError> {
        use domain::dns::entity::{BlocklistAction, DomainPattern, InjectTarget};

        let action = match self.blocklist.action.as_str() {
            "block" => BlocklistAction::Block,
            "alert" => BlocklistAction::Alert,
            "log" => BlocklistAction::Log,
            other => {
                return Err(ConfigError::InvalidValue {
                    field: "dns.blocklist.action".to_string(),
                    value: other.to_string(),
                    expected: "block, alert, log".to_string(),
                });
            }
        };

        let inject_target = match self.blocklist.inject_target.as_str() {
            "threatintel" => InjectTarget::ThreatIntel,
            "firewall" => InjectTarget::Firewall,
            "ips" => InjectTarget::Ips,
            other => {
                return Err(ConfigError::InvalidValue {
                    field: "dns.blocklist.inject_target".to_string(),
                    value: other.to_string(),
                    expected: "threatintel, firewall, ips".to_string(),
                });
            }
        };

        let mut patterns = Vec::new();
        for (idx, domain_str) in self.blocklist.domains.iter().enumerate() {
            let pattern =
                DomainPattern::parse(domain_str).map_err(|e| ConfigError::Validation {
                    field: format!("dns.blocklist.domains[{idx}]"),
                    message: e.to_string(),
                })?;
            patterns.push(pattern);
        }

        Ok(domain::dns::entity::DomainBlocklistConfig {
            patterns,
            action,
            inject_target,
            grace_period_secs: self.blocklist.grace_period_secs,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBlocklistSectionConfig {
    #[serde(default)]
    pub domains: Vec<String>,

    #[serde(default = "default_blocklist_action")]
    pub action: String,

    #[serde(default = "default_inject_target")]
    pub inject_target: String,

    #[serde(default = "default_grace_period")]
    pub grace_period_secs: u64,

    #[serde(default)]
    pub feeds: Vec<DnsBlocklistFeedConfig>,
}

impl Default for DnsBlocklistSectionConfig {
    fn default() -> Self {
        Self {
            domains: Vec::new(),
            action: "block".to_string(),
            inject_target: "threatintel".to_string(),
            grace_period_secs: 300,
            feeds: Vec::new(),
        }
    }
}

impl DnsBlocklistSectionConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        check_limit(
            "dns.blocklist.domains",
            self.domains.len(),
            MAX_BLOCKLIST_DOMAINS,
        )?;
        check_limit("dns.blocklist.feeds", self.feeds.len(), MAX_BLOCKLIST_FEEDS)?;

        // Validate action
        if !["block", "alert", "log"].contains(&self.action.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "dns.blocklist.action".to_string(),
                value: self.action.clone(),
                expected: "block, alert, log".to_string(),
            });
        }

        // Validate inject_target
        if !["threatintel", "firewall", "ips"].contains(&self.inject_target.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: "dns.blocklist.inject_target".to_string(),
                value: self.inject_target.clone(),
                expected: "threatintel, firewall, ips".to_string(),
            });
        }

        // Validate each domain pattern
        for (idx, domain_str) in self.domains.iter().enumerate() {
            let pattern = domain::dns::entity::DomainPattern::parse(domain_str).map_err(|e| {
                ConfigError::Validation {
                    field: format!("dns.blocklist.domains[{idx}]"),
                    message: e.to_string(),
                }
            })?;

            // Check wildcard depth
            if let domain::dns::entity::DomainPattern::Wildcard { suffix, .. } = &pattern {
                let depth = suffix.chars().filter(|&c| c == '.').count() + 1;
                if depth > 5 {
                    return Err(ConfigError::Validation {
                        field: format!("dns.blocklist.domains[{idx}]"),
                        message: format!(
                            "wildcard pattern '*.{suffix}' has {depth} label levels (max 5)"
                        ),
                    });
                }
            }
        }

        // Validate feeds
        for (idx, feed) in self.feeds.iter().enumerate() {
            feed.validate(idx)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsBlocklistFeedConfig {
    pub name: String,
    pub url: String,

    #[serde(default = "default_blocklist_feed_format")]
    pub format: String,

    #[serde(default = "default_feed_refresh_interval")]
    pub refresh_interval_secs: u64,
}

impl DnsBlocklistFeedConfig {
    fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("dns.blocklist.feeds[{idx}]");

        if self.name.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.name"),
                message: "feed name must not be empty".to_string(),
            });
        }
        if self.url.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.url"),
                message: "feed URL must not be empty".to_string(),
            });
        }
        if !["plaintext", "hosts"].contains(&self.format.as_str()) {
            return Err(ConfigError::InvalidValue {
                field: format!("{prefix}.format"),
                value: self.format.clone(),
                expected: "plaintext, hosts".to_string(),
            });
        }
        if self.refresh_interval_secs < 60 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.refresh_interval_secs"),
                message: "must be at least 60 seconds".to_string(),
            });
        }
        Ok(())
    }
}

fn default_blocklist_action() -> String {
    "block".to_string()
}
fn default_inject_target() -> String {
    "threatintel".to_string()
}
fn default_grace_period() -> u64 {
    300
}
fn default_blocklist_feed_format() -> String {
    "plaintext".to_string()
}
fn default_feed_refresh_interval() -> u64 {
    3600
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheConfig {
    #[serde(default = "default_dns_max_entries")]
    pub max_entries: usize,

    #[serde(default = "default_dns_min_ttl")]
    pub min_ttl_secs: u64,

    #[serde(default = "default_dns_purge_interval")]
    pub purge_interval_secs: u64,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            min_ttl_secs: 60,
            purge_interval_secs: 30,
        }
    }
}

impl DnsCacheConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_entries < 1_000 || self.max_entries > 1_000_000 {
            return Err(ConfigError::Validation {
                field: "dns.cache.max_entries".to_string(),
                message: "must be between 1,000 and 1,000,000".to_string(),
            });
        }
        if self.min_ttl_secs < 10 {
            return Err(ConfigError::Validation {
                field: "dns.cache.min_ttl_secs".to_string(),
                message: "must be at least 10 seconds".to_string(),
            });
        }
        if self.purge_interval_secs < 10 {
            return Err(ConfigError::Validation {
                field: "dns.cache.purge_interval_secs".to_string(),
                message: "must be at least 10 seconds".to_string(),
            });
        }
        Ok(())
    }
}

fn default_dns_max_entries() -> usize {
    100_000
}
fn default_dns_min_ttl() -> u64 {
    60
}
fn default_dns_purge_interval() -> u64 {
    30
}
