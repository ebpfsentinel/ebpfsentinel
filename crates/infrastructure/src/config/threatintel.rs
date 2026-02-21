//! Threat Intelligence domain configuration structs and conversion logic.

use domain::threatintel::entity::{FeedConfig, FeedFormat, FieldMapping};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_mode, default_true, parse_domain_mode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub feeds: Vec<ThreatIntelFeedConfig>,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            feeds: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelFeedConfig {
    pub id: String,
    pub name: String,
    pub url: String,

    /// Feed data format: csv, json, stix, plaintext.
    #[serde(default = "default_plaintext")]
    pub format: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Refresh interval in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_refresh_secs")]
    pub refresh_interval_secs: u64,

    /// Maximum IOCs to load from this feed.
    #[serde(default = "default_max_iocs")]
    pub max_iocs: usize,

    /// Per-feed action override ("alert" or "block"). Inherits global if absent.
    #[serde(default)]
    pub default_action: Option<String>,

    /// Minimum confidence to accept an IOC (0 = accept all).
    #[serde(default)]
    pub min_confidence: u8,

    /// Column/field for the IP address (CSV/JSON).
    #[serde(default)]
    pub ip_field: Option<String>,

    /// Column/field for confidence score (CSV/JSON).
    #[serde(default)]
    pub confidence_field: Option<String>,

    /// Column/field for threat category (CSV/JSON).
    #[serde(default)]
    pub category_field: Option<String>,

    /// Field separator for CSV feeds.
    #[serde(default)]
    pub separator: Option<char>,

    /// Comment prefix for plaintext feeds (e.g. "#").
    #[serde(default)]
    pub comment_prefix: Option<String>,

    /// Whether to skip the first line (CSV header).
    #[serde(default)]
    pub skip_header: bool,

    /// Optional auth header (e.g. "X-OTX-API-KEY: abc123").
    #[serde(default)]
    pub auth_header: Option<String>,
}

fn default_plaintext() -> String {
    "plaintext".to_string()
}
fn default_refresh_secs() -> u64 {
    3600
}
fn default_max_iocs() -> usize {
    500_000
}

impl ThreatIntelFeedConfig {
    pub fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("threatintel.feeds[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "feed ID must not be empty".to_string(),
            });
        }

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

        // Only allow http:// and https:// schemes to prevent SSRF
        if !self.url.starts_with("http://") && !self.url.starts_with("https://") {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.url"),
                message: format!(
                    "feed URL must use http:// or https:// scheme, got: '{}'",
                    self.url
                ),
            });
        }

        if self.refresh_interval_secs == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.refresh_interval_secs"),
                message: "refresh interval must be > 0".to_string(),
            });
        }

        // Validate format string
        parse_feed_format(&self.format).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.format"),
            value: self.format.clone(),
            expected: "csv, json, stix, plaintext".to_string(),
        })?;

        if let Some(ref action) = self.default_action {
            parse_domain_mode(action)?;
        }

        Ok(())
    }

    pub fn to_domain_feed_config(&self, _global_mode: &str) -> Result<FeedConfig, ConfigError> {
        let format = parse_feed_format(&self.format).map_err(|()| ConfigError::InvalidValue {
            field: "format".to_string(),
            value: self.format.clone(),
            expected: "csv, json, stix, plaintext".to_string(),
        })?;

        let field_mapping = if self.ip_field.is_some()
            || self.confidence_field.is_some()
            || self.category_field.is_some()
            || self.separator.is_some()
            || self.comment_prefix.is_some()
            || self.skip_header
        {
            Some(FieldMapping {
                ip_field: self.ip_field.clone().unwrap_or_else(|| "ip".to_string()),
                confidence_field: self.confidence_field.clone(),
                category_field: self.category_field.clone(),
                separator: self.separator.unwrap_or(','),
                comment_prefix: self.comment_prefix.clone(),
                skip_header: self.skip_header,
            })
        } else {
            None
        };

        Ok(FeedConfig {
            id: self.id.clone(),
            name: self.name.clone(),
            url: self.url.clone(),
            format,
            enabled: self.enabled,
            refresh_interval_secs: self.refresh_interval_secs,
            max_iocs: self.max_iocs,
            default_action: self.default_action.clone(),
            min_confidence: self.min_confidence,
            field_mapping,
            auth_header: self.auth_header.clone(),
        })
    }
}

pub(super) fn parse_feed_format(s: &str) -> Result<FeedFormat, ()> {
    match s.to_lowercase().as_str() {
        "csv" => Ok(FeedFormat::Csv),
        "json" => Ok(FeedFormat::Json),
        "stix" => Ok(FeedFormat::Stix),
        "plaintext" | "txt" | "text" => Ok(FeedFormat::Plaintext),
        _ => Err(()),
    }
}
