//! Threat Intelligence domain configuration structs and conversion logic.

use std::collections::HashMap;

use domain::threatintel::crowdsec::CROWDSEC_FEED_ID;
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

    /// Per-country confidence boost values (e.g. `{"RU": 10, "CN": 5}`).
    /// Positive boosts IOC confidence, negative reduces it. Clamped 0-100.
    #[serde(default)]
    pub country_confidence_boost: Option<HashMap<String, i8>>,

    /// Capacity of the kernel IOC tables (IPv4 and IPv6 each, plus their
    /// bloom filters), in entries. Absent, it is derived from the enabled
    /// feeds' `max_iocs` (see [`ThreatIntelConfig::capacity`]). Applies at
    /// the next agent start: a pinned map keeps the size it was created with.
    #[serde(default)]
    pub max_entries: Option<u32>,

    /// A CrowdSec local API to read decisions from and, optionally, to write
    /// the agent's own blocks back to. Absent or disabled, nothing is asked
    /// of it and nothing is sent.
    #[serde(default)]
    pub crowdsec: CrowdsecConfig,
}

/// The CrowdSec local API, read as a bouncer and written as a machine.
///
/// Reading is the bouncer half: the agent pulls the bans in force and loads
/// each banned address as an indicator, the way any other feed is loaded.
/// Writing is the machine half, off unless `report.enabled` is set too.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdsecConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Base address of the local API, e.g. `http://127.0.0.1:8080`. Unlike
    /// an internet feed it may be on the host or the local network.
    #[serde(default)]
    pub lapi_url: String,

    /// Key of a bouncer registered with `cscli bouncers add`.
    #[serde(default)]
    pub bouncer_key: String,

    /// How often the decision list is read again, in seconds.
    #[serde(default = "default_crowdsec_refresh_secs")]
    pub refresh_interval_secs: u64,

    /// Most decisions loaded at once.
    #[serde(default = "default_crowdsec_max_decisions")]
    pub max_decisions: usize,

    /// `alert` or `block` for a banned address. Inherits `threatintel.mode`
    /// when absent.
    #[serde(default)]
    pub default_action: Option<String>,

    #[serde(default)]
    pub report: CrowdsecReportConfig,
}

/// Writing the agent's blocks back to the local API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdsecReportConfig {
    #[serde(default)]
    pub enabled: bool,

    /// Machine registered with `cscli machines add`.
    #[serde(default)]
    pub machine_id: String,

    #[serde(default)]
    pub password: String,

    /// How often the blocks seen since the last report are sent, in seconds.
    #[serde(default = "default_crowdsec_report_secs")]
    pub interval_secs: u64,

    /// When set, each reported source also carries a ban of this length
    /// (`4h`, `30m`), which the local API hands to every bouncer it serves.
    /// Absent, the report is recorded and decides nothing.
    #[serde(default)]
    pub decision_duration: Option<String>,
}

fn default_crowdsec_refresh_secs() -> u64 {
    60
}
fn default_crowdsec_max_decisions() -> usize {
    100_000
}
fn default_crowdsec_report_secs() -> u64 {
    60
}

impl Default for CrowdsecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            lapi_url: String::new(),
            bouncer_key: String::new(),
            refresh_interval_secs: default_crowdsec_refresh_secs(),
            max_decisions: default_crowdsec_max_decisions(),
            default_action: None,
            report: CrowdsecReportConfig::default(),
        }
    }
}

impl Default for CrowdsecReportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            machine_id: String::new(),
            password: String::new(),
            interval_secs: default_crowdsec_report_secs(),
            decision_duration: None,
        }
    }
}

/// A CrowdSec duration: digits followed by `s`, `m` or `h`, possibly
/// repeated (`1h30m`).
fn is_crowdsec_duration(s: &str) -> bool {
    let mut digits = false;
    let mut any = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            digits = true;
        } else if matches!(c, 's' | 'm' | 'h') && digits {
            digits = false;
            any = true;
        } else {
            return false;
        }
    }
    any && !digits
}

impl CrowdsecConfig {
    fn invalid(field: &str, message: &str) -> ConfigError {
        ConfigError::Validation {
            field: format!("threatintel.crowdsec.{field}"),
            message: message.to_string(),
        }
    }

    /// Checked only when enabled, so a block left in place and switched off
    /// does not stop the agent.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        FeedConfig::validate_local_api_url(&self.lapi_url)
            .map_err(|m| Self::invalid("lapi_url", m))?;
        if self.bouncer_key.trim().is_empty() {
            return Err(Self::invalid("bouncer_key", "must not be empty"));
        }
        if self.bouncer_key.contains(['\r', '\n']) {
            return Err(Self::invalid("bouncer_key", "must be one line"));
        }
        if self.refresh_interval_secs < 60 {
            return Err(Self::invalid(
                "refresh_interval_secs",
                "must be at least 60",
            ));
        }
        if self.max_decisions == 0 {
            return Err(Self::invalid("max_decisions", "must be > 0"));
        }
        if let Some(ref action) = self.default_action {
            parse_domain_mode(action)?;
        }
        let report = &self.report;
        if report.enabled {
            if report.machine_id.trim().is_empty() {
                return Err(Self::invalid("report.machine_id", "must not be empty"));
            }
            if report.password.is_empty() {
                return Err(Self::invalid("report.password", "must not be empty"));
            }
            if report.interval_secs < 10 {
                return Err(Self::invalid("report.interval_secs", "must be at least 10"));
            }
            if let Some(ref d) = report.decision_duration
                && !is_crowdsec_duration(d)
            {
                return Err(Self::invalid(
                    "report.decision_duration",
                    "must look like 4h, 30m or 1h30m",
                ));
            }
        }
        Ok(())
    }

    /// The decision list as a feed, when reading is enabled.
    #[must_use]
    pub fn to_domain_feed_config(&self) -> Option<FeedConfig> {
        if !self.enabled {
            return None;
        }
        Some(FeedConfig {
            id: CROWDSEC_FEED_ID.to_string(),
            name: "CrowdSec local API".to_string(),
            url: format!(
                "{}/v1/decisions?type=ban",
                self.lapi_url.trim_end_matches('/')
            ),
            format: FeedFormat::Crowdsec,
            enabled: true,
            refresh_interval_secs: self.refresh_interval_secs,
            max_iocs: self.max_decisions,
            default_action: self.default_action.clone(),
            min_confidence: 0,
            field_mapping: None,
            auth_header: Some(format!("X-Api-Key: {}", self.bouncer_key.trim())),
        })
    }
}

/// Smallest capacity the IOC tables are ever created with.
pub const THREATINTEL_MIN_CAPACITY: u32 = 4_096;
/// Largest capacity `threatintel.max_entries` may ask for.
pub const THREATINTEL_MAX_CAPACITY: u32 = 4_194_304;

impl ThreatIntelConfig {
    /// Whether anything is configured to be fetched: a feed, or the CrowdSec
    /// decision list.
    #[must_use]
    pub fn has_feeds(&self) -> bool {
        !self.feeds.is_empty() || self.crowdsec.enabled
    }

    /// The capacity the kernel IOC tables are created with.
    ///
    /// `max_entries` when set; otherwise the enabled feeds' `max_iocs` added
    /// up, rounded up to a power of two so the hash table is not created at
    /// a size it fills to the last slot, held above
    /// [`THREATINTEL_MIN_CAPACITY`] and below [`THREATINTEL_MAX_CAPACITY`]. A
    /// configuration with no feed gets the floor rather than a million slots
    /// that hold nothing.
    #[must_use]
    pub fn capacity(&self) -> u32 {
        if let Some(n) = self.max_entries {
            return n;
        }
        let wanted: u64 = self
            .feeds
            .iter()
            .filter(|f| f.enabled)
            .map(|f| f.max_iocs as u64)
            .sum::<u64>()
            + if self.crowdsec.enabled {
                self.crowdsec.max_decisions as u64
            } else {
                0
            };
        let wanted = wanted.clamp(
            u64::from(THREATINTEL_MIN_CAPACITY),
            u64::from(THREATINTEL_MAX_CAPACITY),
        );
        let rounded = wanted.next_power_of_two();
        u32::try_from(rounded.min(u64::from(THREATINTEL_MAX_CAPACITY)))
            .unwrap_or(THREATINTEL_MAX_CAPACITY)
    }

    /// Bounds on an explicit `max_entries`.
    pub fn validate_capacity(&self) -> Result<(), ConfigError> {
        if let Some(n) = self.max_entries
            && !(THREATINTEL_MIN_CAPACITY..=THREATINTEL_MAX_CAPACITY).contains(&n)
        {
            return Err(ConfigError::Validation {
                field: "threatintel.max_entries".to_string(),
                message: format!(
                    "must be between {THREATINTEL_MIN_CAPACITY} and {THREATINTEL_MAX_CAPACITY}"
                ),
            });
        }
        Ok(())
    }
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            feeds: Vec::new(),
            country_confidence_boost: None,
            max_entries: None,
            crowdsec: CrowdsecConfig::default(),
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

        // Enforce the full SSRF guard (http(s) scheme + no loopback / private /
        // link-local / metadata targets), not just the URL scheme.
        FeedConfig::validate_url(&self.url).map_err(|message| ConfigError::Validation {
            field: format!("{prefix}.url"),
            message: message.to_string(),
        })?;

        if self.refresh_interval_secs == 0 {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.refresh_interval_secs"),
                message: "refresh interval must be > 0".to_string(),
            });
        }

        if self.id == CROWDSEC_FEED_ID {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: format!("`{CROWDSEC_FEED_ID}` is reserved for threatintel.crowdsec"),
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── CrowdSec ─────────────────────────────────────────────────────

    fn crowdsec() -> CrowdsecConfig {
        CrowdsecConfig {
            enabled: true,
            lapi_url: "http://127.0.0.1:8080/".to_string(),
            bouncer_key: "k3y".to_string(),
            ..CrowdsecConfig::default()
        }
    }

    #[test]
    fn crowdsec_is_off_by_default_and_unchecked_while_off() {
        let cfg = CrowdsecConfig::default();
        assert!(!cfg.enabled && !cfg.report.enabled);
        assert!(cfg.validate().is_ok());
        assert!(cfg.to_domain_feed_config().is_none());
    }

    #[test]
    fn crowdsec_becomes_a_local_feed() {
        let feed = crowdsec().to_domain_feed_config().unwrap();
        assert_eq!(feed.id, CROWDSEC_FEED_ID);
        assert_eq!(feed.format, FeedFormat::Crowdsec);
        assert_eq!(feed.url, "http://127.0.0.1:8080/v1/decisions?type=ban");
        assert_eq!(feed.auth_header.as_deref(), Some("X-Api-Key: k3y"));
        assert!(feed.validate().is_ok());
    }

    #[test]
    fn crowdsec_validation() {
        assert!(crowdsec().validate().is_ok());
        let mut cfg = crowdsec();
        cfg.lapi_url = "http://169.254.169.254".to_string();
        assert!(cfg.validate().is_err());
        let mut cfg = crowdsec();
        cfg.bouncer_key = "a\nb".to_string();
        assert!(cfg.validate().is_err());
        let mut cfg = crowdsec();
        cfg.report.enabled = true;
        assert!(cfg.validate().is_err());
        cfg.report.machine_id = "agent".to_string();
        cfg.report.password = "pw".to_string();
        assert!(cfg.validate().is_ok());
        cfg.report.decision_duration = Some("1h30m".to_string());
        assert!(cfg.validate().is_ok());
        cfg.report.decision_duration = Some("4 hours".to_string());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn crowdsec_is_not_a_feed_format_and_its_id_is_reserved() {
        assert!(parse_feed_format("crowdsec").is_err());
        let mut feed = valid_feed();
        feed.id = CROWDSEC_FEED_ID.to_string();
        assert!(feed.validate(0).is_err());
    }

    #[test]
    fn crowdsec_decisions_count_toward_capacity() {
        let mut cfg = ThreatIntelConfig {
            crowdsec: crowdsec(),
            ..ThreatIntelConfig::default()
        };
        cfg.crowdsec.max_decisions = 600_000;
        assert_eq!(cfg.capacity(), 1_048_576);
    }

    // ── Default config ───────────────────────────────────────────────

    #[test]
    fn default_config() {
        let cfg = ThreatIntelConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.mode, "alert");
        assert!(cfg.feeds.is_empty());
        assert!(cfg.max_entries.is_none());
    }

    // ── capacity ─────────────────────────────────────────────────────

    #[test]
    fn capacity_with_no_feed_is_the_floor() {
        assert_eq!(
            ThreatIntelConfig::default().capacity(),
            THREATINTEL_MIN_CAPACITY
        );
    }

    #[test]
    fn capacity_sums_enabled_feeds_and_rounds_up_to_a_power_of_two() {
        let mut cfg = ThreatIntelConfig::default();
        let mut a = valid_feed();
        a.max_iocs = 300_000;
        let mut b = valid_feed();
        b.id = "feed2".to_string();
        b.max_iocs = 300_000;
        let mut off = valid_feed();
        off.id = "feed3".to_string();
        off.enabled = false;
        off.max_iocs = 5_000_000;
        cfg.feeds = vec![a, b, off];
        // 600_000 rounds up to 2^20; the disabled feed is not counted.
        assert_eq!(cfg.capacity(), 1_048_576);
    }

    #[test]
    fn capacity_is_capped() {
        let mut cfg = ThreatIntelConfig::default();
        let mut a = valid_feed();
        a.max_iocs = 100_000_000;
        cfg.feeds = vec![a];
        assert_eq!(cfg.capacity(), THREATINTEL_MAX_CAPACITY);
    }

    #[test]
    fn explicit_max_entries_wins_and_is_bounded() {
        let mut cfg = ThreatIntelConfig {
            max_entries: Some(8_192),
            ..Default::default()
        };
        assert_eq!(cfg.capacity(), 8_192);
        assert!(cfg.validate_capacity().is_ok());
        cfg.max_entries = Some(100);
        assert!(cfg.validate_capacity().is_err());
        cfg.max_entries = Some(THREATINTEL_MAX_CAPACITY + 1);
        assert!(cfg.validate_capacity().is_err());
    }

    // ── Helpers ──────────────────────────────────────────────────────

    fn valid_feed() -> ThreatIntelFeedConfig {
        serde_norway::from_str(
            r#"
id: feed1
name: Test Feed
url: "https://example.com/feed.txt"
format: plaintext
refresh_interval_secs: 3600
"#,
        )
        .unwrap()
    }

    // ── ThreatIntelFeedConfig::validate() ────────────────────────────

    #[test]
    fn validate_empty_id_error() {
        let mut feed = valid_feed();
        feed.id = String::new();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("feed ID must not be empty"));
    }

    #[test]
    fn validate_empty_name_error() {
        let mut feed = valid_feed();
        feed.name = String::new();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("feed name must not be empty"));
    }

    #[test]
    fn validate_empty_url_error() {
        let mut feed = valid_feed();
        feed.url = String::new();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("feed URL must not be empty"));
    }

    #[test]
    fn validate_non_http_url_error() {
        let mut feed = valid_feed();
        feed.url = "file:///etc/passwd".to_string();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("http:// or https://"));
    }

    #[test]
    fn validate_rejects_ssrf_metadata_url() {
        let mut feed = valid_feed();
        feed.url = "http://169.254.169.254/latest/meta-data/".to_string();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("link-local"));
    }

    #[test]
    fn validate_rejects_loopback_url() {
        let mut feed = valid_feed();
        feed.url = "http://127.0.0.1:8080/feed".to_string();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn validate_refresh_interval_zero_error() {
        let mut feed = valid_feed();
        feed.refresh_interval_secs = 0;
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("refresh interval must be > 0"));
    }

    #[test]
    fn validate_invalid_format_error() {
        let mut feed = valid_feed();
        feed.format = "xml".to_string();
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("xml"));
    }

    #[test]
    fn validate_invalid_default_action_error() {
        let mut feed = valid_feed();
        feed.default_action = Some("nuke".to_string());
        let err = feed.validate(0).unwrap_err();
        assert!(err.to_string().contains("nuke"));
    }

    #[test]
    fn validate_valid_feed_passes() {
        let feed = valid_feed();
        feed.validate(0).unwrap();
    }

    // ── to_domain_feed_config() ──────────────────────────────────────

    #[test]
    fn to_domain_feed_config_with_field_mapping() {
        let feed: ThreatIntelFeedConfig = serde_norway::from_str(
            r##"
id: csv-feed
name: CSV Feed
url: "https://example.com/feed.csv"
format: csv
ip_field: src_ip
confidence_field: score
category_field: cat
separator: ";"
comment_prefix: "#"
skip_header: true
min_confidence: 50
"##,
        )
        .unwrap();

        let domain = feed.to_domain_feed_config("alert").unwrap();
        assert_eq!(domain.id, "csv-feed");
        assert_eq!(domain.name, "CSV Feed");
        assert_eq!(domain.url, "https://example.com/feed.csv");
        assert!(matches!(domain.format, FeedFormat::Csv));
        assert!(domain.enabled);
        assert_eq!(domain.min_confidence, 50);

        let mapping = domain.field_mapping.unwrap();
        assert_eq!(mapping.ip_field, "src_ip");
        assert_eq!(mapping.confidence_field.as_deref(), Some("score"));
        assert_eq!(mapping.category_field.as_deref(), Some("cat"));
        assert_eq!(mapping.separator, ';');
        assert_eq!(mapping.comment_prefix.as_deref(), Some("#"));
        assert!(mapping.skip_header);
    }

    #[test]
    fn to_domain_feed_config_without_field_mapping() {
        let feed = valid_feed();
        let domain = feed.to_domain_feed_config("alert").unwrap();
        assert!(domain.field_mapping.is_none());
        assert_eq!(domain.refresh_interval_secs, 3600);
        assert_eq!(domain.max_iocs, 500_000);
    }

    // ── parse_feed_format ────────────────────────────────────────────

    #[test]
    fn parse_feed_format_all_valid() {
        assert!(matches!(parse_feed_format("csv"), Ok(FeedFormat::Csv)));
        assert!(matches!(parse_feed_format("json"), Ok(FeedFormat::Json)));
        assert!(matches!(parse_feed_format("stix"), Ok(FeedFormat::Stix)));
        assert!(matches!(
            parse_feed_format("plaintext"),
            Ok(FeedFormat::Plaintext)
        ));
        assert!(matches!(
            parse_feed_format("txt"),
            Ok(FeedFormat::Plaintext)
        ));
        assert!(matches!(
            parse_feed_format("text"),
            Ok(FeedFormat::Plaintext)
        ));
        assert!(parse_feed_format("xml").is_err());
    }
}
