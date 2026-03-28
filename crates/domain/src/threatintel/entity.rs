use serde::{Deserialize, Serialize};
use std::net::IpAddr;

// ── Threat type ─────────────────────────────────────────────────────

/// Categorization of threat indicators. Matches kernel-side `THREAT_TYPE_*`
/// constants in ebpf-common.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    Other,
    Malware,
    C2,
    Scanner,
    Spam,
}

impl ThreatType {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Other => 0,
            Self::Malware => 1,
            Self::C2 => 2,
            Self::Scanner => 3,
            Self::Spam => 4,
        }
    }

    pub fn from_u8(n: u8) -> Self {
        match n {
            1 => Self::Malware,
            2 => Self::C2,
            3 => Self::Scanner,
            4 => Self::Spam,
            _ => Self::Other,
        }
    }
}

impl std::fmt::Display for ThreatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Other => "other",
            Self::Malware => "malware",
            Self::C2 => "c2",
            Self::Scanner => "scanner",
            Self::Spam => "spam",
        };
        f.write_str(s)
    }
}

// ── Indicator of Compromise ─────────────────────────────────────────

/// A single indicator of compromise loaded from a threat intelligence feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    /// The malicious IP address.
    pub ip: IpAddr,
    /// Identifier of the feed that provided this IOC.
    pub feed_id: String,
    /// Confidence score from the originating feed (0-100).
    pub confidence: u8,
    /// Threat category.
    pub threat_type: ThreatType,
    /// Timestamp (nanoseconds) when this IOC was last observed.
    pub last_seen: u64,
    /// Human-readable name of the source feed.
    pub source_feed: String,
}

impl Ioc {
    /// Validate IOC fields.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.confidence > 100 {
            return Err("confidence must be 0-100");
        }
        if self.feed_id.is_empty() {
            return Err("feed_id must not be empty");
        }
        Ok(())
    }
}

// ── Threat intel alert ──────────────────────────────────────────────

/// Alert generated when a packet matches a loaded IOC.
/// Carries the full packet context plus IOC metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIntelAlert {
    /// Feed that sourced the matched IOC.
    pub feed_id: String,
    /// Confidence of the matched IOC (0-100).
    pub confidence: u8,
    /// Threat type category.
    pub threat_type: ThreatType,
    /// Alert or Block, from the global threat intel mode.
    pub mode: crate::common::entity::DomainMode,
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6.
    pub src_addr: [u32; 4],
    /// Destination address: same encoding as `src_addr`.
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub timestamp_ns: u64,
}

impl ThreatIntelAlert {
    /// Returns the source IPv4 address (first element of `src_addr`).
    pub fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Returns the destination IPv4 address (first element of `dst_addr`).
    pub fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }
}

// ── Multi-type CTI indicators (STIX) ────────────────────────────────

/// Parsed CTI indicators from a multi-type feed (STIX 2.1).
/// Groups indicators by target engine for downstream distribution.
#[derive(Debug, Clone, Default)]
pub struct CtiIndicators {
    /// IP-based IOCs for the threat intel engine.
    pub iocs: Vec<Ioc>,
    /// Malicious domain names for the DNS blocklist and reputation engines.
    pub domains: Vec<CtiDomain>,
    /// Malicious URLs for the L7 firewall engine.
    pub urls: Vec<CtiUrl>,
}

/// A domain indicator extracted from a CTI feed.
#[derive(Debug, Clone)]
pub struct CtiDomain {
    pub domain: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: ThreatType,
    /// STIX indicator source (e.g. `"stix:feed-id"`) for bulk cleanup on refresh.
    pub source: Option<String>,
}

/// A URL indicator extracted from a CTI feed.
#[derive(Debug, Clone)]
pub struct CtiUrl {
    pub url: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: ThreatType,
    pub source: Option<String>,
}

// ── Feed format ─────────────────────────────────────────────────────

/// Feed format — defines HOW to parse, not WHO publishes.
/// Adding support for a new format requires implementing one parser trait;
/// no changes to the engine or config model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    /// Comma/character-separated values. Uses `FieldMapping.separator`.
    Csv,
    /// JSON array of objects. Uses `FieldMapping.ip_field` as JSONPath-like key.
    Json,
    /// STIX 2.1 bundle. Extracts indicators of type `ipv4-addr`.
    Stix,
    /// One IP per line. Lines starting with `comment_prefix` are skipped.
    Plaintext,
}

// ── Field mapping ───────────────────────────────────────────────────

/// Configurable field mapping for generic feed parsing.
/// Allows any CSV/JSON/plaintext feed to be ingested without code changes —
/// just define which column or field holds the IP, confidence, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldMapping {
    /// Column name (CSV) or JSON key/path holding the IP address.
    pub ip_field: String,
    /// Optional column/key for confidence score.
    #[serde(default)]
    pub confidence_field: Option<String>,
    /// Optional column/key for threat category.
    #[serde(default)]
    pub category_field: Option<String>,
    /// Field separator for CSV format (default: ',').
    #[serde(default = "default_separator")]
    pub separator: char,
    /// Comment prefix for plaintext format (e.g. "#").
    #[serde(default)]
    pub comment_prefix: Option<String>,
    /// Whether to skip the first line (CSV header).
    #[serde(default)]
    pub skip_header: bool,
}

fn default_separator() -> char {
    ','
}

impl Default for FieldMapping {
    fn default() -> Self {
        Self {
            ip_field: "ip".to_string(),
            confidence_field: None,
            category_field: None,
            separator: ',',
            comment_prefix: None,
            skip_header: false,
        }
    }
}

// ── Feed configuration ──────────────────────────────────────────────

/// Source-agnostic feed descriptor.
///
/// Any HTTP/HTTPS URL serving IOCs in a supported format can be configured
/// via YAML — no provider-specific code needed. Pre-built YAML templates
/// for popular feeds are
/// provided as examples, not hardcoded adapters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Unique feed identifier (e.g. "alienvault-otx", "internal-blocklist").
    pub id: String,
    /// Human-readable feed name.
    pub name: String,
    /// Feed download URL (HTTP/HTTPS).
    pub url: String,
    /// Format of the feed data.
    pub format: FeedFormat,
    /// Whether this feed is active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How often to re-download the feed (seconds). Default: 3600 (1h).
    #[serde(default = "default_refresh")]
    pub refresh_interval_secs: u64,
    /// Maximum IOCs to load from this feed. Default: 500,000.
    #[serde(default = "default_max_iocs")]
    pub max_iocs: usize,
    /// Per-feed action override ("alert" or "block"). Inherits global if absent.
    #[serde(default)]
    pub default_action: Option<String>,
    /// Minimum confidence to accept an IOC (0 = accept all).
    #[serde(default)]
    pub min_confidence: u8,
    /// How to extract fields from the feed data. Optional for plaintext (one IP per line).
    #[serde(default)]
    pub field_mapping: Option<FieldMapping>,
    /// Optional auth header (e.g. "X-OTX-API-KEY: abc123").
    #[serde(default)]
    pub auth_header: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_refresh() -> u64 {
    3600
}
fn default_max_iocs() -> usize {
    500_000
}

impl FeedConfig {
    /// Validate feed configuration fields.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.id.is_empty() {
            return Err("feed id must not be empty");
        }
        if self.name.is_empty() {
            return Err("feed name must not be empty");
        }
        if self.url.is_empty() {
            return Err("feed url must not be empty");
        }
        Self::validate_url(&self.url)?;
        if self.refresh_interval_secs == 0 {
            return Err("refresh_interval_secs must be > 0");
        }
        if self.max_iocs == 0 {
            return Err("max_iocs must be > 0");
        }
        if let Some(ref auth) = self.auth_header {
            Self::validate_auth_header(auth)?;
        }
        Ok(())
    }

    /// Validate feed URL: must be http(s), must not target private/loopback/link-local addresses.
    fn validate_url(url: &str) -> Result<(), &'static str> {
        // Scheme check
        let rest = if let Some(r) = url.strip_prefix("https://") {
            r
        } else if let Some(r) = url.strip_prefix("http://") {
            r
        } else {
            return Err("feed url must use http:// or https:// scheme");
        };

        // Extract host (strip path, query, fragment, userinfo, port)
        let host_port = rest.split('/').next().unwrap_or(rest);
        let host_port = host_port.split('?').next().unwrap_or(host_port);
        let host_port = host_port.split('#').next().unwrap_or(host_port);
        // Strip userinfo (user:pass@host)
        let host_port = host_port.rsplit_once('@').map_or(host_port, |(_, hp)| hp);

        // Extract host, handling IPv6 brackets and port
        let host = if let Some(bracketed) = host_port.strip_prefix('[') {
            // IPv6: [::1]:port
            bracketed.split(']').next().unwrap_or(bracketed)
        } else {
            // IPv4 or hostname: strip trailing :port
            host_port.rsplit_once(':').map_or(host_port, |(h, _)| h)
        };

        if host.is_empty() {
            return Err("feed url has empty host");
        }

        // Block well-known dangerous hostnames
        let host_lower = host.to_ascii_lowercase();
        if host_lower == "localhost"
            || host_lower == "metadata.google.internal"
            || host_lower.ends_with(".internal")
        {
            return Err("feed url must not target localhost or metadata endpoints");
        }

        // If host parses as an IP address, reject private/loopback/link-local ranges
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if ip.is_loopback() {
                return Err("feed url must not target loopback addresses");
            }
            if ip.is_unspecified() {
                return Err("feed url must not target unspecified addresses");
            }
            match ip {
                std::net::IpAddr::V4(v4) => {
                    if v4.is_private()
                        || v4.is_link_local()
                        || v4.octets()[0] == 169 && v4.octets()[1] == 254
                    {
                        return Err("feed url must not target private or link-local addresses");
                    }
                }
                std::net::IpAddr::V6(v6) => {
                    // Reject ULA (fc00::/7) and link-local (fe80::/10)
                    let first = v6.segments()[0];
                    if (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfe80 {
                        return Err("feed url must not target private or link-local addresses");
                    }
                }
            }
        }

        Ok(())
    }

    /// Validate auth header: must contain `:`, name/value must not contain CR/LF/NUL.
    fn validate_auth_header(header: &str) -> Result<(), &'static str> {
        let Some((name, value)) = header.split_once(':') else {
            return Err("auth_header must be in 'Name: value' format");
        };
        let name = name.trim();
        let value = value.trim();
        if name.is_empty() {
            return Err("auth_header name must not be empty");
        }
        // RFC 7230: header name is a token (visible ASCII, no delimiters)
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err("auth_header name contains invalid characters");
        }
        // Reject CR, LF, NUL in value (prevents header injection / CRLF attacks)
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
            return Err("auth_header value contains forbidden characters (CR/LF/NUL)");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    // ── ThreatType ──────────────────────────────────────────────────

    #[test]
    fn threat_type_u8_roundtrip() {
        for tt in [
            ThreatType::Other,
            ThreatType::Malware,
            ThreatType::C2,
            ThreatType::Scanner,
            ThreatType::Spam,
        ] {
            assert_eq!(ThreatType::from_u8(tt.to_u8()), tt);
        }
    }

    #[test]
    fn threat_type_from_u8_unknown_defaults_to_other() {
        assert_eq!(ThreatType::from_u8(255), ThreatType::Other);
        assert_eq!(ThreatType::from_u8(42), ThreatType::Other);
    }

    #[test]
    fn threat_type_display() {
        assert_eq!(format!("{}", ThreatType::Malware), "malware");
        assert_eq!(format!("{}", ThreatType::C2), "c2");
        assert_eq!(format!("{}", ThreatType::Other), "other");
    }

    // ── Ioc ─────────────────────────────────────────────────────────

    fn make_ioc() -> Ioc {
        Ioc {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            feed_id: "feed-001".to_string(),
            confidence: 85,
            threat_type: ThreatType::C2,
            last_seen: 1_000_000,
            source_feed: "Test Feed".to_string(),
        }
    }

    #[test]
    fn ioc_validate_ok() {
        assert!(make_ioc().validate().is_ok());
    }

    #[test]
    fn ioc_validate_confidence_over_100() {
        let mut ioc = make_ioc();
        ioc.confidence = 101;
        assert!(ioc.validate().is_err());
    }

    #[test]
    fn ioc_validate_empty_feed_id() {
        let mut ioc = make_ioc();
        ioc.feed_id = String::new();
        assert!(ioc.validate().is_err());
    }

    #[test]
    fn ioc_validate_confidence_boundary() {
        let mut ioc = make_ioc();
        ioc.confidence = 0;
        assert!(ioc.validate().is_ok());
        ioc.confidence = 100;
        assert!(ioc.validate().is_ok());
    }

    // ── FeedConfig ──────────────────────────────────────────────────

    fn make_feed() -> FeedConfig {
        FeedConfig {
            id: "test-feed".to_string(),
            name: "Test Feed".to_string(),
            url: "https://example.com/iocs.csv".to_string(),
            format: FeedFormat::Csv,
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            default_action: None,
            min_confidence: 0,
            field_mapping: None,
            auth_header: None,
        }
    }

    #[test]
    fn feed_config_validate_ok() {
        assert!(make_feed().validate().is_ok());
    }

    #[test]
    fn feed_config_empty_id_fails() {
        let mut f = make_feed();
        f.id = String::new();
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_config_empty_name_fails() {
        let mut f = make_feed();
        f.name = String::new();
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_config_empty_url_fails() {
        let mut f = make_feed();
        f.url = String::new();
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_config_zero_refresh_fails() {
        let mut f = make_feed();
        f.refresh_interval_secs = 0;
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_config_zero_max_iocs_fails() {
        let mut f = make_feed();
        f.max_iocs = 0;
        assert!(f.validate().is_err());
    }

    // ── URL validation (SSRF prevention) ────────────────────────────

    #[test]
    fn feed_url_rejects_non_http_scheme() {
        let mut f = make_feed();
        f.url = "ftp://example.com/feed.csv".to_string();
        assert_eq!(
            f.validate().unwrap_err(),
            "feed url must use http:// or https:// scheme"
        );
    }

    #[test]
    fn feed_url_rejects_loopback() {
        let mut f = make_feed();
        f.url = "http://127.0.0.1/feed.csv".to_string();
        assert_eq!(
            f.validate().unwrap_err(),
            "feed url must not target loopback addresses"
        );
    }

    #[test]
    fn feed_url_rejects_localhost() {
        let mut f = make_feed();
        f.url = "http://localhost/feed.csv".to_string();
        assert_eq!(
            f.validate().unwrap_err(),
            "feed url must not target localhost or metadata endpoints"
        );
    }

    #[test]
    fn feed_url_rejects_private_rfc1918() {
        for addr in ["10.0.0.1", "172.16.0.1", "192.168.1.1"] {
            let mut f = make_feed();
            f.url = format!("http://{addr}/feed.csv");
            assert!(f.validate().is_err(), "should reject private IP {addr}");
        }
    }

    #[test]
    fn feed_url_rejects_link_local() {
        let mut f = make_feed();
        f.url = "http://169.254.169.254/latest/meta-data/".to_string();
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_url_rejects_ipv6_loopback() {
        let mut f = make_feed();
        f.url = "http://[::1]/feed.csv".to_string();
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_url_rejects_metadata_internal() {
        let mut f = make_feed();
        f.url = "http://metadata.google.internal/computeMetadata/v1/".to_string();
        assert!(f.validate().is_err());
    }

    #[test]
    fn feed_url_accepts_public_https() {
        let f = make_feed(); // url is https://example.com/iocs.csv
        assert!(f.validate().is_ok());
    }

    #[test]
    fn feed_url_accepts_public_ip() {
        let mut f = make_feed();
        f.url = "https://1.2.3.4/feed.csv".to_string();
        assert!(f.validate().is_ok());
    }

    // ── Auth header validation (CRLF injection prevention) ──────────

    #[test]
    fn auth_header_valid() {
        let mut f = make_feed();
        f.auth_header = Some("X-OTX-API-KEY: abc123".to_string());
        assert!(f.validate().is_ok());
    }

    #[test]
    fn auth_header_rejects_crlf_in_value() {
        let mut f = make_feed();
        f.auth_header = Some("Authorization: Bearer token\r\nX-Injected: evil".to_string());
        assert_eq!(
            f.validate().unwrap_err(),
            "auth_header value contains forbidden characters (CR/LF/NUL)"
        );
    }

    #[test]
    fn auth_header_rejects_missing_colon() {
        let mut f = make_feed();
        f.auth_header = Some("NoColonHere".to_string());
        assert_eq!(
            f.validate().unwrap_err(),
            "auth_header must be in 'Name: value' format"
        );
    }

    #[test]
    fn auth_header_rejects_invalid_name_chars() {
        let mut f = make_feed();
        f.auth_header = Some("Bad Header: value".to_string());
        assert_eq!(
            f.validate().unwrap_err(),
            "auth_header name contains invalid characters"
        );
    }

    // ── FieldMapping ────────────────────────────────────────────────

    #[test]
    fn field_mapping_defaults() {
        let m = FieldMapping::default();
        assert_eq!(m.ip_field, "ip");
        assert_eq!(m.separator, ',');
        assert!(!m.skip_header);
        assert!(m.confidence_field.is_none());
        assert!(m.category_field.is_none());
        assert!(m.comment_prefix.is_none());
    }

    // ── FeedFormat serde ────────────────────────────────────────────

    #[test]
    fn feed_format_serde_roundtrip() {
        for fmt in [
            FeedFormat::Csv,
            FeedFormat::Json,
            FeedFormat::Stix,
            FeedFormat::Plaintext,
        ] {
            let json = serde_json::to_string(&fmt).unwrap();
            let back: FeedFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(back, fmt);
        }
    }
}
