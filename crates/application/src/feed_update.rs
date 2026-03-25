use std::net::IpAddr;
use std::sync::Arc;

use domain::common::error::DomainError;
use domain::threatintel::entity::{
    CtiDomain, CtiIndicators, CtiUrl, FeedConfig, FeedFormat, Ioc, ThreatType,
};
use domain::threatintel::parser::{
    extract_domains_from_stix_pattern, extract_ips_from_stix_pattern,
    extract_urls_from_stix_pattern, map_stix_indicator_types, parse_feed, parse_stix_feed,
    parse_threat_type,
};
use ports::secondary::feed_source::FeedSource;
use ports::secondary::metrics_port::MetricsPort;

/// Fetch and parse all enabled feeds **concurrently**, returning a merged IOC list.
///
/// All feeds are fetched in parallel. Failed feeds are logged and skipped
/// (partial success: remaining feeds still load). IOC deduplication is
/// handled downstream by the engine's `reload()`.
pub async fn fetch_all_feeds(
    feeds: &[FeedConfig],
    source: &dyn FeedSource,
    metrics: &Arc<dyn MetricsPort>,
) -> Vec<Ioc> {
    let futures: Vec<_> = feeds
        .iter()
        .filter(|f| f.enabled)
        .map(|feed| async move {
            let result = fetch_single_feed(feed, source).await;
            (feed, result)
        })
        .collect();

    let results = futures_util::future::join_all(futures).await;

    let mut all_iocs = Vec::new();
    for (feed, result) in results {
        match result {
            Ok(iocs) => {
                tracing::info!(
                    feed_id = %feed.id,
                    ioc_count = iocs.len(),
                    "feed loaded successfully"
                );
                metrics.record_config_reload(&feed.id, "success");
                all_iocs.extend(iocs);
            }
            Err(e) => {
                tracing::warn!(
                    feed_id = %feed.id,
                    error = %e,
                    "feed download/parse failed, skipping"
                );
                metrics.record_config_reload(&feed.id, "failure");
            }
        }
    }

    all_iocs
}

/// Fetch and parse a single feed.
async fn fetch_single_feed(
    feed: &FeedConfig,
    source: &dyn FeedSource,
) -> Result<Vec<Ioc>, DomainError> {
    let raw_data = source.fetch_feed(feed).await?;
    parse_feed(&raw_data, feed, parse_json_feed)
}

/// Result of fetching all feeds, carrying multi-type indicators.
#[derive(Debug, Default)]
pub struct FeedUpdateResult {
    /// IP-based IOCs for the threat intel engine.
    pub iocs: Vec<Ioc>,
    /// Domain indicators for DNS blocklist and reputation engines.
    pub domains: Vec<CtiDomain>,
    /// URL indicators for L7 firewall engine.
    pub urls: Vec<CtiUrl>,
}

/// Fetch and parse all enabled feeds **concurrently**, returning multi-type indicators.
///
/// STIX feeds produce IPs, domains, and URLs. Legacy feeds (CSV, JSON,
/// plaintext) produce IPs only. Failed feeds are logged and skipped.
pub async fn fetch_all_feeds_v2(
    feeds: &[FeedConfig],
    source: &dyn FeedSource,
    metrics: &Arc<dyn MetricsPort>,
) -> FeedUpdateResult {
    let futures: Vec<_> = feeds
        .iter()
        .filter(|f| f.enabled)
        .map(|feed| async move {
            let raw_data = source.fetch_feed(feed).await;
            (feed, raw_data)
        })
        .collect();

    let fetched = futures_util::future::join_all(futures).await;

    let mut result = FeedUpdateResult::default();
    for (feed, raw_data) in fetched {
        let raw_data = match raw_data {
            Ok(data) => data,
            Err(e) => {
                tracing::warn!(feed_id = %feed.id, error = %e, "feed download failed, skipping");
                metrics.record_config_reload(&feed.id, "failure");
                continue;
            }
        };

        match feed.format {
            FeedFormat::Stix => match parse_stix_feed(&raw_data, feed, parse_stix_json) {
                Ok(indicators) => {
                    tracing::info!(
                        feed_id = %feed.id,
                        iocs = indicators.iocs.len(),
                        domains = indicators.domains.len(),
                        urls = indicators.urls.len(),
                        "STIX feed loaded"
                    );
                    metrics.record_config_reload(&feed.id, "success");
                    result.iocs.extend(indicators.iocs);
                    result.domains.extend(indicators.domains);
                    result.urls.extend(indicators.urls);
                }
                Err(e) => {
                    tracing::warn!(feed_id = %feed.id, error = %e, "STIX feed parse failed");
                    metrics.record_config_reload(&feed.id, "failure");
                }
            },
            _ => match parse_feed(&raw_data, feed, parse_json_feed) {
                Ok(iocs) => {
                    tracing::info!(feed_id = %feed.id, ioc_count = iocs.len(), "feed loaded");
                    metrics.record_config_reload(&feed.id, "success");
                    result.iocs.extend(iocs);
                }
                Err(e) => {
                    tracing::warn!(feed_id = %feed.id, error = %e, "feed parse failed");
                    metrics.record_config_reload(&feed.id, "failure");
                }
            },
        }
    }

    result
}

// ── STIX 2.1 JSON parser ──────────────────────────────────────────────

/// Parse a STIX 2.1 bundle JSON into `CtiIndicators`.
///
/// Extracts indicators from:
/// 1. `indicator` SDOs (via pattern parsing)
/// 2. Direct SCOs (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`)
/// 3. `relationship` SROs (enriches threat type via linked malware/attack-pattern)
///
/// Handles `valid_until` expiration filtering.
fn parse_stix_json(text: &str, config: &FeedConfig) -> Result<CtiIndicators, DomainError> {
    let parsed: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| DomainError::EngineError(format!("STIX JSON parse error: {e}")))?;

    let bundle_type = parsed.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if bundle_type != "bundle" {
        return Err(DomainError::EngineError(format!(
            "expected STIX bundle, got type '{bundle_type}'"
        )));
    }

    let objects = match parsed.get("objects").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return Ok(CtiIndicators::default()),
    };

    let source_tag = format!("stix:{}", config.id);
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Phase 1: index SDOs by ID for relationship enrichment
    let mut sdo_types: std::collections::HashMap<&str, ThreatType> =
        std::collections::HashMap::new();
    for obj in objects {
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let obj_id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");
        match obj_type {
            "malware" => {
                sdo_types.insert(obj_id, ThreatType::Malware);
            }
            "attack-pattern" => {
                sdo_types.insert(obj_id, ThreatType::Scanner);
            }
            "threat-actor" => {
                sdo_types.insert(obj_id, ThreatType::C2);
            }
            _ => {}
        }
    }

    // Phase 2: build relationship map (indicator_id → ThreatType)
    let mut relationship_enrichment: std::collections::HashMap<&str, ThreatType> =
        std::collections::HashMap::new();
    for obj in objects {
        if obj.get("type").and_then(|v| v.as_str()) != Some("relationship") {
            continue;
        }
        let rel_type = obj
            .get("relationship_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if rel_type != "indicates" {
            continue;
        }
        let source_ref = obj.get("source_ref").and_then(|v| v.as_str()).unwrap_or("");
        let target_ref = obj.get("target_ref").and_then(|v| v.as_str()).unwrap_or("");
        if let Some(&threat_type) = sdo_types.get(target_ref) {
            relationship_enrichment.insert(source_ref, threat_type);
        }
    }

    // Phase 3: extract indicators
    let mut result = CtiIndicators::default();

    for obj in objects {
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let obj_id = obj.get("id").and_then(|v| v.as_str()).unwrap_or("");

        match obj_type {
            "indicator" => {
                // Check temporal validity
                if let Some(valid_until) = obj.get("valid_until").and_then(|v| v.as_str()) {
                    if let Some(until_secs) = parse_iso8601_epoch_secs(valid_until) {
                        if until_secs < now_secs {
                            continue; // expired
                        }
                    }
                }

                let confidence = obj
                    .get("confidence")
                    .and_then(|v| v.as_u64())
                    .map_or(100, |v| v.min(100) as u8);

                // Determine threat type from indicator_types + relationship enrichment
                let indicator_types: Vec<&str> = obj
                    .get("indicator_types")
                    .and_then(|v| v.as_array())
                    .map_or_else(Vec::new, |arr| {
                        arr.iter().filter_map(|v| v.as_str()).collect()
                    });
                let mut threat_type = map_stix_indicator_types(&indicator_types);
                // Relationship enrichment overrides (more specific)
                if let Some(&rel_type) = relationship_enrichment.get(obj_id) {
                    threat_type = rel_type;
                }

                let last_seen = obj
                    .get("valid_from")
                    .and_then(|v| v.as_str())
                    .and_then(parse_iso8601_epoch_secs)
                    .map(|s| s * 1_000_000_000)
                    .unwrap_or(0);

                let pattern = obj.get("pattern").and_then(|v| v.as_str()).unwrap_or("");

                // Extract IPs
                for ip in extract_ips_from_stix_pattern(pattern) {
                    result.iocs.push(Ioc {
                        ip,
                        feed_id: config.id.clone(),
                        confidence,
                        threat_type,
                        last_seen,
                        source_feed: config.name.clone(),
                    });
                }

                // Extract domains
                for domain in extract_domains_from_stix_pattern(pattern) {
                    result.domains.push(CtiDomain {
                        domain,
                        feed_id: config.id.clone(),
                        confidence,
                        threat_type,
                        source: Some(source_tag.clone()),
                    });
                }

                // Extract URLs
                for url in extract_urls_from_stix_pattern(pattern) {
                    result.urls.push(CtiUrl {
                        url,
                        feed_id: config.id.clone(),
                        confidence,
                        threat_type,
                        source: Some(source_tag.clone()),
                    });
                }
            }
            // Direct SCOs (no pattern wrapper)
            "ipv4-addr" | "ipv6-addr" => {
                if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
                    if let Ok(ip) = value.parse::<IpAddr>() {
                        result.iocs.push(Ioc {
                            ip,
                            feed_id: config.id.clone(),
                            confidence: 50, // SCOs without relationship context are less reliable
                            threat_type: ThreatType::Other,
                            last_seen: 0,
                            source_feed: config.name.clone(),
                        });
                    }
                }
            }
            "domain-name" => {
                if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
                    if value.contains('.') {
                        result.domains.push(CtiDomain {
                            domain: value.to_lowercase(),
                            feed_id: config.id.clone(),
                            confidence: 50,
                            threat_type: ThreatType::Other,
                            source: Some(source_tag.clone()),
                        });
                    }
                }
            }
            "url" => {
                if let Some(value) = obj.get("value").and_then(|v| v.as_str()) {
                    result.urls.push(CtiUrl {
                        url: value.to_string(),
                        feed_id: config.id.clone(),
                        confidence: 50,
                        threat_type: ThreatType::Other,
                        source: Some(source_tag.clone()),
                    });
                }
            }
            _ => {} // skip unknown types
        }
    }

    Ok(result)
}

/// Parse a subset of ISO 8601 timestamps to epoch seconds.
/// Supports `2024-01-15T00:00:00Z` and `2024-01-15T00:00:00.000Z`.
fn parse_iso8601_epoch_secs(s: &str) -> Option<u64> {
    // Format: YYYY-MM-DDTHH:MM:SS[.fff]Z
    let s = s.trim().trim_end_matches('Z');
    let (date_part, time_part) = s.split_once('T')?;
    let mut date_parts = date_part.split('-');
    let year: u64 = date_parts.next()?.parse().ok()?;
    let month: u64 = date_parts.next()?.parse().ok()?;
    let day: u64 = date_parts.next()?.parse().ok()?;

    let time_part = time_part.split('.').next()?; // strip fractional seconds
    let mut time_parts = time_part.split(':');
    let hour: u64 = time_parts.next()?.parse().ok()?;
    let min: u64 = time_parts.next()?.parse().ok()?;
    let sec: u64 = time_parts.next()?.parse().ok()?;

    // Simplified days-from-epoch (not accounting for leap seconds, good enough for expiry)
    let days = days_from_civil(year, month, day)?;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

/// Days from Unix epoch (1970-01-01) for a given civil date.
fn days_from_civil(year: u64, month: u64, day: u64) -> Option<u64> {
    if month < 1 || month > 12 || day < 1 || day > 31 || year < 1970 {
        return None;
    }
    // Algorithm from Howard Hinnant
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let m = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe;
    // Unix epoch offset: 1970-01-01 = day 719468 from civil epoch
    days.checked_sub(719468)
}

/// Build an L7 firewall rule from a STIX URL indicator.
///
/// Parses the URL to extract host and path, creating an HTTP block rule.
/// Rule IDs are prefixed with `stix:` for identification and cleanup.
pub fn build_l7_rule_from_url(
    url_indicator: &CtiUrl,
    priority: u32,
) -> Option<domain::l7::entity::L7Rule> {
    let stripped = url_indicator
        .url
        .strip_prefix("https://")
        .or_else(|| url_indicator.url.strip_prefix("http://"))?;

    let (host, path) = match stripped.find('/') {
        Some(pos) => (&stripped[..pos], Some(stripped[pos..].to_string())),
        None => (stripped, None),
    };

    if host.is_empty() {
        return None;
    }

    let host_matcher = domain::l7::domain_matcher::DomainMatcher::new(host).ok()?;
    let sanitized_host = host.replace('.', "-");
    let rule_id = format!("stix-{}-{}", url_indicator.feed_id, sanitized_host);

    Some(domain::l7::entity::L7Rule {
        id: domain::common::entity::RuleId(rule_id),
        priority,
        action: domain::firewall::entity::FirewallAction::Deny,
        matcher: domain::l7::entity::L7Matcher::Http {
            method: None,
            path_pattern: path,
            host_pattern: Some(host_matcher),
            content_type: None,
        },
        src_ip: None,
        dst_ip: None,
        dst_port: None,
        src_ip_alias: None,
        dst_ip_alias: None,
        dst_port_alias: None,
        src_country_codes: None,
        dst_country_codes: None,
        enabled: true,
    })
}

/// Parse a JSON feed into IOCs. Expects a top-level array of objects.
///
/// This lives in the application layer (rather than domain) to keep `serde_json`
/// out of the domain crate's production dependencies.
fn parse_json_feed(text: &str, config: &FeedConfig) -> Result<Vec<Ioc>, DomainError> {
    let mapping = config.field_mapping.clone().unwrap_or_default();

    let parsed: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| DomainError::EngineError(format!("JSON parse error: {e}")))?;

    let items = match &parsed {
        serde_json::Value::Array(arr) => arr.as_slice(),
        _ => {
            return Err(DomainError::EngineError(
                "JSON feed must be a top-level array".to_string(),
            ));
        }
    };

    let mut iocs = Vec::new();

    for item in items {
        let ip_str = item
            .get(&mapping.ip_field)
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        let confidence = mapping
            .confidence_field
            .as_ref()
            .and_then(|cf| item.get(cf.as_str()))
            .and_then(serde_json::Value::as_u64)
            .map_or(100, |v| v.min(100) as u8);

        let threat_type = mapping
            .category_field
            .as_ref()
            .and_then(|cf| item.get(cf.as_str()))
            .and_then(serde_json::Value::as_str)
            .map_or(ThreatType::Other, parse_threat_type);

        iocs.push(Ioc {
            ip,
            feed_id: config.id.clone(),
            confidence,
            threat_type,
            last_seen: 0,
            source_feed: config.name.clone(),
        });
    }

    Ok(iocs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::threatintel::entity::FeedFormat;
    use ports::secondary::metrics_port::{
        AlertMetrics, AuditMetrics, ConfigMetrics, ConntrackMetrics, DdosMetrics, DlpMetrics,
        DnsMetrics, DomainMetrics, EventMetrics, FingerprintMetrics, FirewallMetrics, IpsMetrics,
        LbMetrics, PacketMetrics, RoutingMetrics, SystemMetrics,
    };
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct MockSource {
        response: Vec<u8>,
        fail: bool,
    }

    impl FeedSource for MockSource {
        fn fetch_feed<'a>(
            &'a self,
            _config: &'a FeedConfig,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DomainError>> + Send + 'a>> {
            let fail = self.fail;
            let data = self.response.clone();
            Box::pin(async move {
                if fail {
                    Err(DomainError::EngineError("mock failure".to_string()))
                } else {
                    Ok(data)
                }
            })
        }
    }

    struct TestMetrics {
        reload_success: AtomicU32,
        reload_failure: AtomicU32,
    }

    impl TestMetrics {
        fn new() -> Self {
            Self {
                reload_success: AtomicU32::new(0),
                reload_failure: AtomicU32::new(0),
            }
        }
    }

    impl PacketMetrics for TestMetrics {}
    impl FirewallMetrics for TestMetrics {}
    impl AlertMetrics for TestMetrics {}
    impl IpsMetrics for TestMetrics {}
    impl DnsMetrics for TestMetrics {}
    impl DomainMetrics for TestMetrics {}
    impl SystemMetrics for TestMetrics {}
    impl ConfigMetrics for TestMetrics {
        fn record_config_reload(&self, _: &str, result: &str) {
            if result == "success" {
                self.reload_success.fetch_add(1, Ordering::Relaxed);
            } else {
                self.reload_failure.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    impl EventMetrics for TestMetrics {}
    impl DlpMetrics for TestMetrics {}
    impl DdosMetrics for TestMetrics {}
    impl ConntrackMetrics for TestMetrics {}
    impl RoutingMetrics for TestMetrics {}
    impl AuditMetrics for TestMetrics {}
    impl LbMetrics for TestMetrics {}
    impl FingerprintMetrics for TestMetrics {}

    fn make_feed(id: &str, enabled: bool) -> FeedConfig {
        FeedConfig {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.com/{id}"),
            format: FeedFormat::Plaintext,
            enabled,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            default_action: None,
            min_confidence: 0,
            field_mapping: None,
            auth_header: None,
        }
    }

    #[tokio::test]
    async fn fetch_all_with_valid_data() {
        let source = MockSource {
            response: b"1.2.3.4\n5.6.7.8\n".to_vec(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        let feeds = vec![make_feed("feed-a", true)];

        let iocs =
            fetch_all_feeds(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        assert_eq!(iocs.len(), 2);
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fetch_skips_disabled_feeds() {
        let source = MockSource {
            response: b"1.2.3.4\n".to_vec(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        let feeds = vec![make_feed("feed-a", false)];

        let iocs =
            fetch_all_feeds(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        assert!(iocs.is_empty());
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn fetch_handles_failure_gracefully() {
        let source = MockSource {
            response: vec![],
            fail: true,
        };
        let metrics = Arc::new(TestMetrics::new());
        let feeds = vec![make_feed("bad-feed", true)];

        let iocs =
            fetch_all_feeds(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        assert!(iocs.is_empty());
        assert_eq!(metrics.reload_failure.load(Ordering::Relaxed), 1);
    }

    // ── Helper: make a JSON feed config ────────────────────────────────

    fn make_json_feed(
        id: &str,
        field_mapping: Option<domain::threatintel::entity::FieldMapping>,
    ) -> FeedConfig {
        FeedConfig {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.com/{id}"),
            format: FeedFormat::Json,
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            default_action: None,
            min_confidence: 0,
            field_mapping,
            auth_header: None,
        }
    }

    fn make_csv_feed(id: &str) -> FeedConfig {
        FeedConfig {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.com/{id}"),
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

    // ── JSON feed parsing ──────────────────────────────────────────────

    #[tokio::test]
    async fn json_feed_parses_valid_array() {
        let json = r#"[{"ip":"10.0.0.1"},{"ip":"10.0.0.2"}]"#;
        let source = MockSource {
            response: json.as_bytes().to_vec(),
            fail: false,
        };
        let feed = make_json_feed("json-1", None);
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(iocs[1].ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn json_feed_skips_invalid_ips() {
        let json = r#"[{"ip":"10.0.0.1"},{"ip":"not-an-ip"},{"ip":"192.168.1.1"}]"#;
        let source = MockSource {
            response: json.as_bytes().to_vec(),
            fail: false,
        };
        let feed = make_json_feed("json-2", None);
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(iocs[1].ip, "192.168.1.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn json_feed_extracts_confidence_and_type() {
        use domain::threatintel::entity::FieldMapping;

        let json = r#"[{"addr":"1.2.3.4","score":75,"cat":"malware"}]"#;
        let mapping = FieldMapping {
            ip_field: "addr".to_string(),
            confidence_field: Some("score".to_string()),
            category_field: Some("cat".to_string()),
            ..Default::default()
        };
        let source = MockSource {
            response: json.as_bytes().to_vec(),
            fail: false,
        };
        let feed = make_json_feed("json-3", Some(mapping));
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].confidence, 75);
        assert_eq!(iocs[0].threat_type, ThreatType::Malware);
    }

    #[tokio::test]
    async fn json_feed_rejects_non_array() {
        let json = r#"{"ip":"1.2.3.4"}"#;
        let source = MockSource {
            response: json.as_bytes().to_vec(),
            fail: false,
        };
        let feed = make_json_feed("json-4", None);
        let result = fetch_single_feed(&feed, &source).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("top-level array"), "error was: {err_msg}");
    }

    #[tokio::test]
    async fn json_feed_empty_array() {
        let json = r"[]";
        let source = MockSource {
            response: json.as_bytes().to_vec(),
            fail: false,
        };
        let feed = make_json_feed("json-5", None);
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert!(iocs.is_empty());
    }

    // ── Multiple feeds ─────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_all_partial_success() {
        // We need two feeds but MockSource is shared. The first feed will
        // succeed, the second will use the same source — but since MockSource
        // cannot vary per feed, we test partial success by using one enabled
        // feed that returns data and one that triggers failure.
        //
        // Strategy: use a successful source for fetch_all_feeds with 2 feeds,
        // but make one disabled and create a separate call. Instead, let's
        // test via two calls and merge — but actually the simplest approach
        // is to accept the MockSource limitation and test the metrics path.
        //
        // Better: we can test partial success by having the source succeed
        // but one feed's data be unparseable (e.g. JSON format with plaintext data).
        let source = MockSource {
            response: b"1.2.3.4\n5.6.7.8\n".to_vec(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        // Feed 1: Plaintext format — will parse the plaintext response fine
        let mut feed1 = make_feed("good-feed", true);
        feed1.format = FeedFormat::Plaintext;
        // Feed 2: JSON format — the plaintext data is not valid JSON → parse error
        let mut feed2 = make_feed("bad-json-feed", true);
        feed2.format = FeedFormat::Json;

        let iocs = fetch_all_feeds(
            &[feed1, feed2],
            &source,
            &(metrics.clone() as Arc<dyn MetricsPort>),
        )
        .await;

        assert_eq!(iocs.len(), 2); // only from the successful feed
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.reload_failure.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fetch_all_empty_feeds_list() {
        let source = MockSource {
            response: b"1.2.3.4\n".to_vec(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        let feeds: Vec<FeedConfig> = vec![];

        let iocs =
            fetch_all_feeds(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        assert!(iocs.is_empty());
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.reload_failure.load(Ordering::Relaxed), 0);
    }

    // ── Feed format via fetch_single_feed ──────────────────────────────

    #[tokio::test]
    async fn csv_feed_parses_correctly() {
        let csv_data = b"10.0.0.1\n10.0.0.2\n10.0.0.3\n";
        let source = MockSource {
            response: csv_data.to_vec(),
            fail: false,
        };
        let feed = make_csv_feed("csv-1");
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert_eq!(iocs.len(), 3);
        assert_eq!(iocs[0].ip, "10.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(iocs[2].ip, "10.0.0.3".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn plaintext_feed_with_comments() {
        use domain::threatintel::entity::FieldMapping;

        let data = b"# This is a comment\n1.1.1.1\n# Another comment\n2.2.2.2\n";
        let source = MockSource {
            response: data.to_vec(),
            fail: false,
        };
        let mut feed = make_feed("plaintext-comments", true);
        feed.field_mapping = Some(FieldMapping {
            comment_prefix: Some("#".to_string()),
            ..Default::default()
        });
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].ip, "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(iocs[1].ip, "2.2.2.2".parse::<IpAddr>().unwrap());
    }

    // ── Edge cases ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_empty_response() {
        let source = MockSource {
            response: Vec::new(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        let feeds = vec![make_feed("empty-feed", true)];

        let iocs =
            fetch_all_feeds(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        assert!(iocs.is_empty());
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn feed_id_propagated_to_iocs() {
        let json = r#"[{"ip":"8.8.8.8"},{"ip":"8.8.4.4"}]"#;
        let source = MockSource {
            response: json.as_bytes().to_vec(),
            fail: false,
        };
        let feed = make_json_feed("my-custom-feed", None);
        let iocs = fetch_single_feed(&feed, &source).await.unwrap();
        assert_eq!(iocs.len(), 2);
        for ioc in &iocs {
            assert_eq!(ioc.feed_id, "my-custom-feed");
            assert_eq!(ioc.source_feed, "my-custom-feed");
        }
    }

    // ── STIX 2.1 parsing ──────────────────────────────────────────────

    fn make_stix_feed(id: &str) -> FeedConfig {
        FeedConfig {
            id: id.to_string(),
            name: id.to_string(),
            url: format!("https://example.com/{id}"),
            format: FeedFormat::Stix,
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            default_action: None,
            min_confidence: 0,
            field_mapping: None,
            auth_header: None,
        }
    }

    const STIX_BUNDLE: &str = r#"{
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '198.51.100.1']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z",
                "confidence": 85,
                "indicator_types": ["malicious-activity"]
            },
            {
                "type": "indicator",
                "id": "indicator--2",
                "pattern": "[domain-name:value = 'evil.example.com']",
                "pattern_type": "stix",
                "valid_from": "2024-06-01T00:00:00Z",
                "confidence": 70,
                "indicator_types": ["command-and-control"]
            },
            {
                "type": "indicator",
                "id": "indicator--3",
                "pattern": "[url:value = 'http://malware.test/payload.exe']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z",
                "confidence": 90
            },
            {
                "type": "indicator",
                "id": "indicator--expired",
                "pattern": "[ipv4-addr:value = '203.0.113.50']",
                "pattern_type": "stix",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_until": "2020-06-01T00:00:00Z"
            },
            {
                "type": "malware",
                "id": "malware--1",
                "name": "EvilBot"
            },
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "indicates",
                "source_ref": "indicator--1",
                "target_ref": "malware--1"
            },
            {
                "type": "ipv4-addr",
                "id": "ipv4-addr--1",
                "value": "192.0.2.42"
            },
            {
                "type": "domain-name",
                "id": "domain-name--1",
                "value": "phishing.example.org"
            },
            {
                "type": "ipv6-addr",
                "id": "ipv6-addr--1",
                "value": "2001:db8::dead:beef"
            }
        ]
    }"#;

    #[test]
    fn stix_json_extracts_indicator_ips() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let ips: Vec<_> = result.iocs.iter().map(|i| i.ip.to_string()).collect();
        assert!(ips.contains(&"198.51.100.1".to_string()));
    }

    #[test]
    fn stix_json_extracts_indicator_domains() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let domains: Vec<_> = result.domains.iter().map(|d| d.domain.as_str()).collect();
        assert!(domains.contains(&"evil.example.com"));
    }

    #[test]
    fn stix_json_extracts_indicator_urls() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let urls: Vec<_> = result.urls.iter().map(|u| u.url.as_str()).collect();
        assert!(urls.contains(&"http://malware.test/payload.exe"));
    }

    #[test]
    fn stix_json_filters_expired_indicators() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let ips: Vec<_> = result.iocs.iter().map(|i| i.ip.to_string()).collect();
        assert!(!ips.contains(&"203.0.113.50".to_string()));
    }

    #[test]
    fn stix_json_extracts_sco_ips() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let ips: Vec<_> = result.iocs.iter().map(|i| i.ip.to_string()).collect();
        assert!(ips.contains(&"192.0.2.42".to_string()));
        assert!(ips.contains(&"2001:db8::dead:beef".to_string()));
    }

    #[test]
    fn stix_json_sco_confidence_is_50() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let sco = result
            .iocs
            .iter()
            .find(|i| i.ip.to_string() == "192.0.2.42")
            .unwrap();
        assert_eq!(sco.confidence, 50);
    }

    #[test]
    fn stix_json_extracts_sco_domains() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let domains: Vec<_> = result.domains.iter().map(|d| d.domain.as_str()).collect();
        assert!(domains.contains(&"phishing.example.org"));
    }

    #[test]
    fn stix_json_relationship_enrichment() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let ind1 = result
            .iocs
            .iter()
            .find(|i| i.ip.to_string() == "198.51.100.1")
            .unwrap();
        // indicator--1 has relationship to malware--1 → Malware
        assert_eq!(ind1.threat_type, ThreatType::Malware);
    }

    #[test]
    fn stix_json_indicator_types_mapping() {
        let feed = make_stix_feed("stix-1");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        let c2_domain = result
            .domains
            .iter()
            .find(|d| d.domain == "evil.example.com")
            .unwrap();
        assert_eq!(c2_domain.threat_type, ThreatType::C2);
        assert_eq!(c2_domain.confidence, 70);
    }

    #[test]
    fn stix_json_source_tag_set() {
        let feed = make_stix_feed("my-stix-feed");
        let result = parse_stix_json(STIX_BUNDLE, &feed).unwrap();
        for domain in &result.domains {
            assert_eq!(domain.source.as_deref(), Some("stix:my-stix-feed"));
        }
    }

    #[test]
    fn stix_json_rejects_non_bundle() {
        let feed = make_stix_feed("stix-bad");
        let result = parse_stix_json(r#"{"type": "indicator"}"#, &feed);
        assert!(result.is_err());
    }

    #[test]
    fn stix_json_empty_objects() {
        let feed = make_stix_feed("stix-empty");
        let result = parse_stix_json(r#"{"type": "bundle", "objects": []}"#, &feed).unwrap();
        assert!(result.iocs.is_empty());
        assert!(result.domains.is_empty());
        assert!(result.urls.is_empty());
    }

    #[test]
    fn stix_json_no_objects_key() {
        let feed = make_stix_feed("stix-no-obj");
        let result = parse_stix_json(r#"{"type": "bundle"}"#, &feed).unwrap();
        assert!(result.iocs.is_empty());
    }

    #[test]
    fn stix_json_confidence_default_100() {
        let bundle = r#"{"type": "bundle", "objects": [
            {"type": "indicator", "id": "indicator--x",
             "pattern": "[ipv4-addr:value = '10.0.0.1']",
             "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z"}
        ]}"#;
        let feed = make_stix_feed("stix-conf");
        let result = parse_stix_json(bundle, &feed).unwrap();
        assert_eq!(result.iocs[0].confidence, 100);
    }

    #[test]
    fn stix_json_confidence_clamped() {
        let bundle = r#"{"type": "bundle", "objects": [
            {"type": "indicator", "id": "indicator--x",
             "pattern": "[ipv4-addr:value = '10.0.0.1']",
             "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z",
             "confidence": 150}
        ]}"#;
        let feed = make_stix_feed("stix-clamp");
        let result = parse_stix_json(bundle, &feed).unwrap();
        assert_eq!(result.iocs[0].confidence, 100);
    }

    #[tokio::test]
    async fn fetch_all_v2_stix_feed() {
        let source = MockSource {
            response: STIX_BUNDLE.as_bytes().to_vec(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        let feeds = vec![make_stix_feed("stix-v2")];

        let result =
            fetch_all_feeds_v2(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        assert!(!result.iocs.is_empty());
        assert!(!result.domains.is_empty());
        assert!(!result.urls.is_empty());
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fetch_all_v2_mixed_feeds() {
        let source = MockSource {
            response: STIX_BUNDLE.as_bytes().to_vec(),
            fail: false,
        };
        let metrics = Arc::new(TestMetrics::new());
        // STIX feed will parse OK, plaintext will fail (STIX JSON is not plaintext IPs)
        let feeds = vec![make_stix_feed("stix-feed"), {
            let mut f = make_feed("plain-feed", true);
            f.format = FeedFormat::Plaintext;
            f
        }];

        let result =
            fetch_all_feeds_v2(&feeds, &source, &(metrics.clone() as Arc<dyn MetricsPort>)).await;

        // STIX feed succeeds, plaintext parses the STIX JSON as text (0 IPs from garbage lines)
        assert!(!result.iocs.is_empty()); // from STIX
        assert!(!result.domains.is_empty()); // from STIX
        assert_eq!(metrics.reload_success.load(Ordering::Relaxed), 2);
    }

    // ── ISO 8601 parsing ──────────────────────────────────────────────

    #[test]
    fn iso8601_basic() {
        assert_eq!(
            parse_iso8601_epoch_secs("2024-01-01T00:00:00Z"),
            Some(1704067200)
        );
    }

    #[test]
    fn iso8601_with_fractional() {
        assert_eq!(
            parse_iso8601_epoch_secs("2024-01-01T00:00:00.000Z"),
            Some(1704067200)
        );
    }

    #[test]
    fn iso8601_invalid() {
        assert!(parse_iso8601_epoch_secs("not-a-date").is_none());
    }

    // ── L7 rule builder (v2) ──────────────────────────────────────────

    #[test]
    fn build_l7_rule_http_url() {
        let url = CtiUrl {
            url: "http://evil.com/malware.exe".to_string(),
            feed_id: "stix-feed".to_string(),
            confidence: 90,
            threat_type: ThreatType::Malware,
            source: Some("stix:stix-feed".to_string()),
        };
        let rule = build_l7_rule_from_url(&url, 1000).unwrap();
        assert!(rule.id.0.starts_with("stix-"));
        assert!(rule.enabled);
        match &rule.matcher {
            domain::l7::entity::L7Matcher::Http {
                path_pattern,
                host_pattern,
                ..
            } => {
                assert_eq!(path_pattern.as_deref(), Some("/malware.exe"));
                assert!(host_pattern.is_some());
            }
            _ => panic!("expected HTTP matcher"),
        }
    }

    #[test]
    fn build_l7_rule_https_url() {
        let url = CtiUrl {
            url: "https://phishing.test/login".to_string(),
            feed_id: "f1".to_string(),
            confidence: 80,
            threat_type: ThreatType::C2,
            source: None,
        };
        let rule = build_l7_rule_from_url(&url, 500).unwrap();
        assert_eq!(rule.priority, 500);
    }

    #[test]
    fn build_l7_rule_no_path() {
        let url = CtiUrl {
            url: "http://evil.com".to_string(),
            feed_id: "f1".to_string(),
            confidence: 80,
            threat_type: ThreatType::Other,
            source: None,
        };
        let rule = build_l7_rule_from_url(&url, 100).unwrap();
        match &rule.matcher {
            domain::l7::entity::L7Matcher::Http { path_pattern, .. } => {
                assert!(path_pattern.is_none());
            }
            _ => panic!("expected HTTP matcher"),
        }
    }

    #[test]
    fn build_l7_rule_invalid_url_returns_none() {
        let url = CtiUrl {
            url: "not-a-url".to_string(),
            feed_id: "f1".to_string(),
            confidence: 80,
            threat_type: ThreatType::Other,
            source: None,
        };
        assert!(build_l7_rule_from_url(&url, 100).is_none());
    }
}
