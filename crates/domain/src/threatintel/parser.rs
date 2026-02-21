use crate::common::error::DomainError;
use crate::threatintel::entity::{FeedConfig, FeedFormat, Ioc, ThreatType};
use std::net::IpAddr;

/// Parse raw feed data into IOCs based on the feed configuration.
///
/// Dispatches to the appropriate format parser (plaintext, CSV, JSON).
/// JSON parsing is handled by the caller-provided `json_parser` function,
/// keeping format-specific serialization concerns out of the domain layer.
/// STIX parsing is deferred to a future story.
pub fn parse_feed(
    data: &[u8],
    config: &FeedConfig,
    json_parser: impl FnOnce(&str, &FeedConfig) -> Result<Vec<Ioc>, DomainError>,
) -> Result<Vec<Ioc>, DomainError> {
    let text = String::from_utf8_lossy(data);

    let raw_iocs = match config.format {
        FeedFormat::Plaintext => parse_plaintext(&text, config),
        FeedFormat::Csv => parse_csv(&text, config),
        FeedFormat::Json => json_parser(&text, config)?,
        FeedFormat::Stix => {
            return Err(DomainError::EngineError(
                "STIX feed parsing not yet implemented".to_string(),
            ));
        }
    };

    // Apply min_confidence filter
    let filtered: Vec<Ioc> = raw_iocs
        .into_iter()
        .filter(|ioc| ioc.confidence >= config.min_confidence)
        .take(config.max_iocs)
        .collect();

    Ok(filtered)
}

/// Parse plaintext feed: one IP per line.
/// Lines starting with `comment_prefix` or empty lines are skipped.
fn parse_plaintext(text: &str, config: &FeedConfig) -> Vec<Ioc> {
    let comment_prefix = config
        .field_mapping
        .as_ref()
        .and_then(|m| m.comment_prefix.as_deref())
        .unwrap_or("#");

    let mut iocs = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(comment_prefix) {
            continue;
        }

        // Take only the first whitespace-separated token (some feeds have trailing comments)
        let token = trimmed.split_whitespace().next().unwrap_or(trimmed);

        // Strip CIDR suffix if present (e.g. "1.2.3.0/24" → skip, we only handle host IPs)
        if token.contains('/') {
            continue;
        }

        if let Ok(ip) = token.parse::<IpAddr>() {
            iocs.push(Ioc {
                ip,
                feed_id: config.id.clone(),
                confidence: 100, // Plaintext feeds have no confidence; assume max
                threat_type: ThreatType::Other,
                last_seen: 0,
                source_feed: config.name.clone(),
            });
        }
        // Silently skip unparseable lines
    }

    iocs
}

/// Parse CSV feed using the field mapping to locate IP, confidence, category.
fn parse_csv(text: &str, config: &FeedConfig) -> Vec<Ioc> {
    let mapping = config.field_mapping.clone().unwrap_or_default();

    let comment_prefix = mapping.comment_prefix.as_deref().unwrap_or("#");
    let sep = mapping.separator;

    let mut lines = text.lines();
    let mut header_indices: Option<HeaderMap> = None;

    // If skip_header or if ip_field looks like a column name, parse header
    if mapping.skip_header
        && let Some(header_line) = lines.next()
    {
        header_indices = Some(parse_header(header_line, sep));
    }

    let mut iocs = Vec::new();

    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(comment_prefix) {
            continue;
        }

        let fields: Vec<&str> = trimmed.split(sep).map(str::trim).collect();

        // Resolve IP field index
        let ip_str = resolve_field(&fields, &mapping.ip_field, header_indices.as_ref());
        let ip_str = match ip_str {
            Some(s) if !s.is_empty() => s,
            _ => continue,
        };

        let ip: IpAddr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => continue,
        };

        // Resolve confidence
        let confidence = mapping
            .confidence_field
            .as_ref()
            .and_then(|cf| resolve_field(&fields, cf, header_indices.as_ref()))
            .and_then(|s| s.parse::<u8>().ok())
            .unwrap_or(100);

        // Resolve category → ThreatType
        let threat_type = mapping
            .category_field
            .as_ref()
            .and_then(|cf| resolve_field(&fields, cf, header_indices.as_ref()))
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

    iocs
}

// ── Helpers ─────────────────────────────────────────────────────────

type HeaderMap = std::collections::HashMap<String, usize>;

fn parse_header(line: &str, sep: char) -> HeaderMap {
    line.split(sep)
        .enumerate()
        .map(|(i, h)| (h.trim().to_lowercase(), i))
        .collect()
}

/// Resolve a field by name (from header map) or by numeric index.
fn resolve_field<'a>(
    fields: &[&'a str],
    field_name: &str,
    header: Option<&HeaderMap>,
) -> Option<&'a str> {
    // First try numeric index
    if let Ok(idx) = field_name.parse::<usize>() {
        return fields.get(idx).copied();
    }
    // Then try header lookup
    if let Some(hdr) = header
        && let Some(&idx) = hdr.get(&field_name.to_lowercase())
    {
        return fields.get(idx).copied();
    }
    // Fallback: try first field if field_name is "ip" (default)
    if field_name == "ip" {
        return fields.first().copied();
    }
    None
}

pub fn parse_threat_type(s: &str) -> ThreatType {
    match s.to_lowercase().as_str() {
        "malware" | "mal" => ThreatType::Malware,
        "c2" | "c&c" | "command-and-control" | "botnet" => ThreatType::C2,
        "scanner" | "scan" | "scanning" => ThreatType::Scanner,
        "spam" | "spammer" => ThreatType::Spam,
        _ => ThreatType::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threatintel::entity::{FeedFormat, FieldMapping};

    /// JSON parser for tests (uses `serde_json` dev-dependency).
    fn test_json_parser(text: &str, config: &FeedConfig) -> Result<Vec<Ioc>, DomainError> {
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

    /// Dummy JSON parser for tests that don't exercise JSON paths.
    fn no_json(_: &str, _: &FeedConfig) -> Result<Vec<Ioc>, DomainError> {
        Err(DomainError::EngineError("unexpected JSON call".into()))
    }

    fn plaintext_config() -> FeedConfig {
        FeedConfig {
            id: "test".to_string(),
            name: "Test Feed".to_string(),
            url: "https://example.com".to_string(),
            format: FeedFormat::Plaintext,
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            default_action: None,
            min_confidence: 0,
            field_mapping: None,
            auth_header: None,
        }
    }

    fn csv_config() -> FeedConfig {
        FeedConfig {
            format: FeedFormat::Csv,
            field_mapping: Some(FieldMapping {
                ip_field: "ip".to_string(),
                confidence_field: Some("score".to_string()),
                category_field: Some("category".to_string()),
                separator: ',',
                comment_prefix: Some("#".to_string()),
                skip_header: true,
            }),
            ..plaintext_config()
        }
    }

    fn json_config() -> FeedConfig {
        FeedConfig {
            format: FeedFormat::Json,
            field_mapping: Some(FieldMapping {
                ip_field: "ip_address".to_string(),
                confidence_field: Some("confidence".to_string()),
                category_field: Some("type".to_string()),
                ..FieldMapping::default()
            }),
            ..plaintext_config()
        }
    }

    // ── Plaintext tests ─────────────────────────────────────────────

    #[test]
    fn plaintext_basic() {
        let data = b"1.2.3.4\n5.6.7.8\n";
        let iocs = parse_feed(data, &plaintext_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(iocs[1].ip, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn plaintext_skips_comments_and_blank() {
        let data = b"# Comment\n1.2.3.4\n\n# Another\n5.6.7.8\n";
        let iocs = parse_feed(data, &plaintext_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn plaintext_skips_cidr() {
        let data = b"1.2.3.0/24\n5.6.7.8\n";
        let iocs = parse_feed(data, &plaintext_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].ip, "5.6.7.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn plaintext_skips_invalid_lines() {
        let data = b"1.2.3.4\nnot-an-ip\n5.6.7.8\n";
        let iocs = parse_feed(data, &plaintext_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn plaintext_custom_comment_prefix() {
        let mut config = plaintext_config();
        config.field_mapping = Some(FieldMapping {
            comment_prefix: Some(";".to_string()),
            ..FieldMapping::default()
        });
        let data = b"; Spamhaus DROP\n1.2.3.4\n";
        let iocs = parse_feed(data, &config, test_json_parser).unwrap();
        assert_eq!(iocs.len(), 1);
    }

    #[test]
    fn plaintext_trailing_text() {
        let data = b"1.2.3.4 ; malware host\n5.6.7.8\n";
        let iocs = parse_feed(data, &plaintext_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 2);
    }

    #[test]
    fn plaintext_confidence_is_100() {
        let data = b"1.2.3.4\n";
        let iocs = parse_feed(data, &plaintext_config(), no_json).unwrap();
        assert_eq!(iocs[0].confidence, 100);
    }

    // ── CSV tests ───────────────────────────────────────────────────

    #[test]
    fn csv_with_header() {
        let data = b"ip,score,category\n1.2.3.4,85,malware\n5.6.7.8,60,scanner\n";
        let iocs = parse_feed(data, &csv_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].confidence, 85);
        assert_eq!(iocs[0].threat_type, ThreatType::Malware);
        assert_eq!(iocs[1].confidence, 60);
        assert_eq!(iocs[1].threat_type, ThreatType::Scanner);
    }

    #[test]
    fn csv_skips_comments() {
        let data = b"ip,score,category\n# bad line\n1.2.3.4,80,c2\n";
        let iocs = parse_feed(data, &csv_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 1);
    }

    #[test]
    fn csv_skips_unparseable_ips() {
        let data = b"ip,score,category\nnot-ip,80,malware\n1.2.3.4,90,c2\n";
        let iocs = parse_feed(data, &csv_config(), no_json).unwrap();
        assert_eq!(iocs.len(), 1);
    }

    #[test]
    fn csv_missing_confidence_defaults_100() {
        let mut config = csv_config();
        config.field_mapping.as_mut().unwrap().confidence_field = None;
        let data = b"ip,category\n1.2.3.4,malware\n";
        let iocs = parse_feed(data, &config, test_json_parser).unwrap();
        assert_eq!(iocs[0].confidence, 100);
    }

    // ── JSON tests ──────────────────────────────────────────────────

    #[test]
    fn json_basic_array() {
        let data = br#"[
            {"ip_address": "1.2.3.4", "confidence": 90, "type": "c2"},
            {"ip_address": "5.6.7.8", "confidence": 70, "type": "spam"}
        ]"#;
        let iocs = parse_feed(data, &json_config(), test_json_parser).unwrap();
        assert_eq!(iocs.len(), 2);
        assert_eq!(iocs[0].confidence, 90);
        assert_eq!(iocs[0].threat_type, ThreatType::C2);
        assert_eq!(iocs[1].threat_type, ThreatType::Spam);
    }

    #[test]
    fn json_missing_confidence_defaults_100() {
        let data = br#"[{"ip_address": "1.2.3.4"}]"#;
        let iocs = parse_feed(data, &json_config(), test_json_parser).unwrap();
        assert_eq!(iocs[0].confidence, 100);
    }

    #[test]
    fn json_not_array_fails() {
        let data = br#"{"ip_address": "1.2.3.4"}"#;
        let result = parse_feed(data, &json_config(), test_json_parser);
        assert!(result.is_err());
    }

    #[test]
    fn json_skips_bad_ips() {
        let data = br#"[{"ip_address": "not-an-ip"}, {"ip_address": "1.2.3.4"}]"#;
        let iocs = parse_feed(data, &json_config(), test_json_parser).unwrap();
        assert_eq!(iocs.len(), 1);
    }

    // ── Filter tests ────────────────────────────────────────────────

    #[test]
    fn min_confidence_filter() {
        let mut config = json_config();
        config.min_confidence = 80;
        let data = br#"[
            {"ip_address": "1.2.3.4", "confidence": 90},
            {"ip_address": "5.6.7.8", "confidence": 50}
        ]"#;
        let iocs = parse_feed(data, &config, test_json_parser).unwrap();
        assert_eq!(iocs.len(), 1);
        assert_eq!(iocs[0].ip, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn max_iocs_limit() {
        let mut config = plaintext_config();
        config.max_iocs = 2;
        let data = b"1.1.1.1\n2.2.2.2\n3.3.3.3\n4.4.4.4\n";
        let iocs = parse_feed(data, &config, test_json_parser).unwrap();
        assert_eq!(iocs.len(), 2);
    }

    // ── STIX deferred ───────────────────────────────────────────────

    #[test]
    fn stix_returns_error() {
        let mut config = plaintext_config();
        config.format = FeedFormat::Stix;
        let result = parse_feed(b"", &config, no_json);
        assert!(result.is_err());
    }

    // ── Threat type parsing ─────────────────────────────────────────

    #[test]
    fn threat_type_parsing() {
        assert_eq!(parse_threat_type("malware"), ThreatType::Malware);
        assert_eq!(parse_threat_type("c2"), ThreatType::C2);
        assert_eq!(parse_threat_type("C&C"), ThreatType::C2);
        assert_eq!(parse_threat_type("scanner"), ThreatType::Scanner);
        assert_eq!(parse_threat_type("spam"), ThreatType::Spam);
        assert_eq!(parse_threat_type("unknown"), ThreatType::Other);
    }
}
