#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;

use domain::common::error::DomainError;
use domain::threatintel::entity::{FeedConfig, FeedFormat, FieldMapping, Ioc, ThreatType};
use domain::threatintel::parser::{parse_feed, parse_threat_type};

/// Build a minimal `FeedConfig` for the given format.
fn feed_config(format: FeedFormat) -> FeedConfig {
    FeedConfig {
        id: "fuzz".to_string(),
        name: "fuzz-feed".to_string(),
        url: "http://localhost/fuzz".to_string(),
        format,
        enabled: true,
        refresh_interval_secs: 3600,
        max_iocs: 10_000,
        default_action: None,
        min_confidence: 0,
        field_mapping: Some(FieldMapping {
            ip_field: "ip".to_string(),
            confidence_field: Some("confidence".to_string()),
            category_field: Some("category".to_string()),
            separator: ',',
            comment_prefix: Some("#".to_string()),
            skip_header: true,
        }),
        auth_header: None,
    }
}

/// JSON feed parser (mirrors the application-layer implementation).
fn json_parser(text: &str, config: &FeedConfig) -> Result<Vec<Ioc>, DomainError> {
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

fuzz_target!(|data: &[u8]| {
    // Plaintext: one IP per line
    let _ = parse_feed(data, &feed_config(FeedFormat::Plaintext), json_parser);

    // CSV: columnar data with field mapping
    let _ = parse_feed(data, &feed_config(FeedFormat::Csv), json_parser);

    // JSON: structured IOC data
    let _ = parse_feed(data, &feed_config(FeedFormat::Json), json_parser);
});
