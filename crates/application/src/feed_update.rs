use std::net::IpAddr;
use std::sync::Arc;

use domain::common::error::DomainError;
use domain::threatintel::entity::{FeedConfig, Ioc, ThreatType};
use domain::threatintel::parser::{parse_feed, parse_threat_type};
use ports::secondary::feed_source::FeedSource;
use ports::secondary::metrics_port::MetricsPort;

/// Fetch and parse all enabled feeds, returning a merged IOC list.
///
/// Each feed is fetched independently. Failed feeds are logged and skipped
/// (partial success: remaining feeds still load). IOC deduplication is
/// handled downstream by the engine's `reload()`.
pub async fn fetch_all_feeds(
    feeds: &[FeedConfig],
    source: &dyn FeedSource,
    metrics: &Arc<dyn MetricsPort>,
) -> Vec<Ioc> {
    let mut all_iocs = Vec::new();

    for feed in feeds {
        if !feed.enabled {
            continue;
        }

        match fetch_single_feed(feed, source).await {
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
}
