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
        AlertMetrics, ConfigMetrics, DnsMetrics, DomainMetrics, EventMetrics, FirewallMetrics,
        IpsMetrics, PacketMetrics, SystemMetrics,
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
}
