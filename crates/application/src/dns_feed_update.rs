//! Download the configured DNS blocklist feeds and apply them.
//!
//! A feed is a public list of domains, refreshed on its own schedule. Each one
//! owns the patterns it contributed, so a refresh replaces that feed's previous
//! contents instead of accumulating: a domain the publisher dropped stops being
//! blocked, and the domains written in the configuration file are never touched.

use domain::dns::blocklist::{BlocklistFeedFormat, parse_blocklist_feed};
use domain::threatintel::entity::{FeedConfig, FeedFormat};
use ports::secondary::feed_source::FeedSource;

use crate::dns_blocklist_service_impl::DnsBlocklistAppService;

/// One DNS blocklist feed to download.
#[derive(Debug, Clone)]
pub struct DnsFeedSpec {
    /// Feed name, also the source tag its patterns carry.
    pub name: String,
    /// HTTP(S) URL serving the list.
    pub url: String,
    /// How the list is laid out.
    pub format: BlocklistFeedFormat,
}

/// The source tag every pattern of `feed` carries.
///
/// Namespaced so a DNS feed and a threat-intel feed of the same name cannot
/// wipe each other's patterns on refresh.
#[must_use]
pub fn source_tag(feed: &str) -> String {
    format!("dns-feed:{feed}")
}

/// Result of one refresh cycle over every configured feed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DnsFeedRefreshResult {
    /// Feeds fetched and applied.
    pub succeeded: usize,
    /// Feeds that could not be fetched or decoded. Their previous patterns are
    /// kept: a network blip must not silently unblock a list.
    pub failed: usize,
    /// Patterns now held across all feeds that succeeded.
    pub patterns: usize,
}

/// Fetch every feed concurrently and apply each one as it is parsed.
///
/// A failing feed is logged and skipped; the others still load.
pub async fn refresh_dns_blocklist_feeds(
    feeds: &[DnsFeedSpec],
    source: &dyn FeedSource,
    blocklist: &DnsBlocklistAppService,
) -> DnsFeedRefreshResult {
    let fetches = feeds.iter().map(|feed| async move {
        let result = fetch_one(feed, source).await;
        (feed, result)
    });
    let fetched = futures_util::future::join_all(fetches).await;

    let mut result = DnsFeedRefreshResult::default();
    for (feed, domains) in fetched {
        match domains {
            Ok(domains) => {
                let outcome = blocklist.replace_source_patterns(&source_tag(&feed.name), &domains);
                tracing::info!(
                    feed = %feed.name,
                    applied = outcome.applied,
                    skipped = outcome.skipped,
                    previous = outcome.removed,
                    "DNS blocklist feed applied"
                );
                result.succeeded += 1;
                result.patterns += outcome.applied;
            }
            Err(e) => {
                tracing::warn!(
                    feed = %feed.name,
                    error = %e,
                    "DNS blocklist feed refresh failed, keeping the patterns it last provided"
                );
                result.failed += 1;
            }
        }
    }
    result
}

/// Download one feed and parse it into domain strings.
async fn fetch_one(feed: &DnsFeedSpec, source: &dyn FeedSource) -> Result<Vec<String>, String> {
    // The download port speaks the threat-intel feed descriptor. Only the id,
    // url and auth header take part in a fetch; the IOC-shaped fields below are
    // inert here and are set to the values the port treats as "no limit, no
    // filtering".
    let descriptor = FeedConfig {
        id: feed.name.clone(),
        name: feed.name.clone(),
        url: feed.url.clone(),
        format: FeedFormat::Plaintext,
        enabled: true,
        refresh_interval_secs: 3600,
        max_iocs: usize::MAX,
        default_action: None,
        min_confidence: 0,
        field_mapping: None,
        auth_header: None,
    };

    let bytes = source
        .fetch_feed(&descriptor)
        .await
        .map_err(|e| e.to_string())?;
    let body = String::from_utf8(bytes).map_err(|_| "feed body is not valid UTF-8".to_string())?;
    parse_blocklist_feed(&body, feed.format).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use domain::common::error::DomainError;
    use domain::dns::entity::{BlocklistAction, DomainBlocklistConfig, InjectTarget};
    use ports::test_utils::NoopMetrics;

    use super::*;

    struct StaticSource(Vec<(String, Result<String, String>)>);

    impl FeedSource for StaticSource {
        fn fetch_feed<'a>(
            &'a self,
            config: &'a FeedConfig,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DomainError>> + Send + 'a>> {
            let answer = self
                .0
                .iter()
                .find(|(id, _)| *id == config.id)
                .map(|(_, body)| body.clone());
            Box::pin(async move {
                match answer {
                    Some(Ok(body)) => Ok(body.into_bytes()),
                    Some(Err(e)) => Err(DomainError::EngineError(e)),
                    None => Err(DomainError::EngineError("no such feed".to_string())),
                }
            })
        }
    }

    fn service() -> DnsBlocklistAppService {
        DnsBlocklistAppService::new(
            DomainBlocklistConfig {
                patterns: Vec::new(),
                action: BlocklistAction::Block,
                inject_target: InjectTarget::ThreatIntel,
                grace_period_secs: 300,
            },
            None,
            Arc::new(NoopMetrics),
        )
    }

    fn spec(name: &str, format: BlocklistFeedFormat) -> DnsFeedSpec {
        DnsFeedSpec {
            name: name.to_string(),
            url: format!("https://example.test/{name}"),
            format,
        }
    }

    fn patterns(svc: &DnsBlocklistAppService) -> Vec<String> {
        let mut names: Vec<String> = svc
            .list_patterns_with_counts()
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        names.sort();
        names
    }

    #[tokio::test]
    async fn a_hosts_feed_becomes_blocklist_patterns() {
        let svc = service();
        let source = StaticSource(vec![(
            "ads".to_string(),
            Ok("# comment\n0.0.0.0 ads.example.com\n127.0.0.1 tracker.example.net\n".to_string()),
        )]);

        let result =
            refresh_dns_blocklist_feeds(&[spec("ads", BlocklistFeedFormat::Hosts)], &source, &svc)
                .await;

        assert_eq!(result.succeeded, 1);
        assert_eq!(result.failed, 0);
        assert_eq!(result.patterns, 2);
        assert_eq!(
            patterns(&svc),
            vec![
                "ads.example.com".to_string(),
                "tracker.example.net".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn a_refresh_drops_what_the_publisher_removed() {
        let svc = service();
        let first = StaticSource(vec![(
            "list".to_string(),
            Ok("gone.example.com\nstays.example.com\n".to_string()),
        )]);
        refresh_dns_blocklist_feeds(
            &[spec("list", BlocklistFeedFormat::Plaintext)],
            &first,
            &svc,
        )
        .await;

        let second = StaticSource(vec![(
            "list".to_string(),
            Ok("stays.example.com\n".to_string()),
        )]);
        let result = refresh_dns_blocklist_feeds(
            &[spec("list", BlocklistFeedFormat::Plaintext)],
            &second,
            &svc,
        )
        .await;

        assert_eq!(result.patterns, 1);
        assert_eq!(patterns(&svc), vec!["stays.example.com".to_string()]);
    }

    #[tokio::test]
    async fn a_failing_feed_keeps_the_patterns_it_last_provided() {
        let svc = service();
        let first = StaticSource(vec![(
            "list".to_string(),
            Ok("kept.example.com\n".to_string()),
        )]);
        refresh_dns_blocklist_feeds(
            &[spec("list", BlocklistFeedFormat::Plaintext)],
            &first,
            &svc,
        )
        .await;

        let broken = StaticSource(vec![("list".to_string(), Err("HTTP 503".to_string()))]);
        let result = refresh_dns_blocklist_feeds(
            &[spec("list", BlocklistFeedFormat::Plaintext)],
            &broken,
            &svc,
        )
        .await;

        assert_eq!(result.failed, 1);
        assert_eq!(patterns(&svc), vec!["kept.example.com".to_string()]);
    }

    #[tokio::test]
    async fn a_feed_never_removes_a_pattern_from_the_configuration_file() {
        let svc = service();
        svc.add_pattern("configured.example.com")
            .expect("pattern is valid");
        let source = StaticSource(vec![(
            "list".to_string(),
            Ok("feed.example.com\n".to_string()),
        )]);

        refresh_dns_blocklist_feeds(
            &[spec("list", BlocklistFeedFormat::Plaintext)],
            &source,
            &svc,
        )
        .await;
        let empty = StaticSource(vec![("list".to_string(), Ok(String::new()))]);
        refresh_dns_blocklist_feeds(
            &[spec("list", BlocklistFeedFormat::Plaintext)],
            &empty,
            &svc,
        )
        .await;

        assert_eq!(patterns(&svc), vec!["configured.example.com".to_string()]);
    }

    #[tokio::test]
    async fn two_feeds_do_not_wipe_each_other() {
        let svc = service();
        let source = StaticSource(vec![
            ("a".to_string(), Ok("a.example.com\n".to_string())),
            ("b".to_string(), Ok("b.example.com\n".to_string())),
        ]);

        let result = refresh_dns_blocklist_feeds(
            &[
                spec("a", BlocklistFeedFormat::Plaintext),
                spec("b", BlocklistFeedFormat::Plaintext),
            ],
            &source,
            &svc,
        )
        .await;

        assert_eq!(result.succeeded, 2);
        assert_eq!(
            patterns(&svc),
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }
}
