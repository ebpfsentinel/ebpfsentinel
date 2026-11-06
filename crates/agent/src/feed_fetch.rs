//! The threat intelligence feed fetcher: the task that reads every configured
//! feed, the CrowdSec local API among them, into the threat intel service on
//! start, on a timer and on demand.
//!
//! Both binaries run it. It lives apart from the boot sequence of either so
//! that the one which builds its own datapath does not end up with the feeds
//! configured, listed and never fetched.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use application::dns_blocklist_service_impl::DnsBlocklistAppService;
use application::threatintel_service_impl::ThreatIntelAppService;
use arc_swap::ArcSwap;
use infrastructure::config::AgentConfig;
use ports::secondary::feed_source::FeedSource;
use ports::secondary::metrics_port::MetricsPort;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// The manual half of the fetcher: what the refresh route holds to ask for a
/// cycle, and the flag telling it a cycle is already fetching.
#[derive(Clone)]
pub struct FeedTrigger {
    pub tx: mpsc::Sender<()>,
    pub in_flight: Arc<AtomicBool>,
}

/// The task half of the fetcher, waiting to be started once the services it
/// writes into exist.
pub struct FeedFetcher {
    rx: mpsc::Receiver<()>,
    in_flight: Arc<AtomicBool>,
}

/// A trigger and the fetcher it reaches, or `None` when threat intel is off or
/// no feed is configured, in which case the refresh route reports the feature
/// off rather than queueing a request nobody reads.
#[must_use]
pub fn channel(config: &AgentConfig) -> Option<(FeedTrigger, FeedFetcher)> {
    if !(config.threatintel.enabled && config.threatintel.has_feeds()) {
        return None;
    }
    let (tx, rx) = mpsc::channel::<()>(4);
    let in_flight = Arc::new(AtomicBool::new(false));
    Some((
        FeedTrigger {
            tx,
            in_flight: Arc::clone(&in_flight),
        },
        FeedFetcher { rx, in_flight },
    ))
}

/// The interval every feed shares: the shortest any enabled feed or the
/// CrowdSec block asked for, never under a minute.
#[must_use]
pub fn refresh_interval_secs(config: &AgentConfig) -> u64 {
    config
        .threatintel
        .feeds
        .iter()
        .filter(|f| f.enabled)
        .map(|f| f.refresh_interval_secs)
        .chain(
            config
                .threatintel
                .crowdsec
                .enabled
                .then_some(config.threatintel.crowdsec.refresh_interval_secs),
        )
        .filter(|s| *s > 0)
        .min()
        .unwrap_or(3600)
        .max(60)
}

/// Raises the shared "a feed cycle is fetching" flag for as long as it is held.
///
/// The manual refresh route reads that flag to refuse a second outbound fetch,
/// so the flag has to fall again however the cycle ends - which is what makes
/// this a guard rather than a pair of stores around the call.
struct FeedCycleGuard(Arc<AtomicBool>);

impl FeedCycleGuard {
    fn claim(flag: &Arc<AtomicBool>) -> Self {
        flag.store(true, Ordering::SeqCst);
        Self(Arc::clone(flag))
    }
}

impl Drop for FeedCycleGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Where one cycle writes: the indicators, the DNS blocklist that receives
/// the domain ones, and the metrics the fetch is counted in.
pub struct FeedSinks {
    pub ti_svc: Arc<ArcSwap<ThreatIntelAppService>>,
    pub dns_blocklist: Option<Arc<DnsBlocklistAppService>>,
    pub metrics: Arc<dyn MetricsPort>,
}

impl FeedFetcher {
    /// Fetch once now, then every `refresh_secs` and on every trigger, until
    /// `cancel` fires or every trigger is dropped.
    pub fn spawn(
        mut self,
        source: Arc<dyn FeedSource>,
        sinks: FeedSinks,
        refresh_secs: u64,
        cancel: CancellationToken,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            {
                let _running = FeedCycleGuard::claim(&self.in_flight);
                run_cycle(&sinks, source.as_ref(), "initial").await;
            }
            let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
            interval.tick().await; // the first tick is immediate, already fetched above
            loop {
                tokio::select! {
                    () = cancel.cancelled() => break,
                    _ = interval.tick() => {
                        let _running = FeedCycleGuard::claim(&self.in_flight);
                        run_cycle(&sinks, source.as_ref(), "periodic").await;
                    }
                    msg = self.rx.recv() => match msg {
                        Some(()) => {
                            info!("manual threat intel feed refresh triggered");
                            // The route already claimed the slot before queueing
                            // this message; claiming again keeps the flag raised
                            // for the whole cycle and releases it on the way out.
                            let _running = FeedCycleGuard::claim(&self.in_flight);
                            run_cycle(&sinks, source.as_ref(), "manual").await;
                        }
                        // All triggers dropped - happens only at shutdown.
                        None => break,
                    },
                }
            }
        })
    }
}

/// One cycle: fetch every enabled feed, reload the indicator set, stamp
/// `last_fetched`, and hand any STIX domain indicator to the DNS blocklist.
async fn run_cycle(sinks: &FeedSinks, source: &dyn FeedSource, phase: &'static str) {
    let feeds = sinks.ti_svc.load().list_feeds().to_vec();
    let result = application::feed_update::fetch_all_feeds_v2(&feeds, source, &sinks.metrics).await;

    let mut svc = (**sinks.ti_svc.load()).clone();
    if !result.iocs.is_empty()
        && let Err(e) = svc.reload_iocs(result.iocs)
    {
        warn!(phase, "feed IOC reload failed: {e}");
    }
    // Retain URL indicators so they surface read-only via the API (the
    // IP-only threat-intel engine has no place for them).
    svc.reload_urls(result.urls);
    // Stamp the fetch time on every cycle, even when no IOCs changed, so the
    // feed status reflects the most recent fetch attempt.
    svc.mark_fetched();
    sinks.ti_svc.store(Arc::new(svc));

    if let Some(bl_svc) = sinks.dns_blocklist.as_ref() {
        for domain in &result.domains {
            let source_tag = domain.source.clone();
            if let Err(e) = bl_svc.add_pattern_with_source(&domain.domain, source_tag) {
                tracing::debug!(domain = %domain.domain, error = %e, "domain blocklist inject skipped");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::error::DomainError;
    use domain::threatintel::engine::ThreatIntelEngine;
    use domain::threatintel::entity::FeedConfig;
    use ports::test_utils::NoopMetrics;
    use std::future::Future;
    use std::net::IpAddr;
    use std::pin::Pin;
    use std::sync::Mutex;

    /// Answers whatever body it currently holds, as a local API would.
    struct LapiStandIn(Mutex<Vec<u8>>);

    impl FeedSource for LapiStandIn {
        fn fetch_feed<'a>(
            &'a self,
            _config: &'a FeedConfig,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, DomainError>> + Send + 'a>> {
            let body = self.0.lock().map(|b| b.clone()).unwrap_or_default();
            Box::pin(async move { Ok(body) })
        }
    }

    fn crowdsec_config() -> AgentConfig {
        let mut config = AgentConfig::from_yaml(
            "agent:\n  interfaces: [lo]\nthreatintel:\n  enabled: true\n  crowdsec:\n    enabled: true\n    lapi_url: http://127.0.0.1:8080\n    bouncer_key: k\n",
        )
        .expect("config parses");
        config.threatintel.crowdsec.refresh_interval_secs = 3600;
        config
    }

    fn sinks(config: &AgentConfig) -> FeedSinks {
        let metrics = Arc::new(NoopMetrics) as Arc<dyn MetricsPort>;
        let svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1024),
            Arc::clone(&metrics),
            config.threatintel_feeds().expect("feeds"),
        );
        FeedSinks {
            ti_svc: Arc::new(ArcSwap::from_pointee(svc)),
            dns_blocklist: None,
            metrics,
        }
    }

    const BAN: &str = r#"[{"id":1,"origin":"crowdsec","scenario":"crowdsecurity/ssh-bf","scope":"Ip","type":"ban","value":"203.0.113.9","duration":"3h"}]"#;

    async fn wait_for(svc: &Arc<ArcSwap<ThreatIntelAppService>>, ip: IpAddr) -> bool {
        for _ in 0..200 {
            if svc.load().lookup(&ip).is_some() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[test]
    fn no_trigger_without_a_feed() {
        let mut config = crowdsec_config();
        config.threatintel.crowdsec.enabled = false;
        assert!(channel(&config).is_none());
        let mut config = crowdsec_config();
        config.threatintel.enabled = false;
        assert!(channel(&config).is_none());
    }

    #[test]
    fn the_crowdsec_interval_counts_and_a_minute_is_the_floor() {
        let mut config = crowdsec_config();
        config.threatintel.crowdsec.refresh_interval_secs = 120;
        assert_eq!(refresh_interval_secs(&config), 120);
        config.threatintel.crowdsec.refresh_interval_secs = 5;
        assert_eq!(refresh_interval_secs(&config), 60);
    }

    #[tokio::test]
    async fn a_ban_is_loaded_at_start_and_a_new_one_on_a_trigger() {
        let config = crowdsec_config();
        let (trigger, fetcher) = channel(&config).expect("crowdsec is a feed");
        let sinks = sinks(&config);
        let ti = Arc::clone(&sinks.ti_svc);
        let source = Arc::new(LapiStandIn(Mutex::new(BAN.as_bytes().to_vec())));
        let cancel = CancellationToken::new();
        let task = fetcher.spawn(
            Arc::clone(&source) as Arc<dyn FeedSource>,
            sinks,
            3600,
            cancel.clone(),
        );

        assert!(wait_for(&ti, "203.0.113.9".parse().expect("ip")).await);

        *source.0.lock().expect("lock") = BAN.replace("203.0.113.9", "203.0.113.10").into_bytes();
        trigger.tx.send(()).await.expect("fetcher listening");
        assert!(wait_for(&ti, "203.0.113.10".parse().expect("ip")).await);

        cancel.cancel();
        task.await.expect("task ends");
        assert!(!trigger.in_flight.load(Ordering::SeqCst));
    }
}
