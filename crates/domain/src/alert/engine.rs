use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use super::entity::{Alert, AlertRoute};

/// Why an alert did or did not reach its destinations.
///
/// Dedup and throttle are *delivery* controls: they decide whether an alert is
/// handed to the senders, never whether it is recorded. Callers persist, stream
/// and count the alert before consulting the router, so an alert suppressed
/// here is still in the store and on the event stream. Keeping the two
/// suppressions distinct from an empty route list is what lets the caller name
/// the real reason instead of reporting every non-delivery as "no route".
#[derive(Debug)]
pub enum AlertDecision<'a> {
    /// An identical alert was seen within the dedup window.
    Deduplicated,
    /// The rule exceeded its budget for the throttle window.
    Throttled,
    /// The alert passed both gates; the routes it matched (possibly none).
    Routed(Vec<(usize, &'a AlertRoute)>),
}

impl<'a> AlertDecision<'a> {
    /// Routes to deliver to — empty when the alert was suppressed or matched nothing.
    pub fn routes(&self) -> &[(usize, &'a AlertRoute)] {
        match self {
            Self::Deduplicated | Self::Throttled => &[],
            Self::Routed(routes) => routes,
        }
    }

    /// Label for the drop metric, or `None` when the alert is being delivered.
    pub fn drop_reason(&self) -> Option<&'static str> {
        match self {
            Self::Deduplicated => Some("dedup"),
            Self::Throttled => Some("throttle"),
            Self::Routed(routes) if routes.is_empty() => Some("no_route"),
            Self::Routed(_) => None,
        }
    }
}

/// Alert router with deduplication, throttling, and severity/type route matching.
///
/// Processing pipeline: dedup check → throttle check → route matching.
#[derive(Debug)]
pub struct AlertRouter {
    routes: Vec<AlertRoute>,
    dedup_window: Duration,
    throttle_window: Duration,
    throttle_max: usize,
    recent_hashes: VecDeque<(u64, Instant)>,
    throttle_counts: HashMap<String, (usize, Instant)>,
}

impl AlertRouter {
    pub fn new(
        routes: Vec<AlertRoute>,
        dedup_window: Duration,
        throttle_window: Duration,
        throttle_max: usize,
    ) -> Self {
        Self {
            routes,
            dedup_window,
            throttle_window,
            throttle_max,
            recent_hashes: VecDeque::new(),
            throttle_counts: HashMap::new(),
        }
    }

    /// Process an alert through dedup → throttle → route matching.
    pub fn process_alert(&mut self, alert: &Alert) -> AlertDecision<'_> {
        let now = Instant::now();

        // 1. Deduplication check
        let hash = Self::dedup_key(alert);
        self.expire_dedup(now);
        if self.is_duplicate(hash) {
            return AlertDecision::Deduplicated;
        }
        self.recent_hashes.push_back((hash, now));

        // 2. Throttle check
        let throttle_key = alert.rule_id.0.clone();
        self.expire_throttle(now);
        if self.is_throttled(&throttle_key, now) {
            return AlertDecision::Throttled;
        }

        // 3. Route matching
        AlertDecision::Routed(
            self.routes
                .iter()
                .enumerate()
                .filter(|(_, route)| Self::matches_route(alert, route))
                .collect(),
        )
    }

    /// Compute a dedup key by hashing (`rule_id`, `src_ip()`, `dst_ip()`, `dst_port`, protocol).
    fn dedup_key(alert: &Alert) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        alert.rule_id.0.hash(&mut hasher);
        alert.src_ip().hash(&mut hasher);
        alert.dst_ip().hash(&mut hasher);
        alert.dst_port.hash(&mut hasher);
        alert.protocol.hash(&mut hasher);
        hasher.finish()
    }

    /// Check if a route matches an alert by severity and event type.
    fn matches_route(alert: &Alert, route: &AlertRoute) -> bool {
        // Severity check: alert severity must be >= route min_severity
        if alert.severity.to_u8() < route.min_severity.to_u8() {
            return false;
        }

        // Event type filter: if set, alert component must be in the list
        if let Some(ref types) = route.event_types
            && !types.iter().any(|t| t == &alert.component)
        {
            return false;
        }

        true
    }

    /// Hot-reload routes without resetting dedup/throttle state.
    pub fn reload_routes(&mut self, routes: Vec<AlertRoute>) {
        self.routes = routes;
    }

    fn expire_dedup(&mut self, now: Instant) {
        while let Some(&(_, ts)) = self.recent_hashes.front() {
            if now.duration_since(ts) > self.dedup_window {
                self.recent_hashes.pop_front();
            } else {
                break;
            }
        }
    }

    fn is_duplicate(&self, hash: u64) -> bool {
        self.recent_hashes.iter().any(|&(h, _)| h == hash)
    }

    fn expire_throttle(&mut self, now: Instant) {
        self.throttle_counts
            .retain(|_, (_, ts)| now.duration_since(*ts) <= self.throttle_window);
    }

    fn is_throttled(&mut self, key: &str, now: Instant) -> bool {
        let entry = self
            .throttle_counts
            .entry(key.to_string())
            .or_insert((0, now));
        entry.0 += 1;
        entry.0 > self.throttle_max
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::common::entity::{DomainMode, RuleId, Severity};

    use super::super::entity::AlertDestination;

    fn make_alert(rule_id: &str, severity: Severity) -> Alert {
        Alert {
            id: format!("test-{rule_id}"),
            timestamp_ns: 1_000_000_000,
            component: "ids".to_string(),
            severity,
            rule_id: RuleId(rule_id.to_string()),
            action: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            is_ipv6: false,
            message: "test alert".to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: None,
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
        }
    }

    fn make_route(name: &str, min_severity: Severity) -> AlertRoute {
        AlertRoute {
            name: name.to_string(),
            destination: AlertDestination::Log,
            min_severity,
            event_types: None,
        }
    }

    fn make_route_with_types(name: &str, min_severity: Severity, types: Vec<String>) -> AlertRoute {
        AlertRoute {
            name: name.to_string(),
            destination: AlertDestination::Log,
            min_severity,
            event_types: Some(types),
        }
    }

    fn make_router(routes: Vec<AlertRoute>) -> AlertRouter {
        AlertRouter::new(routes, Duration::from_mins(1), Duration::from_mins(5), 100)
    }

    #[test]
    fn dedup_within_window_suppresses_duplicate() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router = make_router(routes);
        let alert = make_alert("ids-001", Severity::High);

        let first = router.process_alert(&alert);
        assert_eq!(first.routes().len(), 1);

        let second = router.process_alert(&alert);
        assert!(second.routes().is_empty(), "duplicate should be suppressed");
    }

    #[test]
    fn dedup_expired_allows_same_alert() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_millis(0), // instant expiry
            Duration::from_mins(5),
            100,
        );
        let alert = make_alert("ids-001", Severity::High);

        let first = router.process_alert(&alert);
        assert_eq!(first.routes().len(), 1);

        // After expiry window (0ms), dedup should allow
        let second = router.process_alert(&alert);
        assert_eq!(second.routes().len(), 1);
    }

    #[test]
    fn suppression_reasons_are_distinct() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router =
            AlertRouter::new(routes, Duration::from_mins(1), Duration::from_mins(5), 1);
        let alert = make_alert("ids-001", Severity::High);

        assert_eq!(router.process_alert(&alert).drop_reason(), None);
        assert_eq!(
            router.process_alert(&alert).drop_reason(),
            Some("dedup"),
            "the identical alert is a duplicate, not a throttle victim"
        );

        // A different flow clears dedup but exhausts the per-rule budget.
        let mut other = make_alert("ids-001", Severity::High);
        other.src_addr[0] = 0xC0A8_0002;
        assert_eq!(router.process_alert(&other).drop_reason(), Some("throttle"));

        // An alert nothing routes to is neither of the two.
        let mut router = AlertRouter::new(
            vec![make_route("critical-only", Severity::Critical)],
            Duration::from_mins(1),
            Duration::from_mins(5),
            100,
        );
        assert_eq!(
            router
                .process_alert(&make_alert("ids-002", Severity::Low))
                .drop_reason(),
            Some("no_route")
        );
    }

    #[test]
    fn throttle_within_limit_allows() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 3);

        // Different src_ip to avoid dedup
        for i in 0..3 {
            let mut alert = make_alert("ids-001", Severity::High);
            alert.src_addr[0] = i;
            let result = router.process_alert(&alert);
            assert_eq!(result.routes().len(), 1, "alert {i} should pass throttle");
        }
    }

    #[test]
    fn throttle_exceeded_suppresses() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 2);

        for i in 0..2 {
            let mut alert = make_alert("ids-001", Severity::High);
            alert.src_addr[0] = i;
            let result = router.process_alert(&alert);
            assert_eq!(result.routes().len(), 1);
        }

        // Third alert should be throttled
        let mut alert = make_alert("ids-001", Severity::High);
        alert.src_addr[0] = 999;
        let result = router.process_alert(&alert);
        assert!(result.routes().is_empty(), "should be throttled");
    }

    #[test]
    fn route_severity_filter_high_only() {
        let routes = vec![make_route("high-only", Severity::High)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 100);

        let low = make_alert("ids-low", Severity::Low);
        assert!(router.process_alert(&low).routes().is_empty());

        let high = make_alert("ids-high", Severity::High);
        assert_eq!(router.process_alert(&high).routes().len(), 1);
    }

    #[test]
    fn route_type_filter_ids_only() {
        let routes = vec![make_route_with_types(
            "ids-only",
            Severity::Low,
            vec!["ids".to_string()],
        )];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 100);

        let ids_alert = make_alert("ids-001", Severity::High);
        assert_eq!(router.process_alert(&ids_alert).routes().len(), 1);

        let mut fw_alert = make_alert("fw-001", Severity::High);
        fw_alert.component = "firewall".to_string();
        assert!(router.process_alert(&fw_alert).routes().is_empty());
    }

    #[test]
    fn multiple_routes_matched() {
        let routes = vec![
            make_route("all", Severity::Low),
            make_route("high-only", Severity::High),
        ];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 100);

        let alert = make_alert("ids-001", Severity::High);
        let matches = router.process_alert(&alert);
        assert_eq!(matches.routes().len(), 2);
        assert_eq!(matches.routes()[0].0, 0);
        assert_eq!(matches.routes()[1].0, 1);
    }

    #[test]
    fn no_routes_matched() {
        let routes = vec![make_route("critical-only", Severity::Critical)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 100);

        let alert = make_alert("ids-001", Severity::Low);
        assert!(router.process_alert(&alert).routes().is_empty());
    }

    #[test]
    fn reload_routes_replaces_routes() {
        let routes = vec![make_route("old", Severity::Critical)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 100);

        let alert = make_alert("ids-001", Severity::Low);
        assert!(router.process_alert(&alert).routes().is_empty());

        router.reload_routes(vec![make_route("new", Severity::Low)]);
        let mut alert2 = make_alert("ids-002", Severity::Low);
        alert2.src_addr[0] = 999;
        assert_eq!(router.process_alert(&alert2).routes().len(), 1);
    }

    #[test]
    fn empty_routes_matches_nothing() {
        let mut router =
            AlertRouter::new(vec![], Duration::from_secs(0), Duration::from_mins(5), 100);
        let alert = make_alert("ids-001", Severity::Critical);
        assert!(router.process_alert(&alert).routes().is_empty());
    }

    #[test]
    fn different_alerts_not_deduplicated() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router = make_router(routes);

        let alert1 = make_alert("ids-001", Severity::High);
        let alert2 = make_alert("ids-002", Severity::High);

        assert_eq!(router.process_alert(&alert1).routes().len(), 1);
        assert_eq!(router.process_alert(&alert2).routes().len(), 1);
    }

    #[test]
    fn severity_ordering_in_route_filter() {
        let routes = vec![make_route("medium-up", Severity::Medium)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_mins(5), 100);

        // Low < Medium → filtered out
        let low = make_alert("a", Severity::Low);
        assert!(router.process_alert(&low).routes().is_empty());

        // Medium >= Medium → passes
        let med = make_alert("b", Severity::Medium);
        assert_eq!(router.process_alert(&med).routes().len(), 1);

        // High >= Medium → passes
        let high = make_alert("c", Severity::High);
        assert_eq!(router.process_alert(&high).routes().len(), 1);

        // Critical >= Medium → passes
        let crit = make_alert("d", Severity::Critical);
        assert_eq!(router.process_alert(&crit).routes().len(), 1);
    }

    // Property-based tests
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn dedup_window_prevents_duplicate_alerts(
                rule_id in "[a-z]{3}-[0-9]{3}",
            ) {
                let route = AlertRoute {
                    name: "test".to_string(),
                    destination: AlertDestination::Log,
                    min_severity: Severity::Low,
                    event_types: None,
                };
                let mut router = AlertRouter::new(
                    vec![route],
                    Duration::from_mins(1),
                    Duration::from_mins(5),
                    100,
                );

                let alert = Alert {
                    id: format!("1000-{rule_id}"),
                    timestamp_ns: 1_000_000_000,
                    component: "ids".to_string(),
                    severity: Severity::High,
                    rule_id: RuleId(rule_id.clone()),
                    action: DomainMode::Alert,
                    src_addr: [1, 0, 0, 0],
                    dst_addr: [2, 0, 0, 0],
                    src_port: 12345,
                    dst_port: 80,
                    protocol: 6,
                    is_ipv6: false,
                    message: "test".to_string(),
                    false_positive: false,
                    src_domain: None,
                    dst_domain: None,
                    src_domain_score: None,
                    dst_domain_score: None,
                    src_geo: None,
                    dst_geo: None,
                    confidence: None,
                    threat_type: None,
                    data_type: None,
                    pid: None,
                    tgid: None,
                    direction: None,
                    matched_domain: None,
                    attack_type: None,
                    peak_pps: None,
                    current_pps: None,
                    mitigation_status: None,
                    total_packets: None,
                    mitre_attack: None,
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
                    container_metadata: None,
                };

                // First alert should match routes
                let routes1 = router.process_alert(&alert);
                prop_assert!(!routes1.routes().is_empty(), "first alert should match routes");

                // Same alert immediately should be deduped
                let routes2 = router.process_alert(&alert);
                prop_assert!(routes2.routes().is_empty(), "duplicate alert should be deduped");
            }
        }
    }
}
