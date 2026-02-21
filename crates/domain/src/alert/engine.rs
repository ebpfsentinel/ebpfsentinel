use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::time::{Duration, Instant};

use super::entity::{Alert, AlertRoute};

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
    /// Returns indices and references to matching routes.
    /// Returns empty vec if alert is deduplicated or throttled.
    pub fn process_alert(&mut self, alert: &Alert) -> Vec<(usize, &AlertRoute)> {
        let now = Instant::now();

        // 1. Deduplication check
        let hash = Self::dedup_key(alert);
        self.expire_dedup(now);
        if self.is_duplicate(hash) {
            return Vec::new();
        }
        self.recent_hashes.push_back((hash, now));

        // 2. Throttle check
        let throttle_key = alert.rule_id.0.clone();
        self.expire_throttle(now);
        if self.is_throttled(&throttle_key, now) {
            return Vec::new();
        }

        // 3. Route matching
        self.routes
            .iter()
            .enumerate()
            .filter(|(_, route)| Self::matches_route(alert, route))
            .collect()
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
        AlertRouter::new(
            routes,
            Duration::from_secs(60),
            Duration::from_secs(300),
            100,
        )
    }

    #[test]
    fn dedup_within_window_suppresses_duplicate() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router = make_router(routes);
        let alert = make_alert("ids-001", Severity::High);

        let first = router.process_alert(&alert);
        assert_eq!(first.len(), 1);

        let second = router.process_alert(&alert);
        assert!(second.is_empty(), "duplicate should be suppressed");
    }

    #[test]
    fn dedup_expired_allows_same_alert() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_millis(0), // instant expiry
            Duration::from_secs(300),
            100,
        );
        let alert = make_alert("ids-001", Severity::High);

        let first = router.process_alert(&alert);
        assert_eq!(first.len(), 1);

        // After expiry window (0ms), dedup should allow
        let second = router.process_alert(&alert);
        assert_eq!(second.len(), 1);
    }

    #[test]
    fn throttle_within_limit_allows() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_secs(300), 3);

        // Different src_ip to avoid dedup
        for i in 0..3 {
            let mut alert = make_alert("ids-001", Severity::High);
            alert.src_addr[0] = i;
            let result = router.process_alert(&alert);
            assert_eq!(result.len(), 1, "alert {i} should pass throttle");
        }
    }

    #[test]
    fn throttle_exceeded_suppresses() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router =
            AlertRouter::new(routes, Duration::from_secs(0), Duration::from_secs(300), 2);

        for i in 0..2 {
            let mut alert = make_alert("ids-001", Severity::High);
            alert.src_addr[0] = i;
            let result = router.process_alert(&alert);
            assert_eq!(result.len(), 1);
        }

        // Third alert should be throttled
        let mut alert = make_alert("ids-001", Severity::High);
        alert.src_addr[0] = 999;
        let result = router.process_alert(&alert);
        assert!(result.is_empty(), "should be throttled");
    }

    #[test]
    fn route_severity_filter_high_only() {
        let routes = vec![make_route("high-only", Severity::High)];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );

        let low = make_alert("ids-low", Severity::Low);
        assert!(router.process_alert(&low).is_empty());

        let high = make_alert("ids-high", Severity::High);
        assert_eq!(router.process_alert(&high).len(), 1);
    }

    #[test]
    fn route_type_filter_ids_only() {
        let routes = vec![make_route_with_types(
            "ids-only",
            Severity::Low,
            vec!["ids".to_string()],
        )];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );

        let ids_alert = make_alert("ids-001", Severity::High);
        assert_eq!(router.process_alert(&ids_alert).len(), 1);

        let mut fw_alert = make_alert("fw-001", Severity::High);
        fw_alert.component = "firewall".to_string();
        assert!(router.process_alert(&fw_alert).is_empty());
    }

    #[test]
    fn multiple_routes_matched() {
        let routes = vec![
            make_route("all", Severity::Low),
            make_route("high-only", Severity::High),
        ];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );

        let alert = make_alert("ids-001", Severity::High);
        let matches = router.process_alert(&alert);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].0, 0);
        assert_eq!(matches[1].0, 1);
    }

    #[test]
    fn no_routes_matched() {
        let routes = vec![make_route("critical-only", Severity::Critical)];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );

        let alert = make_alert("ids-001", Severity::Low);
        assert!(router.process_alert(&alert).is_empty());
    }

    #[test]
    fn reload_routes_replaces_routes() {
        let routes = vec![make_route("old", Severity::Critical)];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );

        let alert = make_alert("ids-001", Severity::Low);
        assert!(router.process_alert(&alert).is_empty());

        router.reload_routes(vec![make_route("new", Severity::Low)]);
        let mut alert2 = make_alert("ids-002", Severity::Low);
        alert2.src_addr[0] = 999;
        assert_eq!(router.process_alert(&alert2).len(), 1);
    }

    #[test]
    fn empty_routes_matches_nothing() {
        let mut router = AlertRouter::new(
            vec![],
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );
        let alert = make_alert("ids-001", Severity::Critical);
        assert!(router.process_alert(&alert).is_empty());
    }

    #[test]
    fn different_alerts_not_deduplicated() {
        let routes = vec![make_route("all", Severity::Low)];
        let mut router = make_router(routes);

        let alert1 = make_alert("ids-001", Severity::High);
        let alert2 = make_alert("ids-002", Severity::High);

        assert_eq!(router.process_alert(&alert1).len(), 1);
        assert_eq!(router.process_alert(&alert2).len(), 1);
    }

    #[test]
    fn severity_ordering_in_route_filter() {
        let routes = vec![make_route("medium-up", Severity::Medium)];
        let mut router = AlertRouter::new(
            routes,
            Duration::from_secs(0),
            Duration::from_secs(300),
            100,
        );

        // Low < Medium → filtered out
        let low = make_alert("a", Severity::Low);
        assert!(router.process_alert(&low).is_empty());

        // Medium >= Medium → passes
        let med = make_alert("b", Severity::Medium);
        assert_eq!(router.process_alert(&med).len(), 1);

        // High >= Medium → passes
        let high = make_alert("c", Severity::High);
        assert_eq!(router.process_alert(&high).len(), 1);

        // Critical >= Medium → passes
        let crit = make_alert("d", Severity::Critical);
        assert_eq!(router.process_alert(&crit).len(), 1);
    }
}
