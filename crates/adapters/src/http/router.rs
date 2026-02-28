use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::routing::{delete, get, patch, post};
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

/// Maximum request body size for API endpoints (64 KiB).
const MAX_BODY_SIZE: usize = 64 * 1024;

/// Rate limit for write endpoints: 60 requests per 60 seconds per IP.
const WRITE_RATE_LIMIT_PER_SECOND: u64 = 1;
const WRITE_RATE_LIMIT_BURST: u32 = 60;

use super::agent_handler::agent_status;
use super::alert_handler::{list_alerts, mark_false_positive};
use super::alias_handler::alias_status;
use super::audit_handler::{list_audit_logs, rule_history};
use super::conntrack_handler::{conntrack_status, flush_connections, list_connections};
use super::ddos_handler::{
    create_ddos_policy, ddos_attacks, ddos_history, ddos_status, delete_ddos_policy,
    list_ddos_policies,
};
use super::dlp_handler::{dlp_status, list_dlp_patterns};
use super::dns_handler::{dns_stats, flush_dns_cache, list_dns_blocklist, list_dns_cache};
use super::domain_handler::{add_to_blocklist, list_domain_reputations, remove_from_blocklist};
use super::firewall_handler::{create_rule, delete_rule, list_rules};
use super::health_handler::{healthz, readyz};
use super::ids_handler::{ids_status, list_ids_rules};
use super::ips_handler::{
    list_ips_blacklist, list_ips_domain_blocks, list_ips_rules, patch_ips_rule_mode,
};
use super::l7_handler::{create_l7_rule, delete_l7_rule, list_l7_rules};
use super::lb_handler::{
    create_lb_service, delete_lb_service, get_lb_service, lb_status, list_lb_services,
};
use super::metrics_handler::metrics;
use super::middleware::auth::jwt_auth_middleware;
use super::nat_handler::{list_nat_rules, nat_status};
use super::openapi::ApiDoc;
use super::ops_handler::{get_config, get_ebpf_status, reload_config};
use super::ratelimit_handler::{
    create_ratelimit_rule, delete_ratelimit_rule, list_ratelimit_rules,
};
use super::routing_handler::{list_gateways, routing_status};
use super::state::AppState;
use super::threatintel_handler::{list_feeds, list_iocs, threatintel_status};

/// Build the main Axum router with all REST API routes.
///
/// Routes are split into three groups:
/// 1. **Public** (no auth): `/healthz`, `/readyz` — K8s probes
/// 2. **Metrics** (conditional auth): `/metrics` — auth only when configured
/// 3. **API** (protected): `/api/v1/*` — auth when provider is present
#[allow(clippy::too_many_lines)]
pub fn build_router(state: Arc<AppState>, swagger_ui: bool) -> Router {
    // Group 1: Public routes — never require auth (K8s probes)
    let public_routes = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz));

    // Group 2: Metrics route — conditionally protected
    let metrics_routes = {
        let r = Router::new().route("/metrics", get(metrics));
        if state.auth_provider.is_some() && state.metrics_auth_required {
            r.layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                jwt_auth_middleware,
            ))
        } else {
            r
        }
    };

    // Group 3: Protected API routes — split into read and write
    //
    // Write routes get an additional per-IP rate limit (60 req/min).
    // Read routes have no rate limit.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(WRITE_RATE_LIMIT_PER_SECOND)
            .burst_size(WRITE_RATE_LIMIT_BURST)
            .finish()
            .expect("governor config should build"),
    );

    let api_routes = {
        // Read-only routes (no rate limiting)
        let read_routes = Router::new()
            .route("/api/v1/agent/status", get(agent_status))
            .route("/api/v1/firewall/rules", get(list_rules))
            .route("/api/v1/firewall/l7-rules", get(list_l7_rules))
            .route("/api/v1/ips/rules", get(list_ips_rules))
            .route("/api/v1/ips/blacklist", get(list_ips_blacklist))
            .route("/api/v1/ips/domain-blocks", get(list_ips_domain_blocks))
            .route("/api/v1/ids/status", get(ids_status))
            .route("/api/v1/ids/rules", get(list_ids_rules))
            .route("/api/v1/ratelimit/rules", get(list_ratelimit_rules))
            .route("/api/v1/threatintel/status", get(threatintel_status))
            .route("/api/v1/threatintel/iocs", get(list_iocs))
            .route("/api/v1/threatintel/feeds", get(list_feeds))
            .route("/api/v1/alerts", get(list_alerts))
            .route("/api/v1/audit/logs", get(list_audit_logs))
            .route("/api/v1/audit/rules/{id}/history", get(rule_history))
            .route("/api/v1/config", get(get_config))
            .route("/api/v1/ebpf/status", get(get_ebpf_status))
            .route("/api/v1/dns/cache", get(list_dns_cache))
            .route("/api/v1/dns/stats", get(dns_stats))
            .route("/api/v1/dns/blocklist", get(list_dns_blocklist))
            .route("/api/v1/domains/reputation", get(list_domain_reputations))
            .route("/api/v1/ddos/status", get(ddos_status))
            .route("/api/v1/ddos/attacks", get(ddos_attacks))
            .route("/api/v1/ddos/attacks/history", get(ddos_history))
            .route("/api/v1/ddos/policies", get(list_ddos_policies))
            .route("/api/v1/conntrack/status", get(conntrack_status))
            .route("/api/v1/conntrack/connections", get(list_connections))
            .route("/api/v1/dlp/status", get(dlp_status))
            .route("/api/v1/dlp/patterns", get(list_dlp_patterns))
            .route("/api/v1/nat/status", get(nat_status))
            .route("/api/v1/nat/rules", get(list_nat_rules))
            .route("/api/v1/aliases/status", get(alias_status))
            .route("/api/v1/routing/status", get(routing_status))
            .route("/api/v1/routing/gateways", get(list_gateways))
            .route("/api/v1/lb/status", get(lb_status))
            .route("/api/v1/lb/services", get(list_lb_services))
            .route("/api/v1/lb/services/{id}", get(get_lb_service));

        // Write routes (rate limited: 60 req/min per IP)
        let write_routes = Router::new()
            .route("/api/v1/firewall/rules", post(create_rule))
            .route("/api/v1/firewall/rules/{id}", delete(delete_rule))
            .route("/api/v1/firewall/l7-rules", post(create_l7_rule))
            .route("/api/v1/firewall/l7-rules/{id}", delete(delete_l7_rule))
            .route("/api/v1/ips/rules/{id}", patch(patch_ips_rule_mode))
            .route("/api/v1/ratelimit/rules", post(create_ratelimit_rule))
            .route(
                "/api/v1/ratelimit/rules/{id}",
                delete(delete_ratelimit_rule),
            )
            .route(
                "/api/v1/alerts/{id}/false-positive",
                post(mark_false_positive),
            )
            .route("/api/v1/ddos/policies", post(create_ddos_policy))
            .route("/api/v1/ddos/policies/{id}", delete(delete_ddos_policy))
            .route("/api/v1/config/reload", post(reload_config))
            .route("/api/v1/conntrack/flush", post(flush_connections))
            .route("/api/v1/dns/cache", delete(flush_dns_cache))
            .route("/api/v1/domains/blocklist", post(add_to_blocklist))
            .route(
                "/api/v1/domains/blocklist/{domain}",
                delete(remove_from_blocklist),
            )
            .route("/api/v1/lb/services", post(create_lb_service))
            .route("/api/v1/lb/services/{id}", delete(delete_lb_service))
            .layer(GovernorLayer::new(governor_conf));

        let r = read_routes
            .merge(write_routes)
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE));

        if state.auth_provider.is_some() {
            r.layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                jwt_auth_middleware,
            ))
        } else {
            r
        }
    };

    let router = public_routes.merge(metrics_routes).merge(api_routes);

    let router = if swagger_ui {
        router.merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
    } else {
        router
    };

    router.with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    use application::audit_service_impl::AuditAppService;
    use application::firewall_service_impl::FirewallAppService;
    use application::ips_service_impl::IpsAppService;
    use application::l7_service_impl::L7AppService;
    use application::ratelimit_service_impl::RateLimitAppService;
    use application::threatintel_service_impl::ThreatIntelAppService;
    use domain::audit::entity::AuditEntry;
    use domain::audit::error::AuditError;
    use domain::firewall::engine::FirewallEngine;
    use domain::ips::engine::IpsEngine;
    use domain::l7::engine::L7Engine;
    use domain::ratelimit::engine::RateLimitEngine;
    use domain::threatintel::engine::ThreatIntelEngine;
    use infrastructure::metrics::AgentMetrics;
    use ports::secondary::audit_sink::AuditSink;
    use ports::secondary::metrics_port::MetricsPort;
    use ports::test_utils::NoopMetrics;

    struct NoopSink;
    impl AuditSink for NoopSink {
        fn write_entry(&self, _entry: &AuditEntry) -> Result<(), AuditError> {
            Ok(())
        }
    }

    #[test]
    fn build_router_does_not_panic() {
        let noop: Arc<dyn MetricsPort> = Arc::new(NoopMetrics);
        let fw_svc = FirewallAppService::new(FirewallEngine::new(), None, Arc::clone(&noop));
        let ips_svc = IpsAppService::new(IpsEngine::default(), Arc::clone(&noop));
        let l7_svc = L7AppService::new(L7Engine::new(), Arc::clone(&noop));
        let rl_svc = RateLimitAppService::new(RateLimitEngine::new(), Arc::clone(&noop));
        let ti_svc = ThreatIntelAppService::new(
            ThreatIntelEngine::new(1_000_000),
            Arc::clone(&noop),
            vec![],
        );
        let audit_svc = AuditAppService::new(Arc::new(NoopSink) as Arc<dyn AuditSink>);
        let (reload_tx, _reload_rx) = tokio::sync::mpsc::channel(1);
        let state = Arc::new(AppState::new(
            Arc::new(AgentMetrics::new()),
            Arc::new(AtomicBool::new(false)),
            Arc::new(tokio::sync::RwLock::new(fw_svc)),
            Arc::new(tokio::sync::RwLock::new(ips_svc)),
            Arc::new(tokio::sync::RwLock::new(l7_svc)),
            Arc::new(tokio::sync::RwLock::new(rl_svc)),
            Arc::new(tokio::sync::RwLock::new(ti_svc)),
            Arc::new(tokio::sync::RwLock::new(audit_svc)),
            Arc::new(tokio::sync::RwLock::new(
                infrastructure::config::AgentConfig::from_yaml("agent:\n  interfaces: [eth0]")
                    .unwrap(),
            )),
            reload_tx,
            Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
        ));
        let _router = build_router(state, true);
    }
}
