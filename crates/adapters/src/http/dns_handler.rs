use std::net::IpAddr;
use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use ports::secondary::dns_cache_port::DnsCachePort;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::error::ApiError;
use super::state::AppState;

// ── Query parameters ────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
pub struct CacheQueryParams {
    /// Filter by domain substring (case-insensitive).
    pub domain: Option<String>,
    /// Reverse lookup: find domains for this IP.
    pub ip: Option<String>,
    /// Page number (0-indexed).
    #[serde(default)]
    pub page: usize,
    /// Page size (max 500).
    #[serde(default = "default_page_size")]
    pub page_size: usize,
}

fn default_page_size() -> usize {
    50
}

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct DnsCacheEntryResponse {
    pub domain: String,
    pub ips: Vec<String>,
    pub ttl_remaining_secs: i64,
    pub query_count: u64,
    pub is_blocked: bool,
}

#[derive(Serialize, ToSchema)]
pub struct DnsCacheListResponse {
    pub entries: Vec<DnsCacheEntryResponse>,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Serialize, ToSchema)]
pub struct DnsStatsResponse {
    pub total_entries: usize,
    pub hit_count: u64,
    pub miss_count: u64,
    pub eviction_count: u64,
    pub expired_count: u64,
    pub top_queried: Vec<TopQueriedEntry>,
    pub blocklist_pattern_count: usize,
    pub blocklist_domains_blocked: u64,
    pub blocklist_ips_injected: usize,
}

#[derive(Serialize, ToSchema)]
pub struct TopQueriedEntry {
    pub domain: String,
    pub query_count: u64,
}

#[derive(Serialize, ToSchema)]
pub struct BlocklistRuleResponse {
    pub pattern: String,
    pub action: String,
    pub match_count: u64,
}

#[derive(Serialize, ToSchema)]
pub struct DnsFlushResponse {
    pub flushed_entries: usize,
}

// ── Helpers ─────────────────────────────────────────────────────────

fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        * 1_000_000_000
}

fn get_dns_services(
    state: &AppState,
) -> Result<
    (
        &Arc<application::dns_cache_service_impl::DnsCacheAppService>,
        &Arc<application::dns_blocklist_service_impl::DnsBlocklistAppService>,
    ),
    ApiError,
> {
    let cache = state
        .dns_cache_service
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "DNS intelligence is not enabled".to_string(),
        })?;
    let blocklist = state
        .dns_blocklist_service
        .as_ref()
        .ok_or(ApiError::ServiceUnavailable {
            message: "DNS intelligence is not enabled".to_string(),
        })?;
    Ok((cache, blocklist))
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/dns/cache` — list DNS cache entries.
#[utoipa::path(
    get, path = "/api/v1/dns/cache",
    tag = "DNS Intelligence",
    params(CacheQueryParams),
    responses(
        (status = 200, description = "DNS cache entries", body = DnsCacheListResponse),
        (status = 503, description = "DNS not enabled"),
    )
)]
pub async fn list_dns_cache(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CacheQueryParams>,
) -> Result<impl IntoResponse, ApiError> {
    let (cache, blocklist) = get_dns_services(&state)?;
    let page_size = params.page_size.min(500);
    let now = now_ns();

    let entries = if let Some(ref ip_str) = params.ip {
        // Reverse lookup
        let ip: IpAddr = ip_str.parse().map_err(|_| ApiError::BadRequest {
            code: "VALIDATION_ERROR",
            message: format!("invalid IP address: {ip_str}"),
        })?;
        let domains = cache.lookup_ip(&ip);
        domains
            .into_iter()
            .filter_map(|domain| {
                let entry = cache.lookup_domain(&domain)?;
                let is_blocked = check_blocked(blocklist, &domain);
                let ttl_remaining = compute_ttl_remaining(&entry, now);
                Some(DnsCacheEntryResponse {
                    domain,
                    ips: entry.ips.iter().map(ToString::to_string).collect(),
                    ttl_remaining_secs: ttl_remaining,
                    query_count: entry.query_count,
                    is_blocked,
                })
            })
            .collect()
    } else if let Some(ref domain_filter) = params.domain {
        // Domain substring search
        let raw = cache.search_by_domain(domain_filter, params.page, page_size);
        raw.into_iter()
            .map(|(domain, entry)| {
                let is_blocked = check_blocked(blocklist, &domain);
                let ttl_remaining = compute_ttl_remaining(&entry, now);
                DnsCacheEntryResponse {
                    domain,
                    ips: entry.ips.iter().map(ToString::to_string).collect(),
                    ttl_remaining_secs: ttl_remaining,
                    query_count: entry.query_count,
                    is_blocked,
                }
            })
            .collect()
    } else {
        // Paginated listing
        let raw = cache.lookup_all(params.page, page_size);
        raw.into_iter()
            .map(|(domain, entry)| {
                let is_blocked = check_blocked(blocklist, &domain);
                let ttl_remaining = compute_ttl_remaining(&entry, now);
                DnsCacheEntryResponse {
                    domain,
                    ips: entry.ips.iter().map(ToString::to_string).collect(),
                    ttl_remaining_secs: ttl_remaining,
                    query_count: entry.query_count,
                    is_blocked,
                }
            })
            .collect()
    };

    Ok(Json(DnsCacheListResponse {
        entries,
        page: params.page,
        page_size,
    }))
}

/// `GET /api/v1/dns/stats` — DNS cache and blocklist statistics.
#[utoipa::path(
    get, path = "/api/v1/dns/stats",
    tag = "DNS Intelligence",
    responses(
        (status = 200, description = "DNS statistics", body = DnsStatsResponse),
        (status = 503, description = "DNS not enabled"),
    )
)]
pub async fn dns_stats(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, ApiError> {
    let (cache, blocklist) = get_dns_services(&state)?;
    let cache_stats = cache.stats();
    let bl_stats = blocklist.stats();
    let top = cache.top_queried(10);

    Ok(Json(DnsStatsResponse {
        total_entries: cache_stats.total_entries,
        hit_count: cache_stats.hit_count,
        miss_count: cache_stats.miss_count,
        eviction_count: cache_stats.eviction_count,
        expired_count: cache_stats.expired_count,
        top_queried: top
            .into_iter()
            .map(|(domain, count)| TopQueriedEntry {
                domain,
                query_count: count,
            })
            .collect(),
        blocklist_pattern_count: bl_stats.pattern_count,
        blocklist_domains_blocked: bl_stats.domains_blocked,
        blocklist_ips_injected: bl_stats.ips_injected,
    }))
}

/// `GET /api/v1/dns/blocklist` — list loaded blocklist rules.
#[utoipa::path(
    get, path = "/api/v1/dns/blocklist",
    tag = "DNS Intelligence",
    responses(
        (status = 200, description = "Blocklist rules", body = Vec<BlocklistRuleResponse>),
        (status = 503, description = "DNS not enabled"),
    )
)]
pub async fn list_dns_blocklist(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let (_, blocklist) = get_dns_services(&state)?;
    let action = blocklist.action().to_string();
    let rules: Vec<BlocklistRuleResponse> = blocklist
        .list_patterns_with_counts()
        .into_iter()
        .map(|(pattern, match_count)| BlocklistRuleResponse {
            pattern,
            action: action.clone(),
            match_count,
        })
        .collect();
    Ok(Json(rules))
}

/// `DELETE /api/v1/dns/cache` — flush the DNS cache.
#[utoipa::path(
    delete, path = "/api/v1/dns/cache",
    tag = "DNS Intelligence",
    responses(
        (status = 200, description = "Cache flushed", body = DnsFlushResponse),
        (status = 503, description = "DNS not enabled"),
    )
)]
pub async fn flush_dns_cache(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ApiError> {
    let (cache, _) = get_dns_services(&state)?;
    let count = cache.flush_and_count();
    Ok(Json(DnsFlushResponse {
        flushed_entries: count,
    }))
}

fn compute_ttl_remaining(entry: &domain::dns::entity::DnsCacheEntry, now_ns: u64) -> i64 {
    let expiry_ns = entry.inserted_at_ns + entry.ttl_secs * 1_000_000_000;
    let expiry_secs = expiry_ns / 1_000_000_000;
    let now_secs = now_ns / 1_000_000_000;
    // Both values fit in i64 (seconds since epoch)
    i64::try_from(expiry_secs).unwrap_or(i64::MAX) - i64::try_from(now_secs).unwrap_or(i64::MAX)
}

fn check_blocked(
    blocklist: &application::dns_blocklist_service_impl::DnsBlocklistAppService,
    domain: &str,
) -> bool {
    blocklist.list_patterns_with_counts().iter().any(|(p, _)| {
        domain::dns::entity::DomainPattern::parse(p).is_ok_and(|pat| pat.matches(domain))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_entry_response_serialization() {
        let resp = DnsCacheEntryResponse {
            domain: "example.com".to_string(),
            ips: vec!["1.2.3.4".to_string()],
            ttl_remaining_secs: 250,
            query_count: 42,
            is_blocked: false,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["domain"], "example.com");
        assert_eq!(json["ttl_remaining_secs"], 250);
        assert_eq!(json["query_count"], 42);
        assert!(!json["is_blocked"].as_bool().unwrap());
    }

    #[test]
    fn stats_response_serialization() {
        let resp = DnsStatsResponse {
            total_entries: 100,
            hit_count: 500,
            miss_count: 50,
            eviction_count: 10,
            expired_count: 5,
            top_queried: vec![TopQueriedEntry {
                domain: "google.com".to_string(),
                query_count: 200,
            }],
            blocklist_pattern_count: 3,
            blocklist_domains_blocked: 15,
            blocklist_ips_injected: 8,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total_entries"], 100);
        assert_eq!(json["hit_count"], 500);
        assert_eq!(json["top_queried"][0]["domain"], "google.com");
    }

    #[test]
    fn blocklist_rule_response_serialization() {
        let resp = BlocklistRuleResponse {
            pattern: "*.malware.com".to_string(),
            action: "block".to_string(),
            match_count: 42,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["pattern"], "*.malware.com");
        assert_eq!(json["action"], "block");
        assert_eq!(json["match_count"], 42);
    }

    #[test]
    fn flush_response_serialization() {
        let resp = DnsFlushResponse {
            flushed_entries: 150,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["flushed_entries"], 150);
    }

    #[test]
    fn compute_ttl_remaining_positive() {
        let entry = domain::dns::entity::DnsCacheEntry {
            ips: vec![],
            ttl_secs: 300,
            inserted_at_ns: 1_000_000_000_000, // 1000s
            last_queried_ns: 1_000_000_000_000,
            query_count: 1,
        };
        // now = 1100s → remaining = 1000 + 300 - 1100 = 200s
        let remaining = compute_ttl_remaining(&entry, 1_100_000_000_000);
        assert_eq!(remaining, 200);
    }

    #[test]
    fn compute_ttl_remaining_expired() {
        let entry = domain::dns::entity::DnsCacheEntry {
            ips: vec![],
            ttl_secs: 60,
            inserted_at_ns: 1_000_000_000_000,
            last_queried_ns: 1_000_000_000_000,
            query_count: 1,
        };
        // now = 1100s → remaining = 1000 + 60 - 1100 = -40s
        let remaining = compute_ttl_remaining(&entry, 1_100_000_000_000);
        assert_eq!(remaining, -40);
    }
}
