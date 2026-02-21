use std::time::Duration;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// HTTP client for the eBPFsentinel REST API.
pub struct ApiClient {
    client: reqwest::Client,
    base_url: String,
    token: Option<String>,
}

// ── Response DTOs ──────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Deserialize, Serialize)]
pub struct ReadyResponse {
    pub status: String,
    pub ebpf_loaded: bool,
}

#[derive(Deserialize, Serialize)]
pub struct AgentStatusResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub ebpf_loaded: bool,
    pub rule_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct RuleResponse {
    pub id: String,
    pub enabled: bool,
    pub priority: u32,
    pub action: String,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub src_port: Option<String>,
    pub dst_port: Option<String>,
    pub scope: String,
}

#[derive(Deserialize, Serialize)]
pub struct L7RuleResponse {
    pub id: String,
    pub priority: u32,
    pub action: String,
    pub matcher: serde_json::Value,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub dst_port: Option<String>,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct IpsRuleResponse {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub mode: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    pub pattern: String,
    pub enabled: bool,
    pub domain_pattern: Option<String>,
    pub domain_match_mode: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct BlacklistEntryResponse {
    pub ip: String,
    pub reason: String,
    pub auto_generated: bool,
    pub ttl_remaining_secs: u64,
}

#[derive(Deserialize, Serialize)]
pub struct DomainBlockResponse {
    pub ip: String,
    pub domain: String,
    pub source: String,
    pub reason: String,
    pub ttl_remaining_secs: u64,
}

#[derive(Deserialize, Serialize)]
pub struct RateLimitRuleResponse {
    pub id: String,
    pub scope: String,
    pub rate: u64,
    pub burst: u64,
    pub action: String,
    pub algorithm: String,
    pub src_ip: Option<String>,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct ThreatIntelStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub ioc_count: u64,
    pub feed_count: u64,
}

#[derive(Deserialize, Serialize)]
pub struct IocResponse {
    pub ip: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: String,
    pub source_feed: String,
}

#[derive(Deserialize, Serialize)]
pub struct FeedResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: String,
    pub enabled: bool,
    pub refresh_interval_secs: u64,
    pub max_iocs: u64,
    pub min_confidence: u8,
}

#[derive(Deserialize, Serialize)]
pub struct AlertListResponse {
    pub alerts: Vec<AlertResponse>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Deserialize, Serialize)]
pub struct AlertResponse {
    pub id: String,
    pub timestamp_ns: u64,
    pub component: String,
    pub severity: String,
    pub rule_id: String,
    pub action: String,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u32,
    pub dst_port: u32,
    pub protocol: u32,
    pub message: String,
    #[serde(default)]
    pub false_positive: bool,
    #[serde(default)]
    pub src_domain: Option<String>,
    #[serde(default)]
    pub dst_domain: Option<String>,
    #[serde(default)]
    pub src_domain_score: Option<f64>,
    #[serde(default)]
    pub dst_domain_score: Option<f64>,
}

#[derive(Deserialize, Serialize)]
pub struct FalsePositiveResponse {
    pub alert_id: String,
    pub marked: bool,
}

#[derive(Deserialize, Serialize)]
pub struct AuditLogResponse {
    pub entries: Vec<AuditEntryResponse>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
}

#[derive(Deserialize, Serialize)]
pub struct AuditEntryResponse {
    pub timestamp_ns: u64,
    pub component: String,
    pub action: String,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u32,
    pub dst_port: u32,
    pub protocol: u32,
    pub rule_id: String,
    pub detail: String,
}

#[derive(Deserialize, Serialize)]
pub struct RuleHistoryResponse {
    pub rule_id: String,
    pub entries: Vec<RuleHistoryEntry>,
}

#[derive(Deserialize, Serialize)]
pub struct RuleHistoryEntry {
    pub version: u32,
    pub timestamp_ns: u64,
    pub component: String,
    pub action: String,
    pub actor: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

// ── DNS Intelligence ────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct DnsCacheListResponse {
    pub entries: Vec<DnsCacheEntryResponse>,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Deserialize, Serialize)]
pub struct DnsCacheEntryResponse {
    pub domain: String,
    pub ips: Vec<String>,
    pub ttl_remaining_secs: i64,
    pub query_count: u64,
    pub is_blocked: bool,
}

#[derive(Deserialize, Serialize)]
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

#[derive(Deserialize, Serialize)]
pub struct TopQueriedEntry {
    pub domain: String,
    pub query_count: u64,
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistRuleResponse {
    pub pattern: String,
    pub action: String,
    pub match_count: u64,
}

#[derive(Deserialize, Serialize)]
pub struct DnsFlushResponse {
    pub flushed_entries: usize,
}

// ── Domain Intelligence ──────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct DomainReputationListResponse {
    pub entries: Vec<DomainReputationEntry>,
    pub page: usize,
    pub page_size: usize,
}

#[derive(Deserialize, Serialize)]
pub struct DomainReputationEntry {
    pub domain: String,
    pub score: f64,
    pub factors: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub is_blocked: bool,
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistAddResponse {
    pub domain: String,
    pub added: bool,
}

#[derive(Deserialize, Serialize)]
pub struct BlocklistRemoveResponse {
    pub domain: String,
    pub removed: bool,
}

#[derive(Deserialize)]
struct ApiErrorBody {
    error: ApiErrorDetail,
}

#[derive(Deserialize)]
struct ApiErrorDetail {
    code: String,
    message: String,
}

impl ApiClient {
    pub fn new(host: &str, port: u16, token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            base_url: format!("http://{host}:{port}"),
            token,
        }
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .client
            .request(method, format!("{}{path}", self.base_url));
        if let Some(ref token) = self.token {
            req = req.bearer_auth(token);
        }
        req
    }

    // ── Health ──────────────────────────────────────────────────────

    pub async fn healthz(&self) -> anyhow::Result<HealthResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/healthz")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn readyz(&self) -> anyhow::Result<ReadyResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/readyz")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Agent Status ────────────────────────────────────────────────

    pub async fn get_status(&self) -> anyhow::Result<AgentStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/agent/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Metrics ─────────────────────────────────────────────────────

    pub async fn metrics(&self) -> anyhow::Result<String> {
        let resp = self
            .request(reqwest::Method::GET, "/metrics")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        if resp.status().is_success() {
            return resp.text().await.context("failed to read metrics body");
        }
        bail!("request failed with status {}", resp.status());
    }

    // ── Firewall ────────────────────────────────────────────────────

    pub async fn list_rules(&self) -> anyhow::Result<Vec<RuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/firewall/rules")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_rule(&self, body: &serde_json::Value) -> anyhow::Result<RuleResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/firewall/rules")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_rule(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/firewall/rules/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    // ── L7 ──────────────────────────────────────────────────────────

    pub async fn list_l7_rules(&self) -> anyhow::Result<Vec<L7RuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/firewall/l7-rules")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_l7_rule(&self, body: &serde_json::Value) -> anyhow::Result<L7RuleResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/firewall/l7-rules")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_l7_rule(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/firewall/l7-rules/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    // ── IPS ─────────────────────────────────────────────────────────

    pub async fn list_ips_rules(&self) -> anyhow::Result<Vec<IpsRuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ips/rules")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_ips_blacklist(&self) -> anyhow::Result<Vec<BlacklistEntryResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ips/blacklist")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_ips_domain_blocks(&self) -> anyhow::Result<Vec<DomainBlockResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ips/domain-blocks")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn patch_ips_mode(&self, id: &str, mode: &str) -> anyhow::Result<()> {
        let body = serde_json::json!({ "mode": mode });
        let resp = self
            .request(reqwest::Method::PATCH, &format!("/api/v1/ips/rules/{id}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        if resp.status().is_success() {
            return Ok(());
        }
        let status = resp.status();
        if let Ok(body) = resp.json::<ApiErrorBody>().await {
            bail!("{} ({}): {}", body.error.message, body.error.code, status);
        }
        bail!("request failed with status {status}");
    }

    // ── Rate Limiting ───────────────────────────────────────────────

    pub async fn list_ratelimit_rules(&self) -> anyhow::Result<Vec<RateLimitRuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ratelimit/rules")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_ratelimit_rule(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<RateLimitRuleResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/ratelimit/rules")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_ratelimit_rule(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/ratelimit/rules/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    // ── Threat Intelligence ─────────────────────────────────────────

    pub async fn threatintel_status(&self) -> anyhow::Result<ThreatIntelStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/threatintel/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_iocs(&self) -> anyhow::Result<Vec<IocResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/threatintel/iocs")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_feeds(&self) -> anyhow::Result<Vec<FeedResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/threatintel/feeds")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Alerts ──────────────────────────────────────────────────────

    pub async fn list_alerts(
        &self,
        component: Option<&str>,
        severity: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> anyhow::Result<AlertListResponse> {
        let mut req = self.request(reqwest::Method::GET, "/api/v1/alerts");
        req = req.query(&[("limit", limit.to_string()), ("offset", offset.to_string())]);
        if let Some(c) = component {
            req = req.query(&[("component", c)]);
        }
        if let Some(s) = severity {
            req = req.query(&[("min_severity", s)]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn mark_false_positive(&self, id: &str) -> anyhow::Result<FalsePositiveResponse> {
        let resp = self
            .request(
                reqwest::Method::POST,
                &format!("/api/v1/alerts/{id}/false-positive"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── DNS Intelligence ─────────────────────────────────────────────

    pub async fn dns_cache(
        &self,
        domain: Option<&str>,
        ip: Option<&str>,
        page: usize,
        page_size: usize,
    ) -> anyhow::Result<DnsCacheListResponse> {
        let mut req = self.request(reqwest::Method::GET, "/api/v1/dns/cache");
        req = req.query(&[
            ("page", page.to_string()),
            ("page_size", page_size.to_string()),
        ]);
        if let Some(d) = domain {
            req = req.query(&[("domain", d)]);
        }
        if let Some(i) = ip {
            req = req.query(&[("ip", i)]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn dns_stats(&self) -> anyhow::Result<DnsStatsResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/dns/stats")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn dns_blocklist(&self) -> anyhow::Result<Vec<BlocklistRuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/dns/blocklist")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn dns_flush(&self) -> anyhow::Result<DnsFlushResponse> {
        let resp = self
            .request(reqwest::Method::DELETE, "/api/v1/dns/cache")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Domain Intelligence ──────────────────────────────────────────

    pub async fn list_domain_reputations(
        &self,
        domain: Option<&str>,
        min_score: Option<f64>,
        page: usize,
        page_size: usize,
    ) -> anyhow::Result<DomainReputationListResponse> {
        use std::fmt::Write;
        let mut url = format!("/api/v1/domains/reputation?page={page}&page_size={page_size}");
        if let Some(d) = domain {
            let _ = write!(url, "&domain={d}");
        }
        if let Some(s) = min_score {
            let _ = write!(url, "&min_score={s}");
        }
        let resp = self
            .request(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn domain_block(&self, domain: &str) -> anyhow::Result<BlocklistAddResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/domains/blocklist")
            .json(&serde_json::json!({ "domain": domain }))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn domain_unblock(&self, domain: &str) -> anyhow::Result<BlocklistRemoveResponse> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/domains/blocklist/{domain}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Audit ───────────────────────────────────────────────────────

    pub async fn list_audit_logs(
        &self,
        component: Option<&str>,
        action: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> anyhow::Result<AuditLogResponse> {
        let mut req = self.request(reqwest::Method::GET, "/api/v1/audit/logs");
        req = req.query(&[("limit", limit.to_string()), ("offset", offset.to_string())]);
        if let Some(c) = component {
            req = req.query(&[("component", c)]);
        }
        if let Some(a) = action {
            req = req.query(&[("action", a)]);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn rule_history(&self, id: &str) -> anyhow::Result<RuleHistoryResponse> {
        let resp = self
            .request(
                reqwest::Method::GET,
                &format!("/api/v1/audit/rules/{id}/history"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }
}

fn connection_error(base_url: &str, err: &reqwest::Error) -> anyhow::Error {
    if err.is_connect() {
        anyhow::anyhow!("cannot connect to agent at {base_url} — is the agent running?")
    } else if err.is_timeout() {
        anyhow::anyhow!("connection to agent at {base_url} timed out")
    } else {
        anyhow::anyhow!("request to agent failed: {err}")
    }
}

async fn handle_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> anyhow::Result<T> {
    if resp.status().is_success() {
        return resp
            .json::<T>()
            .await
            .context("failed to parse response body");
    }
    let status = resp.status();
    if let Ok(body) = resp.json::<ApiErrorBody>().await {
        bail!("{} ({}): {}", body.error.message, body.error.code, status);
    }
    bail!("request failed with status {status}");
}

async fn handle_delete(resp: reqwest::Response) -> anyhow::Result<()> {
    if resp.status().is_success() {
        return Ok(());
    }
    let status = resp.status();
    if let Ok(body) = resp.json::<ApiErrorBody>().await {
        bail!("{} ({}): {}", body.error.message, body.error.code, status);
    }
    bail!("request failed with status {status}");
}
