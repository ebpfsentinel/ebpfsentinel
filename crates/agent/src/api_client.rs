use std::time::Duration;

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};

/// HTTP client for the eBPFsentinel REST API.
pub struct ApiClient {
    client: reqwest::Client,
    /// Second client for the two Server-Sent Events routes. The ordinary one
    /// carries a total request deadline, which a stream that is meant to stay
    /// open would trip on its first quiet minute; this one has no deadline and
    /// a per-read timeout instead, so a connection that has gone silent past
    /// several keepalives is still noticed.
    stream_client: reqwest::Client,
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
pub struct AgentIdentityResponse {
    pub version: String,
    pub hostname: String,
    pub uptime_seconds: u64,
    pub operator_managed: bool,
    #[serde(default)]
    pub operator_endpoint: Option<String>,
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
    /// Absent unless another rule holds a kernel map slot this rule claims.
    pub kernel_slot: Option<SlotContentionResponse>,
}

/// Reported by the agent when two rules claim the same kernel map slot.
#[derive(Deserialize, Serialize)]
pub struct SlotContentionResponse {
    pub shadowed_by: Vec<String>,
    pub evaluated_in_userspace: bool,
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
    pub rate: u64,
    pub burst: u64,
    pub action: String,
    pub algorithm: String,
    pub src_ip: String,
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
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6.
    pub src_addr: Vec<u32>,
    /// Destination address (same encoding).
    pub dst_addr: Vec<u32>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    #[serde(default)]
    pub is_ipv6: bool,
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
    #[serde(default)]
    pub src_geo: Option<String>,
    #[serde(default)]
    pub dst_geo: Option<String>,
    #[serde(default)]
    pub ja4_fingerprint: Option<String>,
}

impl AlertResponse {
    /// Format source IP as string.
    pub fn src_ip_str(&self) -> String {
        addr_to_string(&self.src_addr, self.is_ipv6)
    }
    /// Format destination IP as string.
    pub fn dst_ip_str(&self) -> String {
        addr_to_string(&self.dst_addr, self.is_ipv6)
    }
}

/// Convert a `[u32; 4]`-style address to a human-readable IP string.
fn addr_to_string(addr: &[u32], is_ipv6: bool) -> String {
    if is_ipv6 {
        let mut bytes = [0u8; 16];
        for (i, &word) in addr.iter().take(4).enumerate() {
            bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        std::net::Ipv6Addr::from(bytes).to_string()
    } else {
        let v4 = addr.first().copied().unwrap_or(0);
        if v4 == 0 {
            "-".to_string()
        } else {
            std::net::Ipv4Addr::from(v4).to_string()
        }
    }
}

#[derive(Deserialize, Serialize)]
pub struct FalsePositiveResponse {
    pub alert_id: String,
    pub marked: bool,
}

#[derive(Deserialize, Serialize)]
pub struct MitreCoverageResponse {
    pub attack_version: String,
    pub total_techniques: usize,
    pub techniques: Vec<MitreTechniqueEntry>,
    pub by_tactic: Vec<MitreTacticSummary>,
}

#[derive(Deserialize, Serialize)]
pub struct MitreTechniqueEntry {
    pub component: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub description: String,
}

#[derive(Deserialize, Serialize)]
pub struct MitreTacticSummary {
    pub tactic: String,
    pub covered_techniques: usize,
    pub components: Vec<String>,
}

// ── Response Actions ────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct ResponseActionResponse {
    pub id: String,
    pub action_type: String,
    pub target: String,
    pub ttl_secs: u64,
    pub remaining_secs: u64,
    pub rule_id: String,
    #[serde(default)]
    pub rate_pps: Option<u64>,
    pub revoked: bool,
}

#[derive(Deserialize, Serialize)]
pub struct ResponseListResponse {
    pub actions: Vec<ResponseActionResponse>,
    pub active_count: usize,
}

#[derive(Serialize)]
struct CreateResponseBody {
    action: String,
    target: String,
    ttl: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rate_pps: Option<u64>,
}

// ── Captures ────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct CaptureResponse {
    pub id: String,
    pub filter: String,
    pub duration_secs: u64,
    pub snap_length: u32,
    pub output_path: String,
    pub interface: String,
    pub status: String,
    pub file_size_bytes: u64,
    pub packets_captured: u64,
}

#[derive(Deserialize, Serialize)]
pub struct CaptureListResponse {
    pub captures: Vec<CaptureResponse>,
}

#[derive(Serialize)]
struct StartCaptureBody {
    filter: String,
    duration_seconds: u64,
    snap_length: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct FingerprintSummaryResponse {
    pub cached_count: usize,
    pub max_size: usize,
    pub ttl_seconds: u64,
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
pub struct DnsStatusResponse {
    pub enabled: bool,
    pub blocklist_pattern_count: usize,
    pub blocklist_domains_blocked: u64,
    pub blocklist_ips_injected: usize,
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

// ── Connection Tracking ──────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct ConnTrackStatusResponse {
    pub enabled: bool,
    pub connection_count: u64,
    pub max_connections: u64,
}

#[derive(Deserialize, Serialize)]
pub struct ConnectionResponse {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub state: String,
    pub packets_fwd: u32,
    pub packets_rev: u32,
    pub bytes_fwd: u32,
    pub bytes_rev: u32,
}

/// One frame of `GET /api/v1/conntrack/events`. The stream serialises the
/// agent's own lifecycle record, so `event_type` arrives capitalised where
/// the list endpoint's fields do not; the printer lowercases it.
#[derive(Deserialize, Serialize)]
pub struct ConntrackEventFrame {
    pub event_type: String,
    pub connection: ConnectionResponse,
}

// ── eBPF Status ─────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct EbpfStatusResponse {
    pub programs: Vec<EbpfProgramStatus>,
    /// Attaches the kernel refused. `programs[].loaded` says a program is in
    /// the kernel; this says whether it reached the wire.
    #[serde(default)]
    pub attach_blocked: Vec<EbpfAttachBlockEntry>,
}

#[derive(Deserialize, Serialize)]
pub struct EbpfProgramStatus {
    pub name: String,
    pub loaded: bool,
}

/// One attach the kernel refused, and what is standing in the way.
#[derive(Deserialize, Serialize)]
pub struct EbpfAttachBlockEntry {
    pub program: String,
    pub interface: String,
    pub reason: String,
    /// The interface already carries somebody else's XDP program.
    pub nested_xdp: bool,
}

// ── DDoS Protection ─────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct DdosStatusResponse {
    pub enabled: bool,
    pub active_attacks: usize,
    pub total_mitigated: u64,
    pub policy_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct DdosAttackResponse {
    pub id: String,
    pub attack_type: String,
    pub status: String,
    pub start_time_ns: u64,
    pub peak_pps: u64,
    pub current_pps: u64,
    pub total_packets: u64,
    pub source_count: u64,
}

#[derive(Deserialize, Serialize)]
pub struct DdosPolicyResponse {
    pub id: String,
    pub attack_type: String,
    pub detection_threshold_pps: u64,
    pub mitigation_action: String,
    pub auto_block_duration_secs: u64,
    pub enabled: bool,
}

// ── QoS ─────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct QosStatusResponse {
    pub enabled: bool,
    pub pipe_count: usize,
    pub queue_count: usize,
    pub classifier_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct QosPipeResponse {
    pub id: String,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub direction: String,
    pub delay_ms: u32,
    pub loss_pct: f32,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct QosQueueResponse {
    pub id: String,
    pub pipe_id: String,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct QosClassifierResponse {
    pub id: String,
    pub queue_id: String,
    pub priority: u32,
    pub match_rule: serde_json::Value,
}

// ── Load Balancer ────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct LbStatusResponse {
    pub enabled: bool,
    pub service_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct LbServiceResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub listen_port: u16,
    pub algorithm: String,
    pub backend_count: usize,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct LbServiceDetailResponse {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub listen_port: u16,
    pub algorithm: String,
    pub enabled: bool,
    pub backends: Vec<LbBackendResponse>,
}

#[derive(Deserialize, Serialize)]
pub struct LbBackendResponse {
    pub id: String,
    pub addr: String,
    pub port: u16,
    pub weight: u32,
    pub enabled: bool,
    pub status: String,
    pub active_connections: u64,
}

#[derive(Deserialize, Serialize)]
pub struct LbVipStatusResponse {
    pub role: String,
    pub interface: String,
    pub is_speaker: bool,
    pub bindings_count: usize,
    pub vips: Vec<LbVipResponse>,
}

#[derive(Deserialize, Serialize)]
pub struct LbVipResponse {
    pub name: String,
    pub addr: String,
    pub arp_replies: u64,
    pub self_announced: bool,
}

// ── NAT ─────────────────────────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct NatStatusResponse {
    pub enabled: bool,
    pub rule_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct NatRuleResponse {
    pub id: String,
    pub nat_type: String,
    pub direction: String,
    pub priority: u32,
    pub enabled: bool,
}

#[derive(Deserialize, Serialize)]
pub struct NptV6RuleResponse {
    pub id: String,
    pub enabled: bool,
    pub internal_prefix: String,
    pub external_prefix: String,
    pub prefix_len: u8,
}

// ── Zones ─────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct ZoneStatusResponse {
    pub enabled: bool,
    pub zone_count: usize,
    pub policy_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct ZoneResponse {
    pub id: String,
    pub interfaces: Vec<String>,
    pub default_policy: String,
}

#[derive(Deserialize, Serialize)]
pub struct ZonePolicyResponse {
    /// Stable identifier `{from}__{to}`, which is also what the delete route takes.
    pub id: String,
    pub from: String,
    pub to: String,
    pub policy: String,
    pub action: String,
}

// ── Policy routing ───────────────────────────

#[derive(Deserialize, Serialize)]
pub struct RoutingStatusResponse {
    pub enabled: bool,
    pub gateway_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct GatewayResponse {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub gateway_ip: String,
    pub priority: u32,
    pub weight: u32,
    pub enabled: bool,
    pub status: String,
    pub health_status: String,
}

#[derive(Deserialize, Serialize)]
pub struct RouteResponse {
    pub destination: String,
    pub gateway_id: String,
    pub gateway_ip: String,
}

// ── IDS ──────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct IdsStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub rule_count: usize,
}

/// Per-rule threshold detection, present only on rate-based IDS rules.
#[derive(Deserialize, Serialize)]
pub struct IdsThresholdResponse {
    pub threshold_type: String,
    pub count: u32,
    pub window_secs: u64,
    pub track_by: String,
}

#[derive(Deserialize, Serialize)]
pub struct IdsRuleResponse {
    pub id: String,
    pub description: String,
    pub severity: String,
    pub mode: String,
    pub protocol: String,
    pub dst_port: Option<u16>,
    pub pattern: String,
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<IdsThresholdResponse>,
    /// Present only when another rule holds a kernel map slot this rule also claims.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_slot: Option<SlotContentionResponse>,
}

// ── GeoIP ───────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct GeoIpStatusResponse {
    pub enabled: bool,
    /// A database is loaded and answering.
    pub ready: bool,
}

#[derive(Deserialize, Serialize)]
pub struct GeoIpLookupResponse {
    pub ip: String,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
}

// ── DLP ──────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct DlpStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub pattern_count: usize,
}

#[derive(Deserialize, Serialize)]
pub struct DlpPatternResponse {
    pub id: String,
    pub name: String,
    pub regex: String,
    pub severity: String,
    pub data_type: String,
    pub enabled: bool,
}

// ── TLS ──────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct TlsStatusResponse {
    /// The request that asked reached the agent over TLS.
    pub tls: bool,
    pub negotiated_group: Option<String>,
    /// The negotiated group is a post-quantum hybrid.
    pub post_quantum: bool,
}

// ── Aliases ──────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct AliasStatusResponse {
    pub alias_count: usize,
}

// ── eBPF inventory ───────────────────────────

/// One uprobe the DLP module currently holds a link for.
#[derive(Deserialize, Serialize)]
pub struct UprobeEntry {
    pub lib: String,
    pub path: String,
    pub dev: u64,
    pub ino: u64,
    pub program: String,
    pub symbol: String,
    pub offset: u64,
    pub retprobe: bool,
    pub brokered: bool,
    pub sticky: bool,
}

#[derive(Deserialize, Serialize)]
pub struct UprobeInventoryResponse {
    pub libraries: usize,
    pub probes: Vec<UprobeEntry>,
}

#[derive(Deserialize, Serialize)]
pub struct ProgramTypeSupport {
    pub program_type: String,
    pub supported: bool,
}

#[derive(Deserialize, Serialize)]
pub struct HelperSupportEntry {
    pub program_type: String,
    pub helper: String,
    pub supported: bool,
}

#[derive(Deserialize, Serialize)]
pub struct MissingHelperEntry {
    pub object: String,
    pub program_type: String,
    pub helper: String,
    pub detail: String,
}

/// What the kernel answered when the agent probed it at startup.
///
/// `probed = false` means the probe could not run, not that the kernel lacks
/// anything: nothing was measured, and `reason` says why.
#[derive(Deserialize, Serialize)]
pub struct KernelFeaturesResponse {
    pub probed: bool,
    pub reason: Option<String>,
    pub load_mode: String,
    pub program_types: Vec<ProgramTypeSupport>,
    pub helpers: Vec<HelperSupportEntry>,
    pub missing_required: Vec<MissingHelperEntry>,
}

// ── Operations ───────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct ReloadResponse {
    pub status: String,
    pub message: String,
}

// ── Threat intelligence URLs ────────────────────

#[derive(Deserialize, Serialize)]
pub struct UrlIocResponse {
    pub url: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: String,
}

#[derive(Deserialize, Serialize)]
pub struct RefreshResponse {
    pub status: String,
    pub message: String,
}

// ── IPS blacklist mutation ─────────────────────

#[derive(Deserialize, Serialize)]
pub struct BlacklistMutationResponse {
    pub ip: String,
    pub reason: String,
    pub ttl_remaining_secs: u64,
}

// ── JA4S ────────────────────────────────────

#[derive(Deserialize, Serialize)]
pub struct Ja4sSummaryResponse {
    pub cached_count: usize,
    pub max_size: usize,
    pub ttl_seconds: u64,
    pub persistent: bool,
}

// ── Conntrack flush ──────────────────────────

#[derive(Deserialize, Serialize)]
pub struct ConnTrackFlushResponse {
    pub flushed: usize,
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
            .tcp_nodelay(true)
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(4)
            .build()
            .expect("failed to build HTTP client");
        let stream_client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(STREAM_READ_TIMEOUT_SECS))
            .tcp_nodelay(true)
            .build()
            .expect("failed to build streaming HTTP client");
        Self {
            client,
            stream_client,
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

    /// Same as [`Self::request`] but on the deadline-free client, for the
    /// routes whose answer is a stream rather than a body.
    fn stream_request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let mut req = self
            .stream_client
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
        // readyz returns 503 with valid JSON when eBPF is not loaded (degraded mode).
        // Accept both 200 and 503 as valid responses.
        resp.json::<ReadyResponse>()
            .await
            .context("failed to parse readyz response")
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

    /// `GET /api/v1/agent/identity` — operator-managed metadata.
    pub async fn get_identity(&self) -> anyhow::Result<AgentIdentityResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/agent/identity")
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

    #[allow(clippy::too_many_arguments)]
    pub async fn list_alerts(
        &self,
        component: Option<&str>,
        severity: Option<&str>,
        tactic: Option<&str>,
        technique: Option<&str>,
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
        if let Some(t) = tactic {
            req = req.query(&[("tactic", t)]);
        }
        if let Some(t) = technique {
            req = req.query(&[("technique", t)]);
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

    // ── MITRE ATT&CK ──────────────────────────────────────────────────

    pub async fn mitre_coverage(&self) -> anyhow::Result<MitreCoverageResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/mitre/coverage")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Captures ──────────────────────────────────────────────────────

    pub async fn start_capture(
        &self,
        filter: &str,
        duration_secs: u64,
        snap_length: u32,
        interface: Option<&str>,
    ) -> anyhow::Result<CaptureResponse> {
        let body = StartCaptureBody {
            filter: filter.to_string(),
            duration_seconds: duration_secs,
            snap_length,
            interface: interface.map(String::from),
        };
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/captures/manual")
            .json(&body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn stop_capture(&self, id: &str) -> anyhow::Result<CaptureResponse> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/api/v1/captures/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_captures(&self) -> anyhow::Result<CaptureListResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/captures")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Responses ─────────────────────────────────────────────────────

    pub async fn list_responses(&self) -> anyhow::Result<ResponseListResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/responses")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_response(
        &self,
        action: &str,
        target: &str,
        ttl: &str,
        rate_pps: Option<u64>,
    ) -> anyhow::Result<ResponseActionResponse> {
        let body = CreateResponseBody {
            action: action.to_string(),
            target: target.to_string(),
            ttl: ttl.to_string(),
            rate_pps,
        };
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/responses/manual")
            .json(&body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn revoke_response(&self, id: &str) -> anyhow::Result<ResponseActionResponse> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/api/v1/responses/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Fingerprints ──────────────────────────────────────────────────

    pub async fn fingerprint_summary(&self) -> anyhow::Result<FingerprintSummaryResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/fingerprints/summary")
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
        let mut req = self.request(reqwest::Method::GET, "/api/v1/domains/reputation");
        req = req.query(&[
            ("page", page.to_string()),
            ("page_size", page_size.to_string()),
        ]);
        if let Some(d) = domain {
            req = req.query(&[("domain", d)]);
        }
        if let Some(s) = min_score {
            req = req.query(&[("min_score", s.to_string())]);
        }
        let resp = req
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

    // ── Connection Tracking ─────────────────────────────────────────

    pub async fn conntrack_status(&self) -> anyhow::Result<ConnTrackStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/conntrack/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_connections(&self, limit: usize) -> anyhow::Result<Vec<ConnectionResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/conntrack/connections")
            .query(&[("limit", limit.to_string())])
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── eBPF Status ──────────────────────────────────────────────────

    pub async fn ebpf_status(&self) -> anyhow::Result<EbpfStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ebpf/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── DDoS Protection ──────────────────────────────────────────────

    pub async fn ddos_status(&self) -> anyhow::Result<DdosStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ddos/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn ddos_attacks(&self) -> anyhow::Result<Vec<DdosAttackResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ddos/attacks")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn ddos_history(&self, limit: usize) -> anyhow::Result<Vec<DdosAttackResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ddos/attacks/history")
            .query(&[("limit", limit.to_string())])
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn ddos_policies(&self) -> anyhow::Result<Vec<DdosPolicyResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ddos/policies")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_ddos_policy(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<DdosPolicyResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/ddos/policies")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_ddos_policy(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/ddos/policies/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
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

    // ── Load Balancer ──────────────────────────────────────────────

    pub async fn lb_status(&self) -> anyhow::Result<LbStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/lb/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_lb_services(&self) -> anyhow::Result<Vec<LbServiceResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/lb/services")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn get_lb_service(&self, id: &str) -> anyhow::Result<LbServiceDetailResponse> {
        let resp = self
            .request(reqwest::Method::GET, &format!("/api/v1/lb/services/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_lb_service(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<LbServiceResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/lb/services")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_lb_service(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/lb/services/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    pub async fn list_lb_vips(&self) -> anyhow::Result<LbVipStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/lb/vips")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn apply_lb_announce(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<LbVipStatusResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/lb/vips")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── QoS ────────────────────────────────────────────────────────

    pub async fn qos_status(&self) -> anyhow::Result<QosStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/qos/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_qos_pipes(&self) -> anyhow::Result<Vec<QosPipeResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/qos/pipes")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_qos_pipe(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<QosPipeResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/qos/pipes")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_qos_pipe(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/api/v1/qos/pipes/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    pub async fn list_qos_queues(&self) -> anyhow::Result<Vec<QosQueueResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/qos/queues")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_qos_queue(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<QosQueueResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/qos/queues")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_qos_queue(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/api/v1/qos/queues/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    pub async fn list_qos_classifiers(&self) -> anyhow::Result<Vec<QosClassifierResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/qos/classifiers")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_qos_classifier(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<QosClassifierResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/qos/classifiers")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_qos_classifier(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/qos/classifiers/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    // ── NAT ───────────────────────────────────────────────────────

    pub async fn nat_status(&self) -> anyhow::Result<NatStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/nat/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_nat_rules(&self) -> anyhow::Result<Vec<NatRuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/nat/rules")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_nptv6_rules(&self) -> anyhow::Result<Vec<NptV6RuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/nat/nptv6")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_nptv6_rule(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<NptV6RuleResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/nat/nptv6")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_nptv6_rule(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/api/v1/nat/nptv6/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    // ── Zones ───────────────────────────────────────────────────────

    pub async fn zone_status(&self) -> anyhow::Result<ZoneStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/zones/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_zones(&self) -> anyhow::Result<Vec<ZoneResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/zones")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_zone(&self, body: &serde_json::Value) -> anyhow::Result<ZoneResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/zones")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_zone(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(reqwest::Method::DELETE, &format!("/api/v1/zones/{id}"))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    pub async fn list_zone_policies(&self) -> anyhow::Result<Vec<ZonePolicyResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/zones/policies")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_zone_policy(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<ZonePolicyResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/zones/policies")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_zone_policy(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/zones/policies/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    // ── Policy routing ──────────────────────────────────────────────

    pub async fn routing_status(&self) -> anyhow::Result<RoutingStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/routing/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_gateways(&self) -> anyhow::Result<Vec<GatewayResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/routing/gateways")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn create_gateway(
        &self,
        body: &serde_json::Value,
    ) -> anyhow::Result<GatewayResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/routing/gateways")
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn delete_gateway(&self, id: &str) -> anyhow::Result<()> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/routing/gateways/{id}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_delete(resp).await
    }

    pub async fn list_routes(&self) -> anyhow::Result<Vec<RouteResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/routing/routes")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── IDS ─────────────────────────────────────────────────────────

    pub async fn ids_status(&self) -> anyhow::Result<IdsStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ids/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_ids_rules(&self) -> anyhow::Result<Vec<IdsRuleResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ids/rules")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── GeoIP ───────────────────────────────────────────────────────

    pub async fn geoip_status(&self) -> anyhow::Result<GeoIpStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/geoip/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn geoip_lookup(&self, ip: &str) -> anyhow::Result<GeoIpLookupResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/geoip/lookup")
            .query(&[("ip", ip)])
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── DLP ─────────────────────────────────────────────────────────

    pub async fn dlp_status(&self) -> anyhow::Result<DlpStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/dlp/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn list_dlp_patterns(&self) -> anyhow::Result<Vec<DlpPatternResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/dlp/patterns")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── TLS ─────────────────────────────────────────────────────────

    pub async fn tls_status(&self) -> anyhow::Result<TlsStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/tls/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Aliases ─────────────────────────────────────────────────────

    pub async fn alias_status(&self) -> anyhow::Result<AliasStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/aliases/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn set_alias_content(
        &self,
        id: &str,
        body: &serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .request(
                reqwest::Method::PUT,
                &format!("/api/v1/aliases/{id}/content"),
            )
            .json(body)
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── eBPF inventory ──────────────────────────────────────────────

    pub async fn list_uprobes(&self) -> anyhow::Result<UprobeInventoryResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ebpf/uprobes")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn kernel_features(&self) -> anyhow::Result<KernelFeaturesResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/ebpf/kernel-features")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Operations ──────────────────────────────────────────────────

    pub async fn get_config(&self) -> anyhow::Result<serde_json::Value> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/config")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn reload_config(&self) -> anyhow::Result<ReloadResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/config/reload")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Threat intelligence URLs and refresh ────────────────────────

    pub async fn list_url_iocs(&self) -> anyhow::Result<Vec<UrlIocResponse>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/threatintel/urls")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn refresh_feeds(&self, feed_id: Option<&str>) -> anyhow::Result<RefreshResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/threatintel/feeds/refresh")
            .json(&serde_json::json!({ "feed_id": feed_id }))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── IPS blacklist mutation ──────────────────────────────────────

    pub async fn add_blacklist_entry(
        &self,
        ip: &str,
        reason: Option<&str>,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<BlacklistMutationResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/ips/blacklist")
            .json(&serde_json::json!({
                "ip": ip,
                "reason": reason,
                "ttl_secs": ttl_secs,
            }))
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn remove_blacklist_entry(
        &self,
        ip: &str,
    ) -> anyhow::Result<BlacklistMutationResponse> {
        let resp = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api/v1/ips/blacklist/{ip}"),
            )
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── JA4S ────────────────────────────────────────────────────────

    pub async fn ja4s_summary(&self) -> anyhow::Result<Ja4sSummaryResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/fingerprints/ja4s")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── DNS status and conntrack flush ──────────────────────────────

    pub async fn dns_status(&self) -> anyhow::Result<DnsStatusResponse> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v1/dns/status")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    pub async fn conntrack_flush(&self) -> anyhow::Result<ConnTrackFlushResponse> {
        let resp = self
            .request(reqwest::Method::POST, "/api/v1/conntrack/flush")
            .send()
            .await
            .map_err(|e| connection_error(&self.base_url, &e))?;
        handle_response(resp).await
    }

    // ── Server-Sent Events ───────────────────────────────────────────

    /// Open the live alert stream. `resume_from` is the id of the last alert
    /// already printed; the agent replays what came after it from its own
    /// buffer, so a reconnect does not leave a hole.
    pub async fn stream_alerts(
        &self,
        component: Option<&str>,
        severity_min: Option<&str>,
        resume_from: Option<&str>,
    ) -> Result<SseStream, StreamOpenError> {
        let mut req = self.stream_request(reqwest::Method::GET, "/api/v1/alerts/stream");
        if let Some(component) = component {
            req = req.query(&[("component", component)]);
        }
        if let Some(severity_min) = severity_min {
            req = req.query(&[("severity_min", severity_min)]);
        }
        if let Some(resume_from) = resume_from {
            req = req.header("Last-Event-ID", resume_from);
        }
        self.open_stream(req, resume_from).await
    }

    /// Open the live conntrack lifecycle stream. The route answers 404 where
    /// the poller has nothing to read, which is what a kernel built without
    /// `CONFIG_NF_CONNTRACK_PROCFS` gives, so the caller falls back to polling
    /// the connection list rather than retrying for ever.
    pub async fn stream_conntrack_events(&self) -> Result<SseStream, StreamOpenError> {
        let req = self.stream_request(reqwest::Method::GET, "/api/v1/conntrack/events");
        self.open_stream(req, None).await
    }

    async fn open_stream(
        &self,
        req: reqwest::RequestBuilder,
        resume_from: Option<&str>,
    ) -> Result<SseStream, StreamOpenError> {
        let resp = req
            .header("Accept", "text/event-stream")
            .send()
            .await
            .map_err(|e| StreamOpenError::Failed(connection_error(&self.base_url, &e)))?;

        let status = resp.status();
        if status.is_success() {
            return Ok(SseStream {
                resp,
                buf: Vec::new(),
                last_id: resume_from.map(ToString::to_string),
            });
        }

        // 404 and 503 are both the server saying this build serves no such
        // stream. Every other status is a refusal of this request in
        // particular - a token that expired, a filter the server rejected -
        // and retrying it unchanged would loop on the same answer.
        let message = stream_error_message(resp).await;
        if matches!(
            status,
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::SERVICE_UNAVAILABLE
        ) {
            return Err(StreamOpenError::NotAvailable { message });
        }
        Err(StreamOpenError::Failed(anyhow::anyhow!(
            "{message} ({status})"
        )))
    }
}

/// How long a stream may stay silent before the client calls the connection
/// dead. The agent sends a keepalive comment every 15 seconds, so this is
/// three of them.
const STREAM_READ_TIMEOUT_SECS: u64 = 45;

/// Why a Server-Sent Events route could not be opened.
#[derive(Debug)]
pub enum StreamOpenError {
    /// The server answered and said it serves no such stream. Nothing about
    /// retrying will change that, so the caller degrades to polling.
    NotAvailable { message: String },
    /// Anything else: the agent is unreachable, the connection broke, the
    /// request was refused. Worth retrying, not worth degrading for.
    Failed(anyhow::Error),
}

impl std::fmt::Display for StreamOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAvailable { message } => f.write_str(message),
            Self::Failed(err) => write!(f, "{err}"),
        }
    }
}

/// One Server-Sent Event, assembled from the `id:`, `event:` and `data:`
/// lines of a frame. Comment lines - which is what the keepalive is - are
/// consumed by the reader and never surface here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    pub id: Option<String>,
    pub name: Option<String>,
    pub data: String,
}

/// A live Server-Sent Events response, read one frame at a time.
pub struct SseStream {
    resp: reqwest::Response,
    buf: Vec<u8>,
    last_id: Option<String>,
}

impl SseStream {
    /// The id of the last event that carried one, which a reconnect passes
    /// back as `Last-Event-ID` to resume where this stream stopped.
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_id.as_deref()
    }

    /// The next event, or `None` when the server closed the stream.
    pub async fn next_event(&mut self) -> anyhow::Result<Option<SseEvent>> {
        loop {
            while let Some(frame) = take_frame(&mut self.buf) {
                if let Some(event) = parse_frame(&frame) {
                    if let Some(ref id) = event.id {
                        self.last_id = Some(id.clone());
                    }
                    return Ok(Some(event));
                }
            }
            match self.resp.chunk().await {
                Ok(Some(bytes)) => self.buf.extend_from_slice(&bytes),
                Ok(None) => return Ok(None),
                Err(e) => bail!("stream read failed: {e}"),
            }
        }
    }
}

/// Read whatever the server put in the body of a refusal, so the caller can
/// say why rather than only which status.
async fn stream_error_message(resp: reqwest::Response) -> String {
    let status = resp.status();
    match resp.json::<ApiErrorBody>().await {
        Ok(body) => body.error.message,
        Err(_) => format!("request failed with status {status}"),
    }
}

/// Cut the first complete frame out of the buffer. A frame ends at the first
/// blank line; the terminator goes with it. `None` means what is buffered is
/// still a partial frame.
fn take_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    for i in 0..buf.len() {
        if buf[i] != b'\n' {
            continue;
        }
        // A blank line is LF LF, or LF CR LF where the server writes CRLF.
        let terminator = match (buf.get(i + 1), buf.get(i + 2)) {
            (Some(b'\n'), _) => i + 1,
            (Some(b'\r'), Some(b'\n')) => i + 2,
            _ => continue,
        };
        let frame = buf[..i].to_vec();
        buf.drain(..=terminator);
        return Some(frame);
    }
    None
}

/// Assemble one frame's fields. Returns `None` for a frame carrying nothing
/// but comments, which is what a keepalive is.
fn parse_frame(frame: &[u8]) -> Option<SseEvent> {
    let text = String::from_utf8_lossy(frame);
    let mut event = SseEvent::default();
    let mut data = String::new();
    let mut carries_a_field = false;

    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = match line.find(':') {
            Some(at) => {
                let value = &line[at + 1..];
                (&line[..at], value.strip_prefix(' ').unwrap_or(value))
            }
            None => (line, ""),
        };
        match field {
            "id" => {
                event.id = Some(value.to_string());
                carries_a_field = true;
            }
            "event" => {
                event.name = Some(value.to_string());
                carries_a_field = true;
            }
            "data" => {
                if !data.is_empty() {
                    data.push('\n');
                }
                data.push_str(value);
                carries_a_field = true;
            }
            // `retry` and anything else the spec adds later: the reconnect
            // delay here is the caller's backoff, not the server's suggestion.
            _ => {}
        }
    }

    if !carries_a_field {
        return None;
    }
    event.data = data;
    Some(event)
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    /// Routes the command tree deliberately does not call, and why. A route
    /// listed here is a decision somebody wrote down; a route missing from
    /// both the client and this list is an oversight the test below catches.
    /// Empty on purpose: the two Server-Sent Events routes that used to sit
    /// here are consumed by `watch` and `conntrack watch`, so every mounted
    /// route is now reached from a command.
    const UNREACHED_ROUTES: &[(&str, &str, &str)] = &[];

    /// Collapse `{id}` and friends so a path with a parameter compares equal
    /// however the two sides spell the placeholder.
    fn normalise(path: &str) -> String {
        let path = path.split('?').next().unwrap_or(path);
        let mut out = String::with_capacity(path.len());
        let mut depth = 0usize;
        for ch in path.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    if depth == 1 {
                        out.push_str("{}");
                    }
                }
                '}' => depth = depth.saturating_sub(1),
                _ if depth == 0 => out.push(ch),
                _ => {}
            }
        }
        out
    }

    /// Every `/api/v1` operation the checked-in document describes. The
    /// document is pinned to the mounted router in both directions by the
    /// router's own suite, and CI fails when it drifts from the annotations,
    /// so reading it here is reading the mounted surface.
    fn documented_api_routes() -> BTreeSet<(String, String)> {
        let spec: serde_json::Value = serde_json::from_str(include_str!("../../../openapi.json"))
            .expect("openapi.json is valid JSON");
        let paths = spec["paths"]
            .as_object()
            .expect("openapi.json carries a paths object");

        let mut pairs = BTreeSet::new();
        for (path, item) in paths {
            if !path.starts_with("/api/v1") {
                continue;
            }
            let item = item.as_object().expect("a path item is an object");
            for method in item.keys() {
                let upper = method.to_uppercase();
                if matches!(
                    upper.as_str(),
                    "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS"
                ) {
                    pairs.insert((upper, normalise(path)));
                }
            }
        }
        pairs
    }

    /// The shipped half of this file, so a route named in this test module is
    /// not mistaken for a route the client calls.
    fn shipped_source() -> &'static str {
        let src = include_str!("api_client.rs");
        &src[..src.find("#[cfg(test)]").expect("test module marker")]
    }

    /// Every method and path pair this client requests. Each call is written
    /// as `request(Method::X, "<literal>")`, so the literal that follows the
    /// verb is the route. A call whose path is built somewhere else has no
    /// literal to find, which `every_request_names_its_route` refuses.
    fn requested_routes() -> BTreeSet<(String, String)> {
        let mut pairs = BTreeSet::new();
        for (method, literal) in request_sites() {
            if let Some(literal) = literal {
                pairs.insert((method, normalise(&literal)));
            }
        }
        pairs
    }

    /// One entry per `reqwest::Method::` occurrence: the verb, and the string
    /// literal that follows it before the next call boundary, if there is one.
    fn request_sites() -> Vec<(String, Option<String>)> {
        const MARKER: &str = "reqwest::Method::";
        let src = shipped_source();
        let mut sites = Vec::new();
        let mut from = 0usize;

        while let Some(rel) = src[from..].find(MARKER) {
            let at = from + rel;
            let after = at + MARKER.len();
            let verb: String = src[after..]
                .chars()
                .take_while(char::is_ascii_uppercase)
                .collect();
            let rest = &src[after + verb.len()..];

            // The literal, if any, sits between the comma and the closing
            // paren of this one call. Stop at the paren so the next call's
            // literal is never attributed to this verb.
            let end = rest.find(')').unwrap_or(rest.len());
            let head = &rest[..end];
            let literal = head.find('"').and_then(|open| {
                head[open + 1..]
                    .find('"')
                    .map(|close| head[open + 1..open + 1 + close].to_string())
            });

            sites.push((verb, literal));
            from = after;
        }
        sites
    }

    #[test]
    fn every_request_names_its_route() {
        let anonymous: Vec<String> = request_sites()
            .into_iter()
            .filter(|(_, literal)| literal.is_none())
            .map(|(verb, _)| verb)
            .collect();
        assert!(
            anonymous.is_empty(),
            "a request builds its path away from the verb, so route coverage \
             cannot see it: {anonymous:?}. Pass the route as a literal and put \
             the parameters on `query`."
        );
    }

    #[test]
    fn the_client_reaches_every_mounted_route() {
        let documented = documented_api_routes();
        assert!(
            documented.len() > 90,
            "the document describes only {} operations under /api/v1, which \
             means it failed to load",
            documented.len()
        );

        let exempt: BTreeSet<(String, String)> = UNREACHED_ROUTES
            .iter()
            .map(|(method, path, _)| ((*method).to_string(), normalise(path)))
            .collect();

        let reachable: BTreeSet<(String, String)> =
            requested_routes().union(&exempt).cloned().collect();

        let unreachable: Vec<String> = documented
            .difference(&reachable)
            .map(|(method, path)| format!("{method} {path}"))
            .collect();

        assert!(
            unreachable.is_empty(),
            "mounted but reachable from no command, and carried on no \
             exemption: {unreachable:?}"
        );
    }

    #[test]
    fn every_exemption_is_a_route_that_exists() {
        let documented = documented_api_routes();
        for (method, path, reason) in UNREACHED_ROUTES {
            assert!(
                documented.contains(&((*method).to_string(), normalise(path))),
                "{method} {path} is exempted from the command tree but is \
                 mounted nowhere, so the exemption outlived its route"
            );
            assert!(
                reason.len() > 30,
                "{method} {path} is exempted without saying why"
            );
        }
    }

    #[test]
    fn a_frame_carries_its_id_event_and_data() {
        let mut buf = b"id: alert-7\nevent: alert\ndata: {\"id\":\"alert-7\"}\n\n".to_vec();
        let frame = super::take_frame(&mut buf).expect("one complete frame");
        assert!(buf.is_empty(), "the terminator goes with the frame");
        let event = super::parse_frame(&frame).expect("the frame carries fields");
        assert_eq!(event.id.as_deref(), Some("alert-7"));
        assert_eq!(event.name.as_deref(), Some("alert"));
        assert_eq!(event.data, "{\"id\":\"alert-7\"}");
    }

    #[test]
    fn a_partial_frame_waits_for_the_rest() {
        let mut buf = b"event: alert\ndata: {\"id\":\"al".to_vec();
        let before = buf.len();
        assert!(super::take_frame(&mut buf).is_none());
        assert_eq!(buf.len(), before, "nothing was consumed");

        buf.extend_from_slice(b"ert-7\"}\n\n");
        let frame = super::take_frame(&mut buf).expect("the frame completed");
        let event = super::parse_frame(&frame).expect("fields");
        assert_eq!(event.data, "{\"id\":\"alert-7\"}");
    }

    #[test]
    fn a_keepalive_comment_is_not_an_event() {
        let mut buf = b":keepalive\n\n".to_vec();
        let frame = super::take_frame(&mut buf).expect("a complete frame");
        assert!(
            super::parse_frame(&frame).is_none(),
            "a frame of nothing but comments is the keepalive, not an event"
        );
    }

    #[test]
    fn two_frames_come_out_one_at_a_time() {
        let mut buf = b"data: one\n\ndata: two\n\n".to_vec();
        let first = super::parse_frame(&super::take_frame(&mut buf).expect("first")).expect("a");
        assert_eq!(first.data, "one");
        let second = super::parse_frame(&super::take_frame(&mut buf).expect("second")).expect("b");
        assert_eq!(second.data, "two");
        assert!(super::take_frame(&mut buf).is_none());
    }

    #[test]
    fn carriage_returns_are_a_line_ending_and_not_content() {
        let mut buf = b"event: new\r\ndata: {}\r\n\r\n".to_vec();
        let frame = super::take_frame(&mut buf).expect("a complete frame");
        assert!(buf.is_empty());
        let event = super::parse_frame(&frame).expect("fields");
        assert_eq!(event.name.as_deref(), Some("new"));
        assert_eq!(event.data, "{}");
    }

    #[test]
    fn several_data_lines_join_with_a_newline() {
        let mut buf = b"data: one\ndata: two\n\n".to_vec();
        let frame = super::take_frame(&mut buf).expect("a complete frame");
        let event = super::parse_frame(&frame).expect("fields");
        assert_eq!(event.data, "one\ntwo");
    }

    #[test]
    fn a_frame_split_across_a_multibyte_character_is_not_corrupted() {
        // A chunk boundary can land inside a UTF-8 sequence, which is why the
        // reader buffers bytes and decodes a whole frame rather than decoding
        // every chunk as it arrives.
        let whole = "data: caf\u{e9}\n\n".as_bytes().to_vec();
        let split = whole.len() - 3; // inside the two bytes of the accent
        let mut buf = whole[..split].to_vec();
        assert!(super::take_frame(&mut buf).is_none());
        buf.extend_from_slice(&whole[split..]);
        let frame = super::take_frame(&mut buf).expect("the frame completed");
        assert_eq!(
            super::parse_frame(&frame).expect("fields").data,
            "caf\u{e9}"
        );
    }

    #[test]
    fn an_alert_frame_parses_into_the_shape_the_printer_reads() {
        // The stream serialises the agent's own alert record, so the severity
        // and the action arrive capitalised and the addresses as an array.
        let body = serde_json::json!({
            "id": "alert-1",
            "timestamp_ns": 1_700_000_000_000_000_000u64,
            "component": "ids",
            "severity": "High",
            "rule_id": "ids-001",
            "action": "Alert",
            "src_addr": [0xC0A8_0001u32, 0, 0, 0],
            "dst_addr": [0x0A00_0001u32, 0, 0, 0],
            "src_port": 4444,
            "dst_port": 80,
            "protocol": 6,
            "is_ipv6": false,
            "message": "signature match",
            "mitre_attack": { "technique_id": "T1071" },
        })
        .to_string();

        let alert: super::AlertResponse =
            serde_json::from_str(&body).expect("the frame body is an alert");
        assert_eq!(alert.id, "alert-1");
        assert_eq!(alert.severity, "High");
        assert_eq!(alert.src_ip_str(), "192.168.0.1");
        assert_eq!(alert.dst_ip_str(), "10.0.0.1");
        assert!(!alert.false_positive, "an absent field takes its default");
    }

    #[test]
    fn a_conntrack_frame_parses_into_an_event_and_a_connection() {
        let body = serde_json::json!({
            "event_type": "New",
            "connection": {
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.3",
                "src_port": 51_000,
                "dst_port": 443,
                "protocol": 6,
                "state": "Established",
                "packets_fwd": 3,
                "packets_rev": 2,
                "bytes_fwd": 300,
                "bytes_rev": 200,
                "first_seen_ns": 1u64,
                "last_seen_ns": 2u64,
            },
        })
        .to_string();

        let frame: super::ConntrackEventFrame =
            serde_json::from_str(&body).expect("the frame body is a conntrack event");
        assert_eq!(frame.event_type, "New");
        assert_eq!(frame.connection.src_ip, "10.0.0.2");
        assert_eq!(frame.connection.dst_port, 443);
    }

    /// Serve `app` on a loopback port and hand back a client pointed at it.
    async fn client_for(app: axum::Router) -> super::ApiClient {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("the bound address").port();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        super::ApiClient::new("127.0.0.1", port, None)
    }

    #[tokio::test]
    async fn the_client_reads_a_live_stream_frame_by_frame() {
        use axum::response::sse::{Event, Sse};
        use axum::routing::get;

        async fn stream()
        -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>> {
            let events = vec![
                Ok(Event::default().comment("keepalive")),
                Ok(Event::default()
                    .id("alert-1")
                    .event("alert")
                    .data("{\"n\":1}")),
                Ok(Event::default()
                    .id("alert-2")
                    .event("alert")
                    .data("{\"n\":2}")),
            ];
            Sse::new(tokio_stream::iter(events))
        }

        let app = axum::Router::new().route("/api/v1/alerts/stream", get(stream));
        let client = client_for(app).await;

        let mut stream = client
            .stream_alerts(None, None, None)
            .await
            .expect("the stream opened");

        let first = stream
            .next_event()
            .await
            .expect("a read")
            .expect("an event");
        assert_eq!(
            first.id.as_deref(),
            Some("alert-1"),
            "the keepalive is not an event"
        );
        assert_eq!(first.name.as_deref(), Some("alert"));
        assert_eq!(first.data, "{\"n\":1}");

        let second = stream
            .next_event()
            .await
            .expect("a read")
            .expect("an event");
        assert_eq!(second.id.as_deref(), Some("alert-2"));

        assert!(
            stream.next_event().await.expect("a read").is_none(),
            "the server closed the stream"
        );
        assert_eq!(
            stream.last_event_id(),
            Some("alert-2"),
            "a reconnect resumes after the last event that carried an id"
        );
    }

    #[tokio::test]
    async fn a_reconnect_hands_back_the_last_event_id() {
        use axum::http::HeaderMap;
        use axum::response::sse::{Event, Sse};
        use axum::routing::get;

        async fn stream(
            headers: HeaderMap,
        ) -> Sse<impl tokio_stream::Stream<Item = Result<Event, std::convert::Infallible>>>
        {
            let seen = headers
                .get("last-event-id")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            Sse::new(tokio_stream::iter(vec![Ok(Event::default().data(seen))]))
        }

        let app = axum::Router::new().route("/api/v1/alerts/stream", get(stream));
        let client = client_for(app).await;

        let mut stream = client
            .stream_alerts(None, None, Some("alert-9"))
            .await
            .expect("the stream opened");
        let event = stream
            .next_event()
            .await
            .expect("a read")
            .expect("an event");
        assert_eq!(event.data, "alert-9");
    }

    #[tokio::test]
    async fn a_404_is_the_answer_that_makes_the_caller_poll() {
        use axum::http::StatusCode;
        use axum::routing::get;

        async fn refuse() -> (StatusCode, axum::Json<serde_json::Value>) {
            (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "error": {
                        "code": "SERVICE_NOT_AVAILABLE",
                        "message": "Conntrack event stream not enabled",
                    }
                })),
            )
        }

        let app = axum::Router::new().route("/api/v1/conntrack/events", get(refuse));
        let client = client_for(app).await;

        match client.stream_conntrack_events().await {
            Err(super::StreamOpenError::NotAvailable { message }) => {
                assert_eq!(message, "Conntrack event stream not enabled");
            }
            Err(other) => panic!("a 404 must degrade to polling, got {other}"),
            Ok(_) => panic!("a 404 is not an open stream"),
        }
    }

    #[tokio::test]
    async fn a_refusal_that_is_not_about_the_stream_is_worth_retrying() {
        use axum::http::StatusCode;
        use axum::routing::get;

        async fn refuse() -> (StatusCode, axum::Json<serde_json::Value>) {
            (
                StatusCode::UNAUTHORIZED,
                axum::Json(serde_json::json!({
                    "error": { "code": "UNAUTHORIZED", "message": "Authentication required" }
                })),
            )
        }

        let app = axum::Router::new().route("/api/v1/alerts/stream", get(refuse));
        let client = client_for(app).await;

        match client.stream_alerts(None, None, None).await {
            Err(super::StreamOpenError::Failed(e)) => {
                let said = e.to_string();
                assert!(said.contains("Authentication required"), "said {said}");
            }
            Err(other) => panic!("a 401 is not the server saying it has no stream: {other}"),
            Ok(_) => panic!("a 401 is not an open stream"),
        }
    }

    #[test]
    fn no_exemption_is_also_called() {
        let requested = requested_routes();
        for (method, path, _) in UNREACHED_ROUTES {
            assert!(
                !requested.contains(&((*method).to_string(), normalise(path))),
                "{method} {path} is called by the client and exempted at the \
                 same time, so the exemption is stale"
            );
        }
    }
}
