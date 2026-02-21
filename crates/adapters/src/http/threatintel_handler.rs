use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use serde::Serialize;
use utoipa::ToSchema;

use super::state::AppState;

// ── Response DTOs ───────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct ThreatIntelStatusResponse {
    pub enabled: bool,
    pub mode: String,
    pub ioc_count: usize,
    pub feed_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct IocResponse {
    pub ip: String,
    pub feed_id: String,
    pub confidence: u8,
    pub threat_type: String,
    pub source_feed: String,
}

#[derive(Serialize, ToSchema)]
pub struct FeedResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub format: String,
    pub enabled: bool,
    pub refresh_interval_secs: u64,
    pub max_iocs: usize,
    pub min_confidence: u8,
}

// ── Handlers ────────────────────────────────────────────────────────

/// `GET /api/v1/threatintel/status` — threat intel subsystem status.
#[utoipa::path(
    get, path = "/api/v1/threatintel/status",
    tag = "Threat Intelligence",
    responses((status = 200, description = "Threat intel subsystem status", body = ThreatIntelStatusResponse))
)]
pub async fn threatintel_status(
    State(state): State<Arc<AppState>>,
) -> Json<ThreatIntelStatusResponse> {
    let svc = state.threatintel_service.read().await;
    Json(ThreatIntelStatusResponse {
        enabled: svc.enabled(),
        mode: svc.mode().as_str().to_string(),
        ioc_count: svc.ioc_count(),
        feed_count: svc.list_feeds().len(),
    })
}

/// `GET /api/v1/threatintel/iocs` — list loaded IOCs.
#[utoipa::path(
    get, path = "/api/v1/threatintel/iocs",
    tag = "Threat Intelligence",
    responses((status = 200, description = "List of loaded IOCs", body = Vec<IocResponse>))
)]
pub async fn list_iocs(State(state): State<Arc<AppState>>) -> Json<Vec<IocResponse>> {
    let svc = state.threatintel_service.read().await;
    let iocs: Vec<IocResponse> = svc
        .engine()
        .all_iocs()
        .map(|ioc| IocResponse {
            ip: ioc.ip.to_string(),
            feed_id: ioc.feed_id.clone(),
            confidence: ioc.confidence,
            threat_type: ioc.threat_type.to_string(),
            source_feed: ioc.source_feed.clone(),
        })
        .collect();
    Json(iocs)
}

/// `GET /api/v1/threatintel/feeds` — list configured feeds.
#[utoipa::path(
    get, path = "/api/v1/threatintel/feeds",
    tag = "Threat Intelligence",
    responses((status = 200, description = "List of configured feeds", body = Vec<FeedResponse>))
)]
pub async fn list_feeds(State(state): State<Arc<AppState>>) -> Json<Vec<FeedResponse>> {
    let svc = state.threatintel_service.read().await;
    let feeds: Vec<FeedResponse> = svc
        .list_feeds()
        .iter()
        .map(|f| FeedResponse {
            id: f.id.clone(),
            name: f.name.clone(),
            url: f.url.clone(),
            format: format!("{:?}", f.format).to_lowercase(),
            enabled: f.enabled,
            refresh_interval_secs: f.refresh_interval_secs,
            max_iocs: f.max_iocs,
            min_confidence: f.min_confidence,
        })
        .collect();
    Json(feeds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_response_serialization() {
        let resp = ThreatIntelStatusResponse {
            enabled: true,
            mode: "alert".to_string(),
            ioc_count: 42,
            feed_count: 3,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["enabled"], true);
        assert_eq!(json["mode"], "alert");
        assert_eq!(json["ioc_count"], 42);
        assert_eq!(json["feed_count"], 3);
    }

    #[test]
    fn ioc_response_serialization() {
        let resp = IocResponse {
            ip: "10.0.0.1".to_string(),
            feed_id: "alienvault-otx".to_string(),
            confidence: 90,
            threat_type: "c2".to_string(),
            source_feed: "AlienVault OTX".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["ip"], "10.0.0.1");
        assert_eq!(json["feed_id"], "alienvault-otx");
        assert_eq!(json["confidence"], 90);
        assert_eq!(json["threat_type"], "c2");
    }

    #[test]
    fn feed_response_serialization() {
        let resp = FeedResponse {
            id: "test".to_string(),
            name: "Test Feed".to_string(),
            url: "https://example.com".to_string(),
            format: "csv".to_string(),
            enabled: true,
            refresh_interval_secs: 3600,
            max_iocs: 500_000,
            min_confidence: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "test");
        assert_eq!(json["refresh_interval_secs"], 3600);
    }
}
