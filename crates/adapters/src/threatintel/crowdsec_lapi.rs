//! Writes signals to a CrowdSec local API as a registered machine.
//!
//! The local API accepts alerts only from a machine (`cscli machines add`),
//! which logs in with its identifier and password for a short-lived token.
//! The token is kept in memory, never on disk, and a refused one is replaced
//! by logging in again once before the window is given up.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use domain::common::error::DomainError;
use domain::flow::siem::rfc3339_millis;
use domain::threatintel::crowdsec::Signal;
use ports::secondary::signal_report_port::SignalReportPort;
use serde_json::{Value, json};
use tokio::sync::Mutex;

/// Version written beside every scenario this agent reports.
const SCENARIO_VERSION: &str = "1.0";

/// The body of `POST /v1/alerts` for one window of signals.
///
/// Each signal becomes one alert whose only source is the blocked address.
/// When `decision_duration` is set the alert also carries a ban of that
/// length, which the local API hands to every bouncer it serves; absent, the
/// alert is recorded and decides nothing.
#[must_use]
pub fn alerts_body(signals: &[Signal], decision_duration: Option<&str>) -> Value {
    let alerts: Vec<Value> = signals
        .iter()
        .map(|s| {
            let ip = s.source.to_string();
            let start = rfc3339_millis(s.first_ns / 1_000_000);
            let stop = rfc3339_millis(s.last_ns / 1_000_000);
            let message = format!("{ip} blocked {} times by {}", s.count, s.scenario);
            let mut alert = json!({
                "scenario": s.scenario,
                "scenario_hash": "",
                "scenario_version": SCENARIO_VERSION,
                "message": message,
                "events_count": s.count,
                "start_at": start,
                "stop_at": stop,
                "capacity": 0,
                "leakspeed": "0",
                "simulated": false,
                "events": [{
                    "timestamp": stop,
                    "meta": [{ "key": "source_ip", "value": ip }],
                }],
                "source": { "scope": "Ip", "value": ip, "ip": ip },
            });
            if let Some(duration) = decision_duration {
                alert["decisions"] = json!([{
                    "duration": duration,
                    "origin": "ebpfsentinel",
                    "scenario": s.scenario,
                    "scope": "Ip",
                    "type": "ban",
                    "value": ip,
                }]);
            }
            alert
        })
        .collect();
    Value::Array(alerts)
}

/// A machine registered against a CrowdSec local API.
pub struct LapiSignalReporter {
    client: reqwest::Client,
    base_url: String,
    machine_id: String,
    password: String,
    decision_duration: Option<String>,
    token: Mutex<Option<String>>,
}

impl LapiSignalReporter {
    /// A reporter for the local API at `base_url` (no trailing path).
    ///
    /// The client follows no redirect: the local API is named by the operator
    /// and must not be able to send the machine's password anywhere else.
    pub fn new(
        base_url: &str,
        machine_id: String,
        password: String,
        decision_duration: Option<String>,
    ) -> Result<Self, DomainError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .user_agent("ebpfsentinel-agent/0.1")
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| DomainError::EngineError(format!("HTTP client init failed: {e}")))?;
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            machine_id,
            password,
            decision_duration,
            token: Mutex::new(None),
        })
    }

    async fn login(&self) -> Result<String, DomainError> {
        let response = self
            .client
            .post(format!("{}/v1/watchers/login", self.base_url))
            .json(&json!({
                "machine_id": self.machine_id,
                "password": self.password,
                "scenarios": [],
            }))
            .send()
            .await
            .map_err(|e| DomainError::EngineError(format!("CrowdSec login failed: {e}")))?;
        if !response.status().is_success() {
            return Err(DomainError::EngineError(format!(
                "CrowdSec login refused: HTTP {}",
                response.status()
            )));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|e| DomainError::EngineError(format!("CrowdSec login answer: {e}")))?;
        body.get("token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .ok_or_else(|| DomainError::EngineError("CrowdSec login carried no token".to_string()))
    }

    async fn push(&self, token: &str, body: &Value) -> Result<reqwest::StatusCode, DomainError> {
        let response = self
            .client
            .post(format!("{}/v1/alerts", self.base_url))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(|e| DomainError::EngineError(format!("CrowdSec alert push failed: {e}")))?;
        Ok(response.status())
    }

    async fn report_window(&self, signals: &[Signal]) -> Result<(), DomainError> {
        let body = alerts_body(signals, self.decision_duration.as_deref());
        let mut token = self.token.lock().await;
        let mut fresh = false;
        if token.is_none() {
            *token = Some(self.login().await?);
            fresh = true;
        }
        loop {
            let current = token.clone().unwrap_or_default();
            let status = self.push(&current, &body).await?;
            if status.is_success() {
                return Ok(());
            }
            if status == reqwest::StatusCode::UNAUTHORIZED && !fresh {
                *token = None;
                *token = Some(self.login().await?);
                fresh = true;
                continue;
            }
            if status == reqwest::StatusCode::UNAUTHORIZED {
                *token = None;
            }
            return Err(DomainError::EngineError(format!(
                "CrowdSec refused the alerts: HTTP {status}"
            )));
        }
    }
}

impl SignalReportPort for LapiSignalReporter {
    fn report<'a>(
        &'a self,
        signals: &'a [Signal],
    ) -> Pin<Box<dyn Future<Output = Result<(), DomainError>> + Send + 'a>> {
        Box::pin(self.report_window(signals))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn signal() -> Signal {
        Signal {
            source: "203.0.113.1".parse().unwrap(),
            scenario: "ebpfsentinel/ids".to_string(),
            count: 3,
            first_ns: 1_700_000_000_000_000_000,
            last_ns: 1_700_000_060_000_000_000,
        }
    }

    #[test]
    fn the_body_carries_the_source_and_nothing_else_about_the_host() {
        let body = alerts_body(&[signal()], None);
        let alert = &body[0];
        assert_eq!(alert["scenario"], "ebpfsentinel/ids");
        assert_eq!(alert["events_count"], 3);
        assert_eq!(alert["source"]["value"], "203.0.113.1");
        assert_eq!(alert["start_at"], "2023-11-14T22:13:20.000Z");
        assert_eq!(alert["stop_at"], "2023-11-14T22:14:20.000Z");
        assert!(alert.get("decisions").is_none());
        let text = body.to_string();
        assert!(!text.contains("10.0.0.1"));
    }

    #[test]
    fn a_decision_duration_adds_a_ban() {
        let body = alerts_body(&[signal()], Some("4h"));
        let decision = &body[0]["decisions"][0];
        assert_eq!(decision["type"], "ban");
        assert_eq!(decision["duration"], "4h");
        assert_eq!(decision["value"], "203.0.113.1");
    }

    #[derive(Default)]
    struct Lapi {
        logins: AtomicUsize,
        pushes: AtomicUsize,
        refuse_first_push: bool,
    }

    async fn login(State(lapi): State<Arc<Lapi>>) -> axum::Json<Value> {
        let n = lapi.logins.fetch_add(1, Ordering::SeqCst);
        axum::Json(json!({ "code": 200, "expire": "x", "token": format!("t{}", n + 1) }))
    }

    async fn alerts(
        State(lapi): State<Arc<Lapi>>,
        headers: HeaderMap,
        axum::Json(body): axum::Json<Value>,
    ) -> StatusCode {
        lapi.pushes.fetch_add(1, Ordering::SeqCst);
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if lapi.refuse_first_push && auth == "Bearer t0" {
            return StatusCode::UNAUTHORIZED;
        }
        assert_eq!(body[0]["source"]["value"], "203.0.113.1");
        StatusCode::CREATED
    }

    async fn serve(lapi: Arc<Lapi>) -> String {
        let app = Router::new()
            .route("/v1/watchers/login", post(login))
            .route("/v1/alerts", post(alerts))
            .with_state(lapi);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn logs_in_once_and_reuses_the_token() {
        let lapi = Arc::new(Lapi::default());
        let url = serve(Arc::clone(&lapi)).await;
        let reporter =
            LapiSignalReporter::new(&url, "agent".to_string(), "pw".to_string(), None).unwrap();
        reporter.report(&[signal()]).await.unwrap();
        reporter.report(&[signal()]).await.unwrap();
        assert_eq!(lapi.logins.load(Ordering::SeqCst), 1);
        assert_eq!(lapi.pushes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_expired_token_is_replaced_once() {
        let lapi = Arc::new(Lapi {
            refuse_first_push: true,
            ..Lapi::default()
        });
        let url = serve(Arc::clone(&lapi)).await;
        let reporter =
            LapiSignalReporter::new(&url, "agent".to_string(), "pw".to_string(), None).unwrap();
        // The agent holds t0, which the push refuses: a stale token
        // is what a restarted local API leaves the agent holding.
        *reporter.token.lock().await = Some("t0".to_string());
        reporter.report(&[signal()]).await.unwrap();
        assert_eq!(lapi.logins.load(Ordering::SeqCst), 1);
        assert_eq!(lapi.pushes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn an_unreachable_api_is_an_error_not_a_panic() {
        let reporter = LapiSignalReporter::new(
            "http://127.0.0.1:9",
            "agent".to_string(),
            "pw".to_string(),
            None,
        )
        .unwrap();
        assert!(reporter.report(&[signal()]).await.is_err());
    }
}
