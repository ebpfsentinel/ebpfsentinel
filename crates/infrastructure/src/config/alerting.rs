//! Alerting domain configuration structs and conversion logic.

use domain::alert::entity::{AlertDestination, AlertRoute};
use serde::{Deserialize, Serialize};

use super::common::{ConfigError, default_true, parse_severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_dedup_window")]
    pub dedup_window_secs: u64,

    #[serde(default = "default_throttle_window")]
    pub throttle_window_secs: u64,

    #[serde(default = "default_throttle_max")]
    pub throttle_max: usize,

    #[serde(default)]
    pub smtp: Option<SmtpConfig>,

    #[serde(default)]
    pub otlp: Option<OtlpExportConfig>,

    #[serde(default = "default_alerting_routes")]
    pub routes: Vec<AlertRouteConfig>,
}

/// The wire an OTLP export travels on.
///
/// Two values and no third: the exporter has one branch per value, so a word
/// outside this set is a collector nobody is exporting to. It is parsed
/// rather than matched at the point of use, because a spelling that fell
/// through to gRPC was an estate that believed it was exporting over HTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtlpProtocol {
    /// OTLP over gRPC, the collector's 4317 port.
    Grpc,
    /// OTLP over HTTP with a protobuf body, the collector's 4318 port.
    Http,
}

impl OtlpProtocol {
    /// The two words an operator may write, in the order the error names them.
    pub const ACCEPTED: &'static str = "grpc, http";

    /// Parse a configured protocol, ignoring case. `None` for any word that
    /// is neither `grpc` nor `http`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "grpc" => Some(Self::Grpc),
            "http" => Some(Self::Http),
            _ => None,
        }
    }

    /// The word this protocol is written as.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::Http => "http",
        }
    }
}

/// OTLP export configuration for alert delivery via OpenTelemetry Protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtlpExportConfig {
    /// OTLP collector endpoint (e.g. `http://otel-collector:4317`).
    pub endpoint: String,
    /// Transport protocol: `grpc` (default) or `http`.
    #[serde(default = "default_otlp_protocol")]
    pub protocol: String,
    /// Export timeout in milliseconds.
    #[serde(default = "default_otlp_timeout_ms")]
    pub timeout_ms: u64,
    /// Headers sent with every export, which is how a hosted collector is
    /// authenticated. The value reaches the wire verbatim.
    #[serde(default)]
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// PEM bundle trusted in addition to the system roots, for a collector
    /// behind a private certificate authority.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Whether the collector's certificate is verified. Turning it off is
    /// only honoured on `http`, so the configuration refuses the pair rather
    /// than exporting to a verified collector an operator believed was not.
    #[serde(default = "default_true")]
    pub verify_tls: bool,
}

impl OtlpExportConfig {
    /// The protocol this block names.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidValue`] naming both accepted words when
    /// the configured protocol is neither of them.
    pub fn protocol(&self) -> Result<OtlpProtocol, ConfigError> {
        OtlpProtocol::parse(&self.protocol).ok_or_else(|| ConfigError::InvalidValue {
            field: "alerting.otlp.protocol".to_string(),
            value: self.protocol.clone(),
            expected: OtlpProtocol::ACCEPTED.to_string(),
        })
    }

    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        let endpoint = self.endpoint.trim();
        if endpoint.is_empty() {
            return Err(ConfigError::Validation {
                field: "alerting.otlp.endpoint".to_string(),
                message: "otlp export requires a collector endpoint".to_string(),
            });
        }
        // Both transports dial an HTTP origin: tonic builds its channel from
        // one and the HTTP exporter posts to one, so a scheme neither of them
        // can dial is a boot-time refusal rather than an export that never
        // leaves.
        let authority = endpoint
            .strip_prefix("http://")
            .or_else(|| endpoint.strip_prefix("https://"));
        match authority {
            Some(rest) if !rest.split('/').next().unwrap_or_default().is_empty() => {}
            _ => {
                return Err(ConfigError::Validation {
                    field: "alerting.otlp.endpoint".to_string(),
                    message: format!(
                        "collector endpoint must be http://host:port or https://host:port, got '{}'",
                        self.endpoint
                    ),
                });
            }
        }

        let protocol = self.protocol()?;

        for (name, value) in self.headers.iter().flatten() {
            validate_header(name, value).map_err(|message| ConfigError::Validation {
                field: "alerting.otlp.headers".to_string(),
                message,
            })?;
        }

        if let Some(path) = self.ca_cert.as_deref()
            && path.trim().is_empty()
        {
            return Err(ConfigError::Validation {
                field: "alerting.otlp.ca_cert".to_string(),
                message: "certificate authority path must not be empty".to_string(),
            });
        }

        if !self.verify_tls && protocol == OtlpProtocol::Grpc {
            return Err(ConfigError::Validation {
                field: "alerting.otlp.verify_tls".to_string(),
                message: "certificate verification can only be turned off on the http protocol"
                    .to_string(),
            });
        }

        Ok(())
    }
}

fn default_otlp_protocol() -> String {
    "grpc".to_string()
}

fn default_otlp_timeout_ms() -> u64 {
    5000
}

/// SMTP server configuration for email alert delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    pub from_address: String,
    #[serde(default = "default_true")]
    pub tls: bool,
}

fn default_smtp_port() -> u16 {
    587
}

fn default_dedup_window() -> u64 {
    60
}
fn default_throttle_window() -> u64 {
    300
}
fn default_throttle_max() -> usize {
    100
}
fn default_alerting_routes() -> Vec<AlertRouteConfig> {
    vec![AlertRouteConfig {
        name: "default-log".to_string(),
        destination: "log".to_string(),
        min_severity: "low".to_string(),
        event_types: None,
        webhook_url: None,
        email_to: None,
        webhook_headers: None,
    }]
}

impl Default for AlertingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dedup_window_secs: default_dedup_window(),
            throttle_window_secs: default_throttle_window(),
            throttle_max: default_throttle_max(),
            smtp: None,
            otlp: None,
            routes: default_alerting_routes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRouteConfig {
    pub name: String,
    pub destination: String,
    pub min_severity: String,
    pub event_types: Option<Vec<String>>,
    /// Webhook URL — required when `destination` is "webhook".
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Email recipient address — required when `destination` is "email".
    #[serde(default)]
    pub email_to: Option<String>,
    /// Optional custom HTTP headers for webhook requests.
    #[serde(default)]
    pub webhook_headers: Option<std::collections::HashMap<String, String>>,
}

impl AlertRouteConfig {
    pub(super) fn validate(
        &self,
        idx: usize,
        smtp_present: bool,
        otlp_present: bool,
    ) -> Result<(), ConfigError> {
        let prefix = format!("alerting.routes[{idx}]");

        if self.name.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.name"),
                message: "route name must not be empty".to_string(),
            });
        }

        parse_alert_destination(&self.destination).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.destination"),
            value: self.destination.clone(),
            expected: "log, email, webhook, otlp".to_string(),
        })?;

        parse_severity(&self.min_severity).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.min_severity"),
            value: self.min_severity.clone(),
            expected: "low, medium, high, critical".to_string(),
        })?;

        // Webhook routes require a webhook_url with http(s) scheme
        if self.destination.eq_ignore_ascii_case("webhook") {
            match &self.webhook_url {
                None => {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.webhook_url"),
                        message: "webhook route requires a webhook_url".to_string(),
                    });
                }
                Some(url) if !url.starts_with("http://") && !url.starts_with("https://") => {
                    return Err(ConfigError::Validation {
                        field: format!("{prefix}.webhook_url"),
                        message: format!(
                            "webhook URL must use http:// or https:// scheme, got '{url}'"
                        ),
                    });
                }
                _ => {}
            }

            // Custom headers reach the wire verbatim, so reject anything that
            // could forge a second header or overwrite the body encoding.
            for (name, value) in self.webhook_headers.iter().flatten() {
                validate_header(name, value).map_err(|message| ConfigError::Validation {
                    field: format!("{prefix}.webhook_headers"),
                    message,
                })?;
            }
        }

        // Email routes require an email_to and smtp config
        if self.destination.eq_ignore_ascii_case("email") {
            if self.email_to.is_none() {
                return Err(ConfigError::Validation {
                    field: format!("{prefix}.email_to"),
                    message: "email route requires an email_to address".to_string(),
                });
            }
            if !smtp_present {
                return Err(ConfigError::Validation {
                    field: "alerting.smtp".to_string(),
                    message: "email route requires smtp configuration".to_string(),
                });
            }
        }

        // An OTLP route carries no endpoint of its own, so without the block
        // there is nothing to export to. It is refused here for the same
        // reason an email route with no relay is: a route that silently sends
        // nowhere is discovered as an absence of alerts.
        if self.destination.eq_ignore_ascii_case("otlp") && !otlp_present {
            return Err(ConfigError::Validation {
                field: "alerting.otlp".to_string(),
                message: "otlp route requires otlp configuration".to_string(),
            });
        }

        Ok(())
    }

    pub fn to_domain_route(&self) -> Result<AlertRoute, ConfigError> {
        let min_severity =
            parse_severity(&self.min_severity).map_err(|()| ConfigError::InvalidValue {
                field: "min_severity".to_string(),
                value: self.min_severity.clone(),
                expected: "low, medium, high, critical".to_string(),
            })?;

        let destination = match self.destination.to_lowercase().as_str() {
            "log" => AlertDestination::Log,
            "email" => AlertDestination::Email {
                to: self.email_to.clone().unwrap_or_default(),
            },
            "webhook" => AlertDestination::Webhook {
                url: self.webhook_url.clone().unwrap_or_default(),
                headers: self
                    .webhook_headers
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .collect(),
            },
            "otlp" => AlertDestination::Otlp,
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "destination".to_string(),
                    value: self.destination.clone(),
                    expected: "log, email, webhook, otlp".to_string(),
                });
            }
        };

        Ok(AlertRoute {
            name: self.name.clone(),
            destination,
            min_severity,
            event_types: self.event_types.clone(),
        })
    }
}

/// Validate a header pair an operator wrote, whether it rides a webhook post
/// or an OTLP export.
///
/// The name must be an RFC 7230 token and the value must carry no CR, LF or
/// NUL, otherwise a crafted config could inject an extra header or split the
/// request. `Content-Type` is reserved: the sender sets it to the encoding it
/// is writing and a second value would make the request ambiguous.
///
/// # Errors
///
/// Returns the sentence naming what is wrong with the pair, which is the
/// message the configuration error carries.
pub fn validate_header(name: &str, value: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("header name must not be empty".to_string());
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    {
        return Err(format!("header name '{name}' contains invalid characters"));
    }
    if trimmed.eq_ignore_ascii_case("content-type") {
        return Err("Content-Type is set by the sender and cannot be overridden".to_string());
    }
    if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(format!(
            "value of header '{name}' contains forbidden characters (CR/LF/NUL)"
        ));
    }
    Ok(())
}

fn parse_alert_destination(s: &str) -> Result<AlertDestination, ()> {
    match s.to_lowercase().as_str() {
        "log" => Ok(AlertDestination::Log),
        "email" => Ok(AlertDestination::Email { to: String::new() }),
        "webhook" => Ok(AlertDestination::Webhook {
            url: String::new(),
            headers: std::collections::BTreeMap::new(),
        }),
        "otlp" => Ok(AlertDestination::Otlp),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Deserialization tests ────────────────────────────────────────

    #[test]
    fn default_config_from_empty_yaml() {
        let cfg: AlertingConfig = serde_yaml_ng::from_str("{}").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.dedup_window_secs, 60);
        assert_eq!(cfg.throttle_window_secs, 300);
        assert_eq!(cfg.throttle_max, 100);
        assert!(cfg.smtp.is_none());
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].name, "default-log");
        assert_eq!(cfg.routes[0].destination, "log");
        assert_eq!(cfg.routes[0].min_severity, "low");
    }

    #[test]
    fn webhook_route_deserializes() {
        let yaml = r#"
enabled: true
routes:
  - name: slack-hook
    destination: webhook
    min_severity: high
    webhook_url: "https://hooks.example.com/alert"
"#;
        let cfg: AlertingConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert_eq!(cfg.routes.len(), 1);
        assert_eq!(cfg.routes[0].name, "slack-hook");
        assert_eq!(cfg.routes[0].destination, "webhook");
        assert_eq!(
            cfg.routes[0].webhook_url.as_deref(),
            Some("https://hooks.example.com/alert")
        );
    }

    #[test]
    fn email_route_with_smtp_deserializes() {
        let yaml = r"
smtp:
  host: smtp.example.com
  port: 465
  from_address: alerts@example.com
  tls: true
routes:
  - name: ops-email
    destination: email
    min_severity: critical
    email_to: ops@example.com
";
        let cfg: AlertingConfig = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(cfg.smtp.is_some());
        let smtp = cfg.smtp.as_ref().unwrap();
        assert_eq!(smtp.host, "smtp.example.com");
        assert_eq!(smtp.port, 465);
        assert_eq!(cfg.routes[0].destination, "email");
        assert_eq!(cfg.routes[0].email_to.as_deref(), Some("ops@example.com"));
    }

    // ── Validation tests ────────────────────────────────────────────

    #[test]
    fn validate_empty_name_is_error() {
        let route = AlertRouteConfig {
            name: String::new(),
            destination: "log".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn validate_invalid_destination_is_error() {
        let route = AlertRouteConfig {
            name: "r1".to_string(),
            destination: "carrier_pigeon".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn validate_invalid_severity_is_error() {
        let route = AlertRouteConfig {
            name: "r1".to_string(),
            destination: "log".to_string(),
            min_severity: "ultra".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn validate_webhook_without_url_is_error() {
        let route = AlertRouteConfig {
            name: "r1".to_string(),
            destination: "webhook".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn validate_email_without_email_to_is_error() {
        let route = AlertRouteConfig {
            name: "r1".to_string(),
            destination: "email".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(route.validate(0, true, true).is_err());
    }

    #[test]
    fn validate_email_without_smtp_is_error() {
        let route = AlertRouteConfig {
            name: "r1".to_string(),
            destination: "email".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: Some("a@b.com".to_string()),
            webhook_headers: None,
        };
        assert!(route.validate(0, false, true).is_err());
    }

    // ── to_domain_route tests ───────────────────────────────────────

    #[test]
    fn to_domain_log_route() {
        let route = AlertRouteConfig {
            name: "my-log".to_string(),
            destination: "log".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        let domain = route.to_domain_route().unwrap();
        assert_eq!(domain.name, "my-log");
        assert!(matches!(domain.destination, AlertDestination::Log));
        assert_eq!(domain.min_severity, domain::common::entity::Severity::Low);
    }

    #[test]
    fn to_domain_webhook_route() {
        let route = AlertRouteConfig {
            name: "wh".to_string(),
            destination: "webhook".to_string(),
            min_severity: "high".to_string(),
            event_types: Some(vec!["ids".to_string()]),
            webhook_url: Some("https://example.com/hook".to_string()),
            email_to: None,
            webhook_headers: None,
        };
        let domain = route.to_domain_route().unwrap();
        assert!(matches!(
            domain.destination,
            AlertDestination::Webhook { ref url, .. } if url == "https://example.com/hook"
        ));
        assert_eq!(domain.min_severity, domain::common::entity::Severity::High);
        assert_eq!(domain.event_types, Some(vec!["ids".to_string()]));
    }

    #[test]
    fn to_domain_email_route() {
        let route = AlertRouteConfig {
            name: "em".to_string(),
            destination: "email".to_string(),
            min_severity: "critical".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: Some("ops@co.com".to_string()),
            webhook_headers: None,
        };
        let domain = route.to_domain_route().unwrap();
        assert!(matches!(
            domain.destination,
            AlertDestination::Email { ref to } if to == "ops@co.com"
        ));
        assert_eq!(
            domain.min_severity,
            domain::common::entity::Severity::Critical
        );
    }

    #[test]
    fn to_domain_otlp_route() {
        let route = AlertRouteConfig {
            name: "otlp-export".to_string(),
            destination: "otlp".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        let domain = route.to_domain_route().unwrap();
        assert!(matches!(domain.destination, AlertDestination::Otlp));
    }

    #[test]
    fn otlp_config_deserialization() {
        let yaml = r"
enabled: true
otlp:
  endpoint: http://otel-collector:4317
  protocol: grpc
  timeout_ms: 3000
routes:
  - name: otlp-all
    destination: otlp
    min_severity: low
";
        let config: AlertingConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let otlp = config.otlp.unwrap();
        assert_eq!(otlp.endpoint, "http://otel-collector:4317");
        assert_eq!(otlp.protocol, "grpc");
        assert_eq!(otlp.timeout_ms, 3000);
        assert_eq!(config.routes[0].destination, "otlp");
    }

    #[test]
    fn otlp_config_defaults() {
        let yaml = r"
enabled: true
otlp:
  endpoint: http://localhost:4317
routes: []
";
        let config: AlertingConfig = serde_yaml_ng::from_str(yaml).unwrap();
        let otlp = config.otlp.unwrap();
        assert_eq!(otlp.protocol, "grpc");
        assert_eq!(otlp.timeout_ms, 5000);
    }

    #[test]
    fn to_domain_invalid_destination_is_error() {
        let route = AlertRouteConfig {
            name: "bad".to_string(),
            destination: "fax".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(route.to_domain_route().is_err());
    }

    // ── Custom webhook headers ───────────────────────────────────────

    fn webhook_route_with_headers(pairs: &[(&str, &str)]) -> AlertRouteConfig {
        AlertRouteConfig {
            name: "hook".to_string(),
            destination: "webhook".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: Some("https://example.com/hook".to_string()),
            email_to: None,
            webhook_headers: Some(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            ),
        }
    }

    #[test]
    fn webhook_headers_reach_the_domain_route() {
        let route = webhook_route_with_headers(&[("X-Auth-Token", "s3cret")]);
        route.validate(0, false, true).unwrap();

        let domain = route.to_domain_route().unwrap();
        match domain.destination {
            AlertDestination::Webhook { ref headers, .. } => {
                assert_eq!(
                    headers.get("X-Auth-Token").map(String::as_str),
                    Some("s3cret")
                );
            }
            other => panic!("expected a webhook destination, got {other:?}"),
        }
    }

    #[test]
    fn webhook_without_headers_yields_an_empty_map() {
        let route = AlertRouteConfig {
            name: "hook".to_string(),
            destination: "webhook".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: Some("https://example.com/hook".to_string()),
            email_to: None,
            webhook_headers: None,
        };
        let domain = route.to_domain_route().unwrap();
        match domain.destination {
            AlertDestination::Webhook { ref headers, .. } => assert!(headers.is_empty()),
            other => panic!("expected a webhook destination, got {other:?}"),
        }
    }

    #[test]
    fn webhook_header_value_with_crlf_is_rejected() {
        let route = webhook_route_with_headers(&[("X-Auth", "a\r\nX-Injected: yes")]);
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn webhook_header_name_with_separator_is_rejected() {
        let route = webhook_route_with_headers(&[("X-Bad: Name", "value")]);
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn webhook_header_cannot_override_content_type() {
        let route = webhook_route_with_headers(&[("Content-Type", "text/plain")]);
        assert!(route.validate(0, false, true).is_err());
        let route = webhook_route_with_headers(&[("content-type", "text/plain")]);
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn webhook_header_with_empty_name_is_rejected() {
        let route = webhook_route_with_headers(&[("   ", "value")]);
        assert!(route.validate(0, false, true).is_err());
    }

    #[test]
    fn non_webhook_route_ignores_header_validation() {
        // Headers only apply to webhook routes; a stray map on a log route is
        // inert rather than a config error.
        let mut route = webhook_route_with_headers(&[("Content-Type", "text/plain")]);
        route.destination = "log".to_string();
        route.webhook_url = None;
        assert!(route.validate(0, false, true).is_ok());
    }

    // - OTLP collector block ------------------------------------------

    fn collector(yaml: &str) -> OtlpExportConfig {
        serde_yaml_ng::from_str(yaml).expect("the block parses")
    }

    #[test]
    fn a_protocol_is_read_whatever_case_it_was_written_in() {
        for written in ["grpc", "gRPC", "  GRPC "] {
            assert_eq!(OtlpProtocol::parse(written), Some(OtlpProtocol::Grpc));
        }
        for written in ["http", "HTTP", "Http"] {
            assert_eq!(OtlpProtocol::parse(written), Some(OtlpProtocol::Http));
        }
    }

    #[test]
    fn a_third_protocol_names_both_accepted_words() {
        let config = collector("endpoint: http://collector:4317\nprotocol: kafka");
        let error = config.validate().expect_err("kafka is not a transport");
        let rendered = error.to_string();
        assert!(
            rendered.contains("grpc") && rendered.contains("http"),
            "the refusal named neither accepted word: {rendered}"
        );
    }

    #[test]
    fn an_endpoint_that_dials_nowhere_is_refused() {
        for endpoint in [
            "",
            "   ",
            "collector:4317",
            "grpc://collector:4317",
            "http://",
        ] {
            let config = OtlpExportConfig {
                endpoint: endpoint.to_string(),
                protocol: "grpc".to_string(),
                timeout_ms: 5000,
                headers: None,
                ca_cert: None,
                verify_tls: true,
            };
            assert!(
                config.validate().is_err(),
                "'{endpoint}' was accepted as a collector endpoint"
            );
        }
    }

    #[test]
    fn a_collector_header_is_held_to_the_webhook_rule() {
        let config = collector(
            "endpoint: http://collector:4317\nheaders:\n  Authorization: \"a\\r\\nX-Injected: yes\"",
        );
        assert!(config.validate().is_err());

        let config =
            collector("endpoint: http://collector:4317\nheaders:\n  Authorization: Bearer t");
        config.validate().expect("a bearer token is a header");
    }

    #[test]
    fn verification_cannot_be_turned_off_on_grpc() {
        let config = collector("endpoint: https://collector:4317\nverify_tls: false");
        let error = config
            .validate()
            .expect_err("tonic offers no way to skip verification");
        assert!(
            error.to_string().contains("http"),
            "the refusal did not name the protocol that honours it: {error}"
        );

        let config =
            collector("endpoint: https://collector:4318\nprotocol: http\nverify_tls: false");
        config.validate().expect("the http exporter honours it");
    }

    #[test]
    fn an_otlp_route_without_a_collector_refuses_to_boot() {
        let route = AlertRouteConfig {
            name: "otlp".to_string(),
            destination: "otlp".to_string(),
            min_severity: "low".to_string(),
            event_types: None,
            webhook_url: None,
            email_to: None,
            webhook_headers: None,
        };
        assert!(
            route.validate(0, false, false).is_err(),
            "a route with nowhere to export was accepted"
        );
        route
            .validate(0, false, true)
            .expect("the same route with a collector configured");
    }
}
