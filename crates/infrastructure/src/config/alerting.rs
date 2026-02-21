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

    #[serde(default = "default_alerting_routes")]
    pub routes: Vec<AlertRouteConfig>,
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
    pub(super) fn validate(&self, idx: usize, smtp_present: bool) -> Result<(), ConfigError> {
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
            expected: "log, email, webhook".to_string(),
        })?;

        parse_severity(&self.min_severity).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.min_severity"),
            value: self.min_severity.clone(),
            expected: "low, medium, high, critical".to_string(),
        })?;

        // Webhook routes require a webhook_url
        if self.destination.eq_ignore_ascii_case("webhook") && self.webhook_url.is_none() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.webhook_url"),
                message: "webhook route requires a webhook_url".to_string(),
            });
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
            },
            _ => {
                return Err(ConfigError::InvalidValue {
                    field: "destination".to_string(),
                    value: self.destination.clone(),
                    expected: "log, email, webhook".to_string(),
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

fn parse_alert_destination(s: &str) -> Result<AlertDestination, ()> {
    match s.to_lowercase().as_str() {
        "log" => Ok(AlertDestination::Log),
        "email" => Ok(AlertDestination::Email { to: String::new() }),
        "webhook" => Ok(AlertDestination::Webhook { url: String::new() }),
        _ => Err(()),
    }
}
