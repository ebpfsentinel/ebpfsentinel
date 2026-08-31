//! The one mapping from an alert to an OTLP log record.
//!
//! Two editions export alerts to a collector: the open source agent through
//! the OpenTelemetry SDK, the enterprise layer through OTLP/HTTP JSON with a
//! durable buffer behind it. A routing rule written against one of them has
//! to work against the other, so the record itself is built here and each
//! edition only carries it onto its own wire.
//!
//! What the record carries is a decision rather than a union of what the two
//! senders happened to send:
//!
//! - `timeUnixNano` is the alert's own time and `observedTimeUnixNano` the
//!   moment of export, so a collector can tell a late batch from an old event.
//! - the severity travels as both the number a collector filters on and the
//!   product's own word for it, never a `Debug` rendering of an internal type.
//! - `mitre.technique.id` is present only when the alert names a technique,
//!   because an attribute carrying an empty string is a field a query matches
//!   on and learns nothing from.
//!
//! An exporter that knows more than the alert - an event identifier, a tenant,
//! the L7 enrichment - appends its own attributes to the record it is given.

use domain::alert::entity::Alert;
use domain::common::entity::Severity;
use domain::common::error::DomainError;
use opentelemetry::logs::{AnyValue, LogRecord};
use std::time::{SystemTime, UNIX_EPOCH};

/// Severity numbers from the OpenTelemetry logs data model. The product has
/// four levels and the model has twenty-four, so each maps to the first
/// number of its range.
const SEVERITY_NUMBER_INFO: u8 = 9;
const SEVERITY_NUMBER_WARN: u8 = 13;
const SEVERITY_NUMBER_ERROR: u8 = 17;
const SEVERITY_NUMBER_FATAL: u8 = 21;

/// An alert as an OTLP log record, before either edition puts it on a wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtlpLogRecord {
    /// When the alert was raised, in nanoseconds since the Unix epoch.
    pub time_unix_nano: u64,
    /// When the record was handed to the exporter, same clock.
    pub observed_time_unix_nano: u64,
    /// The severity a collector filters on.
    pub severity_number: u8,
    /// The severity in the product's own vocabulary.
    pub severity_text: &'static str,
    /// The whole alert as JSON.
    pub body: String,
    /// Attributes, in the order they were added.
    pub attributes: Vec<(String, String)>,
}

impl OtlpLogRecord {
    /// Build the record every exporter starts from.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::EngineError`] when the alert cannot be
    /// serialised. An empty body would reach the collector as a record that
    /// looks delivered and carries nothing.
    pub fn from_alert(alert: &Alert, observed_time_unix_nano: u64) -> Result<Self, DomainError> {
        let body = serde_json::to_string(alert)
            .map_err(|e| DomainError::EngineError(format!("OTLP alert body serialisation: {e}")))?;

        let mut attributes = Vec::with_capacity(3);
        if let Some(technique_id) = alert
            .mitre_attack
            .as_ref()
            .map(|m| m.technique_id.clone())
            .filter(|id| !id.is_empty())
        {
            attributes.push(("mitre.technique.id".to_string(), technique_id));
        }
        attributes.push(("alert.component".to_string(), alert.component.clone()));
        attributes.push(("alert.rule_id".to_string(), alert.rule_id.0.clone()));

        Ok(Self {
            time_unix_nano: alert.timestamp_ns,
            observed_time_unix_nano,
            severity_number: severity_number(alert.severity),
            severity_text: severity_text(alert.severity),
            body,
            attributes,
        })
    }

    /// Append an attribute an exporter knows and the alert does not.
    #[must_use]
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.push((key.into(), value.into()));
        self
    }

    /// Write the record onto an SDK log record, for the sender that owns one.
    pub fn apply<R: LogRecord>(&self, record: &mut R) {
        record.set_timestamp(unix_nano_to_system_time(self.time_unix_nano));
        record.set_observed_timestamp(unix_nano_to_system_time(self.observed_time_unix_nano));
        record.set_body(AnyValue::String(self.body.clone().into()));
        record.set_severity_number(severity_from_number(self.severity_number));
        record.set_severity_text(self.severity_text);
        for (key, value) in &self.attributes {
            record.add_attribute(key.clone(), value.clone());
        }
    }

    /// Render the record as one OTLP/HTTP JSON `logRecord`, for the sender
    /// that writes the payload itself.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let attributes: Vec<serde_json::Value> = self
            .attributes
            .iter()
            .map(|(key, value)| serde_json::json!({"key": key, "value": {"stringValue": value}}))
            .collect();

        serde_json::json!({
            "timeUnixNano": self.time_unix_nano.to_string(),
            "observedTimeUnixNano": self.observed_time_unix_nano.to_string(),
            "severityNumber": self.severity_number,
            "severityText": self.severity_text,
            "body": {"stringValue": self.body},
            "attributes": attributes,
        })
    }
}

/// The service every OTLP export from this agent names when an operator has
/// not named one.
const DEFAULT_SERVICE_NAME: &str = "ebpfsentinel";

/// What an operator asked for through the environment.
///
/// The two variables are read into a value rather than consulted where they
/// are needed, because a process-wide variable is not something one test can
/// set while its neighbours are running.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OtlpResourceEnv {
    /// `OTEL_SERVICE_NAME`.
    pub service_name: Option<String>,
    /// `OTEL_RESOURCE_ATTRIBUTES`, still in its `key=value,key=value` form.
    pub resource_attributes: Option<String>,
}

impl OtlpResourceEnv {
    /// Read the two variables the OpenTelemetry specification defines.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            service_name: non_empty(std::env::var("OTEL_SERVICE_NAME").ok()),
            resource_attributes: non_empty(std::env::var("OTEL_RESOURCE_ATTRIBUTES").ok()),
        }
    }
}

/// The resource attributes an export carries, so two agents reporting into
/// one collector are told apart.
///
/// The defaults are what this build knows about itself: the product name, the
/// version that produced the record, and the machine it ran on. An operator's
/// environment wins over all three, because a resource that cannot be
/// overridden is worse than none in a collector holding a whole fleet:
/// `OTEL_RESOURCE_ATTRIBUTES` replaces or adds any key, and
/// `OTEL_SERVICE_NAME` then wins over the `service.name` that string may
/// itself have carried, which is the precedence the specification states.
#[must_use]
pub fn resource_attributes(env: &OtlpResourceEnv) -> Vec<(String, String)> {
    let mut attributes = vec![
        ("service.name".to_string(), DEFAULT_SERVICE_NAME.to_string()),
        (
            "service.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
    ];

    // An identity the agent could not read is left off rather than sent as a
    // word standing in for one: a fleet of records all claiming the same
    // placeholder is exactly the confusion this attribute exists to end.
    if let Some(instance) = instance_id() {
        attributes.push(("service.instance.id".to_string(), instance));
    }

    if let Some(raw) = env.resource_attributes.as_deref() {
        for entry in raw.split_terminator(',') {
            if let Some((key, value)) = entry.split_once('=') {
                set_attribute(&mut attributes, key.trim(), value.trim());
            }
        }
    }

    if let Some(name) = env.service_name.as_deref() {
        set_attribute(&mut attributes, "service.name", name);
    }

    attributes
}

/// The resource as one OTLP/HTTP JSON `resource`, for the sender that writes
/// the payload itself rather than handing it to the SDK.
#[must_use]
pub fn resource_to_json(attributes: &[(String, String)]) -> serde_json::Value {
    let attributes: Vec<serde_json::Value> = attributes
        .iter()
        .map(|(key, value)| serde_json::json!({"key": key, "value": {"stringValue": value}}))
        .collect();

    serde_json::json!({ "attributes": attributes })
}

/// The machine this agent runs on, under the names an orchestrator and a
/// container image already carry it.
fn instance_id() -> Option<String> {
    for variable in ["EBPFSENTINEL_NODE_NAME", "HOSTNAME"] {
        if let Some(name) = non_empty(std::env::var(variable).ok()) {
            return Some(name);
        }
    }
    non_empty(
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|name| name.trim().to_string()),
    )
}

/// Replace the value of an attribute already present, or append it.
fn set_attribute(attributes: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some(existing) = attributes.iter_mut().find(|(name, _)| name == key) {
        existing.1 = value.to_string();
    } else {
        attributes.push((key.to_string(), value.to_string()));
    }
}

/// A variable an operator set to nothing at all is a variable they did not set.
fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

/// The moment an exporter is handing a record over, on the clock the alert
/// stamps are already on.
#[must_use]
pub fn now_unix_nano() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn unix_nano_to_system_time(unix_nano: u64) -> SystemTime {
    UNIX_EPOCH + std::time::Duration::from_nanos(unix_nano)
}

fn severity_number(severity: Severity) -> u8 {
    match severity {
        Severity::Low => SEVERITY_NUMBER_INFO,
        Severity::Medium => SEVERITY_NUMBER_WARN,
        Severity::High => SEVERITY_NUMBER_ERROR,
        Severity::Critical => SEVERITY_NUMBER_FATAL,
    }
}

fn severity_text(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

/// The SDK's own severity for a number this module produced.
fn severity_from_number(number: u8) -> opentelemetry::logs::Severity {
    match number {
        SEVERITY_NUMBER_WARN => opentelemetry::logs::Severity::Warn,
        SEVERITY_NUMBER_ERROR => opentelemetry::logs::Severity::Error,
        SEVERITY_NUMBER_FATAL => opentelemetry::logs::Severity::Fatal,
        _ => opentelemetry::logs::Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::alert::mitre::MitreAttackInfo;
    use domain::common::entity::{DomainMode, RuleId};

    /// The value of one attribute, so a test reads what a collector would.
    fn value_of<'a>(attributes: &'a [(String, String)], key: &str) -> Option<&'a str> {
        attributes
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn the_defaults_name_the_product_and_the_build() {
        let attributes = resource_attributes(&OtlpResourceEnv::default());

        assert_eq!(value_of(&attributes, "service.name"), Some("ebpfsentinel"));
        assert_eq!(
            value_of(&attributes, "service.version"),
            Some(env!("CARGO_PKG_VERSION"))
        );
    }

    #[test]
    fn the_operators_service_name_wins() {
        let env = OtlpResourceEnv {
            service_name: Some("fleet-edge".to_string()),
            resource_attributes: None,
        };

        let attributes = resource_attributes(&env);

        assert_eq!(value_of(&attributes, "service.name"), Some("fleet-edge"));
        assert_eq!(
            attributes
                .iter()
                .filter(|(name, _)| name == "service.name")
                .count(),
            1,
            "the name was added again rather than replaced: {attributes:?}"
        );
    }

    /// `OTEL_RESOURCE_ATTRIBUTES` replaces what this build set and adds what
    /// it never knew, and `OTEL_SERVICE_NAME` still wins over the name that
    /// string carried.
    #[test]
    fn the_operators_attributes_replace_and_add() {
        let env = OtlpResourceEnv {
            service_name: Some("named-last".to_string()),
            resource_attributes: Some(
                "service.name=named-first, deployment.environment = staging ,broken".to_string(),
            ),
        };

        let attributes = resource_attributes(&env);

        assert_eq!(value_of(&attributes, "service.name"), Some("named-last"));
        assert_eq!(
            value_of(&attributes, "deployment.environment"),
            Some("staging"),
            "the spaces around a pair were not trimmed: {attributes:?}"
        );
        assert!(
            !attributes.iter().any(|(name, _)| name == "broken"),
            "an entry with no value became an attribute: {attributes:?}"
        );
    }

    #[test]
    fn the_resource_renders_as_otlp_json() {
        let rendered =
            resource_to_json(&[("service.name".to_string(), "ebpfsentinel".to_string())]);

        assert_eq!(
            rendered,
            serde_json::json!({
                "attributes": [
                    {"key": "service.name", "value": {"stringValue": "ebpfsentinel"}}
                ]
            })
        );
    }

    fn sample_alert() -> Alert {
        Alert {
            id: "1000000000-ids-001".to_string(),
            timestamp_ns: 1_709_913_600_123_000_000,
            component: "ids".to_string(),
            severity: Severity::High,
            rule_id: RuleId("ids-001".to_string()),
            action: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            is_ipv6: false,
            message: "SSH bruteforce detected".to_string(),
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

    #[test]
    fn the_record_carries_both_clocks() {
        let alert = sample_alert();
        let record = OtlpLogRecord::from_alert(&alert, 1_709_913_601_000_000_000)
            .expect("the alert serialises");

        assert_eq!(record.time_unix_nano, alert.timestamp_ns);
        assert_eq!(record.observed_time_unix_nano, 1_709_913_601_000_000_000);
    }

    #[test]
    fn a_severity_is_a_number_and_the_products_own_word() {
        let cases = [
            (Severity::Low, SEVERITY_NUMBER_INFO, "low"),
            (Severity::Medium, SEVERITY_NUMBER_WARN, "medium"),
            (Severity::High, SEVERITY_NUMBER_ERROR, "high"),
            (Severity::Critical, SEVERITY_NUMBER_FATAL, "critical"),
        ];

        for (severity, number, text) in cases {
            let mut alert = sample_alert();
            alert.severity = severity;
            let record = OtlpLogRecord::from_alert(&alert, 0).expect("the alert serialises");
            assert_eq!(record.severity_number, number);
            assert_eq!(record.severity_text, text);
        }
    }

    #[test]
    fn an_alert_naming_no_technique_carries_no_technique_attribute() {
        let record = OtlpLogRecord::from_alert(&sample_alert(), 0).expect("the alert serialises");
        let keys: Vec<&str> = record.attributes.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["alert.component", "alert.rule_id"]);
    }

    #[test]
    fn a_named_technique_is_the_first_attribute() {
        let mut alert = sample_alert();
        alert.mitre_attack = Some(MitreAttackInfo {
            technique_id: "T1110".to_string(),
            technique_name: "Brute Force".to_string(),
            tactic: "credential-access".to_string(),
        });

        let record = OtlpLogRecord::from_alert(&alert, 0).expect("the alert serialises");
        assert_eq!(
            record.attributes.first(),
            Some(&("mitre.technique.id".to_string(), "T1110".to_string()))
        );
    }

    #[test]
    fn an_exporter_appends_what_the_alert_does_not_know() {
        let record = OtlpLogRecord::from_alert(&sample_alert(), 0)
            .expect("the alert serialises")
            .with_attribute("event.id", "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b");

        assert_eq!(
            record.attributes.last(),
            Some(&(
                "event.id".to_string(),
                "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".to_string()
            ))
        );
    }

    #[test]
    fn the_body_is_the_whole_alert() {
        let record = OtlpLogRecord::from_alert(&sample_alert(), 0).expect("the alert serialises");
        let body: serde_json::Value =
            serde_json::from_str(&record.body).expect("the body is the alert as JSON");
        assert_eq!(body["message"], "SSH bruteforce detected");
    }

    #[test]
    fn the_wire_shape_names_every_field_the_collector_reads() {
        let record = OtlpLogRecord::from_alert(&sample_alert(), 1_709_913_601_000_000_000)
            .expect("the alert serialises");
        let json = record.to_json();

        assert_eq!(json["timeUnixNano"], "1709913600123000000");
        assert_eq!(json["observedTimeUnixNano"], "1709913601000000000");
        assert_eq!(json["severityNumber"], SEVERITY_NUMBER_ERROR);
        assert_eq!(json["severityText"], "high");
        assert_eq!(json["body"]["stringValue"], record.body);
        assert_eq!(json["attributes"][0]["key"], "alert.component");
        assert_eq!(json["attributes"][0]["value"]["stringValue"], "ids");
    }

    #[test]
    fn every_number_this_module_writes_maps_back_to_a_severity() {
        for severity in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let number = severity_number(severity);
            assert_eq!(
                u8::try_from(severity_from_number(number) as u32).unwrap_or(0),
                number,
                "the SDK severity for {number} is a different number"
            );
        }
    }

    #[test]
    fn a_stamp_survives_the_trip_through_a_system_time() {
        let unix_nano = 1_709_913_600_123_000_000;
        let restored = unix_nano_to_system_time(unix_nano)
            .duration_since(UNIX_EPOCH)
            .expect("the stamp is after the epoch");
        assert_eq!(
            u64::try_from(restored.as_nanos()).expect("the stamp fits"),
            unix_nano
        );
    }
}
