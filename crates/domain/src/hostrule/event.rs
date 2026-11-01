//! One occurrence of an intention, with the fields its source could read.

use std::collections::BTreeMap;

use serde::Serialize;

use super::error::HostRuleError;
use super::field::{FieldType, FieldValue};
use super::intent::Intent;

/// Length of a SHA-256 digest written in hexadecimal.
const SHA256_HEX_LEN: usize = 64;

/// One occurrence of an intention.
///
/// A field the source could not read is absent rather than defaulted: a
/// file event whose writer had already exited has no `exe`, and an empty
/// string in its place would match a rule asking for an empty executable.
/// Only declared fields of the declared type can be set, so an event cannot
/// carry what no rule could ever ask about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntentEvent {
    intent: Intent,
    fields: BTreeMap<&'static str, FieldValue>,
}

impl IntentEvent {
    /// An occurrence with no field read yet.
    #[must_use]
    pub fn new(intent: Intent) -> Self {
        Self {
            intent,
            fields: BTreeMap::new(),
        }
    }

    /// Set one field, refusing a field the intention does not carry or a
    /// value of the wrong type.
    ///
    /// # Errors
    ///
    /// [`HostRuleError::UnknownField`], [`HostRuleError::FieldType`],
    /// [`HostRuleError::PortOutOfRange`] or [`HostRuleError::MalformedHash`].
    pub fn with(mut self, name: &str, value: FieldValue) -> Result<Self, HostRuleError> {
        let spec = self.intent.field(name)?;
        let intent = self.intent.as_str();
        if !spec.ty.accepts(&value) {
            return Err(HostRuleError::FieldType {
                intent,
                field: spec.name,
                expected: spec.ty.as_str(),
                given: value.kind(),
            });
        }
        match (spec.ty, &value) {
            (FieldType::Port, FieldValue::Integer(port))
                if !(0..=i64::from(u16::MAX)).contains(port) =>
            {
                return Err(HostRuleError::PortOutOfRange {
                    intent,
                    field: spec.name,
                    value: *port,
                });
            }
            (FieldType::Hash, FieldValue::Text(digest)) if !is_sha256_hex(digest) => {
                return Err(HostRuleError::MalformedHash {
                    intent,
                    field: spec.name,
                });
            }
            _ => {}
        }
        self.fields.insert(spec.name, value);
        Ok(self)
    }

    /// The intention this is an occurrence of.
    #[must_use]
    pub fn intent(&self) -> Intent {
        self.intent
    }

    /// One field, absent when the source could not read it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&FieldValue> {
        self.fields.get(name)
    }

    /// Every field that was read, by name.
    pub fn fields(&self) -> impl Iterator<Item = (&'static str, &FieldValue)> {
        self.fields.iter().map(|(name, value)| (*name, value))
    }
}

fn is_sha256_hex(digest: &str) -> bool {
    digest.len() == SHA256_HEX_LEN
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn text(value: &str) -> FieldValue {
        FieldValue::Text(value.to_string())
    }

    #[test]
    fn declared_fields_of_the_declared_type_are_kept() {
        let event = IntentEvent::new(Intent::ProcessConnects)
            .with("exe", text("/usr/bin/curl"))
            .unwrap()
            .with("uid", FieldValue::Integer(1000))
            .unwrap()
            .with(
                "remote_address",
                FieldValue::Address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
            )
            .unwrap()
            .with("remote_port", FieldValue::Integer(443))
            .unwrap();

        assert_eq!(event.intent(), Intent::ProcessConnects);
        assert_eq!(event.get("exe"), Some(&text("/usr/bin/curl")));
        assert_eq!(event.get("protocol"), None);
        assert_eq!(event.fields().count(), 4);
    }

    #[test]
    fn a_field_the_intent_does_not_carry_is_refused() {
        let err = IntentEvent::new(Intent::PortHidden)
            .with("exe", text("/usr/sbin/sshd"))
            .unwrap_err();
        assert!(matches!(err, HostRuleError::UnknownField { .. }), "{err}");
    }

    #[test]
    fn a_value_of_the_wrong_type_is_refused_naming_both_types() {
        let err = IntentEvent::new(Intent::ProcessStarts)
            .with("uid", text("root"))
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("`uid` of intent `process.starts` is an integer"),
            "{message}"
        );
        assert!(message.contains("given is text"), "{message}");

        assert!(
            IntentEvent::new(Intent::ProcessConnects)
                .with("remote_address", text("192.0.2.7"))
                .is_err()
        );
        assert!(
            IntentEvent::new(Intent::ProcessStarts)
                .with("exe_on_disk", FieldValue::Integer(0))
                .is_err()
        );
    }

    #[test]
    fn a_port_outside_its_range_is_refused() {
        for port in [-1, 65_536] {
            let err = IntentEvent::new(Intent::ProcessListens)
                .with("local_port", FieldValue::Integer(port))
                .unwrap_err();
            assert!(matches!(err, HostRuleError::PortOutOfRange { value, .. } if value == port));
        }
        for port in [0, 65_535] {
            assert!(
                IntentEvent::new(Intent::ProcessListens)
                    .with("local_port", FieldValue::Integer(port))
                    .is_ok()
            );
        }
    }

    #[test]
    fn a_digest_is_sixty_four_lowercase_hex_characters() {
        let good = "a".repeat(64);
        assert!(
            IntentEvent::new(Intent::FileIntegrityBreaks)
                .with("actual_hash", text(&good))
                .is_ok()
        );
        for bad in [
            "A".repeat(64),
            "a".repeat(63),
            "g".repeat(64),
            String::new(),
        ] {
            let err = IntentEvent::new(Intent::FileIntegrityBreaks)
                .with("actual_hash", text(&bad))
                .unwrap_err();
            assert!(matches!(err, HostRuleError::MalformedHash { .. }), "{bad}");
        }
    }

    #[test]
    fn an_event_serialises_with_the_intent_name_and_its_fields() {
        let event = IntentEvent::new(Intent::FileChanges)
            .with("path", text("/srv/share/report.docx"))
            .unwrap()
            .with("uid", FieldValue::Integer(33))
            .unwrap();
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["intent"], "file.changes");
        assert_eq!(json["fields"]["path"], "/srv/share/report.docx");
        assert_eq!(json["fields"]["uid"], 33);
    }
}
