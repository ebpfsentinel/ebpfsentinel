use thiserror::Error;

use crate::common::error::DomainError;

/// Why a host rule or an intent event was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HostRuleError {
    /// The name is not an intention the agent ships.
    #[error("unknown intent `{name}`; the intents that exist are: {known}")]
    UnknownIntent { name: String, known: String },

    /// The field is not one the intention carries.
    #[error("intent `{intent}` has no field `{field}`; its fields are: {known}")]
    UnknownField {
        intent: &'static str,
        field: String,
        known: String,
    },

    /// The value is not of the type the field is declared with.
    #[error("field `{field}` of intent `{intent}` is {expected}, and the value given is {given}")]
    FieldType {
        intent: &'static str,
        field: &'static str,
        expected: &'static str,
        given: &'static str,
    },

    /// A hash field holds something that is not a SHA-256 digest.
    #[error(
        "field `{field}` of intent `{intent}` holds a SHA-256 digest as 64 lowercase hex characters"
    )]
    MalformedHash {
        intent: &'static str,
        field: &'static str,
    },

    /// A port field holds a number outside a port's range.
    #[error("field `{field}` of intent `{intent}` is a port, and {value} is outside 0 to 65535")]
    PortOutOfRange {
        intent: &'static str,
        field: &'static str,
        value: i64,
    },

    /// A host rule that does not load, and why.
    #[error("host rule `{id}`: {reason}")]
    Rule { id: String, reason: String },

    /// An exception that does not load, and why.
    #[error("host rule exception `{id}`: {reason}")]
    Exception { id: String, reason: String },

    /// Two host rules carry one identifier.
    #[error("host rule `{id}` is defined twice; an identifier names one rule")]
    DuplicateRule { id: String },
}

impl From<HostRuleError> for DomainError {
    fn from(e: HostRuleError) -> Self {
        DomainError::InvalidConfig(e.to_string())
    }
}
