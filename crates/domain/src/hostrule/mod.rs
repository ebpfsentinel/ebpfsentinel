//! Host rules: an operator names an intention, never a syscall.
//!
//! A rule written against a kernel vocabulary - a kprobe symbol, an argument
//! index and its type - is a rule only a kernel engineer can write and only
//! the same engineer can keep working across kernel versions. This module
//! inverts that contract. The operator names what a workload does in the
//! product's own words (`process.connects`, `file.changes`), each intention
//! carries a closed set of typed fields, and the map from intention to hook
//! is the agent's, probed on the host it runs on.
//!
//! The price is stated rather than hidden: only the intentions listed in
//! [`Intent`] can be asked for. Adding one is a change to that enum, never a
//! configuration key, which is what keeps the surface something one
//! maintainer can hold.

pub mod binding;
pub mod error;
pub mod event;
pub mod field;
pub mod intent;
pub mod rule;

pub use binding::{Applicability, Binding, HostSources, Source, resolve};
pub use error::HostRuleError;
pub use event::IntentEvent;
pub use field::{FieldSpec, FieldType, FieldValue, RESERVED_KEYS};
pub use intent::{Intent, IntentFamily};
pub use rule::{
    Condition, Glob, HOST_RULE_COMPONENT, HostRule, HostRuleAction, HostRuleSet, HostRuleSpec,
    IntentBlock, Matcher, RawValue, Test,
};
