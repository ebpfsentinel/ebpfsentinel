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
pub mod count;
pub mod error;
pub mod event;
pub mod field;
pub mod intent;
pub mod limits;
pub mod rule;
pub mod sequence;
pub mod shadow;

pub use binding::{Applicability, Binding, HostSources, Source, resolve};
pub use count::{
    Count, CountPer, HOST_RULE_COUNT_EVENTS_MAX, HOST_RULE_COUNT_KEYS_MAX, HOST_RULE_COUNT_MIN_MAX,
    WindowCounts,
};
pub use error::HostRuleError;
pub use event::IntentEvent;
pub use field::{FieldSpec, FieldType, FieldValue, RESERVED_KEYS};
pub use intent::{Intent, IntentFamily};
pub use limits::{HOST_RULE_LIMITS, HostRuleLimit};
pub use rule::{
    Condition, FollowedBy, Glob, HOST_RULE_COMPONENT, HOST_RULE_REGEX_DFA_LIMIT,
    HOST_RULE_REGEX_SIZE_LIMIT, HOST_RULE_WINDOW_MAX_NS, HostRule, HostRuleAction, HostRuleSet,
    HostRuleSpec, IntentBlock, Matcher, Pattern, RawValue, Test,
};
pub use sequence::{HOST_RULE_PENDING_MAX, HostRuleState, PendingSequences, Subject};
pub use shadow::{
    HOST_RULE_SAME_READING_NS, HOST_RULE_SHADOW_WORKLOADS_MAX, HostShadowBook, HostShadowReading,
    PromotionRefused, WorkloadHits,
};
