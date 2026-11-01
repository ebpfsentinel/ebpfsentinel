//! Mass encryption, recognised by signals that agree.
//!
//! No single behaviour says a run is encrypting files: a backup rewrites
//! many files, an archiver writes content with no structure, a build renames
//! in bulk. What has no common innocent cause is several of them, from one
//! actor, inside one window. This module is that composition and nothing
//! else: each signal is produced where its reading lives, the tier of each is
//! a table here, and a verdict is never reported without the signals that
//! reached it and the ones this host could not read.

pub mod actor;
pub mod engine;
pub mod entropy;
pub mod paths;
pub mod signal;

pub use actor::{Actor, actor_of};
pub use engine::{
    Corroboration, MASS_ENCRYPTION_COMPONENT, MASS_ENCRYPTION_RULE_ID, RANSOM_ACTORS_MAX,
    RANSOM_WINDOW_NS, RansomEngine, RansomVerdict, corroborate,
};
pub use entropy::{ENTROPY_HIGH_MILLIBITS, ENTROPY_LOW_MILLIBITS, entropy_rose};
pub use paths::{DistinctPaths, RANSOM_DISTINCT_REWRITES, RANSOM_ENTROPY_RISES};
pub use signal::{RansomSignal, SignalKind, Tier, UnavailableSignal, unavailable};
