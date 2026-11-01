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
pub mod backup;
pub mod canary;
pub mod crypto;
pub mod engine;
pub mod entropy;
pub mod header;
pub mod note;
pub mod paths;
pub mod refusal;
pub mod rename;
pub mod replace;
pub mod shadow;
pub mod signal;
pub mod stop;
pub mod thresholds;

pub use actor::{Actor, actor_of};
pub use backup::{
    BACKUP_PRIOR_WINDOW_NS, BACKUP_PROGRAMS, BACKUP_UNIT_MARKERS, SHELLS, backup_destroyed,
    backup_destroyed_signal, backup_program, initiator,
};
pub use canary::{
    CANARIES_MAX, CANARY_DIRECTORIES, CANARY_EXEMPT, CANARY_NAMES, canary_exempt,
    canary_name_refusal, canary_paths, canary_touched,
};
pub use crypto::{CryptoRates, RANSOM_CRYPTO_CALLS, RANSOM_CRYPTO_FILES};
pub use engine::{
    Corroboration, MASS_ENCRYPTION_COMPONENT, MASS_ENCRYPTION_RULE_ID, RANSOM_ACTORS_MAX,
    RANSOM_WINDOW_NS, RansomEngine, RansomVerdict, corroborate,
};
pub use entropy::{ENTROPY_HIGH_MILLIBITS, ENTROPY_LOW_MILLIBITS, entropy_rose};
pub use header::{HEADER_BYTES, expected_headers, header_mismatch};
pub use note::{
    RANSOM_NOTE_DIRECTORIES, RANSOM_NOTE_NAMES_MAX, RansomNotes, SCATTERED_NAMES, scattered,
};
pub use paths::{
    DistinctPaths, RANSOM_DISTINCT_REWRITES, RANSOM_ENTROPY_RISES, RANSOM_HEADER_MISMATCHES,
    learned_evidence,
};
pub use refusal::{
    CountBy, MAX_WRITE_REFUSAL_DIRECTORIES, MAX_WRITE_REFUSAL_EXPECTED_WRITERS,
    MAX_WRITE_REFUSAL_WINDOW_SECS, WRITE_REFUSAL_RULE_ID, WRITE_REFUSAL_THRESHOLD,
    WRITE_REFUSAL_WINDOW_SECS, WRITE_REFUSAL_WRITERS, WriteRefusalError, WriteRefusalHook,
    WriteRefusalRecord, WriteRefusalRegime, WriteRefusalSetRef, validate_write_refusal,
};
pub use rename::{
    MassRenames, RANSOM_MASS_RENAMES, RANSOM_RENAME_EXTENSIONS_MAX, renamed_to_new_extension,
};
pub use replace::{
    RANSOM_REPLACEMENTS, REPLACEMENT_FRESH_NS, REPLACEMENT_HALVES_MAX, REPLACEMENT_OVERHEAD_BYTES,
    Replacements, original_of, renamed_over, replaces, written_now,
};
pub use shadow::{RANSOM_SHADOW_RECENT_MAX, RansomShadow, ShadowVerdict};
pub use signal::{RansomSignal, SignalKind, Tier, UnavailableSignal, unavailable};
pub use stop::{
    FilesWritten, RANSOM_FILES_COUNTED_MAX, RANSOM_STOP_SETTLE_MS, RansomStop, run_members,
};
pub use thresholds::{
    BASELINE_CEILING_FACTOR, BASELINE_FLOOR_DIVISOR, BASELINED, bounded_threshold,
    shipped_threshold, threshold_band,
};
