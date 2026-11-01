//! A baseline that moves the mass encryption thresholds per executable.

use domain::ransom::SignalKind;

/// What an executable normally does, learned from what it was counted doing.
///
/// The verdict is still the typed engine's: a baseline only answers which
/// threshold one count is read against for one executable, and the caller
/// holds that answer inside the band the content fixes, so no baseline can
/// lift a threshold past its ceiling or move one a baseline may not move.
pub trait RansomBaselinePort: Send + Sync {
    /// One file counted toward `kind` for the executable at `exe`.
    fn counted(&self, exe: &str, kind: SignalKind, at_ns: u64);

    /// The threshold learned for `kind` for the executable at `exe`, or
    /// `None` where nothing is learned yet and the shipped one applies.
    fn threshold(&self, exe: &str, kind: SignalKind) -> Option<usize>;
}
