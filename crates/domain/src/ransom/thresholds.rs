//! How far a learned baseline may move a threshold, which the content fixes
//! rather than the model.
//!
//! Four counts are read against a threshold a baseline may move: distinct
//! rewrites, entropy rises, replacements and renames to one new extension.
//! A learned threshold is only ever a number inside the band set here, so an
//! estate that slowly teaches its baseline that mass writes are normal can
//! carry a threshold to the ceiling and no further. The decisive signals, a
//! canary touched and a header that contradicts its name, are read against
//! no threshold a baseline can reach, and neither are the encryption calls,
//! the scattered notes or the destruction of backups.

use super::paths::{RANSOM_DISTINCT_REWRITES, RANSOM_ENTROPY_RISES};
use super::rename::RANSOM_MASS_RENAMES;
use super::replace::RANSOM_REPLACEMENTS;
use super::signal::SignalKind;

/// The signals whose threshold a baseline may move.
pub const BASELINED: [SignalKind; 4] = [
    SignalKind::DistinctRewrites,
    SignalKind::EntropyRise,
    SignalKind::ReplaceSequence,
    SignalKind::MassRename,
];

/// A learned threshold goes no lower than the shipped one divided by this.
pub const BASELINE_FLOOR_DIVISOR: usize = 2;

/// A learned threshold goes no higher than the shipped one times this.
pub const BASELINE_CEILING_FACTOR: usize = 4;

/// The threshold that ships for `kind`, or `None` where no baseline may move
/// it.
#[must_use]
pub fn shipped_threshold(kind: SignalKind) -> Option<usize> {
    match kind {
        SignalKind::DistinctRewrites => Some(RANSOM_DISTINCT_REWRITES),
        SignalKind::EntropyRise => Some(RANSOM_ENTROPY_RISES),
        SignalKind::ReplaceSequence => Some(RANSOM_REPLACEMENTS),
        SignalKind::MassRename => Some(RANSOM_MASS_RENAMES),
        _ => None,
    }
}

/// The band a learned threshold for `kind` is held inside, floor and
/// ceiling, or `None` where no baseline may move it.
#[must_use]
pub fn threshold_band(kind: SignalKind) -> Option<(usize, usize)> {
    shipped_threshold(kind).map(|shipped| {
        (
            (shipped / BASELINE_FLOOR_DIVISOR).max(1),
            shipped * BASELINE_CEILING_FACTOR,
        )
    })
}

/// `learned` held inside the band for `kind`, or `None` where no baseline
/// may move that threshold, whatever was learned.
#[must_use]
pub fn bounded_threshold(kind: SignalKind, learned: usize) -> Option<usize> {
    threshold_band(kind).map(|(floor, ceiling)| learned.clamp(floor, ceiling))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_learned_threshold_stays_inside_the_band_the_content_fixes() {
        assert_eq!(threshold_band(SignalKind::MassRename), Some((25, 200)));
        assert_eq!(bounded_threshold(SignalKind::MassRename, 1), Some(25));
        assert_eq!(bounded_threshold(SignalKind::MassRename, 90), Some(90));
        assert_eq!(bounded_threshold(SignalKind::MassRename, 10_000), Some(200));
        assert_eq!(
            bounded_threshold(SignalKind::DistinctRewrites, 10_000),
            Some(400)
        );
    }

    #[test]
    fn a_decisive_signal_and_the_unbaselined_ones_take_no_learned_threshold() {
        for kind in SignalKind::ALL {
            let moved = bounded_threshold(kind, 7).is_some();
            assert_eq!(moved, BASELINED.contains(&kind), "{kind:?}");
        }
        assert!(bounded_threshold(SignalKind::CanaryTouched, 1).is_none());
        assert!(bounded_threshold(SignalKind::HeaderMismatch, 1).is_none());
    }
}
