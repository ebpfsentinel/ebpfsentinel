//! A rise in sampled entropy, from ordinary content to near-random content.
//!
//! The entropy is read where the hash is, from the same bytes, so measuring it
//! costs no second read. It is sampled rather than computed over the whole
//! file: the sample is the first 64 KiB, the first block the hash reads, and a
//! file shorter than that is sampled whole. It is a derived number in bits per
//! byte, kept in thousandths, and says nothing of the content it came from, on
//! the ground a hash already stands on.
//!
//! What sampling costs is stated rather than hidden. A run that encrypts only
//! a tail of each file, or encrypts in intermittent blocks to go faster, can
//! leave the first 64 KiB untouched and the sampled entropy flat. A file that
//! was already compressed or encrypted cannot rise at all. That is why a rise
//! is a supporting signal and never enough on its own.

/// Below this, in thousandths of a bit per byte, the sampled content is
/// ordinary: text, code, configuration, most office and database formats.
pub const ENTROPY_LOW_MILLIBITS: u16 = 7_000;

/// At or above this, the sampled content is indistinguishable from random:
/// ciphertext, or already compressed data.
pub const ENTROPY_HIGH_MILLIBITS: u16 = 7_900;

/// Whether a file sampled at `before` and sampled again at `now` went from
/// ordinary to near-random. A sample missing on either side is no rise.
#[must_use]
pub fn entropy_rose(before: Option<u16>, now: Option<u16>) -> bool {
    matches!(
        (before, now),
        (Some(before), Some(now)) if before < ENTROPY_LOW_MILLIBITS && now >= ENTROPY_HIGH_MILLIBITS
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_content_turned_random_is_a_rise() {
        assert!(entropy_rose(Some(4_500), Some(7_998)));
        assert!(entropy_rose(Some(6_999), Some(ENTROPY_HIGH_MILLIBITS)));
    }

    #[test]
    fn already_dense_content_or_a_missing_sample_is_not() {
        assert!(!entropy_rose(Some(ENTROPY_LOW_MILLIBITS), Some(7_999)));
        assert!(!entropy_rose(Some(4_500), Some(7_899)));
        assert!(!entropy_rose(None, Some(7_999)));
        assert!(!entropy_rose(Some(4_500), None));
    }
}
