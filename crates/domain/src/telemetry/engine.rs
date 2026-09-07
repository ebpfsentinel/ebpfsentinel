//! When one installation speaks, and how far apart two of them do.

use std::time::Duration;

use super::entity::InstallationId;

/// FNV-1a's offset basis and prime.
///
/// FNV-1a rather than shift-and-add: these identifiers are thirty-two hex
/// characters out of a sixteen-value alphabet, and a weak mix leaves whole
/// families of them sharing an offset, which is the one thing the spread exists
/// to avoid.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// How long between beats.
///
/// Fixed rather than negotiated: nothing answers this beat with an interval, so
/// there is one number here and changing it changes the whole fleet's cadence
/// at the next release. Thirty minutes is far below any useful notion of an
/// installation having gone away and far above anything that would show up in a
/// bill.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_mins(30);

/// The most an installation waits before its first beat.
///
/// A fleet restarting in lockstep - a cluster rollout, a node pool replaced -
/// would otherwise land every first beat on the same second. Spreading them
/// over a minute costs nothing and turns a spike into a flat line.
pub const MAX_STARTUP_DELAY: Duration = Duration::from_secs(60);

/// How long this installation waits before its first beat.
///
/// Derived from the identifier rather than drawn fresh, so a machine that
/// restarts twice in a minute lands on the same offset both times instead of
/// walking across the window.
#[must_use]
pub fn startup_delay(id: &InstallationId) -> Duration {
    let room = MAX_STARTUP_DELAY.as_secs();
    if room == 0 {
        return Duration::ZERO;
    }

    let spread = id.as_str().bytes().fold(FNV_OFFSET, |acc, byte| {
        (acc ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    });

    // Scaled off the high half rather than taken modulo: FNV's low bits barely
    // move between neighbouring inputs, so `% room` on them puts a whole fleet
    // back on a handful of seconds - which is exactly the failure this function
    // exists to prevent, and it fails silently.
    let scaled = (u128::from(spread) * u128::from(room)) >> 64;
    Duration::from_secs(u64::try_from(scaled).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interval_is_half_an_hour() {
        assert_eq!(HEARTBEAT_INTERVAL.as_secs(), 1800);
    }

    #[test]
    fn one_installation_always_waits_the_same_time() {
        let id = InstallationId::from_bytes([0x11; 16]);
        assert_eq!(startup_delay(&id), startup_delay(&id));
    }

    #[test]
    fn a_fleet_restarting_together_does_not_land_on_one_second() {
        let delays: Vec<Duration> = (0..64u8)
            .map(|n| startup_delay(&InstallationId::from_bytes([n; 16])))
            .collect();

        assert!(delays.iter().all(|d| *d < MAX_STARTUP_DELAY));

        let mut seconds: Vec<u64> = delays.iter().map(Duration::as_secs).collect();
        seconds.sort_unstable();
        seconds.dedup();
        assert!(
            seconds.len() > 32,
            "sixty-four installations landed on {} distinct seconds",
            seconds.len()
        );
    }
}
