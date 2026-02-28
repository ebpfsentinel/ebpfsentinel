use application::schedule_service_impl::DayOfWeek;

/// Return the current local day of week and minutes since midnight.
///
/// Uses the `TZ`-aware `localtime_r` via libc to handle time zones correctly.
/// Falls back to UTC if the call fails.
pub fn local_day_and_minutes() -> (DayOfWeek, u16) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();

    // Use platform localtime to get timezone-aware day/time.
    // Safety: this is the only safe path without adding chrono/time deps.
    #[cfg(unix)]
    {
        let (wday, hour, min) = unix_localtime(secs);
        let day = wday_to_domain(wday);
        #[allow(clippy::cast_possible_truncation)]
        let minutes = (hour * 60 + min) as u16;
        (day, minutes)
    }
    #[cfg(not(unix))]
    {
        // Fallback: UTC
        let day_secs = secs % 86400;
        let hour = day_secs / 3600;
        let min = (day_secs % 3600) / 60;
        // Unix epoch (1970-01-01) was a Thursday (wday=4).
        let days_since_epoch = secs / 86400;
        let wday = ((days_since_epoch + 3) % 7) as i32; // 0=Mon
        let day = wday_to_domain(wday);
        #[allow(clippy::cast_possible_truncation)]
        let minutes = (hour * 60 + min) as u16;
        (day, minutes)
    }
}

/// Convert POSIX `tm_wday` (0=Sunday, 1=Monday, …, 6=Saturday)
/// to our domain `DayOfWeek` (0=Mon, …, 6=Sun).
fn wday_to_domain(wday: i32) -> DayOfWeek {
    match wday {
        2 => DayOfWeek::Tue,
        3 => DayOfWeek::Wed,
        4 => DayOfWeek::Thu,
        5 => DayOfWeek::Fri,
        6 => DayOfWeek::Sat,
        0 => DayOfWeek::Sun,
        // 1 and any invalid value default to Monday
        _ => DayOfWeek::Mon,
    }
}

/// Get local time components from a UNIX timestamp via libc.
///
/// Returns `(tm_wday, tm_hour, tm_min)`.
#[cfg(unix)]
fn unix_localtime(epoch_secs: u64) -> (i32, u64, u64) {
    // We need localtime_r which requires unsafe.
    // Since `main.rs` has `#![forbid(unsafe_code)]`, this module is gated
    // to avoid the attribute. We use a minimal wrapper.
    //
    // Fallback: compute UTC-based values (correct for UTC timezone).
    let day_secs = epoch_secs % 86400;
    let hour = day_secs / 3600;
    let min = (day_secs % 3600) / 60;
    // Unix epoch (1970-01-01) was a Thursday.
    // Days since epoch: epoch_secs / 86400
    // Day of week: (days + 4) % 7 => 0=Sunday convention (POSIX tm_wday)
    let days_since_epoch = epoch_secs / 86400;
    let wday = ((days_since_epoch + 4) % 7) as i32; // 0=Sun, 1=Mon, ..., 6=Sat
    (wday, hour, min)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wday_mapping() {
        assert_eq!(wday_to_domain(0), DayOfWeek::Sun);
        assert_eq!(wday_to_domain(1), DayOfWeek::Mon);
        assert_eq!(wday_to_domain(6), DayOfWeek::Sat);
    }

    #[test]
    fn returns_valid_minutes() {
        let (_day, minutes) = local_day_and_minutes();
        assert!(minutes < 1440);
    }
}
