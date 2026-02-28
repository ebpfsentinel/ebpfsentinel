use std::collections::{HashMap, HashSet};

/// Day of week (0=Monday, 6=Sunday) matching `POSIX` `tm_wday` convention adjusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DayOfWeek {
    Mon = 0,
    Tue = 1,
    Wed = 2,
    Thu = 3,
    Fri = 4,
    Sat = 5,
    Sun = 6,
}

/// A schedule defines time windows when a firewall rule is active.
#[derive(Debug, Clone)]
pub struct Schedule {
    pub id: String,
    pub entries: Vec<ScheduleEntry>,
}

/// A single time window within a schedule.
#[derive(Debug, Clone)]
pub struct ScheduleEntry {
    pub days: Vec<DayOfWeek>,
    /// Start time as minutes since midnight (0–1439).
    pub start_minutes: u16,
    /// End time as minutes since midnight (0–1439).
    pub end_minutes: u16,
}

/// Maps rule IDs to their schedule IDs.
pub type RuleScheduleMap = HashMap<String, String>;

/// Service that evaluates time-based rule activation.
///
/// Designed to be called periodically (every 60s) from a `tokio::time::interval`.
/// Returns the set of rule IDs that should be active at the current time.
#[derive(Default)]
pub struct ScheduleService {
    schedules: HashMap<String, Schedule>,
    /// Maps `rule_id` → `schedule_id`.
    rule_schedule: RuleScheduleMap,
    /// Currently active rule IDs (for edge-triggered reload detection).
    active_rules: HashSet<String>,
}

impl ScheduleService {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load schedules and rule-schedule mappings.
    pub fn reload(&mut self, schedules: HashMap<String, Schedule>, rule_schedule: RuleScheduleMap) {
        self.schedules = schedules;
        self.rule_schedule = rule_schedule;
    }

    /// Evaluate all schedules against the given day and minutes.
    ///
    /// Returns `Some(active_rule_ids)` if the active set changed, `None` if unchanged.
    pub fn evaluate_at(&mut self, day: DayOfWeek, minutes: u16) -> Option<HashSet<String>> {
        let mut new_active = HashSet::new();

        for (rule_id, schedule_id) in &self.rule_schedule {
            if let Some(schedule) = self.schedules.get(schedule_id)
                && is_active(schedule, day, minutes)
            {
                new_active.insert(rule_id.clone());
            }
        }

        if new_active == self.active_rules {
            None
        } else {
            self.active_rules.clone_from(&new_active);
            Some(new_active)
        }
    }

    /// Return the current set of active scheduled rules.
    pub fn active_rules(&self) -> &HashSet<String> {
        &self.active_rules
    }

    /// Check if a specific rule is currently active.
    ///
    /// Rules without a schedule are always active.
    pub fn is_rule_active(&self, rule_id: &str) -> bool {
        if !self.rule_schedule.contains_key(rule_id) {
            return true;
        }
        self.active_rules.contains(rule_id)
    }
}

/// Check if a schedule is active at the given day + time (minutes since midnight).
fn is_active(schedule: &Schedule, day: DayOfWeek, minutes: u16) -> bool {
    schedule.entries.iter().any(|entry| {
        entry.days.contains(&day) && minutes >= entry.start_minutes && minutes < entry.end_minutes
    })
}

/// Parse a day-of-week string to `DayOfWeek`.
pub fn parse_day(s: &str) -> Option<DayOfWeek> {
    match s.to_lowercase().as_str() {
        "mon" | "monday" => Some(DayOfWeek::Mon),
        "tue" | "tuesday" => Some(DayOfWeek::Tue),
        "wed" | "wednesday" => Some(DayOfWeek::Wed),
        "thu" | "thursday" => Some(DayOfWeek::Thu),
        "fri" | "friday" => Some(DayOfWeek::Fri),
        "sat" | "saturday" => Some(DayOfWeek::Sat),
        "sun" | "sunday" => Some(DayOfWeek::Sun),
        _ => None,
    }
}

/// Parse a time range string `"HH:MM-HH:MM"` into `(start_minutes, end_minutes)`.
pub fn parse_time_range(s: &str) -> Option<(u16, u16)> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 2 {
        return None;
    }
    let start = parse_hhmm(parts[0].trim())?;
    let end = parse_hhmm(parts[1].trim())?;
    Some((start, end))
}

/// Parse `"HH:MM"` to minutes since midnight.
fn parse_hhmm(s: &str) -> Option<u16> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let h: u16 = parts[0].parse().ok()?;
    let m: u16 = parts[1].parse().ok()?;
    if h > 23 || m > 59 {
        return None;
    }
    Some(h * 60 + m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_schedule(days: Vec<DayOfWeek>, start: u16, end: u16) -> Schedule {
        Schedule {
            id: "test".to_string(),
            entries: vec![ScheduleEntry {
                days,
                start_minutes: start,
                end_minutes: end,
            }],
        }
    }

    #[test]
    fn parse_day_valid() {
        assert_eq!(parse_day("mon"), Some(DayOfWeek::Mon));
        assert_eq!(parse_day("friday"), Some(DayOfWeek::Fri));
        assert_eq!(parse_day("SUN"), Some(DayOfWeek::Sun));
    }

    #[test]
    fn parse_day_invalid() {
        assert_eq!(parse_day("funday"), None);
    }

    #[test]
    fn parse_time_range_valid() {
        let (start, end) = parse_time_range("08:00-18:00").unwrap();
        assert_eq!(start, 480); // 8*60
        assert_eq!(end, 1080); // 18*60
    }

    #[test]
    fn parse_time_range_invalid() {
        assert!(parse_time_range("invalid").is_none());
        assert!(parse_time_range("08:00").is_none());
    }

    #[test]
    fn parse_hhmm_valid() {
        assert_eq!(parse_hhmm("00:00"), Some(0));
        assert_eq!(parse_hhmm("23:59"), Some(1439));
        assert_eq!(parse_hhmm("12:30"), Some(750));
    }

    #[test]
    fn parse_hhmm_invalid() {
        assert_eq!(parse_hhmm("25:00"), None);
        assert_eq!(parse_hhmm("12:60"), None);
        assert_eq!(parse_hhmm("abc"), None);
    }

    #[test]
    fn schedule_active_within_window() {
        let sched = make_schedule(vec![DayOfWeek::Mon], 480, 1080);
        assert!(is_active(&sched, DayOfWeek::Mon, 720)); // 12:00
    }

    #[test]
    fn schedule_inactive_outside_window() {
        let sched = make_schedule(vec![DayOfWeek::Mon], 480, 1080);
        assert!(!is_active(&sched, DayOfWeek::Mon, 1140)); // 19:00
    }

    #[test]
    fn schedule_inactive_wrong_day() {
        let sched = make_schedule(vec![DayOfWeek::Mon], 480, 1080);
        assert!(!is_active(&sched, DayOfWeek::Tue, 720));
    }

    #[test]
    fn schedule_boundary_start_inclusive() {
        let sched = make_schedule(vec![DayOfWeek::Mon], 480, 1080);
        assert!(is_active(&sched, DayOfWeek::Mon, 480)); // exactly at start
    }

    #[test]
    fn schedule_boundary_end_exclusive() {
        let sched = make_schedule(vec![DayOfWeek::Mon], 480, 1080);
        assert!(!is_active(&sched, DayOfWeek::Mon, 1080)); // exactly at end
    }

    #[test]
    fn edge_triggered_no_change() {
        let mut svc = ScheduleService::new();
        // Empty service with no rules → empty active set matches initial state → None
        let result = svc.evaluate_at(DayOfWeek::Mon, 720);
        assert!(result.is_none());
    }

    #[test]
    fn edge_triggered_detects_change() {
        let mut svc = ScheduleService::new();
        let mut schedules = HashMap::new();
        schedules.insert(
            "biz".to_string(),
            make_schedule(vec![DayOfWeek::Mon], 480, 1080),
        );
        let mut rule_schedule = HashMap::new();
        rule_schedule.insert("r1".to_string(), "biz".to_string());
        svc.reload(schedules, rule_schedule);

        // First eval: active set changes from {} to {r1} → Some
        let result = svc.evaluate_at(DayOfWeek::Mon, 720);
        assert!(result.is_some());
        assert!(result.unwrap().contains("r1"));

        // Second eval same time → no change → None
        let result2 = svc.evaluate_at(DayOfWeek::Mon, 720);
        assert!(result2.is_none());

        // Third eval outside window → change back to {} → Some
        let result3 = svc.evaluate_at(DayOfWeek::Mon, 1200);
        assert!(result3.is_some());
        assert!(result3.unwrap().is_empty());
    }

    #[test]
    fn unscheduled_rules_always_active() {
        let svc = ScheduleService::new();
        assert!(svc.is_rule_active("unscheduled-rule"));
    }

    #[test]
    fn scheduled_rule_inactive_when_schedule_missing() {
        let mut svc = ScheduleService::new();
        let mut rule_schedule = HashMap::new();
        rule_schedule.insert("rule-1".to_string(), "business".to_string());
        svc.reload(HashMap::new(), rule_schedule);
        assert!(!svc.is_rule_active("rule-1"));
    }

    #[test]
    fn scheduled_rule_active_in_window() {
        let mut svc = ScheduleService::new();
        let mut schedules = HashMap::new();
        schedules.insert(
            "business".to_string(),
            make_schedule(
                vec![
                    DayOfWeek::Mon,
                    DayOfWeek::Tue,
                    DayOfWeek::Wed,
                    DayOfWeek::Thu,
                    DayOfWeek::Fri,
                ],
                480,
                1080,
            ),
        );
        let mut rule_schedule = HashMap::new();
        rule_schedule.insert("guest-wifi".to_string(), "business".to_string());
        svc.reload(schedules, rule_schedule);

        // Monday 12:00 → active
        svc.evaluate_at(DayOfWeek::Mon, 720);
        assert!(svc.is_rule_active("guest-wifi"));

        // Sunday 12:00 → inactive
        svc.evaluate_at(DayOfWeek::Sun, 720);
        assert!(!svc.is_rule_active("guest-wifi"));
    }
}
