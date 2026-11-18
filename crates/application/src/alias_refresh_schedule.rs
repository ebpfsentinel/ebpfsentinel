//! When each timed alias is next refreshed.
//!
//! A URL table or a DNS name carries its own refresh interval, so each one is
//! due on its own clock rather than on a cadence shared with the `GeoIP`
//! database. The schedule is rebuilt against the loaded aliases on every
//! call, which is how a reload that adds, drops or re-times an alias is
//! picked up without restarting anything.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Next due time of every timed alias, by name.
#[derive(Debug, Default)]
pub struct AliasRefreshSchedule {
    entries: HashMap<String, Entry>,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    interval: Duration,
    next: Instant,
}

impl AliasRefreshSchedule {
    /// An empty schedule. The first [`Self::due`] sets every alias one
    /// interval out, because start-up has just resolved all of them.
    pub fn new() -> Self {
        Self::default()
    }

    /// Bring the schedule in line with `aliases` (name, interval in seconds)
    /// and return the names due at `now`, each moved one interval on.
    ///
    /// An alias seen for the first time after the schedule was started is
    /// due at once: a reload loads its definition, never its addresses. An
    /// alias whose interval changed starts over on the new one.
    pub fn due(&mut self, now: Instant, aliases: &[(String, u64)], started: bool) -> Vec<String> {
        self.entries
            .retain(|name, _| aliases.iter().any(|(n, _)| n == name));
        let mut due = Vec::new();
        for (name, secs) in aliases {
            let interval = Duration::from_secs((*secs).max(1));
            match self.entries.get_mut(name) {
                Some(entry) if entry.interval == interval => {
                    if entry.next <= now {
                        entry.next = now + interval;
                        due.push(name.clone());
                    }
                }
                Some(entry) => {
                    entry.interval = interval;
                    entry.next = now + interval;
                }
                None => {
                    if started {
                        due.push(name.clone());
                    }
                    self.entries.insert(
                        name.clone(),
                        Entry {
                            interval,
                            next: now + interval,
                        },
                    );
                }
            }
        }
        due.sort();
        due
    }

    /// The earliest due time, `None` while no alias is timed.
    pub fn next_due(&self) -> Option<Instant> {
        self.entries.values().map(|e| e.next).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[(&str, u64)]) -> Vec<(String, u64)> {
        items.iter().map(|(n, s)| ((*n).to_string(), *s)).collect()
    }

    #[test]
    fn each_alias_is_due_on_its_own_interval() {
        let t0 = Instant::now();
        let mut s = AliasRefreshSchedule::new();
        let aliases = set(&[("dns", 10), ("url", 30)]);
        assert!(s.due(t0, &aliases, false).is_empty());
        assert_eq!(s.next_due(), Some(t0 + Duration::from_secs(10)));

        assert_eq!(
            s.due(t0 + Duration::from_secs(10), &aliases, true),
            vec!["dns"]
        );
        assert_eq!(
            s.due(t0 + Duration::from_secs(20), &aliases, true),
            vec!["dns"]
        );
        assert_eq!(
            s.due(t0 + Duration::from_secs(30), &aliases, true),
            vec!["dns", "url"]
        );
        assert!(
            s.due(t0 + Duration::from_secs(31), &aliases, true)
                .is_empty()
        );
    }

    #[test]
    fn an_alias_added_by_a_reload_is_due_at_once() {
        let t0 = Instant::now();
        let mut s = AliasRefreshSchedule::new();
        s.due(t0, &set(&[("dns", 10)]), false);
        let after = set(&[("dns", 10), ("new", 3600)]);
        assert_eq!(
            s.due(t0 + Duration::from_secs(1), &after, true),
            vec!["new"]
        );
        assert!(s.due(t0 + Duration::from_secs(2), &after, true).is_empty());
    }

    #[test]
    fn a_dropped_alias_leaves_and_a_retimed_one_starts_over() {
        let t0 = Instant::now();
        let mut s = AliasRefreshSchedule::new();
        s.due(t0, &set(&[("a", 10), ("b", 10)]), false);
        let after = set(&[("a", 100)]);
        assert!(s.due(t0 + Duration::from_secs(5), &after, true).is_empty());
        assert_eq!(s.next_due(), Some(t0 + Duration::from_secs(105)));
        assert!(s.due(t0 + Duration::from_secs(10), &after, true).is_empty());
    }

    #[test]
    fn no_timed_alias_means_nothing_to_wait_for() {
        let mut s = AliasRefreshSchedule::new();
        assert!(s.due(Instant::now(), &[], true).is_empty());
        assert_eq!(s.next_due(), None);
    }
}
