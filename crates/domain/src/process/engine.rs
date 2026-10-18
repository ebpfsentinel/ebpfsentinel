use std::collections::HashMap;

use super::entity::{ProcessEntry, ProcessTableStats};

/// The bounded table of live processes.
///
/// A pid is the key, because a pid is what every other subsystem has in its
/// hand. The table is not a cache and has no clock: an entry lives from the
/// exec that created it to the exit that ends it. The bound is a safety net
/// for the one case the kernel cannot be relied on - an exit notification
/// lost because the ring buffer was full - and when it is reached the oldest
/// exec is dropped and counted, because a table that grew without limit would
/// be an out-of-memory kill on a node under fork pressure.
#[derive(Debug)]
pub struct ProcessTable {
    entries: HashMap<u32, ProcessEntry>,
    capacity: usize,
    recorded: u64,
    replaced: u64,
    evicted: u64,
    purged: u64,
    missing_exit: u64,
}

impl ProcessTable {
    /// A table holding at most `capacity` live processes.
    ///
    /// A zero capacity is raised to one rather than refused: a table that can
    /// hold nothing would answer every lookup with "unknown" and look exactly
    /// like a kernel that refused the attach.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            entries: HashMap::with_capacity(capacity.min(4096)),
            capacity,
            recorded: 0,
            replaced: 0,
            evicted: 0,
            purged: 0,
            missing_exit: 0,
        }
    }

    /// Record an exec, returning the entry it replaced for the same pid.
    ///
    /// A replacement is the ordinary case rather than an error: a shell forks,
    /// the child execs the shell's own image and then execs the binary it was
    /// asked to run, and the table must end up on the second one.
    pub fn record(&mut self, entry: ProcessEntry) -> Option<ProcessEntry> {
        self.recorded += 1;
        let pid = entry.pid;
        if let Some(previous) = self.entries.insert(pid, entry) {
            self.replaced += 1;
            return Some(previous);
        }
        self.evict_while_over_capacity();
        None
    }

    /// Remove the entry for `pid` because the kernel said it exited.
    ///
    /// Returns what was removed, or `None` when the table never held it,
    /// which counts as a missing exec and is visible in the stats.
    pub fn purge(&mut self, pid: u32) -> Option<ProcessEntry> {
        if let Some(entry) = self.entries.remove(&pid) {
            self.purged += 1;
            Some(entry)
        } else {
            self.missing_exit += 1;
            None
        }
    }

    /// The entry for `pid`, if the table holds one.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.entries.get(&pid)
    }

    /// Mutable access to the entry for `pid`, for the enrichment that lands
    /// after the exec has been recorded.
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessEntry> {
        self.entries.get_mut(&pid)
    }

    /// Every entry, newest exec first.
    #[must_use]
    pub fn list(&self) -> Vec<ProcessEntry> {
        let mut entries: Vec<ProcessEntry> = self.entries.values().cloned().collect();
        entries.sort_unstable_by(|a, b| {
            b.started_at_ns
                .cmp(&a.started_at_ns)
                .then_with(|| a.pid.cmp(&b.pid))
        });
        entries
    }

    /// How many entries the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The counters an operator needs to judge whether the table is honest.
    #[must_use]
    pub fn stats(&self) -> ProcessTableStats {
        ProcessTableStats {
            capacity: self.capacity,
            entries: self.entries.len(),
            recorded: self.recorded,
            replaced: self.replaced,
            evicted: self.evicted,
            purged: self.purged,
            missing_exit: self.missing_exit,
        }
    }

    /// Drop the oldest exec until the table is inside its bound.
    ///
    /// Oldest rather than least-recently-read: the table has no read clock,
    /// and a long-lived daemon is exactly the process an operator is most
    /// likely to look up, so a read-based policy would be free to evict it
    /// during a fork storm it had no part in. Dropping the oldest is at least
    /// a rule somebody can predict, and the count says when it bit.
    fn evict_while_over_capacity(&mut self) {
        while self.entries.len() > self.capacity {
            let Some(oldest) = self
                .entries
                .values()
                .min_by_key(|e| (e.started_at_ns, e.pid))
                .map(|e| e.pid)
            else {
                return;
            };
            self.entries.remove(&oldest);
            self.evicted += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::entity::ProcessIdentity;

    fn entry(pid: u32, at: u64) -> ProcessEntry {
        ProcessEntry::new(pid, format!("p{pid}"), at)
    }

    #[test]
    fn an_exec_is_readable_by_pid() {
        let mut table = ProcessTable::new(8);
        assert!(table.record(entry(10, 1)).is_none());
        assert_eq!(table.get(10).map(|e| e.pid), Some(10));
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
    }

    #[test]
    fn a_second_exec_on_one_pid_replaces_the_first() {
        let mut table = ProcessTable::new(8);
        table.record(entry(10, 1));
        let replaced = table.record(entry(10, 2));
        assert_eq!(replaced.map(|e| e.started_at_ns), Some(1));
        assert_eq!(table.len(), 1);
        assert_eq!(table.get(10).unwrap().started_at_ns, 2);
        assert_eq!(table.stats().replaced, 1);
    }

    #[test]
    fn an_exit_purges_the_pid_rather_than_ageing_it_out() {
        let mut table = ProcessTable::new(8);
        table.record(entry(10, 1));
        assert!(table.purge(10).is_some());
        assert!(table.get(10).is_none());
        assert_eq!(table.stats().purged, 1);
        assert_eq!(table.stats().missing_exit, 0);
    }

    #[test]
    fn an_exit_for_an_unknown_pid_is_counted_not_hidden() {
        let mut table = ProcessTable::new(8);
        assert!(table.purge(999).is_none());
        assert_eq!(table.stats().missing_exit, 1);
    }

    #[test]
    fn the_bound_holds_and_the_oldest_exec_is_what_goes() {
        let mut table = ProcessTable::new(3);
        for pid in 1..=5u32 {
            table.record(entry(pid, u64::from(pid)));
        }
        assert_eq!(table.len(), 3);
        assert!(table.get(1).is_none());
        assert!(table.get(2).is_none());
        assert!(table.get(5).is_some());
        assert_eq!(table.stats().evicted, 2);
    }

    #[test]
    fn a_zero_capacity_table_still_holds_one_process() {
        let mut table = ProcessTable::new(0);
        table.record(entry(1, 1));
        assert_eq!(table.len(), 1);
        assert_eq!(table.stats().capacity, 1);
    }

    #[test]
    fn the_listing_is_newest_exec_first() {
        let mut table = ProcessTable::new(8);
        table.record(entry(1, 10));
        table.record(entry(2, 30));
        table.record(entry(3, 20));
        let pids: Vec<u32> = table.list().iter().map(|e| e.pid).collect();
        assert_eq!(pids, vec![2, 3, 1]);
    }

    #[test]
    fn enrichment_lands_on_the_entry_the_exec_created() {
        let mut table = ProcessTable::new(8);
        table.record(entry(7, 1));
        let held = table.get_mut(7).unwrap();
        held.identity = ProcessIdentity::Path {
            path: "/usr/bin/curl".to_string(),
            dev: 64,
            inode: 99,
        };
        held.command_line = Some("curl https://example.test".to_string());
        assert_eq!(table.get(7).unwrap().identity.path(), Some("/usr/bin/curl"));
    }

    #[test]
    fn the_stats_count_every_exec_including_the_replacements() {
        let mut table = ProcessTable::new(8);
        table.record(entry(1, 1));
        table.record(entry(1, 2));
        table.record(entry(2, 3));
        let stats = table.stats();
        assert_eq!(stats.recorded, 3);
        assert_eq!(stats.replaced, 1);
        assert_eq!(stats.entries, 2);
    }
}
