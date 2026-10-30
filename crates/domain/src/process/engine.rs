use std::collections::HashMap;

use super::entity::{ProcessEntry, ProcessKey, ProcessTableStats};

/// The most ancestors a lineage walk returns. Deep enough for a container
/// runtime, a shell, an interpreter and what it launched, short enough that a
/// chain broken into a loop by a lost record still ends.
pub const MAX_LINEAGE: usize = 8;

/// The ancestors of a process, parent first, and how the walk ended.
///
/// The two flags are different statements and a reader is owed both. A
/// truncated chain went on past the bound and was cut on purpose; an
/// incomplete one names a parent the table no longer holds, because it
/// exited before anything it started was seen or was evicted at a bound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lineage {
    /// At most [`MAX_LINEAGE`], parent first, live or kept after their exit.
    pub ancestors: Vec<ProcessEntry>,
    /// The walk stopped at the bound with a further ancestor named.
    pub truncated: bool,
    /// The walk stopped at an ancestor that was named and never found.
    pub incomplete: bool,
}

impl Lineage {
    /// Whether the walk found nothing to say: no ancestor and no gap.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ancestors.is_empty() && !self.truncated && !self.incomplete
    }
}

/// What an exit did to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// The process is gone from the live table, kept as an ancestor or not.
    Purged,
    /// The table never held the pid.
    Missing,
    /// The table holds the pid for a later process than the one that exited:
    /// the exit is late and the live entry is left alone.
    Stale,
}

/// The bounded table of processes.
///
/// A pid is the key, because a pid is what every other subsystem has in its
/// hand. The table is not a cache and has no clock: an entry lives from the
/// exec or fork that created it to the exit that ends it. The bound is a
/// safety net for the one case the kernel cannot be relied on - an exit
/// notification lost because the ring buffer was full - and when it is
/// reached the oldest entry is dropped and counted, because a table that
/// grew without limit would be an out-of-memory kill on a node under fork
/// pressure.
///
/// An exited process is kept, apart from the live ones and under a bound of
/// its own, for as long as a process it started is still known: the shell of
/// a one-liner exits long before the binary it launched opens a socket, and
/// the lineage of that socket is the one thing an operator wants named. It
/// is keyed by pid and start time, since its pid may already belong to
/// somebody else, and it goes when its last descendant does.
#[derive(Debug)]
pub struct ProcessTable {
    entries: HashMap<u32, ProcessEntry>,
    ancestors: HashMap<ProcessKey, ProcessEntry>,
    /// How many known processes, live or kept, name each key as parent.
    children: HashMap<ProcessKey, u32>,
    capacity: usize,
    ancestor_capacity: usize,
    recorded: u64,
    replaced: u64,
    evicted: u64,
    purged: u64,
    missing_exit: u64,
    forks: u64,
    ancestors_evicted: u64,
}

impl ProcessTable {
    /// A table holding at most `capacity` live processes, and a quarter as
    /// many exited ancestors.
    ///
    /// A zero capacity is raised to one rather than refused: a table that can
    /// hold nothing would answer every lookup with "unknown" and look exactly
    /// like a kernel that refused the attach.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            entries: HashMap::with_capacity(capacity.min(4096)),
            ancestors: HashMap::new(),
            children: HashMap::new(),
            capacity,
            ancestor_capacity: (capacity / 4).max(1),
            recorded: 0,
            replaced: 0,
            evicted: 0,
            purged: 0,
            missing_exit: 0,
            forks: 0,
            ancestors_evicted: 0,
        }
    }

    /// Record an exec, returning the entry it replaced for the same pid.
    ///
    /// A replacement is the ordinary case rather than an error: a shell forks,
    /// the child execs the shell's own image and then execs the binary it was
    /// asked to run, and the table must end up on the second one.
    pub fn record(&mut self, entry: ProcessEntry) -> Option<ProcessEntry> {
        self.recorded += 1;
        self.insert(entry)
    }

    /// Record a fork: a new process that runs its parent's image until it
    /// execs. Counted apart from execs, so `recorded` keeps meaning what it
    /// meant before forks were followed.
    pub fn record_fork(&mut self, entry: ProcessEntry) -> Option<ProcessEntry> {
        self.forks += 1;
        self.insert(entry)
    }

    fn insert(&mut self, entry: ProcessEntry) -> Option<ProcessEntry> {
        let pid = entry.pid;
        if let Some(parent) = entry.parent_key() {
            *self.children.entry(parent).or_insert(0) += 1;
        }
        let previous = self.entries.insert(pid, entry);
        if let Some(previous) = &previous {
            self.replaced += 1;
            let same_process =
                self.entries.get(&pid).map(ProcessEntry::key) == Some(previous.key());
            if same_process {
                // An exec on a known process: what named it as parent still
                // does, only its own parent link is renewed.
                if let Some(parent) = previous.parent_key() {
                    self.release_parent(parent);
                }
            } else {
                // The pid moved to another process whose predecessor's exit
                // never arrived: that predecessor is over.
                let at = self.entries.get(&pid).map_or(0, |e| e.started_at_ns);
                self.retire(previous.clone(), at);
            }
        } else {
            self.evict_while_over_capacity();
        }
        previous
    }

    /// The kernel said `pid` exited. `start_ns` is the start the exit
    /// carried, where it carried one, which tells a late exit from the exit
    /// of the process the table now holds.
    pub fn purge(&mut self, pid: u32, start_ns: Option<u64>, at_ns: u64) -> PurgeOutcome {
        let Some(held) = self.entries.get(&pid) else {
            self.missing_exit += 1;
            return PurgeOutcome::Missing;
        };
        if let (Some(exited), Some(live)) = (start_ns, held.start_ns)
            && exited != live
        {
            self.missing_exit += 1;
            return PurgeOutcome::Stale;
        }
        let Some(entry) = self.entries.remove(&pid) else {
            return PurgeOutcome::Missing;
        };
        self.purged += 1;
        self.retire(entry, at_ns);
        PurgeOutcome::Purged
    }

    /// A process left the live table: keep it while something names it as
    /// parent, otherwise let it go and tell its own parent.
    fn retire(&mut self, mut entry: ProcessEntry, at_ns: u64) {
        let key = entry.key();
        if self.children.get(&key).copied().unwrap_or(0) > 0 {
            entry.exited_at_ns = Some(at_ns);
            self.ancestors.insert(key, entry);
            self.evict_ancestors_while_over_capacity();
        } else if let Some(parent) = entry.parent_key() {
            self.release_parent(parent);
        }
    }

    /// One fewer process names `parent`; a kept ancestor nothing names any
    /// more goes, and the release walks up from there.
    fn release_parent(&mut self, parent: ProcessKey) {
        let mut next = Some(parent);
        while let Some(key) = next.take() {
            let Some(count) = self.children.get_mut(&key) else {
                return;
            };
            *count = count.saturating_sub(1);
            if *count > 0 {
                return;
            }
            self.children.remove(&key);
            if let Some(gone) = self.ancestors.remove(&key) {
                next = gone.parent_key();
            }
        }
    }

    /// The entry for `pid`, if the table holds one live.
    #[must_use]
    pub fn get(&self, pid: u32) -> Option<&ProcessEntry> {
        self.entries.get(&pid)
    }

    /// Mutable access to the live entry for `pid`, for the enrichment that
    /// lands after the exec has been recorded.
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessEntry> {
        self.entries.get_mut(&pid)
    }

    /// The process `key` names: the live entry when its pid still belongs to
    /// it, the kept ancestor otherwise. An unknown start matches the live
    /// holder of the pid, which is the best the `/proc` read can say.
    #[must_use]
    pub fn find(&self, key: ProcessKey) -> Option<&ProcessEntry> {
        if let Some(live) = self.entries.get(&key.pid)
            && (key.start_ns == 0 || live.start_ns.unwrap_or(0) == key.start_ns)
        {
            return Some(live);
        }
        self.ancestors.get(&key)
    }

    /// The ancestors of the live process `pid`, parent first, at most
    /// [`MAX_LINEAGE`] of them. The walk stops at the first ancestor the table
    /// does not know, and the boolean says whether one was named and not
    /// found, so a reader can tell a chain that ends at the root from one the
    /// table lost.
    #[must_use]
    pub fn lineage(&self, pid: u32) -> Lineage {
        let mut lineage = Lineage::default();
        let Some(mut current) = self.entries.get(&pid) else {
            return lineage;
        };
        loop {
            // Pid 0 is the idle task: the root, never in the table and
            // never lost.
            let Some(parent) = current.parent_key().filter(|p| p.pid != 0) else {
                return lineage;
            };
            if lineage.ancestors.len() == MAX_LINEAGE {
                lineage.truncated = true;
                return lineage;
            }
            let Some(found) = self.find(parent) else {
                lineage.incomplete = true;
                return lineage;
            };
            if found.key() == current.key() {
                return lineage;
            }
            lineage.ancestors.push(found.clone());
            current = found;
        }
    }

    /// Every live entry, newest exec first.
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

    /// How many live entries the table holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table holds nothing live.
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
            forks: self.forks,
            ancestors: self.ancestors.len(),
            ancestor_capacity: self.ancestor_capacity,
            ancestors_evicted: self.ancestors_evicted,
        }
    }

    /// Drop the oldest entry until the table is inside its bound.
    ///
    /// Oldest rather than least-recently-read: the table has no read clock,
    /// and a long-lived daemon is exactly the process an operator is most
    /// likely to look up, so a read-based policy would be free to evict it
    /// during a fork storm it had no part in. Dropping the oldest is at least
    /// a rule somebody can predict, and the count says when it bit. An
    /// evicted entry is not kept as an ancestor: the table is out of room.
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
            if let Some(gone) = self.entries.remove(&oldest)
                && let Some(parent) = gone.parent_key()
            {
                self.release_parent(parent);
            }
            self.evicted += 1;
        }
    }

    /// Drop the ancestor that exited first until the kept set is inside its
    /// bound. Its descendants then end their chain one step short, which is
    /// what `ancestors_evicted` says.
    fn evict_ancestors_while_over_capacity(&mut self) {
        while self.ancestors.len() > self.ancestor_capacity {
            let Some(oldest) = self
                .ancestors
                .values()
                .min_by_key(|e| (e.exited_at_ns, e.pid))
                .map(ProcessEntry::key)
            else {
                return;
            };
            self.children.remove(&oldest);
            if let Some(gone) = self.ancestors.remove(&oldest)
                && let Some(parent) = gone.parent_key()
            {
                self.release_parent(parent);
            }
            self.ancestors_evicted += 1;
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
        assert_eq!(table.purge(10, None, 5), PurgeOutcome::Purged);
        assert!(table.get(10).is_none());
        assert_eq!(table.stats().purged, 1);
        assert_eq!(table.stats().missing_exit, 0);
    }

    #[test]
    fn an_exit_for_an_unknown_pid_is_counted_not_hidden() {
        let mut table = ProcessTable::new(8);
        assert_eq!(table.purge(999, None, 5), PurgeOutcome::Missing);
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

    fn child(pid: u32, start: u64, parent: (u32, u64), at: u64) -> ProcessEntry {
        let mut e = ProcessEntry::new(pid, format!("p{pid}"), at);
        e.start_ns = Some(start);
        e.parent_pid = Some(parent.0);
        e.parent_start_ns = Some(parent.1);
        e
    }

    #[test]
    fn an_exited_parent_is_kept_while_its_child_lives() {
        let mut table = ProcessTable::new(8);
        table.record(child(10, 100, (1, 0), 100));
        table.record_fork(child(11, 200, (10, 100), 200));
        assert_eq!(table.purge(10, Some(100), 300), PurgeOutcome::Purged);
        assert!(table.get(10).is_none());
        let lineage = table.lineage(11);
        let (chain, lost) = (lineage.ancestors, lineage.incomplete);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].pid, 10);
        assert_eq!(chain[0].exited_at_ns, Some(300));
        assert!(lost, "pid 1 was named and is not in the table");
        assert_eq!(table.stats().ancestors, 1);
        assert_eq!(table.stats().forks, 1);

        // The child goes, and the ancestor nothing names any more goes too.
        table.purge(11, Some(200), 400);
        assert_eq!(table.stats().ancestors, 0);
    }

    #[test]
    fn a_chain_of_exited_ancestors_goes_when_its_last_descendant_does() {
        let mut table = ProcessTable::new(8);
        table.record(child(10, 100, (0, 0), 1));
        table.record_fork(child(11, 110, (10, 100), 2));
        table.record_fork(child(12, 120, (11, 110), 3));
        table.purge(10, Some(100), 4);
        table.purge(11, Some(110), 5);
        let lineage = table.lineage(12);
        let (chain, lost) = (lineage.ancestors, lineage.incomplete);
        assert_eq!(
            chain.iter().map(|e| e.pid).collect::<Vec<_>>(),
            vec![11, 10]
        );
        assert!(!lost, "pid 0 is the root, not a lost ancestor");
        table.purge(12, Some(120), 6);
        assert_eq!(table.stats().ancestors, 0);
        assert!(table.children.is_empty());
    }

    #[test]
    fn a_reused_pid_does_not_stand_in_for_the_parent_that_held_it() {
        let mut table = ProcessTable::new(8);
        table.record(child(10, 100, (0, 0), 1));
        table.record_fork(child(11, 110, (10, 100), 2));
        table.purge(10, Some(100), 3);
        // Pid 10 is handed to an unrelated process.
        table.record(child(10, 500, (0, 0), 4));
        let chain = table.lineage(11).ancestors;
        assert_eq!(chain[0].start_ns, Some(100));
        assert_eq!(chain[0].exited_at_ns, Some(3));
    }

    #[test]
    fn a_late_exit_leaves_the_later_holder_of_the_pid_alone() {
        let mut table = ProcessTable::new(8);
        table.record(child(10, 500, (0, 0), 4));
        assert_eq!(table.purge(10, Some(100), 5), PurgeOutcome::Stale);
        assert!(table.get(10).is_some());
        assert_eq!(table.stats().missing_exit, 1);
    }

    #[test]
    fn an_exec_keeps_the_children_that_name_the_process() {
        let mut table = ProcessTable::new(8);
        table.record_fork(child(10, 100, (1, 0), 1));
        table.record_fork(child(11, 110, (10, 100), 2));
        // The parent execs: same process, new image.
        table.record(child(10, 100, (1, 0), 3));
        table.purge(10, Some(100), 4);
        assert_eq!(table.lineage(11).ancestors[0].pid, 10);
    }

    #[test]
    fn the_kept_ancestors_have_a_bound_of_their_own() {
        // Capacity 8 keeps two exited ancestors.
        let mut table = ProcessTable::new(8);
        for (n, pid) in (20..23u32).enumerate() {
            let start = 100 + n as u64;
            table.record(child(pid, start, (0, 0), start));
            table.record_fork(child(pid + 10, start + 50, (pid, start), start + 50));
            table.purge(pid, Some(start), 200 + n as u64);
        }
        let stats = table.stats();
        assert_eq!(stats.ancestor_capacity, 2);
        assert_eq!(stats.ancestors, 2);
        assert_eq!(stats.ancestors_evicted, 1);
        // The first to exit is what went, so its child's chain now ends early.
        let lineage = table.lineage(30);
        assert!(lineage.ancestors.is_empty());
        assert!(lineage.incomplete);
        assert_eq!(table.lineage(32).ancestors.len(), 1);
    }

    #[test]
    fn a_lineage_is_bounded() {
        let mut table = ProcessTable::new(64);
        table.record(child(1, 1, (0, 0), 1));
        for pid in 2..=20u32 {
            let start = u64::from(pid);
            table.record_fork(child(pid, start, (pid - 1, start - 1), start));
        }
        let lineage = table.lineage(20);
        assert_eq!(lineage.ancestors.len(), MAX_LINEAGE);
        assert_eq!(lineage.ancestors[0].pid, 19);
        assert!(lineage.truncated);
        assert!(!lineage.incomplete);
    }

    #[test]
    fn a_chain_ending_exactly_at_the_bound_is_not_truncated() {
        let mut table = ProcessTable::new(64);
        table.record(child(1, 1, (0, 0), 1));
        for pid in 2..=9u32 {
            let start = u64::from(pid);
            table.record_fork(child(pid, start, (pid - 1, start - 1), start));
        }
        let lineage = table.lineage(9);
        assert_eq!(lineage.ancestors.len(), 8);
        assert!(!lineage.truncated);
        assert!(!lineage.is_empty());
        assert!(table.lineage(1).is_empty());
    }
}
