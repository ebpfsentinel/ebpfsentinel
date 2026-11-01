//! The supporting signal read from the file watcher alone: many distinct
//! files rewritten by one actor inside one window.
//!
//! A count of changes is not the signal, since a database rewriting one file
//! a thousand times is ordinary. Distinct paths are, and only past a number no
//! interactive workload reaches in a minute. A backup or a package upgrade
//! does reach it, which is why the signal is only ever supporting.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::process::entity::ProcessKey;

use super::actor::Actor;
use super::engine::{RANSOM_ACTORS_MAX, RANSOM_WINDOW_NS};
use super::signal::{RansomSignal, SignalKind};

/// How many distinct files one actor rewrites in a window before the signal
/// is raised.
pub const RANSOM_DISTINCT_REWRITES: usize = 100;

#[derive(Debug)]
struct Run {
    opened_ns: u64,
    last_ns: u64,
    paths: HashSet<u64>,
    raised: bool,
}

/// Distinct rewritten paths per actor, in windows that open at the first
/// change and close `window_ns` later. Each actor holds at most `threshold`
/// path hashes, and at most `max_actors` actors are held.
#[derive(Debug)]
pub struct DistinctRewrites {
    window_ns: u64,
    threshold: usize,
    max_actors: usize,
    runs: HashMap<ProcessKey, Run>,
}

impl Default for DistinctRewrites {
    fn default() -> Self {
        Self::new(
            RANSOM_WINDOW_NS,
            RANSOM_DISTINCT_REWRITES,
            RANSOM_ACTORS_MAX,
        )
    }
}

fn hash(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

impl DistinctRewrites {
    #[must_use]
    pub fn new(window_ns: u64, threshold: usize, max_actors: usize) -> Self {
        Self {
            window_ns,
            threshold: threshold.max(1),
            max_actors: max_actors.max(1),
            runs: HashMap::new(),
        }
    }

    /// How many actors are held now.
    #[must_use]
    pub fn actors(&self) -> usize {
        self.runs.len()
    }

    /// Count a change to `path` by `pid` on behalf of `actor`, and return the
    /// signal the first time the actor's window reaches the threshold.
    pub fn record(
        &mut self,
        actor: &Actor,
        pid: u32,
        path: &str,
        at_ns: u64,
    ) -> Option<RansomSignal> {
        if !self.runs.contains_key(&actor.key) {
            self.make_room(at_ns);
        }
        let window = self.window_ns;
        let run = self.runs.entry(actor.key).or_insert_with(|| Run {
            opened_ns: at_ns,
            last_ns: at_ns,
            paths: HashSet::new(),
            raised: false,
        });
        if at_ns.saturating_sub(run.opened_ns) > window {
            run.opened_ns = at_ns;
            run.paths.clear();
            run.raised = false;
        }
        run.last_ns = run.last_ns.max(at_ns);
        if run.raised {
            return None;
        }
        run.paths.insert(hash(path));
        if run.paths.len() < self.threshold {
            return None;
        }
        run.raised = true;
        let seconds = at_ns.saturating_sub(run.opened_ns) / 1_000_000_000;
        run.paths.clear();
        Some(RansomSignal {
            kind: SignalKind::DistinctRewrites,
            actor: actor.clone(),
            pid,
            at_ns,
            evidence: format!(
                "{} distinct files rewritten in {seconds} s, the last {path}",
                self.threshold
            ),
        })
    }

    fn make_room(&mut self, at_ns: u64) {
        if self.runs.len() < self.max_actors {
            return;
        }
        let window = self.window_ns;
        self.runs
            .retain(|_, run| at_ns.saturating_sub(run.last_ns) <= window);
        while self.runs.len() >= self.max_actors {
            let Some(oldest) = self
                .runs
                .iter()
                .min_by_key(|(_, run)| run.last_ns)
                .map(|(key, _)| *key)
            else {
                return;
            };
            self.runs.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn actor(pid: u32) -> Actor {
        Actor {
            key: ProcessKey { pid, start_ns: 1 },
            pid,
            exe: None,
        }
    }

    #[test]
    fn the_threshold_of_distinct_paths_raises_the_signal_once() {
        let mut rewrites = DistinctRewrites::new(RANSOM_WINDOW_NS, 3, 8);
        let a = actor(10);
        assert!(rewrites.record(&a, 11, "/d/a", S).is_none());
        assert!(rewrites.record(&a, 12, "/d/a", 2 * S).is_none());
        assert!(rewrites.record(&a, 12, "/d/b", 3 * S).is_none());
        let signal = rewrites.record(&a, 13, "/d/c", 4 * S).unwrap();
        assert_eq!(signal.kind, SignalKind::DistinctRewrites);
        assert_eq!(signal.pid, 13);
        assert_eq!(
            signal.evidence,
            "3 distinct files rewritten in 3 s, the last /d/c"
        );
        assert!(rewrites.record(&a, 13, "/d/e", 5 * S).is_none());
    }

    #[test]
    fn a_new_window_counts_from_zero() {
        let mut rewrites = DistinctRewrites::new(RANSOM_WINDOW_NS, 2, 8);
        let a = actor(10);
        rewrites.record(&a, 10, "/a", 0);
        assert!(rewrites.record(&a, 10, "/b", 61 * S).is_none());
        assert!(rewrites.record(&a, 10, "/c", 62 * S).is_some());
    }

    #[test]
    fn two_actors_count_apart_and_the_bound_holds() {
        let mut rewrites = DistinctRewrites::new(RANSOM_WINDOW_NS, 2, 2);
        rewrites.record(&actor(1), 1, "/a", S);
        assert!(rewrites.record(&actor(2), 2, "/b", 2 * S).is_none());
        rewrites.record(&actor(3), 3, "/c", 3 * S);
        assert_eq!(rewrites.actors(), 2);
        // Actor 1 was let go, so its next path is its first again.
        assert!(rewrites.record(&actor(1), 1, "/d", 4 * S).is_none());
    }
}
