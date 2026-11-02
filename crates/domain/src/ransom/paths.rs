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
use super::replace::RANSOM_REPLACEMENTS;
use super::signal::{RansomSignal, SignalKind};

/// How many distinct files one actor rewrites in a window before the signal
/// is raised.
pub const RANSOM_DISTINCT_REWRITES: usize = 100;

/// How many files one actor rewrites from ordinary to near-random content in a
/// window before the signal is raised.
pub const RANSOM_ENTROPY_RISES: usize = 20;

/// How many files one actor leaves with leading bytes that no longer match
/// their extension in a window before the signal is raised. Decisive on its
/// own, so it waits for more than a stray mislabelled file or two.
pub const RANSOM_HEADER_MISMATCHES: usize = 10;

#[derive(Debug)]
struct Run {
    opened_ns: u64,
    last_ns: u64,
    paths: HashSet<u64>,
    raised: bool,
}

/// Distinct paths per actor that showed one signal's fact, in windows that
/// open at the first such path and close `window_ns` later. Each actor holds
/// at most `threshold` path hashes, and at most `max_actors` actors are held.
#[derive(Debug)]
pub struct DistinctPaths {
    kind: SignalKind,
    window_ns: u64,
    threshold: usize,
    max_actors: usize,
    runs: HashMap<ProcessKey, Run>,
}

fn hash(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

/// What `threshold` paths of `kind` in `seconds` say, the last one named.
fn evidence(kind: SignalKind, threshold: usize, seconds: u64, path: &str) -> String {
    match kind {
        SignalKind::EntropyRise => format!(
            "{threshold} files rewritten from ordinary to near-random content in {seconds} s, the last {path}"
        ),
        SignalKind::HeaderMismatch => format!(
            "{threshold} files left with leading bytes that do not match their extension in {seconds} s, the last {path}"
        ),
        SignalKind::ReplaceSequence => format!(
            "{threshold} files replaced by a file of their size written fresh beside them in {seconds} s, the last {path}"
        ),
        _ => format!("{threshold} distinct files rewritten in {seconds} s, the last {path}"),
    }
}

/// `evidence`, followed where the threshold was a learned one by the words
/// saying so, so an operator reading the alert knows which number was
/// crossed and where it came from.
#[must_use]
pub fn learned_evidence(evidence: String, learned: Option<usize>) -> String {
    match learned {
        Some(threshold) => {
            format!("{evidence}, against a threshold of {threshold} learned for this executable")
        }
        None => evidence,
    }
}

impl DistinctPaths {
    /// Distinct files rewritten, counted on every rewrite.
    #[must_use]
    pub fn rewrites() -> Self {
        Self::new(
            SignalKind::DistinctRewrites,
            RANSOM_WINDOW_NS,
            RANSOM_DISTINCT_REWRITES,
            RANSOM_ACTORS_MAX,
        )
    }

    /// Files whose sampled entropy rose from ordinary to near-random.
    #[must_use]
    pub fn entropy_rises() -> Self {
        Self::new(
            SignalKind::EntropyRise,
            RANSOM_WINDOW_NS,
            RANSOM_ENTROPY_RISES,
            RANSOM_ACTORS_MAX,
        )
    }

    /// Files whose leading bytes no longer match what their extension names.
    #[must_use]
    pub fn header_mismatches() -> Self {
        Self::new(
            SignalKind::HeaderMismatch,
            RANSOM_WINDOW_NS,
            RANSOM_HEADER_MISMATCHES,
            RANSOM_ACTORS_MAX,
        )
    }

    /// Files replaced by one of their size written fresh beside them.
    #[must_use]
    pub fn replacements() -> Self {
        Self::new(
            SignalKind::ReplaceSequence,
            RANSOM_WINDOW_NS,
            RANSOM_REPLACEMENTS,
            RANSOM_ACTORS_MAX,
        )
    }

    #[must_use]
    pub fn new(kind: SignalKind, window_ns: u64, threshold: usize, max_actors: usize) -> Self {
        Self {
            kind,
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

    /// The signal this counter raises.
    #[must_use]
    pub fn kind(&self) -> SignalKind {
        self.kind
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
        self.record_against(actor, pid, path, at_ns, None)
    }

    /// [`Self::record`] against `learned`, a threshold a baseline set for
    /// this actor, where there is one. The evidence says which threshold was
    /// crossed and that it was learned.
    pub fn record_against(
        &mut self,
        actor: &Actor,
        pid: u32,
        path: &str,
        at_ns: u64,
        learned: Option<usize>,
    ) -> Option<RansomSignal> {
        let threshold = learned.unwrap_or(self.threshold).max(1);
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
        if run.paths.len() < threshold {
            return None;
        }
        run.raised = true;
        let seconds = at_ns.saturating_sub(run.opened_ns) / 1_000_000_000;
        run.paths.clear();
        Some(RansomSignal {
            kind: self.kind,
            actor: actor.clone(),
            pid,
            at_ns,
            evidence: learned_evidence(
                evidence(self.kind, threshold, seconds, path),
                learned.filter(|_| threshold != self.threshold),
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
            remote: None,
        }
    }

    #[test]
    fn a_learned_threshold_moves_the_count_and_is_named_in_the_evidence() {
        let mut rewrites = DistinctPaths::new(SignalKind::DistinctRewrites, RANSOM_WINDOW_NS, 2, 8);
        let a = actor(10);
        let learned = Some(3);
        assert!(
            rewrites
                .record_against(&a, 11, "/d/a", S, learned)
                .is_none()
        );
        assert!(
            rewrites
                .record_against(&a, 11, "/d/b", S, learned)
                .is_none()
        );
        let signal = rewrites.record_against(&a, 11, "/d/c", S, learned).unwrap();
        assert!(
            signal
                .evidence
                .ends_with("against a threshold of 3 learned for this executable"),
            "{}",
            signal.evidence
        );
        // A learned threshold equal to the shipped one is not named.
        let mut same = DistinctPaths::new(SignalKind::DistinctRewrites, RANSOM_WINDOW_NS, 1, 8);
        let signal = same.record_against(&a, 11, "/d/a", S, Some(1)).unwrap();
        assert!(!signal.evidence.contains("learned"));
    }

    #[test]
    fn the_threshold_of_distinct_paths_raises_the_signal_once() {
        let mut rewrites = DistinctPaths::new(SignalKind::DistinctRewrites, RANSOM_WINDOW_NS, 3, 8);
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
        let mut rewrites = DistinctPaths::new(SignalKind::DistinctRewrites, RANSOM_WINDOW_NS, 2, 8);
        let a = actor(10);
        rewrites.record(&a, 10, "/a", 0);
        assert!(rewrites.record(&a, 10, "/b", 61 * S).is_none());
        assert!(rewrites.record(&a, 10, "/c", 62 * S).is_some());
    }

    #[test]
    fn two_actors_count_apart_and_the_bound_holds() {
        let mut rewrites = DistinctPaths::new(SignalKind::DistinctRewrites, RANSOM_WINDOW_NS, 2, 2);
        rewrites.record(&actor(1), 1, "/a", S);
        assert!(rewrites.record(&actor(2), 2, "/b", 2 * S).is_none());
        rewrites.record(&actor(3), 3, "/c", 3 * S);
        assert_eq!(rewrites.actors(), 2);
        // Actor 1 was let go, so its next path is its first again.
        assert!(rewrites.record(&actor(1), 1, "/d", 4 * S).is_none());
    }

    #[test]
    fn each_counter_raises_its_own_signal() {
        let mut rises = DistinctPaths::new(SignalKind::EntropyRise, RANSOM_WINDOW_NS, 2, 8);
        let a = actor(10);
        rises.record(&a, 10, "/a", 0);
        let signal = rises.record(&a, 10, "/b", 2 * S).unwrap();
        assert_eq!(signal.kind, SignalKind::EntropyRise);
        assert_eq!(
            signal.evidence,
            "2 files rewritten from ordinary to near-random content in 2 s, the last /b"
        );
        assert_eq!(DistinctPaths::rewrites().kind, SignalKind::DistinctRewrites);
        assert_eq!(
            DistinctPaths::entropy_rises().threshold,
            RANSOM_ENTROPY_RISES
        );
    }
}
