//! The strong signal read from the system crypto library: one actor calling
//! the symmetric encryption entry points at the rate it writes files.
//!
//! A probe on those entry points counts calls per process and reads nothing
//! else, so what arrives here is a number. A program encrypting is common; a
//! program encrypting about as often as it rewrites files, across many files
//! within a minute, is doing one thing. Both halves are needed: the calls
//! alone are every TLS terminator and every encrypted backup stream, and the
//! files alone are the distinct-rewrite signal already counted elsewhere.
//!
//! A binary that carries its own cipher, or links one statically, never calls
//! the library, and the signal is absent for it rather than wrong.

use std::collections::HashMap;

use crate::process::entity::ProcessKey;

use super::actor::Actor;
use super::engine::{RANSOM_ACTORS_MAX, RANSOM_WINDOW_NS};
use super::signal::{RansomSignal, SignalKind};

/// Encryption calls one actor makes in a window before its rate is read.
pub const RANSOM_CRYPTO_CALLS: u64 = 200;

/// Files one actor rewrites in the same window for its encryption to be
/// tracking its writes.
pub const RANSOM_CRYPTO_FILES: u64 = 20;

#[derive(Debug)]
struct Run {
    opened_ns: u64,
    last_ns: u64,
    calls: u64,
    files: u64,
    raised: bool,
}

/// Encryption calls and rewritten files per actor, in windows that open at
/// the first of either and close `window_ns` later.
#[derive(Debug)]
pub struct CryptoRates {
    window_ns: u64,
    calls: u64,
    files: u64,
    max_actors: usize,
    runs: HashMap<ProcessKey, Run>,
}

impl Default for CryptoRates {
    fn default() -> Self {
        Self::new(
            RANSOM_WINDOW_NS,
            RANSOM_CRYPTO_CALLS,
            RANSOM_CRYPTO_FILES,
            RANSOM_ACTORS_MAX,
        )
    }
}

impl CryptoRates {
    #[must_use]
    pub fn new(window_ns: u64, calls: u64, files: u64, max_actors: usize) -> Self {
        Self {
            window_ns,
            calls: calls.max(1),
            files: files.max(1),
            max_actors: max_actors.max(1),
            runs: HashMap::new(),
        }
    }

    /// How many actors are held now.
    #[must_use]
    pub fn actors(&self) -> usize {
        self.runs.len()
    }

    /// `calls` encryption calls made by `pid` on behalf of `actor` since the
    /// last reading; the signal the first time the actor's rate tracks its
    /// writes in the window.
    pub fn called(
        &mut self,
        actor: &Actor,
        pid: u32,
        calls: u64,
        at_ns: u64,
    ) -> Option<RansomSignal> {
        if calls == 0 {
            return None;
        }
        self.run(actor, at_ns).calls += calls;
        self.raise(actor, pid, at_ns)
    }

    /// One file rewritten by `pid` on behalf of `actor`; the signal when that
    /// rewrite is what brings the actor's writes level with its encryption.
    /// An actor never seen encrypting holds nothing, so a host where no
    /// process calls the library keeps no state for its writers.
    pub fn wrote(&mut self, actor: &Actor, pid: u32, at_ns: u64) -> Option<RansomSignal> {
        if !self.runs.contains_key(&actor.key) {
            return None;
        }
        self.run(actor, at_ns).files += 1;
        self.raise(actor, pid, at_ns)
    }

    fn raise(&mut self, actor: &Actor, pid: u32, at_ns: u64) -> Option<RansomSignal> {
        let (calls, files) = (self.calls, self.files);
        let run = self.runs.get_mut(&actor.key)?;
        if run.raised || run.calls < calls || run.files < files || run.calls < run.files {
            return None;
        }
        run.raised = true;
        let seconds = at_ns.saturating_sub(run.opened_ns) / 1_000_000_000;
        Some(RansomSignal {
            kind: SignalKind::CryptoRate,
            actor: actor.clone(),
            pid,
            at_ns,
            evidence: format!(
                "{} encryption calls beside {} files rewritten in {seconds} s",
                run.calls, run.files
            ),
        })
    }

    fn run(&mut self, actor: &Actor, at_ns: u64) -> &mut Run {
        if !self.runs.contains_key(&actor.key) {
            self.make_room(at_ns);
        }
        let window = self.window_ns;
        let run = self.runs.entry(actor.key).or_insert(Run {
            opened_ns: at_ns,
            last_ns: at_ns,
            calls: 0,
            files: 0,
            raised: false,
        });
        if at_ns.saturating_sub(run.opened_ns) > window {
            *run = Run {
                opened_ns: at_ns,
                last_ns: at_ns,
                calls: 0,
                files: 0,
                raised: false,
            };
        }
        run.last_ns = run.last_ns.max(at_ns);
        run
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
    fn encryption_tracking_the_writes_raises_once() {
        let mut rates = CryptoRates::new(RANSOM_WINDOW_NS, 10, 3, 8);
        let a = actor(1);
        // Writes before any encryption hold nothing.
        assert!(rates.wrote(&a, 1, S).is_none());
        assert_eq!(rates.actors(), 0);
        assert!(rates.called(&a, 1, 6, S).is_none());
        assert!(rates.wrote(&a, 1, S).is_none());
        assert!(rates.wrote(&a, 1, S).is_none());
        assert!(rates.called(&a, 2, 4, 2 * S).is_none());
        let signal = rates.wrote(&a, 2, 3 * S).unwrap();
        assert_eq!(signal.kind, SignalKind::CryptoRate);
        assert_eq!(
            signal.evidence,
            "10 encryption calls beside 3 files rewritten in 2 s"
        );
        assert!(rates.called(&a, 2, 100, 4 * S).is_none());
    }

    #[test]
    fn calls_alone_or_fewer_calls_than_files_raise_nothing() {
        let mut rates = CryptoRates::new(RANSOM_WINDOW_NS, 10, 3, 8);
        let tls = actor(1);
        assert!(rates.called(&tls, 1, 100_000, S).is_none());
        let copier = actor(2);
        assert!(rates.called(&copier, 2, 1, S).is_none());
        for _ in 0..12 {
            assert!(rates.wrote(&copier, 2, S).is_none());
        }
        // Eleven calls beside twelve files: the writes outrun the encryption.
        assert!(rates.called(&copier, 2, 10, S).is_none());
        // Another call brings them level.
        assert!(rates.called(&copier, 2, 1, S).is_some());
    }

    #[test]
    fn a_new_window_and_bounded_actors() {
        let mut rates = CryptoRates::new(RANSOM_WINDOW_NS, 2, 1, 2);
        let a = actor(1);
        rates.called(&a, 1, 2, 0);
        assert!(rates.wrote(&a, 1, 61 * S).is_none());
        rates.called(&actor(2), 2, 1, 62 * S);
        rates.called(&actor(3), 3, 1, 63 * S);
        assert_eq!(rates.actors(), 2);
    }
}
