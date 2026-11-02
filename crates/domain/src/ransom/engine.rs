//! The verdict: signals of one actor that agree inside one window.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::process::entity::ProcessKey;

use super::actor::Actor;
use super::backup::BACKUP_PRIOR_WINDOW_NS;
use super::signal::{RansomSignal, SignalKind, Tier, UnavailableSignal};

/// The component a verdict is raised under.
pub const MASS_ENCRYPTION_COMPONENT: &str = "mass_encryption";

/// The rule a verdict is raised under: there is one, whatever reached it.
pub const MASS_ENCRYPTION_RULE_ID: &str = "mass-encryption";

/// How long signals of one actor are held together: sixty seconds.
pub const RANSOM_WINDOW_NS: u64 = 60_000_000_000;

/// The most actors held at once. The one seen longest ago goes first.
pub const RANSOM_ACTORS_MAX: usize = 4096;

/// Which combination of tiers reached a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Corroboration {
    /// One decisive signal.
    Decisive,
    /// Two strong signals of different kinds.
    TwoStrong,
    /// One strong signal and two supporting ones of different kinds.
    StrongAndTwoSupporting,
    /// One strong signal, after a prior.
    StrongAfterPrior,
    /// Two supporting signals of different kinds, after a prior.
    TwoSupportingAfterPrior,
}

impl Corroboration {
    /// The rule in words, for the alert.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decisive => "one decisive signal",
            Self::TwoStrong => "two strong signals",
            Self::StrongAndTwoSupporting => "one strong and two supporting signals",
            Self::StrongAfterPrior => "one strong signal after backups were destroyed",
            Self::TwoSupportingAfterPrior => "two supporting signals after backups were destroyed",
        }
    }
}

/// Whether the kinds seen reach a verdict, and by which rule. Each kind
/// counts once however often it was seen. A prior reaches nothing alone: it
/// lowers what the other tiers must add up to, by one strong signal or by
/// the strong one of the strong-and-two-supporting rule.
#[must_use]
pub fn corroborate(kinds: impl IntoIterator<Item = SignalKind>) -> Option<Corroboration> {
    let mut seen: Vec<SignalKind> = kinds.into_iter().collect();
    seen.sort_unstable();
    seen.dedup();
    let count = |tier| seen.iter().filter(|kind| kind.tier() == tier).count();
    let (decisive, strong, supporting, prior) = (
        count(Tier::Decisive),
        count(Tier::Strong),
        count(Tier::Supporting),
        count(Tier::Prior),
    );
    if decisive >= 1 {
        Some(Corroboration::Decisive)
    } else if strong >= 2 {
        Some(Corroboration::TwoStrong)
    } else if strong >= 1 && supporting >= 2 {
        Some(Corroboration::StrongAndTwoSupporting)
    } else if prior >= 1 && strong >= 1 {
        Some(Corroboration::StrongAfterPrior)
    } else if prior >= 1 && supporting >= 2 {
        Some(Corroboration::TwoSupportingAfterPrior)
    } else {
        None
    }
}

/// A run recognised, with everything that recognised it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RansomVerdict {
    pub actor: Actor,
    pub at_ns: u64,
    pub corroboration: Corroboration,
    /// The latest signal of every kind held for the actor, the ones that
    /// reached the verdict among them, in the order of the tier table.
    pub signals: Vec<RansomSignal>,
    /// What this host could not read when the verdict was reached, so a
    /// reader knows whether the engine was whole.
    pub unavailable: Vec<UnavailableSignal>,
}

impl RansomVerdict {
    /// The verdict in one paragraph: the actor, the rule, every signal with
    /// its evidence, and what was not read.
    #[must_use]
    pub fn describe(&self) -> String {
        let exe = self.actor.exe.as_deref().unwrap_or("an unread executable");
        let signals: Vec<String> = self
            .signals
            .iter()
            .map(|s| format!("{} (pid {}): {}", s.kind.as_str(), s.pid, s.evidence))
            .collect();
        let by = match &self.actor.remote {
            Some(remote) => format!(
                "written for {} through {exe} (pid {})",
                remote.describe(),
                self.actor.pid
            ),
            None => format!("by {exe} (pid {})", self.actor.pid),
        };
        let mut out = format!(
            "mass encryption {by} on {}: {}",
            self.corroboration.as_str(),
            signals.join("; ")
        );
        if !self.unavailable.is_empty() {
            let missing: Vec<String> = self
                .unavailable
                .iter()
                .map(|u| format!("{} ({})", u.kind.as_str(), u.reason))
                .collect();
            out.push_str(". Not read on this host: ");
            out.push_str(&missing.join("; "));
        }
        out
    }
}

#[derive(Debug)]
struct ActorState {
    actor: Actor,
    latest: BTreeMap<SignalKind, RansomSignal>,
    last_ns: u64,
    convicted: bool,
}

/// The signals held per actor, and the verdicts they reach.
///
/// A verdict is reported once per actor: further signals are held, and a new
/// verdict is possible only after every signal of the actor has left the
/// window. Memory is bounded twice: at most one signal per kind per actor,
/// and at most `max_actors` actors. Priors are held apart, under the process
/// that ran the command, for longer than the window, and count for every
/// actor that process or one of its ancestors started; they too are bounded
/// at `max_actors`.
#[derive(Debug)]
pub struct RansomEngine {
    window_ns: u64,
    prior_window_ns: u64,
    max_actors: usize,
    actors: HashMap<ProcessKey, ActorState>,
    priors: HashMap<ProcessKey, RansomSignal>,
    evicted: u64,
}

impl Default for RansomEngine {
    fn default() -> Self {
        Self::new(RANSOM_WINDOW_NS, RANSOM_ACTORS_MAX)
    }
}

impl RansomEngine {
    /// An engine holding signals for `window_ns` and at most `max_actors`
    /// actors.
    #[must_use]
    pub fn new(window_ns: u64, max_actors: usize) -> Self {
        Self {
            window_ns,
            prior_window_ns: BACKUP_PRIOR_WINDOW_NS.max(window_ns),
            max_actors: max_actors.max(1),
            actors: HashMap::new(),
            priors: HashMap::new(),
            evicted: 0,
        }
    }

    /// How many actors are held now.
    #[must_use]
    pub fn actors(&self) -> usize {
        self.actors.len()
    }

    /// How many actors were let go at the bound while still in a window.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// How many priors are held now.
    #[must_use]
    pub fn priors(&self) -> usize {
        self.priors.len()
    }

    /// Hold a prior under the process its actor names, the one that ran the
    /// command. It reaches no verdict by itself.
    pub fn hold_prior(&mut self, signal: RansomSignal) {
        let at_ns = signal.at_ns;
        let key = signal.actor.key;
        if !self.priors.contains_key(&key) && self.priors.len() >= self.max_actors {
            let window = self.prior_window_ns;
            self.priors
                .retain(|_, held| at_ns.saturating_sub(held.at_ns) <= window);
            if self.priors.len() >= self.max_actors
                && let Some(oldest) = self
                    .priors
                    .iter()
                    .min_by_key(|(_, held)| held.at_ns)
                    .map(|(key, _)| *key)
            {
                self.priors.remove(&oldest);
            }
        }
        self.priors.insert(key, signal);
    }

    /// The freshest prior that counts for an actor started below one of
    /// `keys`, still inside its window at `at_ns`.
    fn prior_for(&self, keys: &[ProcessKey], at_ns: u64) -> Option<RansomSignal> {
        keys.iter()
            .filter_map(|key| self.priors.get(key))
            .filter(|held| at_ns.saturating_sub(held.at_ns) <= self.prior_window_ns)
            .max_by_key(|held| held.at_ns)
            .cloned()
    }

    /// Hold `signal`, and return a verdict if its actor now reaches one.
    /// `unavailable` is asked only when a verdict is reached.
    pub fn observe(
        &mut self,
        signal: RansomSignal,
        unavailable: impl FnOnce() -> Vec<UnavailableSignal>,
    ) -> Option<RansomVerdict> {
        self.observe_under(signal, &[], unavailable)
    }

    /// As `observe`, for an actor whose ancestors are `ancestry`: a prior
    /// held under the actor or any of them counts toward its verdict.
    pub fn observe_under(
        &mut self,
        signal: RansomSignal,
        ancestry: &[ProcessKey],
        unavailable: impl FnOnce() -> Vec<UnavailableSignal>,
    ) -> Option<RansomVerdict> {
        let at_ns = signal.at_ns;
        let mut keys = Vec::with_capacity(ancestry.len() + 1);
        keys.push(signal.actor.key);
        keys.extend_from_slice(ancestry);
        let prior = self.prior_for(&keys, at_ns);
        let key = signal.actor.key;
        if !self.actors.contains_key(&key) {
            self.make_room(at_ns);
        }
        let window = self.window_ns;
        let state = self.actors.entry(key).or_insert_with(|| ActorState {
            actor: signal.actor.clone(),
            latest: BTreeMap::new(),
            last_ns: at_ns,
            convicted: false,
        });
        state
            .latest
            .retain(|_, held| at_ns.saturating_sub(held.at_ns) <= window);
        if state.latest.is_empty() {
            state.convicted = false;
        }
        state.last_ns = state.last_ns.max(at_ns);
        state.latest.insert(signal.kind, signal);
        if state.convicted {
            return None;
        }
        let corroboration = corroborate(
            state
                .latest
                .keys()
                .copied()
                .chain(prior.as_ref().map(|p| p.kind)),
        )?;
        state.convicted = true;
        let mut signals: Vec<RansomSignal> = state.latest.values().cloned().collect();
        signals.extend(prior);
        Some(RansomVerdict {
            actor: state.actor.clone(),
            at_ns,
            corroboration,
            signals,
            unavailable: unavailable(),
        })
    }

    /// Drop the actors whose window closed, and the one seen longest ago if
    /// the bound is still reached.
    fn make_room(&mut self, at_ns: u64) {
        if self.actors.len() < self.max_actors {
            return;
        }
        let window = self.window_ns;
        self.actors
            .retain(|_, state| at_ns.saturating_sub(state.last_ns) <= window);
        while self.actors.len() >= self.max_actors {
            let Some(oldest) = self
                .actors
                .iter()
                .min_by_key(|(_, state)| state.last_ns)
                .map(|(key, _)| *key)
            else {
                return;
            };
            self.actors.remove(&oldest);
            self.evicted += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000_000;

    fn actor(pid: u32) -> Actor {
        Actor {
            key: ProcessKey {
                pid,
                start_ns: u64::from(pid),
            },
            pid,
            exe: Some("/tmp/enc".to_string()),
            remote: None,
        }
    }

    fn signal(kind: SignalKind, pid: u32, at_s: u64) -> RansomSignal {
        RansomSignal {
            kind,
            actor: actor(pid),
            pid: pid + 1,
            at_ns: at_s * S,
            evidence: format!("{} seen", kind.as_str()),
        }
    }

    fn whole() -> Vec<UnavailableSignal> {
        Vec::new()
    }

    #[test]
    fn each_combination_of_tiers_reaches_or_misses_a_verdict() {
        use SignalKind::*;
        assert_eq!(corroborate([CanaryTouched]), Some(Corroboration::Decisive));
        assert_eq!(corroborate([HeaderMismatch]), Some(Corroboration::Decisive));
        assert_eq!(
            corroborate([MassRename, RansomNote]),
            Some(Corroboration::TwoStrong)
        );
        assert_eq!(
            corroborate([ReplaceSequence, DistinctRewrites, EntropyRise]),
            Some(Corroboration::StrongAndTwoSupporting)
        );
        assert_eq!(corroborate([MassRename]), None);
        assert_eq!(corroborate([MassRename, DistinctRewrites]), None);
        assert_eq!(corroborate([DistinctRewrites, EntropyRise]), None);
        assert_eq!(corroborate([MassRename, MassRename]), None);
        assert_eq!(corroborate([]), None);
    }

    #[test]
    fn a_prior_alone_reaches_nothing_and_lowers_the_rest() {
        use SignalKind::*;
        assert_eq!(corroborate([BackupDestroyed]), None);
        assert_eq!(corroborate([BackupDestroyed, DistinctRewrites]), None);
        assert_eq!(
            corroborate([BackupDestroyed, MassRename]),
            Some(Corroboration::StrongAfterPrior)
        );
        assert_eq!(
            corroborate([BackupDestroyed, EntropyRise, DistinctRewrites]),
            Some(Corroboration::TwoSupportingAfterPrior)
        );
        assert_eq!(
            corroborate([BackupDestroyed, CanaryTouched]),
            Some(Corroboration::Decisive)
        );
    }

    #[test]
    fn a_prior_counts_for_runs_started_below_whoever_ran_the_command() {
        let mut engine = RansomEngine::default();
        let shell = actor(5);
        engine.hold_prior(RansomSignal {
            kind: SignalKind::BackupDestroyed,
            actor: shell.clone(),
            pid: 6,
            at_ns: S,
            evidence: "zfs dataset or snapshot destroyed: zfs destroy tank".into(),
        });
        assert_eq!(engine.priors(), 1);
        // An unrelated actor gains nothing from it.
        assert!(
            engine
                .observe(signal(SignalKind::MassRename, 10, 2), whole)
                .is_none()
        );
        // An actor started below the shell does, within ten minutes.
        let verdict = engine
            .observe_under(signal(SignalKind::RansomNote, 20, 300), &[shell.key], whole)
            .unwrap();
        assert_eq!(verdict.corroboration, Corroboration::StrongAfterPrior);
        let kinds: Vec<SignalKind> = verdict.signals.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            vec![SignalKind::RansomNote, SignalKind::BackupDestroyed]
        );
        assert!(verdict.describe().contains("after backups were destroyed"));
        // Past the prior's window it counts for nobody.
        assert!(
            engine
                .observe_under(signal(SignalKind::MassRename, 30, 700), &[shell.key], whole)
                .is_none()
        );
    }

    #[test]
    fn priors_are_bounded() {
        let mut engine = RansomEngine::new(RANSOM_WINDOW_NS, 2);
        for pid in 1..=3 {
            engine.hold_prior(RansomSignal {
                kind: SignalKind::BackupDestroyed,
                actor: actor(pid),
                pid,
                at_ns: u64::from(pid) * S,
                evidence: String::new(),
            });
        }
        assert_eq!(engine.priors(), 2);
    }

    #[test]
    fn signals_compose_inside_the_window_and_not_across_it() {
        let mut engine = RansomEngine::default();
        assert!(
            engine
                .observe(signal(SignalKind::MassRename, 10, 0), whole)
                .is_none()
        );
        assert!(
            engine
                .observe(signal(SignalKind::RansomNote, 10, 61), whole)
                .is_none()
        );
        let verdict = engine
            .observe(signal(SignalKind::CryptoRate, 10, 100), whole)
            .unwrap();
        assert_eq!(verdict.corroboration, Corroboration::TwoStrong);
        let kinds: Vec<SignalKind> = verdict.signals.iter().map(|s| s.kind).collect();
        assert_eq!(kinds, vec![SignalKind::CryptoRate, SignalKind::RansomNote]);
    }

    #[test]
    fn the_window_boundary_itself_is_inside() {
        let mut engine = RansomEngine::default();
        engine.observe(signal(SignalKind::MassRename, 10, 0), whole);
        assert!(
            engine
                .observe(signal(SignalKind::RansomNote, 10, 60), whole)
                .is_some()
        );
    }

    #[test]
    fn workers_of_one_actor_compose_and_two_actors_do_not() {
        let mut engine = RansomEngine::default();
        let mut first = signal(SignalKind::MassRename, 10, 1);
        first.pid = 11;
        let mut second = signal(SignalKind::RansomNote, 10, 2);
        second.pid = 12;
        engine.observe(first, whole);
        let verdict = engine.observe(second, whole).unwrap();
        let pids: Vec<u32> = verdict.signals.iter().map(|s| s.pid).collect();
        assert_eq!(pids, vec![12, 11]);
        assert_eq!(verdict.actor.pid, 10);

        let mut engine = RansomEngine::default();
        engine.observe(signal(SignalKind::MassRename, 10, 1), whole);
        assert!(
            engine
                .observe(signal(SignalKind::RansomNote, 20, 2), whole)
                .is_none()
        );
    }

    #[test]
    fn a_verdict_names_every_signal_held_and_fires_once() {
        let mut engine = RansomEngine::default();
        engine.observe(signal(SignalKind::DistinctRewrites, 10, 1), whole);
        let verdict = engine
            .observe(signal(SignalKind::CanaryTouched, 10, 2), whole)
            .unwrap();
        assert_eq!(verdict.signals.len(), 2);
        let text = verdict.describe();
        assert!(text.contains("canary_touched (pid 11): canary_touched seen"));
        assert!(text.contains("distinct_rewrites (pid 11)"));
        assert!(text.contains("on one decisive signal"));
        assert!(
            engine
                .observe(signal(SignalKind::HeaderMismatch, 10, 3), whole)
                .is_none()
        );
        // Once every signal left the window, the actor can be convicted again.
        assert!(
            engine
                .observe(signal(SignalKind::CanaryTouched, 10, 200), whole)
                .is_some()
        );
    }

    #[test]
    fn a_verdict_reached_with_signals_unavailable_says_which_and_why() {
        let mut engine = RansomEngine::default();
        engine.observe(signal(SignalKind::MassRename, 10, 1), whole);
        let verdict = engine
            .observe(signal(SignalKind::ReplaceSequence, 10, 2), || {
                vec![
                    UnavailableSignal {
                        kind: SignalKind::CryptoRate,
                        reason: "statically linked".to_string(),
                    },
                    UnavailableSignal {
                        kind: SignalKind::CanaryTouched,
                        reason: "file_watch: fanotify refused".to_string(),
                    },
                ]
            })
            .unwrap();
        assert_eq!(verdict.unavailable.len(), 2);
        assert!(verdict.describe().ends_with(
            "Not read on this host: crypto_rate (statically linked); \
             canary_touched (file_watch: fanotify refused)"
        ));
    }

    #[test]
    fn unavailability_is_asked_only_when_a_verdict_is_reached() {
        let mut engine = RansomEngine::default();
        let mut asked = false;
        engine.observe(signal(SignalKind::MassRename, 10, 1), || {
            asked = true;
            Vec::new()
        });
        assert!(!asked);
    }

    #[test]
    fn the_actor_bound_lets_the_oldest_go_first() {
        let mut engine = RansomEngine::new(RANSOM_WINDOW_NS, 2);
        engine.observe(signal(SignalKind::MassRename, 1, 1), whole);
        engine.observe(signal(SignalKind::MassRename, 2, 2), whole);
        engine.observe(signal(SignalKind::MassRename, 3, 3), whole);
        assert_eq!(engine.actors(), 2);
        assert_eq!(engine.evicted(), 1);
        // Actor 1 was let go, so its second strong signal stands alone.
        assert!(
            engine
                .observe(signal(SignalKind::RansomNote, 1, 4), whole)
                .is_none()
        );
        assert!(
            engine
                .observe(signal(SignalKind::RansomNote, 3, 5), whole)
                .is_some()
        );
    }

    #[test]
    fn closed_windows_are_dropped_before_anything_is_evicted() {
        let mut engine = RansomEngine::new(RANSOM_WINDOW_NS, 2);
        engine.observe(signal(SignalKind::MassRename, 1, 1), whole);
        engine.observe(signal(SignalKind::MassRename, 2, 2), whole);
        engine.observe(signal(SignalKind::MassRename, 3, 100), whole);
        assert_eq!(engine.actors(), 1);
        assert_eq!(engine.evicted(), 0);
    }
}
