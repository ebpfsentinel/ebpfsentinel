//! The signals, their tiers, and what each needs from the host.

use serde::Serialize;

use crate::hostrule::{HostSources, Source};

use super::actor::Actor;

/// How much one signal weighs in a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Enough on its own: legitimate software has no reason to produce it.
    Decisive,
    /// Two of these, or one with two supporting signals.
    Strong,
    /// Common on its own; it only ever corroborates.
    Supporting,
    /// Observed before a run rather than during one: it never counts toward
    /// a verdict, whatever else is seen.
    Prior,
}

/// One behaviour the engine composes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    /// A file planted where no legitimate process looks was opened.
    CanaryTouched,
    /// Files no longer start with the bytes their extension promises.
    HeaderMismatch,
    /// The system crypto library is called at the rate files are written.
    CryptoRate,
    /// One new filename appeared in many directories.
    RansomNote,
    /// Many files renamed to one new extension.
    MassRename,
    /// Files read, written anew beside the original, renamed over it.
    ReplaceSequence,
    /// Many distinct files rewritten in one window.
    DistinctRewrites,
    /// Rewritten content stopped being structured.
    EntropyRise,
    /// Snapshots, backups or their units destroyed.
    BackupDestroyed,
}

const FILE: &[Source] = &[Source::ProcessTracing, Source::FileWatch];
const PROCESS: &[Source] = &[Source::ProcessTracing];

impl SignalKind {
    /// Every signal, in the order of the tier table.
    pub const ALL: [SignalKind; 9] = [
        Self::CanaryTouched,
        Self::HeaderMismatch,
        Self::CryptoRate,
        Self::RansomNote,
        Self::MassRename,
        Self::ReplaceSequence,
        Self::DistinctRewrites,
        Self::EntropyRise,
        Self::BackupDestroyed,
    ];

    /// The tier table: the one place a signal's weight is decided.
    #[must_use]
    pub fn tier(self) -> Tier {
        match self {
            Self::CanaryTouched | Self::HeaderMismatch => Tier::Decisive,
            Self::CryptoRate | Self::RansomNote | Self::MassRename | Self::ReplaceSequence => {
                Tier::Strong
            }
            Self::DistinctRewrites | Self::EntropyRise => Tier::Supporting,
            Self::BackupDestroyed => Tier::Prior,
        }
    }

    /// The sources the signal is read from. Every signal is attributed to a
    /// process, so process tracing is always one of them.
    #[must_use]
    pub fn sources(self) -> &'static [Source] {
        match self {
            Self::CryptoRate | Self::BackupDestroyed => PROCESS,
            _ => FILE,
        }
    }

    /// The name the signal is reported under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanaryTouched => "canary_touched",
            Self::HeaderMismatch => "header_mismatch",
            Self::CryptoRate => "crypto_rate",
            Self::RansomNote => "ransom_note",
            Self::MassRename => "mass_rename",
            Self::ReplaceSequence => "replace_sequence",
            Self::DistinctRewrites => "distinct_rewrites",
            Self::EntropyRise => "entropy_rise",
            Self::BackupDestroyed => "backup_destroyed",
        }
    }
}

/// One observation, attributed to an actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RansomSignal {
    pub kind: SignalKind,
    /// The lineage the signal counts against.
    pub actor: Actor,
    /// The process that produced it, which may be a worker of the actor.
    pub pid: u32,
    /// When it was observed, on the clock the window is measured on.
    pub at_ns: u64,
    /// What was seen, in one sentence an operator can check.
    pub evidence: String,
}

impl RansomSignal {
    /// The signal's weight, read from the tier table.
    #[must_use]
    pub fn tier(&self) -> Tier {
        self.kind.tier()
    }
}

/// A signal this host could not read, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnavailableSignal {
    pub kind: SignalKind,
    pub reason: String,
}

/// The signals that cannot take part in a verdict on this host: those whose
/// sources the host reported absent, and those the agent was not built to
/// read, which are named as such rather than left out.
#[must_use]
pub fn unavailable(host: &HostSources, read: &[SignalKind]) -> Vec<UnavailableSignal> {
    SignalKind::ALL
        .into_iter()
        .filter_map(|kind| {
            if !read.contains(&kind) {
                return Some(UnavailableSignal {
                    kind,
                    reason: "not read by this agent".to_string(),
                });
            }
            let reasons: Vec<String> = kind
                .sources()
                .iter()
                .filter_map(|source| match host.sources.get(source) {
                    Some(Ok(())) => None,
                    Some(Err(reason)) => Some(format!("{}: {reason}", source.as_str())),
                    None => Some(format!("{}: not reported by this host", source.as_str())),
                })
                .collect();
            (!reasons.is_empty()).then(|| UnavailableSignal {
                kind,
                reason: reasons.join("; "),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tier_table_has_two_decisive_four_strong_two_supporting_and_one_prior() {
        let count = |tier| {
            SignalKind::ALL
                .iter()
                .filter(|kind| kind.tier() == tier)
                .count()
        };
        assert_eq!(count(Tier::Decisive), 2);
        assert_eq!(count(Tier::Strong), 4);
        assert_eq!(count(Tier::Supporting), 2);
        assert_eq!(count(Tier::Prior), 1);
    }

    #[test]
    fn every_signal_needs_process_tracing_to_be_attributed() {
        for kind in SignalKind::ALL {
            assert!(kind.sources().contains(&Source::ProcessTracing), "{kind:?}");
        }
    }

    #[test]
    fn a_signal_not_read_is_named_and_a_missing_source_gives_its_reason() {
        let host = HostSources::new(Some((6, 12)))
            .present(Source::ProcessTracing)
            .absent(Source::FileWatch, "fanotify refused");
        let out = unavailable(
            &host,
            &[SignalKind::DistinctRewrites, SignalKind::CryptoRate],
        );
        let rewrites = out
            .iter()
            .find(|u| u.kind == SignalKind::DistinctRewrites)
            .unwrap();
        assert_eq!(rewrites.reason, "file_watch: fanotify refused");
        assert!(!out.iter().any(|u| u.kind == SignalKind::CryptoRate));
        let canary = out
            .iter()
            .find(|u| u.kind == SignalKind::CanaryTouched)
            .unwrap();
        assert_eq!(canary.reason, "not read by this agent");
        assert_eq!(out.len(), SignalKind::ALL.len() - 1);
    }

    #[test]
    fn a_host_reporting_nothing_names_every_source_it_lacks() {
        let out = unavailable(&HostSources::new(None), &[SignalKind::DistinctRewrites]);
        let rewrites = out
            .iter()
            .find(|u| u.kind == SignalKind::DistinctRewrites)
            .unwrap();
        assert_eq!(
            rewrites.reason,
            "process_tracing: not reported by this host; file_watch: not reported by this host"
        );
    }
}
