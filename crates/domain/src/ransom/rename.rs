//! The strong signal read from renames: many files given one new extension
//! by one actor inside one window.
//!
//! A ransom run that encrypts in place and then renames leaves every file it
//! touched under one extension it chose, which a sampled read of the content
//! may not tell apart from a compressed file but the name does. A build
//! system renames too, and what it renames is a temporary name onto a final
//! one, so a rename counts only where the extension changed, where the old
//! name was not hidden, the old extension not a temporary one and the new one
//! neither temporary, nor a backup suffix, nor a number, which is what log
//! rotation appends.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::process::entity::ProcessKey;

use super::actor::Actor;
use super::engine::{RANSOM_ACTORS_MAX, RANSOM_WINDOW_NS};
use super::signal::{RansomSignal, SignalKind};

/// How many distinct files one actor gives one new extension in a window
/// before the signal is raised.
pub const RANSOM_MASS_RENAMES: usize = 50;

/// New extensions counted per actor at most in one window. A run picks one;
/// an actor spreading renames over more is not that shape, and what it adds
/// past this many is not counted.
pub const RANSOM_RENAME_EXTENSIONS_MAX: usize = 8;

/// Extensions a name carries while it is being written, or once it was set
/// aside, and never the one a ransom run leaves.
const PASSING: &[&str] = &[
    "tmp",
    "temp",
    "part",
    "partial",
    "swp",
    "crdownload",
    "download",
    "new",
    "lock",
    "bak",
    "old",
    "orig",
];

fn last_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn extension_of(name: &str) -> Option<String> {
    let (stem, extension) = name.rsplit_once('.')?;
    (!stem.is_empty() && !extension.is_empty()).then(|| extension.to_ascii_lowercase())
}

/// The new extension `from` renamed to `to` gives a file, lowercased, when
/// the rename is one a ransom run makes rather than one a build, an editor,
/// a download or log rotation makes.
#[must_use]
pub fn renamed_to_new_extension(from: &str, to: &str) -> Option<String> {
    let old_name = last_name(from);
    if old_name.starts_with('.') {
        return None;
    }
    let new = extension_of(last_name(to))?;
    let old = extension_of(old_name);
    if old.as_deref() == Some(new.as_str())
        || old.as_deref().is_some_and(|o| PASSING.contains(&o))
        || PASSING.contains(&new.as_str())
        || new.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some(new)
}

fn hash(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug)]
struct Run {
    opened_ns: u64,
    last_ns: u64,
    by_extension: HashMap<String, HashSet<u64>>,
    raised: bool,
}

/// Distinct files renamed to each new extension, per actor, in windows that
/// open at the first such rename and close `window_ns` later.
#[derive(Debug)]
pub struct MassRenames {
    window_ns: u64,
    threshold: usize,
    max_actors: usize,
    runs: HashMap<ProcessKey, Run>,
}

impl Default for MassRenames {
    fn default() -> Self {
        Self::new(RANSOM_WINDOW_NS, RANSOM_MASS_RENAMES, RANSOM_ACTORS_MAX)
    }
}

impl MassRenames {
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

    /// Count the rename of `from` to `to` by `pid` on behalf of `actor`, and
    /// return the signal the first time one new extension reaches the
    /// threshold in the actor's window.
    pub fn record(
        &mut self,
        actor: &Actor,
        pid: u32,
        from: &str,
        to: &str,
        at_ns: u64,
    ) -> Option<RansomSignal> {
        let extension = renamed_to_new_extension(from, to)?;
        if !self.runs.contains_key(&actor.key) {
            self.make_room(at_ns);
        }
        let window = self.window_ns;
        let run = self.runs.entry(actor.key).or_insert_with(|| Run {
            opened_ns: at_ns,
            last_ns: at_ns,
            by_extension: HashMap::new(),
            raised: false,
        });
        if at_ns.saturating_sub(run.opened_ns) > window {
            run.opened_ns = at_ns;
            run.by_extension.clear();
            run.raised = false;
        }
        run.last_ns = run.last_ns.max(at_ns);
        if run.raised {
            return None;
        }
        if !run.by_extension.contains_key(&extension)
            && run.by_extension.len() >= RANSOM_RENAME_EXTENSIONS_MAX
        {
            return None;
        }
        let renamed = run.by_extension.entry(extension.clone()).or_default();
        renamed.insert(hash(to));
        if renamed.len() < self.threshold {
            return None;
        }
        run.raised = true;
        run.by_extension.clear();
        let seconds = at_ns.saturating_sub(run.opened_ns) / 1_000_000_000;
        Some(RansomSignal {
            kind: SignalKind::MassRename,
            actor: actor.clone(),
            pid,
            at_ns,
            evidence: format!(
                "{} files renamed to .{extension} in {seconds} s, the last {from} to {to}",
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
    fn only_a_rename_to_a_new_lasting_extension_counts() {
        let new = |from, to| renamed_to_new_extension(from, to);
        assert_eq!(
            new("/d/q3.xlsx", "/d/q3.xlsx.LOCKED"),
            Some("locked".into())
        );
        assert_eq!(new("/d/README", "/d/README.enc"), Some("enc".into()));
        // The same extension, a build's temporary output, an editor's swap
        // file, a hidden partial download, a lock released, log rotation and
        // a backup copy.
        assert_eq!(new("/d/a.txt", "/d/b.TXT"), None);
        assert_eq!(new("/d/main.o.tmp", "/d/main.o"), None);
        assert_eq!(new("/d/a.txt.swp", "/d/a.txt"), None);
        assert_eq!(new("/d/.a.iso.abc123", "/d/a.iso"), None);
        assert_eq!(new("/d/index.lock", "/d/index"), None);
        assert_eq!(new("/d/app.log", "/d/app.log.1"), None);
        assert_eq!(new("/d/app.conf", "/d/app.conf.bak"), None);
        assert_eq!(new("/d/a.txt", "/d/a"), None);
    }

    #[test]
    fn one_new_extension_across_the_threshold_raises_the_signal_once() {
        let mut renames = MassRenames::new(RANSOM_WINDOW_NS, 3, 8);
        let a = actor(10);
        assert!(
            renames
                .record(&a, 11, "/d/a.pdf", "/d/a.pdf.crypt", S)
                .is_none()
        );
        // Renaming the same file again is not another file.
        assert!(
            renames
                .record(&a, 11, "/d/a.pdf", "/d/a.pdf.crypt", S)
                .is_none()
        );
        assert!(
            renames
                .record(&a, 11, "/d/b.doc", "/d/b.doc.crypt", 2 * S)
                .is_none()
        );
        // A different new extension counts apart.
        assert!(
            renames
                .record(&a, 11, "/d/c.doc", "/d/c.doc.zz", 2 * S)
                .is_none()
        );
        let signal = renames
            .record(&a, 12, "/d/c.png", "/d/c.png.crypt", 3 * S)
            .unwrap();
        assert_eq!(signal.kind, SignalKind::MassRename);
        assert_eq!(signal.pid, 12);
        assert_eq!(
            signal.evidence,
            "3 files renamed to .crypt in 2 s, the last /d/c.png to /d/c.png.crypt"
        );
        assert!(
            renames
                .record(&a, 12, "/d/e.png", "/d/e.png.crypt", 4 * S)
                .is_none()
        );
    }

    #[test]
    fn extensions_past_the_bound_and_actors_past_theirs_are_not_held() {
        let mut renames = MassRenames::new(RANSOM_WINDOW_NS, 2, 2);
        let a = actor(1);
        for n in 0..RANSOM_RENAME_EXTENSIONS_MAX {
            renames.record(&a, 1, "/d/x.txt", &format!("/d/x.e{n}"), S);
        }
        // A ninth extension is not counted, so two of it raise nothing.
        assert!(renames.record(&a, 1, "/d/y.txt", "/d/y.ninth", S).is_none());
        assert!(renames.record(&a, 1, "/d/z.txt", "/d/z.ninth", S).is_none());
        renames.record(&actor(2), 2, "/d/a.txt", "/d/a.x", 2 * S);
        renames.record(&actor(3), 3, "/d/a.txt", "/d/a.x", 3 * S);
        assert_eq!(renames.actors(), 2);
    }

    #[test]
    fn a_new_window_counts_from_zero() {
        let mut renames = MassRenames::new(RANSOM_WINDOW_NS, 2, 8);
        let a = actor(10);
        renames.record(&a, 10, "/a.txt", "/a.x", 0);
        assert!(renames.record(&a, 10, "/b.txt", "/b.x", 61 * S).is_none());
        assert!(renames.record(&a, 10, "/c.txt", "/c.x", 62 * S).is_some());
    }
}
