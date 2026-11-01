//! The strong signal read from names alone: one new filename written into
//! many directories by one actor inside one window.
//!
//! A ransom run leaves its note in every directory it walks, under one name.
//! Nothing of the file is read, only that it was created and where, so the
//! signal costs nothing and carries no privacy question. The count is of
//! directories rather than files, since a run writes one note per directory.
//! A few build, packaging and desktop tools also scatter one name widely, and
//! those names are listed here and never counted.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use crate::process::entity::ProcessKey;

use super::actor::Actor;
use super::engine::{RANSOM_ACTORS_MAX, RANSOM_WINDOW_NS};
use super::signal::{RansomSignal, SignalKind};

/// How many distinct directories one actor writes one new name into in a
/// window before the signal is raised.
pub const RANSOM_NOTE_DIRECTORIES: usize = 40;

/// Names followed per actor at once. A build creates thousands of names, each
/// in a directory or two; the name least recently seen is dropped first, so a
/// note written into every directory a run walks keeps its place.
pub const RANSOM_NOTE_NAMES_MAX: usize = 256;

/// Names that build systems, package managers, language toolchains and
/// desktop environments write into many directories at once, compared
/// without regard to case.
pub const SCATTERED_NAMES: &[&str] = &[
    // Version control and editors.
    ".gitkeep",
    ".keep",
    ".gitignore",
    ".gitattributes",
    ".npmignore",
    ".editorconfig",
    // Python packaging and bytecode.
    "__init__.py",
    "py.typed",
    "metadata",
    "record",
    "wheel",
    "installer",
    "requested",
    "top_level.txt",
    "entry_points.txt",
    "direct_url.json",
    // JavaScript and TypeScript packages.
    "package.json",
    "index.js",
    "index.d.ts",
    "index.mjs",
    "index.cjs",
    "readme.md",
    "license",
    "license.md",
    "license.txt",
    "changelog.md",
    // Other toolchains.
    "cargo.toml",
    ".cargo-ok",
    ".cargo_vcs_info.json",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build",
    "build.bazel",
    "makefile",
    "cmakelists.txt",
    "meson.build",
    // Desktop environments and file managers.
    ".directory",
    ".ds_store",
    "thumbs.db",
    "desktop.ini",
];

/// Whether `name` is one legitimate software also scatters.
#[must_use]
pub fn scattered(name: &str) -> bool {
    SCATTERED_NAMES
        .iter()
        .any(|listed| listed.eq_ignore_ascii_case(name))
}

fn hash(text: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

#[derive(Debug)]
struct Name {
    last_ns: u64,
    directories: HashSet<u64>,
}

#[derive(Debug)]
struct Run {
    opened_ns: u64,
    last_ns: u64,
    names: HashMap<String, Name>,
    raised: bool,
}

/// Distinct directories each new name was written into, per actor, in windows
/// that open at the first such file and close `window_ns` later.
#[derive(Debug)]
pub struct RansomNotes {
    window_ns: u64,
    threshold: usize,
    max_actors: usize,
    runs: HashMap<ProcessKey, Run>,
}

impl Default for RansomNotes {
    fn default() -> Self {
        Self::new(RANSOM_WINDOW_NS, RANSOM_NOTE_DIRECTORIES, RANSOM_ACTORS_MAX)
    }
}

impl RansomNotes {
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

    /// Count the new file at `path`, created by `pid` on behalf of `actor`,
    /// and return the signal the first time one name reaches the threshold
    /// of directories in the actor's window.
    pub fn record(
        &mut self,
        actor: &Actor,
        pid: u32,
        path: &str,
        at_ns: u64,
    ) -> Option<RansomSignal> {
        let (directory, name) = path.rsplit_once('/')?;
        if name.is_empty() || scattered(name) {
            return None;
        }
        if !self.runs.contains_key(&actor.key) {
            self.make_room(at_ns);
        }
        let window = self.window_ns;
        let run = self.runs.entry(actor.key).or_insert_with(|| Run {
            opened_ns: at_ns,
            last_ns: at_ns,
            names: HashMap::new(),
            raised: false,
        });
        if at_ns.saturating_sub(run.opened_ns) > window {
            run.opened_ns = at_ns;
            run.names.clear();
            run.raised = false;
        }
        run.last_ns = run.last_ns.max(at_ns);
        if run.raised {
            return None;
        }
        if !run.names.contains_key(name)
            && run.names.len() >= RANSOM_NOTE_NAMES_MAX
            && let Some(stalest) = run
                .names
                .iter()
                .min_by_key(|(_, held)| held.last_ns)
                .map(|(held, _)| held.clone())
        {
            run.names.remove(&stalest);
        }
        let held = run.names.entry(name.to_owned()).or_insert_with(|| Name {
            last_ns: at_ns,
            directories: HashSet::new(),
        });
        held.last_ns = held.last_ns.max(at_ns);
        held.directories.insert(hash(directory));
        if held.directories.len() < self.threshold {
            return None;
        }
        run.raised = true;
        run.names.clear();
        let seconds = at_ns.saturating_sub(run.opened_ns) / 1_000_000_000;
        Some(RansomSignal {
            kind: SignalKind::RansomNote,
            actor: actor.clone(),
            pid,
            at_ns,
            evidence: format!(
                "{name} written into {} directories in {seconds} s, the last {directory}",
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
    fn one_name_in_many_directories_raises_the_signal_once() {
        let mut notes = RansomNotes::new(RANSOM_WINDOW_NS, 3, 8);
        let a = actor(10);
        assert!(notes.record(&a, 11, "/d1/HOW_TO_DECRYPT.txt", S).is_none());
        // The same directory again is not another directory.
        assert!(notes.record(&a, 11, "/d1/HOW_TO_DECRYPT.txt", S).is_none());
        assert!(notes.record(&a, 11, "/d2/HOW_TO_DECRYPT.txt", S).is_none());
        // Another name counts apart.
        assert!(notes.record(&a, 11, "/d3/other.txt", S).is_none());
        let signal = notes
            .record(&a, 12, "/d3/HOW_TO_DECRYPT.txt", 4 * S)
            .unwrap();
        assert_eq!(signal.kind, SignalKind::RansomNote);
        assert_eq!(signal.pid, 12);
        assert_eq!(
            signal.evidence,
            "HOW_TO_DECRYPT.txt written into 3 directories in 3 s, the last /d3"
        );
        assert!(
            notes
                .record(&a, 12, "/d4/HOW_TO_DECRYPT.txt", 5 * S)
                .is_none()
        );
    }

    #[test]
    fn names_tools_scatter_are_never_counted() {
        let mut notes = RansomNotes::new(RANSOM_WINDOW_NS, 2, 8);
        let a = actor(1);
        for name in ["package.json", "__init__.py", "README.md", ".DS_Store"] {
            assert!(scattered(name));
            assert!(notes.record(&a, 1, &format!("/x/{name}"), S).is_none());
            assert!(notes.record(&a, 1, &format!("/y/{name}"), S).is_none());
        }
        assert!(!scattered("README.txt"));
    }

    #[test]
    fn a_note_kept_fresh_survives_a_build_of_many_names() {
        let mut notes = RansomNotes::new(RANSOM_WINDOW_NS, 3, 8);
        let a = actor(1);
        notes.record(&a, 1, "/d0/note.txt", S);
        notes.record(&a, 1, "/d1/note.txt", 2 * S);
        for n in 0..RANSOM_NOTE_NAMES_MAX * 2 {
            notes.record(&a, 1, &format!("/src/f{n}.o"), 2 * S);
            if n == RANSOM_NOTE_NAMES_MAX / 2 {
                notes.record(&a, 1, "/d1/note.txt", 3 * S);
            }
        }
        // The note's last sighting is the freshest, so it is still held.
        assert!(notes.record(&a, 1, "/d2/note.txt", 4 * S).is_some());
    }

    #[test]
    fn a_new_window_and_bounded_actors() {
        let mut notes = RansomNotes::new(RANSOM_WINDOW_NS, 2, 2);
        let a = actor(1);
        notes.record(&a, 1, "/a/n.txt", 0);
        assert!(notes.record(&a, 1, "/b/n.txt", 61 * S).is_none());
        assert!(notes.record(&a, 1, "/c/n.txt", 62 * S).is_some());
        notes.record(&actor(2), 2, "/a/n.txt", 63 * S);
        notes.record(&actor(3), 3, "/a/n.txt", 64 * S);
        assert_eq!(notes.actors(), 2);
    }
}
