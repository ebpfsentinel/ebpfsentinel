//! The strong signal read from the shape of a write: a file replaced by a new
//! one of its own size, written fresh beside it.
//!
//! A run that does not encrypt in place reads each file, writes what it read
//! transformed into a new file beside it, and then either renames that file
//! over the original or deletes the original. Volume does not tell that apart
//! from a backup or a package upgrade; the shape does, on two counts the file
//! watch can see. The replacement is written now, where `rsync -a`, `cp -p`, a
//! package manager or an archive extraction leaves the time its source
//! carried, and the replacement is as large as the original plus at most a
//! bounded overhead, which is what writing back what was read, padded and
//! headed, produces. The read itself is not observed: a filesystem-wide read
//! event would cost every open on the host, so the size stands for it.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::process::entity::ProcessKey;

use super::actor::Actor;
use super::engine::{RANSOM_ACTORS_MAX, RANSOM_WINDOW_NS};

/// How many distinct files one actor replaces in a window before the signal
/// is raised.
pub const RANSOM_REPLACEMENTS: usize = 20;

/// The most a replacement may exceed the original by and still be the
/// original written back: a header, a footer, padding and a wrapped key.
pub const REPLACEMENT_OVERHEAD_BYTES: u64 = 1 << 20;

/// How far a replacement's modification time may sit from now and still be a
/// file written now rather than one carrying its source's time.
pub const REPLACEMENT_FRESH_NS: u64 = 300_000_000_000;

/// Halves of a replacement held per actor while the other half is awaited,
/// for each of the two halves.
pub const REPLACEMENT_HALVES_MAX: usize = 1024;

/// Whether a file of `replacement` bytes is one of `original` bytes written
/// back: never smaller, larger by at most the overhead, and not an empty file
/// replaced, which is a placeholder rather than content.
#[must_use]
pub fn replaces(original: u64, replacement: u64) -> bool {
    original > 0 && replacement >= original && replacement - original <= REPLACEMENT_OVERHEAD_BYTES
}

/// Whether a file modified at `mtime_ns` was written within the freshness
/// bound of `now_ns`, both in nanoseconds since the epoch.
#[must_use]
pub fn written_now(mtime_ns: i64, now_ns: u64) -> bool {
    u64::try_from(mtime_ns).is_ok_and(|mtime| now_ns.abs_diff(mtime) <= REPLACEMENT_FRESH_NS)
}

fn directory(path: &str) -> Option<&str> {
    path.rsplit_once('/').map(|(dir, _)| dir)
}

/// The original a file written beside it replaces: the same path with its
/// last extension taken off, `report.docx` for `report.docx.locked`. A hidden
/// name or a name with no extension replaces nothing by its name.
#[must_use]
pub fn original_of(path: &str) -> Option<&str> {
    let (dir, name) = path.rsplit_once('/')?;
    let (stem, extension) = name.rsplit_once('.')?;
    if stem.is_empty() || extension.is_empty() || stem.starts_with('.') {
        return None;
    }
    Some(&path[..dir.len() + 1 + stem.len()])
}

/// Whether renaming `from` over `to` replaced a file of `before` bytes with
/// one of `now` bytes written beside it.
#[must_use]
pub fn renamed_over(from: &str, to: &str, before: u64, now: u64) -> bool {
    directory(from).is_some() && directory(from) == directory(to) && replaces(before, now)
}

fn hash(path: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    path.hash(&mut hasher);
    hasher.finish()
}

/// One half seen: the size it names and when.
#[derive(Debug, Clone, Copy)]
struct Seen {
    size: u64,
    at_ns: u64,
}

#[derive(Debug, Default)]
struct Halves {
    last_ns: u64,
    /// Fresh files written beside an original, by the original's path.
    written: HashMap<u64, Seen>,
    /// Originals deleted, by their path.
    deleted: HashMap<u64, Seen>,
}

/// Keep `seen` under `key`, dropping what fell out of the window and then the
/// oldest half once the bound is reached.
fn hold(halves: &mut HashMap<u64, Seen>, key: u64, seen: Seen, window_ns: u64) {
    if !halves.contains_key(&key) && halves.len() >= REPLACEMENT_HALVES_MAX {
        halves.retain(|_, half| seen.at_ns.saturating_sub(half.at_ns) <= window_ns);
        if halves.len() >= REPLACEMENT_HALVES_MAX
            && let Some(oldest) = halves
                .iter()
                .min_by_key(|(_, half)| half.at_ns)
                .map(|(key, _)| *key)
        {
            halves.remove(&oldest);
        }
    }
    halves.insert(key, seen);
}

/// The two halves of a write-beside-then-delete replacement, per actor,
/// matched whichever settles first: a file watch settles a batch of paths in
/// no fixed order, so the deletion of an original can be read before the file
/// that replaced it.
#[derive(Debug)]
pub struct Replacements {
    window_ns: u64,
    max_actors: usize,
    actors: HashMap<ProcessKey, Halves>,
}

impl Default for Replacements {
    fn default() -> Self {
        Self::new(RANSOM_WINDOW_NS, RANSOM_ACTORS_MAX)
    }
}

impl Replacements {
    #[must_use]
    pub fn new(window_ns: u64, max_actors: usize) -> Self {
        Self {
            window_ns,
            max_actors: max_actors.max(1),
            actors: HashMap::new(),
        }
    }

    /// How many actors are held now.
    #[must_use]
    pub fn actors(&self) -> usize {
        self.actors.len()
    }

    /// A fresh file of `size` bytes written beside `original` by `actor`;
    /// whether it completes a replacement of that original.
    pub fn written(&mut self, actor: &Actor, original: &str, size: u64, at_ns: u64) -> bool {
        let key = hash(original);
        let window = self.window_ns;
        let halves = self.halves(actor, at_ns);
        if let Some(gone) = halves.deleted.get(&key).copied()
            && at_ns.saturating_sub(gone.at_ns) <= window
            && replaces(gone.size, size)
        {
            halves.deleted.remove(&key);
            return true;
        }
        hold(&mut halves.written, key, Seen { size, at_ns }, window);
        false
    }

    /// `original`, a known file of `size` bytes, deleted by `actor`; whether
    /// that completes its replacement.
    pub fn deleted(&mut self, actor: &Actor, original: &str, size: u64, at_ns: u64) -> bool {
        let key = hash(original);
        let window = self.window_ns;
        let halves = self.halves(actor, at_ns);
        if let Some(beside) = halves.written.get(&key).copied()
            && at_ns.saturating_sub(beside.at_ns) <= window
            && replaces(size, beside.size)
        {
            halves.written.remove(&key);
            return true;
        }
        hold(&mut halves.deleted, key, Seen { size, at_ns }, window);
        false
    }

    fn halves(&mut self, actor: &Actor, at_ns: u64) -> &mut Halves {
        if !self.actors.contains_key(&actor.key) {
            self.make_room(at_ns);
        }
        let halves = self.actors.entry(actor.key).or_default();
        halves.last_ns = halves.last_ns.max(at_ns);
        halves
    }

    fn make_room(&mut self, at_ns: u64) {
        if self.actors.len() < self.max_actors {
            return;
        }
        let window = self.window_ns;
        self.actors
            .retain(|_, halves| at_ns.saturating_sub(halves.last_ns) <= window);
        while self.actors.len() >= self.max_actors {
            let Some(oldest) = self
                .actors
                .iter()
                .min_by_key(|(_, halves)| halves.last_ns)
                .map(|(key, _)| *key)
            else {
                return;
            };
            self.actors.remove(&oldest);
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
    fn a_replacement_is_the_original_size_plus_a_bounded_overhead() {
        assert!(replaces(1000, 1000));
        assert!(replaces(1000, 1000 + REPLACEMENT_OVERHEAD_BYTES));
        assert!(!replaces(1000, 999));
        assert!(!replaces(1000, 1001 + REPLACEMENT_OVERHEAD_BYTES));
        assert!(!replaces(0, 10));
    }

    #[test]
    fn a_file_carrying_its_source_time_is_not_written_now() {
        let now = 1_800_000_000 * S;
        assert!(written_now(i64::try_from(now - 2 * S).unwrap(), now));
        assert!(!written_now(i64::try_from(now - 3600 * S).unwrap(), now));
        assert!(!written_now(-1, now));
    }

    #[test]
    fn the_original_is_the_name_without_its_last_extension() {
        assert_eq!(original_of("/d/report.docx.locked"), Some("/d/report.docx"));
        assert_eq!(original_of("/d/report.docx"), Some("/d/report"));
        assert_eq!(original_of("/d/README"), None);
        assert_eq!(original_of("/d/.bashrc"), None);
        assert_eq!(original_of("/d/.report.docx.x1"), None);
        assert!(renamed_over("/d/.tmp1", "/d/a.pdf", 10, 12));
        assert!(!renamed_over("/e/.tmp1", "/d/a.pdf", 10, 12));
        assert!(!renamed_over("/d/.tmp1", "/d/a.pdf", 10, 2));
    }

    #[test]
    fn the_two_halves_match_in_either_order() {
        let mut replacements = Replacements::default();
        let a = actor(1);
        assert!(!replacements.written(&a, "/d/a.pdf", 1200, S));
        assert!(replacements.deleted(&a, "/d/a.pdf", 1000, 2 * S));
        assert!(!replacements.deleted(&a, "/d/b.pdf", 1000, 2 * S));
        assert!(replacements.written(&a, "/d/b.pdf", 1000, 3 * S));
        // Another actor's half, a smaller file and a stale half match nothing.
        assert!(!replacements.deleted(&actor(2), "/d/c.pdf", 1000, 3 * S));
        assert!(!replacements.written(&a, "/d/c.pdf", 1000, 3 * S));
        assert!(!replacements.written(&a, "/d/e.pdf", 10, 3 * S));
        assert!(!replacements.deleted(&a, "/d/e.pdf", 1000, 3 * S));
        assert!(!replacements.written(&a, "/d/f.pdf", 1000, 3 * S));
        assert!(!replacements.deleted(&a, "/d/f.pdf", 1000, 70 * S));
    }

    #[test]
    fn halves_and_actors_are_bounded() {
        let mut replacements = Replacements::new(RANSOM_WINDOW_NS, 2);
        let a = actor(1);
        for n in 0..=REPLACEMENT_HALVES_MAX {
            replacements.written(&a, &format!("/d/{n}"), 10, S);
        }
        assert_eq!(
            replacements.actors.get(&a.key).map(|h| h.written.len()),
            Some(REPLACEMENT_HALVES_MAX)
        );
        replacements.written(&actor(2), "/d/x", 10, 2 * S);
        replacements.written(&actor(3), "/d/x", 10, 3 * S);
        assert_eq!(replacements.actors(), 2);
    }
}
