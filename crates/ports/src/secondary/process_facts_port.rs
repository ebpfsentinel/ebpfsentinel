//! What only a running process can say about itself.

use domain::process::detection::ProcessFacts;

/// Reads, at the moment a process is tested, whether its standard streams are
/// an internet socket and whether the file it runs still exists.
///
/// Both answers are about the process as it is now, which is why they are not
/// in the table: a shell's streams are redirected after it starts, and a
/// binary is removed after it was executed. A process that is gone, or that
/// the agent may not inspect, answers `None`, and no detection that needs
/// either fact fires on it.
pub trait ProcessFactsReader: Send + Sync {
    /// The facts about `pid`, or `None` where they cannot be read.
    fn read_facts(&self, pid: u32) -> Option<ProcessFacts>;
}
