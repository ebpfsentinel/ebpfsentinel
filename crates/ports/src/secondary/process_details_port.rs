use domain::process::entity::ProcessDetails;

/// Reads what `/proc` knows about a process that the exec notification does
/// not carry: its parent, and the command line it was started with.
///
/// The read races the process it describes. A binary that execs and exits
/// inside the time it takes to be notified leaves nothing behind, and the
/// port says so by returning `None` rather than inventing a parent of 1 or an
/// empty command line, because a wrong parent is a wrong investigation.
pub trait ProcessDetailsReader: Send + Sync {
    /// What `/proc` can say about `pid` right now.
    fn read_details(&self, pid: u32) -> Option<ProcessDetails>;
}
