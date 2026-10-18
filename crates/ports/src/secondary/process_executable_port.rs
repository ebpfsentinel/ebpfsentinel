//! Resolving the executable behind a pid.

use domain::dlp::entity::DlpExecutable;

/// Reads the binary a process is running.
///
/// A DLP event names a pid; an operator needs the program. The read happens
/// when the alert is raised, which is after the write the probe saw, so a
/// short-lived process is routinely gone by then: the port returns `None` for
/// that case rather than a placeholder path, because an alert naming the wrong
/// binary is worse than one naming none.
pub trait ProcessExecutableReader: Send + Sync {
    /// The executable `pid` is running, or `None` where it cannot be read.
    fn read_executable(&self, pid: u32) -> Option<DlpExecutable>;
}
