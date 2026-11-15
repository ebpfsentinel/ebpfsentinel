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

    /// The `(dev, inode)` the kernel reads for the file `pid` runs, when it
    /// differs from what a stat answered as `dev`/`inode`.
    ///
    /// A stat is not always what the kernel sees: overlayfs reports a lower
    /// layer's own device for a file it serves from that layer, while the
    /// task's address space maps the file on the overlay's superblock, and a
    /// kernel program matching by inode reads the latter. `None` where the
    /// two agree, where the file behind `pid` is no longer the one stated, or
    /// where it cannot be read.
    fn kernel_identity(&self, pid: u32, dev: u64, inode: u64) -> Option<(u64, u64)> {
        let _ = (pid, dev, inode);
        None
    }

    /// Every pid running on the host, where the reader can list them.
    ///
    /// A process the agent never saw exec - one already running when it
    /// started - is known only from here. Empty where the host cannot be
    /// listed.
    fn running(&self) -> Vec<u32> {
        Vec::new()
    }
}
