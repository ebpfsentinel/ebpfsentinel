use domain::process::digest::ExeHash;

/// Obtains the digest of the file a process is running.
///
/// The process table names a binary by its path, and a path is whatever
/// anything able to write a file chose to put there. A digest names the
/// bytes. The read happens at the exec, against the file the process itself
/// has mapped rather than against a name that may since point elsewhere, and
/// `dev` and `inode` are the identity the table already read, so a digest is
/// never attached to a different file than the path beside it.
pub trait ExecutableDigester: Send + Sync {
    /// The digest of the executable `pid` runs, which must be the file
    /// `(dev, inode)`, or `None` where the process is gone, the file cannot
    /// be opened, is another file by now, or is larger than is read.
    fn digest(&self, pid: u32, dev: u64, inode: u64) -> Option<ExeHash>;
}
