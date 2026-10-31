use domain::common::error::DomainError;
use domain::tcp_health::RawTcpEdge;

/// The kernel-side counter of TCP health per edge, read whole.
pub trait TcpHealthPort: Send + Sync {
    /// Every edge the kernel holds, summed over the CPUs, and the number of
    /// events it saw but could not count under an edge.
    ///
    /// # Errors
    ///
    /// Returns an error when the maps cannot be read.
    fn read(&self) -> Result<(Vec<RawTcpEdge>, u64), DomainError>;
}
