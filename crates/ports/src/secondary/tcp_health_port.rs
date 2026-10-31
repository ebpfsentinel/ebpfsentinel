use domain::common::error::DomainError;
use domain::tcp_health::RawTcpEdge;
use domain::tcp_health::reset_scan::{ResetVerdict, SourceRate};

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

/// Decides whether one source's resets over the window are above the line
/// it is held to.
///
/// Every source that moved is handed over at every reading, the ones within
/// their line included, so a judge that learns what a source usually draws
/// sees all of it.
pub trait ResetRateJudge: Send + Sync {
    /// The line `rate` crossed, `None` when it is within it.
    fn judge(&self, rate: &SourceRate) -> Option<ResetVerdict>;
}
