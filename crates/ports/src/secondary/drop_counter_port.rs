use domain::common::error::DomainError;
use domain::drops::RawDrop;

/// The kernel-side counter of dropped packets, read whole.
pub trait DropCounterPort: Send + Sync {
    /// Every counter the kernel holds, its reason named, and the number of
    /// drops it saw but had no room to count under a pair.
    ///
    /// # Errors
    ///
    /// Returns an error when the maps cannot be read.
    fn read(&self) -> Result<(Vec<RawDrop>, u64), DomainError>;
}
