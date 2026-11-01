use domain::common::error::DomainError;
use domain::hidden::NamespacePorts;

/// Takes the two readings a hidden port is found between - the kernel's
/// socket listings and a bind probe - in every network namespace on the
/// node.
pub trait HiddenPortReader: Send + Sync {
    /// Read every namespace and probe `ports` in each, twice over.
    ///
    /// # Errors
    ///
    /// The reading could not be made at all: the warden refused or is
    /// unreachable. A namespace that could not be entered is returned with
    /// its reason rather than failing the whole reading.
    fn read(&self, ports: &[u16]) -> Result<Vec<NamespacePorts>, DomainError>;

    /// Where the reading comes from: `warden` or `local`.
    fn source(&self) -> &'static str;
}
