use domain::common::error::DomainError;
use domain::inventory::InventorySweep;

/// Reads the package databases of every filesystem root processes run in.
pub trait PackageInventoryReader: Send + Sync {
    /// Read every root once. A database that cannot be read is reported in
    /// the sweep with its reason rather than failing it.
    ///
    /// # Errors
    ///
    /// The roots could not be listed: the warden refused or is unreachable.
    fn read(&self) -> Result<InventorySweep, DomainError>;

    /// Where the reading comes from: `warden` or `local`.
    fn source(&self) -> &'static str;
}
