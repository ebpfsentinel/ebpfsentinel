//! Guest naming secondary port.
//!
//! Given a guest's device in the host namespace, answer which virtual machine
//! it was made for, read from the hypervisor's own records.

use domain::guest::GuestNaming;

/// Reads the hypervisor records naming the guest behind a device.
pub trait GuestNamingPort: Send + Sync {
    /// The guest behind `interface`, or why no record names one.
    fn name_guest(&self, interface: &str) -> GuestNaming;
}
