//! Listing the eBPF programs on the node's network path.

use domain::common::error::DomainError;
use domain::network_program::{NetworkProgram, OwnBpfObjects};

/// Reads every eBPF program attached on the network path, or of a network
/// type, with the processes holding it, and what the agent itself holds.
pub trait NetworkProgramReader: Send + Sync {
    /// The programs as the kernel lists them now, the agent's own included.
    ///
    /// # Errors
    ///
    /// The kernel refused the enumeration, or the warden refused or is
    /// unreachable.
    fn list(&self) -> Result<Vec<NetworkProgram>, DomainError>;

    /// The programs and links the agent holds a descriptor on.
    fn own(&self) -> OwnBpfObjects;

    /// Where the reading comes from: `warden` or `local`.
    fn source(&self) -> &'static str;
}
