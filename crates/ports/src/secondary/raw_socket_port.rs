//! Listing the packet sockets open on the node.

use domain::common::error::DomainError;
use domain::raw_socket::RawSocket;

/// Reads every `AF_PACKET` socket on the node, in every network namespace,
/// with the process holding it and the state of its filter.
pub trait RawSocketReader: Send + Sync {
    /// The sockets as the kernel lists them now.
    ///
    /// # Errors
    ///
    /// The reading could not be made at all: the warden refused or is
    /// unreachable. A namespace that could not be read is left out rather
    /// than failing the whole reading.
    fn list(&self) -> Result<Vec<RawSocket>, DomainError>;

    /// Where the reading comes from: `warden` or `local`.
    fn source(&self) -> &'static str;
}
