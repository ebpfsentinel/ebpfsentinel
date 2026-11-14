//! The DNS allow-list resolver's sockets, bound by the warden.
//!
//! The resolver listens on port 53, below the unprivileged range, and the
//! rootless agent holds no `CAP_NET_BIND_SERVICE` on the host. The warden binds
//! both sockets and hands each over; the agent serves them from then on.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::path::Path;

use ebpfsentinel_warden_client::WardenClient;

/// Bind the UDP socket and the TCP listener on `listen` through the warden at
/// `sock`. Both come back blocking, as the kernel made them; the caller sets
/// them non-blocking before handing them to a runtime.
///
/// # Errors
///
/// The connection to the warden, or the warden's refusal naming the address.
pub fn bind(sock: &Path, listen: SocketAddr) -> std::io::Result<(UdpSocket, TcpListener)> {
    let mut client = WardenClient::connect(sock)?;
    let udp = UdpSocket::from(client.resolver_socket(listen, false)?);
    let tcp = TcpListener::from(client.resolver_socket(listen, true)?);
    Ok((udp, tcp))
}
