//! The socket the DNS allow-list resolver serves on.
//!
//! Containers are pointed at port 53 on an address the host holds, usually
//! the bridge gateway, and a container's resolver configuration names no
//! other port. Binding below the unprivileged range needs
//! `CAP_NET_BIND_SERVICE` on the host, which the rootless agent gave up, so the
//! warden binds and hands the descriptor over. It binds port 53 and nothing
//! else, on an address that a container can reach: loopback is the host's own
//! and the unspecified address would answer on every interface.

use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::OwnedFd;

/// The one port bound here.
pub const RESOLVER_PORT: u16 = 53;

/// Whether `listen` is an address the warden binds for the resolver.
///
/// # Errors
///
/// Names what is refused about the address.
pub fn admit(listen: SocketAddr) -> Result<(), String> {
    if listen.port() != RESOLVER_PORT {
        return Err(format!(
            "only port {RESOLVER_PORT} is bound for the resolver, not {}",
            listen.port()
        ));
    }
    if listen.ip().is_loopback() || listen.ip().is_unspecified() {
        return Err(format!(
            "{} is not an address containers reach the resolver on",
            listen.ip()
        ));
    }
    Ok(())
}

/// Bind `listen`, a listening TCP socket when `stream`, a UDP socket
/// otherwise.
///
/// # Errors
///
/// The refusal from [`admit`], or the bind's own failure naming the address.
pub fn bind(listen: SocketAddr, stream: bool) -> Result<OwnedFd, String> {
    admit(listen)?;
    let bound = if stream {
        TcpListener::bind(listen).map(OwnedFd::from)
    } else {
        UdpSocket::bind(listen).map(OwnedFd::from)
    };
    bound.map_err(|e| {
        let proto = if stream { "tcp" } else { "udp" };
        format!("could not bind {proto} {listen}: {e}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_53_on_an_address_containers_reach_is_admitted() {
        assert!(admit("172.17.0.1:53".parse().unwrap()).is_ok());
        assert!(admit("[fd00::1]:53".parse().unwrap()).is_ok());
    }

    #[test]
    fn another_port_is_refused() {
        let err = admit("172.17.0.1:22".parse().unwrap()).unwrap_err();
        assert!(err.contains("only port 53"), "{err}");
    }

    #[test]
    fn loopback_and_unspecified_are_refused() {
        for listen in ["127.0.0.1:53", "0.0.0.0:53", "[::]:53", "[::1]:53"] {
            assert!(admit(listen.parse().unwrap()).is_err(), "{listen}");
        }
    }

    #[test]
    fn a_refused_address_binds_nothing() {
        assert!(bind("127.0.0.1:53".parse().unwrap(), false).is_err());
    }
}
