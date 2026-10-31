use std::net::IpAddr;

/// The transport a bound socket carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListenerProtocol {
    Tcp,
    Udp,
}

impl ListenerProtocol {
    /// From the IP protocol number the kernel writes. Anything other than TCP
    /// and UDP is not a listener this module describes.
    #[must_use]
    pub fn from_ip_protocol(protocol: u8) -> Option<Self> {
        match protocol {
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// How far an address reaches.
///
/// Ordered from the widest: a socket bound on every address of its namespace
/// is the one nobody may have meant to expose, so it is listed first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ListenerScope {
    /// `0.0.0.0` or `::`: every address the namespace holds, now and later.
    AllAddresses,
    /// One address of an interface.
    Address,
    /// `127.0.0.0/8` or `::1`: nothing off the node reaches it.
    Loopback,
}

impl ListenerScope {
    #[must_use]
    pub fn of(address: IpAddr) -> Self {
        if address.is_unspecified() {
            Self::AllAddresses
        } else if address.is_loopback() {
            Self::Loopback
        } else {
            Self::Address
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AllAddresses => "all_addresses",
            Self::Address => "address",
            Self::Loopback => "loopback",
        }
    }
}

/// A socket holding a local address, as the kernel recorded it at the bind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundSocket {
    pub address: IpAddr,
    pub port: u16,
    pub protocol: ListenerProtocol,
    /// Whether a TCP socket has called `listen()`. A UDP socket receives as
    /// soon as it is bound, so it is always listening.
    pub listening: bool,
    /// The process that bound it, by its thread group id.
    pub pid: u32,
    /// The real uid of the binding task.
    pub uid: u32,
    /// cgroup v2 id of the binding task, 0 where the kernel had none.
    pub cgroup_id: u64,
    /// When the bind happened, in nanoseconds of boot time.
    pub bound_at_ns: u64,
}

impl BoundSocket {
    #[must_use]
    pub fn scope(&self) -> ListenerScope {
        ListenerScope::of(self.address)
    }

    /// Whether this socket accepts traffic: a UDP socket once bound, a TCP
    /// socket once it has called `listen()`. A TCP socket that is bound and
    /// not listening is a client that chose its own source, or a server a
    /// moment before its `listen()`, and neither is exposed.
    #[must_use]
    pub fn accepts(&self) -> bool {
        match self.protocol {
            ListenerProtocol::Udp => true,
            ListenerProtocol::Tcp => self.listening,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn socket(address: IpAddr, protocol: ListenerProtocol, listening: bool) -> BoundSocket {
        BoundSocket {
            address,
            port: 8080,
            protocol,
            listening,
            pid: 42,
            uid: 0,
            cgroup_id: 0,
            bound_at_ns: 0,
        }
    }

    #[test]
    fn an_unspecified_address_reaches_everything_and_loopback_nothing_off_the_node() {
        assert_eq!(
            ListenerScope::of(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            ListenerScope::AllAddresses
        );
        assert_eq!(
            ListenerScope::of(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            ListenerScope::AllAddresses
        );
        assert_eq!(
            ListenerScope::of(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53))),
            ListenerScope::Loopback
        );
        assert_eq!(
            ListenerScope::of(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            ListenerScope::Loopback
        );
        assert_eq!(
            ListenerScope::of(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
            ListenerScope::Address
        );
        assert!(ListenerScope::AllAddresses < ListenerScope::Address);
        assert!(ListenerScope::Address < ListenerScope::Loopback);
    }

    #[test]
    fn a_bound_udp_socket_accepts_and_a_bound_tcp_one_only_once_it_listens() {
        let any = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        assert!(socket(any, ListenerProtocol::Udp, false).accepts());
        assert!(!socket(any, ListenerProtocol::Tcp, false).accepts());
        assert!(socket(any, ListenerProtocol::Tcp, true).accepts());
    }

    #[test]
    fn only_tcp_and_udp_are_listeners() {
        assert_eq!(
            ListenerProtocol::from_ip_protocol(6),
            Some(ListenerProtocol::Tcp)
        );
        assert_eq!(
            ListenerProtocol::from_ip_protocol(17),
            Some(ListenerProtocol::Udp)
        );
        assert_eq!(ListenerProtocol::from_ip_protocol(132), None);
    }
}
