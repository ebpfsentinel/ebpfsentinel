//! Userspace network adapters (raw socket / ioctl) for the L2 VIP announcer
//! (interface MAC/ifindex resolution, gratuitous ARP), multi-WAN default-route
//! programming, rootless packet capture over launcher-provisioned
//! `AF_PACKET` sockets, and the client a file service's process serves.

pub mod bird;
pub mod default_route;
pub mod dns_upstream;
pub mod gratuitous_arp;
pub mod iface_addrs;
pub mod iface_mac;
pub mod pcap_capture;
pub mod served_peer;

pub use default_route::IpDefaultRoute;
pub use gratuitous_arp::RawSocketGratuitousArp;
pub use iface_mac::IoctlIfaceMacResolver;
pub use served_peer::ProcServedPeer;
