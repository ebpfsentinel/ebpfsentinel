//! Userspace network adapters (raw socket / ioctl) for the L2 VIP announcer
//! (interface MAC/ifindex resolution, gratuitous ARP), multi-WAN default-route
//! programming, and rootless packet capture over launcher-provisioned
//! `AF_PACKET` sockets.

pub mod default_route;
pub mod gratuitous_arp;
pub mod iface_mac;
pub mod pcap_capture;

pub use default_route::IpDefaultRoute;
pub use gratuitous_arp::RawSocketGratuitousArp;
pub use iface_mac::IoctlIfaceMacResolver;
