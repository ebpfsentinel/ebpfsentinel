//! Userspace network adapters (raw socket / ioctl) for the L2 VIP announcer
//! (interface MAC/ifindex resolution, gratuitous ARP) and rootless packet
//! capture over launcher-provisioned `AF_PACKET` sockets.

pub mod gratuitous_arp;
pub mod iface_mac;
pub mod pcap_capture;

pub use gratuitous_arp::RawSocketGratuitousArp;
pub use iface_mac::IoctlIfaceMacResolver;
