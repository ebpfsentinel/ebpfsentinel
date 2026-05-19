//! Userspace network adapters (raw socket / ioctl) for the L2 VIP
//! announcer: interface MAC/ifindex resolution and gratuitous ARP.

pub mod gratuitous_arp;
pub mod iface_mac;

pub use gratuitous_arp::RawSocketGratuitousArp;
pub use iface_mac::IoctlIfaceMacResolver;
