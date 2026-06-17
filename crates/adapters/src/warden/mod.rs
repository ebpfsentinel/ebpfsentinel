//! Adapters backed by the warden control plane. The rootless agent loads its own
//! eBPF but brokers the host-netns operations it cannot perform from its user
//! namespace — gratuitous ARP, packet capture, and cross-container uprobe attach
//! — to the privileged warden over its typed `AF_UNIX` protocol.

pub mod arp;
pub mod pcap;
pub mod uprobe;
