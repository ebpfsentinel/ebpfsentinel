#![forbid(unsafe_code)]

use std::net::IpAddr;

use domain::firewall::entity::IpNetwork;
use ebpf_common::firewall::{FirewallLpmEntryV4, FirewallLpmEntryV6};

/// Convert a `[u32; 4]` address to [`IpAddr`].
///
/// IPv4 uses only the first element; IPv6 uses all four u32s in network
/// (big-endian) order.
pub fn addr_to_ip(addr: [u32; 4], ipv6: bool) -> IpAddr {
    if ipv6 {
        let mut bytes = [0u8; 16];
        for (i, word) in addr.iter().enumerate() {
            bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        IpAddr::V6(std::net::Ipv6Addr::from(bytes))
    } else {
        IpAddr::V4(std::net::Ipv4Addr::from(addr[0]))
    }
}

/// Convert domain [`IpNetwork`] CIDRs to eBPF LPM Trie entry types.
///
/// IPv4 addresses are converted from host byte order (`u32`) to network
/// byte order (`[u8; 4]`) as required by the LPM Trie key format.
pub fn convert_to_lpm_entries(
    ips: &[IpNetwork],
    action: u8,
) -> (Vec<FirewallLpmEntryV4>, Vec<FirewallLpmEntryV6>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpNetwork::V4 { addr, prefix_len } => {
                v4.push(FirewallLpmEntryV4 {
                    prefix_len: u32::from(*prefix_len),
                    addr: addr.to_be_bytes(),
                    action,
                });
            }
            IpNetwork::V6 { addr, prefix_len } => {
                v6.push(FirewallLpmEntryV6 {
                    prefix_len: u32::from(*prefix_len),
                    addr: *addr,
                    action,
                });
            }
        }
    }
    (v4, v6)
}

pub mod alert_enrichment;
pub mod alert_event;
pub mod alert_pipeline;
pub mod alias_service_impl;
pub mod audit_service_impl;
pub mod config_reload;
pub mod conntrack_service_impl;
pub mod ddos_service_impl;
pub mod dlp_service_impl;
pub mod dns_blocklist_service_impl;
pub mod dns_cache_service_impl;
pub mod domain_reputation_service_impl;
pub mod feed_update;
pub mod firewall_service_impl;
pub mod ids_service_impl;
pub mod ips_service_impl;
pub mod l7_service_impl;
pub mod lb_service_impl;
pub mod nat_service_impl;
pub mod packet_pipeline;
pub mod qos_service_impl;
pub mod ratelimit_service_impl;
pub mod reputation_enforcement;
pub mod retry;
pub mod routing_service_impl;
pub mod schedule_service_impl;
pub mod threatintel_service_impl;
pub mod zone_service_impl;
