use std::net::IpAddr;

use domain::alert::entity::Alert;
use domain::workload::entity::Workload;

/// One DNS query, seen from the socket that sent it.
#[derive(Debug, Clone, Copy)]
pub struct DnsQuery<'a> {
    /// Kernel monotonic timestamp of the packet, in nanoseconds.
    pub timestamp_ns: u64,
    /// Address of the side that asked.
    pub client: IpAddr,
    /// Address of the resolver asked.
    pub server: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    /// IP protocol number of the query (17 for UDP, 6 for TCP).
    pub ip_protocol: u8,
    /// The first name in the question section, lowercased.
    pub domain: &'a str,
    /// The workload that sent the query, with its ancestry, when the socket
    /// tables could name it.
    pub workload: Option<&'a Workload>,
}

/// Secondary port consulted once per DNS query leaving or crossing the node.
///
/// An observer that finds something returns the alert it raises. The caller
/// fills in what it knows better than the observer - the flow, the workload
/// and the container - and sends it down the ordinary alert path, so the
/// observer never has to resolve the socket a second time.
pub trait DnsQueryObserver: Send + Sync {
    fn observe(&self, query: &DnsQuery<'_>) -> Option<Alert>;

    /// Stable name of the observer, used in logs.
    fn name(&self) -> &'static str {
        "observer"
    }
}
