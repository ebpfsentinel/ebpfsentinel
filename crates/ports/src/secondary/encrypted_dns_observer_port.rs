use std::net::IpAddr;

use domain::dns::encrypted_dns::EncryptedDnsProtocol;
use domain::workload::entity::Workload;

/// One connection to an encrypted DNS resolver, recognised from its TLS
/// `ClientHello`: `DoT` by its port, `DoH` by a server name on the resolver
/// list.
#[derive(Debug, Clone, Copy)]
pub struct EncryptedDnsConnection<'a> {
    /// Kernel monotonic timestamp of the packet, in nanoseconds.
    pub timestamp_ns: u64,
    /// Address of the side that opened the connection.
    pub client: IpAddr,
    /// Address of the resolver.
    pub server: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    /// IP protocol number of the connection (6 for TCP).
    pub ip_protocol: u8,
    pub protocol: EncryptedDnsProtocol,
    /// The server name the `ClientHello` carried. `None` for a `DoT`
    /// handshake that named no server, which is then known by its address
    /// alone.
    pub server_name: Option<&'a str>,
    /// The workload that opened the connection, with its ancestry, when the
    /// socket tables could name it.
    pub workload: Option<&'a Workload>,
}

/// Secondary port handed every encrypted DNS connection the pipeline
/// recognises, once its handshake has been seen.
///
/// The pipeline raises its own detection alert either way; an observer is
/// what decides on the connection, and raises and enforces what it decides
/// itself.
pub trait EncryptedDnsObserver: Send + Sync {
    fn observe(&self, connection: &EncryptedDnsConnection<'_>);

    /// Stable name of the observer, used in logs.
    fn name(&self) -> &'static str {
        "observer"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_dns_observer_port_is_object_safe() {
        fn _check(observer: &dyn EncryptedDnsObserver) {
            observer.observe(&EncryptedDnsConnection {
                timestamp_ns: 1,
                client: IpAddr::from([10, 0, 0, 1]),
                server: IpAddr::from([9, 9, 9, 9]),
                client_port: 40_000,
                server_port: 853,
                ip_protocol: 6,
                protocol: EncryptedDnsProtocol::Dot,
                server_name: Some("dns.quad9.net"),
                workload: None,
            });
        }
    }
}
