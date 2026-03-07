use std::net::IpAddr;

use domain::common::error::DomainError;

/// Metadata for an IOC injected via DNS blocklist resolution.
#[derive(Debug, Clone)]
pub struct IocMetadata {
    /// Source identifier (e.g. `"dns-blocklist"`).
    pub source: String,
    /// The domain that resolved to the injected IP.
    pub domain: Option<String>,
    /// Threat classification (e.g. `"blocklisted-domain"`).
    pub threat_type: String,
    /// Confidence score (0-100).
    pub confidence: u8,
}

/// Secondary port for dynamic eBPF map writes from DNS blocklist.
///
/// Allows the domain/application layer to inject or remove IPs from
/// kernel-space eBPF maps without depending on aya directly.
pub trait EbpfMapWritePort: Send + Sync {
    /// Insert an IP into the threat intelligence IOC map.
    fn inject_threatintel_ip(&self, ip: IpAddr, metadata: &IocMetadata) -> Result<(), DomainError>;

    /// Remove an IP from the threat intelligence IOC map.
    fn remove_threatintel_ip(&self, ip: IpAddr) -> Result<(), DomainError>;

    /// Insert an IP as a firewall drop rule.
    fn inject_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError>;

    /// Remove an IP from the firewall drop rules.
    fn remove_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    struct InMemoryMapWrite {
        threatintel: Mutex<HashSet<IpAddr>>,
        firewall: Mutex<HashSet<IpAddr>>,
    }

    impl InMemoryMapWrite {
        fn new() -> Self {
            Self {
                threatintel: Mutex::new(HashSet::new()),
                firewall: Mutex::new(HashSet::new()),
            }
        }
    }

    impl EbpfMapWritePort for InMemoryMapWrite {
        fn inject_threatintel_ip(
            &self,
            ip: IpAddr,
            _metadata: &IocMetadata,
        ) -> Result<(), DomainError> {
            self.threatintel.lock().unwrap().insert(ip);
            Ok(())
        }

        fn remove_threatintel_ip(&self, ip: IpAddr) -> Result<(), DomainError> {
            self.threatintel.lock().unwrap().remove(&ip);
            Ok(())
        }

        fn inject_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError> {
            self.firewall.lock().unwrap().insert(ip);
            Ok(())
        }

        fn remove_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError> {
            self.firewall.lock().unwrap().remove(&ip);
            Ok(())
        }
    }

    fn sample_metadata() -> IocMetadata {
        IocMetadata {
            source: "dns-blocklist".to_string(),
            domain: Some("malware.example.com".to_string()),
            threat_type: "blocklisted-domain".to_string(),
            confidence: 90,
        }
    }

    #[test]
    fn inject_and_remove_threatintel() {
        let mock = InMemoryMapWrite::new();
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        let meta = sample_metadata();

        mock.inject_threatintel_ip(ip, &meta).unwrap();
        assert!(mock.threatintel.lock().unwrap().contains(&ip));

        mock.remove_threatintel_ip(ip).unwrap();
        assert!(!mock.threatintel.lock().unwrap().contains(&ip));
    }

    #[test]
    fn inject_and_remove_firewall() {
        let mock = InMemoryMapWrite::new();
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();

        mock.inject_firewall_drop(ip).unwrap();
        assert!(mock.firewall.lock().unwrap().contains(&ip));

        mock.remove_firewall_drop(ip).unwrap();
        assert!(!mock.firewall.lock().unwrap().contains(&ip));
    }

    #[test]
    fn object_safe() {
        fn _check(_: &dyn EbpfMapWritePort) {}
    }
}
