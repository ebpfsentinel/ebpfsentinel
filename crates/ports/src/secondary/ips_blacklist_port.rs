use std::net::IpAddr;
use std::time::Duration;

use domain::common::error::DomainError;

/// Secondary port for IPS blacklist operations.
///
/// Used by the DNS blocklist service to inject/remove IPs from the IPS
/// blacklist when `inject_target: ips` is configured. The implementation
/// wraps `IpsAppService` with interior mutability.
pub trait IpsBlacklistPort: Send + Sync {
    /// Add an IP to the IPS blacklist with the given reason and TTL.
    fn add_to_blacklist(
        &self,
        ip: IpAddr,
        reason: String,
        ttl: Duration,
    ) -> Result<(), DomainError>;

    /// Remove an IP from the IPS blacklist.
    fn remove_from_blacklist(&self, ip: &IpAddr) -> Result<(), DomainError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct InMemoryBlacklist {
        entries: Mutex<HashMap<IpAddr, String>>,
    }

    impl InMemoryBlacklist {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }
    }

    impl IpsBlacklistPort for InMemoryBlacklist {
        fn add_to_blacklist(
            &self,
            ip: IpAddr,
            reason: String,
            _ttl: Duration,
        ) -> Result<(), DomainError> {
            self.entries.lock().unwrap().insert(ip, reason);
            Ok(())
        }

        fn remove_from_blacklist(&self, ip: &IpAddr) -> Result<(), DomainError> {
            self.entries.lock().unwrap().remove(ip);
            Ok(())
        }
    }

    #[test]
    fn add_and_remove() {
        let mock = InMemoryBlacklist::new();
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();

        mock.add_to_blacklist(ip, "test reason".to_string(), Duration::from_secs(60))
            .unwrap();
        assert!(mock.entries.lock().unwrap().contains_key(&ip));

        mock.remove_from_blacklist(&ip).unwrap();
        assert!(!mock.entries.lock().unwrap().contains_key(&ip));
    }

    #[test]
    fn add_duplicate_ok() {
        let mock = InMemoryBlacklist::new();
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();

        mock.add_to_blacklist(ip, "first".to_string(), Duration::from_secs(60))
            .unwrap();
        mock.add_to_blacklist(ip, "second".to_string(), Duration::from_secs(120))
            .unwrap();
        assert!(mock.entries.lock().unwrap().contains_key(&ip));
    }

    #[test]
    fn remove_nonexistent_ok() {
        let mock = InMemoryBlacklist::new();
        let ip = "192.168.1.1".parse::<IpAddr>().unwrap();

        mock.remove_from_blacklist(&ip).unwrap();
    }

    #[test]
    fn object_safe() {
        fn _check(_: &dyn IpsBlacklistPort) {}
    }
}
