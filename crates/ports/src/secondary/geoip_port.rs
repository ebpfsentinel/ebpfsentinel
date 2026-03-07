use domain::alias::entity::GeoIpInfo;
use std::net::IpAddr;

/// Port for `GeoIP` lookups.
pub trait GeoIpPort: Send + Sync {
    /// Look up `GeoIP` info for an IP address.
    fn lookup(&self, ip: &IpAddr) -> Option<GeoIpInfo>;

    /// Return true if the database is loaded and ready.
    fn is_ready(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct MockGeoIp {
        data: Mutex<HashMap<IpAddr, GeoIpInfo>>,
        ready: Mutex<bool>,
    }

    impl MockGeoIp {
        fn new(ready: bool) -> Self {
            Self {
                data: Mutex::new(HashMap::new()),
                ready: Mutex::new(ready),
            }
        }

        fn add(&self, ip: IpAddr, info: GeoIpInfo) {
            self.data.lock().unwrap().insert(ip, info);
        }
    }

    impl GeoIpPort for MockGeoIp {
        fn lookup(&self, ip: &IpAddr) -> Option<GeoIpInfo> {
            self.data.lock().unwrap().get(ip).cloned()
        }

        fn is_ready(&self) -> bool {
            *self.ready.lock().unwrap()
        }
    }

    #[test]
    fn lookup_returns_info() {
        let geo = MockGeoIp::new(true);
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        geo.add(
            ip,
            GeoIpInfo {
                country_code: Some("US".to_string()),
                country_name: Some("United States".to_string()),
                city: Some("Mountain View".to_string()),
                asn: Some(15169),
                as_org: Some("Google LLC".to_string()),
                latitude: Some(37.386),
                longitude: Some(-122.084),
            },
        );

        let info = geo.lookup(&ip).unwrap();
        assert_eq!(info.country_code, Some("US".to_string()));
        assert_eq!(info.asn, Some(15169));

        let unknown: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(geo.lookup(&unknown).is_none());
    }

    #[test]
    fn is_ready_reflects_state() {
        let geo_ready = MockGeoIp::new(true);
        assert!(geo_ready.is_ready());

        let geo_not_ready = MockGeoIp::new(false);
        assert!(!geo_not_ready.is_ready());
    }

    #[test]
    fn object_safe() {
        fn _check(_: &dyn GeoIpPort) {}
    }
}
