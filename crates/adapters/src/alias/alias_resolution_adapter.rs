use domain::common::error::DomainError;
use domain::firewall::entity::IpNetwork;
use ports::secondary::alias_resolution_port::AliasResolutionPort;
use tracing::{debug, warn};

/// Adapter implementing `AliasResolutionPort` using HTTP + DNS resolution.
///
/// Handles external lookups for URL table aliases, dynamic DNS aliases.
/// `GeoIP` support requires the `maxminddb` crate (not included by default).
pub struct AliasResolutionAdapter {
    http_client: reqwest::Client,
}

impl AliasResolutionAdapter {
    /// Create a new adapter.
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("ebpfsentinel-agent/1.0")
            .build()
            .unwrap_or_default();

        Self { http_client }
    }
}

impl Default for AliasResolutionAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl AliasResolutionPort for AliasResolutionAdapter {
    fn fetch_url_table(&self, url: &str) -> Result<Vec<IpNetwork>, DomainError> {
        // Use tokio's block_in_place for sync context
        let url = url.to_string();
        let client = self.http_client.clone();

        let body = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let response = client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| DomainError::EngineError(format!("HTTP fetch failed: {e}")))?;

                if !response.status().is_success() {
                    return Err(DomainError::EngineError(format!(
                        "HTTP {} for {}",
                        response.status(),
                        url
                    )));
                }

                response
                    .text()
                    .await
                    .map_err(|e| DomainError::EngineError(format!("body read failed: {e}")))
            })
        })?;

        let mut ips = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            // Skip comments and empty lines
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Take the first whitespace-separated token (some lists have metadata after)
            let token = line.split_whitespace().next().unwrap_or(line);

            match parse_ip_network(token) {
                Some(net) => ips.push(net),
                None => {
                    debug!(line = token, "skipping unparseable line in URL table");
                }
            }
        }

        debug!(url, count = ips.len(), "URL table fetched");
        Ok(ips)
    }

    fn resolve_dns(&self, hostname: &str) -> Result<Vec<IpNetwork>, DomainError> {
        use std::net::ToSocketAddrs;

        let addr_str = format!("{hostname}:0");
        let addrs = addr_str.to_socket_addrs().map_err(|e| {
            DomainError::EngineError(format!("DNS resolution failed for {hostname}: {e}"))
        })?;

        let mut ips = Vec::new();
        for addr in addrs {
            match addr.ip() {
                std::net::IpAddr::V4(v4) => {
                    ips.push(IpNetwork::V4 {
                        addr: u32::from(v4),
                        prefix_len: 32,
                    });
                }
                std::net::IpAddr::V6(v6) => {
                    ips.push(IpNetwork::V6 {
                        addr: v6.octets(),
                        prefix_len: 128,
                    });
                }
            }
        }

        debug!(hostname, count = ips.len(), "DNS resolved");
        Ok(ips)
    }

    fn lookup_geoip(&self, country_codes: &[String]) -> Result<Vec<IpNetwork>, DomainError> {
        // GeoIP requires the maxminddb crate — not included by default.
        // Return an empty result with a warning.
        warn!(
            codes = ?country_codes,
            "GeoIP lookup requested but maxminddb is not enabled; returning empty result"
        );
        Ok(Vec::new())
    }
}

/// Parse a CIDR or bare IP into an `IpNetwork`.
fn parse_ip_network(s: &str) -> Option<IpNetwork> {
    if s.contains(':') {
        parse_ip_network_v6(s)
    } else {
        parse_ip_network_v4(s)
    }
}

fn parse_ip_network_v4(s: &str) -> Option<IpNetwork> {
    let (ip_str, prefix_len) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, prefix.parse::<u8>().ok()?),
        None => (s, 32),
    };

    if prefix_len > 32 {
        return None;
    }

    let addr: std::net::Ipv4Addr = ip_str.parse().ok()?;
    Some(IpNetwork::V4 {
        addr: u32::from(addr),
        prefix_len,
    })
}

fn parse_ip_network_v6(s: &str) -> Option<IpNetwork> {
    let (ip_str, prefix_len) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, prefix.parse::<u8>().ok()?),
        None => (s, 128),
    };

    if prefix_len > 128 {
        return None;
    }

    let addr: std::net::Ipv6Addr = ip_str.parse().ok()?;
    Some(IpNetwork::V6 {
        addr: addr.octets(),
        prefix_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_cidr() {
        let net = parse_ip_network("192.168.1.0/24").unwrap();
        match net {
            IpNetwork::V4 { prefix_len, .. } => assert_eq!(prefix_len, 24),
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn parse_ipv4_host() {
        let net = parse_ip_network("10.0.0.1").unwrap();
        match net {
            IpNetwork::V4 { prefix_len, .. } => assert_eq!(prefix_len, 32),
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn parse_ipv6_cidr() {
        let net = parse_ip_network("2001:db8::/32").unwrap();
        match net {
            IpNetwork::V6 { prefix_len, .. } => assert_eq!(prefix_len, 32),
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_ipv6_host() {
        let net = parse_ip_network("::1").unwrap();
        match net {
            IpNetwork::V6 { prefix_len, .. } => assert_eq!(prefix_len, 128),
            _ => panic!("expected V6"),
        }
    }

    #[test]
    fn parse_invalid() {
        assert!(parse_ip_network("not-an-ip").is_none());
        assert!(parse_ip_network("192.168.0.0/33").is_none());
        assert!(parse_ip_network("::1/129").is_none());
    }

    #[test]
    fn adapter_default() {
        let adapter = AliasResolutionAdapter::default();
        // Just verify it doesn't panic
        let _ = adapter;
    }
}
