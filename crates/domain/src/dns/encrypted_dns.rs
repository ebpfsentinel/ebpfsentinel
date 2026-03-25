use serde::{Deserialize, Serialize};

/// Protocol type for encrypted DNS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptedDnsProtocol {
    /// DNS over HTTPS (port 443, SNI match).
    Doh,
    /// DNS over TLS (port 853).
    Dot,
}

/// Result of encrypted DNS detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDnsDetection {
    pub protocol: EncryptedDnsProtocol,
    pub resolver: String,
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub dst_port: u16,
}

/// Built-in list of known `DoH` resolver SNI domains.
const KNOWN_DOH_RESOLVERS: &[&str] = &[
    // Google
    "dns.google",
    "dns.google.com",
    // Cloudflare
    "cloudflare-dns.com",
    "one.one.one.one",
    // Quad9
    "dns.quad9.net",
    // OpenDNS / Cisco
    "doh.opendns.com",
    // AdGuard
    "dns.adguard.com",
    "dns.adguard-dns.com",
    // Mullvad
    "doh.mullvad.net",
    // NextDNS
    "dns.nextdns.io",
    // CleanBrowsing
    "doh.cleanbrowsing.org",
    // Comcast
    "doh.xfinity.com",
    // Mozilla / Firefox
    "mozilla.cloudflare-dns.com",
    "use-application-dns.net",
    // ControlD
    "freedns.controld.com",
    // Wikimedia
    "wikimedia-dns.org",
    // LibreDNS
    "doh.libredns.gr",
    // Tiar
    "doh.tiar.app",
    "doh.tiarap.org",
    // DNS.SB
    "doh.dns.sb",
    // Applied Privacy
    "doh.applied-privacy.net",
    // CIRA Canadian Shield
    "private.canadianshield.cira.ca",
    "protected.canadianshield.cira.ca",
    // Switch (Swiss)
    "dns.switch.ch",
    // Digitale Gesellschaft
    "dns.digitale-gesellschaft.ch",
    // Foundation for Applied Privacy
    "doh.ffmuc.net",
    // BlahDNS
    "doh-jp.blahdns.com",
    "doh-de.blahdns.com",
    // Snopyta (RIP but still in some lists)
    "fi.doh.dns.snopyta.org",
];

/// `DoT` standard port.
const DOT_PORT: u16 = 853;

/// Detector for encrypted DNS traffic (`DoH`/`DoT`).
#[derive(Clone)]
pub struct EncryptedDnsDetector {
    doh_domains: Vec<String>,
}

impl EncryptedDnsDetector {
    /// Create a detector with the built-in `DoH` resolver list.
    pub fn new() -> Self {
        Self {
            doh_domains: KNOWN_DOH_RESOLVERS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
        }
    }

    /// Add custom `DoH` resolver domains from config.
    pub fn add_custom_resolvers(&mut self, resolvers: &[String]) {
        for r in resolvers {
            let lower = r.to_lowercase();
            if !self.doh_domains.contains(&lower) {
                self.doh_domains.push(lower);
            }
        }
    }

    /// Check if a TLS connection to the given SNI + port is encrypted DNS.
    pub fn detect(
        &self,
        sni: Option<&str>,
        dst_port: u16,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
    ) -> Option<EncryptedDnsDetection> {
        // DoT: port 853
        if dst_port == DOT_PORT {
            return Some(EncryptedDnsDetection {
                protocol: EncryptedDnsProtocol::Dot,
                resolver: sni.unwrap_or("unknown").to_string(),
                src_addr,
                dst_addr,
                dst_port,
            });
        }

        // DoH: SNI matches known resolver
        if let Some(sni_val) = sni {
            let sni_lower = sni_val.to_lowercase();
            if self
                .doh_domains
                .iter()
                .any(|d| sni_lower == *d || sni_lower.ends_with(&format!(".{d}")))
            {
                return Some(EncryptedDnsDetection {
                    protocol: EncryptedDnsProtocol::Doh,
                    resolver: sni_val.to_string(),
                    src_addr,
                    dst_addr,
                    dst_port,
                });
            }
        }

        None
    }

    /// Number of known `DoH` resolver domains.
    pub fn resolver_count(&self) -> usize {
        self.doh_domains.len()
    }
}

impl Default for EncryptedDnsDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_dot_by_port() {
        let detector = EncryptedDnsDetector::new();
        let result = detector.detect(Some("dns.google"), DOT_PORT, [1, 0, 0, 0], [2, 0, 0, 0]);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.protocol, EncryptedDnsProtocol::Dot);
        assert_eq!(d.resolver, "dns.google");
    }

    #[test]
    fn detect_doh_by_sni() {
        let detector = EncryptedDnsDetector::new();
        let result = detector.detect(Some("cloudflare-dns.com"), 443, [1, 0, 0, 0], [2, 0, 0, 0]);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.protocol, EncryptedDnsProtocol::Doh);
        assert_eq!(d.resolver, "cloudflare-dns.com");
    }

    #[test]
    fn no_detection_for_normal_https() {
        let detector = EncryptedDnsDetector::new();
        let result = detector.detect(Some("www.example.com"), 443, [1, 0, 0, 0], [2, 0, 0, 0]);
        assert!(result.is_none());
    }

    #[test]
    fn detect_doh_case_insensitive() {
        let detector = EncryptedDnsDetector::new();
        let result = detector.detect(Some("DNS.Google"), 443, [1, 0, 0, 0], [2, 0, 0, 0]);
        assert!(result.is_some());
    }

    #[test]
    fn detect_doh_subdomain() {
        let detector = EncryptedDnsDetector::new();
        let result = detector.detect(
            Some("abc123.dns.nextdns.io"),
            443,
            [1, 0, 0, 0],
            [2, 0, 0, 0],
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap().protocol, EncryptedDnsProtocol::Doh);
    }

    #[test]
    fn custom_resolver_added() {
        let mut detector = EncryptedDnsDetector::new();
        detector.add_custom_resolvers(&["corp-doh.internal.local".to_string()]);
        let result = detector.detect(
            Some("corp-doh.internal.local"),
            443,
            [1, 0, 0, 0],
            [2, 0, 0, 0],
        );
        assert!(result.is_some());
    }

    #[test]
    fn resolver_count_includes_builtins() {
        let detector = EncryptedDnsDetector::new();
        assert!(detector.resolver_count() >= 25);
    }

    #[test]
    fn dot_port_853_no_sni() {
        let detector = EncryptedDnsDetector::new();
        let result = detector.detect(None, DOT_PORT, [1, 0, 0, 0], [2, 0, 0, 0]);
        assert!(result.is_some());
        let d = result.unwrap();
        assert_eq!(d.protocol, EncryptedDnsProtocol::Dot);
        assert_eq!(d.resolver, "unknown");
    }
}
