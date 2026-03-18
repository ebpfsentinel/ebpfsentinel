use serde::{Deserialize, Serialize};

use crate::alert::mitre::{self, MitreAttackInfo, MitreContext};
use crate::common::entity::{DomainMode, RuleId, Severity};
use crate::ddos::entity::DdosAttack;
use crate::dlp::entity::DlpAlert;
use crate::dns::entity::{DnsAlert, DnsAlertReason};
use crate::ids::entity::IdsAlert;
use crate::threatintel::entity::ThreatIntelAlert;

/// Component type for packet-level security alerts (firewall, ratelimit, L7, IPS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketAlertComponent {
    Firewall,
    Ratelimit,
    L7,
    Ips,
}

/// A security alert from a packet-level enforcement decision.
///
/// Shared by firewall (deny/reject), rate limiting (drop), L7 content
/// filtering (deny/reject), and IPS auto-blacklisting.
#[derive(Debug, Clone)]
pub struct PacketSecurityAlert {
    pub component: PacketAlertComponent,
    pub src_addr: [u32; 4],
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub is_ipv6: bool,
    pub timestamp_ns: u64,
    pub rule_id: String,
    pub action_label: String,
    pub severity: Severity,
    pub detail: String,
}

/// Full-context alert with all FR30 fields.
///
/// Contains complete packet context (IPs, ports, protocol), matched rule
/// metadata, severity, action taken, and a human-readable message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub timestamp_ns: u64,
    pub component: String,
    pub severity: Severity,
    pub rule_id: RuleId,
    pub action: DomainMode,
    /// Source address: `[v4, 0, 0, 0]` for IPv4, full 128-bit for IPv6.
    pub src_addr: [u32; 4],
    /// Destination address: same encoding as `src_addr`.
    pub dst_addr: [u32; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// `true` if the addresses are IPv6.
    pub is_ipv6: bool,
    pub message: String,
    /// Whether this alert has been marked as a false positive by an operator.
    #[serde(default)]
    pub false_positive: bool,
    /// Reverse-DNS domain for source IP (enriched from DNS cache).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_domain: Option<String>,
    /// Reverse-DNS domain for destination IP (enriched from DNS cache).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_domain: Option<String>,
    /// Reputation score for source domain (0.0=clean, 1.0=malicious).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_domain_score: Option<f64>,
    /// Reputation score for destination domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_domain_score: Option<f64>,
    /// `GeoIP` location for source IP (e.g. "US/New York (ASN: AS15169 Google)").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_geo: Option<String>,
    /// `GeoIP` location for destination IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_geo: Option<String>,

    // ── Domain-specific context (populated based on component) ───
    /// Threat intel: IOC confidence score (0-100).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<u8>,
    /// Threat intel: threat category (malware, c2, scanner, spam, other).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threat_type: Option<String>,
    /// DLP: data category (pci, pii, credentials, custom).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    /// DLP: process ID that triggered the alert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// DLP: thread group ID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tgid: Option<u32>,
    /// DLP: direction (0=write, 1=read).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<u8>,
    /// IDS: matched domain name for domain-aware rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_domain: Option<String>,
    /// `DDoS`: attack type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attack_type: Option<String>,
    /// `DDoS`: peak packets per second observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_pps: Option<u64>,
    /// `DDoS`: current smoothed packets per second (EWMA).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_pps: Option<u64>,
    /// `DDoS`: mitigation status (detecting, active, mitigated, expired).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitigation_status: Option<String>,
    /// `DDoS`: total packets in attack.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_packets: Option<u64>,
    /// MITRE ATT&CK technique mapping for this alert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mitre_attack: Option<MitreAttackInfo>,
    /// JA4 TLS `ClientHello` fingerprint (enriched from L7 cache).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ja4_fingerprint: Option<String>,
}

impl Alert {
    /// Create a domain alert from an IDS alert with a human-readable description.
    pub fn from_ids_alert(ids: &IdsAlert, description: &str) -> Self {
        Self {
            id: Self::generate_id(ids.timestamp_ns, &ids.rule_id),
            timestamp_ns: ids.timestamp_ns,
            component: "ids".to_string(),
            severity: ids.severity,
            rule_id: ids.rule_id.clone(),
            action: ids.mode,
            src_addr: ids.src_addr,
            dst_addr: ids.dst_addr,
            src_port: ids.src_port,
            dst_port: ids.dst_port,
            protocol: ids.protocol,
            is_ipv6: ids.is_ipv6,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: ids.matched_domain.clone(),
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: Some(mitre::lookup(&MitreContext::Ids)),
            ja4_fingerprint: None,
        }
    }

    /// Create a domain alert from a DLP alert with a human-readable description.
    /// DLP events are process-level (pid/tgid), not network-level, so IP/port
    /// fields are zeroed.
    pub fn from_dlp_alert(dlp: &DlpAlert, description: &str) -> Self {
        Self {
            id: Self::generate_id(dlp.timestamp_ns, &dlp.pattern_id),
            timestamp_ns: dlp.timestamp_ns,
            component: "dlp".to_string(),
            severity: dlp.severity,
            rule_id: dlp.pattern_id.clone(),
            action: dlp.mode,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: Some(dlp.data_type.clone()),
            pid: Some(dlp.pid),
            tgid: Some(dlp.tgid),
            direction: Some(dlp.direction),
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: Some(mitre::lookup(&MitreContext::Dlp(&dlp.data_type))),
            ja4_fingerprint: None,
        }
    }

    /// Create a domain alert from a threat intelligence match.
    pub fn from_threatintel_alert(ti: &ThreatIntelAlert, description: &str) -> Self {
        Self {
            id: Self::generate_id(ti.timestamp_ns, &RuleId(ti.feed_id.clone())),
            timestamp_ns: ti.timestamp_ns,
            component: "threatintel".to_string(),
            severity: Severity::High, // IOC matches are high-severity by default
            rule_id: RuleId(ti.feed_id.clone()),
            action: ti.mode,
            src_addr: ti.src_addr,
            dst_addr: ti.dst_addr,
            src_port: ti.src_port,
            dst_port: ti.dst_port,
            protocol: ti.protocol,
            is_ipv6: ti.is_ipv6,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: Some(ti.confidence),
            threat_type: Some(ti.threat_type.to_string()),
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: Some(mitre::lookup(&MitreContext::ThreatIntel(ti.threat_type))),
            ja4_fingerprint: None,
        }
    }

    /// Create a domain alert from a `DDoS` attack state change.
    #[allow(clippy::too_many_arguments)]
    pub fn from_ddos_attack(
        attack: &DdosAttack,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        is_ipv6: bool,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        description: &str,
    ) -> Self {
        let severity = match attack.attack_type.severity() {
            crate::ddos::entity::DdosSeverity::Medium => Severity::Medium,
            crate::ddos::entity::DdosSeverity::High => Severity::High,
            crate::ddos::entity::DdosSeverity::Critical => Severity::Critical,
        };
        Self {
            id: Self::generate_id(attack.last_seen_ns, &RuleId(attack.id.clone())),
            timestamp_ns: attack.last_seen_ns,
            component: "ddos".to_string(),
            severity,
            rule_id: RuleId(attack.id.clone()),
            action: DomainMode::Block,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            is_ipv6,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: Some(format!("{:?}", attack.attack_type)),
            peak_pps: Some(attack.peak_pps),
            current_pps: Some(attack.current_pps),
            mitigation_status: Some(format!("{:?}", attack.mitigation_status)),
            total_packets: Some(attack.total_packets),
            mitre_attack: Some(mitre::lookup(&MitreContext::Ddos(attack.attack_type))),
            ja4_fingerprint: None,
        }
    }

    /// Create a domain alert from a DNS security event (blocklist, reputation, encrypted DNS).
    pub fn from_dns_alert(dns: &DnsAlert, description: &str) -> Self {
        let mitre_context = match &dns.reason {
            DnsAlertReason::Blocklist { .. } | DnsAlertReason::EncryptedDns { .. } => {
                MitreContext::Dns(mitre::DnsMitreReason::BlocklistOrEncrypted)
            }
            DnsAlertReason::Reputation { .. } => {
                MitreContext::Dns(mitre::DnsMitreReason::Reputation)
            }
        };
        let rule_id = match &dns.reason {
            DnsAlertReason::Blocklist { pattern } => RuleId(format!("dns-blocklist:{pattern}")),
            DnsAlertReason::Reputation { score } => RuleId(format!("dns-reputation:{score:.2}")),
            DnsAlertReason::EncryptedDns { protocol, resolver } => {
                RuleId(format!("dns-encrypted:{protocol}:{resolver}"))
            }
        };
        Self {
            id: Self::generate_id(dns.timestamp_ns, &rule_id),
            timestamp_ns: dns.timestamp_ns,
            component: "dns".to_string(),
            severity: dns.severity,
            rule_id,
            action: DomainMode::Alert,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message: description.to_string(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: Some(dns.domain.clone()),
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: Some(mitre::lookup(&mitre_context)),
            ja4_fingerprint: None,
        }
    }

    /// Create an alert from a packet-level security event (firewall, ratelimit, L7, IPS).
    pub fn from_packet_security_alert(psa: &PacketSecurityAlert) -> Self {
        let component_str = match psa.component {
            PacketAlertComponent::Firewall => "firewall",
            PacketAlertComponent::Ratelimit => "ratelimit",
            PacketAlertComponent::L7 => "l7",
            PacketAlertComponent::Ips => "ips",
        };
        let mode = match psa.action_label.as_str() {
            "drop" | "deny" | "reject" | "blacklist" => DomainMode::Block,
            _ => DomainMode::Alert,
        };
        let rule_id = RuleId(psa.rule_id.clone());
        let mitre_context = match psa.component {
            PacketAlertComponent::Firewall => {
                MitreContext::PacketSecurity(mitre::PacketSecurityMitreReason::Firewall)
            }
            PacketAlertComponent::Ratelimit => {
                MitreContext::PacketSecurity(mitre::PacketSecurityMitreReason::Ratelimit)
            }
            PacketAlertComponent::L7 => {
                MitreContext::PacketSecurity(mitre::PacketSecurityMitreReason::L7)
            }
            PacketAlertComponent::Ips => {
                MitreContext::PacketSecurity(mitre::PacketSecurityMitreReason::Ips)
            }
        };
        Self {
            id: Self::generate_id(psa.timestamp_ns, &rule_id),
            timestamp_ns: psa.timestamp_ns,
            component: component_str.to_string(),
            severity: psa.severity,
            rule_id,
            action: mode,
            src_addr: psa.src_addr,
            dst_addr: psa.dst_addr,
            src_port: psa.src_port,
            dst_port: psa.dst_port,
            protocol: psa.protocol,
            is_ipv6: psa.is_ipv6,
            message: psa.detail.clone(),
            false_positive: false,
            src_domain: None,
            dst_domain: None,
            src_domain_score: None,
            dst_domain_score: None,
            src_geo: None,
            dst_geo: None,
            confidence: None,
            threat_type: None,
            data_type: None,
            pid: None,
            tgid: None,
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: Some(mitre::lookup(&mitre_context)),
            ja4_fingerprint: None,
        }
    }

    /// Returns the source IPv4 address (first element of `src_addr`).
    pub fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Returns the destination IPv4 address (first element of `dst_addr`).
    pub fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }

    /// Generate a simple unique ID from timestamp and rule ID.
    fn generate_id(timestamp_ns: u64, rule_id: &RuleId) -> String {
        format!("{timestamp_ns}-{rule_id}")
    }
}

/// Routing destination for an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertDestination {
    Email { to: String },
    Webhook { url: String },
    Otlp,
    Log,
}

/// A route that determines which alerts go to which destination,
/// filtered by minimum severity and optional event type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertRoute {
    pub name: String,
    pub destination: AlertDestination,
    pub min_severity: Severity,
    /// If `None`, matches all component types. If `Some`, only routes alerts
    /// whose `component` field is in the list (e.g. `["ids"]`).
    pub event_types: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::entity::DomainMode;

    fn sample_dlp_alert() -> DlpAlert {
        DlpAlert {
            pattern_id: RuleId("dlp-pci-visa".to_string()),
            pattern_name: "Visa Card Number".to_string(),
            severity: Severity::Critical,
            mode: DomainMode::Alert,
            data_type: "pci".to_string(),
            pid: 1234,
            tgid: 5678,
            direction: 0,
            redacted_excerpt: "[REDACTED:pci]".to_string(),
            timestamp_ns: 2_000_000_000,
        }
    }

    fn sample_ids_alert() -> IdsAlert {
        IdsAlert {
            rule_id: RuleId("ids-001".to_string()),
            severity: Severity::High,
            mode: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 22,
            protocol: 6,
            is_ipv6: false,
            rule_index: 0,
            timestamp_ns: 1_000_000_000,
            matched_domain: None,
        }
    }

    #[test]
    fn alert_from_ids_alert_maps_all_fields() {
        let ids = sample_ids_alert();
        let alert = Alert::from_ids_alert(&ids, "SSH bruteforce detected");

        assert_eq!(alert.component, "ids");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.rule_id.0, "ids-001");
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0xC0A8_0001);
        assert_eq!(alert.dst_ip(), 0x0A00_0001);
        assert_eq!(alert.src_port, 12345);
        assert_eq!(alert.dst_port, 22);
        assert_eq!(alert.protocol, 6);
        assert!(!alert.is_ipv6);
        assert_eq!(alert.timestamp_ns, 1_000_000_000);
        assert_eq!(alert.message, "SSH bruteforce detected");
        assert!(alert.id.contains("ids-001"));
    }

    #[test]
    fn alert_from_ids_alert_block_mode() {
        let mut ids = sample_ids_alert();
        ids.mode = DomainMode::Block;
        ids.severity = Severity::Critical;
        let alert = Alert::from_ids_alert(&ids, "Critical threat blocked");

        assert_eq!(alert.action, DomainMode::Block);
        assert_eq!(alert.severity, Severity::Critical);
    }

    #[test]
    fn alert_route_with_event_types_filter() {
        let route = AlertRoute {
            name: "ids-only".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::High,
            event_types: Some(vec!["ids".to_string()]),
        };
        assert_eq!(route.event_types.as_ref().unwrap().len(), 1);
        assert_eq!(route.event_types.as_ref().unwrap()[0], "ids");
    }

    #[test]
    fn alert_route_without_event_types_matches_all() {
        let route = AlertRoute {
            name: "all-alerts".to_string(),
            destination: AlertDestination::Log,
            min_severity: Severity::Low,
            event_types: None,
        };
        assert!(route.event_types.is_none());
    }

    // ── DLP Alert tests ──────────────────────────────────────────

    #[test]
    fn alert_from_dlp_alert_maps_all_fields() {
        let dlp = sample_dlp_alert();
        let alert = Alert::from_dlp_alert(&dlp, "Visa card detected in SSL traffic");

        assert_eq!(alert.component, "dlp");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.rule_id.0, "dlp-pci-visa");
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0);
        assert_eq!(alert.dst_ip(), 0);
        assert!(!alert.is_ipv6);
        assert_eq!(alert.src_port, 0);
        assert_eq!(alert.dst_port, 0);
        assert_eq!(alert.protocol, 0);
        assert_eq!(alert.timestamp_ns, 2_000_000_000);
        assert_eq!(alert.message, "Visa card detected in SSL traffic");
        assert!(alert.id.contains("dlp-pci-visa"));
    }

    #[test]
    fn alert_from_dlp_alert_block_mode() {
        let mut dlp = sample_dlp_alert();
        dlp.mode = DomainMode::Block;
        let alert = Alert::from_dlp_alert(&dlp, "Blocked");

        assert_eq!(alert.action, DomainMode::Block);
    }

    // ── Threat Intel Alert tests ──────────────────────────────────

    fn sample_ti_alert() -> ThreatIntelAlert {
        use crate::threatintel::entity::ThreatType;
        ThreatIntelAlert {
            feed_id: "alienvault-otx".to_string(),
            confidence: 90,
            threat_type: ThreatType::C2,
            mode: DomainMode::Alert,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 12345,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            timestamp_ns: 3_000_000_000,
        }
    }

    #[test]
    fn alert_from_threatintel_maps_all_fields() {
        let ti = sample_ti_alert();
        let alert = Alert::from_threatintel_alert(&ti, "C2 callback detected to known IOC");

        assert_eq!(alert.component, "threatintel");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.rule_id.0, "alienvault-otx");
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.src_ip(), 0xC0A8_0001);
        assert_eq!(alert.dst_ip(), 0x0A00_0001);
        assert_eq!(alert.src_port, 12345);
        assert_eq!(alert.dst_port, 443);
        assert_eq!(alert.protocol, 6);
        assert_eq!(alert.timestamp_ns, 3_000_000_000);
        assert!(alert.id.contains("alienvault-otx"));
    }

    #[test]
    fn alert_from_threatintel_block_mode() {
        let mut ti = sample_ti_alert();
        ti.mode = DomainMode::Block;
        let alert = Alert::from_threatintel_alert(&ti, "Blocked");
        assert_eq!(alert.action, DomainMode::Block);
    }

    // ── DNS Alert tests ──────────────────────────────────────────────

    fn sample_dns_blocklist_alert() -> crate::dns::entity::DnsAlert {
        crate::dns::entity::DnsAlert {
            domain: "evil.com".to_string(),
            resolved_ips: vec!["1.2.3.4".parse().unwrap()],
            reason: DnsAlertReason::Blocklist {
                pattern: "evil.com".to_string(),
            },
            severity: Severity::High,
            timestamp_ns: 4_000_000_000,
        }
    }

    #[test]
    fn alert_from_dns_alert_blocklist() {
        let dns = sample_dns_blocklist_alert();
        let alert = Alert::from_dns_alert(&dns, "DNS blocklist match: evil.com");

        assert_eq!(alert.component, "dns");
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.action, DomainMode::Alert);
        assert_eq!(alert.matched_domain, Some("evil.com".to_string()));
        assert_eq!(alert.timestamp_ns, 4_000_000_000);
        assert!(alert.rule_id.0.contains("dns-blocklist:evil.com"));
        assert!(alert.mitre_attack.is_some());
        assert_eq!(
            alert.mitre_attack.as_ref().unwrap().technique_id,
            "T1071.004"
        );
    }

    #[test]
    fn alert_from_dns_alert_reputation() {
        let dns = crate::dns::entity::DnsAlert {
            domain: "suspicious.com".to_string(),
            resolved_ips: vec![],
            reason: DnsAlertReason::Reputation { score: 0.92 },
            severity: Severity::High,
            timestamp_ns: 5_000_000_000,
        };
        let alert = Alert::from_dns_alert(&dns, "reputation auto-block");

        assert_eq!(alert.component, "dns");
        assert_eq!(alert.matched_domain, Some("suspicious.com".to_string()));
        assert!(alert.rule_id.0.contains("dns-reputation:0.92"));
        assert_eq!(alert.mitre_attack.as_ref().unwrap().technique_id, "T1568");
    }

    #[test]
    fn alert_from_dns_alert_encrypted_dns() {
        let dns = crate::dns::entity::DnsAlert {
            domain: "dns.google".to_string(),
            resolved_ips: vec![],
            reason: DnsAlertReason::EncryptedDns {
                protocol: "doh".to_string(),
                resolver: "dns.google".to_string(),
            },
            severity: Severity::Medium,
            timestamp_ns: 6_000_000_000,
        };
        let alert = Alert::from_dns_alert(&dns, "encrypted DNS detected");

        assert_eq!(alert.component, "dns");
        assert_eq!(alert.severity, Severity::Medium);
        assert!(alert.rule_id.0.contains("dns-encrypted:doh:dns.google"));
        assert_eq!(
            alert.mitre_attack.as_ref().unwrap().technique_id,
            "T1071.004"
        );
    }

    // ── Packet Security Alert tests ──────────────────────────────────

    fn sample_psa(component: PacketAlertComponent, action: &str) -> PacketSecurityAlert {
        PacketSecurityAlert {
            component,
            src_addr: [0xC0A8_0001, 0, 0, 0],
            dst_addr: [0x0A00_0001, 0, 0, 0],
            src_port: 54321,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            timestamp_ns: 7_000_000_000,
            rule_id: "test-rule".to_string(),
            action_label: action.to_string(),
            severity: Severity::Medium,
            detail: "test detail".to_string(),
        }
    }

    #[test]
    fn alert_from_firewall_psa() {
        let psa = sample_psa(PacketAlertComponent::Firewall, "deny");
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "firewall");
        assert_eq!(alert.severity, Severity::Medium);
        assert_eq!(alert.action, DomainMode::Block);
        assert_eq!(alert.src_ip(), 0xC0A8_0001);
        assert_eq!(alert.dst_ip(), 0x0A00_0001);
        assert_eq!(alert.src_port, 54321);
        assert_eq!(alert.dst_port, 443);
        assert_eq!(alert.protocol, 6);
        assert_eq!(alert.mitre_attack.as_ref().unwrap().technique_id, "T1190");
    }

    #[test]
    fn alert_from_ratelimit_psa() {
        let psa = sample_psa(PacketAlertComponent::Ratelimit, "drop");
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "ratelimit");
        assert_eq!(alert.action, DomainMode::Block);
        assert_eq!(alert.mitre_attack.as_ref().unwrap().technique_id, "T1498");
    }

    #[test]
    fn alert_from_l7_psa() {
        let psa = sample_psa(PacketAlertComponent::L7, "reject");
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "l7");
        assert_eq!(alert.action, DomainMode::Block);
        assert_eq!(alert.mitre_attack.as_ref().unwrap().technique_id, "T1071");
    }

    #[test]
    fn alert_from_ips_psa() {
        let psa = sample_psa(PacketAlertComponent::Ips, "blacklist");
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "ips");
        assert_eq!(alert.action, DomainMode::Block);
        assert_eq!(alert.mitre_attack.as_ref().unwrap().technique_id, "T1110");
    }
}
