use serde::{Deserialize, Serialize};

use crate::ddos::entity::DdosAttackType;
use crate::threatintel::entity::ThreatType;

/// MITRE ATT&CK framework version used for technique mappings.
pub const MITRE_ATTACK_VERSION: &str = "v18";

/// MITRE ATT&CK technique metadata attached to every alert.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MitreAttackInfo {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

/// Sub-reason for packet-level security MITRE mapping.
pub enum PacketSecurityMitreReason {
    Firewall,
    Ratelimit,
    L7,
    Ips,
}

/// Sub-reason for DNS MITRE mapping.
pub enum DnsMitreReason {
    /// Blocklist match or encrypted DNS detection.
    BlocklistOrEncrypted,
    /// Reputation-based auto-block.
    Reputation,
}

/// Context passed to [`lookup`] to select the correct ATT&CK technique.
pub enum MitreContext<'a> {
    Ids,
    ThreatIntel(ThreatType),
    Dlp(&'a str),
    Ddos(DdosAttackType),
    Dns(DnsMitreReason),
    PacketSecurity(PacketSecurityMitreReason),
}

/// Return the ATT&CK technique for the given alert context.
///
/// The mapping is static and zero-heap in the registry itself — every
/// returned [`MitreAttackInfo`] is built from `&'static str` literals.
pub fn lookup(ctx: &MitreContext<'_>) -> MitreAttackInfo {
    match ctx {
        MitreContext::Ids => info("T1071", "Application Layer Protocol", "command-and-control"),

        MitreContext::ThreatIntel(tt) => match tt {
            ThreatType::Malware | ThreatType::C2 => {
                info("T1071.001", "Web Protocols", "command-and-control")
            }
            ThreatType::Scanner => info("T1595", "Active Scanning", "reconnaissance"),
            ThreatType::Spam => info("T1566", "Phishing", "initial-access"),
            ThreatType::Other => info("T1568", "Dynamic Resolution", "command-and-control"),
        },

        MitreContext::Dlp(data_type) => match *data_type {
            "pii" => info(
                "T1048",
                "Exfiltration Over Alternative Protocol",
                "exfiltration",
            ),
            "credentials" => info(
                "T1048.003",
                "Exfiltration Over Unencrypted Non-C2 Protocol",
                "exfiltration",
            ),
            // "pci" and all other data types default to T1041
            _ => info("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
        },

        MitreContext::PacketSecurity(reason) => match reason {
            PacketSecurityMitreReason::Firewall => info(
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
            ),
            PacketSecurityMitreReason::Ratelimit => {
                info("T1498", "Network Denial of Service", "impact")
            }
            PacketSecurityMitreReason::L7 => {
                info("T1071", "Application Layer Protocol", "command-and-control")
            }
            PacketSecurityMitreReason::Ips => info("T1110", "Brute Force", "credential-access"),
        },

        MitreContext::Dns(reason) => match reason {
            DnsMitreReason::BlocklistOrEncrypted => info("T1071.004", "DNS", "command-and-control"),
            DnsMitreReason::Reputation => {
                info("T1568", "Dynamic Resolution", "command-and-control")
            }
        },

        MitreContext::Ddos(attack_type) => match attack_type {
            DdosAttackType::SynFlood => info("T1499.001", "OS Exhaustion Flood", "impact"),
            DdosAttackType::UdpAmplification => {
                info("T1498.002", "Reflection Amplification", "impact")
            }
            DdosAttackType::IcmpFlood => info("T1498", "Network Denial of Service", "impact"),
            DdosAttackType::RstFlood | DdosAttackType::FinFlood | DdosAttackType::AckFlood => {
                info("T1499", "Endpoint Denial of Service", "impact")
            }
            DdosAttackType::Volumetric => info("T1498.001", "Direct Network Flood", "impact"),
        },
    }
}

/// A single entry in the coverage matrix.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoverageEntry {
    pub component: String,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    /// Human-readable description of what triggers this mapping.
    pub description: String,
}

/// Per-tactic coverage summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TacticCoverage {
    pub tactic: String,
    pub covered_techniques: usize,
    pub components: Vec<String>,
}

/// Full MITRE ATT&CK coverage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub attack_version: String,
    pub total_techniques: usize,
    pub techniques: Vec<CoverageEntry>,
    pub by_tactic: Vec<TacticCoverage>,
}

/// Static coverage table — all technique mappings the agent can produce.
fn all_coverage_entries() -> Vec<CoverageEntry> {
    let mut entries = Vec::with_capacity(19);
    entries.extend(packet_security_coverage_entries());
    entries.extend(detection_coverage_entries());
    entries.extend(ddos_coverage_entries());
    entries
}

fn packet_security_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "firewall",
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
            "Firewall deny/reject",
        ),
        entry(
            "ratelimit",
            "T1498",
            "Network Denial of Service",
            "impact",
            "Rate limit exceeded",
        ),
        entry(
            "l7",
            "T1071",
            "Application Layer Protocol",
            "command-and-control",
            "L7 content-based deny",
        ),
        entry(
            "ips",
            "T1110",
            "Brute Force",
            "credential-access",
            "IPS auto-blacklist threshold",
        ),
    ]
}

fn detection_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "ids",
            "T1071",
            "Application Layer Protocol",
            "command-and-control",
            "IDS signature match",
        ),
        entry(
            "threatintel",
            "T1071.001",
            "Web Protocols",
            "command-and-control",
            "IOC hit: malware or C2",
        ),
        entry(
            "threatintel",
            "T1595",
            "Active Scanning",
            "reconnaissance",
            "IOC hit: scanner",
        ),
        entry(
            "threatintel",
            "T1566",
            "Phishing",
            "initial-access",
            "IOC hit: spam source",
        ),
        entry(
            "threatintel",
            "T1568",
            "Dynamic Resolution",
            "command-and-control",
            "IOC hit: other threat type",
        ),
        entry(
            "dlp",
            "T1041",
            "Exfiltration Over C2 Channel",
            "exfiltration",
            "DLP match: PCI or generic",
        ),
        entry(
            "dlp",
            "T1048",
            "Exfiltration Over Alternative Protocol",
            "exfiltration",
            "DLP match: PII",
        ),
        entry(
            "dlp",
            "T1048.003",
            "Exfiltration Over Unencrypted Non-C2 Protocol",
            "exfiltration",
            "DLP match: credentials",
        ),
        entry(
            "dns",
            "T1071.004",
            "DNS",
            "command-and-control",
            "DNS blocklist match or encrypted DNS detection",
        ),
        entry(
            "dns",
            "T1568",
            "Dynamic Resolution",
            "command-and-control",
            "DNS reputation auto-block",
        ),
    ]
}

fn ddos_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "ddos",
            "T1499.001",
            "OS Exhaustion Flood",
            "impact",
            "SYN flood detected",
        ),
        entry(
            "ddos",
            "T1498.002",
            "Reflection Amplification",
            "impact",
            "UDP amplification detected",
        ),
        entry(
            "ddos",
            "T1498",
            "Network Denial of Service",
            "impact",
            "ICMP flood detected",
        ),
        entry(
            "ddos",
            "T1499",
            "Endpoint Denial of Service",
            "impact",
            "RST/FIN/ACK flood detected",
        ),
        entry(
            "ddos",
            "T1498.001",
            "Direct Network Flood",
            "impact",
            "Volumetric attack detected",
        ),
    ]
}

/// Build a coverage report filtered to the given active components.
pub fn coverage_report(active_components: &[&str]) -> CoverageReport {
    let all = all_coverage_entries();
    let techniques: Vec<CoverageEntry> = all
        .into_iter()
        .filter(|e| {
            active_components
                .iter()
                .any(|c| e.component.eq_ignore_ascii_case(c))
        })
        .collect();

    // Group by tactic
    let mut tactic_map: std::collections::BTreeMap<String, (usize, Vec<String>)> =
        std::collections::BTreeMap::new();
    for t in &techniques {
        let entry = tactic_map
            .entry(t.tactic.clone())
            .or_insert_with(|| (0, Vec::new()));
        entry.0 += 1;
        if !entry.1.contains(&t.component) {
            entry.1.push(t.component.clone());
        }
    }

    let by_tactic: Vec<TacticCoverage> = tactic_map
        .into_iter()
        .map(|(tactic, (count, components))| TacticCoverage {
            tactic,
            covered_techniques: count,
            components,
        })
        .collect();

    let total = techniques.len();
    CoverageReport {
        attack_version: MITRE_ATTACK_VERSION.to_string(),
        total_techniques: total,
        techniques,
        by_tactic,
    }
}

fn entry(
    component: &'static str,
    id: &'static str,
    name: &'static str,
    tactic: &'static str,
    description: &'static str,
) -> CoverageEntry {
    CoverageEntry {
        component: component.to_string(),
        technique_id: id.to_string(),
        technique_name: name.to_string(),
        tactic: tactic.to_string(),
        description: description.to_string(),
    }
}

fn info(id: &'static str, name: &'static str, tactic: &'static str) -> MitreAttackInfo {
    MitreAttackInfo {
        technique_id: id.to_string(),
        technique_name: name.to_string(),
        tactic: tactic.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constant() {
        assert_eq!(MITRE_ATTACK_VERSION, "v18");
    }

    #[test]
    fn ids_maps_to_t1071() {
        let info = lookup(&MitreContext::Ids);
        assert_eq!(info.technique_id, "T1071");
        assert_eq!(info.technique_name, "Application Layer Protocol");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn threatintel_malware() {
        let info = lookup(&MitreContext::ThreatIntel(ThreatType::Malware));
        assert_eq!(info.technique_id, "T1071.001");
        assert_eq!(info.technique_name, "Web Protocols");
    }

    #[test]
    fn threatintel_c2() {
        let info = lookup(&MitreContext::ThreatIntel(ThreatType::C2));
        assert_eq!(info.technique_id, "T1071.001");
    }

    #[test]
    fn threatintel_scanner() {
        let info = lookup(&MitreContext::ThreatIntel(ThreatType::Scanner));
        assert_eq!(info.technique_id, "T1595");
        assert_eq!(info.tactic, "reconnaissance");
    }

    #[test]
    fn threatintel_spam() {
        let info = lookup(&MitreContext::ThreatIntel(ThreatType::Spam));
        assert_eq!(info.technique_id, "T1566");
        assert_eq!(info.tactic, "initial-access");
    }

    #[test]
    fn threatintel_other() {
        let info = lookup(&MitreContext::ThreatIntel(ThreatType::Other));
        assert_eq!(info.technique_id, "T1568");
    }

    #[test]
    fn dlp_pci() {
        let info = lookup(&MitreContext::Dlp("pci"));
        assert_eq!(info.technique_id, "T1041");
        assert_eq!(info.tactic, "exfiltration");
    }

    #[test]
    fn dlp_pii() {
        let info = lookup(&MitreContext::Dlp("pii"));
        assert_eq!(info.technique_id, "T1048");
    }

    #[test]
    fn dlp_credentials() {
        let info = lookup(&MitreContext::Dlp("credentials"));
        assert_eq!(info.technique_id, "T1048.003");
    }

    #[test]
    fn dlp_unknown_falls_back_to_t1041() {
        let info = lookup(&MitreContext::Dlp("custom-secrets"));
        assert_eq!(info.technique_id, "T1041");
        assert_eq!(info.tactic, "exfiltration");
    }

    #[test]
    fn firewall_maps_to_t1190() {
        let info = lookup(&MitreContext::PacketSecurity(
            PacketSecurityMitreReason::Firewall,
        ));
        assert_eq!(info.technique_id, "T1190");
        assert_eq!(info.tactic, "initial-access");
    }

    #[test]
    fn ratelimit_maps_to_t1498() {
        let info = lookup(&MitreContext::PacketSecurity(
            PacketSecurityMitreReason::Ratelimit,
        ));
        assert_eq!(info.technique_id, "T1498");
        assert_eq!(info.tactic, "impact");
    }

    #[test]
    fn l7_maps_to_t1071() {
        let info = lookup(&MitreContext::PacketSecurity(PacketSecurityMitreReason::L7));
        assert_eq!(info.technique_id, "T1071");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn ips_maps_to_t1110() {
        let info = lookup(&MitreContext::PacketSecurity(
            PacketSecurityMitreReason::Ips,
        ));
        assert_eq!(info.technique_id, "T1110");
        assert_eq!(info.tactic, "credential-access");
    }

    #[test]
    fn coverage_report_packet_security_components() {
        let report = coverage_report(&["firewall", "ratelimit", "l7", "ips"]);
        assert_eq!(report.total_techniques, 4);
        let ids: Vec<&str> = report
            .techniques
            .iter()
            .map(|t| t.technique_id.as_str())
            .collect();
        assert!(ids.contains(&"T1190"));
        assert!(ids.contains(&"T1498"));
        assert!(ids.contains(&"T1071"));
        assert!(ids.contains(&"T1110"));
    }

    #[test]
    fn dns_blocklist_maps_to_t1071_004() {
        let info = lookup(&MitreContext::Dns(DnsMitreReason::BlocklistOrEncrypted));
        assert_eq!(info.technique_id, "T1071.004");
        assert_eq!(info.technique_name, "DNS");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn dns_reputation_maps_to_t1568() {
        let info = lookup(&MitreContext::Dns(DnsMitreReason::Reputation));
        assert_eq!(info.technique_id, "T1568");
        assert_eq!(info.technique_name, "Dynamic Resolution");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn coverage_report_dns_component() {
        let report = coverage_report(&["dns"]);
        assert_eq!(report.total_techniques, 2);
        assert!(report.techniques.iter().all(|t| t.component == "dns"));
        let technique_ids: Vec<&str> = report
            .techniques
            .iter()
            .map(|t| t.technique_id.as_str())
            .collect();
        assert!(technique_ids.contains(&"T1071.004"));
        assert!(technique_ids.contains(&"T1568"));
    }

    #[test]
    fn ddos_syn_flood() {
        let info = lookup(&MitreContext::Ddos(DdosAttackType::SynFlood));
        assert_eq!(info.technique_id, "T1499.001");
        assert_eq!(info.tactic, "impact");
    }

    #[test]
    fn ddos_udp_amplification() {
        let info = lookup(&MitreContext::Ddos(DdosAttackType::UdpAmplification));
        assert_eq!(info.technique_id, "T1498.002");
    }

    #[test]
    fn ddos_icmp_flood() {
        let info = lookup(&MitreContext::Ddos(DdosAttackType::IcmpFlood));
        assert_eq!(info.technique_id, "T1498");
    }

    #[test]
    fn ddos_rst_fin_ack_map_to_t1499() {
        for attack in [
            DdosAttackType::RstFlood,
            DdosAttackType::FinFlood,
            DdosAttackType::AckFlood,
        ] {
            let info = lookup(&MitreContext::Ddos(attack));
            assert_eq!(info.technique_id, "T1499");
            assert_eq!(info.technique_name, "Endpoint Denial of Service");
        }
    }

    #[test]
    fn ddos_volumetric() {
        let info = lookup(&MitreContext::Ddos(DdosAttackType::Volumetric));
        assert_eq!(info.technique_id, "T1498.001");
    }

    #[test]
    fn coverage_report_all_components() {
        let report = coverage_report(&[
            "ids",
            "threatintel",
            "dlp",
            "ddos",
            "dns",
            "firewall",
            "ratelimit",
            "l7",
            "ips",
        ]);
        assert_eq!(report.attack_version, "v18");
        assert_eq!(report.total_techniques, 19);
        assert!(!report.by_tactic.is_empty());
    }

    #[test]
    fn coverage_report_single_component() {
        let report = coverage_report(&["dlp"]);
        assert_eq!(report.total_techniques, 3);
        assert!(report.techniques.iter().all(|t| t.component == "dlp"));
        assert_eq!(report.by_tactic.len(), 1);
        assert_eq!(report.by_tactic[0].tactic, "exfiltration");
    }

    #[test]
    fn coverage_report_no_components() {
        let report = coverage_report(&[]);
        assert_eq!(report.total_techniques, 0);
        assert!(report.techniques.is_empty());
        assert!(report.by_tactic.is_empty());
    }

    #[test]
    fn coverage_report_tactic_grouping() {
        let report = coverage_report(&[
            "ids",
            "threatintel",
            "dlp",
            "ddos",
            "dns",
            "firewall",
            "ratelimit",
            "l7",
            "ips",
        ]);
        let impact = report
            .by_tactic
            .iter()
            .find(|t| t.tactic == "impact")
            .unwrap();
        assert_eq!(impact.covered_techniques, 6);
        assert!(impact.components.contains(&"ratelimit".to_string()));
        assert!(impact.components.contains(&"ddos".to_string()));
    }

    #[test]
    fn coverage_report_case_insensitive() {
        let report = coverage_report(&["IDS", "DLP"]);
        assert_eq!(report.total_techniques, 4); // 1 IDS + 3 DLP
    }
}
