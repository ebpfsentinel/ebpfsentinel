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

/// Component type for packet-level security MITRE mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSecurityComponent {
    Firewall,
    Ratelimit,
    L7,
    Ips,
}

/// Context for port-aware MITRE mapping on packet-level security alerts.
pub struct PacketSecurityMitreContext {
    pub component: PacketSecurityComponent,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Sub-reason for DNS MITRE mapping.
pub enum DnsMitreReason {
    /// Blocklist match or encrypted DNS detection.
    BlocklistOrEncrypted,
    /// Reputation-based auto-block.
    Reputation,
}

/// ML anomaly type for MITRE mapping (feature-driven classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlAnomalyType {
    /// `packet_rate` or `byte_rate` drift — volumetric anomaly.
    TrafficVolumeDrift,
    /// `tcp_ratio`/`udp_ratio`/`icmp_ratio`/`other_ratio` drift — protocol tunneling.
    ProtocolRatioDrift,
    /// `port_entropy` spike — port scanning.
    PortEntropySpike,
    /// `unique_src_ips` spike — distributed source anomaly.
    SourceDiversitySpike,
    /// `unique_dst_ports` spike — lateral movement / service discovery.
    DestPortDiversitySpike,
    /// `avg_payload_size` or `std_payload_size` spike — data staging.
    PayloadSizeAnomaly,
    /// `connection_count` spike — brute force / worm propagation.
    ConnectionCountSpike,
}

/// Context passed to [`lookup`] to select the correct ATT&CK technique.
pub enum MitreContext<'a> {
    Ids {
        dst_port: u16,
    },
    ThreatIntel {
        threat_type: ThreatType,
        dst_port: u16,
    },
    Dlp(&'a str),
    Ddos(DdosAttackType),
    Dns(DnsMitreReason),
    PacketSecurity(PacketSecurityMitreContext),
    MlAnomaly(MlAnomalyType),
}

/// Return the ATT&CK technique for the given alert context.
///
/// The mapping is static and zero-heap in the registry itself — every
/// returned [`MitreAttackInfo`] is built from `&'static str` literals.
pub fn lookup(ctx: &MitreContext<'_>) -> MitreAttackInfo {
    match ctx {
        MitreContext::Ids { dst_port } => lookup_ids(*dst_port),

        MitreContext::ThreatIntel {
            threat_type,
            dst_port,
        } => lookup_threatintel(*threat_type, *dst_port),

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

        MitreContext::PacketSecurity(ctx) => lookup_packet_security(ctx),

        MitreContext::MlAnomaly(anomaly_type) => lookup_ml_anomaly(*anomaly_type),

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

/// Port-aware MITRE mapping for IDS signature matches.
///
/// An IDS alert on port 22 (SSH) indicates different attacker behavior
/// than one on port 443 (HTTPS) or port 53 (DNS tunneling).
fn lookup_ids(dst_port: u16) -> MitreAttackInfo {
    match dst_port {
        22 => info("T1021.004", "SSH", "lateral-movement"),
        23 => info("T1021", "Remote Services", "lateral-movement"),
        25 | 587 | 465 => info("T1071.003", "Mail Protocols", "command-and-control"),
        53 => info("T1071.004", "DNS", "command-and-control"),
        80 | 443 | 8080 | 8443 => info("T1071.001", "Web Protocols", "command-and-control"),
        3389 => info("T1021.001", "Remote Desktop Protocol", "lateral-movement"),
        445 | 139 => info("T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
        21 => info(
            "T1071.002",
            "File Transfer Protocols",
            "command-and-control",
        ),
        _ => info("T1071", "Application Layer Protocol", "command-and-control"),
    }
}

/// Port-aware MITRE mapping for threat intelligence IOC matches.
///
/// Combines the IOC threat type with destination port for precision.
/// Malware/C2 on HTTPS is different from a scanner hitting SSH.
fn lookup_threatintel(threat_type: ThreatType, dst_port: u16) -> MitreAttackInfo {
    match threat_type {
        ThreatType::Malware | ThreatType::C2 => match dst_port {
            53 => info("T1071.004", "DNS", "command-and-control"),
            25 | 587 | 465 => info("T1071.003", "Mail Protocols", "command-and-control"),
            _ => info("T1071.001", "Web Protocols", "command-and-control"),
        },
        ThreatType::Scanner => match dst_port {
            22 | 3389 => info("T1110", "Brute Force", "credential-access"),
            _ => info("T1595", "Active Scanning", "reconnaissance"),
        },
        ThreatType::Spam => info("T1566", "Phishing", "initial-access"),
        ThreatType::Other => match dst_port {
            53 => info("T1071.004", "DNS", "command-and-control"),
            _ => info("T1568", "Dynamic Resolution", "command-and-control"),
        },
    }
}

/// Port-aware MITRE mapping for packet-level security alerts.
///
/// The same firewall deny on port 22 (SSH brute force) and port 443 (web exploit)
/// should produce different techniques. Uses `dst_port` + `component` to select.
fn lookup_packet_security(ctx: &PacketSecurityMitreContext) -> MitreAttackInfo {
    match ctx.component {
        PacketSecurityComponent::Firewall | PacketSecurityComponent::Ips => match ctx.dst_port {
            22 => info("T1110.001", "Password Guessing", "credential-access"),
            23 => info("T1021", "Remote Services", "lateral-movement"),
            25 | 587 | 465 => info("T1071.003", "Mail Protocols", "command-and-control"),
            53 => info("T1071.004", "DNS", "command-and-control"),
            80 | 443 | 8080 | 8443 | 3306 | 5432 | 1433 | 27017 | 6379 => info(
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
            ),
            3389 => info("T1021.001", "Remote Desktop Protocol", "lateral-movement"),
            445 | 139 => info("T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
            5900..=5999 => info("T1021.005", "VNC", "lateral-movement"),
            _ => info("T1046", "Network Service Scanning", "discovery"),
        },
        PacketSecurityComponent::Ratelimit => match ctx.dst_port {
            22 => info("T1110", "Brute Force", "credential-access"),
            80 | 443 | 8080 | 8443 => info("T1499.002", "Service Exhaustion Flood", "impact"),
            _ => info("T1498", "Network Denial of Service", "impact"),
        },
        PacketSecurityComponent::L7 => match ctx.dst_port {
            25 | 587 | 465 => info("T1071.003", "Mail Protocols", "command-and-control"),
            53 => info("T1071.004", "DNS", "command-and-control"),
            80 | 443 | 8080 | 8443 => info("T1071.001", "Web Protocols", "command-and-control"),
            21 => info(
                "T1071.002",
                "File Transfer Protocols",
                "command-and-control",
            ),
            445 | 139 => info("T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
            _ => info("T1071", "Application Layer Protocol", "command-and-control"),
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
/// Map ML anomaly feature type to the most relevant ATT&CK technique.
fn lookup_ml_anomaly(anomaly_type: MlAnomalyType) -> MitreAttackInfo {
    match anomaly_type {
        MlAnomalyType::TrafficVolumeDrift => info("T1498.001", "Direct Network Flood", "impact"),
        MlAnomalyType::ProtocolRatioDrift => {
            info("T1572", "Protocol Tunneling", "command-and-control")
        }
        MlAnomalyType::PortEntropySpike => info("T1046", "Network Service Scanning", "discovery"),
        MlAnomalyType::SourceDiversitySpike => info("T1090", "Proxy", "command-and-control"),
        MlAnomalyType::DestPortDiversitySpike => {
            info("T1570", "Lateral Tool Transfer", "lateral-movement")
        }
        MlAnomalyType::PayloadSizeAnomaly => info("T1074", "Data Staged", "collection"),
        MlAnomalyType::ConnectionCountSpike => info("T1110", "Brute Force", "credential-access"),
    }
}

/// Map a feature index (from `FeatureVector::as_model_input()` order) to an `MlAnomalyType`.
///
/// Feature order: `packet_rate`(0), `byte_rate`(1), `tcp_ratio`(2), `udp_ratio`(3),
/// `icmp_ratio`(4), `other_ratio`(5), `port_entropy`(6), `unique_src_ips`(7),
/// `unique_dst_ports`(8), `avg_payload_size`(9), `std_payload_size`(10), `connection_count`(11)
pub fn feature_index_to_ml_anomaly_type(feature_idx: usize) -> MlAnomalyType {
    match feature_idx {
        2..=5 => MlAnomalyType::ProtocolRatioDrift,
        6 => MlAnomalyType::PortEntropySpike,
        7 => MlAnomalyType::SourceDiversitySpike,
        8 => MlAnomalyType::DestPortDiversitySpike,
        9 | 10 => MlAnomalyType::PayloadSizeAnomaly,
        11 => MlAnomalyType::ConnectionCountSpike,
        // 0 (packet_rate), 1 (byte_rate), and unknown indices
        _ => MlAnomalyType::TrafficVolumeDrift,
    }
}

fn all_coverage_entries() -> Vec<CoverageEntry> {
    let mut entries = Vec::with_capacity(43);
    entries.extend(firewall_ips_coverage_entries());
    entries.extend(ratelimit_coverage_entries());
    entries.extend(l7_coverage_entries());
    entries.extend(detection_coverage_entries());
    entries.extend(ddos_coverage_entries());
    entries.extend(ml_anomaly_coverage_entries());
    entries
}

fn ml_anomaly_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "ml-anomaly",
            "T1498.001",
            "Direct Network Flood",
            "impact",
            "ML: traffic volume drift (packet/byte rate)",
        ),
        entry(
            "ml-anomaly",
            "T1572",
            "Protocol Tunneling",
            "command-and-control",
            "ML: protocol ratio drift (TCP/UDP/ICMP)",
        ),
        entry(
            "ml-anomaly",
            "T1046",
            "Network Service Scanning",
            "discovery",
            "ML: port entropy spike",
        ),
        entry(
            "ml-anomaly",
            "T1090",
            "Proxy",
            "command-and-control",
            "ML: source IP diversity spike",
        ),
        entry(
            "ml-anomaly",
            "T1570",
            "Lateral Tool Transfer",
            "lateral-movement",
            "ML: destination port diversity spike",
        ),
        entry(
            "ml-anomaly",
            "T1074",
            "Data Staged",
            "collection",
            "ML: payload size anomaly",
        ),
        entry(
            "ml-anomaly",
            "T1110",
            "Brute Force",
            "credential-access",
            "ML: connection count spike",
        ),
    ]
}

fn firewall_ips_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "firewall",
            "T1110.001",
            "Password Guessing",
            "credential-access",
            "Firewall deny on SSH (22)",
        ),
        entry(
            "firewall",
            "T1021",
            "Remote Services",
            "lateral-movement",
            "Firewall deny on Telnet (23)",
        ),
        entry(
            "firewall",
            "T1071.003",
            "Mail Protocols",
            "command-and-control",
            "Firewall deny on SMTP (25/587)",
        ),
        entry(
            "firewall",
            "T1071.004",
            "DNS",
            "command-and-control",
            "Firewall deny on DNS (53)",
        ),
        entry(
            "firewall",
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
            "Firewall deny on HTTP/DB ports",
        ),
        entry(
            "firewall",
            "T1021.001",
            "Remote Desktop Protocol",
            "lateral-movement",
            "Firewall deny on RDP (3389)",
        ),
        entry(
            "firewall",
            "T1021.002",
            "SMB/Windows Admin Shares",
            "lateral-movement",
            "Firewall deny on SMB (445)",
        ),
        entry(
            "firewall",
            "T1046",
            "Network Service Scanning",
            "discovery",
            "Firewall deny on other ports",
        ),
        entry(
            "ips",
            "T1110.001",
            "Password Guessing",
            "credential-access",
            "IPS auto-blacklist on SSH (22)",
        ),
        entry(
            "ips",
            "T1190",
            "Exploit Public-Facing Application",
            "initial-access",
            "IPS auto-blacklist on HTTP/DB",
        ),
        entry(
            "ips",
            "T1046",
            "Network Service Scanning",
            "discovery",
            "IPS auto-blacklist on other ports",
        ),
    ]
}

fn ratelimit_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "ratelimit",
            "T1110",
            "Brute Force",
            "credential-access",
            "Rate limit exceeded on SSH (22)",
        ),
        entry(
            "ratelimit",
            "T1499.002",
            "Service Exhaustion Flood",
            "impact",
            "Rate limit exceeded on HTTP",
        ),
        entry(
            "ratelimit",
            "T1498",
            "Network Denial of Service",
            "impact",
            "Rate limit exceeded on other ports",
        ),
    ]
}

fn l7_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "l7",
            "T1071.001",
            "Web Protocols",
            "command-and-control",
            "L7 deny on HTTP/HTTPS",
        ),
        entry(
            "l7",
            "T1071.002",
            "File Transfer Protocols",
            "command-and-control",
            "L7 deny on FTP",
        ),
        entry(
            "l7",
            "T1071.003",
            "Mail Protocols",
            "command-and-control",
            "L7 deny on SMTP",
        ),
        entry(
            "l7",
            "T1021.002",
            "SMB/Windows Admin Shares",
            "lateral-movement",
            "L7 deny on SMB",
        ),
        entry(
            "l7",
            "T1071",
            "Application Layer Protocol",
            "command-and-control",
            "L7 deny on other protocols",
        ),
    ]
}

fn detection_coverage_entries() -> Vec<CoverageEntry> {
    let mut entries = Vec::with_capacity(22);
    entries.extend(ids_coverage_entries());
    entries.extend(threatintel_coverage_entries());
    entries.extend(dlp_dns_coverage_entries());
    entries
}

fn ids_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "ids",
            "T1021.004",
            "SSH",
            "lateral-movement",
            "IDS match on SSH (22)",
        ),
        entry(
            "ids",
            "T1071.001",
            "Web Protocols",
            "command-and-control",
            "IDS match on HTTP/HTTPS",
        ),
        entry(
            "ids",
            "T1071.003",
            "Mail Protocols",
            "command-and-control",
            "IDS match on SMTP",
        ),
        entry(
            "ids",
            "T1071.004",
            "DNS",
            "command-and-control",
            "IDS match on DNS (53)",
        ),
        entry(
            "ids",
            "T1021.001",
            "Remote Desktop Protocol",
            "lateral-movement",
            "IDS match on RDP (3389)",
        ),
        entry(
            "ids",
            "T1021.002",
            "SMB/Windows Admin Shares",
            "lateral-movement",
            "IDS match on SMB (445)",
        ),
        entry(
            "ids",
            "T1071",
            "Application Layer Protocol",
            "command-and-control",
            "IDS match on other ports",
        ),
    ]
}

fn threatintel_coverage_entries() -> Vec<CoverageEntry> {
    vec![
        entry(
            "threatintel",
            "T1071.001",
            "Web Protocols",
            "command-and-control",
            "IOC hit: malware/C2 on HTTP",
        ),
        entry(
            "threatintel",
            "T1071.003",
            "Mail Protocols",
            "command-and-control",
            "IOC hit: C2 on SMTP",
        ),
        entry(
            "threatintel",
            "T1071.004",
            "DNS",
            "command-and-control",
            "IOC hit: malware/C2 on DNS",
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
            "T1110",
            "Brute Force",
            "credential-access",
            "IOC hit: scanner on SSH/RDP",
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
    ]
}

fn dlp_dns_coverage_entries() -> Vec<CoverageEntry> {
    vec![
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
    fn ids_ssh_maps_to_lateral_movement() {
        let info = lookup(&MitreContext::Ids { dst_port: 22 });
        assert_eq!(info.technique_id, "T1021.004");
        assert_eq!(info.tactic, "lateral-movement");
    }

    #[test]
    fn ids_http_maps_to_web_protocols() {
        let info = lookup(&MitreContext::Ids { dst_port: 443 });
        assert_eq!(info.technique_id, "T1071.001");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn ids_dns_maps_to_dns() {
        let info = lookup(&MitreContext::Ids { dst_port: 53 });
        assert_eq!(info.technique_id, "T1071.004");
    }

    #[test]
    fn ids_unknown_port_maps_to_generic() {
        let info = lookup(&MitreContext::Ids { dst_port: 9999 });
        assert_eq!(info.technique_id, "T1071");
    }

    #[test]
    fn ids_rdp_maps_to_rdp() {
        let info = lookup(&MitreContext::Ids { dst_port: 3389 });
        assert_eq!(info.technique_id, "T1021.001");
    }

    #[test]
    fn threatintel_malware_http() {
        let info = lookup(&MitreContext::ThreatIntel {
            threat_type: ThreatType::Malware,
            dst_port: 443,
        });
        assert_eq!(info.technique_id, "T1071.001");
        assert_eq!(info.technique_name, "Web Protocols");
    }

    #[test]
    fn threatintel_c2_dns() {
        let info = lookup(&MitreContext::ThreatIntel {
            threat_type: ThreatType::C2,
            dst_port: 53,
        });
        assert_eq!(info.technique_id, "T1071.004");
    }

    #[test]
    fn threatintel_scanner_ssh() {
        let info = lookup(&MitreContext::ThreatIntel {
            threat_type: ThreatType::Scanner,
            dst_port: 22,
        });
        assert_eq!(info.technique_id, "T1110");
        assert_eq!(info.tactic, "credential-access");
    }

    #[test]
    fn threatintel_scanner_generic() {
        let info = lookup(&MitreContext::ThreatIntel {
            threat_type: ThreatType::Scanner,
            dst_port: 8080,
        });
        assert_eq!(info.technique_id, "T1595");
        assert_eq!(info.tactic, "reconnaissance");
    }

    #[test]
    fn threatintel_spam() {
        let info = lookup(&MitreContext::ThreatIntel {
            threat_type: ThreatType::Spam,
            dst_port: 25,
        });
        assert_eq!(info.technique_id, "T1566");
        assert_eq!(info.tactic, "initial-access");
    }

    #[test]
    fn threatintel_other() {
        let info = lookup(&MitreContext::ThreatIntel {
            threat_type: ThreatType::Other,
            dst_port: 443,
        });
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

    fn psa(component: PacketSecurityComponent, port: u16) -> PacketSecurityMitreContext {
        PacketSecurityMitreContext {
            component,
            dst_port: port,
            protocol: 6,
        }
    }

    #[test]
    fn firewall_ssh_maps_to_password_guessing() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Firewall,
            22,
        )));
        assert_eq!(info.technique_id, "T1110.001");
        assert_eq!(info.tactic, "credential-access");
    }

    #[test]
    fn firewall_http_maps_to_exploit() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Firewall,
            443,
        )));
        assert_eq!(info.technique_id, "T1190");
        assert_eq!(info.tactic, "initial-access");
    }

    #[test]
    fn firewall_rdp_maps_to_remote_desktop() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Firewall,
            3389,
        )));
        assert_eq!(info.technique_id, "T1021.001");
        assert_eq!(info.tactic, "lateral-movement");
    }

    #[test]
    fn firewall_smb_maps_to_smb() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Firewall,
            445,
        )));
        assert_eq!(info.technique_id, "T1021.002");
    }

    #[test]
    fn firewall_unknown_port_maps_to_scanning() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Firewall,
            9999,
        )));
        assert_eq!(info.technique_id, "T1046");
        assert_eq!(info.tactic, "discovery");
    }

    #[test]
    fn firewall_db_port_maps_to_exploit() {
        for port in [3306, 5432, 1433, 27017, 6379] {
            let info = lookup(&MitreContext::PacketSecurity(psa(
                PacketSecurityComponent::Firewall,
                port,
            )));
            assert_eq!(info.technique_id, "T1190", "port {port}");
        }
    }

    #[test]
    fn ips_ssh_maps_to_password_guessing() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Ips,
            22,
        )));
        assert_eq!(info.technique_id, "T1110.001");
    }

    #[test]
    fn ratelimit_ssh_maps_to_brute_force() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Ratelimit,
            22,
        )));
        assert_eq!(info.technique_id, "T1110");
        assert_eq!(info.tactic, "credential-access");
    }

    #[test]
    fn ratelimit_http_maps_to_service_exhaustion() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Ratelimit,
            80,
        )));
        assert_eq!(info.technique_id, "T1499.002");
        assert_eq!(info.tactic, "impact");
    }

    #[test]
    fn ratelimit_other_maps_to_network_dos() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::Ratelimit,
            12345,
        )));
        assert_eq!(info.technique_id, "T1498");
    }

    #[test]
    fn l7_http_maps_to_web_protocols() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::L7,
            443,
        )));
        assert_eq!(info.technique_id, "T1071.001");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn l7_ftp_maps_to_file_transfer() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::L7,
            21,
        )));
        assert_eq!(info.technique_id, "T1071.002");
    }

    #[test]
    fn l7_smtp_maps_to_mail() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::L7,
            25,
        )));
        assert_eq!(info.technique_id, "T1071.003");
    }

    #[test]
    fn l7_smb_maps_to_smb() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::L7,
            445,
        )));
        assert_eq!(info.technique_id, "T1021.002");
    }

    #[test]
    fn l7_unknown_maps_to_generic_app_layer() {
        let info = lookup(&MitreContext::PacketSecurity(psa(
            PacketSecurityComponent::L7,
            9999,
        )));
        assert_eq!(info.technique_id, "T1071");
    }

    #[test]
    fn coverage_report_packet_security_components() {
        let report = coverage_report(&["firewall", "ratelimit", "l7", "ips"]);
        assert_eq!(report.total_techniques, 19);
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
        assert_eq!(report.total_techniques, 43);
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
        assert_eq!(impact.covered_techniques, 7);
        assert!(impact.components.contains(&"ratelimit".to_string()));
        assert!(impact.components.contains(&"ddos".to_string()));
    }

    #[test]
    fn coverage_report_case_insensitive() {
        let report = coverage_report(&["IDS", "DLP"]);
        assert_eq!(report.total_techniques, 10); // 7 IDS + 3 DLP
    }

    #[test]
    fn ml_anomaly_traffic_volume_drift() {
        let info = lookup(&MitreContext::MlAnomaly(MlAnomalyType::TrafficVolumeDrift));
        assert_eq!(info.technique_id, "T1498.001");
        assert_eq!(info.tactic, "impact");
    }

    #[test]
    fn ml_anomaly_protocol_tunneling() {
        let info = lookup(&MitreContext::MlAnomaly(MlAnomalyType::ProtocolRatioDrift));
        assert_eq!(info.technique_id, "T1572");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn ml_anomaly_port_scanning() {
        let info = lookup(&MitreContext::MlAnomaly(MlAnomalyType::PortEntropySpike));
        assert_eq!(info.technique_id, "T1046");
        assert_eq!(info.tactic, "discovery");
    }

    #[test]
    fn ml_anomaly_brute_force() {
        let info = lookup(&MitreContext::MlAnomaly(
            MlAnomalyType::ConnectionCountSpike,
        ));
        assert_eq!(info.technique_id, "T1110");
        assert_eq!(info.tactic, "credential-access");
    }

    #[test]
    fn ml_anomaly_data_staging() {
        let info = lookup(&MitreContext::MlAnomaly(MlAnomalyType::PayloadSizeAnomaly));
        assert_eq!(info.technique_id, "T1074");
        assert_eq!(info.tactic, "collection");
    }

    #[test]
    fn ml_anomaly_lateral_movement() {
        let info = lookup(&MitreContext::MlAnomaly(
            MlAnomalyType::DestPortDiversitySpike,
        ));
        assert_eq!(info.technique_id, "T1570");
        assert_eq!(info.tactic, "lateral-movement");
    }

    #[test]
    fn ml_anomaly_proxy_detection() {
        let info = lookup(&MitreContext::MlAnomaly(
            MlAnomalyType::SourceDiversitySpike,
        ));
        assert_eq!(info.technique_id, "T1090");
        assert_eq!(info.tactic, "command-and-control");
    }

    #[test]
    fn feature_index_mapping_complete() {
        // packet_rate, byte_rate → traffic volume
        assert_eq!(
            feature_index_to_ml_anomaly_type(0),
            MlAnomalyType::TrafficVolumeDrift
        );
        assert_eq!(
            feature_index_to_ml_anomaly_type(1),
            MlAnomalyType::TrafficVolumeDrift
        );
        // protocol ratios → protocol drift
        assert_eq!(
            feature_index_to_ml_anomaly_type(2),
            MlAnomalyType::ProtocolRatioDrift
        );
        assert_eq!(
            feature_index_to_ml_anomaly_type(5),
            MlAnomalyType::ProtocolRatioDrift
        );
        // port_entropy → scanning
        assert_eq!(
            feature_index_to_ml_anomaly_type(6),
            MlAnomalyType::PortEntropySpike
        );
        // unique_src_ips → source diversity
        assert_eq!(
            feature_index_to_ml_anomaly_type(7),
            MlAnomalyType::SourceDiversitySpike
        );
        // unique_dst_ports → dest diversity
        assert_eq!(
            feature_index_to_ml_anomaly_type(8),
            MlAnomalyType::DestPortDiversitySpike
        );
        // payload sizes → payload anomaly
        assert_eq!(
            feature_index_to_ml_anomaly_type(9),
            MlAnomalyType::PayloadSizeAnomaly
        );
        assert_eq!(
            feature_index_to_ml_anomaly_type(10),
            MlAnomalyType::PayloadSizeAnomaly
        );
        // connection_count → brute force
        assert_eq!(
            feature_index_to_ml_anomaly_type(11),
            MlAnomalyType::ConnectionCountSpike
        );
        // unknown → default (traffic volume)
        assert_eq!(
            feature_index_to_ml_anomaly_type(99),
            MlAnomalyType::TrafficVolumeDrift
        );
    }

    #[test]
    fn ml_anomaly_in_coverage_report() {
        let report = coverage_report(&["ml-anomaly"]);
        assert_eq!(report.total_techniques, 7);
        let technique_ids: Vec<&str> = report
            .techniques
            .iter()
            .map(|t| t.technique_id.as_str())
            .collect();
        assert!(technique_ids.contains(&"T1498.001"));
        assert!(technique_ids.contains(&"T1572"));
        assert!(technique_ids.contains(&"T1046"));
        assert!(technique_ids.contains(&"T1090"));
        assert!(technique_ids.contains(&"T1570"));
        assert!(technique_ids.contains(&"T1074"));
        assert!(technique_ids.contains(&"T1110"));
    }
}
