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

/// Context passed to [`lookup`] to select the correct ATT&CK technique.
pub enum MitreContext<'a> {
    Ids,
    ThreatIntel(ThreatType),
    Dlp(&'a str),
    Ddos(DdosAttackType),
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
}
