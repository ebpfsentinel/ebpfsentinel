use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::alert::mitre::{self, MitreAttackInfo, MitreContext};
use crate::common::entity::{DomainMode, RuleId, Severity};
use crate::ddos::entity::DdosAttack;
use crate::dlp::entity::DlpAlert;
use crate::dns::entity::{DnsAlert, DnsAlertReason};
use crate::firewall::workload::{DestinationAddr, WORKLOAD_FIREWALL_COMPONENT, WorkloadDenial};
use crate::ids::entity::IdsAlert;
use crate::threatintel::entity::ThreatIntelAlert;
use crate::workload::entity::Workload;

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
    /// JA4 TLS `ClientHello` fingerprint for the flow, when one was computed.
    pub ja4_fingerprint: Option<String>,
    /// Container provenance resolved from the event's `cgroup_id`, when the
    /// datapath captured one and the cgroup resolver matched it.
    pub container: Option<crate::container::entity::ContainerInfo>,
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
    /// ML anomaly: composite anomaly score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_anomaly_score: Option<f64>,
    /// ML anomaly: top contributing feature name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_top_feature: Option<String>,
    /// ML anomaly: detection engine (baseline, ewma, fused).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ml_engine: Option<String>,
    /// AI security: provider name (e.g. "Anthropic").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_provider: Option<String>,
    /// AI security: SNI from TLS `ClientHello`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_sni: Option<String>,
    /// AI security: bytes sent to AI provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_bytes_sent: Option<u64>,
    /// AI security: exfiltration detection type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ai_exfil_type: Option<String>,
    /// TLS intelligence: threat category (C2, Malware, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_threat_category: Option<String>,
    /// TLS intelligence: PQC compliance status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pqc_status: Option<String>,
    /// Container context resolved from the event's `cgroup_id` (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<crate::container::entity::ContainerInfo>,
    /// Enricher metadata attached to [`Self::container`] (Docker inspect,
    /// Kubernetes API, ...). Populated by a [`MetadataEnricher`] after the
    /// container resolver produces [`ContainerInfo`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_metadata: Option<crate::container::entity::ContainerMetadata>,
    /// DLP: absolute path of the executable the offending process was
    /// running, as the agent resolved it. Absent when the process was gone
    /// before the alert was raised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
    /// DLP: device the executable's inode lives on. Travels with
    /// [`Self::executable_inode`]: a path is renamed, an inode is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_dev: Option<u64>,
    /// DLP: inode number of the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_inode: Option<u64>,
    /// DLP: how the executable was obtained, so a reader can tell a reading
    /// from an inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_source: Option<String>,
    /// DLP: how the five-tuple was obtained - read off the socket the kernel
    /// was writing through, or correlated from the same task's last write.
    /// Absent on a DLP alert means the address fields carry nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow_source: Option<String>,
    /// The workload that opened the flow this alert is about.
    ///
    /// Absent is a real answer and the common one: a transited flow has no
    /// local process at all, a node whose kernel refused the attribution
    /// hooks has no table to read, and a socket opened before the agent
    /// started was never recorded. The block is therefore never zeroed and
    /// never partially invented - [`crate::workload::entity::is_absent`] is
    /// the one predicate every surface serialises through, so no format can
    /// show a process id of 0.
    #[serde(default, skip_serializing_if = "crate::workload::entity::is_absent")]
    pub workload: Option<Workload>,
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
            mitre_attack: Some(mitre::lookup(&MitreContext::Ids {
                dst_port: ids.dst_port,
                rate_based: ids.rate_based,
            })),
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: ids.container.clone(),
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
        }
    }

    /// Create a domain alert from a DLP alert with a human-readable description.
    ///
    /// A DLP event starts process-level (pid/tgid). Where the datapath could
    /// account for the socket the plaintext went through, the address fields
    /// carry that flow and [`Self::flow_source`] says how it was obtained;
    /// where it could not, they stay zeroed and `flow_source` is absent, which
    /// is how a reader tells "nowhere known" from "0.0.0.0".
    pub fn from_dlp_alert(dlp: &DlpAlert, description: &str) -> Self {
        let flow = dlp.flow;
        Self {
            id: Self::generate_id(dlp.timestamp_ns, &dlp.pattern_id),
            timestamp_ns: dlp.timestamp_ns,
            component: "dlp".to_string(),
            severity: dlp.severity,
            rule_id: dlp.pattern_id.clone(),
            action: dlp.mode,
            src_addr: flow.map_or([0; 4], |f| f.src_addr),
            dst_addr: flow.map_or([0; 4], |f| f.dst_addr),
            src_port: flow.map_or(0, |f| f.src_port),
            dst_port: flow.map_or(0, |f| f.dst_port),
            protocol: flow.map_or(0, |f| f.protocol),
            is_ipv6: flow.is_some_and(|f| f.is_ipv6),
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
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: dlp.container.clone(),
            container_metadata: None,
            executable_path: dlp.executable.as_ref().map(|e| e.path.clone()),
            executable_dev: dlp.executable.as_ref().map(|e| e.dev),
            executable_inode: dlp.executable.as_ref().map(|e| e.inode),
            executable_source: dlp
                .executable
                .as_ref()
                .map(|e| e.source.as_str().to_string()),
            flow_source: flow.map(|f| f.source.as_str().to_string()),
            workload: None,
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
            mitre_attack: Some(mitre::lookup(&MitreContext::ThreatIntel {
                threat_type: ti.threat_type,
                dst_port: ti.dst_port,
            })),
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: ti.container.clone(),
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
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
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
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
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: dns.container.clone(),
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
        }
    }

    /// Create an alert about the agent itself rather than about traffic.
    ///
    /// Every address, port and protocol field is zero and stays zero: this is
    /// not a flow, and filling those in with something plausible would put a
    /// packet that never existed in front of an analyst. `component` is the
    /// subsystem that noticed, `rule_id` is the stable identifier an operator
    /// filters and alerts on, and `message` is what went wrong in one line.
    pub fn operational(
        component: &str,
        rule_id: &str,
        severity: Severity,
        message: String,
        timestamp_ns: u64,
    ) -> Self {
        let rule_id = RuleId(rule_id.to_string());
        Self {
            id: Self::generate_id(timestamp_ns, &rule_id),
            timestamp_ns,
            component: component.to_string(),
            severity,
            rule_id,
            action: DomainMode::Alert,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message,
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
            mitre_attack: None,
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
        }
    }

    /// Create a critical alert when every enabled WAN gateway has gone down
    /// (multi-WAN total-failure). `gateways` lists the down gateway names and
    /// `timestamp_ns` is the wall-clock time of the transition.
    pub fn wan_all_down(gateways: &[String], timestamp_ns: u64) -> Self {
        Self::operational(
            "routing",
            "routing-wan-all-down",
            Severity::Critical,
            format!(
                "all {} WAN gateway(s) down: {}",
                gateways.len(),
                gateways.join(", ")
            ),
            timestamp_ns,
        )
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
        let mitre_component = match psa.component {
            PacketAlertComponent::Firewall => mitre::PacketSecurityComponent::Firewall,
            PacketAlertComponent::Ratelimit => mitre::PacketSecurityComponent::Ratelimit,
            PacketAlertComponent::L7 => mitre::PacketSecurityComponent::L7,
            PacketAlertComponent::Ips => mitre::PacketSecurityComponent::Ips,
        };
        let mitre_context = MitreContext::PacketSecurity(mitre::PacketSecurityMitreContext {
            component: mitre_component,
            dst_port: psa.dst_port,
            protocol: psa.protocol,
        });
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
            ja4_fingerprint: psa.ja4_fingerprint.clone(),
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: psa.container.clone(),
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
        }
    }

    /// Create a domain alert from an ML anomaly detection.
    ///
    /// `anomaly_type` determines the MITRE technique mapping.
    /// `engine` is `"baseline"`, `"ewma"`, or `"fused"`.
    pub fn from_ml_anomaly(
        anomaly_id: &str,
        severity: Severity,
        score: f64,
        top_feature_idx: usize,
        top_feature_name: &str,
        engine: &str,
        timestamp_ns: u64,
    ) -> Self {
        let anomaly_type = mitre::feature_index_to_ml_anomaly_type(top_feature_idx);
        Self {
            id: format!("{timestamp_ns}-ml-{anomaly_id}"),
            timestamp_ns,
            component: "ml-anomaly".to_string(),
            severity,
            rule_id: RuleId(format!("ml-{anomaly_type:?}")),
            action: DomainMode::Alert,
            src_addr: [0; 4],
            dst_addr: [0; 4],
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_ipv6: false,
            message: format!(
                "ML anomaly detected (engine={engine}, score={score:.2}, top_feature={top_feature_name})"
            ),
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
            mitre_attack: Some(mitre::lookup(&MitreContext::MlAnomaly(anomaly_type))),
            ja4_fingerprint: None,
            ml_anomaly_score: Some(score),
            ml_top_feature: Some(top_feature_name.to_string()),
            ml_engine: Some(engine.to_string()),
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
        }
    }

    /// Create a domain alert from a workload policy refusal.
    ///
    /// The rule identifier is the alert's own rule, which is what makes the
    /// counter by rule and the alert about the same thing: an operator
    /// reading a figure on one screen can find the alerts behind it without
    /// a second vocabulary.
    ///
    /// No ATT&CK technique is attached, and the absence is deliberate. Every
    /// other alert here is about something observed on the wire; this one is
    /// about our own policy, and a refusal is as often a rule written too
    /// wide as it is an adversary. Naming a technique would turn the first
    /// case into a report of an attack that did not happen.
    #[must_use]
    pub fn from_workload_denial(denial: &WorkloadDenial, workload: Option<Workload>) -> Self {
        let (dst_addr, is_ipv6) = match denial.destination.addr {
            DestinationAddr::V4(addr) => ([addr, 0, 0, 0], false),
            DestinationAddr::V6(addr) => (
                [
                    u32::from_be_bytes([addr[0], addr[1], addr[2], addr[3]]),
                    u32::from_be_bytes([addr[4], addr[5], addr[6], addr[7]]),
                    u32::from_be_bytes([addr[8], addr[9], addr[10], addr[11]]),
                    u32::from_be_bytes([addr[12], addr[13], addr[14], addr[15]]),
                ],
                true,
            ),
        };
        let message = denial.message();
        Self {
            id: Self::generate_id(denial.at_ns, &denial.rule),
            timestamp_ns: denial.at_ns,
            component: WORKLOAD_FIREWALL_COMPONENT.to_string(),
            severity: Severity::Medium,
            rule_id: denial.rule.clone(),
            action: if denial.enforced {
                DomainMode::Block
            } else {
                DomainMode::Alert
            },
            src_addr: [0; 4],
            dst_addr,
            src_port: 0,
            dst_port: denial.destination.port,
            protocol: denial.destination.protocol.to_u8(),
            is_ipv6,
            message,
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
            tgid: Some(denial.tgid),
            direction: None,
            matched_domain: None,
            attack_type: None,
            peak_pps: None,
            current_pps: None,
            mitigation_status: None,
            total_packets: None,
            mitre_attack: None,
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: None,
            ai_sni: None,
            ai_bytes_sent: None,
            ai_exfil_type: None,
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: workload.filter(|w| w.pid != 0),
        }
    }

    /// Create a domain alert from an AI security detection.
    ///
    /// Used by the enterprise AI security service for shadow AI, AI DLP,
    /// exfiltration, and encrypted DNS policy violations.
    #[allow(clippy::too_many_arguments)]
    pub fn from_ai_security(
        component: &str,
        rule_id: &str,
        severity: Severity,
        action: DomainMode,
        src_addr: [u32; 4],
        dst_addr: [u32; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        is_ipv6: bool,
        message: &str,
        timestamp_ns: u64,
        mitre_context: &MitreContext<'_>,
        ai_provider: Option<&str>,
        ai_sni: Option<&str>,
        ai_bytes_sent: Option<u64>,
        ai_exfil_type: Option<&str>,
    ) -> Self {
        let rid = RuleId(rule_id.to_string());
        Self {
            id: Self::generate_id(timestamp_ns, &rid),
            timestamp_ns,
            component: component.to_string(),
            severity,
            rule_id: rid,
            action,
            src_addr,
            dst_addr,
            src_port,
            dst_port,
            protocol,
            is_ipv6,
            message: message.to_string(),
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
            mitre_attack: Some(mitre::lookup(mitre_context)),
            ja4_fingerprint: None,
            ml_anomaly_score: None,
            ml_top_feature: None,
            ml_engine: None,
            ai_provider: ai_provider.map(str::to_string),
            ai_sni: ai_sni.map(str::to_string),
            ai_bytes_sent,
            ai_exfil_type: ai_exfil_type.map(str::to_string),
            tls_threat_category: None,
            tls_pqc_status: None,
            container: None,
            container_metadata: None,
            executable_path: None,
            executable_dev: None,
            executable_inode: None,
            executable_source: None,
            flow_source: None,
            workload: None,
        }
    }

    /// Attach the workload that owned the flow, where one was resolved.
    ///
    /// Takes an `Option` rather than a `Workload` so a caller that resolved
    /// nothing says so in the same line, instead of branching around the
    /// call and leaving two paths for a reader to compare.
    #[must_use]
    pub fn with_workload(mut self, workload: Option<Workload>) -> Self {
        self.workload = workload.filter(|w| w.pid != 0);
        self
    }

    /// Returns the source IPv4 address (first element of `src_addr`).
    pub fn src_ip(&self) -> u32 {
        self.src_addr[0]
    }

    /// Returns the destination IPv4 address (first element of `dst_addr`).
    pub fn dst_ip(&self) -> u32 {
        self.dst_addr[0]
    }

    /// Generate a unique alert ID.
    ///
    /// `{timestamp_ns}-{rule_id}` alone is not unique: the kernel stamps
    /// events from a clock the userspace does not control, so two distinct
    /// events matching the same rule can carry the same nanosecond. That
    /// collision is not cosmetic - the alert store is keyed by id, so one of
    /// the two alerts silently replaces the other, and the SSE resume
    /// contract locates a client's position by finding its id in the replay
    /// buffer. A process-lifetime counter makes the id unique regardless of
    /// what the clock does.
    fn generate_id(timestamp_ns: u64, rule_id: &RuleId) -> String {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{timestamp_ns}-{rule_id}-{seq}")
    }
}

/// Routing destination for an alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertDestination {
    Email {
        to: String,
    },
    Webhook {
        url: String,
        /// Extra HTTP headers to send with the request (e.g. an auth token).
        /// Ordered so the request is reproducible. Defaults to empty, which
        /// keeps routes serialized before this field readable.
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
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
            container: None,
            executable: None,
            flow: None,
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
            container: None,
            rate_based: false,
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
        // Nothing was resolvable on this fixture, so nothing is claimed.
        assert!(alert.executable_path.is_none());
        assert!(alert.executable_source.is_none());
        assert!(alert.flow_source.is_none());
    }

    #[test]
    fn alert_from_dlp_alert_carries_the_executable_and_the_destination() {
        use crate::dlp::entity::{DlpExecutable, DlpFlow, DlpIdentitySource};

        let mut dlp = sample_dlp_alert();
        dlp.executable = Some(DlpExecutable {
            path: "/usr/bin/python3.13".to_string(),
            dev: 66_306,
            inode: 1_181_234,
            source: DlpIdentitySource::ProcessAtAlertTime,
        });
        dlp.flow = Some(DlpFlow {
            src_addr: [0x0a01_0203, 0, 0, 0],
            dst_addr: [0x5db8_d822, 0, 0, 0],
            src_port: 44001,
            dst_port: 443,
            protocol: 6,
            is_ipv6: false,
            source: DlpIdentitySource::KernelSocket,
        });

        let alert = Alert::from_dlp_alert(&dlp, "Visa card written to a TLS socket");

        assert_eq!(
            alert.executable_path.as_deref(),
            Some("/usr/bin/python3.13")
        );
        assert_eq!(alert.executable_dev, Some(66_306));
        assert_eq!(alert.executable_inode, Some(1_181_234));
        assert_eq!(
            alert.executable_source.as_deref(),
            Some("process_at_alert_time")
        );
        assert_eq!(alert.dst_ip(), 0x5db8_d822);
        assert_eq!(alert.dst_port, 443);
        assert_eq!(alert.src_port, 44001);
        assert_eq!(alert.protocol, 6);
        assert_eq!(alert.flow_source.as_deref(), Some("kernel_socket"));
    }

    #[test]
    fn an_unattributed_alert_serialises_without_a_workload_block() {
        let alert = Alert::from_dlp_alert(&sample_dlp_alert(), "Visa card detected");
        assert!(alert.workload.is_none());
        let json = serde_json::to_string(&alert).unwrap();
        assert!(!json.contains("workload"));
    }

    #[test]
    fn an_attributed_alert_carries_the_block_it_was_given() {
        let workload = crate::workload::entity::Workload::new(
            4_242,
            crate::workload::entity::WorkloadSource::Socket,
        );
        let alert = Alert::from_dlp_alert(&sample_dlp_alert(), "Visa card detected")
            .with_workload(workload);
        assert_eq!(alert.workload.as_ref().unwrap().pid, 4_242);
        let json = serde_json::to_string(&alert).unwrap();
        assert!(json.contains("\"workload\":{\"pid\":4242,\"source\":\"socket\"}"));
    }

    #[test]
    fn a_block_naming_no_process_never_reaches_the_wire() {
        // A resolver hands back `None` for a pid of 0, and the builder
        // refuses one anyway: a surface showing "pid 0" is the one failure
        // this whole field exists to prevent.
        let zeroed = Some(crate::workload::entity::Workload {
            pid: 0,
            source: crate::workload::entity::WorkloadSource::Socket,
            exe: None,
            uid: None,
            cgroup: None,
            container: None,
            image: None,
            pod: None,
            namespace: None,
            service_account: None,
            unit: None,
        });
        let alert =
            Alert::from_dlp_alert(&sample_dlp_alert(), "Visa card detected").with_workload(zeroed);
        assert!(alert.workload.is_none());
        assert!(!serde_json::to_string(&alert).unwrap().contains("workload"));
    }

    #[test]
    fn a_dlp_alert_without_a_flow_keeps_its_addresses_zeroed() {
        let dlp = sample_dlp_alert();
        let alert = Alert::from_dlp_alert(&dlp, "Visa card detected");

        // Zeroed addresses with no `flow_source` is the alert saying it does
        // not know where the data went, which a reader must not confuse with
        // a connection to 0.0.0.0.
        assert_eq!(alert.dst_ip(), 0);
        assert_eq!(alert.dst_port, 0);
        assert!(alert.flow_source.is_none());
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
            container: None,
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
            container: None,
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
            container: None,
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
            container: None,
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
            ja4_fingerprint: None,
            container: None,
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
        // dst_port=443 → T1499.002 (Service Exhaustion Flood)
        assert_eq!(
            alert.mitre_attack.as_ref().unwrap().technique_id,
            "T1499.002"
        );
    }

    #[test]
    fn alert_from_l7_psa() {
        let psa = sample_psa(PacketAlertComponent::L7, "reject");
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "l7");
        assert_eq!(alert.action, DomainMode::Block);
        // dst_port=443 → T1071.001 (Web Protocols)
        assert_eq!(
            alert.mitre_attack.as_ref().unwrap().technique_id,
            "T1071.001"
        );
    }

    #[test]
    fn alert_from_ips_psa() {
        let psa = sample_psa(PacketAlertComponent::Ips, "blacklist");
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "ips");
        assert_eq!(alert.action, DomainMode::Block);
        // dst_port=443 → T1190 (Exploit Public-Facing Application)
        assert_eq!(alert.mitre_attack.as_ref().unwrap().technique_id, "T1190");
    }

    #[test]
    fn alert_from_ips_ssh_psa() {
        let mut psa = sample_psa(PacketAlertComponent::Ips, "blacklist");
        psa.dst_port = 22;
        let alert = Alert::from_packet_security_alert(&psa);

        assert_eq!(alert.component, "ips");
        // dst_port=22 → T1110.001 (Password Guessing)
        assert_eq!(
            alert.mitre_attack.as_ref().unwrap().technique_id,
            "T1110.001"
        );
    }
}

#[cfg(test)]
mod id_uniqueness_tests {
    use super::*;

    #[test]
    fn two_alerts_sharing_a_timestamp_and_rule_get_distinct_ids() {
        // The kernel can stamp two distinct events with the same nanosecond;
        // the store is keyed by id, so a collision loses one of them.
        let a = Alert::generate_id(1_000, &RuleId("ids-001".to_string()));
        let b = Alert::generate_id(1_000, &RuleId("ids-001".to_string()));
        assert_ne!(a, b, "ids collided: {a}");
    }

    #[test]
    fn the_id_still_starts_with_timestamp_and_rule() {
        let id = Alert::generate_id(42, &RuleId("ids-001".to_string()));
        assert!(id.starts_with("42-ids-001-"), "unexpected id shape: {id}");
    }
}

#[cfg(test)]
mod operational_tests {
    use super::*;

    #[test]
    fn an_alert_about_the_agent_carries_no_flow() {
        let alert = Alert::operational(
            "routing",
            "routing-wan-all-down",
            Severity::Critical,
            "every gateway is down".to_string(),
            1_000,
        );
        assert_eq!(alert.src_addr, [0; 4]);
        assert_eq!(alert.dst_addr, [0; 4]);
        assert_eq!(alert.src_port, 0);
        assert_eq!(alert.dst_port, 0);
        assert_eq!(alert.protocol, 0);
        assert!(!alert.is_ipv6);
        assert!(alert.mitre_attack.is_none(), "no technique produced this");
        assert_eq!(alert.action, DomainMode::Alert);
    }

    #[test]
    fn the_gateway_alert_is_the_operational_one_it_always_was() {
        let alert = Alert::wan_all_down(&["gw0".to_string(), "gw1".to_string()], 7);
        assert_eq!(alert.component, "routing");
        assert_eq!(alert.rule_id.0, "routing-wan-all-down");
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.message, "all 2 WAN gateway(s) down: gw0, gw1");
        assert_eq!(alert.timestamp_ns, 7);
    }
}
