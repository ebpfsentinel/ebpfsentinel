use std::sync::Arc;

use domain::common::error::DomainError;
use domain::nat::entity::NatRule;
use ports::secondary::metrics_port::MetricsPort;
use ports::secondary::nat_map_port::NatMapPort;

/// Application-level NAT service.
///
/// Orchestrates NAT rules and eBPF map synchronisation.
/// Designed to be wrapped in `RwLock` for shared access from HTTP handlers.
pub struct NatAppService {
    dnat_rules: Vec<NatRule>,
    snat_rules: Vec<NatRule>,
    map_port: Option<Box<dyn NatMapPort + Send>>,
    metrics: Arc<dyn MetricsPort>,
    enabled: bool,
}

impl NatAppService {
    pub fn new(metrics: Arc<dyn MetricsPort>) -> Self {
        Self {
            dnat_rules: Vec::new(),
            snat_rules: Vec::new(),
            map_port: None,
            metrics,
            enabled: false,
        }
    }

    /// Return whether NAT is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state. Disabling sets rule counts to 0 in eBPF.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled
            && let Some(ref mut port) = self.map_port
            && let Err(e) = port.set_enabled(false)
        {
            tracing::warn!("failed to disable NAT in eBPF: {e}");
        }
    }

    /// Set the eBPF map port for kernel map synchronisation.
    pub fn set_map_port(&mut self, port: Box<dyn NatMapPort + Send>) {
        self.map_port = Some(port);
    }

    /// Reload DNAT rules. Validates and syncs to eBPF.
    pub fn reload_dnat_rules(&mut self, rules: Vec<NatRule>) -> Result<(), DomainError> {
        for rule in &rules {
            rule.validate()
                .map_err(|e| DomainError::InvalidRule(e.to_string()))?;
        }
        self.dnat_rules = rules;
        self.sync_ebpf_dnat();
        self.update_metrics();
        Ok(())
    }

    /// Reload SNAT rules. Validates and syncs to eBPF.
    pub fn reload_snat_rules(&mut self, rules: Vec<NatRule>) -> Result<(), DomainError> {
        for rule in &rules {
            rule.validate()
                .map_err(|e| DomainError::InvalidRule(e.to_string()))?;
        }
        self.snat_rules = rules;
        self.sync_ebpf_snat();
        self.update_metrics();
        Ok(())
    }

    /// List all DNAT rules.
    pub fn dnat_rules(&self) -> &[NatRule] {
        &self.dnat_rules
    }

    /// List all SNAT rules.
    pub fn snat_rules(&self) -> &[NatRule] {
        &self.snat_rules
    }

    /// Return the total number of active NAT rules.
    pub fn rule_count(&self) -> usize {
        self.dnat_rules.len() + self.snat_rules.len()
    }

    fn sync_ebpf_dnat(&mut self) {
        let Some(ref mut port) = self.map_port else {
            return;
        };

        let enabled_rules: Vec<&NatRule> = self.dnat_rules.iter().filter(|r| r.enabled).collect();

        let v4_entries: Vec<ebpf_common::nat::NatRuleEntry> = enabled_rules
            .iter()
            .filter(|r| !is_v6_rule(r))
            .map(|r| nat_rule_to_ebpf_entry(r))
            .collect();

        let v6_entries: Vec<ebpf_common::nat::NatRuleEntryV6> = enabled_rules
            .iter()
            .filter(|r| is_v6_rule(r))
            .map(|r| nat_rule_to_ebpf_entry_v6(r))
            .collect();

        if let Err(e) = port.load_dnat_rules(&v4_entries) {
            tracing::warn!("failed to load DNAT V4 rules into eBPF: {e}");
        }
        if let Err(e) = port.load_dnat_rules_v6(&v6_entries) {
            tracing::warn!("failed to load DNAT V6 rules into eBPF: {e}");
        }
    }

    fn sync_ebpf_snat(&mut self) {
        let Some(ref mut port) = self.map_port else {
            return;
        };

        let enabled_rules: Vec<&NatRule> = self.snat_rules.iter().filter(|r| r.enabled).collect();

        let v4_entries: Vec<ebpf_common::nat::NatRuleEntry> = enabled_rules
            .iter()
            .filter(|r| !is_v6_rule(r))
            .map(|r| nat_rule_to_ebpf_entry(r))
            .collect();

        let v6_entries: Vec<ebpf_common::nat::NatRuleEntryV6> = enabled_rules
            .iter()
            .filter(|r| is_v6_rule(r))
            .map(|r| nat_rule_to_ebpf_entry_v6(r))
            .collect();

        if let Err(e) = port.load_snat_rules(&v4_entries) {
            tracing::warn!("failed to load SNAT V4 rules into eBPF: {e}");
        }
        if let Err(e) = port.load_snat_rules_v6(&v6_entries) {
            tracing::warn!("failed to load SNAT V6 rules into eBPF: {e}");
        }
    }

    fn update_metrics(&self) {
        self.metrics
            .set_rules_loaded("nat", self.rule_count() as u64);
    }
}

/// Convert a domain `NatRule` to an eBPF `NatRuleEntry`.
#[allow(clippy::too_many_lines)]
fn nat_rule_to_ebpf_entry(rule: &NatRule) -> ebpf_common::nat::NatRuleEntry {
    use domain::nat::entity::NatType;
    use ebpf_common::nat::{
        NAT_MATCH_DST_IP, NAT_MATCH_DST_PORT, NAT_MATCH_PROTO, NAT_MATCH_SRC_IP, NAT_TYPE_DNAT,
        NAT_TYPE_MASQUERADE, NAT_TYPE_NONE, NAT_TYPE_ONETOONE, NAT_TYPE_REDIRECT, NAT_TYPE_SNAT,
        NatRuleEntry,
    };
    use std::net::IpAddr;

    let mut entry = NatRuleEntry {
        match_src_ip: 0,
        match_src_mask: 0,
        match_dst_ip: 0,
        match_dst_mask: 0,
        match_dst_port_start: 0,
        match_dst_port_end: 0,
        match_protocol: 0,
        match_flags: 0,
        nat_type: NAT_TYPE_NONE,
        _pad: 0,
        nat_addr: 0,
        nat_port_start: 0,
        nat_port_end: 0,
        nat_interface: 0,
        _pad2: [0; 4],
    };

    // Set match criteria
    if let Some(ref src_cidr) = rule.match_src
        && let Some((ip, mask)) = parse_cidr_to_ip_mask(src_cidr)
    {
        entry.match_src_ip = ip;
        entry.match_src_mask = mask;
        entry.match_flags |= NAT_MATCH_SRC_IP;
    }

    if let Some(ref dst_cidr) = rule.match_dst
        && let Some((ip, mask)) = parse_cidr_to_ip_mask(dst_cidr)
    {
        entry.match_dst_ip = ip;
        entry.match_dst_mask = mask;
        entry.match_flags |= NAT_MATCH_DST_IP;
    }

    if let Some(ref port_range) = rule.match_dst_port {
        entry.match_dst_port_start = port_range.start;
        entry.match_dst_port_end = port_range.end;
        entry.match_flags |= NAT_MATCH_DST_PORT;
    }

    if let Some(ref proto_str) = rule.match_protocol {
        let proto = match proto_str.to_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            "icmp" => 1,
            _ => 0,
        };
        if proto > 0 {
            entry.match_protocol = proto;
            entry.match_flags |= NAT_MATCH_PROTO;
        }
    }

    // Set NAT type and translated values
    match &rule.nat_type {
        NatType::Snat { addr, port_range } => {
            entry.nat_type = NAT_TYPE_SNAT;
            if let IpAddr::V4(v4) = addr {
                entry.nat_addr = u32::from(*v4);
            }
            if let Some(range) = port_range {
                entry.nat_port_start = range.start;
                entry.nat_port_end = range.end;
            }
        }
        NatType::Dnat { addr, port } => {
            entry.nat_type = NAT_TYPE_DNAT;
            if let IpAddr::V4(v4) = addr {
                entry.nat_addr = u32::from(*v4);
            }
            if let Some(p) = port {
                entry.nat_port_start = *p;
                entry.nat_port_end = *p;
            }
        }
        NatType::Masquerade { port_range, .. } => {
            entry.nat_type = NAT_TYPE_MASQUERADE;
            if let Some(range) = port_range {
                entry.nat_port_start = range.start;
                entry.nat_port_end = range.end;
            }
        }
        NatType::OneToOne {
            external, internal, ..
        } => {
            entry.nat_type = NAT_TYPE_ONETOONE;
            if let IpAddr::V4(v4) = external {
                entry.match_dst_ip = u32::from(*v4);
                entry.match_dst_mask = 0xFFFF_FFFF;
                entry.match_flags |= NAT_MATCH_DST_IP;
            }
            if let IpAddr::V4(v4) = internal {
                entry.nat_addr = u32::from(*v4);
            }
        }
        NatType::Redirect { port } => {
            entry.nat_type = NAT_TYPE_REDIRECT;
            entry.nat_port_start = *port;
            entry.nat_port_end = *port;
        }
        NatType::PortForward {
            ext_port,
            int_addr,
            int_port,
        } => {
            entry.nat_type = NAT_TYPE_DNAT;
            entry.match_dst_port_start = ext_port.start;
            entry.match_dst_port_end = ext_port.end;
            entry.match_flags |= NAT_MATCH_DST_PORT;
            if let IpAddr::V4(v4) = int_addr {
                entry.nat_addr = u32::from(*v4);
            }
            entry.nat_port_start = int_port.start;
            entry.nat_port_end = int_port.end;
        }
    }

    entry
}

/// Parse a CIDR string like "192.168.0.0/16" to (ip, mask) in host byte order.
fn parse_cidr_to_ip_mask(cidr: &str) -> Option<(u32, u32)> {
    let (ip_str, prefix_str) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    let prefix_len: u32 = prefix_str.parse().ok()?;
    let mask = if prefix_len == 0 {
        0
    } else {
        !0u32 << (32 - prefix_len)
    };
    Some((u32::from(ip), mask))
}

/// Determine if a NAT rule targets IPv6 addresses.
fn is_v6_rule(rule: &NatRule) -> bool {
    use domain::nat::entity::NatType;
    use std::net::IpAddr;

    // Check NAT type addresses
    match &rule.nat_type {
        NatType::Snat { addr, .. } | NatType::Dnat { addr, .. } => {
            if matches!(addr, IpAddr::V6(_)) {
                return true;
            }
        }
        NatType::OneToOne {
            external, internal, ..
        } => {
            if matches!(external, IpAddr::V6(_)) || matches!(internal, IpAddr::V6(_)) {
                return true;
            }
        }
        NatType::PortForward { int_addr, .. } => {
            if matches!(int_addr, IpAddr::V6(_)) {
                return true;
            }
        }
        NatType::Masquerade { .. } | NatType::Redirect { .. } => {}
    }

    // Check match CIDRs for IPv6 (contains ':')
    if let Some(ref src) = rule.match_src
        && src.contains(':')
    {
        return true;
    }
    if let Some(ref dst) = rule.match_dst
        && dst.contains(':')
    {}

    false
}

/// Convert a domain `NatRule` to an eBPF `NatRuleEntryV6`.
#[allow(clippy::too_many_lines)]
fn nat_rule_to_ebpf_entry_v6(rule: &NatRule) -> ebpf_common::nat::NatRuleEntryV6 {
    use domain::nat::entity::NatType;
    use ebpf_common::nat::{
        NAT_MATCH_DST_IP, NAT_MATCH_DST_PORT, NAT_MATCH_PROTO, NAT_MATCH_SRC_IP, NAT_TYPE_DNAT,
        NAT_TYPE_MASQUERADE, NAT_TYPE_NONE, NAT_TYPE_ONETOONE, NAT_TYPE_REDIRECT, NAT_TYPE_SNAT,
        NatRuleEntryV6,
    };
    use std::net::IpAddr;

    let mut entry = NatRuleEntryV6 {
        match_src_addr: [0; 4],
        match_src_mask: [0; 4],
        match_dst_addr: [0; 4],
        match_dst_mask: [0; 4],
        match_dst_port_start: 0,
        match_dst_port_end: 0,
        match_protocol: 0,
        match_flags: 0,
        nat_type: NAT_TYPE_NONE,
        _pad: 0,
        nat_addr: [0; 4],
        nat_port_start: 0,
        nat_port_end: 0,
        nat_interface: 0,
    };

    // Set match criteria
    if let Some(ref src_cidr) = rule.match_src
        && let Some((addr, mask)) = parse_cidr_to_ipv6_addr_mask(src_cidr)
    {
        entry.match_src_addr = addr;
        entry.match_src_mask = mask;
        entry.match_flags |= NAT_MATCH_SRC_IP;
    }

    if let Some(ref dst_cidr) = rule.match_dst
        && let Some((addr, mask)) = parse_cidr_to_ipv6_addr_mask(dst_cidr)
    {
        entry.match_dst_addr = addr;
        entry.match_dst_mask = mask;
        entry.match_flags |= NAT_MATCH_DST_IP;
    }

    if let Some(ref port_range) = rule.match_dst_port {
        entry.match_dst_port_start = port_range.start;
        entry.match_dst_port_end = port_range.end;
        entry.match_flags |= NAT_MATCH_DST_PORT;
    }

    if let Some(ref proto_str) = rule.match_protocol {
        let proto = match proto_str.to_lowercase().as_str() {
            "tcp" => 6,
            "udp" => 17,
            "icmpv6" => 58,
            _ => 0,
        };
        if proto > 0 {
            entry.match_protocol = proto;
            entry.match_flags |= NAT_MATCH_PROTO;
        }
    }

    match &rule.nat_type {
        NatType::Snat { addr, port_range } => {
            entry.nat_type = NAT_TYPE_SNAT;
            if let IpAddr::V6(v6) = addr {
                entry.nat_addr = ipv6_to_u32x4(v6);
            }
            if let Some(range) = port_range {
                entry.nat_port_start = range.start;
                entry.nat_port_end = range.end;
            }
        }
        NatType::Dnat { addr, port } => {
            entry.nat_type = NAT_TYPE_DNAT;
            if let IpAddr::V6(v6) = addr {
                entry.nat_addr = ipv6_to_u32x4(v6);
            }
            if let Some(p) = port {
                entry.nat_port_start = *p;
                entry.nat_port_end = *p;
            }
        }
        NatType::Masquerade { port_range, .. } => {
            entry.nat_type = NAT_TYPE_MASQUERADE;
            if let Some(range) = port_range {
                entry.nat_port_start = range.start;
                entry.nat_port_end = range.end;
            }
        }
        NatType::OneToOne {
            external, internal, ..
        } => {
            entry.nat_type = NAT_TYPE_ONETOONE;
            if let IpAddr::V6(v6) = external {
                entry.match_dst_addr = ipv6_to_u32x4(v6);
                entry.match_dst_mask = [0xFFFF_FFFF; 4];
                entry.match_flags |= NAT_MATCH_DST_IP;
            }
            if let IpAddr::V6(v6) = internal {
                entry.nat_addr = ipv6_to_u32x4(v6);
            }
        }
        NatType::Redirect { port } => {
            entry.nat_type = NAT_TYPE_REDIRECT;
            entry.nat_port_start = *port;
            entry.nat_port_end = *port;
        }
        NatType::PortForward {
            ext_port,
            int_addr,
            int_port,
        } => {
            entry.nat_type = NAT_TYPE_DNAT;
            entry.match_dst_port_start = ext_port.start;
            entry.match_dst_port_end = ext_port.end;
            entry.match_flags |= NAT_MATCH_DST_PORT;
            if let IpAddr::V6(v6) = int_addr {
                entry.nat_addr = ipv6_to_u32x4(v6);
            }
            entry.nat_port_start = int_port.start;
            entry.nat_port_end = int_port.end;
        }
    }

    entry
}

/// Parse an IPv6 CIDR string like `2001:db8::/32` to (addr, mask) as `[u32; 4]`.
fn parse_cidr_to_ipv6_addr_mask(cidr: &str) -> Option<([u32; 4], [u32; 4])> {
    let (ip_str, prefix_str) = cidr.split_once('/').unwrap_or((cidr, "128"));
    let ip: std::net::Ipv6Addr = ip_str.parse().ok()?;
    let prefix_len: u32 = prefix_str.parse().ok()?;
    let addr = ipv6_to_u32x4(&ip);
    let mask = prefix_to_ipv6_mask(prefix_len);
    Some((addr, mask))
}

/// Convert an `Ipv6Addr` to `[u32; 4]` in network byte order words.
fn ipv6_to_u32x4(ip: &std::net::Ipv6Addr) -> [u32; 4] {
    let octets = ip.octets();
    [
        u32::from_be_bytes([octets[0], octets[1], octets[2], octets[3]]),
        u32::from_be_bytes([octets[4], octets[5], octets[6], octets[7]]),
        u32::from_be_bytes([octets[8], octets[9], octets[10], octets[11]]),
        u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]),
    ]
}

/// Convert a prefix length (0..128) to an IPv6 mask as `[u32; 4]`.
fn prefix_to_ipv6_mask(prefix_len: u32) -> [u32; 4] {
    let mut mask = [0u32; 4];
    let mut remaining = prefix_len.min(128);
    for word in &mut mask {
        if remaining >= 32 {
            *word = 0xFFFF_FFFF;
            remaining -= 32;
        } else if remaining > 0 {
            *word = !0u32 << (32 - remaining);
            remaining = 0;
        }
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::common::entity::RuleId;
    use domain::firewall::entity::PortRange;
    use domain::nat::entity::NatType;
    use ports::test_utils::NoopMetrics;

    fn make_service() -> NatAppService {
        NatAppService::new(Arc::new(NoopMetrics))
    }

    fn make_snat_rule(id: &str) -> NatRule {
        NatRule {
            id: RuleId(id.to_string()),
            priority: 10,
            nat_type: NatType::Snat {
                addr: "10.0.0.1".parse().unwrap(),
                port_range: None,
            },
            match_src: Some("192.168.0.0/16".to_string()),
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            enabled: true,
        }
    }

    fn make_dnat_rule(id: &str) -> NatRule {
        NatRule {
            id: RuleId(id.to_string()),
            priority: 10,
            nat_type: NatType::Dnat {
                addr: "10.0.1.10".parse().unwrap(),
                port: Some(80),
            },
            match_src: None,
            match_dst: None,
            match_dst_port: Some(PortRange {
                start: 8080,
                end: 8080,
            }),
            match_protocol: Some("tcp".to_string()),
            enabled: true,
        }
    }

    #[test]
    fn default_disabled() {
        let svc = make_service();
        assert!(!svc.enabled());
        assert_eq!(svc.rule_count(), 0);
    }

    #[test]
    fn reload_snat_rules() {
        let mut svc = make_service();
        svc.reload_snat_rules(vec![make_snat_rule("snat-1")])
            .unwrap();
        assert_eq!(svc.snat_rules().len(), 1);
        assert_eq!(svc.rule_count(), 1);
    }

    #[test]
    fn reload_dnat_rules() {
        let mut svc = make_service();
        svc.reload_dnat_rules(vec![make_dnat_rule("dnat-1")])
            .unwrap();
        assert_eq!(svc.dnat_rules().len(), 1);
        assert_eq!(svc.rule_count(), 1);
    }

    #[test]
    fn reload_replaces_rules() {
        let mut svc = make_service();
        svc.reload_snat_rules(vec![make_snat_rule("old")]).unwrap();
        svc.reload_snat_rules(vec![make_snat_rule("new-1"), make_snat_rule("new-2")])
            .unwrap();
        assert_eq!(svc.snat_rules().len(), 2);
    }

    #[test]
    fn enable_disable() {
        let mut svc = make_service();
        svc.set_enabled(true);
        assert!(svc.enabled());
        svc.set_enabled(false);
        assert!(!svc.enabled());
    }

    #[test]
    fn nat_rule_to_entry_snat() {
        let rule = make_snat_rule("test");
        let entry = nat_rule_to_ebpf_entry(&rule);
        assert_eq!(entry.nat_type, ebpf_common::nat::NAT_TYPE_SNAT);
        assert_ne!(entry.match_flags & ebpf_common::nat::NAT_MATCH_SRC_IP, 0);
    }

    #[test]
    fn nat_rule_to_entry_dnat() {
        let rule = make_dnat_rule("test");
        let entry = nat_rule_to_ebpf_entry(&rule);
        assert_eq!(entry.nat_type, ebpf_common::nat::NAT_TYPE_DNAT);
        assert_ne!(entry.match_flags & ebpf_common::nat::NAT_MATCH_DST_PORT, 0);
        assert_ne!(entry.match_flags & ebpf_common::nat::NAT_MATCH_PROTO, 0);
    }

    #[test]
    fn parse_cidr_to_ip_mask_works() {
        let (ip, mask) = parse_cidr_to_ip_mask("192.168.0.0/16").unwrap();
        assert_eq!(ip, u32::from(std::net::Ipv4Addr::new(192, 168, 0, 0)));
        assert_eq!(mask, 0xFFFF_0000);
    }

    #[test]
    fn parse_cidr_to_ip_mask_host() {
        let (ip, mask) = parse_cidr_to_ip_mask("10.0.0.1").unwrap();
        assert_eq!(ip, u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(mask, 0xFFFF_FFFF);
    }
}
