//! Firewall domain configuration structs and conversion logic.

use std::collections::HashMap;

use domain::common::entity::RuleId;
use domain::firewall::entity::{FirewallAction, FirewallRule, PortRange, Scope as DomainScope};
use domain::firewall::fqdn::{DEFAULT_GRACE_SECS, FqdnPattern, WorkloadDnsSettings};
use domain::firewall::workload::{
    KubernetesMatchers, WorkloadMatch, WorkloadMode, WorkloadSelector,
};
use domain::netpol::LabelSelector;
use serde::{Deserialize, Serialize};

use super::alias::AliasConfig;

use super::common::{
    ConfigError, default_mode, default_true, parse_action, parse_cidr, parse_ct_state,
    parse_protocol,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_mode")]
    pub mode: String,

    #[serde(default)]
    pub default_policy: DefaultPolicy,

    #[serde(default)]
    pub rules: Vec<FirewallRuleConfig>,

    /// Named aliases for IP sets, port sets, URL tables, `GeoIP`, etc.
    #[serde(default)]
    pub aliases: HashMap<String, AliasConfig>,

    /// Anti-lockout rule configuration.
    #[serde(default)]
    pub anti_lockout: AntiLockoutConfig,

    /// Scrub (packet normalization) configuration.
    #[serde(default)]
    pub scrub: ScrubConfig,

    /// Schedules for time-based rule activation.
    #[serde(default)]
    pub schedules: HashMap<String, ScheduleConfig>,

    /// The resolvers whose answers open the destinations workload rules
    /// name by DNS name.
    #[serde(default)]
    pub workload_dns: WorkloadDnsConfig,
}

// ── Workload DNS config ────────────────────────────────────────────

/// Who an answer is believed from when a workload rule names a destination by
/// DNS name, and how long past its TTL the address stays open.
///
/// Strict for the same reason the workload block is: a misspelled
/// `resolvers` is a policy whose every name stays closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadDnsConfig {
    /// Resolver addresses or networks, such as the cluster DNS Service.
    #[serde(default)]
    pub resolvers: Vec<String>,

    /// Seconds an address stays open past its record's TTL, at most 300.
    #[serde(default = "default_workload_dns_grace")]
    pub grace_secs: u32,
}

impl Default for WorkloadDnsConfig {
    fn default() -> Self {
        Self {
            resolvers: Vec::new(),
            grace_secs: DEFAULT_GRACE_SECS,
        }
    }
}

fn default_workload_dns_grace() -> u32 {
    DEFAULT_GRACE_SECS
}

impl WorkloadDnsConfig {
    /// Read the block into the domain's settings.
    pub fn to_domain(&self) -> Result<WorkloadDnsSettings, ConfigError> {
        let resolvers = self
            .resolvers
            .iter()
            .enumerate()
            .map(|(idx, value)| {
                parse_cidr(value).map_err(|_| ConfigError::InvalidValue {
                    field: format!("firewall.workload_dns.resolvers[{idx}]"),
                    value: value.clone(),
                    expected: "an IP address or a CIDR".to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let settings = WorkloadDnsSettings {
            resolvers,
            grace_secs: self.grace_secs,
        };
        settings.validate().map_err(|e| ConfigError::Validation {
            field: "firewall.workload_dns".to_string(),
            message: e.to_string(),
        })?;
        Ok(settings)
    }
}

impl FirewallConfig {
    /// Whether any rule in this section forges a refusal rather than dropping
    /// in silence.
    ///
    /// The reject program keeps a per-source throttle table so a forged RST
    /// or ICMP message cannot itself become the flood. A section that names
    /// no such rule never reaches that program, so the table it would fill is
    /// sized down at the next start. The vocabulary is `parse_action`'s, read
    /// through it rather than restated, because a word admitted there and not
    /// here would size a table the datapath then fills.
    #[must_use]
    pub fn forges_a_refusal(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| matches!(parse_action(&rule.action), Ok(FirewallAction::Reject)))
    }
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "alert".to_string(),
            default_policy: DefaultPolicy::Pass,
            rules: Vec::new(),
            aliases: HashMap::new(),
            anti_lockout: AntiLockoutConfig::default(),
            scrub: ScrubConfig::default(),
            schedules: HashMap::new(),
            workload_dns: WorkloadDnsConfig::default(),
        }
    }
}

// ── Anti-lockout config ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiLockoutConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Management interfaces (e.g. `["eth0"]`).
    #[serde(default)]
    pub interfaces: Vec<String>,
    /// Management ports beyond the agent's own API ports, which are always
    /// kept open (e.g. `[22]`).
    #[serde(default = "default_anti_lockout_ports")]
    pub ports: Vec<u16>,
}

fn default_anti_lockout_ports() -> Vec<u16> {
    vec![22]
}

impl Default for AntiLockoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interfaces: Vec::new(),
            ports: default_anti_lockout_ports(),
        }
    }
}

// ── Scrub config ────────────────────────────────────────────────────

#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScrubConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ttl: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_mss: Option<u16>,
    #[serde(default)]
    pub random_ip_id: bool,
    #[serde(default)]
    pub clear_df: bool,
    /// Minimum IPv6 Hop Limit to enforce. 0 or `None` means no enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_hop_limit: Option<u8>,
    /// Clear TCP reserved bits (NS/CWR/ECE) to prevent OS fingerprinting.
    /// CWR/ECE only cleared on non-SYN packets to preserve ECN negotiation.
    #[serde(default)]
    pub scrub_tcp_flags: bool,
    /// Clear ECN bits (2 LSBs) in IPv4 TOS / IPv6 Traffic Class.
    #[serde(default)]
    pub strip_ecn: bool,
    /// Normalize TOS/DSCP field to a specific value.
    #[serde(default)]
    pub normalize_tos: bool,
    /// Target TOS value for normalization (default 0 = best effort).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tos_value: Option<u8>,
    /// Remove TCP timestamp option (kind=8, len=10) to prevent OS fingerprinting.
    #[serde(default)]
    pub strip_tcp_timestamps: bool,
    /// Drop IPv4 fragments (MF set or non-zero fragment offset). Refusing
    /// fragments closes a classic inspection-evasion vector.
    #[serde(default)]
    pub drop_fragments: bool,
}

// ── Schedule config ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleConfig {
    pub entries: Vec<ScheduleEntryConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleEntryConfig {
    pub days: Vec<String>,
    pub time: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultPolicy {
    #[default]
    Pass,
    Drop,
}

// ── Firewall rule config (YAML-friendly) ───────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRuleConfig {
    pub id: String,

    #[serde(default = "default_true")]
    pub enabled: bool,

    pub priority: u32,

    pub action: String,

    #[serde(default = "default_protocol")]
    pub protocol: String,

    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,

    pub src_port: Option<PortRangeConfig>,
    pub dst_port: Option<PortRangeConfig>,

    #[serde(default)]
    pub scope: ScopeConfig,

    /// Optional 802.1Q VLAN ID filter (None = match any VLAN).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,

    /// Source IP set alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_alias: Option<String>,

    /// Destination IP set alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_alias: Option<String>,

    /// Source port set alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_port_alias: Option<String>,

    /// Destination port set alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port_alias: Option<String>,

    /// Source MAC set alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_mac_alias: Option<String>,

    /// Destination MAC set alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_mac_alias: Option<String>,

    /// Conntrack state filter (e.g. `[established, related]`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<Vec<String>>,

    // ── Extended fields (Epics 24-31) ───────────────────────────────
    /// TCP flags specification (e.g. `"S/SA"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,

    /// ICMP type to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<u8>,

    /// ICMP code to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<u8>,

    /// Negate source IP match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negate_source: Option<bool>,

    /// Negate destination IP match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negate_destination: Option<bool>,

    /// DSCP value to match (0-63).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dscp_match: Option<u8>,

    /// DSCP value to mark on matched packets (0-63).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dscp_mark: Option<u8>,

    /// Maximum concurrent states for this rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_states: Option<u16>,

    /// Source MAC address (e.g. `"aa:bb:cc:dd:ee:ff"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_mac: Option<String>,

    /// Destination MAC address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_mac: Option<String>,

    /// Schedule name for time-based activation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,

    /// Interface groups this rule applies to. Empty = all (floating).
    /// Prefix with "!" for inversion (e.g., `"!lan"` = all except lan).
    #[serde(default)]
    pub interfaces: Vec<String>,

    /// Tenant this rule belongs to. 0 (the default) is global and applies to
    /// every tenant, which is all a standalone agent resolves.
    #[serde(default)]
    pub tenant_id: u32,

    /// Which workload this rule is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<WorkloadMatchConfig>,
}

// ── Workload match config ──────────────────────────────────────────

/// The workload half of a rule as a document writes it.
///
/// `deny_unknown_fields` is deliberate and is not what the rest of this file
/// does. A misspelled key here is a rule that silently stops naming the
/// workload it was written for, and the document still loads: the rule then
/// matches every workload or none, depending on which key was lost. That is
/// exactly the hole the strictness is for, and it is affordable on a block
/// nothing has written yet.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadMatchConfig {
    /// Absolute path of the executable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,

    /// systemd unit name, such as `nginx.service`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,

    /// Absolute cgroup v2 path, matching that cgroup and everything under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,

    /// Container id, an id prefix of at least twelve characters, or the name
    /// the runtime gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,

    /// Labels of the pod the task runs in, as `match_labels` and
    /// `match_expressions` with the Kubernetes meaning. `{}` names every pod
    /// on the node and no process outside one. Needs the Kubernetes enricher.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pods: Option<LabelSelector>,

    /// Labels of the pod's namespace, in the same shape. A namespace is named
    /// by its name through `kubernetes.io/metadata.name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<LabelSelector>,

    /// Name of the service account the pod runs as.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,

    /// `observe`, the default, or `enforce`. A rule says this for itself
    /// rather than inheriting it, because the first policy anybody writes is
    /// wrong and a kernel refusing a connection is not something a deployment
    /// should walk into.
    #[serde(default = "default_workload_mode")]
    pub mode: String,

    /// Destinations named by DNS name, in place of `dst_ip`: an exact name or
    /// `*.domain` for one label under it. The addresses are learned from the
    /// answers this workload is given by `firewall.workload_dns.resolvers`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fqdn: Vec<String>,
}

fn default_workload_mode() -> String {
    WorkloadMode::Observe.as_str().to_string()
}

impl WorkloadMatchConfig {
    /// Read the block into the domain's selector and mode.
    ///
    /// `prefix` is the document path of the rule, so a refusal names the line
    /// somebody has to go and edit.
    pub fn to_domain(&self, prefix: &str) -> Result<WorkloadMatch, ConfigError> {
        let mode = WorkloadMode::parse(&self.mode).map_err(|value| ConfigError::InvalidValue {
            field: format!("{prefix}.workload.mode"),
            value: value.to_string(),
            expected: "observe, enforce".to_string(),
        })?;

        let selector = WorkloadSelector::with_kubernetes(
            self.exe.clone(),
            self.unit.clone(),
            self.cgroup.clone(),
            self.container.clone(),
            KubernetesMatchers {
                pods: self.pods.clone(),
                namespaces: self.namespaces.clone(),
                service_account: self.service_account.clone(),
            },
        )
        .map_err(|e| ConfigError::Validation {
            field: format!("{prefix}.workload"),
            message: e.to_string(),
        })?;

        let fqdn = self
            .fqdn
            .iter()
            .enumerate()
            .map(|(idx, raw)| {
                FqdnPattern::parse(raw).map_err(|e| ConfigError::Validation {
                    field: format!("{prefix}.workload.fqdn[{idx}]"),
                    message: e.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(WorkloadMatch {
            selector,
            mode,
            fqdn,
        })
    }
}

fn default_protocol() -> String {
    "any".to_string()
}

impl FirewallRuleConfig {
    /// Validate this rule config at the YAML level.
    pub(super) fn validate(&self, idx: usize) -> Result<(), ConfigError> {
        let prefix = format!("firewall.rules[{idx}]");

        if self.id.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.id"),
                message: "rule ID must not be empty".to_string(),
            });
        }

        parse_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.action"),
            value: self.action.clone(),
            expected: "allow, deny, log, reject".to_string(),
        })?;

        parse_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: format!("{prefix}.protocol"),
            value: self.protocol.clone(),
            expected: "tcp, udp, icmp, any".to_string(),
        })?;

        if let Some(ref cidr) = self.src_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }
        if let Some(ref cidr) = self.dst_ip {
            parse_cidr(cidr).map_err(|e| ConfigError::InvalidCidr {
                value: cidr.clone(),
                reason: e.to_string(),
            })?;
        }

        // Validate VLAN ID (802.1Q range: 0-4094)
        if let Some(vid) = self.vlan_id
            && vid > 4094
        {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.vlan_id"),
                message: format!("VLAN ID {vid} must be 0-4094"),
            });
        }

        // Validate conntrack state values
        if let Some(ref states) = self.state {
            for (i, state_str) in states.iter().enumerate() {
                parse_ct_state(state_str).map_err(|()| ConfigError::InvalidValue {
                    field: format!("{prefix}.state[{i}]"),
                    value: state_str.clone(),
                    expected: "new, established, related, invalid, syn_sent, syn_recv, fin_wait, close_wait, time_wait".to_string(),
                })?;
            }
        }

        if self.workload.is_some() {
            self.validate_workload(&prefix)?;
        }

        Ok(())
    }

    /// Check the workload block and everything that may not sit beside it.
    ///
    /// The second half is the domain's own rule rather than a copy of it: the
    /// rule is built and asked, so the list of matchers the socket hooks
    /// cannot decide is written once. It is built with the interface list
    /// emptied because resolving a group name needs the interface
    /// configuration, which this check does not have; the list itself is
    /// refused first and by name, since `interfaces` is the one of those
    /// matchers somebody would otherwise see reported as an unknown group.
    fn validate_workload(&self, prefix: &str) -> Result<(), ConfigError> {
        if let Some(ref workload) = self.workload {
            workload.to_domain(prefix)?;
        }

        if !self.interfaces.is_empty() {
            return Err(ConfigError::Validation {
                field: format!("{prefix}.interfaces"),
                message: "a rule naming a workload is decided in the socket hooks, where the \
                          connection has not been routed and no interface is chosen yet"
                    .to_string(),
            });
        }

        let mut without_interfaces = self.clone();
        without_interfaces.interfaces.clear();
        without_interfaces
            .to_domain_rule(&HashMap::new())
            .map_err(|e| ConfigError::Validation {
                field: prefix.to_string(),
                message: e.to_string(),
            })?;

        Ok(())
    }

    /// Convert to a domain `FirewallRule`. `group_bits` maps every configured
    /// interface-group name to its bit, so `interfaces` can be resolved into
    /// the mask the data plane compares against the arrival interface.
    #[allow(clippy::too_many_lines)]
    pub fn to_domain_rule(
        &self,
        group_bits: &HashMap<String, u32>,
    ) -> Result<FirewallRule, ConfigError> {
        let action = parse_action(&self.action).map_err(|()| ConfigError::InvalidValue {
            field: "action".to_string(),
            value: self.action.clone(),
            expected: "allow, deny, log, reject".to_string(),
        })?;

        let protocol = parse_protocol(&self.protocol).map_err(|()| ConfigError::InvalidValue {
            field: "protocol".to_string(),
            value: self.protocol.clone(),
            expected: "tcp, udp, icmp, any".to_string(),
        })?;

        let src_ip = self
            .src_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.src_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        let dst_ip = self
            .dst_ip
            .as_deref()
            .map(parse_cidr)
            .transpose()
            .map_err(|e| ConfigError::InvalidCidr {
                value: self.dst_ip.clone().unwrap_or_default(),
                reason: e.to_string(),
            })?;

        let src_port = self
            .src_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        let dst_port = self
            .dst_port
            .as_ref()
            .map(PortRangeConfig::to_domain)
            .transpose()?;

        let scope = self.scope.to_domain()?;

        let ct_states = self
            .state
            .as_ref()
            .map(|states| {
                states
                    .iter()
                    .map(|s| {
                        parse_ct_state(s).map_err(|()| ConfigError::InvalidValue {
                            field: "state".to_string(),
                            value: s.clone(),
                            expected: "new, established, related, invalid".to_string(),
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;

        let tcp_flags = self
            .flags
            .as_deref()
            .map(domain::firewall::entity::parse_tcp_flags)
            .transpose()
            .map_err(|e| ConfigError::Validation {
                field: "flags".to_string(),
                message: e.to_string(),
            })?;

        let icmp_type = self.icmp_type;
        let icmp_code = self.icmp_code;

        let src_mac = self
            .src_mac
            .as_deref()
            .map(domain::firewall::entity::parse_mac_address)
            .transpose()
            .map_err(|e| ConfigError::Validation {
                field: "src_mac".to_string(),
                message: e.to_string(),
            })?;

        let dst_mac = self
            .dst_mac
            .as_deref()
            .map(domain::firewall::entity::parse_mac_address)
            .transpose()
            .map_err(|e| ConfigError::Validation {
                field: "dst_mac".to_string(),
                message: e.to_string(),
            })?;

        let rule = FirewallRule {
            id: RuleId(self.id.clone()),
            enabled: self.enabled,
            priority: self.priority,
            action,
            protocol,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            scope,
            vlan_id: self.vlan_id,
            src_alias: self.src_alias.clone(),
            dst_alias: self.dst_alias.clone(),
            src_port_alias: self.src_port_alias.clone(),
            dst_port_alias: self.dst_port_alias.clone(),
            src_mac_alias: self.src_mac_alias.clone(),
            dst_mac_alias: self.dst_mac_alias.clone(),
            ct_states,
            tcp_flags,
            icmp_type,
            icmp_code,
            negate_src: self.negate_source.unwrap_or(false),
            negate_dst: self.negate_destination.unwrap_or(false),
            dscp_match: self.dscp_match,
            dscp_mark: self.dscp_mark,
            max_states: self.max_states,
            src_mac,
            dst_mac,
            schedule: self.schedule.clone(),
            system: false,
            group_mask: super::parse_group_mask(&self.interfaces, group_bits).map_err(
                |message| ConfigError::Validation {
                    field: "firewall.rules.interfaces".to_string(),
                    message,
                },
            )?,
            tenant_id: self.tenant_id,
            workload: self
                .workload
                .as_ref()
                .map(|workload| workload.to_domain("firewall.rules"))
                .transpose()?,
        };

        rule.validate_workload()
            .map_err(|e| ConfigError::Validation {
                field: format!("firewall.rules[{}]", self.id),
                message: e.to_string(),
            })?;

        Ok(rule)
    }
}

// ── Port range config ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PortRangeConfig {
    Single(u16),
    Range(String),
    Explicit { start: u16, end: u16 },
}

impl PortRangeConfig {
    pub fn to_domain(&self) -> Result<PortRange, ConfigError> {
        match self {
            Self::Single(port) => Ok(PortRange {
                start: *port,
                end: *port,
            }),
            Self::Range(s) => {
                // Accept a single port as a string (e.g. "9999") or a range "80-443"
                if let Ok(port) = s.trim().parse::<u16>() {
                    return Ok(PortRange {
                        start: port,
                        end: port,
                    });
                }
                let (start_str, end_str) =
                    s.split_once('-')
                        .ok_or_else(|| ConfigError::InvalidPortRange {
                            value: s.clone(),
                            reason: "expected format 'start-end' (e.g. '80-443')".to_string(),
                        })?;
                let start =
                    start_str
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| ConfigError::InvalidPortRange {
                            value: s.clone(),
                            reason: format!("invalid start port: '{start_str}'"),
                        })?;
                let end =
                    end_str
                        .trim()
                        .parse::<u16>()
                        .map_err(|_| ConfigError::InvalidPortRange {
                            value: s.clone(),
                            reason: format!("invalid end port: '{end_str}'"),
                        })?;
                if start > end {
                    return Err(ConfigError::InvalidPortRange {
                        value: s.clone(),
                        reason: format!("start ({start}) must be <= end ({end})"),
                    });
                }
                Ok(PortRange { start, end })
            }
            Self::Explicit { start, end } => {
                if start > end {
                    return Err(ConfigError::InvalidPortRange {
                        value: format!("{start}-{end}"),
                        reason: format!("start ({start}) must be <= end ({end})"),
                    });
                }
                Ok(PortRange {
                    start: *start,
                    end: *end,
                })
            }
        }
    }
}

// ── Scope config ───────────────────────────────────────────────────

/// Scope supports multiple YAML representations:
///   scope: global
///   scope: { interface: "eth0" }
///   scope: { namespace: "prod" }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScopeConfig {
    Simple(String),
    Map(ScopeMap),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeMap {
    pub interface: Option<String>,
    pub namespace: Option<String>,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self::Simple("global".to_string())
    }
}

impl ScopeConfig {
    /// Resolve the scope, applying the same length and character rules the
    /// API applies, so a value refused over HTTP is refused in a file too.
    pub fn to_domain(&self) -> Result<DomainScope, ConfigError> {
        let (field, value) = match self {
            Self::Simple(s) => ("scope", s.clone()),
            Self::Map(m) => {
                if let Some(ref iface) = m.interface {
                    ("scope.interface", format!("interface:{iface}"))
                } else if let Some(ref ns) = m.namespace {
                    ("scope.namespace", format!("namespace:{ns}"))
                } else {
                    return Ok(DomainScope::Global);
                }
            }
        };
        DomainScope::parse(&value).map_err(|e| ConfigError::InvalidValue {
            field: field.to_string(),
            value,
            expected: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Port range config ─────────────────────────────────────────

    #[test]
    fn to_domain_rule_carries_the_configured_tenant() {
        let rule: FirewallRuleConfig = serde_norway::from_str(
            r"
id: fw-tenant
priority: 10
action: deny
protocol: tcp
tenant_id: 4
",
        )
        .unwrap();

        let domain_rule = rule.to_domain_rule(&HashMap::new()).unwrap();
        assert_eq!(domain_rule.tenant_id, 4);
        assert_eq!(domain_rule.to_ebpf_entry().tenant_id, 4);
    }

    #[test]
    fn to_domain_rule_without_a_tenant_is_global() {
        let rule: FirewallRuleConfig = serde_norway::from_str(
            r"
id: fw-global
priority: 10
action: deny
protocol: tcp
",
        )
        .unwrap();

        assert_eq!(rule.to_domain_rule(&HashMap::new()).unwrap().tenant_id, 0);
    }

    // ── Workload matchers ─────────────────────────────────────────

    fn workload_rule(body: &str) -> FirewallRuleConfig {
        serde_norway::from_str(body).expect("the document parses")
    }

    #[test]
    fn a_rule_may_name_a_workload_and_no_address_at_all() {
        let rule = workload_rule(
            r"
id: fw-nginx
priority: 10
action: deny
workload:
  exe: /usr/sbin/nginx
",
        );

        rule.validate(0).expect("a valid rule");
        let domain_rule = rule.to_domain_rule(&HashMap::new()).expect("a domain rule");
        let workload = domain_rule.workload.expect("the workload half");

        assert_eq!(workload.selector.exe.as_deref(), Some("/usr/sbin/nginx"));
        assert_eq!(workload.mode, WorkloadMode::Observe);
        assert!(domain_rule.dst_ip.is_none());
    }

    #[test]
    fn a_rule_may_name_pods_namespaces_and_a_service_account() {
        let rule = workload_rule(
            r"
id: fw-payments-api
priority: 10
action: allow
workload:
  pods:
    match_labels:
      app: api
    match_expressions:
      - key: tier
        operator: In
        values: [front, edge]
  namespaces:
    match_labels:
      kubernetes.io/metadata.name: payments
  service_account: api
",
        );

        rule.validate(0).expect("a valid rule");
        let domain_rule = rule.to_domain_rule(&HashMap::new()).expect("a domain rule");
        let selector = domain_rule.workload.expect("the workload half").selector;
        assert_eq!(
            selector.describe(),
            "service_account=api pods={app=api,tier in (front,edge)} \
             namespaces={kubernetes.io/metadata.name=payments}"
        );
    }

    #[test]
    fn a_label_selector_the_api_server_refuses_names_the_rule() {
        let rule = workload_rule(
            r"
id: fw-broken
priority: 10
action: deny
workload:
  pods:
    match_expressions:
      - key: tier
        operator: In
",
        );
        let err = rule
            .to_domain_rule(&HashMap::new())
            .expect_err("a requirement without values is refused");
        assert!(err.to_string().contains("pods"), "{err}");
    }

    #[test]
    fn a_rule_naming_a_workload_and_a_destination_keeps_both() {
        let rule = workload_rule(
            r"
id: fw-nginx-db
priority: 10
action: deny
protocol: tcp
dst_ip: 10.0.0.0/8
dst_port: 5432
workload:
  unit: nginx.service
  mode: enforce
",
        );

        rule.validate(0).expect("a valid rule");
        let domain_rule = rule.to_domain_rule(&HashMap::new()).expect("a domain rule");

        assert!(domain_rule.dst_ip.is_some());
        assert_eq!(
            domain_rule.workload.expect("the workload half").mode,
            WorkloadMode::Enforce
        );
    }

    #[test]
    fn a_misspelled_matcher_fails_the_document_rather_than_being_ignored() {
        // The quiet reading is the dangerous one: the rule would load naming
        // no workload, and a deny would then be about every workload there is.
        let refused: Result<FirewallRuleConfig, _> = serde_norway::from_str(
            r"
id: fw-typo
priority: 10
action: deny
workload:
  exec: /usr/sbin/nginx
",
        );

        assert!(refused.is_err());
    }

    #[test]
    fn a_workload_block_naming_nothing_is_refused() {
        let rule = workload_rule(
            r"
id: fw-empty
priority: 10
action: deny
workload:
  mode: enforce
",
        );

        assert!(rule.validate(0).is_err());
    }

    #[test]
    fn a_mode_nobody_defined_is_refused_with_both_words() {
        let rule = workload_rule(
            r"
id: fw-mode
priority: 10
action: deny
workload:
  exe: /usr/sbin/nginx
  mode: block
",
        );

        let refused = rule.validate(0).expect_err("an unknown mode");

        assert!(format!("{refused}").contains("observe, enforce"));
    }

    #[test]
    fn a_matcher_the_socket_hooks_cannot_decide_fails_the_document() {
        for beside in [
            "src_ip: 10.0.0.0/8",
            "src_port: 1024",
            "vlan_id: 10",
            "state: [established]",
            "dscp_match: 46",
            "interfaces: [lan]",
        ] {
            let rule = workload_rule(&format!(
                r"
id: fw-unsupported
priority: 10
action: deny
{beside}
workload:
  exe: /usr/sbin/nginx
"
            ));

            assert!(
                rule.validate(0).is_err(),
                "{beside} should be refused beside a workload"
            );
        }
    }

    #[test]
    fn reject_is_refused_on_a_workload_rule_because_there_is_nothing_to_answer() {
        let rule = workload_rule(
            r"
id: fw-reject
priority: 10
action: reject
workload:
  exe: /usr/sbin/nginx
",
        );

        assert!(rule.validate(0).is_err());
        assert!(rule.to_domain_rule(&HashMap::new()).is_err());
    }

    #[test]
    fn the_same_matchers_are_still_fine_on_a_rule_naming_no_workload() {
        let rule = workload_rule(
            r"
id: fw-address
priority: 10
action: reject
src_ip: 10.0.0.0/8
vlan_id: 10
",
        );

        rule.validate(0).expect("an ordinary address rule");
    }

    #[test]
    fn port_range_single() {
        let pr = PortRangeConfig::Single(80).to_domain().unwrap();
        assert_eq!(pr.start, 80);
        assert_eq!(pr.end, 80);
    }

    #[test]
    fn port_range_string() {
        let pr = PortRangeConfig::Range("80-443".to_string())
            .to_domain()
            .unwrap();
        assert_eq!(pr.start, 80);
        assert_eq!(pr.end, 443);
    }

    #[test]
    fn port_range_explicit() {
        let pr = PortRangeConfig::Explicit {
            start: 1024,
            end: 65535,
        }
        .to_domain()
        .unwrap();
        assert_eq!(pr.start, 1024);
        assert_eq!(pr.end, 65535);
    }

    #[test]
    fn port_range_invalid_inverted() {
        assert!(
            PortRangeConfig::Range("443-80".to_string())
                .to_domain()
                .is_err()
        );
        assert!(
            PortRangeConfig::Explicit {
                start: 443,
                end: 80
            }
            .to_domain()
            .is_err()
        );
    }

    #[test]
    fn port_range_invalid_format() {
        assert!(
            PortRangeConfig::Range("not-a-range".to_string())
                .to_domain()
                .is_err()
        );
    }

    // ── Scope config ──────────────────────────────────────────────

    #[test]
    fn scope_defaults_to_global() {
        let scope = ScopeConfig::default();
        assert!(matches!(scope.to_domain(), Ok(DomainScope::Global)));
    }

    #[test]
    fn a_scope_a_file_names_is_held_to_the_rules_the_api_applies() {
        let scope = ScopeConfig::Simple("../../../etc".to_string());
        assert!(scope.to_domain().is_err());

        let scope = ScopeConfig::Map(ScopeMap {
            interface: Some("this_is_way_too_long_a_name".to_string()),
            namespace: None,
        });
        assert!(scope.to_domain().is_err());

        let scope = ScopeConfig::Map(ScopeMap {
            interface: None,
            namespace: Some("UPPER".to_string()),
        });
        assert!(scope.to_domain().is_err());
    }

    #[test]
    fn a_scope_a_file_names_is_accepted_in_each_of_its_forms() {
        assert!(matches!(
            ScopeConfig::Simple("eth0".to_string()).to_domain(),
            Ok(DomainScope::Interface(_))
        ));
        assert!(matches!(
            ScopeConfig::Map(ScopeMap {
                interface: None,
                namespace: Some("prod".to_string()),
            })
            .to_domain(),
            Ok(DomainScope::Namespace(_))
        ));
    }
}
