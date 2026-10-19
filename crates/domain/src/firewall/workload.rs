//! A firewall rule that names a workload, and what it is allowed to reach.
//!
//! The address matchers answer "from where to where". They cannot answer the
//! question a host firewall is actually asked, which is "which program on
//! this node may leave it, and for what". A selector is that half of the
//! rule: an executable, a systemd unit, a cgroup or a container, any
//! combination of the four, all of them narrowing together.
//!
//! Three decisions are written into the types rather than left to a caller.
//!
//! A selector with no address matcher beside it is legal and means what it
//! reads: this workload, anywhere. A selector with one is an intersection,
//! so a rule refusing `nginx` to `10.0.0.0/8` refuses nothing else. Products
//! disagree about which of the two the empty case means, and an operator who
//! guesses wrong gets either a hole or an outage, so both are asserted here.
//!
//! A matcher that is set and a fact that is absent never match. The agent
//! cannot always see which unit a task belongs to or which image it came
//! from, and a rule that fires on "we do not know" would refuse traffic for
//! a reason nobody can read afterwards. The cost is the other direction: an
//! enforcing deny-by-default policy leaks for whatever the agent failed to
//! resolve, which is why the counters say how often that happened.
//!
//! [`WorkloadMode::Observe`] is the default and the rule it carries decides
//! nothing. Enforcement is written down per rule, the same way the intrusion
//! engine distinguishes detecting from blocking, because the first policy
//! anybody writes is wrong and the kernel refusing a `connect()` is not a
//! thing a deployment should walk into.

use serde::{Deserialize, Serialize};

use ebpf_common::workload_policy::WORKLOAD_POLICY_MAX_RULES;

use crate::common::entity::{Protocol, RuleId};

use super::entity::{FirewallAction, FirewallRule, IpNetwork, PortRange};
use super::error::FirewallError;

/// Longest value one matcher may carry.
///
/// A path on Linux is bounded at 4096 bytes and a unit name at 256, so this
/// is the path bound and the rest sit well inside it. The bound exists so a
/// document cannot make the kernel-side table unbounded by way of a rule
/// nobody reads.
pub const WORKLOAD_MATCHER_MAX_LEN: usize = 4096;

/// The shortest container id prefix a matcher may be written as.
///
/// Runtimes print twelve characters and people copy what they are shown. A
/// shorter prefix than that starts matching containers nobody meant, so it
/// is refused rather than accepted and warned about.
pub const CONTAINER_ID_MIN_PREFIX: usize = 12;

/// Which program, unit, cgroup or container a rule is about.
///
/// Every matcher that is set has to match. None of them being set is not a
/// selector at all and is refused by the constructor, because the rule it
/// would make is "every workload", which is the address-only rule the
/// language already has.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WorkloadSelector {
    /// Absolute path of the executable, compared exactly.
    ///
    /// A path is what the task's own `/proc/<pid>/exe` points at, and it is
    /// forgeable: a process that can write a binary somewhere and exec it
    /// under a name a rule allows is allowed by that rule. Closing that
    /// needs the hash of the mapped file, which this build does not compute,
    /// so a path matcher is a statement about the name and not about the
    /// bytes behind it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// systemd unit name, such as `nginx.service`, compared exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Absolute cgroup v2 path, matching that cgroup and everything under it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// Container id, an id prefix of at least twelve characters, or the name
    /// the runtime gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
}

impl WorkloadSelector {
    /// Build a selector, refusing one that names nothing or names it badly.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::InvalidWorkloadSelector`] when no matcher is
    /// set, when a matcher is blank, longer than
    /// [`WORKLOAD_MATCHER_MAX_LEN`], carries a newline, when `exe` or
    /// `cgroup` is not absolute, or when `container` is an id prefix shorter
    /// than [`CONTAINER_ID_MIN_PREFIX`].
    pub fn new(
        exe: Option<String>,
        unit: Option<String>,
        cgroup: Option<String>,
        container: Option<String>,
    ) -> Result<Self, FirewallError> {
        let selector = Self {
            exe: trimmed(exe),
            unit: trimmed(unit),
            cgroup: trimmed(cgroup),
            container: trimmed(container),
        };
        selector.validate()?;
        Ok(selector)
    }

    /// Check every matcher this selector carries.
    ///
    /// # Errors
    ///
    /// The same refusals [`Self::new`] documents.
    pub fn validate(&self) -> Result<(), FirewallError> {
        if self.is_empty() {
            return Err(FirewallError::InvalidWorkloadSelector {
                reason: "a workload selector must name at least one of exe, unit, cgroup or \
                         container"
                    .to_string(),
            });
        }
        for (field, value) in self.matchers() {
            if value.is_empty() {
                return Err(FirewallError::InvalidWorkloadSelector {
                    reason: format!("{field} must not be empty"),
                });
            }
            if value.len() > WORKLOAD_MATCHER_MAX_LEN {
                return Err(FirewallError::InvalidWorkloadSelector {
                    reason: format!(
                        "{field} is {} bytes, more than the {WORKLOAD_MATCHER_MAX_LEN} a matcher \
                         may carry",
                        value.len()
                    ),
                });
            }
            if value.contains(['\n', '\r', '\0']) {
                return Err(FirewallError::InvalidWorkloadSelector {
                    reason: format!("{field} contains a control character"),
                });
            }
        }
        for (field, value) in [
            ("exe", self.exe.as_deref()),
            ("cgroup", self.cgroup.as_deref()),
        ] {
            if let Some(value) = value
                && !value.starts_with('/')
            {
                return Err(FirewallError::InvalidWorkloadSelector {
                    reason: format!("{field} must be an absolute path: '{value}'"),
                });
            }
        }
        if let Some(container) = self.container.as_deref()
            && is_id_like(container)
            && container.len() < CONTAINER_ID_MIN_PREFIX
        {
            return Err(FirewallError::InvalidWorkloadSelector {
                reason: format!(
                    "container '{container}' reads as an id prefix and is shorter than the \
                     {CONTAINER_ID_MIN_PREFIX} characters a runtime prints"
                ),
            });
        }
        Ok(())
    }

    /// Whether no matcher is set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matchers().next().is_none()
    }

    /// Whether this selector can only be decided against a task.
    ///
    /// A cgroup, a unit and a container are properties of the cgroup the
    /// task sits in, so the kernel can carry them on a cgroup id that
    /// outlives every process in it. An executable belongs to one task, and
    /// the only thing that knows it is the process table, which learns it at
    /// `execve`. The two resolve into different kernel maps and this is the
    /// predicate that decides which.
    #[must_use]
    pub fn names_executable(&self) -> bool {
        self.exe.is_some()
    }

    /// The matchers that are set, as field name and value.
    pub fn matchers(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("exe", self.exe.as_deref()),
            ("unit", self.unit.as_deref()),
            ("cgroup", self.cgroup.as_deref()),
            ("container", self.container.as_deref()),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.map(|value| (field, value)))
    }

    /// Whether `facts` satisfy every matcher this selector carries.
    ///
    /// A matcher with nothing to compare against is a mismatch, never a
    /// match: see the module header for why absence is read that way.
    #[must_use]
    pub fn matches(&self, facts: &WorkloadFacts<'_>) -> bool {
        if let Some(exe) = self.exe.as_deref()
            && facts.exe != Some(exe)
        {
            return false;
        }
        if let Some(unit) = self.unit.as_deref()
            && facts.unit != Some(unit)
        {
            return false;
        }
        if let Some(cgroup) = self.cgroup.as_deref()
            && !facts
                .cgroup
                .is_some_and(|path| cgroup_contains(cgroup, path))
        {
            return false;
        }
        if let Some(container) = self.container.as_deref()
            && !container_matches(container, facts)
        {
            return false;
        }
        true
    }

    /// The selector as one line, for a log, an alert and the command line.
    #[must_use]
    pub fn describe(&self) -> String {
        self.matchers()
            .map(|(field, value)| format!("{field}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What a rule naming a workload does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadMode {
    /// Say so and let the syscall through. The default, and what a policy
    /// being written for the first time should run as for a while.
    #[default]
    Observe,
    /// Refuse the syscall. The task gets `EPERM` from its own `connect()` or
    /// `bind()`, which is an ordinary error it may handle any way it likes.
    Enforce,
}

impl WorkloadMode {
    /// The word a configuration file, an API response and the command line
    /// use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Enforce => "enforce",
        }
    }

    /// Whether the kernel refuses rather than reports.
    #[must_use]
    pub fn enforces(self) -> bool {
        matches!(self, Self::Enforce)
    }

    /// Read the word a configuration file carries.
    ///
    /// # Errors
    ///
    /// Returns the unknown word so the caller can name the field it was on.
    pub fn parse(value: &str) -> Result<Self, &str> {
        match value.trim() {
            "observe" => Ok(Self::Observe),
            "enforce" => Ok(Self::Enforce),
            other => Err(other),
        }
    }
}

/// The workload half of a firewall rule: who, and whether it is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadMatch {
    /// Which workload the rule is about.
    pub selector: WorkloadSelector,
    /// Whether a match refuses the syscall or only reports it.
    #[serde(default)]
    pub mode: WorkloadMode,
}

impl WorkloadMatch {
    /// A match in the mode a rule that does not say runs in.
    #[must_use]
    pub fn observing(selector: WorkloadSelector) -> Self {
        Self {
            selector,
            mode: WorkloadMode::Observe,
        }
    }

    /// A match that refuses the syscall.
    #[must_use]
    pub fn enforcing(selector: WorkloadSelector) -> Self {
        Self {
            selector,
            mode: WorkloadMode::Enforce,
        }
    }
}

/// What the agent knows about one task, as a selector is matched against it.
///
/// Every field is optional because every one of them can fail to resolve: a
/// process gone before `/proc` was read has no executable, a node with no
/// container runtime has no container, and a host that is not running
/// systemd has no unit. The borrowed form is deliberate - this is built per
/// evaluation from a process table entry and nothing here is stored.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkloadFacts<'a> {
    /// Absolute path of the executable, as the process table resolved it.
    pub exe: Option<&'a str>,
    /// systemd unit the task belongs to, such as `nginx.service`.
    pub unit: Option<&'a str>,
    /// Absolute cgroup v2 path of the task.
    pub cgroup: Option<&'a str>,
    /// Container id as the runtime names it, in full.
    pub container_id: Option<&'a str>,
    /// Container name, where a runtime enricher could read one.
    pub container_name: Option<&'a str>,
}

/// Where a task is trying to go, as the socket hook sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadDestination {
    /// The address the task passed to `connect()`, `sendmsg()` or `bind()`.
    pub addr: DestinationAddr,
    /// The port, host order.
    pub port: u16,
    /// The protocol of the socket.
    pub protocol: Protocol,
}

/// The destination address of a socket operation, in the width it came in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestinationAddr {
    /// IPv4, host byte order, as the firewall rules store addresses.
    V4(u32),
    /// IPv6, network order bytes.
    V6([u8; 16]),
}

impl DestinationAddr {
    /// Whether `network` contains this address. A network of the other
    /// family never contains it.
    #[must_use]
    pub fn inside(self, network: &IpNetwork) -> bool {
        match self {
            Self::V4(addr) => network.contains_v4(addr),
            Self::V6(addr) => network.contains_v6(&addr),
        }
    }
}

/// One firewall rule, reduced to what a socket hook can decide.
///
/// The source side is gone on purpose: at `connect()` the kernel has not
/// chosen a source address or a source port yet, so a rule matching on
/// either would be matching on nothing. That is refused when the rule is
/// read rather than dropped here, so an operator finds out from the
/// configuration error and not from traffic that was never matched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadRule {
    /// The rule's own identifier, which is what an alert and a counter carry.
    pub id: RuleId,
    /// Lower is examined first, as everywhere else in the firewall.
    pub priority: u32,
    /// Whether this rule lets the workload through or refuses it.
    pub action: FirewallAction,
    /// Whether a refusal is carried out or only reported.
    pub mode: WorkloadMode,
    /// Which workload the rule is about.
    pub selector: WorkloadSelector,
    /// Protocol of the socket, or [`Protocol::Any`].
    pub protocol: Protocol,
    /// Destination network, absent for "anywhere".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<IpNetwork>,
    /// Destination port range, absent for "any port".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<PortRange>,
    /// Whether the rule is in force.
    pub enabled: bool,
}

impl WorkloadRule {
    /// Whether this rule's destination half admits `destination`.
    ///
    /// A rule with no address matcher admits every destination, which is the
    /// "this workload, anywhere" half of the contract.
    #[must_use]
    pub fn admits_destination(&self, destination: &WorkloadDestination) -> bool {
        if self.protocol != Protocol::Any && self.protocol != destination.protocol {
            return false;
        }
        if let Some(ref network) = self.dst_ip
            && !destination.addr.inside(network)
        {
            return false;
        }
        if let Some(range) = self.dst_port
            && !range.contains(destination.port)
        {
            return false;
        }
        true
    }

    /// Whether the rule refuses what it matches rather than reporting it.
    #[must_use]
    pub fn enforces(&self) -> bool {
        self.mode.enforces() && self.refuses()
    }

    /// Whether the rule's action is a refusal.
    #[must_use]
    pub fn refuses(&self) -> bool {
        matches!(self.action, FirewallAction::Deny)
    }

    /// The destination half as one line, for the command line and a log.
    #[must_use]
    pub fn describe_destination(&self) -> String {
        let mut parts = Vec::new();
        if self.protocol != Protocol::Any {
            parts.push(format!("proto {}", self.protocol.to_u8()));
        }
        match self.dst_ip {
            Some(network) => parts.push(format!("to {}", describe_network(&network))),
            None => parts.push("to anywhere".to_string()),
        }
        if let Some(range) = self.dst_port {
            parts.push(if range.start == range.end {
                format!("port {}", range.start)
            } else {
                format!("ports {}-{}", range.start, range.end)
            });
        }
        parts.join(" ")
    }
}

/// What a policy decided about one socket operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadVerdict {
    /// A rule matched and lets the operation through.
    Allowed { rule: RuleId },
    /// A rule matched and refuses the operation. `enforced` is false when the
    /// rule is observing, in which case the syscall still goes through and
    /// the only thing produced is the alert.
    Refused { rule: RuleId, enforced: bool },
    /// No rule named this workload and this destination, so the policy has
    /// no opinion and the packet path decides as it did before.
    NoRule,
}

/// The rules of one configuration that name a workload, in the order the
/// kernel walks them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadPolicy {
    rules: Vec<WorkloadRule>,
}

impl WorkloadPolicy {
    /// Pick the workload rules out of a firewall configuration.
    ///
    /// Rules with no selector are left alone: they are the address rules the
    /// packet path already enforces, and nothing here touches them.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::WorkloadPolicyTooLarge`] past
    /// [`WORKLOAD_POLICY_MAX_RULES`] rules, and whatever
    /// [`FirewallRule::validate_workload`] refuses.
    pub fn from_rules(rules: &[FirewallRule]) -> Result<Self, FirewallError> {
        let mut selected = Vec::new();
        for rule in rules {
            let Some(workload) = rule.workload.as_ref() else {
                continue;
            };
            rule.validate_workload()?;
            selected.push(WorkloadRule {
                id: rule.id.clone(),
                priority: rule.priority,
                action: rule.action,
                mode: workload.mode,
                selector: workload.selector.clone(),
                protocol: rule.protocol,
                dst_ip: rule.dst_ip,
                dst_port: rule.dst_port,
                enabled: rule.enabled,
            });
        }
        selected.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.id.0.cmp(&b.id.0))
        });
        Self::new(selected)
    }

    /// Hold a list of workload rules, bounded the way the kernel is.
    ///
    /// Bounding the rules is what bounds the selectors: every rule names one,
    /// so a policy inside the rule ceiling names at most that many workloads,
    /// and [`WORKLOAD_POLICY_MAX_SELECTORS`] is the width of the mask that
    /// has to hold them. The two are held in that order by an assertion in
    /// `ebpf_common`, so there is one ceiling to check here rather than two.
    ///
    /// [`WORKLOAD_POLICY_MAX_SELECTORS`]: ebpf_common::workload_policy::WORKLOAD_POLICY_MAX_SELECTORS
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::WorkloadPolicyTooLarge`] past the rule
    /// ceiling.
    pub fn new(rules: Vec<WorkloadRule>) -> Result<Self, FirewallError> {
        if rules.len() > WORKLOAD_POLICY_MAX_RULES {
            return Err(FirewallError::WorkloadPolicyTooLarge {
                count: rules.len(),
                maximum: WORKLOAD_POLICY_MAX_RULES,
            });
        }
        Ok(Self { rules })
    }

    /// The rules, in the order they are examined.
    #[must_use]
    pub fn rules(&self) -> &[WorkloadRule] {
        &self.rules
    }

    /// Whether the policy decides nothing at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The distinct selectors the enabled rules name, in first-seen order.
    ///
    /// This is what the kernel-side bitmap is built from: two rules about the
    /// same workload share one bit, so the ceiling is on workloads and not on
    /// rules.
    pub fn selectors(&self) -> impl Iterator<Item = &WorkloadSelector> {
        let mut seen: Vec<&WorkloadSelector> = Vec::new();
        self.rules
            .iter()
            .filter(|rule| rule.enabled)
            .filter_map(move |rule| {
                if seen.contains(&&rule.selector) {
                    return None;
                }
                seen.push(&rule.selector);
                Some(&rule.selector)
            })
    }

    /// Whether any enabled rule would have the kernel refuse a syscall.
    ///
    /// The agent refuses to start when this is true and the programs did not
    /// attach, because a policy that says it refuses and does not is worse
    /// than no policy: the deployment reports healthy and the rule is a line
    /// in a file nothing reads.
    #[must_use]
    pub fn enforces(&self) -> bool {
        self.rules
            .iter()
            .any(|rule| rule.enabled && rule.enforces())
    }

    /// The enabled rules naming `facts`, in the order they are examined.
    ///
    /// This is what answers "what may this workload reach", which is the
    /// first question asked of any policy that refuses something.
    pub fn rules_for<'a>(
        &'a self,
        facts: &'a WorkloadFacts<'a>,
    ) -> impl Iterator<Item = &'a WorkloadRule> {
        self.rules
            .iter()
            .filter(|rule| rule.enabled && rule.selector.matches(facts))
    }

    /// Decide one socket operation the way the kernel decides it: the first
    /// enabled rule naming this workload and admitting this destination wins.
    #[must_use]
    pub fn evaluate(
        &self,
        facts: &WorkloadFacts<'_>,
        destination: &WorkloadDestination,
    ) -> WorkloadVerdict {
        for rule in self.rules_for(facts) {
            if !rule.admits_destination(destination) {
                continue;
            }
            return if rule.refuses() {
                WorkloadVerdict::Refused {
                    rule: rule.id.clone(),
                    enforced: rule.mode.enforces(),
                }
            } else {
                WorkloadVerdict::Allowed {
                    rule: rule.id.clone(),
                }
            };
        }
        WorkloadVerdict::NoRule
    }
}

/// A network as an operator wrote it, for a line of output.
fn describe_network(network: &IpNetwork) -> String {
    match *network {
        IpNetwork::V4 { addr, prefix_len } => {
            format!("{}/{prefix_len}", std::net::Ipv4Addr::from(addr))
        }
        IpNetwork::V6 { addr, prefix_len } => {
            format!("{}/{prefix_len}", std::net::Ipv6Addr::from(addr))
        }
    }
}

/// Trim a matcher and drop it when nothing is left.
fn trimmed(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Whether a container matcher reads as an id rather than as a name.
///
/// Runtimes name containers in words and identify them in hex, so a value
/// that is nothing but hex digits is read as an id and held to the prefix
/// length. A name that happens to be hex is a name somebody will regret
/// either way.
fn is_id_like(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `path` is `selector` or sits under it.
///
/// Both sides are compared without the mount point, because `/proc` reports
/// a cgroup path relative to the v2 root and an operator writes the one they
/// see under `/sys/fs/cgroup`. Comparing those two literally is the mistake
/// that makes every cgroup rule silently match nothing.
fn cgroup_contains(selector: &str, path: &str) -> bool {
    let selector = strip_mount(selector);
    let path = strip_mount(path);
    if selector == "/" {
        return true;
    }
    let selector = selector.trim_end_matches('/');
    path == selector
        || path
            .strip_prefix(selector)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// The cgroup v2 path a `/proc/<pid>/cgroup` payload reports.
///
/// One line, `0::/system.slice/nginx.service`, and the path is what comes
/// after the two colons. A host running cgroup v1 alone reports no such
/// line, and the answer there is `None` rather than one of the v1
/// controller paths: the kernel keys every hook here on a v2 id, so a v1
/// path would be a string that matches an operator's rule and names a
/// hierarchy nothing enforces on.
#[must_use]
pub fn cgroup_path_of(payload: &str) -> Option<&str> {
    payload
        .lines()
        .find_map(|line| line.trim().strip_prefix("0::"))
        .filter(|path| path.starts_with('/'))
}

/// The systemd unit a cgroup path belongs to, where it belongs to one.
///
/// systemd puts a unit's processes in a cgroup named after the unit, so the
/// unit is the last segment carrying a unit suffix: `nginx.service` under
/// `/system.slice/nginx.service`, and `session-3.scope` under the two slices
/// above it. The last rather than the first, because a unit inside a slice
/// is written below it and the innermost name is the one a person means.
///
/// A slice is not a unit for this purpose even though systemd calls it one:
/// a rule naming `system.slice` would name every service on the host, which
/// is what the cgroup matcher is for and says so in the rule.
#[must_use]
pub fn unit_of(cgroup_path: &str) -> Option<&str> {
    const SUFFIXES: [&str; 5] = [".service", ".scope", ".socket", ".mount", ".timer"];
    cgroup_path
        .rsplit('/')
        .find(|segment| SUFFIXES.iter().any(|suffix| segment.ends_with(suffix)))
}

/// Drop the v2 mount point from a cgroup path, leaving the path the kernel
/// itself reports.
fn strip_mount(path: &str) -> &str {
    let path = path.strip_prefix("/sys/fs/cgroup").unwrap_or(path);
    if path.is_empty() { "/" } else { path }
}

/// Whether a container matcher names the container in `facts`.
fn container_matches(matcher: &str, facts: &WorkloadFacts<'_>) -> bool {
    if facts.container_name == Some(matcher) {
        return true;
    }
    facts
        .container_id
        .is_some_and(|id| id == matcher || (is_id_like(matcher) && id.starts_with(matcher)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::entity::{ConnState, Scope};
    use ebpf_common::workload_policy::WORKLOAD_POLICY_MAX_SELECTORS;

    fn selector(exe: &str) -> WorkloadSelector {
        WorkloadSelector::new(Some(exe.to_string()), None, None, None).expect("a valid selector")
    }

    fn rule(id: &str, priority: u32, action: FirewallAction) -> FirewallRule {
        FirewallRule {
            id: RuleId(id.to_string()),
            priority,
            action,
            protocol: Protocol::Any,
            src_ip: None,
            dst_ip: None,
            src_port: None,
            dst_port: None,
            scope: Scope::Global,
            enabled: true,
            vlan_id: None,
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            src_mac_alias: None,
            dst_mac_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            group_mask: 0,
            tenant_id: 0,
            workload: Some(WorkloadMatch::observing(selector("/usr/sbin/nginx"))),
        }
    }

    fn nginx() -> WorkloadFacts<'static> {
        WorkloadFacts {
            exe: Some("/usr/sbin/nginx"),
            unit: Some("nginx.service"),
            cgroup: Some("/system.slice/nginx.service"),
            container_id: None,
            container_name: None,
        }
    }

    fn to(addr: [u8; 4], port: u16) -> WorkloadDestination {
        WorkloadDestination {
            addr: DestinationAddr::V4(u32::from_be_bytes(addr)),
            port,
            protocol: Protocol::Tcp,
        }
    }

    fn network(addr: [u8; 4], prefix_len: u8) -> IpNetwork {
        IpNetwork::V4 {
            addr: u32::from_be_bytes(addr),
            prefix_len,
        }
    }

    #[test]
    fn a_selector_naming_nothing_is_not_a_selector() {
        let refused = WorkloadSelector::new(None, None, None, None);
        assert!(matches!(
            refused,
            Err(FirewallError::InvalidWorkloadSelector { .. })
        ));
    }

    #[test]
    fn a_matcher_that_is_only_whitespace_names_nothing_either() {
        let refused = WorkloadSelector::new(Some("   ".to_string()), None, None, None);
        assert!(refused.is_err());
    }

    #[test]
    fn an_executable_and_a_cgroup_are_absolute_paths() {
        assert!(WorkloadSelector::new(Some("nginx".to_string()), None, None, None).is_err());
        assert!(WorkloadSelector::new(None, None, Some("system.slice".to_string()), None).is_err());
        assert!(WorkloadSelector::new(None, Some("nginx.service".to_string()), None, None).is_ok());
    }

    #[test]
    fn a_container_id_shorter_than_a_runtime_prints_is_refused() {
        assert!(WorkloadSelector::new(None, None, None, Some("3f2a1b".to_string())).is_err());
        assert!(WorkloadSelector::new(None, None, None, Some("3f2a1b4c5d6e".to_string())).is_ok());
        assert!(WorkloadSelector::new(None, None, None, Some("web".to_string())).is_ok());
    }

    #[test]
    fn every_matcher_set_has_to_match_and_the_others_are_ignored() {
        let both = WorkloadSelector::new(
            Some("/usr/sbin/nginx".to_string()),
            Some("nginx.service".to_string()),
            None,
            None,
        )
        .expect("a valid selector");

        assert!(both.matches(&nginx()));
        assert!(!both.matches(&WorkloadFacts {
            unit: Some("httpd.service"),
            ..nginx()
        }));
    }

    #[test]
    fn a_fact_the_agent_could_not_read_never_matches() {
        // The other reading would have a rule fire on "we do not know", which
        // is a refusal nobody can explain afterwards.
        let selector = WorkloadSelector::new(None, Some("nginx.service".to_string()), None, None)
            .expect("a valid selector");

        assert!(!selector.matches(&WorkloadFacts {
            unit: None,
            ..nginx()
        }));
    }

    #[test]
    fn a_cgroup_matches_itself_and_everything_under_it_mount_point_or_not() {
        let selector = WorkloadSelector::new(None, None, Some("/system.slice".to_string()), None)
            .expect("a valid selector");

        assert!(selector.matches(&nginx()));
        assert!(selector.matches(&WorkloadFacts {
            cgroup: Some("/sys/fs/cgroup/system.slice/nginx.service"),
            ..nginx()
        }));
        assert!(!selector.matches(&WorkloadFacts {
            cgroup: Some("/system.slice-other/x.service"),
            ..nginx()
        }));
        assert!(!selector.matches(&WorkloadFacts {
            cgroup: Some("/user.slice/nginx.service"),
            ..nginx()
        }));
    }

    #[test]
    fn a_container_matches_on_its_name_its_whole_id_or_an_id_prefix() {
        let facts = WorkloadFacts {
            container_id: Some("3f2a1b4c5d6e7f8a9b0c"),
            container_name: Some("web"),
            ..nginx()
        };

        for matcher in ["web", "3f2a1b4c5d6e7f8a9b0c", "3f2a1b4c5d6e"] {
            let selector = WorkloadSelector::new(None, None, None, Some(matcher.to_string()))
                .expect("a valid selector");
            assert!(selector.matches(&facts), "{matcher} should match");
        }

        let other = WorkloadSelector::new(None, None, None, Some("abcdef012345".to_string()))
            .expect("a valid selector");
        assert!(!other.matches(&facts));
    }

    #[test]
    fn a_rule_naming_a_workload_and_no_address_means_that_workload_anywhere() {
        let rules = [rule("anywhere", 10, FirewallAction::Deny)];
        let policy = WorkloadPolicy::from_rules(&rules).expect("a valid policy");

        assert_eq!(
            policy.evaluate(&nginx(), &to([8, 8, 8, 8], 53)),
            WorkloadVerdict::Refused {
                rule: RuleId("anywhere".to_string()),
                enforced: false,
            }
        );
        assert_eq!(
            policy.evaluate(&nginx(), &to([10, 0, 0, 1], 443)),
            WorkloadVerdict::Refused {
                rule: RuleId("anywhere".to_string()),
                enforced: false,
            }
        );
    }

    #[test]
    fn a_rule_naming_a_workload_and_an_address_is_the_intersection_of_the_two() {
        let mut narrowed = rule("narrowed", 10, FirewallAction::Deny);
        narrowed.dst_ip = Some(network([10, 0, 0, 0], 8));
        narrowed.dst_port = Some(PortRange {
            start: 443,
            end: 443,
        });
        let policy = WorkloadPolicy::from_rules(&[narrowed]).expect("a valid policy");

        assert!(matches!(
            policy.evaluate(&nginx(), &to([10, 0, 0, 1], 443)),
            WorkloadVerdict::Refused { .. }
        ));
        // Outside the network, outside the port, or another workload: the
        // rule has nothing to say about any of the three.
        assert_eq!(
            policy.evaluate(&nginx(), &to([8, 8, 8, 8], 443)),
            WorkloadVerdict::NoRule
        );
        assert_eq!(
            policy.evaluate(&nginx(), &to([10, 0, 0, 1], 80)),
            WorkloadVerdict::NoRule
        );
        assert_eq!(
            policy.evaluate(
                &WorkloadFacts {
                    exe: Some("/usr/bin/curl"),
                    ..nginx()
                },
                &to([10, 0, 0, 1], 443)
            ),
            WorkloadVerdict::NoRule
        );
    }

    #[test]
    fn the_first_rule_by_priority_decides_and_a_disabled_one_decides_nothing() {
        let mut allow = rule("allow-dns", 10, FirewallAction::Allow);
        allow.dst_port = Some(PortRange { start: 53, end: 53 });
        let deny = rule("deny-rest", 20, FirewallAction::Deny);
        let mut disabled = rule("disabled", 1, FirewallAction::Deny);
        disabled.enabled = false;

        let policy = WorkloadPolicy::from_rules(&[deny, disabled, allow]).expect("a valid policy");

        assert_eq!(
            policy
                .rules()
                .iter()
                .map(|r| r.id.0.as_str())
                .collect::<Vec<_>>(),
            ["disabled", "allow-dns", "deny-rest"]
        );
        assert_eq!(
            policy.evaluate(&nginx(), &to([8, 8, 8, 8], 53)),
            WorkloadVerdict::Allowed {
                rule: RuleId("allow-dns".to_string()),
            }
        );
        assert_eq!(
            policy.evaluate(&nginx(), &to([8, 8, 8, 8], 443)),
            WorkloadVerdict::Refused {
                rule: RuleId("deny-rest".to_string()),
                enforced: false,
            }
        );
    }

    #[test]
    fn a_rule_without_a_selector_is_left_to_the_packet_path() {
        let mut address_only = rule("address-only", 10, FirewallAction::Deny);
        address_only.workload = None;

        let policy = WorkloadPolicy::from_rules(&[address_only]).expect("a valid policy");

        assert!(policy.is_empty());
        assert_eq!(
            policy.evaluate(&nginx(), &to([10, 0, 0, 1], 443)),
            WorkloadVerdict::NoRule
        );
    }

    #[test]
    fn observing_is_the_default_and_only_enforcing_refuses_the_syscall() {
        assert_eq!(WorkloadMode::default(), WorkloadMode::Observe);

        let mut enforcing = rule("enforced", 10, FirewallAction::Deny);
        enforcing.workload = Some(WorkloadMatch::enforcing(selector("/usr/sbin/nginx")));
        let observing = rule("observed", 20, FirewallAction::Deny);

        let policy =
            WorkloadPolicy::from_rules(std::slice::from_ref(&observing)).expect("a valid policy");
        assert!(!policy.enforces());

        let policy = WorkloadPolicy::from_rules(&[enforcing, observing]).expect("a valid policy");
        assert!(policy.enforces());
        assert_eq!(
            policy.evaluate(&nginx(), &to([8, 8, 8, 8], 53)),
            WorkloadVerdict::Refused {
                rule: RuleId("enforced".to_string()),
                enforced: true,
            }
        );
    }

    #[test]
    fn an_enforcing_rule_that_allows_enforces_nothing() {
        // Enforcement is the kernel refusing a syscall, and an allow has none
        // to refuse. Reading it the other way would make an allow rule able to
        // stop a deployment.
        let mut allowing = rule("allow", 10, FirewallAction::Allow);
        allowing.workload = Some(WorkloadMatch::enforcing(selector("/usr/sbin/nginx")));

        let policy = WorkloadPolicy::from_rules(&[allowing]).expect("a valid policy");

        assert!(!policy.enforces());
    }

    /// One matcher that may not sit beside a workload, and how to set it.
    type Unsupported = (&'static str, fn(&mut FirewallRule));

    #[test]
    fn a_matcher_the_socket_hooks_cannot_decide_fails_the_rule() {
        let unsupported: [Unsupported; 8] = [
            ("src_ip", |rule| {
                rule.src_ip = Some(network([10, 0, 0, 0], 8));
            }),
            ("src_port", |rule| {
                rule.src_port = Some(PortRange {
                    start: 1024,
                    end: 2048,
                });
            }),
            ("vlan_id", |rule| rule.vlan_id = Some(10)),
            ("state", |rule| {
                rule.ct_states = Some(vec![ConnState::Established]);
            }),
            ("dscp", |rule| rule.dscp_match = Some(46)),
            ("negate", |rule| rule.negate_dst = true),
            ("interfaces", |rule| rule.group_mask = 0b10),
            ("reject", |rule| rule.action = FirewallAction::Reject),
        ];

        for (name, apply) in unsupported {
            let mut rule = rule("rule", 10, FirewallAction::Deny);
            apply(&mut rule);
            assert!(
                matches!(
                    rule.validate_workload(),
                    Err(FirewallError::WorkloadMatcherUnsupported { .. })
                ),
                "{name} should be refused on a workload rule"
            );
        }
    }

    #[test]
    fn the_same_matchers_are_fine_on_a_rule_naming_no_workload() {
        let mut address_only = rule("address-only", 10, FirewallAction::Reject);
        address_only.workload = None;
        address_only.src_ip = Some(network([10, 0, 0, 0], 8));

        assert!(address_only.validate_workload().is_ok());
    }

    #[test]
    fn two_rules_about_one_workload_share_a_selector() {
        let first = rule("first", 10, FirewallAction::Allow);
        let second = rule("second", 20, FirewallAction::Deny);
        let mut third = rule("third", 30, FirewallAction::Deny);
        third.workload = Some(WorkloadMatch::observing(selector("/usr/bin/curl")));

        let policy = WorkloadPolicy::from_rules(&[first, second, third]).expect("a valid policy");

        assert_eq!(policy.selectors().count(), 2);
    }

    #[test]
    fn a_policy_past_what_the_kernel_holds_is_refused_rather_than_cut() {
        let rules: Vec<FirewallRule> = (0..=WORKLOAD_POLICY_MAX_RULES)
            .map(|index| {
                let mut rule = rule(&format!("rule-{index}"), 10, FirewallAction::Deny);
                rule.priority = u32::try_from(index).expect("a small index");
                rule
            })
            .collect();

        let refused = WorkloadPolicy::from_rules(&rules);

        assert!(matches!(
            refused,
            Err(FirewallError::WorkloadPolicyTooLarge { .. })
        ));
    }

    #[test]
    fn a_full_policy_still_fits_the_bitmap_one_workload_per_rule() {
        // The rule ceiling is what bounds the selectors, so the worst case for
        // the mask is a policy at the ceiling where no two rules are about the
        // same workload.
        let rules: Vec<FirewallRule> = (0..WORKLOAD_POLICY_MAX_RULES)
            .map(|index| {
                let mut rule = rule(&format!("rule-{index}"), 10, FirewallAction::Deny);
                rule.workload = Some(WorkloadMatch::observing(selector(&format!(
                    "/usr/bin/app-{index}"
                ))));
                rule
            })
            .collect();

        let policy = WorkloadPolicy::from_rules(&rules).expect("a policy at the ceiling");

        assert_eq!(policy.selectors().count(), WORKLOAD_POLICY_MAX_RULES);
        assert!(policy.selectors().count() <= WORKLOAD_POLICY_MAX_SELECTORS);
    }

    #[test]
    fn what_a_workload_may_reach_is_readable_without_a_destination() {
        let mut dns = rule("dns", 10, FirewallAction::Allow);
        dns.protocol = Protocol::Udp;
        dns.dst_ip = Some(network([10, 0, 0, 53], 32));
        dns.dst_port = Some(PortRange { start: 53, end: 53 });
        let other = {
            let mut other = rule("other", 20, FirewallAction::Deny);
            other.workload = Some(WorkloadMatch::observing(selector("/usr/bin/curl")));
            other
        };

        let policy = WorkloadPolicy::from_rules(&[dns, other]).expect("a valid policy");
        let facts = nginx();
        let listed: Vec<String> = policy
            .rules_for(&facts)
            .map(WorkloadRule::describe_destination)
            .collect();

        assert_eq!(listed, ["proto 17 to 10.0.0.53/32 port 53"]);
    }

    #[test]
    fn a_selector_reads_back_as_the_matchers_it_carries() {
        let selector = WorkloadSelector::new(
            Some("/usr/sbin/nginx".to_string()),
            None,
            None,
            Some("web".to_string()),
        )
        .expect("a valid selector");

        assert_eq!(selector.describe(), "exe=/usr/sbin/nginx container=web");
        assert!(selector.names_executable());
    }

    #[test]
    fn the_mode_is_read_and_written_with_one_word() {
        assert_eq!(WorkloadMode::parse("enforce"), Ok(WorkloadMode::Enforce));
        assert_eq!(WorkloadMode::parse(" observe "), Ok(WorkloadMode::Observe));
        assert_eq!(WorkloadMode::parse("block"), Err("block"));
        assert_eq!(WorkloadMode::Enforce.as_str(), "enforce");
    }

    #[test]
    fn a_destination_is_only_inside_a_network_of_its_own_family() {
        let v6 = DestinationAddr::V6([0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        assert!(!v6.inside(&network([10, 0, 0, 0], 8)));
        assert!(v6.inside(&IpNetwork::V6 {
            addr: [0x20, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            prefix_len: 32,
        }));
    }
}

#[cfg(test)]
mod cgroup_facts_tests {
    use super::{cgroup_path_of, unit_of};

    #[test]
    fn the_v2_line_is_the_one_read_and_a_v1_only_host_answers_nothing() {
        assert_eq!(
            cgroup_path_of("0::/system.slice/nginx.service\n"),
            Some("/system.slice/nginx.service")
        );
        assert_eq!(
            cgroup_path_of("12:memory:/docker/abc\n5:cpu:/docker/abc\n"),
            None
        );
        assert_eq!(cgroup_path_of("0::\n"), None);
    }

    #[test]
    fn the_innermost_unit_is_the_unit_and_a_slice_alone_is_not_one() {
        assert_eq!(
            unit_of("/system.slice/nginx.service"),
            Some("nginx.service")
        );
        assert_eq!(
            unit_of("/user.slice/user-1000.slice/session-3.scope"),
            Some("session-3.scope")
        );
        assert_eq!(unit_of("/system.slice"), None);
        assert_eq!(unit_of("/"), None);
    }

    #[test]
    fn a_container_scope_reads_as_the_unit_it_is() {
        // Nothing pretends this is a nicer name than the container matcher
        // gives: it is what systemd called the scope, and a rule naming it
        // matches exactly that container.
        assert_eq!(
            unit_of("/system.slice/docker-0123456789ab.scope"),
            Some("docker-0123456789ab.scope")
        );
    }
}
