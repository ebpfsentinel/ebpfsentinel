//! Which workloads the DLP probes may read plaintext from.
//!
//! The kernel side of this fence already exists: the uprobes check the
//! task's own cgroup, and its ancestors, against an allow-list before they
//! copy a single byte out of a TLS buffer. What was missing is the policy
//! above it. An operator could say "DLP is on" and could not say "this
//! tenant, these workloads", which on a multi-tenant node is the difference
//! between a product and a liability: the fence existed and nobody could aim
//! it.
//!
//! A selector here is that aim, written in the vocabulary a workload is
//! already named by elsewhere in the agent - a tenant, a namespace, a pod, a
//! container, a cgroup, a systemd unit, an executable - and compiled into
//! the allow-list the probes read.
//!
//! Three decisions are written into the types rather than left to a caller.
//!
//! A matcher that is set and a fact that is absent never match, exactly as
//! in the firewall's workload selector. Reading a neighbour's cleartext
//! because the agent could not resolve a pod name is the one failure this
//! policy exists to prevent, so "we do not know" closes the fence rather
//! than opening it.
//!
//! An exclusion beats every inclusion, whatever order the document lists
//! them in. Priority between a positive and a negative rule is a thing
//! operators get wrong under pressure, and the direction that is safe to get
//! wrong is the one that reads less.
//!
//! A selector matching no workload is a finding, not a silence. A typo in a
//! pod label that quietly disables DLP is a breach nobody notices, so the
//! policy reports which rule resolved to nothing and which of its matchers
//! named evidence this node never produced.

use serde::{Deserialize, Serialize};

use crate::firewall::workload::{
    CONTAINER_ID_MIN_PREFIX, WORKLOAD_MATCHER_MAX_LEN, cgroup_contains, is_id_like,
};

use super::error::DlpError;

/// How many selectors one policy may carry.
///
/// Each selector is evaluated against every workload on every refresh, and
/// the allow-list they compile into is bounded kernel-side anyway. The bound
/// exists so a generated document cannot turn the refresh into a quadratic
/// walk nobody is watching.
pub const DLP_SCOPE_MAX_SELECTORS: usize = 64;

/// Longest name a selector may be labelled with.
pub const DLP_SCOPE_NAME_MAX_LEN: usize = 128;

/// What the probes read, before any selector narrows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DlpScopeMode {
    /// Every task on the node, which is what a single-tenant host wants and
    /// what a multi-tenant one must not run.
    #[default]
    All,
    /// Only the workloads the selectors and the configured cgroups name.
    Workloads,
}

impl DlpScopeMode {
    /// The word a configuration file, an API response and the command line
    /// use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Workloads => "workloads",
        }
    }

    /// Whether the allow-list decides what is read.
    #[must_use]
    pub fn is_scoped(self) -> bool {
        matches!(self, Self::Workloads)
    }

    /// Read the word a configuration file carries.
    ///
    /// # Errors
    ///
    /// Returns the unknown word so the caller can name the field it was on.
    pub fn parse(value: &str) -> Result<Self, &str> {
        match value.trim() {
            "all" => Ok(Self::All),
            "workloads" => Ok(Self::Workloads),
            other => Err(other),
        }
    }
}

/// Whether a selector brings a workload into scope or takes it out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DlpScopeAction {
    /// Read this workload's plaintext. The default, because a selector list
    /// is written to name what is watched.
    #[default]
    Include,
    /// Never read this workload, whatever else matched it.
    Exclude,
}

impl DlpScopeAction {
    /// The word a configuration file, an API response and the command line
    /// use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Exclude => "exclude",
        }
    }

    /// Read the word a configuration file carries.
    ///
    /// # Errors
    ///
    /// Returns the unknown word so the caller can name the field it was on.
    pub fn parse(value: &str) -> Result<Self, &str> {
        match value.trim() {
            "include" => Ok(Self::Include),
            "exclude" => Ok(Self::Exclude),
            other => Err(other),
        }
    }
}

/// One rule naming the workloads DLP may read, or may not.
///
/// Every matcher that is set has to match, so the matchers narrow together.
/// None of them being set is not a selector and is refused: the rule it
/// would make is "every workload", which is what `mode: all` already says in
/// one word.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DlpScopeSelector {
    /// What to call this rule in a log, the API and the command line. The
    /// matchers themselves stand in when it is absent, so naming a rule is
    /// a courtesy to whoever reads the report and never a requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether a match reads the workload or refuses to.
    #[serde(default)]
    pub action: DlpScopeAction,
    /// Tenant name as the enterprise registry knows it. The open source
    /// agent resolves no tenant, so a tenant matcher there matches nothing
    /// and is reported as such.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Kubernetes namespace, as the pod metadata enricher read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Pod name, as the pod metadata enricher read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// Container id, an id prefix of at least twelve characters, or the name
    /// the runtime gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// Absolute cgroup v2 path, matching that cgroup and everything under
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// systemd unit name, such as `nginx.service`, compared exactly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Absolute path of the executable, compared exactly.
    ///
    /// A path is forgeable the same way it is in a firewall rule: it names
    /// the binary and not the bytes behind it. An executable matcher also
    /// scopes per task rather than per cgroup, and the cgroup the task sits
    /// in is what the kernel allow-list ends up carrying, so the fence it
    /// buys is only as narrow as that cgroup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
}

impl DlpScopeSelector {
    /// Check every matcher this selector carries.
    ///
    /// # Errors
    ///
    /// Returns [`DlpError::InvalidScopeSelector`] when no matcher is set,
    /// when a matcher or the name is blank, longer than its bound or carries
    /// a control character, when `exe` or `cgroup` is not absolute, when
    /// `cgroup` walks out of the cgroup root, or when `container` is an id
    /// prefix shorter than [`CONTAINER_ID_MIN_PREFIX`].
    pub fn validate(&self) -> Result<(), DlpError> {
        if self.is_empty() {
            return Err(DlpError::InvalidScopeSelector {
                reason: "a DLP scope selector must name at least one of tenant, namespace, pod, \
                         container, cgroup, unit or exe"
                    .to_string(),
            });
        }
        if let Some(name) = self.name.as_deref() {
            if name.trim().is_empty() {
                return Err(DlpError::InvalidScopeSelector {
                    reason: "name must not be empty".to_string(),
                });
            }
            if name.len() > DLP_SCOPE_NAME_MAX_LEN {
                return Err(DlpError::InvalidScopeSelector {
                    reason: format!(
                        "name is {} bytes, more than the {DLP_SCOPE_NAME_MAX_LEN} a selector name \
                         may carry",
                        name.len()
                    ),
                });
            }
        }
        for (field, value) in self.matchers() {
            if value.is_empty() {
                return Err(DlpError::InvalidScopeSelector {
                    reason: format!("{field} must not be empty"),
                });
            }
            if value.len() > WORKLOAD_MATCHER_MAX_LEN {
                return Err(DlpError::InvalidScopeSelector {
                    reason: format!(
                        "{field} is {} bytes, more than the {WORKLOAD_MATCHER_MAX_LEN} a matcher \
                         may carry",
                        value.len()
                    ),
                });
            }
            if value.contains(['\n', '\r', '\0']) {
                return Err(DlpError::InvalidScopeSelector {
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
                return Err(DlpError::InvalidScopeSelector {
                    reason: format!("{field} must be an absolute path: '{value}'"),
                });
            }
        }
        if let Some(cgroup) = self.cgroup.as_deref()
            && cgroup.split('/').any(|part| part == "..")
        {
            return Err(DlpError::InvalidScopeSelector {
                reason: format!("cgroup '{cgroup}' walks out of the cgroup root"),
            });
        }
        if let Some(container) = self.container.as_deref()
            && is_id_like(container)
            && container.len() < CONTAINER_ID_MIN_PREFIX
        {
            return Err(DlpError::InvalidScopeSelector {
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

    /// The matchers that are set, as field name and value.
    pub fn matchers(&self) -> impl Iterator<Item = (&'static str, &str)> {
        [
            ("tenant", self.tenant.as_deref()),
            ("namespace", self.namespace.as_deref()),
            ("pod", self.pod.as_deref()),
            ("container", self.container.as_deref()),
            ("cgroup", self.cgroup.as_deref()),
            ("unit", self.unit.as_deref()),
            ("exe", self.exe.as_deref()),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.map(|value| (field, value)))
    }

    /// Whether this selector can only be decided against a task rather than
    /// against a cgroup.
    ///
    /// A cgroup, a unit, a container, a pod and a tenant are properties of
    /// the cgroup a task sits in, so the cgroup tree alone answers them. An
    /// executable belongs to one task and is learnt at `execve`, which is
    /// what decides whether a selector needs the process table to resolve at
    /// all.
    #[must_use]
    pub fn names_executable(&self) -> bool {
        self.exe.is_some()
    }

    /// What to call this rule in a report.
    #[must_use]
    pub fn label(&self) -> String {
        match self.name.as_deref() {
            Some(name) => name.to_string(),
            None => self.describe(),
        }
    }

    /// The selector as one line, for a log, an alert and the command line.
    #[must_use]
    pub fn describe(&self) -> String {
        self.matchers()
            .map(|(field, value)| format!("{field}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Whether `facts` satisfy every matcher this selector carries.
    ///
    /// A matcher with nothing to compare against is a mismatch, never a
    /// match: see the module header for why absence closes the fence.
    #[must_use]
    pub fn matches(&self, facts: &DlpWorkloadFacts<'_>) -> bool {
        if let Some(tenant) = self.tenant.as_deref()
            && facts.tenant != Some(tenant)
        {
            return false;
        }
        if let Some(namespace) = self.namespace.as_deref()
            && facts.namespace != Some(namespace)
        {
            return false;
        }
        if let Some(pod) = self.pod.as_deref()
            && facts.pod != Some(pod)
        {
            return false;
        }
        if let Some(container) = self.container.as_deref()
            && !container_matches(container, facts)
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
        if let Some(unit) = self.unit.as_deref()
            && facts.unit != Some(unit)
        {
            return false;
        }
        if let Some(exe) = self.exe.as_deref()
            && facts.exe != Some(exe)
        {
            return false;
        }
        true
    }

    /// The matchers this selector carries that no observed workload could
    /// have answered, in the order a report reads them.
    #[must_use]
    pub fn unresolved_matchers(&self, evidence: &DlpScopeEvidence) -> Vec<&'static str> {
        self.matchers()
            .filter(|(field, _)| !evidence.carries(field))
            .map(|(field, _)| field)
            .collect()
    }
}

/// What the agent knows about one workload, as the resolvers answered.
///
/// Every field is optional because every one of them can be unavailable:
/// there is no tenant without the enterprise registry, no pod without the
/// Kubernetes enricher, no executable without an exec event, and no
/// container outside a container runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DlpWorkloadFacts<'a> {
    /// Tenant the workload is attributed to.
    pub tenant: Option<&'a str>,
    /// Kubernetes namespace.
    pub namespace: Option<&'a str>,
    /// Pod name.
    pub pod: Option<&'a str>,
    /// Container id as the runtime names it, in full.
    pub container_id: Option<&'a str>,
    /// Container name, where a runtime enricher could read one.
    pub container_name: Option<&'a str>,
    /// Absolute cgroup v2 path of the workload.
    pub cgroup: Option<&'a str>,
    /// systemd unit the workload belongs to.
    pub unit: Option<&'a str>,
    /// Absolute path of the executable, where a task answered for it.
    pub exe: Option<&'a str>,
}

/// One workload a resolver answered for, owning what it said.
///
/// [`DlpWorkloadFacts`] borrows, because matching happens in a loop over
/// every workload on the node and copying strings to compare them would be
/// the whole cost of the pass. This is the same thing one layer out, where a
/// scanner has to hand its answers across an await point.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DlpObservedWorkload {
    /// Absolute cgroup v2 path, relative to the cgroup root.
    pub cgroup: Option<String>,
    /// Cgroup v2 id, which is what the kernel allow-list is keyed on. A
    /// workload with no id can be matched and cannot be allowed, so it is
    /// reported and never written.
    pub cgroup_id: Option<u64>,
    /// Tenant the workload is attributed to.
    pub tenant: Option<String>,
    /// Kubernetes namespace.
    pub namespace: Option<String>,
    /// Pod name.
    pub pod: Option<String>,
    /// Container id as the runtime names it, in full.
    pub container_id: Option<String>,
    /// Container name, where a runtime enricher could read one.
    pub container_name: Option<String>,
    /// systemd unit the workload belongs to.
    pub unit: Option<String>,
    /// Absolute path of the executable, where a task answered for one.
    pub exe: Option<String>,
}

impl DlpObservedWorkload {
    /// The facts, borrowed, as the selectors match on them.
    #[must_use]
    pub fn facts(&self) -> DlpWorkloadFacts<'_> {
        DlpWorkloadFacts {
            tenant: self.tenant.as_deref(),
            namespace: self.namespace.as_deref(),
            pod: self.pod.as_deref(),
            container_id: self.container_id.as_deref(),
            container_name: self.container_name.as_deref(),
            cgroup: self.cgroup.as_deref(),
            unit: self.unit.as_deref(),
            exe: self.exe.as_deref(),
        }
    }
}

/// Which kinds of fact this node produced at all.
///
/// A selector matching nothing means one of two very different things: the
/// workload it names is not running, or the agent cannot see that kind of
/// fact on this node. Accumulating what was observed is what lets the
/// report tell an operator which of the two they are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DlpScopeEvidence {
    /// One bit per kind of fact, so adding a kind is a constant rather than
    /// another flag on a struct of flags.
    seen: u8,
}

impl DlpScopeEvidence {
    /// The bit a matcher's evidence is recorded in.
    fn bit(field: &str) -> u8 {
        match field {
            "tenant" => 1 << 0,
            "namespace" => 1 << 1,
            "pod" => 1 << 2,
            "container" => 1 << 3,
            "cgroup" => 1 << 4,
            "unit" => 1 << 5,
            "exe" => 1 << 6,
            _ => 0,
        }
    }

    /// Record what one workload answered for.
    pub fn record(&mut self, facts: &DlpWorkloadFacts<'_>) {
        for (field, present) in [
            ("tenant", facts.tenant.is_some()),
            ("namespace", facts.namespace.is_some()),
            ("pod", facts.pod.is_some()),
            (
                "container",
                facts.container_id.is_some() || facts.container_name.is_some(),
            ),
            ("cgroup", facts.cgroup.is_some()),
            ("unit", facts.unit.is_some()),
            ("exe", facts.exe.is_some()),
        ] {
            if present {
                self.seen |= Self::bit(field);
            }
        }
    }

    /// Whether any observed workload carried this kind of fact.
    #[must_use]
    pub fn carries(&self, field: &str) -> bool {
        let bit = Self::bit(field);
        bit != 0 && self.seen & bit != 0
    }
}

/// What one selector decided about one workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlpScopeVerdict {
    /// Read it, because this rule said so and nothing excluded it.
    InScope {
        /// The rule that brought it in.
        rule: String,
    },
    /// Never read it, because this rule took it out.
    Excluded {
        /// The rule that took it out.
        rule: String,
    },
    /// No rule named it, so it stays outside the fence.
    NotSelected,
}

/// The selectors in force, as one policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DlpScopePolicy {
    selectors: Vec<DlpScopeSelector>,
}

impl DlpScopePolicy {
    /// Build a policy, refusing a selector that names nothing or names it
    /// badly, and a list longer than [`DLP_SCOPE_MAX_SELECTORS`].
    ///
    /// # Errors
    ///
    /// Returns [`DlpError::InvalidScopeSelector`] with the index of the
    /// offending selector, because a document with thirty of them needs to
    /// say which one.
    pub fn from_selectors(selectors: Vec<DlpScopeSelector>) -> Result<Self, DlpError> {
        if selectors.len() > DLP_SCOPE_MAX_SELECTORS {
            return Err(DlpError::InvalidScopeSelector {
                reason: format!(
                    "{} selectors, more than the {DLP_SCOPE_MAX_SELECTORS} a DLP scope may carry",
                    selectors.len()
                ),
            });
        }
        for (index, selector) in selectors.iter().enumerate() {
            selector.validate().map_err(|err| match err {
                DlpError::InvalidScopeSelector { reason } => DlpError::InvalidScopeSelector {
                    reason: format!("selector {index}: {reason}"),
                },
                other => other,
            })?;
        }
        Ok(Self { selectors })
    }

    /// Whether no selector was written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.selectors.is_empty()
    }

    /// How many selectors are in force.
    #[must_use]
    pub fn len(&self) -> usize {
        self.selectors.len()
    }

    /// The selectors, in the order the document listed them.
    #[must_use]
    pub fn selectors(&self) -> &[DlpScopeSelector] {
        &self.selectors
    }

    /// Whether any selector can only be decided against a task.
    #[must_use]
    pub fn needs_executables(&self) -> bool {
        self.selectors
            .iter()
            .any(DlpScopeSelector::names_executable)
    }

    /// Decide one workload.
    ///
    /// An exclusion is looked for first and across the whole list, so the
    /// order a document happens to be written in cannot turn a refusal into
    /// a read.
    #[must_use]
    pub fn evaluate(&self, facts: &DlpWorkloadFacts<'_>) -> DlpScopeVerdict {
        for selector in &self.selectors {
            if selector.action == DlpScopeAction::Exclude && selector.matches(facts) {
                return DlpScopeVerdict::Excluded {
                    rule: selector.label(),
                };
            }
        }
        for selector in &self.selectors {
            if selector.action == DlpScopeAction::Include && selector.matches(facts) {
                return DlpScopeVerdict::InScope {
                    rule: selector.label(),
                };
            }
        }
        DlpScopeVerdict::NotSelected
    }
}

/// One workload the report names, with the identity it was decided on.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DlpScopedWorkload {
    /// Absolute cgroup v2 path, where one was resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// Cgroup id the kernel allow-list carries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup_id: Option<u64>,
    /// Tenant, where one was attributed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Kubernetes namespace, where one was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// Pod name, where one was read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod: Option<String>,
    /// Container name or id, whichever the runtime answered with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
    /// systemd unit, where one was resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    /// Executable, where a task answered for one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// The rule that decided it.
    pub rule: String,
}

impl DlpScopedWorkload {
    /// Build a report line from the facts a resolver answered with.
    #[must_use]
    pub fn from_facts(facts: &DlpWorkloadFacts<'_>, cgroup_id: Option<u64>, rule: String) -> Self {
        Self {
            cgroup: facts.cgroup.map(str::to_string),
            cgroup_id,
            tenant: facts.tenant.map(str::to_string),
            namespace: facts.namespace.map(str::to_string),
            pod: facts.pod.map(str::to_string),
            container: facts
                .container_name
                .or(facts.container_id)
                .map(str::to_string),
            unit: facts.unit.map(str::to_string),
            exe: facts.exe.map(str::to_string),
            rule,
        }
    }
}

/// A rule that matched nothing, and why that is worth saying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpUnmatchedSelector {
    /// What the rule is called.
    pub rule: String,
    /// The matchers it carries, as one line.
    pub selector: String,
    /// Whether it would have read a workload or refused one.
    pub action: String,
    /// Why it matched nothing, in a sentence an operator can act on.
    pub reason: String,
}

impl DlpUnmatchedSelector {
    /// Build the finding for a selector that resolved to no workload.
    #[must_use]
    pub fn new(selector: &DlpScopeSelector, evidence: &DlpScopeEvidence) -> Self {
        let unresolved = selector.unresolved_matchers(evidence);
        let reason = if unresolved.is_empty() {
            "no workload on this node matches it".to_string()
        } else {
            format!(
                "no workload on this node matches it, and this agent resolved no {} at all",
                unresolved.join(", ")
            )
        };
        Self {
            rule: selector.label(),
            selector: selector.describe(),
            action: selector.action.as_str().to_string(),
            reason,
        }
    }
}

/// What the probes are reading right now, as a surface can print it.
///
/// This is the effective scope rather than the configured one: it is built
/// from the workloads the resolvers actually answered for, which is the
/// difference between an operator verifying the fence and an operator
/// trusting the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveDlpScope {
    /// Whether the allow-list decides what is read, or everything is.
    pub mode: String,
    /// How many selectors are in force.
    pub selectors: usize,
    /// How many cgroup ids the kernel allow-list carries.
    pub allowed_cgroups: usize,
    /// Whether the probes are attached at all. A scope on a node where DLP
    /// is off reads nothing, and saying so is cheaper than an operator
    /// inferring it.
    pub enabled: bool,
    /// The workloads being read, with the rule that brought each in.
    pub in_scope: Vec<DlpScopedWorkload>,
    /// The workloads explicitly refused, with the rule that refused each.
    pub excluded: Vec<DlpScopedWorkload>,
    /// The rules that matched nothing.
    pub unmatched: Vec<DlpUnmatchedSelector>,
    /// How many workloads were seen and named by no rule. They are counted
    /// rather than listed, because on a busy node that list is the node.
    pub unselected: usize,
    /// When the scope was last resolved, seconds since the epoch.
    pub refreshed_unix: u64,
}

impl EffectiveDlpScope {
    /// The scope of an agent whose DLP probes are not attached.
    #[must_use]
    pub fn disabled(refreshed_unix: u64) -> Self {
        Self {
            mode: DlpScopeMode::All.as_str().to_string(),
            selectors: 0,
            allowed_cgroups: 0,
            enabled: false,
            in_scope: Vec::new(),
            excluded: Vec::new(),
            unmatched: Vec::new(),
            unselected: 0,
            refreshed_unix,
        }
    }
}

/// Whether a container matcher answers for these facts.
fn container_matches(matcher: &str, facts: &DlpWorkloadFacts<'_>) -> bool {
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

    fn selector(name: &str) -> DlpScopeSelector {
        DlpScopeSelector {
            name: Some(name.to_string()),
            ..DlpScopeSelector::default()
        }
    }

    fn pod_facts<'a>(namespace: &'a str, pod: &'a str, cgroup: &'a str) -> DlpWorkloadFacts<'a> {
        DlpWorkloadFacts {
            namespace: Some(namespace),
            pod: Some(pod),
            cgroup: Some(cgroup),
            ..DlpWorkloadFacts::default()
        }
    }

    #[test]
    fn a_selector_naming_nothing_is_refused() {
        let err = DlpScopeSelector::default()
            .validate()
            .expect_err("a selector with no matcher is not a selector");
        assert!(err.to_string().contains("at least one of tenant"));
    }

    #[test]
    fn every_matcher_narrows_together() {
        let mut rule = selector("payments");
        rule.namespace = Some("payments".to_string());
        rule.pod = Some("api-0".to_string());
        assert!(rule.matches(&pod_facts("payments", "api-0", "/kubepods/pod1")));
        assert!(!rule.matches(&pod_facts("payments", "api-1", "/kubepods/pod2")));
    }

    #[test]
    fn a_matcher_without_evidence_never_matches() {
        let mut rule = selector("by-pod");
        rule.pod = Some("api-0".to_string());
        let facts = DlpWorkloadFacts {
            cgroup: Some("/system.slice/nginx.service"),
            ..DlpWorkloadFacts::default()
        };
        assert!(!rule.matches(&facts));
    }

    #[test]
    fn a_cgroup_matcher_covers_what_sits_under_it() {
        let mut rule = selector("slice");
        rule.cgroup = Some("/kubepods.slice".to_string());
        assert!(rule.matches(&pod_facts(
            "payments",
            "api-0",
            "/kubepods.slice/pod-abc/container"
        )));
        assert!(!rule.matches(&pod_facts(
            "payments",
            "api-0",
            "/system.slice/nginx.service"
        )));
    }

    #[test]
    fn an_exclusion_beats_an_inclusion_whatever_the_order() {
        let mut include = selector("all-of-payments");
        include.namespace = Some("payments".to_string());
        let mut exclude = selector("not-the-vault");
        exclude.action = DlpScopeAction::Exclude;
        exclude.pod = Some("vault-0".to_string());

        for selectors in [
            vec![include.clone(), exclude.clone()],
            vec![exclude.clone(), include.clone()],
        ] {
            let policy = DlpScopePolicy::from_selectors(selectors).expect("a valid policy");
            assert_eq!(
                policy.evaluate(&pod_facts("payments", "vault-0", "/kubepods/vault")),
                DlpScopeVerdict::Excluded {
                    rule: "not-the-vault".to_string()
                }
            );
            assert_eq!(
                policy.evaluate(&pod_facts("payments", "api-0", "/kubepods/api")),
                DlpScopeVerdict::InScope {
                    rule: "all-of-payments".to_string()
                }
            );
        }
    }

    #[test]
    fn a_workload_no_rule_names_is_not_in_scope() {
        let mut include = selector("payments");
        include.namespace = Some("payments".to_string());
        let policy = DlpScopePolicy::from_selectors(vec![include]).expect("a valid policy");
        assert_eq!(
            policy.evaluate(&pod_facts("billing", "api-0", "/kubepods/billing")),
            DlpScopeVerdict::NotSelected
        );
    }

    #[test]
    fn an_unnamed_rule_is_reported_by_its_matchers() {
        let rule = DlpScopeSelector {
            unit: Some("nginx.service".to_string()),
            ..DlpScopeSelector::default()
        };
        assert_eq!(rule.label(), "unit=nginx.service");
    }

    #[test]
    fn a_rule_naming_a_fact_the_node_never_produced_says_so() {
        let mut rule = selector("by-pod");
        rule.pod = Some("api-0".to_string());
        let mut evidence = DlpScopeEvidence::default();
        evidence.record(&DlpWorkloadFacts {
            cgroup: Some("/system.slice/nginx.service"),
            unit: Some("nginx.service"),
            ..DlpWorkloadFacts::default()
        });
        let finding = DlpUnmatchedSelector::new(&rule, &evidence);
        assert_eq!(finding.rule, "by-pod");
        assert!(finding.reason.contains("resolved no pod at all"));
    }

    #[test]
    fn a_rule_whose_facts_exist_is_reported_without_the_evidence_clause() {
        let mut rule = selector("by-unit");
        rule.unit = Some("absent.service".to_string());
        let mut evidence = DlpScopeEvidence::default();
        evidence.record(&DlpWorkloadFacts {
            unit: Some("nginx.service"),
            ..DlpWorkloadFacts::default()
        });
        let finding = DlpUnmatchedSelector::new(&rule, &evidence);
        assert_eq!(finding.reason, "no workload on this node matches it");
    }

    #[test]
    fn a_container_id_prefix_shorter_than_a_runtime_prints_is_refused() {
        let mut rule = selector("short");
        rule.container = Some("abc123".to_string());
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_cgroup_escaping_the_root_is_refused() {
        let mut rule = selector("escape");
        rule.cgroup = Some("/kubepods/../../etc".to_string());
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_relative_executable_is_refused() {
        let mut rule = selector("relative");
        rule.exe = Some("nginx".to_string());
        assert!(rule.validate().is_err());
    }

    #[test]
    fn a_policy_naming_which_selector_is_wrong() {
        let mut good = selector("ok");
        good.unit = Some("nginx.service".to_string());
        let err = DlpScopePolicy::from_selectors(vec![good, DlpScopeSelector::default()])
            .expect_err("the second selector names nothing");
        assert!(err.to_string().contains("selector 1"));
    }

    #[test]
    fn more_selectors_than_the_bound_are_refused() {
        let mut rule = selector("one");
        rule.unit = Some("nginx.service".to_string());
        let selectors = vec![rule; DLP_SCOPE_MAX_SELECTORS + 1];
        assert!(DlpScopePolicy::from_selectors(selectors).is_err());
    }

    #[test]
    fn an_executable_rule_is_the_one_that_needs_a_task() {
        let mut by_unit = selector("unit");
        by_unit.unit = Some("nginx.service".to_string());
        let mut by_exe = selector("exe");
        by_exe.exe = Some("/usr/sbin/nginx".to_string());
        assert!(
            !DlpScopePolicy::from_selectors(vec![by_unit.clone()])
                .expect("valid")
                .needs_executables()
        );
        assert!(
            DlpScopePolicy::from_selectors(vec![by_unit, by_exe])
                .expect("valid")
                .needs_executables()
        );
    }

    #[test]
    fn the_mode_words_round_trip() {
        for mode in [DlpScopeMode::All, DlpScopeMode::Workloads] {
            assert_eq!(DlpScopeMode::parse(mode.as_str()), Ok(mode));
        }
        assert_eq!(DlpScopeMode::parse("tenants"), Err("tenants"));
        assert!(DlpScopeMode::Workloads.is_scoped());
        assert!(!DlpScopeMode::All.is_scoped());
    }

    #[test]
    fn the_action_words_round_trip() {
        for action in [DlpScopeAction::Include, DlpScopeAction::Exclude] {
            assert_eq!(DlpScopeAction::parse(action.as_str()), Ok(action));
        }
        assert_eq!(DlpScopeAction::parse("deny"), Err("deny"));
    }

    #[test]
    fn a_report_line_prefers_the_container_name_over_its_id() {
        let facts = DlpWorkloadFacts {
            container_id: Some("abcdef123456789"),
            container_name: Some("payments-api"),
            cgroup: Some("/docker/abcdef"),
            ..DlpWorkloadFacts::default()
        };
        let line = DlpScopedWorkload::from_facts(&facts, Some(42), "rule".to_string());
        assert_eq!(line.container.as_deref(), Some("payments-api"));
        assert_eq!(line.cgroup_id, Some(42));
    }
}
