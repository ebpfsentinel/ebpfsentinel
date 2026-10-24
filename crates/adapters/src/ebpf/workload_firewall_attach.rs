//! Attaching the workload firewall hooks, and saying so when they cannot be.
//!
//! Six programs on a cgroup: `connect4`/`connect6`, `sendmsg4`/`sendmsg6` and
//! `bind4`/`bind6`. The bind pair is the pre-bind one rather than the
//! post-bind pair the attribution object attaches, because post-bind runs
//! after the kernel has assigned the address and can report it but not refuse
//! it.
//!
//! Two more read the packets of a cgroup, egress and ingress, so the answers
//! a named workload is given reach the agent: a rule naming its destination by
//! DNS name is opened by them. They decide nothing and copy nothing until a
//! policy carrying such a rule is in force, and they are part of the same
//! all-or-nothing attach, because a policy that names a destination it can
//! never learn is a policy refusing what it says it allows.
//!
//! Unlike attribution, this object decides things, so a refused attach is not
//! always survivable. The decision is the caller's rather than this module's:
//! the status says what attached, and the start-up path refuses to come up
//! when a policy that enforces is loaded and nothing is enforcing it. A
//! policy that only observes is allowed to run degraded, because what is lost
//! there is a counter.

use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use tracing::{info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;

/// `BPF_CGROUP_INET_INGRESS` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET_INGRESS: u32 = 0;
/// `BPF_CGROUP_INET_EGRESS` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET_EGRESS: u32 = 1;
/// `BPF_CGROUP_INET4_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_BIND: u32 = 8;
/// `BPF_CGROUP_INET6_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_BIND: u32 = 9;
/// `BPF_CGROUP_INET4_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
/// `BPF_CGROUP_INET6_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;
/// `BPF_CGROUP_UDP4_SENDMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
/// `BPF_CGROUP_UDP6_SENDMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP6_SENDMSG: u32 = 15;

/// The programs of the workload firewall, with the attach type each one is
/// loaded for, in the order they are attached.
///
/// All or nothing, with no exception of the kind attribution's join hook is:
/// a policy enforced on `connect()` and not on `sendmsg()` is a policy a
/// datagram walks through, and half an enforcement is the shape of failure
/// that gets written up as a bypass.
pub const WORKLOAD_HOOKS: &[(&str, u32)] = &[
    ("workload_connect4", BPF_CGROUP_INET4_CONNECT),
    ("workload_connect6", BPF_CGROUP_INET6_CONNECT),
    ("workload_sendmsg4", BPF_CGROUP_UDP4_SENDMSG),
    ("workload_sendmsg6", BPF_CGROUP_UDP6_SENDMSG),
    ("workload_bind4", BPF_CGROUP_INET4_BIND),
    ("workload_bind6", BPF_CGROUP_INET6_BIND),
    ("workload_dns_egress", BPF_CGROUP_INET_EGRESS),
    ("workload_dns_ingress", BPF_CGROUP_INET_INGRESS),
];

/// What the agent can say about the workload firewall, for the start-up log
/// and for the kernel-features endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadFirewallStatus {
    /// Every hook is attached and the policy is being decided in the kernel.
    pub attached: bool,
    /// The cgroup the hooks sit on, as configured.
    pub cgroup: String,
    /// The hook names that did attach, in attach order.
    pub hooks: Vec<String>,
    /// Why the workload firewall is off, in one sentence. `None` when every
    /// hook attached.
    pub reason: Option<String>,
    /// The attach went through the warden rather than being issued here.
    pub brokered: bool,
}

/// The one status the whole process reports.
static STATUS: OnceLock<Mutex<WorkloadFirewallStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<WorkloadFirewallStatus> {
    STATUS.get_or_init(|| Mutex::new(WorkloadFirewallStatus::default()))
}

/// Publish what the agent can say about the workload firewall.
pub fn publish_status(status: WorkloadFirewallStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the workload firewall.
#[must_use]
pub fn status() -> WorkloadFirewallStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The sentence a start-up refusal carries.
///
/// It says what the operator asked for and what the host would have given
/// them, because the alternative - starting, reporting healthy and enforcing
/// nothing - is the failure that is only discovered by the thing the rule was
/// written to stop.
#[must_use]
pub fn enforcement_unavailable(reason: &str) -> String {
    format!(
        "the configuration carries a workload rule that refuses, and the cgroup hooks that would \
         carry out the refusal did not attach, so the agent would run with the rule in the file \
         and nothing enforcing it: {reason}"
    )
}

/// Holds the cgroup links alive. Dropping it detaches every hook.
#[derive(Default)]
pub struct WorkloadFirewallAttacher {
    links: Vec<OwnedFd>,
    /// Set when the privileged `BPF_LINK_CREATE` goes through the warden.
    warden_sock: Option<PathBuf>,
    warden: Option<Mutex<ebpfsentinel_warden_client::ReconnectingClient>>,
}

impl WorkloadFirewallAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Route the privileged `BPF_LINK_CREATE` through the warden at `sock`,
    /// which is what a rootless agent with no hold on the cgroup hierarchy
    /// does.
    #[must_use]
    pub fn with_warden_socket(mut self, sock: impl Into<PathBuf>) -> Self {
        let sock = sock.into();
        self.warden = Some(crate::warden::attribution::client_for(&sock));
        self.warden_sock = Some(sock);
        self
    }

    /// Attach every hook of `loader` to `cgroup`, publishing what happened.
    pub fn attach_all(&mut self, loader: &EbpfLoader, cgroup: &str) -> WorkloadFirewallStatus {
        let mut hooks = Vec::with_capacity(WORKLOAD_HOOKS.len());
        for (program, attach_type) in WORKLOAD_HOOKS {
            match self.attach_one(loader, cgroup, program, *attach_type) {
                Ok(link) => {
                    self.links.push(link);
                    hooks.push((*program).to_string());
                }
                Err(reason) => {
                    // Anything already attached comes off. A policy enforced
                    // on one syscall and not on its neighbour is a policy
                    // with a hole in it, and the hole is not visible from
                    // anything the agent reports.
                    self.links.clear();
                    warn!(
                        program,
                        cgroup, reason, "workload firewall off: the cgroup attach was refused"
                    );
                    let status = WorkloadFirewallStatus {
                        attached: false,
                        cgroup: cgroup.to_owned(),
                        hooks: Vec::new(),
                        reason: Some(reason),
                        brokered: self.warden_sock.is_some(),
                    };
                    publish_status(status.clone());
                    return status;
                }
            }
        }
        info!(
            cgroup,
            hooks = hooks.len(),
            brokered = self.warden_sock.is_some(),
            "workload firewall attached"
        );
        let status = WorkloadFirewallStatus {
            attached: true,
            cgroup: cgroup.to_owned(),
            hooks,
            reason: None,
            brokered: self.warden_sock.is_some(),
        };
        publish_status(status.clone());
        status
    }

    /// Attach one program, through the warden where there is one.
    fn attach_one(
        &self,
        loader: &EbpfLoader,
        cgroup: &str,
        program: &str,
        attach_type: u32,
    ) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader
            .program_fd(program)
            .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
        match &self.warden {
            Some(client) => {
                crate::warden::attribution::attach_via_warden(client, prog_fd, cgroup, attach_type)
                    .map_err(|e| e.to_string())
            }
            None => kfunc_attach::attach_cgroup(program, prog_fd, cgroup, attach_type)
                .map_err(|e| e.to_string()),
        }
    }

    /// How many hooks this attacher currently holds a link for.
    #[must_use]
    pub fn attached(&self) -> usize {
        self.links.len()
    }

    /// Detach every hook, which leaves the policy decided by nothing.
    pub fn detach_all(&mut self) {
        if self.links.is_empty() {
            return;
        }
        self.links.clear();
        info!("workload firewall detached");
        publish_status(WorkloadFirewallStatus::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hook_is_named_once_and_carries_its_own_attach_type() {
        let mut names: Vec<&str> = WORKLOAD_HOOKS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), WORKLOAD_HOOKS.len());

        let mut types: Vec<u32> = WORKLOAD_HOOKS.iter().map(|(_, t)| *t).collect();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), WORKLOAD_HOOKS.len());
    }

    #[test]
    fn the_bind_hooks_are_the_ones_that_run_before_the_kernel_assigns_the_address() {
        // Post-bind is 12 and 13 and is what attribution attaches, because
        // naming a listener is all it wants. Refusing one needs 8 and 9, and
        // the two pairs are one digit apart in a header nobody reads twice.
        let bind: Vec<u32> = WORKLOAD_HOOKS
            .iter()
            .filter(|(name, _)| name.contains("bind"))
            .map(|(_, attach_type)| *attach_type)
            .collect();
        assert_eq!(bind, vec![BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND]);
    }

    #[test]
    fn the_dns_hooks_sit_on_both_directions_of_the_cgroup() {
        let dns: Vec<u32> = WORKLOAD_HOOKS
            .iter()
            .filter(|(name, _)| name.contains("dns"))
            .map(|(_, attach_type)| *attach_type)
            .collect();
        assert_eq!(dns, vec![BPF_CGROUP_INET_EGRESS, BPF_CGROUP_INET_INGRESS]);
    }

    #[test]
    fn the_refusal_to_start_says_what_was_asked_for_and_what_the_host_gave() {
        let sentence = enforcement_unavailable("connect4: Operation not permitted (os error 1)");
        assert!(sentence.contains("nothing enforcing it"));
        assert!(sentence.contains("Operation not permitted"));
    }

    #[test]
    fn an_attacher_holding_no_link_detaches_without_touching_the_published_status() {
        publish_status(WorkloadFirewallStatus {
            attached: true,
            cgroup: "/sys/fs/cgroup".to_string(),
            hooks: vec!["workload_connect4".to_string()],
            reason: None,
            brokered: false,
        });
        let mut attacher = WorkloadFirewallAttacher::new();
        attacher.detach_all();
        assert!(status().attached);
        publish_status(WorkloadFirewallStatus::default());
    }
}
