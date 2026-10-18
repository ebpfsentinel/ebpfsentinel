//! Attaching the socket-attribution hooks, and saying so when they cannot be.
//!
//! The six programs of the attribution object sit on a cgroup rather than on
//! an interface: `connect4`/`connect6` and `sendmsg4`/`sendmsg6` fire in the
//! syscall of the task that opens the socket, `post_bind4`/`post_bind6` when
//! it binds one. Attaching to the root of the v2 hierarchy covers every task
//! on the node, which is what a node agent wants.
//!
//! Nothing here enforces. Every program returns the allow verdict and the
//! only thing it writes is one entry in a table keyed by socket cookie. A
//! kernel that refuses the attach costs the workload name on a flow and
//! nothing else, which is why this module degrades rather than failing the
//! start: the reason is logged once and published, so an operator reading a
//! flow with no workload can find out why instead of guessing.

use std::os::fd::{OwnedFd, RawFd};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use tracing::{info, warn};

use super::kfunc_attach;
use super::loader::EbpfLoader;

/// `BPF_CGROUP_SOCK_OPS` from `enum bpf_attach_type`.
pub const BPF_CGROUP_SOCK_OPS: u32 = 3;
/// `BPF_CGROUP_INET4_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
/// `BPF_CGROUP_INET6_CONNECT` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;
/// `BPF_CGROUP_INET4_POST_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET4_POST_BIND: u32 = 12;
/// `BPF_CGROUP_INET6_POST_BIND` from `enum bpf_attach_type`.
pub const BPF_CGROUP_INET6_POST_BIND: u32 = 13;
/// `BPF_CGROUP_UDP4_SENDMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
/// `BPF_CGROUP_UDP6_SENDMSG` from `enum bpf_attach_type`.
pub const BPF_CGROUP_UDP6_SENDMSG: u32 = 15;

/// The one hook of the object that may be absent on its own.
///
/// It joins the socket the other six recorded to the connection the datapath
/// sees, and it is the only program of the object that calls
/// `bpf_get_socket_cookie` from a `sock_ops` context. A kernel can refuse
/// that one helper to that one program type while taking every other hook -
/// a tokenized rootless load on Linux 7.0 does exactly that - and when it
/// does, the workload is still named on the socket and the flow is
/// correlated by its five-tuple instead of by the cookie.
pub const ATTRIBUTION_JOIN_HOOK: &str = "attribution_sockops";

/// The programs of the attribution object, with the attach type each one is
/// loaded for. The order is the order they are attached in, and the first
/// failure stops the pass: a host refusing `connect4` refuses the rest. The
/// exception is [`ATTRIBUTION_JOIN_HOOK`], which the loader may report as
/// refused on its own.
pub const ATTRIBUTION_HOOKS: &[(&str, u32)] = &[
    ("attribution_connect4", BPF_CGROUP_INET4_CONNECT),
    ("attribution_connect6", BPF_CGROUP_INET6_CONNECT),
    ("attribution_post_bind4", BPF_CGROUP_INET4_POST_BIND),
    ("attribution_post_bind6", BPF_CGROUP_INET6_POST_BIND),
    ("attribution_sendmsg4", BPF_CGROUP_UDP4_SENDMSG),
    ("attribution_sendmsg6", BPF_CGROUP_UDP6_SENDMSG),
    ("attribution_sockops", BPF_CGROUP_SOCK_OPS),
];

/// What the agent can say about socket attribution, for the start-up log and
/// for the kernel-features endpoint.
///
/// `attached` false with a `reason` is the degraded case the whole module
/// exists to make legible: the agent is running, flows carry no workload, and
/// the sentence says which hook the kernel refused and with what errno.
/// `attached` true with a `reason` is the narrower one: every socket is still
/// named, and only the cookie-to-flow join is missing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttributionStatus {
    /// Every hook is attached and the socket table is being filled.
    pub attached: bool,
    /// The cgroup the hooks sit on, as configured.
    pub cgroup: String,
    /// The hook names that did attach, in attach order.
    pub hooks: Vec<String>,
    /// Why attribution is off or partial, in one sentence. `None` when
    /// everything attached.
    pub reason: Option<String>,
    /// The attach went through the warden rather than being issued here.
    pub brokered: bool,
}

/// The one status the whole process reports, written by the attacher and read
/// by the kernel-features handler.
static STATUS: OnceLock<Mutex<AttributionStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<AttributionStatus> {
    STATUS.get_or_init(|| Mutex::new(AttributionStatus::default()))
}

/// Publish what the agent can say about socket attribution.
pub fn publish_status(status: AttributionStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about socket attribution.
#[must_use]
pub fn status() -> AttributionStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The one sentence an operator gets when the kernel refused the join hook.
///
/// It names what is lost rather than what failed: every socket is still
/// attributed, and a flow the datapath reports is matched to one by its
/// five-tuple, so the workload arrives with `flow` as its source instead of
/// `socket`. The loader's own error is carried along, because the helper and
/// the errno are what tell a kernel engineer which refusal this is.
#[must_use]
pub fn join_refused_reason(refusal: &str) -> String {
    format!(
        "the kernel refused the socket-to-flow join program, so an established flow is matched \
         to its socket by five-tuple and the workload arrives with `flow` as its source rather \
         than `socket`; every socket is still named: {refusal}"
    )
}

/// Holds the cgroup links alive. Dropping it detaches every hook, which is
/// what a hot reload that turns attribution off does.
#[derive(Default)]
pub struct AttributionAttacher {
    links: Vec<OwnedFd>,
    /// Set when the privileged `BPF_LINK_CREATE` goes through the warden.
    warden_sock: Option<PathBuf>,
    warden: Option<Mutex<ebpfsentinel_warden_client::ReconnectingClient>>,
}

impl AttributionAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Route the privileged `BPF_LINK_CREATE` through the warden at `sock`.
    ///
    /// The rootless agent holds no capability over the cgroup hierarchy, and
    /// the hierarchy it can see is not necessarily the host's. The warden,
    /// which stays in the init namespaces, resolves the path and creates the
    /// link; the agent ends up owning the link fd either way, so an agent that
    /// dies still takes the programs off the cgroup with it.
    #[must_use]
    pub fn with_warden_socket(mut self, sock: impl Into<PathBuf>) -> Self {
        let sock = sock.into();
        self.warden = Some(crate::warden::attribution::client_for(&sock));
        self.warden_sock = Some(sock);
        self
    }

    /// Attach every hook of `loader` to `cgroup`, publishing what happened.
    ///
    /// Returns the status rather than an error: there is no caller for whom a
    /// refused attach is fatal, and returning `Result` would invite one to
    /// treat it as such.
    pub fn attach_all(&mut self, loader: &EbpfLoader, cgroup: &str) -> AttributionStatus {
        let mut hooks = Vec::with_capacity(ATTRIBUTION_HOOKS.len());
        let mut degraded = None;
        for (program, attach_type) in ATTRIBUTION_HOOKS {
            // The join hook may be missing from the object: the loader was
            // told to tolerate a kernel refusing it, and attaching the six
            // hooks that did load is worth more than taking them down with
            // it. Everything else is still all-or-nothing.
            if *program == ATTRIBUTION_JOIN_HOOK
                && let Some(refusal) = loader.refused_program(ATTRIBUTION_JOIN_HOOK)
            {
                warn!(
                    program,
                    cgroup, refusal, "socket attribution joins flows by five-tuple on this host"
                );
                degraded = Some(join_refused_reason(refusal));
                continue;
            }
            match self.attach_one(loader, cgroup, program, *attach_type) {
                Ok(link) => {
                    self.links.push(link);
                    hooks.push((*program).to_string());
                }
                Err(reason) => {
                    // Anything already attached comes off: half the hooks is
                    // worse than none, because a flow with no workload would
                    // then mean "transited" on one path and "not attached" on
                    // another, and nothing on the wire distinguishes them.
                    self.links.clear();
                    warn!(
                        program,
                        cgroup, reason, "socket attribution off: the cgroup attach was refused"
                    );
                    let status = AttributionStatus {
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
            joined = degraded.is_none(),
            "socket attribution attached"
        );
        let status = AttributionStatus {
            attached: true,
            cgroup: cgroup.to_owned(),
            hooks,
            reason: degraded,
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

    /// Detach every hook, leaving the agent running with no workload block.
    pub fn detach_all(&mut self) {
        if self.links.is_empty() {
            return;
        }
        self.links.clear();
        info!("socket attribution detached");
        publish_status(AttributionStatus::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_hook_is_named_once_and_carries_its_own_attach_type() {
        let mut names: Vec<&str> = ATTRIBUTION_HOOKS.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ATTRIBUTION_HOOKS.len());

        let mut types: Vec<u32> = ATTRIBUTION_HOOKS.iter().map(|(_, t)| *t).collect();
        types.sort_unstable();
        types.dedup();
        assert_eq!(types.len(), ATTRIBUTION_HOOKS.len());
    }

    #[test]
    fn the_join_hook_is_one_of_the_hooks_and_is_attached_last() {
        // Last matters: the six that name the socket attach before the one
        // that joins it to a flow, so a refusal of the join costs nothing
        // that already attached.
        let last = ATTRIBUTION_HOOKS
            .last()
            .map(|(name, _)| *name)
            .expect("the hook table is never empty");
        assert_eq!(last, ATTRIBUTION_JOIN_HOOK);
    }

    #[test]
    fn the_join_refusal_names_the_cost_and_keeps_the_kernel_error() {
        let reason = join_refused_reason(
            "BPF_PROG_LOAD `attribution_sockops` (prog_type 15, expected_attach_type 0) \
             failed (errno 22)",
        );
        assert!(reason.contains("five-tuple"));
        assert!(reason.contains("`flow`"));
        assert!(reason.contains("every socket is still named"));
        assert!(reason.contains("errno 22"));
    }

    #[test]
    fn the_default_status_says_nothing_is_attached_and_blames_nobody() {
        let s = AttributionStatus::default();
        assert!(!s.attached);
        assert!(s.reason.is_none());
        assert!(s.hooks.is_empty());
    }

    #[test]
    fn a_published_status_is_what_the_next_reader_gets() {
        let s = AttributionStatus {
            attached: true,
            cgroup: "/sys/fs/cgroup".to_string(),
            hooks: vec!["attribution_connect4".to_string()],
            reason: None,
            brokered: true,
        };
        publish_status(s.clone());
        assert_eq!(status(), s);
        publish_status(AttributionStatus::default());
    }
}
