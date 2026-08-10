//! Runtime per-program-type BPF helper probe.
//!
//! [`kernel_probe`](super::kernel_probe) answers "which kernel version is
//! this", which is a proxy for capability, not capability itself. Vendors
//! backport helpers into older trees and distributions compile features out,
//! so the version and the truth diverge. This module asks the running kernel
//! directly: for every `(program type, helper)` pair the agent's objects
//! actually reference, it loads a two-instruction program that calls the
//! helper and reads the verifier's answer.
//!
//! Two limits are deliberate and must stay visible to whoever reads the
//! output:
//!
//! - **The probe needs `CAP_BPF`.** It issues a plain `BPF_PROG_LOAD` with no
//!   token, because a token authorises the agent's own objects, not an
//!   arbitrary probe program. The agent's normal path is token-only and holds
//!   no `CAP_BPF`, so on that path the probe cannot run at all. It then
//!   reports [`ProbeStatus::NotProbed`] - never "unsupported", which would be
//!   a false negative that reads as a broken kernel.
//! - **Only helpers are probeable.** kfuncs (`bpf_ct_lookup`, the XDP
//!   metadata family, dynptr) are not `bpf_func_id` values and have no
//!   equivalent probe; their availability still comes from the BTF check and
//!   the documented floor.

use std::fmt;
use std::sync::OnceLock;

use aya::programs::ProgramType;
use aya::sys::{BpfHelper, is_helper_supported, is_program_supported};

/// A helper the agent's objects reference, paired with the name to print.
///
/// The name is carried rather than derived because `BpfHelper` is a generated
/// binding whose `Debug` output is the C enum spelling; operators read
/// `bpf_skb_load_bytes`, not `BPF_FUNC_skb_load_bytes`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Helper {
    pub name: &'static str,
    id: BpfHelper,
}

impl Helper {
    const fn new(name: &'static str, id: BpfHelper) -> Self {
        Self { name, id }
    }
}

macro_rules! helpers {
    ($($konst:ident => $name:literal),* $(,)?) => {
        $(
            #[allow(non_upper_case_globals)]
            const $konst: Helper = Helper::new($name, BpfHelper::$konst);
        )*
    };
}

helpers! {
    BPF_FUNC_map_lookup_elem => "bpf_map_lookup_elem",
    BPF_FUNC_ktime_get_boot_ns => "bpf_ktime_get_boot_ns",
    BPF_FUNC_ktime_get_coarse_ns => "bpf_ktime_get_coarse_ns",
    BPF_FUNC_get_smp_processor_id => "bpf_get_smp_processor_id",
    BPF_FUNC_get_prandom_u32 => "bpf_get_prandom_u32",
    BPF_FUNC_get_current_cgroup_id => "bpf_get_current_cgroup_id",
    BPF_FUNC_get_current_pid_tgid => "bpf_get_current_pid_tgid",
    BPF_FUNC_get_socket_cookie => "bpf_get_socket_cookie",
    BPF_FUNC_probe_read_kernel => "bpf_probe_read_kernel",
    BPF_FUNC_probe_read_user => "bpf_probe_read_user",
    BPF_FUNC_loop => "bpf_loop",
    BPF_FUNC_check_mtu => "bpf_check_mtu",
    BPF_FUNC_fib_lookup => "bpf_fib_lookup",
    BPF_FUNC_csum_diff => "bpf_csum_diff",
    BPF_FUNC_l3_csum_replace => "bpf_l3_csum_replace",
    BPF_FUNC_l4_csum_replace => "bpf_l4_csum_replace",
    BPF_FUNC_clone_redirect => "bpf_clone_redirect",
    BPF_FUNC_skb_load_bytes => "bpf_skb_load_bytes",
    BPF_FUNC_skb_store_bytes => "bpf_skb_store_bytes",
    BPF_FUNC_skb_cgroup_id => "bpf_skb_cgroup_id",
    BPF_FUNC_skb_ecn_set_ce => "bpf_skb_ecn_set_ce",
    BPF_FUNC_skb_set_tstamp => "bpf_skb_set_tstamp",
    BPF_FUNC_xdp_adjust_meta => "bpf_xdp_adjust_meta",
    BPF_FUNC_xdp_adjust_tail => "bpf_xdp_adjust_tail",
    BPF_FUNC_ringbuf_reserve => "bpf_ringbuf_reserve",
    BPF_FUNC_ringbuf_submit => "bpf_ringbuf_submit",
    BPF_FUNC_ringbuf_discard => "bpf_ringbuf_discard",
    BPF_FUNC_ringbuf_query => "bpf_ringbuf_query",
    BPF_FUNC_tcp_raw_gen_syncookie_ipv4 => "bpf_tcp_raw_gen_syncookie_ipv4",
    BPF_FUNC_tcp_raw_gen_syncookie_ipv6 => "bpf_tcp_raw_gen_syncookie_ipv6",
    BPF_FUNC_tcp_raw_check_syncookie_ipv4 => "bpf_tcp_raw_check_syncookie_ipv4",
    BPF_FUNC_tcp_raw_check_syncookie_ipv6 => "bpf_tcp_raw_check_syncookie_ipv6",
}

/// The three program types the agent ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProbeType {
    Xdp,
    SchedClassifier,
    KProbe,
}

impl ProbeType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xdp => "xdp",
            Self::SchedClassifier => "sched_cls",
            Self::KProbe => "kprobe",
        }
    }

    const fn as_aya(self) -> ProgramType {
        match self {
            Self::Xdp => ProgramType::Xdp,
            Self::SchedClassifier => ProgramType::SchedClassifier,
            Self::KProbe => ProgramType::KProbe,
        }
    }
}

impl fmt::Display for ProbeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Helpers every object needs regardless of what else it calls: a map lookup
/// (all of them read at least one configuration map) and, for the ones that
/// emit events, the ring-buffer trio.
const BASE: &[Helper] = &[BPF_FUNC_map_lookup_elem];
const RINGBUF: &[Helper] = &[
    BPF_FUNC_ringbuf_reserve,
    BPF_FUNC_ringbuf_submit,
    BPF_FUNC_ringbuf_discard,
];

/// What one compiled object needs from the kernel.
///
/// `helpers` is the object's own call set, taken from its source rather than
/// from the program type: attributing the whole type's union to every object
/// would fail a load that would in fact have succeeded. kfuncs are absent by
/// construction - they are not probeable, see the module docs.
#[derive(Debug, Clone, Copy)]
pub struct ObjectRequirements {
    pub object: &'static str,
    pub program_type: ProbeType,
    pub own: &'static [Helper],
    pub uses_ringbuf: bool,
}

impl ObjectRequirements {
    /// Every helper this object requires, base set included.
    pub fn helpers(&self) -> impl Iterator<Item = Helper> + '_ {
        let ringbuf: &'static [Helper] = if self.uses_ringbuf { RINGBUF } else { &[] };
        BASE.iter()
            .copied()
            .chain(self.own.iter().copied())
            .chain(ringbuf.iter().copied())
    }
}

const fn xdp(
    object: &'static str,
    own: &'static [Helper],
    uses_ringbuf: bool,
) -> ObjectRequirements {
    ObjectRequirements {
        object,
        program_type: ProbeType::Xdp,
        own,
        uses_ringbuf,
    }
}

const fn tc(
    object: &'static str,
    own: &'static [Helper],
    uses_ringbuf: bool,
) -> ObjectRequirements {
    ObjectRequirements {
        object,
        program_type: ProbeType::SchedClassifier,
        own,
        uses_ringbuf,
    }
}

/// Every helper name this module knows how to probe. A `bpf_*` call in a
/// program source that is not here and not a kfunc is an unclassified call,
/// which the `requirements_match_sources` test refuses. That test is its only
/// consumer - at runtime a helper matters only through the object that needs
/// it.
#[cfg(test)]
const HELPER_UNIVERSE: &[Helper] = &[
    BPF_FUNC_map_lookup_elem,
    BPF_FUNC_ktime_get_boot_ns,
    BPF_FUNC_ktime_get_coarse_ns,
    BPF_FUNC_get_smp_processor_id,
    BPF_FUNC_get_prandom_u32,
    BPF_FUNC_get_current_cgroup_id,
    BPF_FUNC_get_current_pid_tgid,
    BPF_FUNC_get_socket_cookie,
    BPF_FUNC_probe_read_kernel,
    BPF_FUNC_probe_read_user,
    BPF_FUNC_loop,
    BPF_FUNC_check_mtu,
    BPF_FUNC_fib_lookup,
    BPF_FUNC_csum_diff,
    BPF_FUNC_l3_csum_replace,
    BPF_FUNC_l4_csum_replace,
    BPF_FUNC_clone_redirect,
    BPF_FUNC_skb_load_bytes,
    BPF_FUNC_skb_store_bytes,
    BPF_FUNC_skb_cgroup_id,
    BPF_FUNC_skb_ecn_set_ce,
    BPF_FUNC_skb_set_tstamp,
    BPF_FUNC_xdp_adjust_meta,
    BPF_FUNC_xdp_adjust_tail,
    BPF_FUNC_ringbuf_reserve,
    BPF_FUNC_ringbuf_submit,
    BPF_FUNC_ringbuf_discard,
    BPF_FUNC_ringbuf_query,
    BPF_FUNC_tcp_raw_gen_syncookie_ipv4,
    BPF_FUNC_tcp_raw_gen_syncookie_ipv6,
    BPF_FUNC_tcp_raw_check_syncookie_ipv4,
    BPF_FUNC_tcp_raw_check_syncookie_ipv6,
];

/// The 16 compiled objects and the helpers each one calls.
///
/// Kept in sync with the sources by the `requirements_match_sources` test in
/// this module's test tree, which greps the program crates: adding a helper
/// call without adding it here fails that test rather than surfacing as a
/// verifier rejection on some operator's kernel.
pub const REQUIREMENTS: &[ObjectRequirements] = &[
    xdp(
        "xdp-firewall",
        &[
            BPF_FUNC_check_mtu,
            BPF_FUNC_fib_lookup,
            BPF_FUNC_get_smp_processor_id,
            BPF_FUNC_ktime_get_boot_ns,
            BPF_FUNC_loop,
            BPF_FUNC_probe_read_kernel,
            BPF_FUNC_xdp_adjust_meta,
        ],
        true,
    ),
    xdp(
        "xdp-firewall-reject",
        &[BPF_FUNC_ktime_get_boot_ns, BPF_FUNC_xdp_adjust_tail],
        false,
    ),
    xdp(
        "xdp-ratelimit",
        &[
            BPF_FUNC_check_mtu,
            BPF_FUNC_get_smp_processor_id,
            BPF_FUNC_ktime_get_boot_ns,
            BPF_FUNC_ktime_get_coarse_ns,
            BPF_FUNC_tcp_raw_check_syncookie_ipv4,
            BPF_FUNC_tcp_raw_check_syncookie_ipv6,
        ],
        true,
    ),
    xdp(
        "xdp-ratelimit-syncookie",
        &[
            BPF_FUNC_tcp_raw_gen_syncookie_ipv4,
            BPF_FUNC_tcp_raw_gen_syncookie_ipv6,
            BPF_FUNC_xdp_adjust_tail,
        ],
        false,
    ),
    xdp(
        "xdp-loadbalancer",
        &[
            BPF_FUNC_check_mtu,
            BPF_FUNC_get_smp_processor_id,
            BPF_FUNC_ktime_get_boot_ns,
        ],
        true,
    ),
    xdp("xdp-vip-announcer", &[], false),
    xdp("xdp-pass", &[], false),
    tc(
        "tc-ids",
        &[
            BPF_FUNC_clone_redirect,
            BPF_FUNC_get_current_cgroup_id,
            BPF_FUNC_get_prandom_u32,
            BPF_FUNC_get_smp_processor_id,
            BPF_FUNC_get_socket_cookie,
            BPF_FUNC_ktime_get_boot_ns,
            BPF_FUNC_skb_cgroup_id,
            BPF_FUNC_skb_load_bytes,
        ],
        true,
    ),
    tc(
        "tc-dns",
        &[
            BPF_FUNC_get_current_cgroup_id,
            BPF_FUNC_ktime_get_boot_ns,
            BPF_FUNC_ringbuf_query,
            BPF_FUNC_skb_load_bytes,
        ],
        true,
    ),
    tc("tc-conntrack", &[BPF_FUNC_probe_read_kernel], false),
    tc("tc-threatintel", &[], true),
    tc(
        "tc-nat-ingress",
        &[
            BPF_FUNC_l3_csum_replace,
            BPF_FUNC_l4_csum_replace,
            BPF_FUNC_loop,
            BPF_FUNC_skb_store_bytes,
        ],
        false,
    ),
    tc(
        "tc-nat-egress",
        &[
            BPF_FUNC_l3_csum_replace,
            BPF_FUNC_l4_csum_replace,
            BPF_FUNC_loop,
            BPF_FUNC_skb_store_bytes,
        ],
        false,
    ),
    tc(
        "tc-qos",
        &[
            BPF_FUNC_get_prandom_u32,
            BPF_FUNC_ktime_get_boot_ns,
            BPF_FUNC_skb_ecn_set_ce,
            BPF_FUNC_skb_set_tstamp,
        ],
        true,
    ),
    tc(
        "tc-scrub",
        &[
            BPF_FUNC_csum_diff,
            BPF_FUNC_get_prandom_u32,
            BPF_FUNC_l3_csum_replace,
            BPF_FUNC_l4_csum_replace,
            BPF_FUNC_loop,
        ],
        false,
    ),
    ObjectRequirements {
        object: "uprobe-dlp",
        program_type: ProbeType::KProbe,
        own: &[
            BPF_FUNC_get_current_cgroup_id,
            BPF_FUNC_get_current_pid_tgid,
            BPF_FUNC_ktime_get_boot_ns,
            BPF_FUNC_probe_read_user,
        ],
        uses_ringbuf: true,
    },
];

/// Whether the probe pass could run at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    /// The kernel answered; the per-helper results are meaningful.
    Probed,
    /// The probe could not run. The results are empty, **not** negative.
    NotProbed { reason: String },
}

impl ProbeStatus {
    #[must_use]
    pub const fn probed(&self) -> bool {
        matches!(self, Self::Probed)
    }
}

/// One `(program type, helper)` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperSupport {
    pub program_type: &'static str,
    pub helper: &'static str,
    pub supported: bool,
}

/// A helper an object needs that the kernel does not offer for its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingHelper {
    pub object: &'static str,
    pub program_type: &'static str,
    pub helper: &'static str,
}

impl fmt::Display for MissingHelper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} needs {} but this kernel does not support it for {} programs",
            self.object, self.helper, self.program_type
        )
    }
}

/// The whole pass, cached for the lifetime of the process.
#[derive(Debug, Clone)]
pub struct HelperReport {
    pub status: ProbeStatus,
    /// How the agent loads its objects. Constant today - the agent has one
    /// loading path - but printed alongside the probe so the asymmetry
    /// between "loads through a token" and "probes with `CAP_BPF`" is on the
    /// record rather than inferred.
    pub load_mode: &'static str,
    pub program_types: Vec<(&'static str, bool)>,
    pub helpers: Vec<HelperSupport>,
    pub missing_required: Vec<MissingHelper>,
}

impl HelperReport {
    /// An empty report for the case where the probe never ran.
    #[must_use]
    pub fn not_probed(reason: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::NotProbed {
                reason: reason.into(),
            },
            load_mode: LOAD_MODE,
            program_types: Vec::new(),
            helpers: Vec::new(),
            missing_required: Vec::new(),
        }
    }

    /// Missing helpers for one object, empty when the probe did not run.
    pub fn gaps_for(&self, object: &str) -> impl Iterator<Item = &MissingHelper> {
        self.missing_required
            .iter()
            .filter(move |m| m.object == object)
    }

    /// One line, suitable for a startup log.
    #[must_use]
    pub fn summary(&self) -> String {
        match &self.status {
            ProbeStatus::NotProbed { reason } => format!(
                "kernel helper probe not run (load mode {}): {reason}",
                self.load_mode
            ),
            ProbeStatus::Probed => {
                let total = self.helpers.len();
                let ok = self.helpers.iter().filter(|h| h.supported).count();
                format!(
                    "kernel helper probe (load mode {}): {ok}/{total} helper/program-type pairs \
                     supported across {} program types, {} required helper(s) missing",
                    self.load_mode,
                    self.program_types.len(),
                    self.missing_required.len()
                )
            }
        }
    }
}

/// The agent's single loading path. eBPF objects are loaded through a BPF
/// token, which is why a probe needing `CAP_BPF` can be unavailable on a host
/// where every program nevertheless loads fine.
pub const LOAD_MODE: &str = "bpf-token";

/// Probe outcome for one pair, as the injectable probe function reports it.
type ProbeFn<'a> = &'a mut dyn FnMut(ProbeType, Helper) -> Result<bool, String>;
type TypeProbeFn<'a> = &'a mut dyn FnMut(ProbeType) -> Result<bool, String>;

/// Build a report from an arbitrary probe implementation.
///
/// Split out from [`run`] so the mapping, the deduplication and the
/// cannot-probe path are testable without a kernel: the tests pass closures
/// that answer from a table.
#[must_use]
pub fn evaluate(type_probe: TypeProbeFn<'_>, helper_probe: ProbeFn<'_>) -> HelperReport {
    let mut program_types: Vec<(&'static str, bool)> = Vec::new();
    for ty in [
        ProbeType::Xdp,
        ProbeType::SchedClassifier,
        ProbeType::KProbe,
    ] {
        match type_probe(ty) {
            Ok(supported) => program_types.push((ty.as_str(), supported)),
            // The first failure ends the pass. A probe that cannot run fails
            // for every pair for the same reason, and hammering the kernel
            // with one rejected syscall per pair to learn that costs startup
            // latency for nothing.
            Err(reason) => return HelperReport::not_probed(reason),
        }
    }

    let mut helpers: Vec<HelperSupport> = Vec::new();
    let mut missing_required: Vec<MissingHelper> = Vec::new();

    for req in REQUIREMENTS {
        for helper in req.helpers() {
            let known = helpers
                .iter()
                .find(|h| h.program_type == req.program_type.as_str() && h.helper == helper.name)
                .map(|h| h.supported);

            let supported = match known {
                Some(s) => s,
                None => match helper_probe(req.program_type, helper) {
                    Ok(s) => {
                        helpers.push(HelperSupport {
                            program_type: req.program_type.as_str(),
                            helper: helper.name,
                            supported: s,
                        });
                        s
                    }
                    Err(reason) => return HelperReport::not_probed(reason),
                },
            };

            if !supported {
                missing_required.push(MissingHelper {
                    object: req.object,
                    program_type: req.program_type.as_str(),
                    helper: helper.name,
                });
            }
        }
    }

    HelperReport {
        status: ProbeStatus::Probed,
        load_mode: LOAD_MODE,
        program_types,
        helpers,
        missing_required,
    }
}

static CACHE: OnceLock<HelperReport> = OnceLock::new();

/// Run the probe once per process and keep the answer.
///
/// Probing is a `BPF_PROG_LOAD` per pair. Repeating it per object load would
/// multiply that by sixteen for an answer that cannot change while the
/// process runs.
pub fn init_cached() -> &'static HelperReport {
    CACHE.get_or_init(run)
}

/// The cached report, or `None` when startup has not probed yet.
///
/// Callers outside startup - the readiness probe, the operational endpoint -
/// use this rather than [`init_cached`], so that reading the state never
/// triggers a syscall pass of its own.
#[must_use]
pub fn cached() -> Option<&'static HelperReport> {
    CACHE.get()
}

/// Render an error together with its source chain.
///
/// aya's `SyscallError` displays as "`bpf_prog_load` failed" and keeps the
/// `io::Error` as a source, so `{e}` alone drops the errno - which is the only
/// part an operator can act on. "operation not permitted" says the probe was
/// refused; "invalid argument" would say something quite different.
fn with_sources(err: &dyn std::error::Error) -> String {
    use std::fmt::Write as _;

    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let _ = write!(out, ": {cause}");
        source = cause.source();
    }
    out
}

/// Probe the live kernel. One syscall per distinct `(program type, helper)`
/// pair, and the whole pass stops at the first syscall the kernel refuses.
#[must_use]
pub fn run() -> HelperReport {
    evaluate(
        &mut |ty| {
            is_program_supported(ty.as_aya())
                .map_err(|e| format!("{ty} program type: {}", with_sources(&e)))
        },
        &mut |ty, helper| {
            is_helper_supported(ty.as_aya(), helper.id)
                .map_err(|e| format!("{} for {ty} programs: {}", helper.name, with_sources(&e)))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn all_supported() -> HelperReport {
        evaluate(&mut |_| Ok(true), &mut |_, _| Ok(true))
    }

    #[test]
    fn every_object_has_a_requirement_entry() {
        // The 16 compiled objects, spelled as the build writes them out.
        let expected: HashSet<&str> = [
            "xdp-firewall",
            "xdp-firewall-reject",
            "xdp-ratelimit",
            "xdp-ratelimit-syncookie",
            "xdp-loadbalancer",
            "xdp-vip-announcer",
            "xdp-pass",
            "tc-ids",
            "tc-dns",
            "tc-conntrack",
            "tc-threatintel",
            "tc-nat-ingress",
            "tc-nat-egress",
            "tc-qos",
            "tc-scrub",
            "uprobe-dlp",
        ]
        .into_iter()
        .collect();
        let listed: HashSet<&str> = REQUIREMENTS.iter().map(|r| r.object).collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn base_helpers_apply_to_every_object() {
        for req in REQUIREMENTS {
            assert!(
                req.helpers().any(|h| h.name == "bpf_map_lookup_elem"),
                "{} lost the base helper set",
                req.object
            );
        }
    }

    #[test]
    fn ringbuf_objects_require_the_ringbuf_trio() {
        let dns = REQUIREMENTS
            .iter()
            .find(|r| r.object == "tc-dns")
            .expect("tc-dns entry");
        let names: Vec<&str> = dns.helpers().map(|h| h.name).collect();
        for expected in [
            "bpf_ringbuf_reserve",
            "bpf_ringbuf_submit",
            "bpf_ringbuf_discard",
            "bpf_ringbuf_query",
        ] {
            assert!(names.contains(&expected), "tc-dns missing {expected}");
        }

        let scrub = REQUIREMENTS
            .iter()
            .find(|r| r.object == "tc-scrub")
            .expect("tc-scrub entry");
        assert!(
            !scrub.helpers().any(|h| h.name == "bpf_ringbuf_reserve"),
            "tc-scrub emits no events and must not require the ring buffer"
        );
    }

    #[test]
    fn all_supported_reports_no_gap() {
        let report = all_supported();
        assert!(report.status.probed());
        assert!(report.missing_required.is_empty());
        assert_eq!(report.program_types.len(), 3);
        assert_eq!(report.load_mode, LOAD_MODE);
    }

    #[test]
    fn each_pair_is_probed_once() {
        let mut calls = 0usize;
        let report = evaluate(&mut |_| Ok(true), &mut |_, _| {
            calls += 1;
            Ok(true)
        });
        assert_eq!(
            calls,
            report.helpers.len(),
            "a repeated (type, helper) pair was probed twice"
        );
        // Cheap sanity bound: the pass must stay far below one syscall per
        // object per helper, which is what a naive loop would cost.
        let naive: usize = REQUIREMENTS.iter().map(|r| r.helpers().count()).sum();
        assert!(calls < naive, "deduplication did not reduce the syscalls");
    }

    #[test]
    fn a_missing_helper_names_object_type_and_helper() {
        let report = evaluate(&mut |_| Ok(true), &mut |ty, helper| {
            Ok(!(ty == ProbeType::Xdp && helper.name == "bpf_fib_lookup"))
        });
        let gaps: Vec<&MissingHelper> = report.gaps_for("xdp-firewall").collect();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].helper, "bpf_fib_lookup");
        assert_eq!(gaps[0].program_type, "xdp");
        assert_eq!(gaps[0].object, "xdp-firewall");
        assert!(gaps[0].to_string().contains("xdp-firewall needs"));
        // Only the object that calls it is blamed.
        assert!(report.gaps_for("tc-ids").next().is_none());
    }

    #[test]
    fn a_refused_type_probe_reports_not_probed_not_unsupported() {
        let report = evaluate(
            &mut |_| Err("Operation not permitted".into()),
            &mut |_, _| panic!("helper probe must not run once the type probe was refused"),
        );
        assert!(!report.status.probed());
        assert!(report.missing_required.is_empty());
        assert!(report.helpers.is_empty());
        assert!(report.summary().contains("not run"));
        assert!(report.summary().contains("Operation not permitted"));
    }

    #[test]
    fn a_refused_helper_probe_discards_partial_results() {
        // A pass that dies halfway must not publish the pairs it did manage:
        // a partial table reads as "these are the only helpers there are".
        let report = evaluate(&mut |_| Ok(true), &mut |_, helper| {
            if helper.name == "bpf_map_lookup_elem" {
                Ok(true)
            } else {
                Err("Operation not permitted".into())
            }
        });
        assert!(!report.status.probed());
        assert!(report.helpers.is_empty());
    }

    #[test]
    fn not_probed_never_blames_an_object() {
        let report = HelperReport::not_probed("no CAP_BPF");
        assert!(report.gaps_for("xdp-firewall").next().is_none());
        assert_eq!(report.load_mode, LOAD_MODE);
    }

    /// `bpf_*` names that are kfuncs, not helpers. They have no `bpf_func_id`
    /// and therefore no probe; the BTF check and the documented kernel floor
    /// cover them. Listed rather than pattern-matched so that a genuinely new
    /// helper cannot slip through as "probably a kfunc".
    const KFUNCS: &[&str] = &[
        "bpf_ct_change_status",
        "bpf_ct_change_timeout",
        "bpf_ct_insert_entry",
        "bpf_ct_opts_layout_is_stable",
        "bpf_ct_release",
        "bpf_ct_set_nat_info",
        "bpf_ct_set_status",
        "bpf_ct_set_timeout",
        "bpf_dynptr_adjust",
        "bpf_dynptr_from_skb",
        "bpf_dynptr_from_xdp",
        "bpf_dynptr_size",
        "bpf_dynptr_slice",
        "bpf_skb_ct_alloc",
        "bpf_skb_ct_lookup",
        "bpf_skb_get_fou_encap",
        "bpf_skb_get_xfrm_info",
        "bpf_skb_set_fou_encap",
        "bpf_skb_set_xfrm_info",
        "bpf_xdp_ct_alloc",
        "bpf_xdp_ct_lookup",
        "bpf_xdp_get_xfrm_state",
        "bpf_xdp_metadata_rx_hash",
        "bpf_xdp_metadata_rx_timestamp",
        "bpf_xdp_metadata_rx_vlan_tag",
        "bpf_xdp_xfrm_state_release",
    ];

    /// Pull the `bpf_*(` call names out of a source file, ignoring `//`
    /// comments - several programs document alternatives they do not call,
    /// and a documented `bpf_redirect_map` is not a dependency.
    fn calls_in(src: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        for line in src.lines() {
            let code = line.split_once("//").map_or(line, |(c, _)| c);
            let bytes = code.as_bytes();
            let mut i = 0;
            while let Some(rel) = code[i..].find("bpf_") {
                let start = i + rel;
                // Only a call, and only at a token boundary.
                let prev_ok = start == 0 || {
                    let p = bytes[start - 1];
                    !p.is_ascii_alphanumeric() && p != b'_'
                };
                let mut end = start;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                if prev_ok && bytes.get(end) == Some(&b'(') {
                    out.insert(code[start..end].to_string());
                }
                i = end.max(start + 4);
            }
        }
        out
    }

    fn program_sources(object: &str) -> Vec<String> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../ebpf-programs")
            .join(object)
            .join("src");
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return out;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "rs")
                && let Ok(src) = std::fs::read_to_string(&path)
            {
                out.push(src);
            }
        }
        out
    }

    #[test]
    fn requirements_match_sources() {
        let universe: HashSet<&str> = HELPER_UNIVERSE.iter().map(|h| h.name).collect();
        let kfuncs: HashSet<&str> = KFUNCS.iter().copied().collect();

        for req in REQUIREMENTS {
            let sources = program_sources(req.object);
            assert!(
                !sources.is_empty(),
                "no sources found for {} - the requirement table names an object that does not \
                 exist, or the crate layout moved",
                req.object
            );

            let declared: HashSet<&str> = req.helpers().map(|h| h.name).collect();
            let mut called = HashSet::new();
            for src in &sources {
                called.extend(calls_in(src));
            }

            for name in &called {
                let name = name.as_str();
                if kfuncs.contains(name) {
                    continue;
                }
                assert!(
                    universe.contains(name),
                    "{} calls {name}, which is neither a known helper nor a listed kfunc - \
                     classify it in HELPER_UNIVERSE or KFUNCS",
                    req.object
                );
                assert!(
                    declared.contains(name),
                    "{} calls {name} but its requirement entry does not list it",
                    req.object
                );
            }
        }
    }

    #[test]
    fn call_extraction_ignores_comments_and_partial_words() {
        let src = "\
// documented alternative: bpf_redirect_map(&MAP, 0, 0)
let t = bpf_ktime_get_boot_ns();
let s = my_bpf_loop(x); // not a helper call
";
        let calls = calls_in(src);
        assert!(calls.contains("bpf_ktime_get_boot_ns"));
        assert!(!calls.contains("bpf_redirect_map"));
        assert!(!calls.contains("bpf_loop"));
    }

    #[test]
    fn summary_counts_supported_pairs() {
        let report = all_supported();
        let s = report.summary();
        assert!(s.contains(LOAD_MODE));
        assert!(s.contains("0 required helper(s) missing"));
    }

    #[test]
    fn the_reason_carries_the_errno_not_just_the_syscall_name() {
        // aya's syscall error displays only the call name and hides the errno
        // in its source. "`bpf_prog_load` failed" cannot be acted on;
        // "... : operation not permitted" is the whole diagnosis.
        #[derive(Debug)]
        struct Outer(std::io::Error);
        impl fmt::Display for Outer {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "`bpf_prog_load` failed")
            }
        }
        impl std::error::Error for Outer {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }

        let err = Outer(std::io::Error::from_raw_os_error(libc::EPERM));
        let rendered = with_sources(&err);
        assert!(rendered.starts_with("`bpf_prog_load` failed"));
        assert!(rendered.contains("Operation not permitted"));
    }
}
