//! Whether this host lets an XDP program read past the first buffer of a
//! frame, asked rather than inferred.
//!
//! A jumbo frame or a hardware GRO aggregate reaches XDP as several buffers.
//! An XDP program sees such frames only when it is loaded declaring that it
//! can (`BPF_F_XDP_HAS_FRAGS`), and then reads only the first buffer through
//! `data..data_end`. The `bpf_xdp_pull_data` kfunc moves the head of the
//! frame into that first buffer, which is what lets the firewall and the load
//! balancer parse headers that fell past it.
//!
//! Being declared is not being usable: the load goes through the agent's BPF
//! token, and a kernel may declare the kfunc and still refuse it to an XDP
//! program. So the probe loads the smallest program that calls it, declaring
//! multi-buffer frames, the way the agent's own XDP objects load. Its answer
//! decides how those objects load: with the declaration and the call where
//! the probe loaded, without either where it did not, which is how they
//! loaded before the kfunc was used.
//!
//! The load is the only syscall, and it runs once at startup. A refusal for
//! lack of privilege is reported as "not probed" with its reason, never as
//! "unsupported", because that would describe the deployment as a kernel.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::kfunc_feature_probe::{insn, judge_refusal};
use super::lsm_probe::VMLINUX_BTF_PATH;

/// The kfunc this probe answers for.
pub const XDP_PULL_KFUNC: &str = "bpf_xdp_pull_data";

/// `XDP_PASS`, the probe program's whole verdict.
const XDP_PASS: i32 = 2;

/// What this host answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XdpPullStatus {
    /// Whether the kernel's BTF declares the kfunc. `None` when the BTF could
    /// not be read, which proves nothing either way.
    pub declared: Option<bool>,
    /// `Some(true)` when the probe program loaded, `Some(false)` when the
    /// kernel refused it for a reason a privilege would not change, `None`
    /// when the probe could not run.
    pub loads: Option<bool>,
    /// Why it is not usable, or why nothing was measured.
    pub reason: Option<String>,
}

impl XdpPullStatus {
    /// Whether the XDP objects load declaring multi-buffer frames and keep
    /// their pull.
    #[must_use]
    pub fn usable(&self) -> bool {
        self.loads == Some(true)
    }
}

/// Decide the answer from the kernel's `FUNC` table (or why it could not be
/// read) and the load of a program calling the kfunc by its BTF id. Taking
/// both as arguments is what lets every outcome be tested without a kernel.
fn evaluate(
    funcs: &Result<HashMap<String, u32>, String>,
    load: &mut dyn FnMut(u32) -> Result<(), (i32, String)>,
) -> XdpPullStatus {
    let table = match funcs {
        Err(why) => {
            return XdpPullStatus {
                declared: None,
                loads: None,
                reason: Some(format!("the kernel BTF could not be read: {why}")),
            };
        }
        Ok(table) => table,
    };
    let Some(&id) = table.get(XDP_PULL_KFUNC) else {
        return XdpPullStatus {
            declared: Some(false),
            loads: Some(false),
            reason: Some(format!("this kernel does not declare {XDP_PULL_KFUNC}")),
        };
    };
    match load(id) {
        Ok(()) => XdpPullStatus {
            declared: Some(true),
            loads: Some(true),
            reason: None,
        },
        Err((errno, log)) => {
            let (loads, reason) = judge_refusal(
                errno,
                &log,
                "an XDP program declaring multi-buffer frames and calling bpf_xdp_pull_data",
            );
            XdpPullStatus {
                declared: Some(true),
                loads,
                reason: Some(reason),
            }
        }
    }
}

/// The probe program: `r2 = 0; call bpf_xdp_pull_data; r0 = XDP_PASS; exit`.
/// `r1` already holds the context the kfunc takes, and a length of zero is
/// one the first buffer always holds, so the call asks the verifier the
/// question and moves nothing.
fn probe_insns(btf_id: u32) -> Vec<u64> {
    vec![
        insn::mov_imm(2, 0),
        insn::call_kfunc(btf_id),
        insn::mov_imm(0, XDP_PASS),
        insn::exit(),
    ]
}

/// Probe this host: read its BTF and attempt the load.
#[must_use]
pub fn run() -> XdpPullStatus {
    let funcs = std::fs::read(VMLINUX_BTF_PATH)
        .map_err(|e| format!("{VMLINUX_BTF_PATH}: {e}"))
        .and_then(|data| super::kfunc::vmlinux_func_ids(data).map_err(|e| e.to_string()));
    evaluate(&funcs, &mut |id| {
        super::kfunc_loader::load_probe_program(&super::kfunc_loader::ProbeProgram {
            prog_type: super::kfunc_loader::PROBE_PROG_TYPE_XDP,
            expected_attach_type: 0,
            prog_flags: super::kfunc_loader::PROBE_F_XDP_HAS_FRAGS,
            attach_btf_id: 0,
            insns: probe_insns(id),
        })
    })
}

static CACHE: OnceLock<XdpPullStatus> = OnceLock::new();

/// Run the probe once per process, at startup, before the first XDP object
/// loads, and keep the answer.
pub fn init_cached() -> &'static XdpPullStatus {
    CACHE.get_or_init(run)
}

/// The cached answer, or `None` when startup has not probed yet, so that
/// reading it from the operational endpoint never issues a load of its own.
#[must_use]
pub fn cached() -> Option<&'static XdpPullStatus> {
    CACHE.get()
}

/// Whether the XDP objects load declaring multi-buffer frames. False until
/// the probe has run, so a process that never probed loads them as they
/// loaded before the kfunc was used.
#[must_use]
pub fn usable() -> bool {
    cached().is_some_and(XdpPullStatus::usable)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(names: &[&str]) -> HashMap<String, u32> {
        names
            .iter()
            .zip(7u32..)
            .map(|(n, id)| ((*n).to_string(), id))
            .collect()
    }

    #[test]
    fn a_declared_kfunc_that_loads_is_usable_and_called_by_its_id() {
        let mut seen = None;
        let status = evaluate(
            &Ok(table(&["bpf_xdp_adjust_meta", XDP_PULL_KFUNC])),
            &mut |id| {
                seen = Some(id);
                Ok(())
            },
        );
        assert_eq!(seen, Some(8));
        assert!(status.usable());
        assert_eq!(status.declared, Some(true));
        assert_eq!(status.reason, None);
    }

    #[test]
    fn an_undeclared_kfunc_is_refused_without_a_load() {
        let mut called = false;
        let status = evaluate(&Ok(table(&["bpf_xdp_adjust_meta"])), &mut |_| {
            called = true;
            Ok(())
        });
        assert!(!called);
        assert!(!status.usable());
        assert_eq!(status.declared, Some(false));
        assert_eq!(status.loads, Some(false));
        assert!(
            status
                .reason
                .expect("reason")
                .contains("does not declare bpf_xdp_pull_data")
        );
    }

    #[test]
    fn a_refused_privilege_is_not_probed_never_unsupported() {
        let status = evaluate(&Ok(table(&[XDP_PULL_KFUNC])), &mut |_| {
            Err((libc::EPERM, String::new()))
        });
        assert!(!status.usable());
        assert_eq!(status.declared, Some(true));
        assert_eq!(status.loads, None);
        assert!(status.reason.expect("reason").contains("CAP_BPF"));
    }

    #[test]
    fn a_kernel_refusal_quotes_the_verifier() {
        let status = evaluate(&Ok(table(&[XDP_PULL_KFUNC])), &mut |_| {
            Err((
                libc::EINVAL,
                "\ncalling kernel function bpf_xdp_pull_data is not allowed\n".into(),
            ))
        });
        assert_eq!(status.loads, Some(false));
        assert!(
            status
                .reason
                .expect("reason")
                .ends_with(": calling kernel function bpf_xdp_pull_data is not allowed")
        );
    }

    #[test]
    fn an_unreadable_btf_proves_nothing_either_way() {
        let status = evaluate(&Err("no such file".into()), &mut |_| Ok(()));
        assert_eq!(status.declared, None);
        assert_eq!(status.loads, None);
        assert!(!status.usable());
    }

    #[test]
    fn the_probe_program_calls_the_kfunc_with_a_zero_length_and_passes() {
        let insns = probe_insns(4242);
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0], insn::mov_imm(2, 0));
        assert_eq!(insns[1], insn::call_kfunc(4242));
        assert_eq!(insns[2], insn::mov_imm(0, 2));
        assert_eq!(insns[3], insn::exit());
    }
}
