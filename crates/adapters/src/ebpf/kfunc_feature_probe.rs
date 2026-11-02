//! Kernel facts a future program would rest on, asked rather than inferred.
//!
//! Each entry here names the one thing it would be used for, and nothing in
//! the agent uses any of them yet: the point is that the day one is wired,
//! whether this host offers it is already a reading on the operational
//! endpoint rather than a kernel version somebody has to interpret.
//!
//! - **kprobe sessions**: one program run on a function's entry and on its
//!   return, with `bpf_session_is_return` and `bpf_session_cookie`, instead of
//!   a kprobe, a kretprobe and a map correlating the two. The probe loads a
//!   kprobe program with the session attach type that calls both kfuncs,
//!   which only a kernel offering sessions accepts.
//! - **`bpf_copy_from_user_str`**: a string copied out of user memory, which
//!   is what reading a process's real argument vector at exec needs. The
//!   probe loads a sleepable LSM program that calls it.
//! - **`bpf_sk_assign_tcp_reqsk`**: a validated SYN cookie handed to the stack
//!   as a request socket, rather than the stack revalidating a cookie it did
//!   not issue. A call needs a listening socket looked up first, which a probe
//!   cannot honestly fake, so this one is read from the kernel's BTF alone and
//!   reported as declared, never as confirmed.
//!
//! A load refused for lack of privilege is "not probed" with its reason, never
//! "unsupported".

use std::collections::HashMap;
use std::sync::OnceLock;

use super::file_kfunc_probe::SLEEPABLE_PROBE_HOOK;
use super::kfunc_loader::{
    PROBE_F_SLEEPABLE, PROBE_LSM_MAC, PROBE_PROG_TYPE_KPROBE, PROBE_PROG_TYPE_LSM,
    PROBE_TRACE_KPROBE_SESSION, ProbeProgram,
};
use super::lsm_probe::VMLINUX_BTF_PATH;

/// Encoders for the few instructions the probes are written in.
///
/// Each returns one instruction as the `u64` the kernel reads, in the
/// little-endian layout of the bpfel target: opcode, then the destination
/// register in the low nibble and the source in the high one, then a signed
/// 16-bit offset and a signed 32-bit immediate.
pub(crate) mod insn {
    /// One instruction from its five fields.
    pub(crate) fn encode(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
        let off = off.to_le_bytes();
        let imm = imm.to_le_bytes();
        u64::from_le_bytes([
            code,
            (src << 4) | (dst & 0x0f),
            off[0],
            off[1],
            imm[0],
            imm[1],
            imm[2],
            imm[3],
        ])
    }

    /// `dst = imm` (64-bit).
    pub(crate) fn mov_imm(dst: u8, imm: i32) -> u64 {
        encode(0xb7, dst, 0, 0, imm)
    }

    /// `dst = src` (64-bit).
    pub(crate) fn mov_reg(dst: u8, src: u8) -> u64 {
        encode(0xbf, dst, src, 0, 0)
    }

    /// `dst += imm` (64-bit).
    pub(crate) fn add_imm(dst: u8, imm: i32) -> u64 {
        encode(0x07, dst, 0, 0, imm)
    }

    /// `*(u64 *)(dst + off) = imm`.
    pub(crate) fn store_dw_imm(dst: u8, off: i16, imm: i32) -> u64 {
        encode(0x7a, dst, 0, off, imm)
    }

    /// A call to the vmlinux kfunc whose BTF id is `btf_id`.
    pub(crate) fn call_kfunc(btf_id: u32) -> u64 {
        encode(0x85, 0, 2, 0, i32::from_ne_bytes(btf_id.to_ne_bytes()))
    }

    /// `exit`.
    pub(crate) fn exit() -> u64 {
        encode(0x95, 0, 0, 0, 0)
    }
}

/// One kfunc an entry depends on, and whether the kernel declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredKfunc {
    pub name: &'static str,
    /// `None` when the kernel's BTF could not be read.
    pub declared: Option<bool>,
}

/// What this host answered for one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KfuncFeature {
    /// Stable identifier, the key a reader matches on.
    pub name: &'static str,
    /// What the agent would use it for, in one sentence.
    pub consumer: &'static str,
    pub kfuncs: Vec<DeclaredKfunc>,
    /// Whether the probe loads a program for this entry, or only reads BTF.
    pub load_tested: bool,
    /// `Some(true)` confirmed by a load, `Some(false)` not declared or
    /// refused by the kernel, `None` when nothing could confirm it either way.
    pub usable: Option<bool>,
    /// Why it is not confirmed usable, in one sentence.
    pub reason: Option<String>,
}

/// Builds a probe program from the kernel's `FUNC` table, with the words
/// naming it in a refusal, or `None` when a function it needs is absent.
type BuildProgram = fn(&HashMap<String, u32>) -> Option<(&'static str, ProbeProgram)>;

/// The loader a probe goes through, injected so every outcome is testable.
type Loader<'a> = dyn FnMut(&ProbeProgram) -> Result<(), (i32, String)> + 'a;

/// One entry of the probe, before it is asked.
struct Entry {
    name: &'static str,
    consumer: &'static str,
    kfuncs: &'static [&'static str],
    /// Builds the program that proves it, from the kernel's `FUNC` table.
    /// `None` for an entry read from BTF alone.
    program: Option<BuildProgram>,
    /// Said of a declared entry that no program confirms.
    unconfirmed: &'static str,
}

const ENTRIES: [Entry; 3] = [
    Entry {
        name: "kprobe_session",
        consumer: "one program on a function's entry and return for the kernel TLS record path, \
                   instead of a kprobe, a kretprobe and a map correlating them",
        kfuncs: &["bpf_session_is_return", "bpf_session_cookie"],
        program: Some(kprobe_session_program),
        unconfirmed: "",
    },
    Entry {
        name: "copy_from_user_str",
        consumer: "the real argument vector of a process, read at exec",
        kfuncs: &["bpf_copy_from_user_str"],
        program: Some(copy_from_user_str_program),
        unconfirmed: "",
    },
    Entry {
        name: "tcp_reqsk_assign",
        consumer: "a validated SYN cookie handed to the stack as a request socket, so the \
                   stack does not revalidate a cookie it did not issue",
        kfuncs: &["bpf_sk_assign_tcp_reqsk"],
        program: None,
        unconfirmed: "declared, not confirmed: a call needs a listening socket looked up \
                      first, so the probe reads the kernel's BTF and loads nothing",
    },
];

/// Each fact's name and the one thing it would be used for, in the order
/// they are reported.
#[must_use]
pub fn entry_consumers() -> Vec<(&'static str, &'static str)> {
    ENTRIES.iter().map(|e| (e.name, e.consumer)).collect()
}

/// A kprobe program loaded with the session attach type, calling both session
/// kfuncs. The verifier offers them to session programs alone.
fn kprobe_session_program(funcs: &HashMap<String, u32>) -> Option<(&'static str, ProbeProgram)> {
    let is_return = *funcs.get("bpf_session_is_return")?;
    let cookie = *funcs.get("bpf_session_cookie")?;
    Some((
        "a kprobe session program",
        ProbeProgram {
            prog_type: PROBE_PROG_TYPE_KPROBE,
            expected_attach_type: PROBE_TRACE_KPROBE_SESSION,
            prog_flags: 0,
            attach_btf_id: 0,
            insns: vec![
                insn::call_kfunc(is_return),
                insn::call_kfunc(cookie),
                insn::mov_imm(0, 0),
                insn::exit(),
            ],
        },
    ))
}

/// A sleepable LSM program copying into a zeroed sixteen-byte stack buffer
/// from a null user pointer. The copy would fail at run time; the verifier
/// accepts the call only where the kfunc is offered to sleepable programs.
fn copy_from_user_str_program(
    funcs: &HashMap<String, u32>,
) -> Option<(&'static str, ProbeProgram)> {
    let copy = *funcs.get("bpf_copy_from_user_str")?;
    let hook = *funcs.get(SLEEPABLE_PROBE_HOOK)?;
    Some((
        "a sleepable LSM program calling it",
        ProbeProgram {
            prog_type: PROBE_PROG_TYPE_LSM,
            expected_attach_type: PROBE_LSM_MAC,
            prog_flags: PROBE_F_SLEEPABLE,
            attach_btf_id: hook,
            insns: vec![
                insn::store_dw_imm(10, -8, 0),
                insn::store_dw_imm(10, -16, 0),
                insn::mov_reg(1, 10),
                insn::add_imm(1, -16),
                insn::mov_imm(2, 16),
                insn::mov_imm(3, 0),
                insn::mov_imm(4, 0),
                insn::call_kfunc(copy),
                insn::mov_imm(0, 0),
                insn::exit(),
            ],
        },
    ))
}

/// Read a refused probe load: `None` and the missing privilege when the
/// kernel refused the caller, `Some(false)` and the verifier's first line when
/// it refused the program.
pub(crate) fn judge_refusal(errno: i32, log: &str, what: &str) -> (Option<bool>, String) {
    let err = std::io::Error::from_raw_os_error(errno);
    if errno == libc::EPERM || errno == libc::EACCES {
        return (
            None,
            format!(
                "the probe could not load {what} ({err}): it needs CAP_BPF and CAP_PERFMON, or \
                 a BPF token allowing it"
            ),
        );
    }
    let first = log.lines().map(str::trim).find(|l| !l.is_empty());
    let reason = match first {
        Some(line) => format!("the kernel refused {what} ({err}): {line}"),
        None => format!("the kernel refused {what} ({err})"),
    };
    (Some(false), reason)
}

/// Decide every entry from the kernel's `FUNC` table and the loads.
fn evaluate(
    funcs: &Result<HashMap<String, u32>, String>,
    load: &mut Loader<'_>,
) -> Vec<KfuncFeature> {
    ENTRIES
        .iter()
        .map(|entry| {
            let table = funcs.as_ref().ok();
            let kfuncs: Vec<DeclaredKfunc> = entry
                .kfuncs
                .iter()
                .map(|&name| DeclaredKfunc {
                    name,
                    declared: table.map(|t| t.contains_key(name)),
                })
                .collect();
            let (usable, reason) = match funcs {
                Err(why) => (
                    None,
                    Some(format!("the kernel BTF could not be read: {why}")),
                ),
                Ok(table) => {
                    let missing: Vec<&str> = kfuncs
                        .iter()
                        .filter(|k| k.declared == Some(false))
                        .map(|k| k.name)
                        .collect();
                    if missing.is_empty() {
                        judge(entry, table, load)
                    } else {
                        (
                            Some(false),
                            Some(format!(
                                "this kernel does not declare {}",
                                missing.join(" or ")
                            )),
                        )
                    }
                }
            };
            KfuncFeature {
                name: entry.name,
                consumer: entry.consumer,
                kfuncs,
                load_tested: entry.program.is_some(),
                usable,
                reason,
            }
        })
        .collect()
}

fn judge(
    entry: &Entry,
    table: &HashMap<String, u32>,
    load: &mut Loader<'_>,
) -> (Option<bool>, Option<String>) {
    let Some(build) = entry.program else {
        return (None, Some(entry.unconfirmed.to_string()));
    };
    let Some((what, program)) = build(table) else {
        return (
            Some(false),
            Some(
                "this kernel names no BPF LSM hook, so it was built without CONFIG_BPF_LSM"
                    .to_string(),
            ),
        );
    };
    match load(&program) {
        Ok(()) => (Some(true), None),
        Err((errno, log)) => {
            let (usable, reason) = judge_refusal(errno, &log, what);
            (usable, Some(reason))
        }
    }
}

/// Probe this host.
#[must_use]
pub fn run() -> Vec<KfuncFeature> {
    let funcs = std::fs::read(VMLINUX_BTF_PATH)
        .map_err(|e| format!("{VMLINUX_BTF_PATH}: {e}"))
        .and_then(|data| super::kfunc::vmlinux_func_ids(data).map_err(|e| e.to_string()));
    evaluate(&funcs, &mut super::kfunc_loader::load_probe_program)
}

static CACHE: OnceLock<Vec<KfuncFeature>> = OnceLock::new();

/// Run the probe once per process, at startup, and keep the answer.
pub fn init_cached() -> &'static [KfuncFeature] {
    CACHE.get_or_init(run)
}

/// The cached answer, or `None` when startup has not probed yet, so that
/// reading it from the operational endpoint never issues a load of its own.
#[must_use]
pub fn cached() -> Option<&'static [KfuncFeature]> {
    CACHE.get().map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(names: &[&str]) -> HashMap<String, u32> {
        names
            .iter()
            .zip(100u32..)
            .map(|(n, id)| ((*n).to_string(), id))
            .collect()
    }

    fn everything() -> HashMap<String, u32> {
        let mut names: Vec<&str> = ENTRIES
            .iter()
            .flat_map(|e| e.kfuncs.iter().copied())
            .collect();
        names.push(SLEEPABLE_PROBE_HOOK);
        table(&names)
    }

    fn by_name<'a>(features: &'a [KfuncFeature], name: &str) -> &'a KfuncFeature {
        features
            .iter()
            .find(|f| f.name == name)
            .expect("entry present")
    }

    #[test]
    fn the_encoder_writes_the_layout_the_kernel_reads() {
        assert_eq!(insn::exit().to_le_bytes(), [0x95, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            insn::mov_imm(2, 16).to_le_bytes(),
            [0xb7, 0x02, 0, 0, 16, 0, 0, 0]
        );
        assert_eq!(insn::mov_reg(1, 10).to_le_bytes()[1], 0xa1);
        assert_eq!(
            insn::store_dw_imm(10, -16, 0).to_le_bytes()[..4],
            [0x7a, 0x0a, 0xf0, 0xff]
        );
        assert_eq!(
            insn::call_kfunc(0x0102_0304).to_le_bytes(),
            [0x85, 0x20, 0, 0, 0x04, 0x03, 0x02, 0x01]
        );
        assert_eq!(
            insn::add_imm(1, -16).to_le_bytes()[4..],
            [0xf0, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    fn every_entry_names_its_consumer_and_its_kfuncs() {
        for e in &ENTRIES {
            assert!(!e.consumer.is_empty(), "{}", e.name);
            assert!(!e.kfuncs.is_empty(), "{}", e.name);
            assert_eq!(e.program.is_none(), !e.unconfirmed.is_empty(), "{}", e.name);
        }
    }

    #[test]
    fn a_kernel_offering_everything_confirms_what_it_loads_and_no_more() {
        let t = everything();
        let mut loaded = Vec::new();
        let features = evaluate(&Ok(t.clone()), &mut |p| {
            loaded.push((p.prog_type, p.expected_attach_type, p.prog_flags));
            Ok(())
        });
        assert_eq!(
            loaded,
            vec![
                (PROBE_PROG_TYPE_KPROBE, PROBE_TRACE_KPROBE_SESSION, 0),
                (PROBE_PROG_TYPE_LSM, PROBE_LSM_MAC, PROBE_F_SLEEPABLE),
            ]
        );
        assert_eq!(by_name(&features, "kprobe_session").usable, Some(true));
        assert_eq!(by_name(&features, "copy_from_user_str").usable, Some(true));
        let reqsk = by_name(&features, "tcp_reqsk_assign");
        assert!(!reqsk.load_tested);
        assert_eq!(reqsk.usable, None);
        assert_eq!(reqsk.kfuncs[0].declared, Some(true));
        assert!(
            reqsk
                .reason
                .as_deref()
                .expect("reason")
                .starts_with("declared, not confirmed")
        );
    }

    #[test]
    fn the_session_program_calls_both_kfuncs_by_their_btf_ids() {
        let t = everything();
        let (_, program) = kprobe_session_program(&t).expect("program");
        assert_eq!(
            program.insns[0],
            insn::call_kfunc(t["bpf_session_is_return"])
        );
        assert_eq!(program.insns[1], insn::call_kfunc(t["bpf_session_cookie"]));
        assert_eq!(program.insns.last(), Some(&insn::exit()));
    }

    #[test]
    fn a_kfunc_the_kernel_does_not_declare_is_never_loaded_for() {
        let t = table(&["bpf_session_cookie", SLEEPABLE_PROBE_HOOK]);
        let mut loads = 0;
        let features = evaluate(&Ok(t), &mut |_| {
            loads += 1;
            Ok(())
        });
        assert_eq!(loads, 0);
        let session = by_name(&features, "kprobe_session");
        assert_eq!(session.usable, Some(false));
        assert_eq!(
            session.reason.as_deref(),
            Some("this kernel does not declare bpf_session_is_return")
        );
        assert_eq!(
            by_name(&features, "tcp_reqsk_assign").usable,
            Some(false),
            "an undeclared kfunc is a definite no, even read from BTF alone"
        );
    }

    #[test]
    fn a_refused_privilege_is_not_probed_and_a_refused_program_quotes_the_verifier() {
        let t = everything();
        let features = evaluate(&Ok(t), &mut |p| {
            if p.prog_type == PROBE_PROG_TYPE_KPROBE {
                Err((libc::EPERM, String::new()))
            } else {
                Err((
                    libc::EINVAL,
                    "calling kernel function is not allowed\n".into(),
                ))
            }
        });
        let session = by_name(&features, "kprobe_session");
        assert_eq!(session.usable, None);
        assert!(
            session
                .reason
                .as_deref()
                .expect("reason")
                .contains("CAP_PERFMON")
        );
        let copy = by_name(&features, "copy_from_user_str");
        assert_eq!(copy.usable, Some(false));
        assert!(
            copy.reason
                .as_deref()
                .expect("reason")
                .ends_with(": calling kernel function is not allowed")
        );
    }

    #[test]
    fn a_kernel_without_the_lsm_hooks_cannot_host_the_sleepable_copy() {
        let t = table(&["bpf_copy_from_user_str"]);
        let features = evaluate(&Ok(t), &mut |_| Ok(()));
        let copy = by_name(&features, "copy_from_user_str");
        assert_eq!(copy.usable, Some(false));
        assert!(
            copy.reason
                .as_deref()
                .expect("reason")
                .contains("CONFIG_BPF_LSM")
        );
    }

    #[test]
    fn an_unreadable_btf_proves_nothing_either_way() {
        let features = evaluate(&Err("gone".into()), &mut |_| Ok(()));
        assert_eq!(features.len(), ENTRIES.len());
        for f in &features {
            assert_eq!(f.usable, None);
            assert!(f.kfuncs.iter().all(|k| k.declared.is_none()));
        }
    }
}
