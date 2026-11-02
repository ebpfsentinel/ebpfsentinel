//! Signalling a thread group at once, from a program the agent runs itself.
//!
//! The syscall-entry tracepoint signals the task it runs in, so a target is
//! reached only when it next enters the kernel, and a process spinning in
//! pure computation never does. A kernel that offers `bpf_send_signal_task`
//! lets a program name its target instead: the agent runs a program of type
//! `BPF_PROG_TYPE_SYSCALL` with the thread group id as its argument, the
//! program finds the task, checks the same fence the tracepoint does, and
//! signals it there and then.
//!
//! What it costs is what the tracepoint costs: the program loads through the
//! agent's token, a syscall program asks for nothing beyond the right to load
//! one, and the signal is sent as the kernel rather than as a user, so no
//! `CAP_KILL` is involved. Where the kernel does not declare the kfuncs, or
//! refuses the program, the tracepoint carries the signal as before and the
//! reason is published beside it.

use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use ebpf_common::signal::{
    SIGNAL_METRIC_HELPER_FAILED, SIGNAL_METRIC_PROTECTED, SIGNAL_METRIC_SENT,
};

use super::kfunc_feature_probe::insn::{add_imm, call_kfunc, encode, exit, mov_imm, mov_reg};
use super::kfunc_loader::{
    PROBE_F_SLEEPABLE, PROBE_PROG_TYPE_SYSCALL, ProbeProgram, load_raw_program,
};
use super::lsm_probe::VMLINUX_BTF_PATH;

/// The three kfuncs the program calls, in the order it calls them.
pub const SIGNAL_TASK_KFUNCS: [&str; 3] = [
    "bpf_task_from_pid",
    "bpf_send_signal_task",
    "bpf_task_release",
];

/// `PIDTYPE_TGID`: the signal goes to the whole thread group, as the
/// tracepoint's does.
const PIDTYPE_TGID: i32 = 1;

/// `BPF_FUNC_map_lookup_elem`.
const HELPER_MAP_LOOKUP: i32 = 1;

/// What the program returns, one value per way it can end.
const RET_SENT: u32 = 0;
const RET_PROTECTED: u32 = 1;
const RET_HELPER_FAILED: u32 = 2;
const RET_GONE: u32 = 3;

/// How one immediate signal ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectOutcome {
    /// The kernel accepted the signal for the thread group.
    Sent,
    /// The target is init, the idle task or in the protected set.
    Protected,
    /// The target was found and the kernel refused to signal it.
    HelperFailed,
    /// No task carries that id any longer.
    Gone,
}

impl DirectOutcome {
    /// The outcome behind a value the program returned, `None` for a value it
    /// never returns.
    #[must_use]
    pub const fn from_return(value: u32) -> Option<Self> {
        match value {
            RET_SENT => Some(Self::Sent),
            RET_PROTECTED => Some(Self::Protected),
            RET_HELPER_FAILED => Some(Self::HelperFailed),
            RET_GONE => Some(Self::Gone),
            _ => None,
        }
    }
}

/// Where the forward jumps of the program land.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    Protected,
    Gone,
    Count,
    Done,
}

/// A tiny assembler: instructions in order, forward jumps patched once every
/// label has a place.
#[derive(Default)]
struct Asm {
    insns: Vec<u64>,
    at: [Option<usize>; 4],
    jumps: Vec<(usize, Label)>,
}

impl Asm {
    fn push(&mut self, insn: u64) {
        self.insns.push(insn);
    }

    fn mark(&mut self, label: Label) {
        self.at[label as usize] = Some(self.insns.len());
    }

    fn jump(&mut self, code: u8, dst: u8, imm: i32, to: Label) {
        self.jumps.push((self.insns.len(), to));
        self.push(encode(code, dst, 0, 0, imm));
    }

    /// `dst = map` through the descriptor the loader resolves.
    fn load_map(&mut self, dst: u8, map: BorrowedFd<'_>) {
        self.push(encode(0x18, dst, 1, 0, map.as_raw_fd()));
        self.push(0);
    }

    fn finish(mut self) -> Option<Vec<u64>> {
        for (from, to) in std::mem::take(&mut self.jumps) {
            let target = self.at[to as usize]?;
            let off = i16::try_from(target.checked_sub(from + 1)?).ok()?;
            let patched =
                (self.insns[from] & !(0xffff << 16)) | (u64::from(off.cast_unsigned()) << 16);
            self.insns[from] = patched;
        }
        Some(self.insns)
    }
}

/// The program, from the kernel's `FUNC` table and the two maps it reads.
///
/// It takes `{ tgid: u32, signal: u32 }` and returns one of the `RET_*`
/// values. The fence is the tracepoint's: init and the idle task are never
/// signalled, nor is anything in the protected set. Each signal sent, refused
/// by the fence or refused by the kernel counts in the same slots the
/// tracepoint counts in.
fn assemble(
    funcs: &HashMap<String, u32>,
    protected: BorrowedFd<'_>,
    metrics: BorrowedFd<'_>,
) -> Option<Vec<u64>> {
    let from_pid = *funcs.get(SIGNAL_TASK_KFUNCS[0])?;
    let send = *funcs.get(SIGNAL_TASK_KFUNCS[1])?;
    let release = *funcs.get(SIGNAL_TASK_KFUNCS[2])?;
    let slot = |s: u32| i32::try_from(s).unwrap_or(i32::MAX);

    let mut a = Asm::default();
    a.push(mov_reg(6, 1));
    a.push(encode(0x61, 7, 6, 0, 0)); // r7 = tgid
    a.push(encode(0x61, 8, 6, 4, 0)); // r8 = signal
    a.jump(0xb5, 7, 1, Label::Protected); // tgid <= 1
    a.push(encode(0x63, 10, 7, -4, 0)); // key on the stack
    a.load_map(1, protected);
    a.push(mov_reg(2, 10));
    a.push(add_imm(2, -4));
    a.push(encode(0x85, 0, 0, 0, HELPER_MAP_LOOKUP));
    a.jump(0x55, 0, 0, Label::Protected); // in the protected set
    a.push(mov_reg(1, 7));
    a.push(call_kfunc(from_pid));
    a.jump(0x15, 0, 0, Label::Gone);
    a.push(mov_reg(9, 0));
    a.push(mov_reg(1, 9));
    a.push(mov_reg(2, 8));
    a.push(mov_imm(3, PIDTYPE_TGID));
    a.push(mov_imm(4, 0));
    a.push(call_kfunc(send));
    a.push(mov_reg(6, 0));
    a.push(mov_reg(1, 9));
    a.push(call_kfunc(release));
    a.push(mov_imm(9, slot(RET_SENT)));
    a.push(mov_imm(7, slot(SIGNAL_METRIC_SENT)));
    a.jump(0x75, 6, 0, Label::Count); // the kernel accepted it
    a.push(mov_imm(9, slot(RET_HELPER_FAILED)));
    a.push(mov_imm(7, slot(SIGNAL_METRIC_HELPER_FAILED)));
    a.jump(0x05, 0, 0, Label::Count);
    a.mark(Label::Protected);
    a.push(mov_imm(9, slot(RET_PROTECTED)));
    a.push(mov_imm(7, slot(SIGNAL_METRIC_PROTECTED)));
    a.jump(0x05, 0, 0, Label::Count);
    a.mark(Label::Gone);
    a.push(mov_imm(0, slot(RET_GONE)));
    a.push(exit());
    a.mark(Label::Count);
    a.push(encode(0x63, 10, 7, -8, 0));
    a.load_map(1, metrics);
    a.push(mov_reg(2, 10));
    a.push(add_imm(2, -8));
    a.push(encode(0x85, 0, 0, 0, HELPER_MAP_LOOKUP));
    a.jump(0x15, 0, 0, Label::Done);
    a.push(encode(0x79, 1, 0, 0, 0));
    a.push(add_imm(1, 1));
    a.push(encode(0x7b, 0, 1, 0, 0));
    a.mark(Label::Done);
    a.push(mov_reg(0, 9));
    a.push(exit());
    a.finish()
}

/// What the kernel answered when the program was offered to it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectSignalProbe {
    /// Whether the kernel's BTF declares all three kfuncs, `None` when it
    /// could not be read.
    pub declared: Option<bool>,
    /// The program, when it loaded.
    pub loaded: bool,
    /// Why it did not, in one sentence.
    pub reason: Option<String>,
}

/// The loaded program, ready to signal.
pub struct DirectSignal {
    prog: OwnedFd,
}

impl DirectSignal {
    /// Read the kernel's BTF, assemble the program against the two maps and
    /// load it through the agent's token.
    ///
    /// # Errors
    ///
    /// Returns what the kernel answered, with the reason it is not usable.
    pub fn load(
        protected: BorrowedFd<'_>,
        metrics: BorrowedFd<'_>,
    ) -> Result<Self, DirectSignalProbe> {
        let funcs = match std::fs::read(VMLINUX_BTF_PATH)
            .map_err(|e| format!("{VMLINUX_BTF_PATH}: {e}"))
            .and_then(|data| super::kfunc::vmlinux_func_ids(data).map_err(|e| e.to_string()))
        {
            Ok(funcs) => funcs,
            Err(e) => {
                return Err(DirectSignalProbe {
                    declared: None,
                    loaded: false,
                    reason: Some(format!("the kernel BTF could not be read: {e}")),
                });
            }
        };
        Self::load_with(&funcs, protected, metrics, |probe| {
            load_raw_program(probe, b"signal_task")
        })
    }

    fn load_with(
        funcs: &HashMap<String, u32>,
        protected: BorrowedFd<'_>,
        metrics: BorrowedFd<'_>,
        load: impl FnOnce(&ProbeProgram) -> Result<OwnedFd, (i32, String)>,
    ) -> Result<Self, DirectSignalProbe> {
        if let Some(missing) = SIGNAL_TASK_KFUNCS
            .iter()
            .find(|name| !funcs.contains_key(**name))
        {
            return Err(DirectSignalProbe {
                declared: Some(false),
                loaded: false,
                reason: Some(format!("the kernel does not declare {missing}")),
            });
        }
        let refused = |reason: String| DirectSignalProbe {
            declared: Some(true),
            loaded: false,
            reason: Some(reason),
        };
        let insns = assemble(funcs, protected, metrics)
            .ok_or_else(|| refused("the signal program could not be assembled".to_string()))?;
        let probe = ProbeProgram {
            prog_type: PROBE_PROG_TYPE_SYSCALL,
            expected_attach_type: 0,
            prog_flags: PROBE_F_SLEEPABLE,
            attach_btf_id: 0,
            insns,
        };
        load(&probe)
            .map(|prog| Self { prog })
            .map_err(|(errno, log)| {
                let last = log.lines().rev().find(|l| !l.trim().is_empty());
                refused(match last {
                    Some(line) => format!(
                        "the kernel refused the signal program (errno {errno}): {}",
                        line.trim()
                    ),
                    None => format!("the kernel refused the signal program (errno {errno})"),
                })
            })
    }

    /// Signal `tgid` with `signal` now.
    ///
    /// # Errors
    ///
    /// Returns why the program could not be run, or a value it never returns.
    pub fn signal(&self, tgid: u32, signal: u32) -> Result<DirectOutcome, String> {
        let mut ctx = [0u8; 8];
        ctx[..4].copy_from_slice(&tgid.to_ne_bytes());
        ctx[4..].copy_from_slice(&signal.to_ne_bytes());
        let value = super::prog_test_run::run_with_context(self.prog.as_fd(), &ctx)
            .map_err(|e| e.to_string())?;
        DirectOutcome::from_return(value)
            .ok_or_else(|| format!("the signal program returned {value}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn funcs() -> HashMap<String, u32> {
        SIGNAL_TASK_KFUNCS
            .iter()
            .zip([101u32, 102, 103])
            .map(|(n, id)| ((*n).to_string(), id))
            .collect()
    }

    fn fds() -> (OwnedFd, OwnedFd) {
        let a = std::fs::File::open("/dev/null").expect("open");
        let b = std::fs::File::open("/dev/null").expect("open");
        (a.into(), b.into())
    }

    fn field(insn: u64, shift: u32, mask: u64) -> u64 {
        (insn >> shift) & mask
    }

    #[test]
    fn every_jump_lands_inside_the_program_and_forward() {
        let (p, m) = fds();
        let insns = assemble(&funcs(), p.as_fd(), m.as_fd()).expect("assembled");
        for (pc, insn) in insns.iter().enumerate() {
            let code = field(*insn, 0, 0xff);
            if code & 0x07 == 0x05 && code != 0x85 && code != 0x95 {
                let off = i16::from_le_bytes([
                    u8::try_from(field(*insn, 16, 0xff)).expect("byte"),
                    u8::try_from(field(*insn, 24, 0xff)).expect("byte"),
                ]);
                assert!(off >= 0, "backward jump at {pc}");
                let target = pc + 1 + usize::try_from(off).expect("forward");
                assert!(target < insns.len(), "jump at {pc} leaves the program");
            }
        }
        assert_eq!(field(*insns.last().expect("last"), 0, 0xff), 0x95);
    }

    #[test]
    fn the_program_calls_the_three_kfuncs_in_order_and_reads_both_maps() {
        let (p, m) = fds();
        let insns = assemble(&funcs(), p.as_fd(), m.as_fd()).expect("assembled");
        let kfuncs: Vec<u64> = insns
            .iter()
            .filter(|i| field(**i, 0, 0xff) == 0x85 && field(**i, 12, 0xf) == 2)
            .map(|i| field(*i, 32, 0xffff_ffff))
            .collect();
        assert_eq!(kfuncs, [101, 102, 103]);
        let maps: Vec<u64> = insns
            .iter()
            .filter(|i| field(**i, 0, 0xff) == 0x18)
            .map(|i| field(*i, 32, 0xffff_ffff))
            .collect();
        let raw = |fd: &OwnedFd| u64::try_from(fd.as_raw_fd()).expect("fd");
        assert_eq!(maps, [raw(&p), raw(&m)]);
    }

    #[test]
    fn a_kernel_missing_a_kfunc_is_said_by_name_and_nothing_is_loaded() {
        let (p, m) = fds();
        let mut f = funcs();
        f.remove("bpf_send_signal_task");
        let probe = DirectSignal::load_with(&f, p.as_fd(), m.as_fd(), |_| {
            Err((0, "must not be called".to_string()))
        })
        .err()
        .expect("refused before the load");
        assert_eq!(probe.declared, Some(false));
        assert!(!probe.loaded);
        assert_eq!(
            probe.reason.as_deref(),
            Some("the kernel does not declare bpf_send_signal_task")
        );
    }

    #[test]
    fn a_refusal_carries_the_errno_and_the_verifier_last_line() {
        let (p, m) = fds();
        let result = DirectSignal::load_with(&funcs(), p.as_fd(), m.as_fd(), |probe| {
            assert_eq!(probe.prog_type, PROBE_PROG_TYPE_SYSCALL);
            assert_eq!(probe.prog_flags, PROBE_F_SLEEPABLE);
            Err((
                13,
                "0: (bf) r6 = r1\nprogram of this type cannot use helper\n".to_string(),
            ))
        });
        let probe = result.err().expect("refused");
        assert_eq!(probe.declared, Some(true));
        assert_eq!(
            probe.reason.as_deref(),
            Some(
                "the kernel refused the signal program (errno 13): program of this type cannot \
                 use helper"
            )
        );
    }

    #[test]
    fn every_value_the_program_returns_is_an_outcome() {
        assert_eq!(DirectOutcome::from_return(0), Some(DirectOutcome::Sent));
        assert_eq!(
            DirectOutcome::from_return(1),
            Some(DirectOutcome::Protected)
        );
        assert_eq!(
            DirectOutcome::from_return(2),
            Some(DirectOutcome::HelperFailed)
        );
        assert_eq!(DirectOutcome::from_return(3), Some(DirectOutcome::Gone));
        assert_eq!(DirectOutcome::from_return(4), None);
    }
}
