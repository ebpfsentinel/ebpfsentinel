//! Run a crafted packet through the loaded programs, in hook order.
//!
//! The programs are asked one at a time with `BPF_PROG_TEST_RUN`, each handed
//! the packet as the previous one left it, because a translation upstream
//! changes what a later stage matches. The XDP entry program is run once and
//! follows its own tail calls, appending a record per stage to the trace
//! metadata; each classifier leaves its record in `skb->cb`. The walk stops
//! at the first program whose return keeps the packet from the next hook.

use std::os::fd::{AsFd, OwnedFd};

use domain::trace::{ProgramRun, TraceDirection, TraceError, TraceHook};
use ebpf_common::trace::{
    TC_TRACE_MARK, TC_TRACE_PRIORITY, TraceRecord, tc_record, xdp_records, xdp_trace_metadata,
};
use ports::secondary::datapath_trace_port::{DatapathRuns, DatapathTracePort};

use super::prog_test_run::{
    SkbContext, TC_ACT_OK, TestRunError, XDP_PASS, run_tc_with_context, run_xdp_with_metadata,
};

/// `TCX_NEXT`, `-1` read unsigned: hand the packet to the next program.
const TCX_NEXT: u32 = u32::MAX;
/// `TC_ACT_PIPE`, which a classifier returns to keep going as well.
const TC_ACT_PIPE: u32 = 3;

/// One loaded program a trace can run.
#[derive(Debug)]
pub struct TracedProgram {
    /// The name the loader gives the program.
    pub name: String,
    /// Where it runs.
    pub hook: TraceHook,
    /// A duplicate of the program's fd, held for the length of the trace.
    pub fd: OwnedFd,
}

/// The programs of one direction, in the order the hooks run them, and the
/// ones of that direction that are not loaded.
#[derive(Debug, Default)]
pub struct TracePlan {
    pub programs: Vec<TracedProgram>,
    pub not_loaded: Vec<String>,
}

/// Where the programs come from: a fresh plan per trace, since a reload
/// swaps the programs behind a name.
pub type TracePlanSource = Box<dyn Fn(TraceDirection) -> TracePlan + Send + Sync>;

/// [`DatapathTracePort`] over `BPF_PROG_TEST_RUN`.
pub struct EbpfDatapathTracer {
    plan: TracePlanSource,
}

impl EbpfDatapathTracer {
    pub fn new(plan: TracePlanSource) -> Self {
        Self { plan }
    }
}

impl DatapathTracePort for EbpfDatapathTracer {
    fn run(&self, packet: &[u8], direction: TraceDirection) -> Result<DatapathRuns, TraceError> {
        let plan = (self.plan)(direction);
        let runs = run_plan(&plan.programs, packet).map_err(|e| unavailable(&e))?;
        Ok(DatapathRuns {
            runs,
            not_loaded: plan.not_loaded,
        })
    }
}

fn unavailable(error: &TestRunError) -> TraceError {
    TraceError::Unavailable(if error.is_unavailable() {
        format!("{error}; running a program needs CAP_BPF or a BPF token")
    } else {
        error.to_string()
    })
}

/// Whether a program's return lets the packet reach the next hook.
fn continues(hook: TraceHook, retval: u32) -> bool {
    match hook {
        TraceHook::Xdp => retval == XDP_PASS,
        TraceHook::TcIngress | TraceHook::TcEgress => {
            matches!(retval, TC_ACT_OK | TC_ACT_PIPE | TCX_NEXT)
        }
    }
}

/// Run `packet` through `programs` in order, chaining the packet each one
/// leaves, until one stops it.
///
/// # Errors
///
/// The first refusal of the kernel.
pub fn run_plan(
    programs: &[TracedProgram],
    packet: &[u8],
) -> Result<Vec<ProgramRun>, TestRunError> {
    let mut packet = packet.to_vec();
    let mut runs = Vec::with_capacity(programs.len());
    for program in programs {
        let (retval, records, data_out) = match program.hook {
            TraceHook::Xdp => {
                let (outcome, meta) =
                    run_xdp_with_metadata(program.fd.as_fd(), &xdp_trace_metadata(), &packet)?;
                let (slots, _) = xdp_records(&meta);
                let records: Vec<TraceRecord> = slots.into_iter().flatten().collect();
                (outcome.retval, records, outcome.data_out)
            }
            TraceHook::TcIngress | TraceHook::TcEgress => {
                let ctx = SkbContext {
                    mark: TC_TRACE_MARK,
                    priority: TC_TRACE_PRIORITY,
                    cb: [0; 5],
                };
                let (outcome, ctx_out) = run_tc_with_context(program.fd.as_fd(), &packet, ctx)?;
                let records = tc_record(&ctx_out.cb, outcome.retval).into_iter().collect();
                (outcome.retval, records, outcome.data_out)
            }
        };
        runs.push(ProgramRun {
            program: program.name.clone(),
            hook: program.hook,
            retval,
            records,
        });
        if !continues(program.hook, retval) {
            break;
        }
        if !data_out.is_empty() {
            packet = data_out;
        }
    }
    Ok(runs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pass_leaves_xdp_for_the_next_hook() {
        assert!(continues(TraceHook::Xdp, XDP_PASS));
        for stop in [0, 1, 3, 4] {
            assert!(!continues(TraceHook::Xdp, stop));
        }
    }

    #[test]
    fn a_classifier_hands_on_with_ok_pipe_or_next() {
        for go in [TC_ACT_OK, TC_ACT_PIPE, TCX_NEXT] {
            assert!(continues(TraceHook::TcIngress, go));
            assert!(continues(TraceHook::TcEgress, go));
        }
        for stop in [2, 4, 7] {
            assert!(!continues(TraceHook::TcIngress, stop));
        }
    }

    #[test]
    fn an_empty_plan_runs_nothing() {
        assert!(run_plan(&[], &[0u8; 64]).unwrap().is_empty());
    }

    #[test]
    fn a_missing_privilege_says_what_is_needed() {
        let error = TestRunError::Syscall {
            errno: libc::EPERM,
            message: "Operation not permitted".into(),
        };
        let TraceError::Unavailable(message) = unavailable(&error) else {
            panic!("unavailable");
        };
        assert!(message.contains("CAP_BPF"));
    }
}
