//! What the mass encryption verdict would have raised while it is in shadow.
//!
//! A verdict in shadow raises no alert: it is counted by the workload of its
//! actor, and the last few are kept as they would have read, so the decision
//! to put it in force is taken on what it would have said on this host.

use std::collections::VecDeque;

use serde::Serialize;

use crate::hostrule::HostShadowReading;

/// Verdicts kept as they would have read, newest last.
pub const RANSOM_SHADOW_RECENT_MAX: usize = 16;

/// One verdict the engine reached in shadow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ShadowVerdict {
    /// When it was reached, boot-time nanoseconds.
    pub at_ns: u64,
    /// The actor's pid.
    pub pid: u32,
    /// The actor's executable, where the table knew it.
    pub exe: Option<String>,
    /// The workload it was counted under.
    pub workload: Option<String>,
    /// The verdict as the alert would have said it.
    pub message: String,
}

/// The verdicts reached in shadow since the agent started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RansomShadow {
    /// Verdicts counted by workload.
    pub reading: HostShadowReading,
    /// The last verdicts, newest last.
    pub recent: VecDeque<ShadowVerdict>,
}

impl RansomShadow {
    /// Count `verdict`, keeping it among the recent ones.
    pub fn record(&mut self, verdict: ShadowVerdict) {
        self.reading.record(verdict.workload.as_deref());
        if self.recent.len() == RANSOM_SHADOW_RECENT_MAX {
            self.recent.pop_front();
        }
        self.recent.push_back(verdict);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(pid: u32, workload: Option<&str>) -> ShadowVerdict {
        ShadowVerdict {
            at_ns: u64::from(pid),
            pid,
            exe: Some("/tmp/enc".to_string()),
            workload: workload.map(str::to_owned),
            message: format!("verdict {pid}"),
        }
    }

    #[test]
    fn verdicts_are_counted_by_workload_and_the_last_ones_are_kept() {
        let mut shadow = RansomShadow::default();
        for pid in 0..20 {
            shadow.record(verdict(pid, Some(if pid % 2 == 0 { "a" } else { "b" })));
        }
        shadow.record(verdict(99, None));
        assert_eq!(shadow.reading.events, 21);
        assert_eq!(shadow.reading.workloads.len(), 3);
        assert_eq!(shadow.recent.len(), RANSOM_SHADOW_RECENT_MAX);
        assert_eq!(shadow.recent.back().map(|v| v.pid), Some(99));
        assert_eq!(shadow.recent.front().map(|v| v.pid), Some(5));
    }
}
