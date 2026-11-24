//! Whether the DLP probes read a whole TLS record, and how much of it.
//!
//! The probes read user memory straight into a ring buffer reservation with
//! `bpf_probe_read_user_dynptr`, which lets one event carry up to
//! `dlp.record_bytes` of plaintext instead of the 4,096 of the bounded copy.
//! The kfunc is optional to the loader: a kernel that does not declare it, or
//! refuses the probes while they call it, gets the probes with the call
//! neutralized, and the bounded copy runs. The size goes into the probes only
//! when the kfunc call was kept, so a degraded object is never asked to take a
//! path it cannot.

use std::sync::{Mutex, OnceLock};

use super::kfunc_loader::DegradedProgram;
use crate::ebpf::map_store::MapStore;

/// The kfunc the whole-record path rests on.
pub const RECORD_KFUNC: &str = "bpf_probe_read_user_dynptr";

/// What the agent can say about the whole-record read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DlpRecordStatus {
    /// Whether the kernel BTF declares the kfunc, `None` while the probes
    /// were never loaded.
    pub declared: Option<bool>,
    /// Whether the probes loaded with the kfunc call kept.
    pub loaded: bool,
    /// Why they did not, in one sentence.
    pub reason: Option<String>,
    /// The most plaintext one event carries: the configured size where the
    /// whole record is read, zero where the bounded copy runs.
    pub record_bytes: u32,
}

/// What the load of the DLP object came to for the whole-record read, from
/// the programs the loader had to degrade. `record_bytes` is the configured
/// size, kept only where the kfunc call was.
#[must_use]
pub fn outcome(degraded: &[DegradedProgram], record_bytes: u32) -> DlpRecordStatus {
    let hit = degraded
        .iter()
        .find(|d| d.kfuncs.iter().any(|k| k == RECORD_KFUNC));
    match hit {
        None => DlpRecordStatus {
            declared: Some(true),
            loaded: true,
            reason: None,
            record_bytes,
        },
        Some(d) => DlpRecordStatus {
            declared: Some(d.declared),
            loaded: false,
            reason: Some(format!(
                "`{}` was neutralized in `{}`: {}",
                RECORD_KFUNC, d.name, d.reason
            )),
            record_bytes: 0,
        },
    }
}

/// Write the whole-record size into the probes. Zero keeps every buffer on
/// the bounded copy.
///
/// # Errors
///
/// Returns an error when the object carries no `DLP_RECORD_BYTES` map or the
/// write is refused.
pub fn push_dlp_record_bytes(ebpf: &mut dyn MapStore, bytes: u32) -> anyhow::Result<()> {
    let map = ebpf
        .map_mut("DLP_RECORD_BYTES")
        .ok_or_else(|| anyhow::anyhow!("DLP_RECORD_BYTES map not found"))?;
    let mut arr = aya::maps::Array::<_, u32>::try_from(map)?;
    arr.set(0, &bytes, 0)?;
    Ok(())
}

static STATUS: OnceLock<Mutex<DlpRecordStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<DlpRecordStatus> {
    STATUS.get_or_init(|| Mutex::new(DlpRecordStatus::default()))
}

/// Publish what the last load of the DLP probes came to.
pub fn publish_status(status: DlpRecordStatus) {
    let mut held = status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *held = status;
}

/// What the agent can currently say about the whole-record read.
#[must_use]
pub fn status() -> DlpRecordStatus {
    status_cell()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn degraded(declared: bool, reason: &str) -> DegradedProgram {
        DegradedProgram {
            name: "ssl_write".to_owned(),
            kfuncs: vec![RECORD_KFUNC.to_owned()],
            declared,
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn a_kept_call_reads_the_configured_size() {
        let s = outcome(&[], 16_384);
        assert_eq!(s.declared, Some(true));
        assert!(s.loaded);
        assert_eq!(s.reason, None);
        assert_eq!(s.record_bytes, 16_384);
    }

    #[test]
    fn an_undeclared_kfunc_leaves_the_bounded_copy_and_says_so() {
        let s = outcome(
            &[degraded(
                false,
                "the kernel BTF does not declare `bpf_probe_read_user_dynptr`",
            )],
            16_384,
        );
        assert_eq!(s.declared, Some(false));
        assert!(!s.loaded);
        assert_eq!(s.record_bytes, 0);
        let reason = s.reason.expect("reason");
        assert!(reason.contains("ssl_write"), "{reason}");
        assert!(reason.contains("does not declare"), "{reason}");
    }

    #[test]
    fn a_refusal_keeps_the_kernel_reason() {
        let s = outcome(
            &[degraded(
                true,
                "verifier: calling kernel function is not allowed",
            )],
            8_192,
        );
        assert_eq!(s.declared, Some(true));
        assert!(!s.loaded);
        assert_eq!(s.record_bytes, 0);
        assert!(s.reason.expect("reason").contains("is not allowed"));
    }

    #[test]
    fn another_kfunc_degraded_is_not_this_one() {
        let other = DegradedProgram {
            kfuncs: vec!["bpf_some_other".to_owned()],
            ..degraded(false, "x")
        };
        assert!(outcome(&[other], 4_096).loaded);
    }

    #[test]
    fn a_published_status_is_the_one_read_back() {
        let s = outcome(&[], 12_000);
        publish_status(s.clone());
        assert_eq!(status(), s);
    }
}
