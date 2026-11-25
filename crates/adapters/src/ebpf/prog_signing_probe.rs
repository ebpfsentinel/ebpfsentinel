//! Whether this kernel reads a signature in `BPF_PROG_LOAD` and checks it.
//!
//! The question is asked the way the kernel answers it rather than by its
//! version: a trivial program is loaded with a non-zero `signature`,
//! `signature_size` and `keyring_id`. A kernel without those fields refuses a
//! non-zero tail with `E2BIG` before it reads anything else; a kernel with
//! them goes on to look the keyring up and check the signature, and whatever
//! it answers then (a rejected key, a missing key, a malformed message, an
//! invalid argument, a refused privilege, or a load) proves the fields exist.

use std::sync::OnceLock;

use super::kfunc_feature_probe::insn;

/// The keyring the probe names: the kernel's secondary trusted keyring, a
/// system keyring every kernel has, so nothing is created to ask.
const PROBE_KEYRING_ID: i32 = 1;

/// A signature no key verifies. Its content does not matter: a kernel without
/// the fields refuses before reading it, and a kernel with them answers
/// whatever it answers, which is presence either way.
const PROBE_SIGNATURE: [u8; 64] = [0x5a; 64];

/// What this host answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgSigningStatus {
    /// `Some(true)` when the kernel reads a signature in a program load,
    /// `Some(false)` when it has no field for one, `None` when the probe could
    /// not ask.
    pub verifies: Option<bool>,
    /// Why the kernel does not verify, or why nothing was asked.
    pub reason: Option<String>,
}

impl ProgSigningStatus {
    /// Whether the kernel checks a program's signature at load.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.verifies == Some(true)
    }
}

/// Decide the answer from the errno of the signed load, `None` when the load
/// succeeded. `E2BIG` is the only absence: the kernel refused the signature
/// fields as an unknown tail. `ENOSYS` means no BPF syscall answered, so
/// nothing was asked. Every other answer comes from a kernel that read the
/// fields, which is presence whatever the verdict on the signature itself.
#[must_use]
pub fn signing_from_errno(errno: Option<i32>) -> ProgSigningStatus {
    match errno {
        Some(libc::E2BIG) => ProgSigningStatus {
            verifies: Some(false),
            reason: Some(
                "this kernel has no signature field in a program load, so it cannot check one"
                    .to_string(),
            ),
        },
        Some(libc::ENOSYS) => ProgSigningStatus {
            verifies: None,
            reason: Some("the bpf system call is not available, so nothing was asked".to_string()),
        },
        None | Some(_) => ProgSigningStatus {
            verifies: Some(true),
            reason: None,
        },
    }
}

/// The probe program: `r0 = 0; exit`, a classifier that passes everything.
fn probe_insns() -> Vec<u64> {
    vec![insn::mov_imm(0, 0), insn::exit()]
}

/// Probe this host: load the trivial program with a signature attached and
/// read the answer. Any descriptor the load returns is closed at once.
#[must_use]
pub fn run() -> ProgSigningStatus {
    let probe = super::kfunc_loader::ProbeProgram {
        prog_type: super::kfunc_loader::PROBE_PROG_TYPE_SCHED_CLS,
        expected_attach_type: 0,
        prog_flags: 0,
        attach_btf_id: 0,
        insns: probe_insns(),
    };
    signing_from_errno(
        super::kfunc_loader::load_signed_probe(&probe, &PROBE_SIGNATURE, PROBE_KEYRING_ID).err(),
    )
}

static CACHE: OnceLock<ProgSigningStatus> = OnceLock::new();

/// Run the probe once per process, at startup, and keep the answer.
pub fn init_cached() -> &'static ProgSigningStatus {
    CACHE.get_or_init(run)
}

/// The cached answer, or `None` when startup has not probed yet, so that
/// reading it from an operational endpoint never issues a load of its own.
#[must_use]
pub fn cached() -> Option<&'static ProgSigningStatus> {
    CACHE.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2big_is_the_only_absence() {
        let status = signing_from_errno(Some(libc::E2BIG));
        assert_eq!(status.verifies, Some(false));
        assert!(!status.verifies());
        assert!(
            status
                .reason
                .is_some_and(|r| r.contains("no signature field"))
        );
    }

    #[test]
    fn a_load_that_succeeds_proves_the_fields_exist() {
        let status = signing_from_errno(None);
        assert_eq!(status.verifies, Some(true));
        assert!(status.verifies());
        assert_eq!(status.reason, None);
    }

    #[test]
    fn every_verdict_on_the_signature_itself_is_presence() {
        for errno in [
            libc::EKEYREJECTED,
            libc::ENOKEY,
            libc::EBADMSG,
            libc::EINVAL,
            libc::EPERM,
            libc::EACCES,
            libc::EOPNOTSUPP,
        ] {
            let status = signing_from_errno(Some(errno));
            assert_eq!(status.verifies, Some(true), "errno {errno}");
            assert_eq!(status.reason, None, "errno {errno}");
        }
    }

    #[test]
    fn no_bpf_syscall_means_nothing_was_asked() {
        let status = signing_from_errno(Some(libc::ENOSYS));
        assert_eq!(status.verifies, None);
        assert!(!status.verifies());
        assert!(status.reason.is_some());
    }

    #[test]
    fn the_probe_program_returns_zero_and_exits() {
        assert_eq!(probe_insns(), vec![insn::mov_imm(0, 0), insn::exit()]);
    }

    #[test]
    fn the_probe_names_a_system_keyring_and_a_non_empty_signature() {
        assert_eq!(PROBE_KEYRING_ID, 1);
        assert!(PROBE_SIGNATURE.iter().any(|&b| b != 0));
    }
}
