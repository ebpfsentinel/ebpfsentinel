use serde::Serialize;

/// What the agent does about program signatures on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningState {
    /// Startup has not asked the kernel, so nothing is claimed either way.
    NotProbed,
    /// The kernel reads no signature in a program load, so the agent's
    /// programs load unsigned and nothing on this node could check one.
    Unsupported,
    /// The kernel verifies signatures, and the agent's programs load
    /// without one: no signed loader was shipped beside them, or none
    /// matched the object the agent loaded.
    Unsigned,
    /// The agent's programs went through loaders signed at build, which the
    /// kernel checked against the keyring the warden made; nothing refuses a
    /// load made through the token without a signature.
    VerifiedNotEnforced,
    /// The kernel checks every signature against the warden's keyring, and
    /// the warden's guard refuses every load made through a BPF token that
    /// is not signed against that keyring.
    Enforced,
}

impl SigningState {
    /// The word an API reader matches on.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotProbed => "not_probed",
            Self::Unsupported => "unsupported",
            Self::Unsigned => "unsigned",
            Self::VerifiedNotEnforced => "verified_not_enforced",
            Self::Enforced => "enforced",
        }
    }
}

/// What the warden said about its guard on program loads when it handed the
/// token over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum LoadGuardReport {
    /// No warden handed anything over: the agent runs without the split, or
    /// with a warden that does not report the guard.
    #[default]
    NotReported,
    /// The guard is attached and held by the warden.
    Attached,
    /// The warden did not attach it, for the reason it gave.
    Absent(String),
}

/// What the loads themselves did: the keyring the warden handed over, the
/// certificate the signed loaders verify against, how many programs went
/// each way, and what the warden said about its guard.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignedLoads {
    /// The serial of the keyring the kernel checked the loaders against,
    /// `None` when the warden handed none over.
    pub keyring_serial: Option<i32>,
    /// SHA-256 of the DER certificate the loaders were signed for, in
    /// lowercase hex, the digest a release's measurements record.
    pub certificate_sha256: Option<String>,
    /// Programs loaded through a signed loader.
    pub signed_programs: u64,
    /// Programs loaded unsigned while a keyring was held.
    pub unsigned_programs: u64,
    /// Programs whose unsigned load the guard refused.
    pub refused_programs: u64,
    /// The guard, as the warden reported it.
    pub load_guard: LoadGuardReport,
}

/// The signing block of the crypto posture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SigningPosture {
    /// The kernel reads a signature in a program load and checks it. False
    /// when it does not, and when nobody asked.
    pub kernel_verifies_signatures: bool,
    /// The BPF LSM is among the active security modules.
    pub bpf_lsm_active: bool,
    /// What the agent does about it.
    pub state: SigningState,
    /// The warden's guard on program loads is attached.
    pub load_guard_attached: bool,
    /// The keyring the loaders were checked against, when the agent loaded
    /// signed or the guard holds the node to it.
    pub keyring_serial: Option<i32>,
    /// The certificate digest the loaders were checked against, when the
    /// agent loaded signed.
    pub certificate_sha256: Option<String>,
    /// Programs loaded through a signed loader.
    pub signed_programs: u64,
    /// Programs loaded unsigned while the kernel could have checked them.
    pub unsigned_programs: u64,
    /// Programs the guard refused because they would have loaded unsigned.
    pub refused_programs: u64,
    /// The condition missing for `enforced`, `None` when enforced.
    pub not_enforced_because: Option<String>,
}

impl SigningPosture {
    /// Derive the block from the signed-load probe (`None` when it has not
    /// run) and the BPF LSM fact.
    #[must_use]
    pub fn derive(kernel_verifies: Option<bool>, bpf_lsm_active: bool) -> Self {
        let state = match kernel_verifies {
            None => SigningState::NotProbed,
            Some(false) => SigningState::Unsupported,
            Some(true) => SigningState::Unsigned,
        };
        let mut posture = Self {
            kernel_verifies_signatures: kernel_verifies == Some(true),
            bpf_lsm_active,
            state,
            load_guard_attached: false,
            keyring_serial: None,
            certificate_sha256: None,
            signed_programs: 0,
            unsigned_programs: 0,
            refused_programs: 0,
            not_enforced_because: None,
        };
        posture.not_enforced_because = posture.missing(None, &LoadGuardReport::NotReported);
        posture
    }

    /// Fold in what the loads did and what the warden said about its guard.
    /// Only a kernel that verifies moves the state past `unsigned`: to
    /// `enforced` when the warden reports its guard attached, which it does
    /// only over a keyring, else to `verified_not_enforced` when at least one
    /// program went through a signed loader. The keyring and the certificate
    /// are reported with those two states and no other.
    #[must_use]
    pub fn with_loads(mut self, loads: SignedLoads) -> Self {
        if self.state != SigningState::Unsigned {
            return self;
        }
        self.unsigned_programs = loads.unsigned_programs;
        let attached = loads.load_guard == LoadGuardReport::Attached;
        if attached && loads.keyring_serial.is_some() {
            self.state = SigningState::Enforced;
            self.load_guard_attached = true;
            self.refused_programs = loads.refused_programs;
        } else if loads.signed_programs > 0 && loads.keyring_serial.is_some() {
            self.state = SigningState::VerifiedNotEnforced;
        }
        if self.state != SigningState::Unsigned {
            self.keyring_serial = loads.keyring_serial;
            self.certificate_sha256 = loads.certificate_sha256;
            self.signed_programs = loads.signed_programs;
        }
        self.not_enforced_because = self.missing(loads.keyring_serial, &loads.load_guard);
        self
    }

    /// The first condition `enforced` lacks, in the order an operator meets
    /// them: the kernel, the boot line, the keyring, the warden.
    fn missing(&self, keyring: Option<i32>, guard: &LoadGuardReport) -> Option<String> {
        if self.state == SigningState::Enforced {
            return None;
        }
        let why = match (self.state, guard) {
            (SigningState::NotProbed, _) => {
                "the kernel has not been asked whether it verifies program signatures".to_owned()
            }
            (SigningState::Unsupported, _) => {
                "the kernel does not verify program signatures".to_owned()
            }
            _ if !self.bpf_lsm_active => {
                "bpf is not in the lsm= list the kernel booted with, so nothing can refuse an \
                 unsigned load"
                    .to_owned()
            }
            _ if keyring.is_none() => {
                "the warden handed over no loader keyring to hold the loads to".to_owned()
            }
            (_, LoadGuardReport::Absent(reason)) => {
                format!("the warden did not attach its guard on program loads: {reason}")
            }
            (_, LoadGuardReport::NotReported) => {
                "no warden reported a guard on program loads".to_owned()
            }
            (_, LoadGuardReport::Attached) => {
                "the warden attached its guard without a keyring to hold loads to".to_owned()
            }
        };
        Some(why)
    }

    /// The state in one sentence a reader acts on.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match (self.state, self.unsigned_programs, self.refused_programs) {
            (SigningState::NotProbed, _, _) => {
                "the kernel has not been asked whether it verifies program signatures"
            }
            (SigningState::Unsupported, _, _) => {
                "the kernel does not verify program signatures, and the agent's programs load \
                 unsigned"
            }
            (SigningState::Unsigned, _, _) => {
                "the kernel can verify program signatures, and the agent's programs load unsigned"
            }
            (SigningState::VerifiedNotEnforced, 0, _) => {
                "the agent's programs load through loaders signed at build, checked by the kernel \
                 against the warden's keyring; an unsigned load through the token would still \
                 pass"
            }
            (SigningState::VerifiedNotEnforced, _, _) => {
                "the agent's programs load through loaders signed at build, checked by the kernel \
                 against the warden's keyring; some loaded unsigned, and an unsigned load \
                 through the token would still pass"
            }
            (SigningState::Enforced, _, 0) => {
                "every load through the token is checked by the kernel against the warden's \
                 keyring, and the warden's guard refuses one that is not signed"
            }
            (SigningState::Enforced, _, _) => {
                "every load through the token is checked by the kernel against the warden's \
                 keyring, and the warden's guard refuses one that is not signed; some of the \
                 agent's programs had no signed loader and were refused"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNELS: [Option<bool>; 3] = [None, Some(false), Some(true)];

    fn guards() -> [LoadGuardReport; 3] {
        [
            LoadGuardReport::NotReported,
            LoadGuardReport::Attached,
            LoadGuardReport::Absent("no BPF LSM".to_owned()),
        ]
    }

    fn loads(
        serial: Option<i32>,
        signed: u64,
        unsigned: u64,
        guard: LoadGuardReport,
    ) -> SignedLoads {
        SignedLoads {
            keyring_serial: serial,
            certificate_sha256: Some("ab".repeat(32)),
            signed_programs: signed,
            unsigned_programs: unsigned,
            refused_programs: 0,
            load_guard: guard,
        }
    }

    #[test]
    fn an_unprobed_kernel_claims_nothing() {
        let p = SigningPosture::derive(None, true);
        assert_eq!(p.state, SigningState::NotProbed);
        assert!(!p.kernel_verifies_signatures);
        assert!(p.bpf_lsm_active);
        assert!(p.reason().contains("not been asked"));
        assert!(
            p.not_enforced_because
                .as_deref()
                .is_some_and(|w| w.contains("not been asked"))
        );
    }

    #[test]
    fn a_kernel_that_verifies_still_runs_unsigned_programs() {
        let p = SigningPosture::derive(Some(true), false);
        assert_eq!(p.state, SigningState::Unsigned);
        assert!(p.kernel_verifies_signatures);
        assert!(!p.bpf_lsm_active);
        assert!(p.reason().contains("can verify"));
    }

    #[test]
    fn a_kernel_without_the_fields_reports_unsupported_and_says_why() {
        let p = SigningPosture::derive(Some(false), true);
        assert_eq!(p.state, SigningState::Unsupported);
        assert!(!p.kernel_verifies_signatures);
        assert!(p.reason().contains("does not verify"));
        assert_eq!(
            p.not_enforced_because.as_deref(),
            Some("the kernel does not verify program signatures")
        );
    }

    #[test]
    fn the_lsm_fact_is_carried_as_given() {
        for lsm in [false, true] {
            for kernel in KERNELS {
                assert_eq!(SigningPosture::derive(kernel, lsm).bpf_lsm_active, lsm);
            }
        }
    }

    /// Every combination of kernel, boot line, keyring, signed loads and
    /// guard: `enforced` exactly when the kernel verifies and the warden
    /// reports the guard attached over a keyring, and every other state names
    /// what is missing.
    #[test]
    fn enforced_only_with_a_verifying_kernel_and_an_attached_guard_over_a_keyring() {
        for kernel in KERNELS {
            for lsm in [false, true] {
                for serial in [None, Some(42)] {
                    for signed in [0, 7] {
                        for guard in guards() {
                            let attached = guard == LoadGuardReport::Attached;
                            let p = SigningPosture::derive(kernel, lsm)
                                .with_loads(loads(serial, signed, 1, guard));
                            let expected = kernel == Some(true) && attached && serial.is_some();
                            assert_eq!(p.state == SigningState::Enforced, expected);
                            assert_eq!(p.load_guard_attached, expected);
                            assert_eq!(p.not_enforced_because.is_none(), expected);
                            if !expected {
                                assert!(
                                    p.not_enforced_because
                                        .as_deref()
                                        .is_some_and(|w| !w.is_empty())
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn signed_loads_without_the_guard_are_verified_but_not_enforced() {
        for guard in [
            LoadGuardReport::NotReported,
            LoadGuardReport::Absent("x".to_owned()),
        ] {
            let p =
                SigningPosture::derive(Some(true), true).with_loads(loads(Some(42), 7, 0, guard));
            assert_eq!(p.state, SigningState::VerifiedNotEnforced);
            assert_eq!(p.keyring_serial, Some(42));
            assert_eq!(
                p.certificate_sha256.as_deref(),
                Some("ab".repeat(32).as_str())
            );
            assert_eq!(p.signed_programs, 7);
            assert!(p.reason().contains("signed at build"));
            assert!(p.reason().contains("would still pass"));
            assert!(!p.reason().contains("some loaded unsigned"));
        }
    }

    #[test]
    fn the_reason_names_the_missing_condition_in_order() {
        let why = |kernel, lsm, serial, guard| {
            SigningPosture::derive(kernel, lsm)
                .with_loads(loads(serial, 7, 0, guard))
                .not_enforced_because
                .unwrap_or_default()
        };
        let absent = LoadGuardReport::Absent("the guard object is not in the image".to_owned());
        assert!(why(Some(false), false, None, absent.clone()).contains("does not verify"));
        assert!(why(Some(true), false, None, absent.clone()).contains("lsm="));
        assert!(why(Some(true), true, None, absent.clone()).contains("no loader keyring"));
        assert!(
            why(Some(true), true, Some(42), absent)
                .contains("did not attach its guard on program loads: the guard object")
        );
        assert!(
            why(Some(true), true, Some(42), LoadGuardReport::NotReported)
                .contains("no warden reported")
        );
    }

    #[test]
    fn an_enforced_node_counts_what_the_guard_refused() {
        let mut l = loads(Some(42), 7, 0, LoadGuardReport::Attached);
        l.refused_programs = 2;
        let p = SigningPosture::derive(Some(true), true).with_loads(l);
        assert_eq!(p.state, SigningState::Enforced);
        assert_eq!(p.refused_programs, 2);
        assert_eq!(p.keyring_serial, Some(42));
        assert!(p.reason().contains("were refused"));

        let p = SigningPosture::derive(Some(true), true).with_loads(loads(
            Some(42),
            7,
            0,
            LoadGuardReport::Attached,
        ));
        assert_eq!(p.refused_programs, 0);
        assert!(!p.reason().contains("were refused"));
    }

    #[test]
    fn refusals_are_reported_only_where_the_guard_is_attached() {
        let mut l = loads(Some(42), 7, 0, LoadGuardReport::NotReported);
        l.refused_programs = 3;
        let p = SigningPosture::derive(Some(true), true).with_loads(l);
        assert_eq!(p.refused_programs, 0);
    }

    #[test]
    fn a_mixed_load_says_some_went_unsigned() {
        let p = SigningPosture::derive(Some(true), true).with_loads(loads(
            Some(42),
            7,
            2,
            LoadGuardReport::NotReported,
        ));
        assert_eq!(p.state, SigningState::VerifiedNotEnforced);
        assert_eq!(p.unsigned_programs, 2);
        assert!(p.reason().contains("some loaded unsigned"));
    }

    #[test]
    fn no_keyring_or_no_signed_program_stays_unsigned_and_names_nothing() {
        for l in [
            loads(None, 7, 0, LoadGuardReport::NotReported),
            loads(Some(42), 0, 3, LoadGuardReport::NotReported),
            loads(None, 7, 0, LoadGuardReport::Attached),
        ] {
            let p = SigningPosture::derive(Some(true), true).with_loads(l);
            assert_eq!(p.state, SigningState::Unsigned);
            assert_eq!(p.keyring_serial, None);
            assert_eq!(p.certificate_sha256, None);
            assert_eq!(p.signed_programs, 0);
        }
    }

    #[test]
    fn a_kernel_that_does_not_verify_never_reports_signed_or_enforced() {
        for kernel in [None, Some(false)] {
            for guard in guards() {
                let p =
                    SigningPosture::derive(kernel, true).with_loads(loads(Some(42), 7, 0, guard));
                assert!(matches!(
                    p.state,
                    SigningState::NotProbed | SigningState::Unsupported
                ));
                assert_eq!(p.keyring_serial, None);
                assert_eq!(p.signed_programs, 0);
                assert!(!p.load_guard_attached);
            }
        }
    }

    #[test]
    fn the_state_serializes_as_its_word() {
        for state in [
            SigningState::NotProbed,
            SigningState::Unsupported,
            SigningState::Unsigned,
            SigningState::VerifiedNotEnforced,
            SigningState::Enforced,
        ] {
            let json = serde_json::to_value(state).expect("serializes");
            assert_eq!(json, serde_json::json!(state.as_str()));
        }
    }

    #[test]
    fn the_block_serializes_with_its_fields() {
        let json =
            serde_json::to_value(SigningPosture::derive(Some(true), true)).expect("serializes");
        assert_eq!(
            json,
            serde_json::json!({
                "kernel_verifies_signatures": true,
                "bpf_lsm_active": true,
                "state": "unsigned",
                "load_guard_attached": false,
                "keyring_serial": null,
                "certificate_sha256": null,
                "signed_programs": 0,
                "unsigned_programs": 0,
                "refused_programs": 0,
                "not_enforced_because": "the warden handed over no loader keyring to hold the loads to",
            })
        );
    }

    #[test]
    fn the_enforced_block_serializes_the_serial_and_no_missing_condition() {
        let p = SigningPosture::derive(Some(true), true).with_loads(loads(
            Some(42),
            7,
            0,
            LoadGuardReport::Attached,
        ));
        let json = serde_json::to_value(&p).expect("serializes");
        assert_eq!(json["state"], serde_json::json!("enforced"));
        assert_eq!(json["load_guard_attached"], serde_json::json!(true));
        assert_eq!(json["keyring_serial"], serde_json::json!(42));
        assert_eq!(json["not_enforced_because"], serde_json::Value::Null);
        assert_eq!(
            json["certificate_sha256"],
            serde_json::json!("ab".repeat(32))
        );
    }
}
