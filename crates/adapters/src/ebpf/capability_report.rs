//! Which capability above the floor is active on this host, and why each
//! other one is not.
//!
//! The report asks the kernel nothing. It reads what the probes already
//! cached and what each adapter published once it tried to attach, and gives
//! every catalogue entry one answer: active, or inactive for exactly one
//! reason. When more than one reason holds, the most actionable is kept,
//! in a fixed order: a probe that could not run says so first, because it
//! proves nothing about the kernel; a kernel older than the capability comes
//! before a kfunc the kernel does not declare; the BPF LSM missing from the
//! boot comes before a refusal, because a refusal on a host without it is a
//! consequence rather than a cause.
//!
//! A version never enables anything: an entry is active only on evidence that
//! the kernel offers it, whatever its number says, and inactive on evidence
//! that it does not, whatever its number says.

use std::sync::OnceLock;

use domain::ransom::refusal::WriteRefusalRoute;

use super::capabilities::{CATALOGUE, Capability, KernelVersion};
use super::file_kfunc_probe::FileKfuncStatus;
use super::kernel_probe::upgrade_hint;
use super::kfunc_feature_probe::KfuncFeature;
use super::lsm_probe::BpfLsmStatus;

/// What to do where the BPF LSM is not active and the probe named no remedy.
const LSM_BOOT_PARAMETER: &str =
    "add bpf to the lsm= kernel boot parameter, keeping the modules already active, and reboot";

/// Where the running kernel names its release.
const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

/// Why a capability is not active here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inactive {
    /// The running kernel is older than the one that introduced it, and
    /// nothing says a vendor backported it.
    KernelOlder { since: KernelVersion },
    /// The kernel is recent enough and does not declare it: a backport
    /// missing or a configuration leaving it out.
    NotDeclared,
    /// It rests on the BPF LSM, which is not among the active security
    /// modules.
    LsmInactive,
    /// Nothing on this host was asked, for the reason given: a privilege the
    /// deployment does not grant, or a configuration that does not use it.
    /// Never a statement about the kernel.
    NotProbed(String),
    /// The kernel declares it and refused it, with the kernel's reason.
    Refused(String),
}

impl Inactive {
    /// The word an API reader and a metric match on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::KernelOlder { .. } => "kernel_older",
            Self::NotDeclared => "not_declared",
            Self::LsmInactive => "lsm_inactive",
            Self::NotProbed(_) => "not_probed",
            Self::Refused(_) => "refused",
        }
    }

    /// The reason in one sentence.
    #[must_use]
    pub fn describe(&self, kernel: Option<KernelVersion>) -> String {
        match self {
            Self::KernelOlder { since } => match kernel {
                Some(found) => format!("needs {since}, found {found}"),
                None => format!("needs {since}"),
            },
            Self::NotDeclared => {
                "the kernel does not declare it: a backport is missing or the kernel \
                 configuration leaves it out"
                    .to_string()
            }
            Self::LsmInactive => "the BPF LSM is not among the active security modules".to_string(),
            Self::NotProbed(why) => format!("not probed: {why}"),
            Self::Refused(why) => format!("refused by the kernel: {why}"),
        }
    }
}

/// How a load the probe attempted ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Load {
    /// The program loaded.
    Loaded,
    /// The kernel refused it for a reason a privilege would not change.
    Refused(String),
    /// The load could not be attempted, for this reason.
    NotRun(String),
    /// The entry is read from BTF alone and nothing is loaded.
    NotAttempted,
}

/// What a probe or an adapter said about one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Evidence {
    /// Kfuncs read from BTF, and the load that confirms them where there is
    /// one. `declared` is `None` when the BTF could not be read.
    Kfunc { declared: Option<bool>, load: Load },
    /// The BPF LSM itself.
    Lsm {
        active: bool,
        built: Option<bool>,
        /// The modules list could be read.
        read: bool,
    },
    /// An attach an adapter tried, or did not try.
    Attach {
        active: bool,
        /// Whether anything was attempted on this host.
        attempted: bool,
        reason: Option<String>,
    },
}

/// One entry and its answer here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityState {
    pub capability: &'static Capability,
    /// `None` when active.
    pub inactive: Option<Inactive>,
    /// How to switch it on, where something on the host can: a kernel to
    /// install or a boot parameter to set. `None` when active, and when the
    /// probe could not run or the kernel refused, since neither names a
    /// change that would help.
    pub hint: Option<String>,
}

impl CapabilityState {
    #[must_use]
    pub const fn active(&self) -> bool {
        self.inactive.is_none()
    }
}

/// Every catalogue entry, answered for this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityReport {
    /// The release string, kept for the hint.
    pub release: Option<String>,
    pub kernel: Option<KernelVersion>,
    pub entries: Vec<CapabilityState>,
}

impl CapabilityReport {
    /// How many entries are active.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.active()).count()
    }
}

/// Decide one entry from its evidence, in the fixed order of reasons.
#[must_use]
pub fn classify(
    capability: &Capability,
    kernel: Option<KernelVersion>,
    lsm_active: bool,
    evidence: &Evidence,
) -> Option<Inactive> {
    let lsm_ok = !capability.needs_lsm || lsm_active;
    let older = kernel.is_some_and(|k| k < capability.since);
    match evidence {
        Evidence::Lsm {
            active,
            built,
            read,
        } => {
            if *active {
                None
            } else if !*read {
                Some(Inactive::NotProbed(
                    "the list of active security modules could not be read".to_string(),
                ))
            } else if older {
                Some(Inactive::KernelOlder {
                    since: capability.since,
                })
            } else if *built == Some(false) {
                Some(Inactive::NotDeclared)
            } else {
                Some(Inactive::LsmInactive)
            }
        }
        Evidence::Kfunc { declared, load } => {
            let confirmed = matches!(load, Load::Loaded | Load::NotAttempted);
            if *declared == Some(true) && confirmed && lsm_ok {
                return None;
            }
            if let Load::NotRun(why) = load {
                return Some(Inactive::NotProbed(why.clone()));
            }
            if declared.is_none() {
                return Some(Inactive::NotProbed(
                    "the kernel BTF could not be read".to_string(),
                ));
            }
            if *declared == Some(false) {
                return Some(if older {
                    Inactive::KernelOlder {
                        since: capability.since,
                    }
                } else {
                    Inactive::NotDeclared
                });
            }
            if !lsm_ok {
                return Some(Inactive::LsmInactive);
            }
            match load {
                Load::Refused(why) => Some(Inactive::Refused(why.clone())),
                // Declared, confirmed and the LSM answered: handled above.
                Load::Loaded | Load::NotAttempted | Load::NotRun(_) => None,
            }
        }
        Evidence::Attach {
            active,
            attempted,
            reason,
        } => {
            if *active && lsm_ok {
                return None;
            }
            if !*attempted {
                return Some(Inactive::NotProbed(reason.clone().unwrap_or_else(|| {
                    "nothing in the configuration uses it, so no attach was attempted".to_string()
                })));
            }
            if older {
                return Some(Inactive::KernelOlder {
                    since: capability.since,
                });
            }
            if !lsm_ok {
                return Some(Inactive::LsmInactive);
            }
            Some(Inactive::Refused(reason.clone().unwrap_or_else(|| {
                "the attach did not complete and gave no reason".to_string()
            })))
        }
    }
}

/// How to switch an inactive entry on, for the reason it is off.
fn hint_for(
    capability: &Capability,
    inactive: &Inactive,
    release: Option<&str>,
    lsm_remedy: Option<&str>,
) -> Option<String> {
    let lsm = || lsm_remedy.unwrap_or(LSM_BOOT_PARAMETER).to_string();
    match inactive {
        Inactive::LsmInactive => Some(lsm()),
        // The LSM itself is switched on at boot, or by a kernel built with it,
        // which is what the LSM probe's remedy already says.
        Inactive::NotDeclared if capability.id == "bpf_lsm" => Some(lsm()),
        Inactive::KernelOlder { since } => release.map(|r| upgrade_hint(r, *since)),
        Inactive::NotDeclared => release.map(|r| upgrade_hint(r, capability.since)),
        Inactive::NotProbed(_) | Inactive::Refused(_) => None,
    }
}

/// Build the report from evidence keyed by catalogue identifier. An entry
/// with no evidence is not probed.
#[must_use]
pub fn build(
    release: Option<String>,
    lsm_active: bool,
    lsm_remedy: Option<&str>,
    evidence: &dyn Fn(&str) -> Option<Evidence>,
) -> CapabilityReport {
    let kernel = release.as_deref().and_then(KernelVersion::parse);
    let entries = CATALOGUE
        .iter()
        .map(|capability| {
            let inactive = match evidence(capability.id) {
                Some(e) => classify(capability, kernel, lsm_active, &e),
                None => Some(Inactive::NotProbed(
                    "startup has not reached the probe that answers for it".to_string(),
                )),
            };
            let hint = inactive
                .as_ref()
                .and_then(|i| hint_for(capability, i, release.as_deref(), lsm_remedy));
            CapabilityState {
                capability,
                inactive,
                hint,
            }
        })
        .collect();
    CapabilityReport {
        release,
        kernel,
        entries,
    }
}

/// The BPF LSM, restated as evidence.
#[must_use]
pub fn lsm_evidence(lsm: &BpfLsmStatus) -> Evidence {
    Evidence::Lsm {
        active: lsm.active,
        built: lsm.built,
        read: !lsm.modules.is_empty(),
    }
}

/// The file kfunc probe, restated as evidence for its one entry.
#[must_use]
pub fn file_kfunc_evidence(status: Option<&FileKfuncStatus>) -> Evidence {
    let Some(status) = status else {
        return Evidence::Kfunc {
            declared: None,
            load: Load::NotRun("startup has not run the file kfunc probe".to_string()),
        };
    };
    let declared = fold_declared(status.kfuncs.iter().map(|k| k.declared));
    let why = || status.sleepable.reason.clone().unwrap_or_default();
    let load = match status.sleepable.loads {
        Some(true) => Load::Loaded,
        Some(false) => Load::Refused(why()),
        None => Load::NotRun(why()),
    };
    Evidence::Kfunc { declared, load }
}

/// One kfunc fact, restated as evidence.
#[must_use]
pub fn kfunc_feature_evidence(feature: &KfuncFeature) -> Evidence {
    let declared = fold_declared(feature.kfuncs.iter().map(|k| k.declared));
    let why = || feature.reason.clone().unwrap_or_default();
    let load = if feature.load_tested {
        match feature.usable {
            Some(true) => Load::Loaded,
            Some(false) => Load::Refused(why()),
            None => Load::NotRun(why()),
        }
    } else {
        Load::NotAttempted
    };
    Evidence::Kfunc { declared, load }
}

/// An adapter's published attach status, restated as evidence. A status
/// carrying no reason and nothing attached was never tried; one whose reason
/// says the configuration turned it off was not tried either.
#[must_use]
pub fn attach_evidence(active: bool, reason: Option<String>) -> Evidence {
    let attempted = active
        || reason
            .as_deref()
            .is_some_and(|r| !r.contains("off in the configuration"));
    Evidence::Attach {
        active,
        attempted,
        reason,
    }
}

/// All declared, any not declared, or unreadable.
fn fold_declared(answers: impl Iterator<Item = Option<bool>>) -> Option<bool> {
    let mut all = Some(true);
    for answer in answers {
        match answer {
            None => return None,
            Some(false) => all = Some(false),
            Some(true) => {}
        }
    }
    all
}

/// The evidence the running agent holds for one catalogue entry.
fn host_evidence(id: &str) -> Option<Evidence> {
    use super::{
        attribution_attach, bpf_guard, exec_network, file_kfunc_probe, kfunc_feature_probe,
        lsm_probe, process_attach, quarantine_map_manager, signal_attach, workload_firewall_attach,
        write_refusal,
    };
    match id {
        "bpf_lsm" => Some(lsm_evidence(lsm_probe::status())),
        "file_kfuncs" => Some(file_kfunc_evidence(file_kfunc_probe::cached())),
        "attribution" => {
            let s = attribution_attach::status();
            Some(attach_evidence(s.attached, s.reason))
        }
        "process_tracing" => {
            let s = process_attach::status();
            Some(attach_evidence(s.attached, s.reason))
        }
        "workload_firewall" => {
            let s = workload_firewall_attach::status();
            Some(attach_evidence(s.attached, s.reason))
        }
        "quarantine" => {
            let s = quarantine_map_manager::status();
            Some(attach_evidence(s.armed, s.reason))
        }
        "process_signal" => {
            let s = signal_attach::status();
            Some(attach_evidence(s.attached, s.reason))
        }
        "network_executables" => {
            let s = exec_network::status();
            Some(attach_evidence(s.attached, s.reason))
        }
        "self_protection" => {
            let s = bpf_guard::status();
            Some(attach_evidence(s.protected, s.reason))
        }
        "write_refusal" => {
            let s = write_refusal::status();
            if s.attached && s.route == Some(WriteRefusalRoute::Fanotify) {
                // Refusing, through the fallback: the capability itself is
                // the kernel deciding at the LSM hook.
                Some(Evidence::Attach {
                    active: false,
                    attempted: true,
                    reason: Some("the fanotify fallback refuses instead".to_string()),
                })
            } else {
                Some(attach_evidence(s.attached, s.reason))
            }
        }
        other => kfunc_feature_probe::cached()
            .and_then(|features| features.iter().find(|f| f.name == other))
            .map(kfunc_feature_evidence),
    }
}

/// Build the report off what this process has already learned.
#[must_use]
pub fn from_host() -> CapabilityReport {
    let release = std::fs::read_to_string(OSRELEASE_PATH)
        .ok()
        .map(|r| r.trim().to_string());
    let lsm = super::lsm_probe::status();
    build(release, lsm.active, lsm.remedy.as_deref(), &host_evidence)
}

static REPORT: OnceLock<CapabilityReport> = OnceLock::new();

/// Build the report once, after every probe and attach of the start-up has
/// answered, and keep it.
pub fn init_cached() -> &'static CapabilityReport {
    REPORT.get_or_init(from_host)
}

/// The report the start-up built, or `None` before it has.
#[must_use]
pub fn cached() -> Option<&'static CapabilityReport> {
    REPORT.get()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::capabilities::{ProbeKind, find};

    const ABOVE: Capability = Capability {
        id: "string_kfuncs",
        unlocks: "kernel strings compared in the kernel",
        probe: ProbeKind::Loaded,
        since: KernelVersion {
            major: 6,
            minor: 17,
        },
        needs_lsm: false,
        fallback: "compared in userspace",
    };

    fn k(major: u32, minor: u32) -> KernelVersion {
        KernelVersion { major, minor }
    }

    #[test]
    fn a_recent_kernel_that_lacks_the_kfunc_is_not_declared_not_active() {
        let e = Evidence::Kfunc {
            declared: Some(false),
            load: Load::Refused("not declared".into()),
        };
        assert_eq!(
            classify(&ABOVE, Some(k(7, 0)), true, &e),
            Some(Inactive::NotDeclared)
        );
    }

    #[test]
    fn a_backport_on_an_older_number_is_active() {
        let e = Evidence::Kfunc {
            declared: Some(true),
            load: Load::Loaded,
        };
        assert_eq!(classify(&ABOVE, Some(k(6, 12)), false, &e), None);
    }

    #[test]
    fn an_older_kernel_without_it_names_the_version_before_the_declaration() {
        let e = Evidence::Kfunc {
            declared: Some(false),
            load: Load::Refused("not declared".into()),
        };
        let inactive = classify(&ABOVE, Some(k(6, 12)), true, &e).expect("inactive");
        assert_eq!(inactive, Inactive::KernelOlder { since: ABOVE.since });
        assert_eq!(inactive.describe(Some(k(6, 12))), "needs 6.17, found 6.12");
    }

    #[test]
    fn a_probe_that_could_not_run_says_nothing_about_the_kernel() {
        let e = Evidence::Kfunc {
            declared: Some(false),
            load: Load::NotRun("the load needs a BPF token and none was granted".into()),
        };
        let inactive = classify(&ABOVE, Some(k(6, 12)), true, &e).expect("inactive");
        assert_eq!(inactive.code(), "not_probed");
        let said = inactive.describe(Some(k(6, 12)));
        assert!(!said.contains("needs 6."), "{said}");
        assert!(!said.contains("found 6."), "{said}");
        assert!(!said.contains("kernel does not"), "{said}");
        assert!(said.contains("BPF token"), "{said}");
    }

    #[test]
    fn the_lsm_comes_before_a_refusal() {
        let file = find("file_kfuncs").expect("entry");
        let e = Evidence::Kfunc {
            declared: Some(true),
            load: Load::Refused("sleepable programs refused".into()),
        };
        assert_eq!(
            classify(file, Some(k(6, 12)), false, &e),
            Some(Inactive::LsmInactive)
        );
        assert_eq!(
            classify(file, Some(k(6, 12)), true, &e),
            Some(Inactive::Refused("sleepable programs refused".into()))
        );
    }

    #[test]
    fn declared_and_loaded_is_still_inactive_without_the_lsm_it_needs() {
        let file = find("file_kfuncs").expect("entry");
        let e = Evidence::Kfunc {
            declared: Some(true),
            load: Load::Loaded,
        };
        assert_eq!(
            classify(file, Some(k(7, 0)), false, &e),
            Some(Inactive::LsmInactive)
        );
        assert_eq!(classify(file, Some(k(7, 0)), true, &e), None);
    }

    #[test]
    fn a_fact_read_from_btf_alone_is_active_when_declared() {
        let reqsk = find("tcp_reqsk_assign").expect("entry");
        let e = Evidence::Kfunc {
            declared: Some(true),
            load: Load::NotAttempted,
        };
        assert_eq!(classify(reqsk, Some(k(6, 12)), false, &e), None);
    }

    #[test]
    fn an_attach_turned_off_in_the_configuration_is_not_probed() {
        let signal = find("process_signal").expect("entry");
        let e = attach_evidence(
            false,
            Some("stopping a process is turned off in the configuration".into()),
        );
        assert_eq!(
            classify(signal, Some(k(6, 12)), true, &e),
            Some(Inactive::NotProbed(
                "stopping a process is turned off in the configuration".into()
            ))
        );
        let never = attach_evidence(false, None);
        assert_eq!(
            classify(signal, Some(k(6, 12)), true, &never)
                .expect("inactive")
                .code(),
            "not_probed"
        );
    }

    #[test]
    fn an_lsm_attach_refused_on_a_host_without_the_lsm_names_the_lsm() {
        let guard = find("self_protection").expect("entry");
        let e = attach_evidence(false, Some("the LSM hook did not attach".into()));
        assert_eq!(
            classify(guard, Some(k(6, 12)), false, &e),
            Some(Inactive::LsmInactive)
        );
        assert_eq!(
            classify(guard, Some(k(6, 12)), true, &e),
            Some(Inactive::Refused("the LSM hook did not attach".into()))
        );
    }

    #[test]
    fn the_lsm_entry_separates_a_build_from_a_boot() {
        let lsm = find("bpf_lsm").expect("entry");
        let booted_without = Evidence::Lsm {
            active: false,
            built: Some(true),
            read: true,
        };
        assert_eq!(
            classify(lsm, Some(k(6, 12)), false, &booted_without),
            Some(Inactive::LsmInactive)
        );
        let built_without = Evidence::Lsm {
            active: false,
            built: Some(false),
            read: true,
        };
        assert_eq!(
            classify(lsm, Some(k(6, 12)), false, &built_without),
            Some(Inactive::NotDeclared)
        );
        let unread = Evidence::Lsm {
            active: false,
            built: None,
            read: false,
        };
        assert_eq!(
            classify(lsm, Some(k(6, 12)), false, &unread)
                .expect("inactive")
                .code(),
            "not_probed"
        );
    }

    #[test]
    fn the_report_answers_every_entry_and_a_missing_one_is_not_probed() {
        let report = build(Some("6.12.48+deb13-amd64".into()), true, None, &|id| {
            (id == "bpf_lsm").then_some(Evidence::Lsm {
                active: true,
                built: Some(true),
                read: true,
            })
        });
        assert_eq!(report.kernel, Some(k(6, 12)));
        assert_eq!(report.entries.len(), CATALOGUE.len());
        assert_eq!(report.active_count(), 1);
        for e in report.entries.iter().filter(|e| !e.active()) {
            assert_eq!(e.inactive.as_ref().expect("inactive").code(), "not_probed");
        }
    }

    #[test]
    fn each_reason_gets_the_hint_that_could_change_it() {
        let lsm_off = "add bpf to the lsm= kernel boot parameter: lsm=landlock,bpf";
        let report = build(
            Some("6.12.48+deb13-amd64".into()),
            false,
            Some(lsm_off),
            &|id| match id {
                "bpf_lsm" => Some(Evidence::Lsm {
                    active: false,
                    built: Some(true),
                    read: true,
                }),
                "tcp_reqsk_assign" => Some(Evidence::Kfunc {
                    declared: Some(false),
                    load: Load::NotAttempted,
                }),
                "kprobe_session" => Some(Evidence::Kfunc {
                    declared: Some(true),
                    load: Load::Refused("invalid argument".into()),
                }),
                _ => None,
            },
        );
        let entry = |id: &str| {
            report
                .entries
                .iter()
                .find(|e| e.capability.id == id)
                .expect("entry")
        };
        assert_eq!(entry("bpf_lsm").hint.as_deref(), Some(lsm_off));
        assert_eq!(
            entry("write_refusal").hint,
            None,
            "not probed names no change"
        );
        let declared = entry("tcp_reqsk_assign").hint.as_deref().expect("hint");
        assert!(declared.contains("backports"), "{declared}");
        assert_eq!(
            entry("kprobe_session").hint,
            None,
            "a refusal names no change"
        );
    }

    #[test]
    fn an_older_kernel_is_pointed_at_the_version_it_lacks() {
        let inactive = Inactive::KernelOlder { since: ABOVE.since };
        let hint = hint_for(&ABOVE, &inactive, Some("6.12.48+deb13-amd64"), None).expect("hint");
        assert!(
            hint.starts_with("This needs 6.17 and the host runs 6.12"),
            "{hint}"
        );
        assert_eq!(hint_for(&ABOVE, &inactive, None, None), None);
    }

    #[test]
    fn declarations_fold_to_all_any_missing_or_unreadable() {
        assert_eq!(
            fold_declared([Some(true), Some(true)].into_iter()),
            Some(true)
        );
        assert_eq!(
            fold_declared([Some(true), Some(false)].into_iter()),
            Some(false)
        );
        assert_eq!(fold_declared([Some(false), None].into_iter()), None);
    }
}
