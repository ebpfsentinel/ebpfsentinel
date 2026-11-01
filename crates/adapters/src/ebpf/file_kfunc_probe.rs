//! Whether this host offers the file kfuncs, asked rather than inferred.
//!
//! Four kfuncs read what a task executes and what a file carries:
//! `bpf_get_task_exe_file` and `bpf_put_file` take and drop a reference on a
//! task's executable, `bpf_path_d_path` renders a path, and
//! `bpf_get_dentry_xattr` reads an extended attribute. The kernel version says
//! nothing reliable about any of them: a vendor backports one, a configuration
//! leaves another out, and the four did not all arrive in the same release.
//!
//! Being declared is also not being usable. The kernel offers them only to a
//! sleepable LSM program, so a host whose kernel declares all four and refuses
//! a sleepable LSM load, or that runs without `bpf` among its security
//! modules, has them and can use none. This probe answers the three questions
//! separately and says which one failed:
//!
//! - **declared**: the kfunc is a `FUNC` in the kernel's own BTF;
//! - **sleepable**: a two-instruction sleepable LSM program loads, through the
//!   same token the agent's own LSM objects use;
//! - **attachable**: the BPF LSM is active, read from [`super::lsm_probe`].
//!
//! The load is the only syscall, and it runs once at startup. A refusal for
//! lack of privilege is reported as "not probed" with its reason, never as
//! "unsupported", because that would describe the deployment as a kernel.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::lsm_probe::{self, BpfLsmStatus, VMLINUX_BTF_PATH};

/// The kfuncs this probe answers for, in the order they are reported.
pub const FILE_KFUNCS: [&str; 4] = [
    "bpf_get_task_exe_file",
    "bpf_put_file",
    "bpf_path_d_path",
    "bpf_get_dentry_xattr",
];

/// The hook the sleepable load is attempted against. It is in the kernel's
/// list of LSM hooks a sleepable program may attach to, which is not every
/// hook: a non-sleepable one would refuse the load for a reason unrelated to
/// the question asked.
const SLEEPABLE_PROBE_HOOK: &str = "bpf_lsm_bprm_committed_creds";

/// Whether a sleepable LSM program loads on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SleepableStatus {
    /// `Some(true)` when the probe program loaded, `Some(false)` when the
    /// kernel refused it for a reason a privilege would not change, `None`
    /// when the probe could not run.
    pub loads: Option<bool>,
    /// Why it does not load, or why nothing was measured.
    pub reason: Option<String>,
}

/// What this host answered about one file kfunc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKfunc {
    pub name: &'static str,
    /// Whether the kernel's BTF declares it. `None` when the BTF could not be
    /// read, which proves nothing either way.
    pub declared: Option<bool>,
    /// Declared, a sleepable LSM program loads, and the BPF LSM is active.
    pub usable: bool,
    /// The first of the three conditions that failed, when it is not usable.
    pub reason: Option<String>,
}

/// The probe's whole answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileKfuncStatus {
    pub sleepable: SleepableStatus,
    pub kfuncs: Vec<FileKfunc>,
    /// The one thing an operator can change on this host to make them usable,
    /// when there is one.
    pub remedy: Option<String>,
}

/// Decide the answer from what was read and what the load returned.
///
/// `funcs` is the kernel's `FUNC` table or the reason it could not be read,
/// `lsm` the BPF LSM status, and `load` the sleepable load against a hook id.
/// Taking all three as arguments is what lets every outcome be tested without
/// a kernel.
fn evaluate(
    funcs: &Result<HashMap<String, u32>, String>,
    lsm: &BpfLsmStatus,
    load: &mut dyn FnMut(u32) -> Result<(), (i32, String)>,
) -> FileKfuncStatus {
    let sleepable = match funcs {
        Err(why) => SleepableStatus {
            loads: None,
            reason: Some(format!("the kernel BTF could not be read: {why}")),
        },
        Ok(table) => match table.get(SLEEPABLE_PROBE_HOOK) {
            None => SleepableStatus {
                loads: Some(false),
                reason: Some(
                    "this kernel names no BPF LSM hook, so it was built without CONFIG_BPF_LSM"
                        .to_string(),
                ),
            },
            Some(&hook) => judge_load(load(hook)),
        },
    };

    let kfuncs = FILE_KFUNCS
        .iter()
        .map(|&name| {
            let declared = funcs.as_ref().ok().map(|t| t.contains_key(name));
            let reason = match declared {
                None => sleepable.reason.clone(),
                Some(false) => Some("this kernel does not declare it".to_string()),
                Some(true) if sleepable.loads != Some(true) => sleepable.reason.clone(),
                Some(true) if !lsm.active => Some(format!(
                    "a sleepable LSM program loads but cannot attach: {}",
                    lsm.reason.as_deref().unwrap_or("the BPF LSM is not active")
                )),
                Some(true) => None,
            };
            FileKfunc {
                name,
                declared,
                usable: reason.is_none(),
                reason,
            }
        })
        .collect::<Vec<_>>();

    let remedy = if kfuncs.iter().all(|k| k.usable) {
        None
    } else if kfuncs.iter().any(|k| k.declared == Some(false)) {
        Some(
            "run a kernel that declares every file kfunc; the version alone does not \
             guarantee it, so read this report again on the new kernel"
                .to_string(),
        )
    } else if sleepable.loads == Some(true) {
        lsm.remedy.clone()
    } else {
        None
    };

    FileKfuncStatus {
        sleepable,
        kfuncs,
        remedy,
    }
}

fn judge_load(outcome: Result<(), (i32, String)>) -> SleepableStatus {
    match outcome {
        Ok(()) => SleepableStatus {
            loads: Some(true),
            reason: None,
        },
        Err((errno, _)) if errno == libc::EPERM || errno == libc::EACCES => SleepableStatus {
            loads: None,
            reason: Some(format!(
                "the probe could not load an LSM program ({}): it needs CAP_BPF and \
                 CAP_PERFMON, or a BPF token allowing LSM programs",
                std::io::Error::from_raw_os_error(errno)
            )),
        },
        Err((errno, log)) => {
            let first = log.lines().map(str::trim).find(|l| !l.is_empty());
            SleepableStatus {
                loads: Some(false),
                reason: Some(match first {
                    Some(line) => format!(
                        "the kernel refused a sleepable LSM program ({}): {line}",
                        std::io::Error::from_raw_os_error(errno)
                    ),
                    None => format!(
                        "the kernel refused a sleepable LSM program ({})",
                        std::io::Error::from_raw_os_error(errno)
                    ),
                }),
            }
        }
    }
}

/// Probe this host: read its BTF, attempt the load, read the BPF LSM status.
#[must_use]
pub fn run() -> FileKfuncStatus {
    let funcs = std::fs::read(VMLINUX_BTF_PATH)
        .map_err(|e| format!("{VMLINUX_BTF_PATH}: {e}"))
        .and_then(|data| super::kfunc::vmlinux_func_ids(data).map_err(|e| e.to_string()));
    evaluate(
        &funcs,
        lsm_probe::status(),
        &mut super::kfunc_loader::load_sleepable_lsm_stub,
    )
}

static CACHE: OnceLock<FileKfuncStatus> = OnceLock::new();

/// Run the probe once per process, at startup, and keep the answer.
pub fn init_cached() -> &'static FileKfuncStatus {
    CACHE.get_or_init(run)
}

/// The cached answer, or `None` when startup has not probed yet, so that
/// reading it from the operational endpoint never issues a load of its own.
#[must_use]
pub fn cached() -> Option<&'static FileKfuncStatus> {
    CACHE.get()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(names: &[&str]) -> HashMap<String, u32> {
        names
            .iter()
            .zip(1u32..)
            .map(|(n, id)| ((*n).to_string(), id))
            .collect()
    }

    fn full_table() -> HashMap<String, u32> {
        let mut names = FILE_KFUNCS.to_vec();
        names.push(SLEEPABLE_PROBE_HOOK);
        table(&names)
    }

    fn lsm(active: bool) -> BpfLsmStatus {
        BpfLsmStatus {
            active,
            built: Some(true),
            modules: if active {
                vec!["capability".into(), "bpf".into()]
            } else {
                vec!["capability".into(), "apparmor".into()]
            },
            reason: (!active).then(|| "bpf is not among the active security modules".into()),
            remedy: (!active).then(|| {
                "add bpf to the lsm= kernel boot parameter, keeping the modules already \
                 active, and reboot: lsm=apparmor,bpf"
                    .into()
            }),
        }
    }

    #[test]
    fn every_kfunc_is_usable_where_all_three_answers_are_yes() {
        let t = full_table();
        let mut hook_seen = None;
        let status = evaluate(&Ok(t.clone()), &lsm(true), &mut |id| {
            hook_seen = Some(id);
            Ok(())
        });
        assert_eq!(hook_seen, t.get(SLEEPABLE_PROBE_HOOK).copied());
        assert_eq!(status.sleepable.loads, Some(true));
        assert!(status.kfuncs.iter().all(|k| k.usable && k.reason.is_none()));
        assert_eq!(
            status.kfuncs.iter().map(|k| k.name).collect::<Vec<_>>(),
            FILE_KFUNCS
        );
        assert_eq!(status.remedy, None);
    }

    #[test]
    fn a_kfunc_the_kernel_does_not_declare_is_named_alone() {
        let t = table(&[
            "bpf_get_task_exe_file",
            "bpf_put_file",
            "bpf_path_d_path",
            SLEEPABLE_PROBE_HOOK,
        ]);
        let status = evaluate(&Ok(t.clone()), &lsm(true), &mut |_| Ok(()));
        let xattr = &status.kfuncs[3];
        assert_eq!(xattr.name, "bpf_get_dentry_xattr");
        assert_eq!(xattr.declared, Some(false));
        assert!(!xattr.usable);
        assert_eq!(
            xattr.reason.as_deref(),
            Some("this kernel does not declare it")
        );
        assert!(status.kfuncs[..3].iter().all(|k| k.usable));
        assert!(
            status
                .remedy
                .expect("remedy")
                .contains("read this report again")
        );
    }

    #[test]
    fn declared_but_without_the_bpf_lsm_says_which_boot_parameter_to_set() {
        let t = full_table();
        let status = evaluate(&Ok(t.clone()), &lsm(false), &mut |_| Ok(()));
        assert_eq!(status.sleepable.loads, Some(true));
        for k in &status.kfuncs {
            assert_eq!(k.declared, Some(true));
            assert!(!k.usable);
            assert!(
                k.reason
                    .as_deref()
                    .expect("reason")
                    .contains("loads but cannot attach"),
            );
        }
        assert!(status.remedy.expect("remedy").contains("lsm="));
    }

    #[test]
    fn a_refused_privilege_is_not_probed_never_unsupported() {
        let t = full_table();
        let status = evaluate(&Ok(t.clone()), &lsm(true), &mut |_| {
            Err((libc::EPERM, String::new()))
        });
        assert_eq!(status.sleepable.loads, None);
        let reason = status.sleepable.reason.clone().expect("reason");
        assert!(reason.contains("CAP_BPF"), "{reason}");
        for k in &status.kfuncs {
            assert_eq!(k.declared, Some(true));
            assert!(!k.usable);
            assert_eq!(k.reason.as_deref(), Some(reason.as_str()));
        }
        // Nothing an operator could change on the host was measured.
        assert_eq!(status.remedy, None);
    }

    #[test]
    fn a_kernel_refusal_quotes_the_verifier() {
        let t = full_table();
        let status = evaluate(&Ok(t.clone()), &lsm(true), &mut |_| {
            Err((
                libc::EINVAL,
                "\n  attach to unsupported member of sleepable hook\nprocessed 0 insns".into(),
            ))
        });
        assert_eq!(status.sleepable.loads, Some(false));
        let reason = status.sleepable.reason.expect("reason");
        assert!(
            reason.ends_with(": attach to unsupported member of sleepable hook"),
            "{reason}"
        );
    }

    #[test]
    fn a_kernel_without_the_lsm_hooks_loads_nothing_and_tries_nothing() {
        let t = table(&FILE_KFUNCS);
        let mut called = false;
        let status = evaluate(&Ok(t.clone()), &lsm(false), &mut |_| {
            called = true;
            Ok(())
        });
        assert!(!called);
        assert_eq!(status.sleepable.loads, Some(false));
        assert!(
            status
                .sleepable
                .reason
                .expect("reason")
                .contains("CONFIG_BPF_LSM")
        );
    }

    #[test]
    fn an_unreadable_btf_proves_nothing_either_way() {
        let status = evaluate(
            &Err("/sys/kernel/btf/vmlinux: No such file or directory".into()),
            &lsm(true),
            &mut |_| Ok(()),
        );
        assert_eq!(status.sleepable.loads, None);
        assert!(
            status
                .kfuncs
                .iter()
                .all(|k| k.declared.is_none() && !k.usable)
        );
        assert_eq!(status.remedy, None);
    }
}
