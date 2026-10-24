//! Whether this host runs the BPF LSM.
//!
//! A program attached at an LSM hook loads only where the kernel was built
//! with `CONFIG_BPF_LSM` **and** booted with `bpf` among its active security
//! modules. The second half is a boot parameter that distributions and host
//! providers set differently, so the kernel version says nothing about it and
//! the only honest answer is the one this host gives.
//!
//! Two files answer it and neither needs a capability: securityfs lists the
//! active modules in boot order, and the kernel's own BTF names the BPF LSM
//! hooks only when they were compiled in. Reading them is the whole probe, so
//! the same answer is available from a running agent and from a binary run by
//! hand on a host where nothing is installed yet.

use std::fs;
use std::path::Path;
use std::sync::OnceLock;

/// Where securityfs lists the active security modules.
pub const LSM_LIST_PATH: &str = "/sys/kernel/security/lsm";

/// Where the kernel publishes its own BTF.
pub const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// A BPF LSM hook the kernel names in its BTF only when `CONFIG_BPF_LSM` is
/// built in. The NUL on each side keeps a longer name from matching.
const BPF_LSM_HOOK_SYMBOL: &[u8] = b"\0bpf_lsm_socket_connect\0";

/// The module the kernel always runs first and that `lsm=` does not take.
const IMPLIED_MODULE: &str = "capability";

/// What this host answered about the BPF LSM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpfLsmStatus {
    /// `bpf` is among the active security modules, so an LSM program can
    /// attach here.
    pub active: bool,
    /// Whether the kernel was built with the BPF LSM, read from its BTF.
    /// `None` when the BTF could not be read, which proves nothing either way.
    pub built: Option<bool>,
    /// The active security modules, in the order the kernel runs them. Empty
    /// when the list could not be read.
    pub modules: Vec<String>,
    /// Why an LSM program cannot attach here, in one sentence.
    pub reason: Option<String>,
    /// What would make it attach, in one sentence.
    pub remedy: Option<String>,
}

/// Probe the live host once and keep the answer.
///
/// The set of active modules is fixed at boot, so a second reading could only
/// ever repeat the first.
#[must_use]
pub fn status() -> &'static BpfLsmStatus {
    static STATUS: OnceLock<BpfLsmStatus> = OnceLock::new();
    STATUS.get_or_init(|| status_from(Path::new(LSM_LIST_PATH), Path::new(VMLINUX_BTF_PATH)))
}

/// Probe from explicit paths, so tests and callers can point at a synthetic
/// securityfs and BTF.
#[must_use]
pub fn status_from(lsm_path: &Path, btf_path: &Path) -> BpfLsmStatus {
    let built = fs::read(btf_path).ok().map(|btf| names_bpf_lsm_hook(&btf));
    match fs::read_to_string(lsm_path) {
        Ok(list) => judge(parse_modules(&list), built),
        Err(e) => BpfLsmStatus {
            active: false,
            built,
            modules: Vec::new(),
            reason: Some(format!(
                "the active security modules are unreadable at {}: {e}",
                lsm_path.display()
            )),
            remedy: Some(
                "mount securityfs at /sys/kernel/security, or run this check on the host itself"
                    .to_string(),
            ),
        },
    }
}

/// Split the comma-separated list securityfs publishes.
fn parse_modules(list: &str) -> Vec<String> {
    list.trim()
        .split(',')
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_string)
        .collect()
}

fn names_bpf_lsm_hook(btf: &[u8]) -> bool {
    btf.windows(BPF_LSM_HOOK_SYMBOL.len())
        .any(|w| w == BPF_LSM_HOOK_SYMBOL)
}

fn judge(modules: Vec<String>, built: Option<bool>) -> BpfLsmStatus {
    if modules.iter().any(|m| m == "bpf") {
        return BpfLsmStatus {
            active: true,
            built,
            modules,
            reason: None,
            remedy: None,
        };
    }
    if built == Some(false) {
        return BpfLsmStatus {
            active: false,
            built,
            modules,
            reason: Some("this kernel was built without CONFIG_BPF_LSM".to_string()),
            remedy: Some(
                "run a kernel built with CONFIG_BPF_LSM=y: no boot parameter can add it"
                    .to_string(),
            ),
        };
    }
    let mut wanted: Vec<&str> = modules
        .iter()
        .map(String::as_str)
        .filter(|m| *m != IMPLIED_MODULE)
        .collect();
    wanted.push("bpf");
    BpfLsmStatus {
        active: false,
        built,
        reason: Some("bpf is not among the active security modules".to_string()),
        remedy: Some(format!(
            "add bpf to the lsm= kernel boot parameter, keeping the modules already active, and \
             reboot: lsm={}",
            wanted.join(",")
        )),
        modules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn btf_with(symbol: &[u8]) -> Vec<u8> {
        let mut btf = b"\x9f\xeb\x01\0header".to_vec();
        btf.extend_from_slice(symbol);
        btf.extend_from_slice(b"tail\0");
        btf
    }

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write fixture");
        path
    }

    #[test]
    fn an_active_bpf_module_is_active_whatever_else_runs() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lsm = write(
            tmp.path(),
            "lsm",
            b"lockdown,capability,landlock,yama,bpf\n",
        );
        let btf = write(tmp.path(), "btf", &btf_with(BPF_LSM_HOOK_SYMBOL));
        let status = status_from(&lsm, &btf);
        assert!(status.active);
        assert_eq!(status.built, Some(true));
        assert_eq!(status.reason, None);
        assert_eq!(status.remedy, None);
        assert_eq!(status.modules.last().map(String::as_str), Some("bpf"));
    }

    #[test]
    fn a_built_but_inactive_module_names_the_boot_parameter_to_set() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lsm = write(
            tmp.path(),
            "lsm",
            b"lockdown,capability,landlock,yama,apparmor,ima,evm\n",
        );
        let btf = write(tmp.path(), "btf", &btf_with(BPF_LSM_HOOK_SYMBOL));
        let status = status_from(&lsm, &btf);
        assert!(!status.active);
        assert_eq!(status.built, Some(true));
        assert_eq!(
            status.reason.as_deref(),
            Some("bpf is not among the active security modules")
        );
        let remedy = status.remedy.expect("remedy");
        assert!(
            remedy.ends_with("lsm=lockdown,landlock,yama,apparmor,ima,evm,bpf"),
            "{remedy}"
        );
    }

    #[test]
    fn a_kernel_built_without_it_offers_no_boot_parameter() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lsm = write(tmp.path(), "lsm", b"capability,apparmor\n");
        let btf = write(
            tmp.path(),
            "btf",
            &btf_with(b"\0bpf_lsm_socket_connect_extra\0"),
        );
        let status = status_from(&lsm, &btf);
        assert!(!status.active);
        assert_eq!(status.built, Some(false));
        assert!(status.remedy.expect("remedy").contains("CONFIG_BPF_LSM=y"));
        assert!(
            status
                .reason
                .expect("reason")
                .contains("without CONFIG_BPF_LSM")
        );
    }

    #[test]
    fn an_unreadable_btf_proves_nothing_about_the_build() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lsm = write(tmp.path(), "lsm", b"capability,yama\n");
        let status = status_from(&lsm, &tmp.path().join("absent"));
        assert_eq!(status.built, None);
        assert!(status.remedy.expect("remedy").ends_with("lsm=yama,bpf"));
    }

    #[test]
    fn an_unreadable_module_list_says_where_it_looked_rather_than_inactive() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let status = status_from(&tmp.path().join("lsm"), &tmp.path().join("btf"));
        assert!(!status.active);
        assert!(status.modules.is_empty());
        assert!(status.reason.expect("reason").contains("unreadable at"));
        assert!(status.remedy.expect("remedy").contains("securityfs"));
    }

    #[test]
    fn the_list_tolerates_spaces_and_a_trailing_comma() {
        assert_eq!(parse_modules(" yama , bpf,\n"), vec!["yama", "bpf"]);
    }
}
