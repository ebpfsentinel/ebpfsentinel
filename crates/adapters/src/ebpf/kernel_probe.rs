//! Runtime kernel feature probe.
//!
//! The agent requires Linux 6.12 or later. 6.9 brought what every program
//! needs to load at all - BPF token delegation, `BPF_MAP_TYPE_ARENA` and the
//! kfuncs added from 6.7 (`bpf_task_get_cgroup1`,
//! `bpf_xdp_metadata_rx_vlan_tag`, `bpf_xdp_get_xfrm_state`,
//! `bpf_iter_css_task`) - and 6.12 is the long-term kernel the distributions
//! and managed node images converged on, which is what makes it the floor
//! rather than the oldest kernel that would load. A kfunc newer than 6.9 is
//! never assumed from the version: the floor says it exists, a probe says
//! whether it loads.
//!
//! This module parses `/proc/sys/kernel/osrelease` and exposes a
//! [`KernelFeatures`] snapshot the bootstrap code consults before loading
//! programs. Below the floor it refuses, and the refusal names the way up for
//! the distribution the release string belongs to, because a floor that does
//! not say what to install is a support ticket.
//!
//! The probe is intentionally lightweight: no libbpf, no syscalls, just
//! one file read + version comparison + BTF file presence checks.

use std::fs;
use std::path::Path;

/// Minimum kernel version required by the agent.
pub const MIN_KERNEL_MAJOR: u32 = 6;
pub const MIN_KERNEL_MINOR: u32 = 12;

/// Snapshot of kernel capabilities relevant to the eBPF loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct KernelFeatures {
    pub major: u32,
    pub minor: u32,
    pub btf_available: bool,
    /// `BPF_TOKEN_CREATE` + `BPF_F_TOKEN_FD` - kernel 6.9.
    pub bpf_token: bool,
    /// `BPF_MAP_TYPE_ARENA` - kernel 6.9.
    pub arena_map: bool,
    /// `bpf_task_get_cgroup1` kfunc - kernel 6.8.
    pub cgroup1_kfunc: bool,
    /// `bpf_xdp_metadata_rx_vlan_tag` kfunc - kernel 6.8.
    pub xdp_vlan_metadata: bool,
    /// `bpf_xdp_get_xfrm_state` kfunc - kernel 6.8.
    pub xdp_xfrm_state: bool,
    /// `bpf_iter_css_task` kfunc - kernel 6.7.
    pub css_task_iter: bool,
}

impl KernelFeatures {
    /// Returns `true` when the live kernel satisfies the project-wide
    /// 6.12 minimum.
    #[must_use]
    pub const fn meets_minimum(&self) -> bool {
        self.major > MIN_KERNEL_MAJOR
            || (self.major == MIN_KERNEL_MAJOR && self.minor >= MIN_KERNEL_MINOR)
    }

    /// Short human-readable version string `"major.minor"`.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

/// Error type emitted when the kernel fails the minimum-version check.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KernelProbeError {
    #[error("failed to read /proc/sys/kernel/osrelease: {0}")]
    ReadOsRelease(String),

    #[error("malformed kernel version string `{0}`")]
    ParseVersion(String),

    #[error("kernel {found} is below the required minimum {required}. {upgrade}")]
    BelowMinimum {
        found: String,
        required: String,
        /// What to install, for the distribution the release string names.
        upgrade: &'static str,
    },
}

/// The way up to the floor, read off the kernel release string.
///
/// The release string is the only thing an agent in a container can trust
/// about the host: `/etc/os-release` inside the image describes the image,
/// and a distroless base calls itself Debian on every host it runs on. The
/// markers below are the ones each family's kernel packages append.
#[must_use]
pub fn upgrade_path(release: &str) -> &'static str {
    let r = release.to_ascii_lowercase();
    if r.contains("azure") || r.contains(".azl") || r.contains(".cm2") {
        "This is an Azure kernel: no current AKS node image carries 6.12, and a standard node \
         pool cannot change its kernel, so the agent is not supported on AKS until its node \
         images reach 6.12. On a self-managed Azure VM, install a 6.12 or later kernel."
    } else if r.contains("amzn2023") || r.contains("amzn2") {
        "On Amazon Linux 2023 install the 6.12 kernel stream (`dnf install kernel6.12`) and \
         reboot; on EKS use the AL2023 node image for Kubernetes 1.33 or later, or a custom AMI \
         built from awslabs/amazon-eks-ami. Amazon Linux 2 has no 6.12 kernel."
    } else if r.contains("-talos") {
        "Upgrade the node to Talos 1.9 or later (`talosctl upgrade`), which ships 6.12."
    } else if r.contains("uek") {
        "Install the Oracle Unbreakable Enterprise Kernel 8, which is 6.12, and reboot."
    } else if r.contains(".el") {
        "RHEL, Rocky and AlmaLinux 10 ship 6.12; version 9 and earlier have no 6.12 kernel, so \
         upgrade the host to 10 (`leapp`) or reinstall it."
    } else if r.contains(".fc") {
        "Upgrade the kernel (`dnf upgrade --refresh kernel`) or the release, and reboot."
    } else if r.contains("deb1") || r.contains("+deb") || r.contains("-cloud-") {
        "Debian 13 ships 6.12; on Debian 12 install a newer kernel from bookworm-backports \
         (`apt install -t bookworm-backports linux-image-amd64`) and reboot."
    } else if r.contains("-generic")
        || r.contains("-aws")
        || r.contains("-gcp")
        || r.contains("-gke")
        || r.contains("-oracle")
        || r.contains("-lowlatency")
    {
        "On Ubuntu 24.04 install the hardware enablement kernel \
         (`apt install linux-generic-hwe-24.04`) and reboot; Ubuntu 22.04 and earlier have no \
         6.12 kernel, so upgrade the release."
    } else if r.contains("-default") {
        "SLES 16 and openSUSE Leap 16 ship 6.12; upgrade the host to one of them."
    } else if r.ends_with('+') && !r.contains('-') {
        "This looks like a GKE Container-Optimized OS kernel: there is no package manager, so \
         upgrade the cluster to a version whose node image is COS milestone 125 or later."
    } else {
        "Install a 6.12 or later kernel from your distribution and reboot; the compatibility \
         matrix in the documentation lists the releases that carry one."
    }
}

/// Probe the kernel using the default `/proc` + `/sys` paths.
///
/// # Errors
/// Returns [`KernelProbeError::ReadOsRelease`] or
/// [`KernelProbeError::ParseVersion`] on IO / parse failures and
/// [`KernelProbeError::BelowMinimum`] when the live kernel is below 6.12.
pub fn probe() -> Result<KernelFeatures, KernelProbeError> {
    probe_from(
        Path::new("/proc/sys/kernel/osrelease"),
        Path::new("/sys/kernel/btf/vmlinux"),
    )
}

/// Probe from explicit `osrelease` + BTF paths. Exposed so callers
/// (e.g. the agent's startup gate) and tests can inject synthetic
/// `/proc` + `/sys` paths instead of the live defaults [`probe`] uses.
///
/// # Errors
/// Same as [`probe`]: IO/parse failures and
/// [`KernelProbeError::BelowMinimum`] when the kernel is below 6.12.
pub fn probe_from(
    osrelease_path: &Path,
    btf_path: &Path,
) -> Result<KernelFeatures, KernelProbeError> {
    let contents = fs::read_to_string(osrelease_path)
        .map_err(|e| KernelProbeError::ReadOsRelease(e.to_string()))?;
    let release = contents.trim();
    let (major, minor) = parse_version(release)?;

    let btf_available = btf_path.exists();
    let features = derive_features(major, minor, btf_available);

    if !features.meets_minimum() {
        return Err(KernelProbeError::BelowMinimum {
            found: features.version_string(),
            required: format!("{MIN_KERNEL_MAJOR}.{MIN_KERNEL_MINOR}"),
            upgrade: upgrade_path(release),
        });
    }

    Ok(features)
}

fn parse_version(raw: &str) -> Result<(u32, u32), KernelProbeError> {
    // /proc/sys/kernel/osrelease looks like "6.9.1-060900-generic".
    let head = raw
        .split(|c: char| !c.is_ascii_digit() && c != '.')
        .next()
        .unwrap_or("");
    let mut parts = head.split('.');
    let major = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| KernelProbeError::ParseVersion(raw.to_string()))?;
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .ok_or_else(|| KernelProbeError::ParseVersion(raw.to_string()))?;
    Ok((major, minor))
}

fn derive_features(major: u32, minor: u32, btf_available: bool) -> KernelFeatures {
    let ge = |maj: u32, min: u32| major > maj || (major == maj && minor >= min);
    KernelFeatures {
        major,
        minor,
        btf_available,
        bpf_token: ge(6, 9),
        arena_map: ge(6, 9),
        cgroup1_kfunc: ge(6, 8),
        xdp_vlan_metadata: ge(6, 8),
        xdp_xfrm_state: ge(6, 8),
        css_task_iter: ge(6, 7),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_release_string() {
        assert_eq!(parse_version("6.9.1-060900-generic").unwrap(), (6, 9));
    }

    #[test]
    fn parses_dash_prefix() {
        assert_eq!(parse_version("6.10.0-rc5+").unwrap(), (6, 10));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_version("abc").is_err());
    }

    #[test]
    fn derive_612_enables_all() {
        let f = derive_features(6, 12, true);
        assert!(f.bpf_token);
        assert!(f.arena_map);
        assert!(f.cgroup1_kfunc);
        assert!(f.xdp_vlan_metadata);
        assert!(f.xdp_xfrm_state);
        assert!(f.css_task_iter);
        assert!(f.meets_minimum());
    }

    #[test]
    fn derive_69_has_every_feature_and_misses_the_floor() {
        let f = derive_features(6, 9, true);
        assert!(f.bpf_token);
        assert!(f.arena_map);
        assert!(!f.meets_minimum());
    }

    #[test]
    fn derive_68_lacks_token_and_arena() {
        let f = derive_features(6, 8, true);
        assert!(!f.bpf_token);
        assert!(!f.arena_map);
        assert!(f.cgroup1_kfunc);
        assert!(!f.meets_minimum());
    }

    #[test]
    fn derive_67_only_css_iter() {
        let f = derive_features(6, 7, true);
        assert!(!f.cgroup1_kfunc);
        assert!(!f.bpf_token);
        assert!(f.css_task_iter);
        assert!(!f.meets_minimum());
    }

    #[test]
    fn meets_minimum_boundary() {
        assert!(derive_features(6, 12, true).meets_minimum());
        assert!(!derive_features(6, 11, true).meets_minimum());
        assert!(!derive_features(6, 9, true).meets_minimum());
        assert!(derive_features(6, 17, true).meets_minimum());
        assert!(derive_features(7, 0, true).meets_minimum());
    }

    #[test]
    fn probe_from_accepts_612_osrelease() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.12.0-test\n").unwrap();
        let btf = tmp.path().join("vmlinux");
        std::fs::write(&btf, "stub").unwrap();
        let f = probe_from(&osrel, &btf).unwrap();
        assert!(f.bpf_token);
        assert!(f.btf_available);
    }

    #[test]
    fn probe_from_rejects_611_and_names_the_way_up() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.11.0-29-generic\n").unwrap();
        let err = probe_from(&osrel, Path::new("/nonexistent")).unwrap_err();
        let KernelProbeError::BelowMinimum {
            found,
            required,
            upgrade,
        } = &err
        else {
            panic!("expected BelowMinimum, got {err:?}");
        };
        assert_eq!(found, "6.11");
        assert_eq!(required, "6.12");
        assert!(upgrade.contains("linux-generic-hwe-24.04"));
        let message = err.to_string();
        assert!(message.contains("6.11"));
        assert!(message.contains("6.12"));
        assert!(message.contains("linux-generic-hwe-24.04"));
    }

    /// Each family's release string, as its kernel packages write it, maps to
    /// that family's way up, and none falls through to the generic answer.
    #[test]
    fn every_family_has_its_own_upgrade_path() {
        let cases = [
            ("6.8.0-1041-azure", "AKS"),
            ("6.6.64.2-9.azl3", "AKS"),
            ("6.1.102-111.182.amzn2023.x86_64", "kernel6.12"),
            (
                "5.10.225-213.878.amzn2.x86_64",
                "Amazon Linux 2 has no 6.12",
            ),
            ("6.6.43-talos", "Talos 1.9"),
            (
                "5.15.0-209.161.7.2.el9uek.x86_64",
                "Unbreakable Enterprise Kernel 8",
            ),
            ("5.14.0-503.11.1.el9_5.x86_64", "leapp"),
            ("6.11.4-301.fc41.x86_64", "dnf upgrade"),
            (
                "6.1.0-26-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.112-1+deb12u1",
                "bookworm-backports",
            ),
            ("6.1.0-26-cloud-amd64", "bookworm-backports"),
            ("6.8.0-48-generic", "linux-generic-hwe-24.04"),
            ("6.8.0-1017-aws", "linux-generic-hwe-24.04"),
            ("6.8.0-1015-gcp", "linux-generic-hwe-24.04"),
            ("6.4.0-150600.23.25-default", "SLES 16"),
            ("6.6.56+", "COS milestone 125"),
        ];
        let generic = upgrade_path("6.1.0-unknown-vendor");
        assert!(generic.contains("compatibility matrix"));
        for (release, expected) in cases {
            let path = upgrade_path(release);
            assert!(
                path.contains(expected),
                "{release}: expected `{expected}` in `{path}`"
            );
            assert_ne!(
                path, generic,
                "{release} fell through to the generic answer"
            );
        }
    }

    /// A kfunc newer than the 6.9 set is never inferred from the version:
    /// the snapshot carries no field that the floor alone would switch on.
    #[test]
    fn the_floor_switches_on_nothing_beyond_the_69_set() {
        let at_floor = derive_features(6, 12, true);
        let at_69 = derive_features(6, 9, true);
        assert_eq!(
            KernelFeatures {
                major: 6,
                minor: 9,
                ..at_floor
            },
            at_69
        );
    }

    #[test]
    fn probe_from_reports_missing_btf() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.12.0\n").unwrap();
        let f = probe_from(&osrel, Path::new("/nonexistent-btf")).unwrap();
        assert!(!f.btf_available);
    }
}
