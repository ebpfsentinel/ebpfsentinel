//! Runtime kernel feature probe.
//!
//! The agent requires Linux 6.18 or later. 6.18 is the first release that
//! verifies the signature of a BPF program, and with `bpf` in `lsm=` an
//! unsigned load can be refused, which is what keeps an agent holding
//! `CAP_PERFMON` from loading a program of its own. It is also the long-term
//! release of 2025, the one the distributions of the last two years and the
//! managed node images reach, which is what makes it the floor rather than
//! the oldest kernel that would load. A kfunc is never assumed from the
//! version: the floor says it exists, a probe says whether it loads.
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

use super::capabilities::KernelVersion;

/// Minimum kernel version required by the agent.
pub const MIN_KERNEL_MAJOR: u32 = 6;
pub const MIN_KERNEL_MINOR: u32 = 18;

/// The running kernel's version, as the floor check reads it.
///
/// A capability is never derived from this number: the floor guarantees a
/// helper or kfunc exists, not that it loads, so each one is probed on its own
/// (`helper_probe`, `KfuncSupport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelFeatures {
    pub major: u32,
    pub minor: u32,
}

impl KernelFeatures {
    /// Returns `true` when the live kernel satisfies the project-wide
    /// 6.18 minimum.
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
        upgrade: String,
    },
}

/// What to install to reach `target`, read off the kernel release string.
///
/// One function answers both questions an operator asks: how to reach the
/// floor the agent refuses below, and how to switch on a capability above it.
/// A host below the floor asked for the floor gets the way to the floor and
/// nothing about extras, because on Ubuntu 24.04 the hardware enablement
/// kernel is what reaches the base. Every other question gets the way to a
/// newer kernel build than the one running.
///
/// The release string is the only thing an agent in a container can trust
/// about the host: `/etc/os-release` inside the image describes the image,
/// and a distroless base calls itself Debian on every host it runs on. The
/// markers are the ones each family's kernel packages append.
///
/// Every kernel version written in either table was checked against the
/// distribution's own release notes or package index on 2026-11-01. Where no
/// version could be confirmed the hint says "a newer kernel" and names the
/// command that lists what the distribution carries, rather than a number.
#[must_use]
pub fn upgrade_hint(release: &str, target: KernelVersion) -> String {
    let running = KernelVersion::parse(release);
    let below_floor = running.is_none_or(|r| r < KernelVersion::FLOOR);
    if target <= KernelVersion::FLOOR && below_floor {
        return to_the_floor(release).to_string();
    }
    let lead = match running {
        Some(r) if r < target => format!("This needs {target} and the host runs {r}: "),
        _ => "This kernel was built without it: ".to_string(),
    };
    format!("{lead}{}", above_the_floor(release))
}

/// The distribution family a release string names, for a log line or a
/// report. "unknown" where no marker matched.
#[must_use]
pub fn distribution_family(release: &str) -> &'static str {
    match family(release) {
        Family::Azure => "azure",
        Family::AmazonLinux2023 => "amazon_linux_2023",
        Family::AmazonLinux2 => "amazon_linux_2",
        Family::Talos => "talos",
        Family::OracleUek => "oracle_uek",
        Family::EnterpriseLinux => "enterprise_linux",
        Family::Fedora => "fedora",
        Family::Debian => "debian",
        Family::Ubuntu => "ubuntu",
        Family::Suse => "suse",
        Family::ContainerOptimizedOs => "container_optimized_os",
        Family::Unknown => "unknown",
    }
}

/// The family a release string names, by the markers its packages append.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Azure,
    AmazonLinux2023,
    AmazonLinux2,
    Talos,
    OracleUek,
    EnterpriseLinux,
    Fedora,
    Debian,
    Ubuntu,
    Suse,
    ContainerOptimizedOs,
    Unknown,
}

fn family(release: &str) -> Family {
    let r = release.to_ascii_lowercase();
    if r.contains("azure") || r.contains(".azl") || r.contains(".cm2") {
        Family::Azure
    } else if r.contains("amzn2023") {
        Family::AmazonLinux2023
    } else if r.contains("amzn2") {
        Family::AmazonLinux2
    } else if r.contains("-talos") {
        Family::Talos
    } else if r.contains("uek") {
        Family::OracleUek
    } else if r.contains(".el") {
        Family::EnterpriseLinux
    } else if r.contains(".fc") {
        Family::Fedora
    } else if r.contains("deb1") || r.contains("+deb") || r.contains("-cloud-") {
        Family::Debian
    } else if r.contains("-generic")
        || r.contains("-aws")
        || r.contains("-gcp")
        || r.contains("-gke")
        || r.contains("-oracle")
        || r.contains("-lowlatency")
    {
        Family::Ubuntu
    } else if r.contains("-default") {
        Family::Suse
    } else if r.ends_with('+') && !r.contains('-') {
        Family::ContainerOptimizedOs
    } else {
        Family::Unknown
    }
}

/// The way past the running kernel on a host already above the floor. No
/// version is written here: none beyond the floor's could be confirmed for
/// every family, so each answer names what to install and how to list it.
fn above_the_floor(release: &str) -> &'static str {
    match family(release) {
        Family::Azure => {
            "an AKS node pool changes its kernel only with its node image, so move it to a \
             newer node image; on a self-managed Ubuntu VM `linux-azure` tracks the newest \
             kernel the release supports (`apt install linux-azure`)."
        }
        Family::AmazonLinux2023 | Family::AmazonLinux2 => {
            "install a newer kernel stream when Amazon Linux publishes one (`dnf list \
             --available 'kernel*'` lists them) and reboot; on EKS that is a newer AL2023 \
             node image."
        }
        Family::Talos => "upgrade the node to a newer Talos release (`talosctl upgrade`).",
        Family::OracleUek => {
            "install a newer Unbreakable Enterprise Kernel when Oracle publishes one, and reboot."
        }
        Family::EnterpriseLinux => {
            "RHEL, Rocky and AlmaLinux keep one kernel version for the life of a release, so \
             there is no newer kernel in this release; Red Hat backports features into it, \
             which is why the agent asks the kernel rather than reading its number."
        }
        Family::Fedora => {
            "upgrade the kernel (`dnf upgrade --refresh kernel`) or the release, and reboot."
        }
        Family::Debian => {
            "install a newer kernel from the release's backports when it carries one (`apt \
             list -a linux-image-amd64` lists them) and reboot."
        }
        Family::Ubuntu => {
            "on an Ubuntu LTS the hardware enablement kernel is the newest the release carries \
             (`apt install linux-generic-hwe-24.04` on 24.04), and a newer one arrives with \
             the release's next enablement stack; otherwise upgrade the release."
        }
        Family::Suse => {
            "SLES and openSUSE Leap keep one kernel version per service pack, so a newer one \
             comes with the next service pack or minor release."
        }
        Family::ContainerOptimizedOs => {
            "upgrade the cluster to a version whose node image carries a newer COS milestone."
        }
        Family::Unknown => "install a newer kernel from your distribution and reboot.",
    }
}

/// The way up to the floor.
fn to_the_floor(release: &str) -> &'static str {
    match family(release) {
        Family::Azure => {
            "This is an Azure kernel: an AKS node pool changes its kernel only with its node image, \
         so move it to the Ubuntu 26.04 node image, which carries 7.0; the Ubuntu 24.04 and \
         Azure Linux 3.0 node images are below 6.18. On a self-managed Ubuntu 24.04 VM, \
         `linux-azure` tracks 7.0 (`apt install linux-azure`); elsewhere install a 6.18 or later \
         kernel."
        }
        Family::AmazonLinux2023 | Family::AmazonLinux2 => {
            "On Amazon Linux 2023 install the 6.18 kernel stream (`dnf install kernel6.18`) and \
         reboot; on EKS use the AL2023 node image on kernel 6.18 or a Bottlerocket variant for \
         Kubernetes 1.36 or later outside FIPS. Amazon Linux 2 has no 6.18 kernel."
        }
        Family::Talos => {
            "Upgrade the node to Talos 1.12 or later (`talosctl upgrade`), which ships 6.18."
        }
        Family::OracleUek => {
            "No Unbreakable Enterprise Kernel reaches 6.18 (UEK 8 is 6.12), so the host needs a \
         distribution that ships 6.18; the compatibility matrix in the documentation lists them."
        }
        Family::EnterpriseLinux => {
            "RHEL, Rocky and AlmaLinux keep 6.12 for the life of release 10 and 5.14 for release 9, \
         so no release of theirs reaches 6.18; the host needs a distribution that ships 6.18, \
         listed in the compatibility matrix of the documentation."
        }
        Family::Fedora => {
            "Upgrade the kernel (`dnf upgrade --refresh kernel`) or the release, and reboot."
        }
        Family::Debian => {
            "On Debian 13 install the trixie-backports kernel \
         (`apt install -t trixie-backports linux-image-amd64`, 6.18 or later) and reboot; Debian 12 \
         and earlier have no 6.18 kernel, so upgrade the release to 13 first."
        }
        Family::Ubuntu => {
            "On Ubuntu 24.04 install the hardware enablement kernel \
         (`apt install linux-generic-hwe-24.04`, 7.0 since 24.04.5) and reboot; Ubuntu 22.04 and \
         earlier have no 6.18 kernel, so upgrade the release to 24.04 or 26.04."
        }
        Family::Suse => {
            "SLES 16 and openSUSE Leap 16 stay on 6.12, so no SLES or Leap release reaches 6.18; \
         openSUSE Tumbleweed does."
        }
        Family::ContainerOptimizedOs => {
            "This looks like a GKE Container-Optimized OS kernel: there is no package manager, so \
         upgrade the cluster to a version whose node image is COS milestone 133 or later."
        }
        Family::Unknown => {
            "Install a 6.18 or later kernel from your distribution and reboot; the compatibility \
         matrix in the documentation lists the releases that carry one."
        }
    }
}

/// Probe the kernel using the default `/proc` + `/sys` paths.
///
/// # Errors
/// Returns [`KernelProbeError::ReadOsRelease`] or
/// [`KernelProbeError::ParseVersion`] on IO / parse failures and
/// [`KernelProbeError::BelowMinimum`] when the live kernel is below 6.18.
pub fn probe() -> Result<KernelFeatures, KernelProbeError> {
    probe_from(Path::new("/proc/sys/kernel/osrelease"))
}

/// Probe from an explicit `osrelease` path. Exposed so callers
/// (e.g. the agent's startup gate) and tests can inject synthetic
/// `/proc` path instead of the live defaults [`probe`] uses.
///
/// # Errors
/// Same as [`probe`]: IO/parse failures and
/// [`KernelProbeError::BelowMinimum`] when the kernel is below 6.18.
pub fn probe_from(osrelease_path: &Path) -> Result<KernelFeatures, KernelProbeError> {
    let contents = fs::read_to_string(osrelease_path)
        .map_err(|e| KernelProbeError::ReadOsRelease(e.to_string()))?;
    let release = contents.trim();
    let (major, minor) = parse_version(release)?;

    let features = KernelFeatures { major, minor };

    if !features.meets_minimum() {
        return Err(KernelProbeError::BelowMinimum {
            found: features.version_string(),
            required: format!("{MIN_KERNEL_MAJOR}.{MIN_KERNEL_MINOR}"),
            upgrade: upgrade_hint(release, KernelVersion::FLOOR),
        });
    }

    Ok(features)
}

pub(crate) fn parse_version(raw: &str) -> Result<(u32, u32), KernelProbeError> {
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
    fn meets_minimum_boundary() {
        let at = |major, minor| KernelFeatures { major, minor }.meets_minimum();
        assert!(at(6, 18));
        assert!(!at(6, 17));
        assert!(!at(6, 12));
        assert!(at(6, 19));
        assert!(at(7, 0));
    }

    #[test]
    fn probe_from_accepts_618_osrelease() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.18.0-test\n").unwrap();
        let f = probe_from(&osrel).unwrap();
        assert_eq!((f.major, f.minor), (6, 18));
    }

    #[test]
    fn probe_from_rejects_617_and_names_the_way_up() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.17.0-14-generic\n").unwrap();
        let err = probe_from(&osrel).unwrap_err();
        let KernelProbeError::BelowMinimum {
            found,
            required,
            upgrade,
        } = &err
        else {
            panic!("expected BelowMinimum, got {err:?}");
        };
        assert_eq!(found, "6.17");
        assert_eq!(required, "6.18");
        assert!(upgrade.contains("linux-generic-hwe-24.04"));
        let message = err.to_string();
        assert!(message.contains("6.17"));
        assert!(message.contains("6.18"));
        assert!(message.contains("linux-generic-hwe-24.04"));
    }

    /// Each family's release string, as its kernel packages write it, maps to
    /// that family's way up, and none falls through to the generic answer.
    #[test]
    fn every_family_has_its_own_upgrade_path() {
        let cases = [
            ("6.8.0-1041-azure", "AKS"),
            ("6.6.64.2-9.azl3", "Ubuntu 26.04"),
            ("6.12.40-63.114.amzn2023.x86_64", "kernel6.18"),
            (
                "5.10.225-213.878.amzn2.x86_64",
                "Amazon Linux 2 has no 6.18",
            ),
            ("6.12.18-talos", "Talos 1.12"),
            ("6.12.0-100.28.2.el10uek.x86_64", "UEK 8 is 6.12"),
            ("6.12.0-55.9.1.el10_0.x86_64", "no release of theirs"),
            ("5.14.0-503.11.1.el9_5.x86_64", "no release of theirs"),
            ("6.17.4-200.fc42.x86_64", "dnf upgrade"),
            ("6.12.48+deb13-amd64", "trixie-backports"),
            ("6.12.0-1004-cloud-amd64", "trixie-backports"),
            ("6.8.0-48-generic", "linux-generic-hwe-24.04"),
            ("6.8.0-1017-aws", "linux-generic-hwe-24.04"),
            ("6.8.0-1015-gcp", "linux-generic-hwe-24.04"),
            ("6.12.0-160000.5-default", "Tumbleweed"),
            ("6.12.18+", "COS milestone 133"),
        ];
        let generic = upgrade_hint("6.1.0-unknown-vendor", KernelVersion::FLOOR);
        assert!(generic.contains("compatibility matrix"));
        for (release, expected) in cases {
            let path = upgrade_hint(release, KernelVersion::FLOOR);
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

    /// Above the floor, each family has its own way to a newer kernel, none
    /// falls through to the generic answer, and none names the floor's way up.
    #[test]
    fn every_family_has_its_own_way_above_the_floor() {
        let target = KernelVersion { major: 7, minor: 1 };
        let cases = [
            ("6.18.0-1003-azure", "node image"),
            ("6.18.5-12.114.amzn2023.x86_64", "kernel stream"),
            ("6.18.9-talos", "newer Talos release"),
            (
                "6.18.0-100.28.2.el11uek.x86_64",
                "Unbreakable Enterprise Kernel",
            ),
            (
                "6.18.0-55.9.1.el11.x86_64",
                "no newer kernel in this release",
            ),
            ("6.19.2-300.fc43.x86_64", "dnf upgrade"),
            ("6.18.12+deb13-amd64", "backports"),
            ("6.18.0-1004-cloud-amd64", "backports"),
            ("7.0.0-15-generic", "enablement stack"),
            ("7.0.0-1005-aws", "enablement stack"),
            ("6.18.0-1.1-default", "service pack"),
            ("6.18.4+", "COS milestone"),
        ];
        let generic = upgrade_hint("6.18.0-unknown-vendor", target);
        assert!(generic.contains("newer kernel from your distribution"));
        for (release, expected) in cases {
            let hint = upgrade_hint(release, target);
            assert!(
                hint.contains(expected),
                "{release}: expected `{expected}` in `{hint}`"
            );
            assert_ne!(
                hint, generic,
                "{release} fell through to the generic answer"
            );
            assert!(
                !hint.contains("6.18 or later") && !hint.contains("has no 6.18"),
                "{release}: a way above the floor names the floor's: {hint}"
            );
        }
    }

    #[test]
    fn the_hint_names_the_shortfall_only_when_there_is_one() {
        let target = KernelVersion { major: 7, minor: 1 };
        let older = upgrade_hint("6.18.12+deb13-amd64", target);
        assert!(
            older.starts_with("This needs 7.1 and the host runs 6.18"),
            "{older}"
        );
        let built_without = upgrade_hint("7.1.0-3-generic", target);
        assert!(
            built_without.starts_with("This kernel was built without it"),
            "{built_without}"
        );
        let at_floor = upgrade_hint("7.0.0-15-generic", KernelVersion::FLOOR);
        assert!(
            at_floor.starts_with("This kernel was built without it"),
            "{at_floor}"
        );
    }

    /// On Ubuntu 24.04 the hardware enablement kernel is what reaches the
    /// base: the floor's refusal names it and says nothing about extras.
    #[test]
    fn the_ubuntu_ga_kernel_is_sent_to_the_floor_not_to_extras() {
        let hint = upgrade_hint("6.8.0-48-generic", KernelVersion::FLOOR);
        assert!(hint.contains("linux-generic-hwe-24.04"), "{hint}");
        assert!(!hint.contains("built without it"), "{hint}");
        assert!(!hint.contains("enablement stack"), "{hint}");
    }
}
