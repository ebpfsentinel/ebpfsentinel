//! Runtime kernel feature probe.
//!
//! The agent requires Linux 6.9+ to load all eBPF programs: BPF token
//! delegation, `BPF_MAP_TYPE_ARENA`, and kfuncs added in 6.7 → 6.9
//! (`bpf_task_get_cgroup1`, `bpf_xdp_metadata_rx_vlan_tag`,
//! `bpf_xdp_get_xfrm_state`, `bpf_iter_css_task`). This module parses
//! `/proc/sys/kernel/osrelease` and exposes a [`KernelFeatures`] snapshot
//! the bootstrap code consults before loading programs.
//!
//! The probe is intentionally lightweight: no libbpf, no syscalls, just
//! one file read + version comparison + BTF file presence checks.

use std::fs;
use std::path::Path;

/// Minimum kernel version required by the agent.
pub const MIN_KERNEL_MAJOR: u32 = 6;
pub const MIN_KERNEL_MINOR: u32 = 9;

/// Snapshot of kernel capabilities relevant to the eBPF loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct KernelFeatures {
    pub major: u32,
    pub minor: u32,
    pub btf_available: bool,
    /// `BPF_TOKEN_CREATE` + `BPF_F_TOKEN_FD` — kernel 6.9.
    pub bpf_token: bool,
    /// `BPF_MAP_TYPE_ARENA` — kernel 6.9.
    pub arena_map: bool,
    /// `bpf_task_get_cgroup1` kfunc — kernel 6.8.
    pub cgroup1_kfunc: bool,
    /// `bpf_xdp_metadata_rx_vlan_tag` kfunc — kernel 6.8.
    pub xdp_vlan_metadata: bool,
    /// `bpf_xdp_get_xfrm_state` kfunc — kernel 6.8.
    pub xdp_xfrm_state: bool,
    /// `bpf_iter_css_task` kfunc — kernel 6.7.
    pub css_task_iter: bool,
}

impl KernelFeatures {
    /// Returns `true` when the live kernel satisfies the project-wide
    /// 6.9 minimum.
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

    #[error(
        "kernel {found} is below the required minimum {required}; upgrade to 6.9+ for BPF token \
         delegation, cgroup1 kfunc, and XDP metadata kfuncs"
    )]
    BelowMinimum { found: String, required: String },
}

/// Probe the kernel using the default `/proc` + `/sys` paths.
///
/// # Errors
/// Returns [`KernelProbeError::ReadOsRelease`] or
/// [`KernelProbeError::ParseVersion`] on IO / parse failures and
/// [`KernelProbeError::BelowMinimum`] when the live kernel is below 6.9.
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
/// [`KernelProbeError::BelowMinimum`] when the kernel is below 6.9.
pub fn probe_from(
    osrelease_path: &Path,
    btf_path: &Path,
) -> Result<KernelFeatures, KernelProbeError> {
    let contents = fs::read_to_string(osrelease_path)
        .map_err(|e| KernelProbeError::ReadOsRelease(e.to_string()))?;
    let (major, minor) = parse_version(contents.trim())?;

    let btf_available = btf_path.exists();
    let features = derive_features(major, minor, btf_available);

    if !features.meets_minimum() {
        return Err(KernelProbeError::BelowMinimum {
            found: features.version_string(),
            required: format!("{MIN_KERNEL_MAJOR}.{MIN_KERNEL_MINOR}"),
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
    fn derive_69_enables_all() {
        let f = derive_features(6, 9, true);
        assert!(f.bpf_token);
        assert!(f.arena_map);
        assert!(f.cgroup1_kfunc);
        assert!(f.xdp_vlan_metadata);
        assert!(f.xdp_xfrm_state);
        assert!(f.css_task_iter);
        assert!(f.meets_minimum());
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
        assert!(derive_features(6, 9, true).meets_minimum());
        assert!(!derive_features(6, 8, true).meets_minimum());
        assert!(derive_features(7, 0, true).meets_minimum());
    }

    #[test]
    fn probe_from_accepts_69_osrelease() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.9.0-test\n").unwrap();
        let btf = tmp.path().join("vmlinux");
        std::fs::write(&btf, "stub").unwrap();
        let f = probe_from(&osrel, &btf).unwrap();
        assert!(f.bpf_token);
        assert!(f.btf_available);
    }

    #[test]
    fn probe_from_rejects_66_osrelease() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.6.0-lts\n").unwrap();
        let err = probe_from(&osrel, Path::new("/nonexistent")).unwrap_err();
        matches!(err, KernelProbeError::BelowMinimum { .. });
    }

    #[test]
    fn probe_from_reports_missing_btf() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let osrel = tmp.path().join("osrelease");
        std::fs::write(&osrel, "6.10.0\n").unwrap();
        let f = probe_from(&osrel, Path::new("/nonexistent-btf")).unwrap();
        assert!(!f.btf_available);
    }
}
