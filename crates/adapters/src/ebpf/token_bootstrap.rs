//! High-level BPF token bootstrap.
//!
//! Runs at agent startup and decides which BPF loading mode the
//! process will use:
//!
//! - `Token` — kernel 6.9+ `BPF_TOKEN_CREATE` against a delegated
//!   bpffs mount; the process drops `CAP_BPF` / `CAP_NET_ADMIN` as
//!   soon as the token fd is obtained.
//! - `Capabilities` — kernel 5.8+ fine-grained capabilities
//!   (`CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`).
//! - `Privileged` — legacy fallback for kernels without `CAP_BPF`
//!   (< 5.8).
//!
//! The caller provides the desired configuration; this module probes
//! the kernel, attempts the preferred path, and on failure falls back
//! according to [`BpfTokenPolicy`]. The returned [`BpfLoadingHandle`]
//! carries both the selected mode and (when applicable) the owning
//! [`OwnedFd`]s for the token and bpffs directory, so the caller can
//! pin them for the lifetime of the agent process.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use super::bpf_token::{self, BpfTokenError};
use super::kernel_probe::{KernelFeatures, KernelProbeError};

/// Loading mode the agent will use to attach eBPF programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfLoadingMode {
    /// `BPF_TOKEN_CREATE`-based delegation (kernel 6.9+). No `CAP_BPF`
    /// required on the process after token creation.
    Token,
    /// Fine-grained Linux capabilities (kernel 5.8+).
    Capabilities,
    /// Legacy `root` / `privileged: true` fallback (kernel < 5.8).
    Privileged,
}

impl BpfLoadingMode {
    /// Stable lowercase label used in logs + metrics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Token => "token",
            Self::Capabilities => "capabilities",
            Self::Privileged => "privileged",
        }
    }

    /// Numeric encoding for the `ebpfsentinel_bpf_token_used` gauge:
    /// `2 = token`, `1 = capabilities`, `0 = privileged`.
    #[must_use]
    pub const fn metric_value(self) -> i64 {
        match self {
            Self::Token => 2,
            Self::Capabilities => 1,
            Self::Privileged => 0,
        }
    }
}

/// Policy decided by the caller ahead of the probe.
#[derive(Debug, Clone)]
pub struct BpfTokenPolicy {
    pub enabled: bool,
    pub bpffs_path: PathBuf,
    pub fallback_allow_capabilities: bool,
}

impl BpfTokenPolicy {
    #[must_use]
    pub fn from_config(
        enabled: bool,
        bpffs_path: impl Into<PathBuf>,
        fallback_allow_capabilities: bool,
    ) -> Self {
        Self {
            enabled,
            bpffs_path: bpffs_path.into(),
            fallback_allow_capabilities,
        }
    }
}

/// Outcome of [`bootstrap`]. Owns the token + bpffs fds so they stay
/// alive for the lifetime of the agent.
pub struct BpfLoadingHandle {
    pub mode: BpfLoadingMode,
    pub kernel: KernelFeatures,
    pub reason: String,
    pub token_fd: Option<OwnedFd>,
    pub bpffs_fd: Option<OwnedFd>,
}

impl std::fmt::Debug for BpfLoadingHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfLoadingHandle")
            .field("mode", &self.mode)
            .field("kernel", &self.kernel.version_string())
            .field("reason", &self.reason)
            .field("token_fd_present", &self.token_fd.is_some())
            .field("bpffs_fd_present", &self.bpffs_fd.is_some())
            .finish()
    }
}

/// Errors returned when the caller refuses to fall back.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("kernel probe failed: {0}")]
    KernelProbe(#[from] KernelProbeError),

    #[error(
        "BPF token creation failed and fallback disabled: {source}; remove \
         `agent.bpf_token.fallback_allow_capabilities = false` to relax"
    )]
    TokenRequired {
        #[source]
        source: BpfTokenError,
    },
}

/// Probe the kernel, attempt to create a BPF token (when enabled),
/// and return a [`BpfLoadingHandle`] reflecting the chosen mode.
///
/// # Errors
/// Returns [`BootstrapError::KernelProbe`] when the live kernel is
/// below 6.9 and [`BootstrapError::TokenRequired`] when the caller
/// forbids capability fallback and token creation fails.
pub fn bootstrap(policy: &BpfTokenPolicy) -> Result<BpfLoadingHandle, BootstrapError> {
    let kernel = super::kernel_probe::probe()?;
    bootstrap_with_kernel(policy, kernel)
}

/// Variant of [`bootstrap`] that takes a pre-computed
/// [`KernelFeatures`]. Used by the unit tests to inject synthetic
/// kernels and by callers that already probed the kernel themselves.
pub fn bootstrap_with_kernel(
    policy: &BpfTokenPolicy,
    kernel: KernelFeatures,
) -> Result<BpfLoadingHandle, BootstrapError> {
    if !policy.enabled {
        return Ok(handle_capabilities(kernel, "bpf_token disabled by config"));
    }
    if !kernel.bpf_token {
        return Ok(handle_capabilities(
            kernel,
            "kernel lacks BPF_TOKEN_CREATE (requires 6.9+)",
        ));
    }

    match bpf_token::create_enterprise_token(&policy.bpffs_path) {
        Ok((bpffs_fd, token_fd)) => Ok(BpfLoadingHandle {
            mode: BpfLoadingMode::Token,
            kernel,
            reason: format!(
                "BPF_TOKEN_CREATE succeeded against {}",
                policy.bpffs_path.display()
            ),
            token_fd: Some(token_fd),
            bpffs_fd: Some(bpffs_fd),
        }),
        Err(err) => {
            if policy.fallback_allow_capabilities {
                Ok(handle_capabilities(
                    kernel,
                    format!("token creation failed: {err}; falling back to capabilities"),
                ))
            } else {
                Err(BootstrapError::TokenRequired { source: err })
            }
        }
    }
}

fn handle_capabilities(kernel: KernelFeatures, reason: impl Into<String>) -> BpfLoadingHandle {
    BpfLoadingHandle {
        mode: BpfLoadingMode::Capabilities,
        kernel,
        reason: reason.into(),
        token_fd: None,
        bpffs_fd: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(major: u32, minor: u32) -> KernelFeatures {
        KernelFeatures {
            major,
            minor,
            btf_available: true,
            bpf_token: major > 6 || (major == 6 && minor >= 9),
            arena_map: major > 6 || (major == 6 && minor >= 9),
            cgroup1_kfunc: major > 6 || (major == 6 && minor >= 8),
            xdp_vlan_metadata: major > 6 || (major == 6 && minor >= 8),
            xdp_xfrm_state: major > 6 || (major == 6 && minor >= 8),
            css_task_iter: major > 6 || (major == 6 && minor >= 7),
        }
    }

    #[test]
    fn disabled_policy_returns_capabilities_mode() {
        let policy = BpfTokenPolicy::from_config(false, "/nonexistent", true);
        let handle = bootstrap_with_kernel(&policy, features(6, 9)).unwrap();
        assert_eq!(handle.mode, BpfLoadingMode::Capabilities);
        assert!(handle.reason.contains("disabled"));
        assert!(handle.token_fd.is_none());
    }

    #[test]
    fn old_kernel_falls_back_to_capabilities() {
        let policy = BpfTokenPolicy::from_config(true, "/nonexistent", true);
        let handle = bootstrap_with_kernel(&policy, features(6, 9)).unwrap();
        // token creation fails with EBADF because /nonexistent is not
        // a bpffs mount, but fallback_allow_capabilities = true → ok.
        assert_eq!(handle.mode, BpfLoadingMode::Capabilities);
        assert!(handle.reason.contains("token creation failed"));
    }

    #[test]
    fn missing_bpf_token_support_falls_back() {
        let policy = BpfTokenPolicy::from_config(true, "/nonexistent", true);
        let handle = bootstrap_with_kernel(&policy, features(6, 8)).unwrap();
        assert_eq!(handle.mode, BpfLoadingMode::Capabilities);
        assert!(handle.reason.contains("requires 6.9"));
    }

    #[test]
    fn fallback_disabled_errors_on_token_failure() {
        let policy = BpfTokenPolicy::from_config(true, "/nonexistent", false);
        let err = bootstrap_with_kernel(&policy, features(6, 9)).unwrap_err();
        matches!(err, BootstrapError::TokenRequired { .. });
    }

    #[test]
    fn mode_metric_values_are_stable() {
        assert_eq!(BpfLoadingMode::Token.metric_value(), 2);
        assert_eq!(BpfLoadingMode::Capabilities.metric_value(), 1);
        assert_eq!(BpfLoadingMode::Privileged.metric_value(), 0);
    }

    #[test]
    fn mode_labels_are_stable() {
        assert_eq!(BpfLoadingMode::Token.as_str(), "token");
        assert_eq!(BpfLoadingMode::Capabilities.as_str(), "capabilities");
        assert_eq!(BpfLoadingMode::Privileged.as_str(), "privileged");
    }
}
