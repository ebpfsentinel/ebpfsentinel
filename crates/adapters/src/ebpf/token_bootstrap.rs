//! High-level BPF token bootstrap.
//!
//! eBPF is loaded **exclusively** through a kernel 6.9+ BPF token
//! (`BPF_TOKEN_CREATE`) created against a delegated bpffs mount. There
//! is no capability-based loading path: the agent never loads eBPF with
//! `CAP_BPF` / `CAP_NET_ADMIN` / `CAP_SYS_ADMIN`. A privileged setup
//! component (systemd `ExecStartPre`, a Kubernetes init container, or
//! the `ebpfsentinel-token-setup.sh` helper) mounts the delegated
//! bpffs; the agent process — which may be fully unprivileged — opens
//! it and creates the token.
//!
//! [`bootstrap`] probes the kernel, creates the token, and returns a
//! [`BpfLoadingHandle`] owning the token + bpffs fds (pinned for the
//! process lifetime). Any failure is fatal by design: an old kernel or
//! a missing delegated bpffs means eBPF cannot be loaded at all, and
//! there is deliberately no fallback to process capabilities.

use std::os::fd::OwnedFd;
use std::path::PathBuf;

use super::bpf_token::{self, BpfTokenError};
use super::kernel_probe::{KernelFeatures, KernelProbeError};

/// Token-creation policy: just the delegated bpffs mount to create the
/// token against. The delegation scope (which commands/maps/programs/
/// attach types are permitted) comes from the bpffs *mount* options, not
/// from here.
#[derive(Debug, Clone)]
pub struct BpfTokenPolicy {
    pub bpffs_path: PathBuf,
}

impl BpfTokenPolicy {
    #[must_use]
    pub fn new(bpffs_path: impl Into<PathBuf>) -> Self {
        Self {
            bpffs_path: bpffs_path.into(),
        }
    }
}

/// Outcome of [`bootstrap`]. Owns the token + bpffs fds so they stay
/// alive for the lifetime of the agent — the kernel authorizes every
/// map/BTF/program load against the token fd, so dropping it would break
/// subsequent loads.
pub struct BpfLoadingHandle {
    pub kernel: KernelFeatures,
    pub reason: String,
    pub token_fd: OwnedFd,
    pub bpffs_fd: OwnedFd,
}

impl std::fmt::Debug for BpfLoadingHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BpfLoadingHandle")
            .field("kernel", &self.kernel.version_string())
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

/// Errors returned when the token cannot be created. Every variant is
/// fatal: the agent cannot load eBPF without a token.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("kernel probe failed: {0}")]
    KernelProbe(#[from] KernelProbeError),

    #[error(
        "kernel {major}.{minor} lacks BPF_TOKEN_CREATE — eBPFsentinel loads eBPF \
         only through a BPF token (kernel 6.9+ required). Upgrade the host kernel."
    )]
    KernelTooOld { major: u32, minor: u32 },

    #[error(
        "BPF token creation failed against `{bpffs}`: {source}. A privileged setup \
         step (systemd ExecStartPre, a Kubernetes init container, or \
         ebpfsentinel-token-setup.sh) must mount the delegated bpffs before the \
         agent starts."
    )]
    TokenCreate {
        bpffs: String,
        #[source]
        source: BpfTokenError,
    },
}

/// Probe the kernel and create the BPF token, returning a
/// [`BpfLoadingHandle`] that owns the token + bpffs fds.
///
/// # Errors
/// Returns [`BootstrapError::KernelProbe`] when the kernel cannot be
/// probed, [`BootstrapError::KernelTooOld`] when it is below 6.9, and
/// [`BootstrapError::TokenCreate`] when `BPF_TOKEN_CREATE` fails (most
/// commonly because the delegated bpffs has not been mounted).
pub fn bootstrap(policy: &BpfTokenPolicy) -> Result<BpfLoadingHandle, BootstrapError> {
    let kernel = super::kernel_probe::probe()?;
    bootstrap_with_kernel(policy, kernel)
}

/// Variant of [`bootstrap`] that takes a pre-computed [`KernelFeatures`].
/// Used by the unit tests to inject synthetic kernels and by callers that
/// already probed the kernel themselves.
///
/// # Errors
/// See [`bootstrap`].
pub fn bootstrap_with_kernel(
    policy: &BpfTokenPolicy,
    kernel: KernelFeatures,
) -> Result<BpfLoadingHandle, BootstrapError> {
    if !kernel.bpf_token {
        return Err(BootstrapError::KernelTooOld {
            major: kernel.major,
            minor: kernel.minor,
        });
    }

    match bpf_token::create_enterprise_token(&policy.bpffs_path) {
        Ok((bpffs_fd, token_fd)) => Ok(BpfLoadingHandle {
            kernel,
            reason: format!(
                "BPF_TOKEN_CREATE succeeded against {}",
                policy.bpffs_path.display()
            ),
            token_fd,
            bpffs_fd,
        }),
        Err(source) => Err(BootstrapError::TokenCreate {
            bpffs: policy.bpffs_path.display().to_string(),
            source,
        }),
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
    fn old_kernel_is_rejected() {
        let policy = BpfTokenPolicy::new("/nonexistent");
        let err = bootstrap_with_kernel(&policy, features(6, 8)).unwrap_err();
        assert!(matches!(err, BootstrapError::KernelTooOld { .. }));
    }

    #[test]
    fn token_create_failure_is_fatal() {
        // /nonexistent is not a bpffs mount, so BPF_TOKEN_CREATE fails.
        // There is no capability fallback: the bootstrap must surface the
        // error instead of silently degrading.
        let policy = BpfTokenPolicy::new("/nonexistent");
        let err = bootstrap_with_kernel(&policy, features(6, 9)).unwrap_err();
        assert!(matches!(err, BootstrapError::TokenCreate { .. }));
    }
}
