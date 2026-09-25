#![allow(unsafe_code)] // Raw BPF_LINK_CREATE syscall for netkit attach.

//! Netkit BPF attach support for Kubernetes pod networking.
//!
//! Netkit (kernel 6.7+) replaces veth pairs for container networking.
//! BPF programs attach natively via `BPF_LINK_CREATE` with
//! `BPF_NETKIT_PRIMARY` (ingress), eliminating the TC qdisc overhead.
//! Cilium uses netkit by default since 1.16.
//!
//! This module provides:
//! - `is_netkit_device(iface)` - detect netkit interfaces
//! - `netkit_attach` - raw `BPF_LINK_CREATE` attach

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};
use std::path::Path;

use tracing::info;

/// `ARPHRD_NONE` - the ARP hardware type reported by netkit devices.
const ARPHRD_NONE: u32 = 65534;

/// `BPF_LINK_CREATE` command for the `bpf()` syscall.
const BPF_LINK_CREATE: u32 = 28;

/// `BPF_NETKIT_PRIMARY` attach type - ingress side of the netkit pair.
pub const BPF_NETKIT_PRIMARY: u32 = 54;

/// `BPF_NETKIT_PEER` attach type - egress side of the netkit pair.
pub const BPF_NETKIT_PEER: u32 = 55;

/// Subset of `union bpf_attr` for `BPF_LINK_CREATE`.
#[repr(C)]
#[derive(Default)]
struct BpfAttrLinkCreate {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    // Netkit-specific fields (union member).
    target_ifindex: u32,
    _pad: [u32; 15], // padding to cover full bpf_attr size
}

/// Check whether `iface` is a netkit device by reading
/// `/sys/class/net/{iface}/type`. Netkit devices report
/// `ARPHRD_NONE` (65534).
pub fn is_netkit_device(iface: &str) -> bool {
    let path = format!("/sys/class/net/{iface}/type");
    match std::fs::read_to_string(&path) {
        Ok(content) => content.trim().parse::<u32>().unwrap_or(0) == ARPHRD_NONE,
        Err(_) => false,
    }
}

/// List all network interfaces that are netkit devices.
pub fn list_netkit_devices() -> Vec<String> {
    let net_dir = Path::new("/sys/class/net");
    let Ok(entries) = std::fs::read_dir(net_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| {
            let name = e.ok()?.file_name().to_str()?.to_string();
            if is_netkit_device(&name) {
                Some(name)
            } else {
                None
            }
        })
        .collect()
}

/// Attach a loaded BPF program to a netkit device via raw
/// `BPF_LINK_CREATE` syscall. Returns an `OwnedFd` for the link
/// (dropping it detaches the program).
///
/// `prog_fd` - fd of the loaded BPF program (from aya).
/// `ifindex` - network interface index of the netkit device.
/// `attach_type` - `BPF_NETKIT_PRIMARY` (ingress) or `BPF_NETKIT_PEER` (egress).
pub fn netkit_attach(
    prog_fd: RawFd,
    ifindex: u32,
    attach_type: u32,
) -> Result<OwnedFd, NetkitError> {
    let attr = BpfAttrLinkCreate {
        #[allow(clippy::cast_sign_loss)]
        prog_fd: prog_fd as u32,
        target_fd: 0, // unused for netkit
        attach_type,
        flags: 0,
        target_ifindex: ifindex,
        _pad: [0; 15],
    };

    #[allow(clippy::cast_possible_truncation)]
    let attr_size = std::mem::size_of::<BpfAttrLinkCreate>() as u32;
    let attr_ptr: *const BpfAttrLinkCreate = &raw const attr;

    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            #[allow(clippy::cast_possible_wrap)]
            (BPF_LINK_CREATE as libc::c_int),
            attr_ptr as usize,
            attr_size as usize,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(NetkitError::AttachFailed {
            ifindex,
            attach_type,
            errno: err.raw_os_error().unwrap_or(0),
            message: err.to_string(),
        });
    }

    #[allow(clippy::cast_possible_truncation)]
    let link_fd = unsafe { OwnedFd::from_raw_fd(fd as i32) };

    let direction = if attach_type == BPF_NETKIT_PRIMARY {
        "primary"
    } else {
        "peer"
    };
    info!(ifindex, direction, "BPF program attached via netkit");

    Ok(link_fd)
}

/// Attach a loaded BPF program to a netkit interface by name.
/// Resolves the interface name to ifindex, then calls `netkit_attach`.
pub fn netkit_attach_by_name(
    prog_fd: RawFd,
    iface: &str,
    attach_type: u32,
) -> Result<OwnedFd, NetkitError> {
    if !is_netkit_device(iface) {
        return Err(NetkitError::NotNetkit {
            iface: iface.to_string(),
        });
    }
    let ifindex = iface_to_ifindex(iface)?;
    netkit_attach(prog_fd, ifindex, attach_type)
}

fn iface_to_ifindex(iface: &str) -> Result<u32, NetkitError> {
    let path = format!("/sys/class/net/{iface}/ifindex");
    let content = std::fs::read_to_string(&path).map_err(|e| NetkitError::IfindexFailed {
        iface: iface.to_string(),
        message: e.to_string(),
    })?;
    content
        .trim()
        .parse::<u32>()
        .map_err(|e| NetkitError::IfindexFailed {
            iface: iface.to_string(),
            message: e.to_string(),
        })
}

/// Which side of a netkit pair a hot-plugged program runs on.
///
/// The kernel runs `BPF_NETKIT_PRIMARY` programs on the primary's transmit
/// path, which is the traffic entering the pod, and `BPF_NETKIT_PEER` programs
/// on the peer's, which is the traffic leaving it. The agent's ingress chain
/// takes the first and its egress chain the second, the same mapping
/// [`super::loader::EbpfLoader::attach_tc_via_netkit`] uses for a configured
/// interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetkitSide {
    /// Traffic entering the pod: the agent's TC ingress chain.
    Ingress,
    /// Traffic leaving the pod: the agent's TC egress chain.
    Egress,
}

impl NetkitSide {
    fn attach_type(self) -> u32 {
        match self {
            Self::Ingress => BPF_NETKIT_PRIMARY,
            Self::Egress => BPF_NETKIT_PEER,
        }
    }
}

/// Registry of loaded TC program FDs for netkit hot-plug attachment.
///
/// When a new netkit device appears at runtime (e.g. Kubernetes pod
/// creation), the watcher callback uses this registry to attach all
/// configured TC programs to the new interface without restarting
/// the agent. Programs attach in registration order, which is the order
/// they run in on each side, so the caller registers them in chain order.
///
/// The links are held per device and dropped when the device goes away:
/// the kernel detaches a link whose device was unregistered, but the link
/// object and its fd live until the fd is closed, so holding them for the
/// life of the agent would leak one fd per program per pod ever scheduled.
///
/// Safety: the stored `RawFd` values are valid as long as the
/// `EbpfState` that owns the underlying `EbpfLoader` instances is
/// alive. The agent shutdown sequence cancels the watcher before
/// dropping `EbpfState`.
pub struct NetkitHotPlugRegistry {
    /// `(program_name, program_fd, side)` for each loaded TC program, in
    /// the order it runs on its side.
    programs: Vec<(String, std::os::fd::RawFd, NetkitSide)>,
    /// Interfaces the agent already attached through its configuration.
    /// A second attach would run the whole chain twice on every packet.
    configured: std::collections::HashSet<String>,
    /// Link FDs for hot-plugged attachments, per interface. Dropping detaches.
    links: std::sync::Mutex<std::collections::HashMap<String, Vec<OwnedFd>>>,
}

impl Default for NetkitHotPlugRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl NetkitHotPlugRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            programs: Vec::new(),
            configured: std::collections::HashSet::new(),
            links: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Register a loaded TC program for hot-plug attachment on `side`.
    pub fn register(&mut self, program_name: String, fd: std::os::fd::RawFd, side: NetkitSide) {
        self.programs.push((program_name, fd, side));
    }

    /// Leave `iface` alone: the agent attached it from its configuration.
    pub fn skip_configured(&mut self, iface: impl Into<String>) {
        self.configured.insert(iface.into());
    }

    /// Attach all registered programs to a netkit interface.
    /// Logs pod context from the namespace scan for correlation.
    /// Logs warnings on individual failures but continues.
    pub fn attach_all(&self, iface: &str, new_pods: &[super::netkit_discovery::PodContext]) {
        if self.configured.contains(iface) {
            return;
        }
        for ctx in new_pods {
            info!(
                iface,
                pod_pid = ctx.pid,
                ns_inode = ctx.ns_inode,
                "hot-plug: new pod namespace detected alongside netkit device"
            );
        }

        let mut attached = Vec::new();
        for (name, fd, side) in &self.programs {
            match netkit_attach_by_name(*fd, iface, side.attach_type()) {
                Ok(link_fd) => {
                    info!(program = %name, iface, ?side, "hot-plug: TC program attached via netkit");
                    attached.push(link_fd);
                }
                Err(e) => {
                    tracing::warn!(
                        program = %name, iface, ?side, error = %e,
                        "hot-plug: failed to attach TC program via netkit"
                    );
                }
            }
        }
        if let Ok(mut links) = self.links.lock() {
            // A device recreated under the same name replaces the old set.
            links.insert(iface.to_string(), attached);
        }
    }

    /// Drop the links held for an interface that has gone away.
    pub fn detach(&self, iface: &str) {
        if let Ok(mut links) = self.links.lock()
            && let Some(dropped) = links.remove(iface)
        {
            info!(
                iface,
                links = dropped.len(),
                "hot-plug: netkit device removed, links released"
            );
        }
    }

    /// Number of registered programs.
    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Number of active hot-plugged links.
    pub fn link_count(&self) -> usize {
        self.links
            .lock()
            .map_or(0, |l| l.values().map(Vec::len).sum())
    }
}

/// Errors from netkit operations.
#[derive(Debug, thiserror::Error)]
pub enum NetkitError {
    #[error(
        "BPF_LINK_CREATE(NETKIT) failed for ifindex={ifindex} attach_type={attach_type}: errno={errno} {message}"
    )]
    AttachFailed {
        ifindex: u32,
        attach_type: u32,
        errno: i32,
        message: String,
    },
    #[error("interface '{iface}' is not a netkit device")]
    NotNetkit { iface: String },
    #[error("failed to resolve ifindex for '{iface}': {message}")]
    IfindexFailed { iface: String, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_netkit_device_returns_false_for_lo() {
        // Loopback is ARPHRD_LOOPBACK (772), not ARPHRD_NONE.
        assert!(!is_netkit_device("lo"));
    }

    #[test]
    fn is_netkit_device_returns_false_for_nonexistent() {
        assert!(!is_netkit_device("nonexistent_iface_xyz"));
    }

    #[test]
    fn list_netkit_devices_returns_empty_on_standard_host() {
        // Most hosts don't have netkit devices unless Cilium is running.
        let devices = list_netkit_devices();
        // Either empty or non-empty - both valid, no panic.
        let _ = devices;
    }

    #[test]
    fn netkit_error_display() {
        let e = NetkitError::NotNetkit {
            iface: "eth0".to_string(),
        };
        assert!(e.to_string().contains("eth0"));
        assert!(e.to_string().contains("not a netkit"));
    }

    #[test]
    fn bpf_attr_link_create_size() {
        // Must be large enough for kernel to parse the netkit fields.
        assert!(std::mem::size_of::<BpfAttrLinkCreate>() >= 20);
    }

    #[test]
    fn hotplug_registry_starts_empty() {
        let reg = NetkitHotPlugRegistry::new();
        assert_eq!(reg.program_count(), 0);
        assert_eq!(reg.link_count(), 0);
    }

    #[test]
    fn hotplug_registry_registers_programs() {
        let mut reg = NetkitHotPlugRegistry::new();
        reg.register("tc_ids".to_string(), 42, NetkitSide::Ingress);
        reg.register("tc_qos".to_string(), 43, NetkitSide::Egress);
        assert_eq!(reg.program_count(), 2);
    }

    #[test]
    fn hotplug_attach_all_on_non_netkit_device_warns() {
        let mut reg = NetkitHotPlugRegistry::new();
        // fd -1 is invalid - attach will fail gracefully.
        reg.register("tc_ids".to_string(), -1, NetkitSide::Ingress);
        // Should not panic, just log warnings.
        reg.attach_all("lo", &[]);
        assert_eq!(reg.link_count(), 0);
    }

    #[test]
    fn sides_map_to_the_netkit_attach_types() {
        // Primary runs on the way into the pod, peer on the way out.
        assert_eq!(NetkitSide::Ingress.attach_type(), BPF_NETKIT_PRIMARY);
        assert_eq!(NetkitSide::Egress.attach_type(), BPF_NETKIT_PEER);
    }

    #[test]
    fn detach_of_an_unknown_device_is_a_no_op() {
        let reg = NetkitHotPlugRegistry::new();
        reg.detach("nk-gone");
        assert_eq!(reg.link_count(), 0);
    }

    #[test]
    fn a_configured_interface_is_not_attached_twice() {
        let mut reg = NetkitHotPlugRegistry::new();
        reg.register("tc_ids".to_string(), -1, NetkitSide::Ingress);
        reg.skip_configured("lo");
        reg.attach_all("lo", &[]);
        // Skipped before any attach was tried, so no entry was recorded.
        assert!(reg.links.lock().unwrap().is_empty());
    }
}
