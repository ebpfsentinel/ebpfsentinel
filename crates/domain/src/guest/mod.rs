//! The virtual machines whose traffic crosses this host.
//!
//! A guest's traffic leaves it through a tap or macvtap device in the host
//! namespace, so the agent sees it on that device and nowhere else: a guest
//! carries its own kernel, and nothing the agent reads in the host's process
//! table or cgroup tree belongs to it. The device is therefore the key, the
//! one exception to the cgroup being a workload's key, and the name comes
//! from whichever hypervisor wrote down which guest the device was made for.
//!
//! A device no hypervisor record names is reported as unnamed with the
//! reason, never given a placeholder: a policy written against a guest's
//! name must not match a device that only looks like one.

/// The hypervisor record a guest's name was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuestSource {
    /// A libvirt domain, named in the status file libvirt keeps for each
    /// running domain.
    Libvirt,
    /// A Proxmox VE virtual machine, named in its configuration file.
    Proxmox,
}

impl GuestSource {
    /// The word the API and the CLI use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Libvirt => "libvirt",
            Self::Proxmox => "proxmox",
        }
    }
}

/// A guest as its hypervisor names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestIdentity {
    /// The name the hypervisor shows: the libvirt domain name, the Proxmox
    /// VM name.
    pub name: String,
    /// The hypervisor's own identifier: the libvirt UUID, the Proxmox VMID.
    pub id: String,
    /// Where the name was read.
    pub source: GuestSource,
    /// The tags the hypervisor carries for the guest, in the order written.
    /// Proxmox tags; libvirt keeps none of its own.
    pub tags: Vec<String>,
}

/// Why a guest's device carries no name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnnamedReason {
    /// Neither hypervisor source is configured on this agent.
    NoSource,
    /// Every configured source was read and none names this device.
    NoRecord,
    /// The record naming the device's guest gives it no name.
    RecordWithoutName {
        /// The record.
        path: String,
    },
    /// A record that could name the device's guest could not be read.
    RecordUnreadable {
        /// The file that failed.
        path: String,
        /// What reading it answered.
        error: String,
    },
}

impl UnnamedReason {
    /// A stable code for the API.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSource => "no_source",
            Self::NoRecord => "no_record",
            Self::RecordWithoutName { .. } => "record_without_name",
            Self::RecordUnreadable { .. } => "record_unreadable",
        }
    }

    /// The same reason in a sentence.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::NoSource => {
                "no hypervisor source is configured: both the libvirt and the Proxmox \
                 directories are empty in the configuration"
                    .to_owned()
            }
            Self::NoRecord => "no libvirt domain and no Proxmox virtual machine names this \
                               device; it may belong to a hypervisor the agent does not read"
                .to_owned(),
            Self::RecordWithoutName { path } => {
                format!("the record for this device's guest gives it no name: {path}")
            }
            Self::RecordUnreadable { path, error } => format!(
                "a hypervisor record that could name this device's guest could not be read: \
                 {path}: {error}"
            ),
        }
    }
}

/// What the hypervisor records say of one device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestNaming {
    /// A record names the guest.
    Named(GuestIdentity),
    /// None does, for the reason given.
    Unnamed(UnnamedReason),
}

/// A guest's device as the agent holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestLink {
    /// Interface index in the host namespace.
    pub ifindex: u32,
    /// Interface name in the host namespace.
    pub interface: String,
    /// `tap` or `macvtap`.
    pub kind: String,
    /// Every program of the chain is on the device.
    pub attached: bool,
    /// Which guest it is, or why that is not known.
    pub naming: GuestNaming,
}

/// Whether a link kind, as the link watcher reports it, is a guest's.
#[must_use]
pub fn is_guest_kind(kind: &str) -> bool {
    matches!(kind, "tap" | "macvtap")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tap_and_macvtap_are_guest_kinds() {
        assert!(is_guest_kind("tap"));
        assert!(is_guest_kind("macvtap"));
        for kind in ["tun", "veth", "macvlan", "bridge-member", ""] {
            assert!(!is_guest_kind(kind), "{kind}");
        }
    }

    #[test]
    fn every_reason_has_a_code_and_a_sentence() {
        let reasons = [
            UnnamedReason::NoSource,
            UnnamedReason::NoRecord,
            UnnamedReason::RecordWithoutName {
                path: "/etc/pve/qemu-server/102.conf".into(),
            },
            UnnamedReason::RecordUnreadable {
                path: "/etc/pve/qemu-server/101.conf".into(),
                error: "permission denied".into(),
            },
        ];
        let codes: Vec<&str> = reasons.iter().map(UnnamedReason::code).collect();
        assert_eq!(
            codes,
            [
                "no_source",
                "no_record",
                "record_without_name",
                "record_unreadable"
            ]
        );
        assert!(
            reasons[3]
                .describe()
                .contains("101.conf: permission denied")
        );
        assert_eq!(GuestSource::Proxmox.as_str(), "proxmox");
        assert_eq!(GuestSource::Libvirt.as_str(), "libvirt");
    }
}
