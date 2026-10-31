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
//!
//! A KubeVirt guest is the other shape: its tap is inside the launcher pod,
//! so what crosses the host is the pod's link, and the guest is named from
//! the labels KubeVirt puts on that pod. The cluster names the same machine
//! through the pod, and both names reach the one device.

use std::collections::BTreeMap;

use crate::coverage::PodSubject;

/// The hypervisor record a guest's name was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuestSource {
    /// A libvirt domain, named in the status file libvirt keeps for each
    /// running domain.
    Libvirt,
    /// A Proxmox VE virtual machine, named in its configuration file.
    Proxmox,
    /// A KubeVirt virtual machine, named from the labels of its launcher
    /// pod.
    Kubevirt,
}

impl GuestSource {
    /// The word the API and the CLI use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Libvirt => "libvirt",
            Self::Proxmox => "proxmox",
            Self::Kubevirt => "kubevirt",
        }
    }
}

/// A guest as its hypervisor names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestIdentity {
    /// The name the hypervisor shows: the libvirt domain name, the Proxmox
    /// VM name, the KubeVirt `namespace/name`.
    pub name: String,
    /// The hypervisor's own identifier: the libvirt UUID, the Proxmox VMID,
    /// the KubeVirt instance's UID.
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

/// The bit that marks a guest's key in the tables the packet path otherwise
/// keys on a cgroup id.
///
/// A guest has no cgroup on the host, so its device stands in for one: the
/// key is the interface index under this bit, which no cgroup id reaches
/// because the kernel numbers cgroups upward from one.
pub const GUEST_SCOPE_KEY_BIT: u64 = 1 << 63;

/// The key a guest's device carries where a host workload's cgroup id would.
#[must_use]
pub fn guest_scope_key(ifindex: u32) -> u64 {
    GUEST_SCOPE_KEY_BIT | u64::from(ifindex)
}

/// What the agent can protect of a guest from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProtection {
    /// What is covered: `network` once the chain is on the device, nothing
    /// before.
    pub covered: Vec<&'static str>,
    /// What is not, and never is from the host.
    pub not_covered: Vec<&'static str>,
    /// Why, in a sentence.
    pub reason: String,
}

impl GuestLink {
    /// What the agent protects of this guest, and why no more.
    #[must_use]
    pub fn protection(&self) -> GuestProtection {
        let reason = "the guest runs its own kernel, so its processes, sockets and TLS \
                      sessions are inside it and the host sees only the packets on its \
                      device; process attribution and data loss prevention need an agent \
                      inside the guest";
        if self.attached {
            GuestProtection {
                covered: vec!["network"],
                not_covered: vec!["process", "dlp"],
                reason: format!("network only: {reason}"),
            }
        } else {
            GuestProtection {
                covered: Vec::new(),
                not_covered: vec!["network", "process", "dlp"],
                reason: format!(
                    "the programs are not on this device yet, so not even its packets are \
                     inspected; and {reason}"
                ),
            }
        }
    }
}

/// Whether a link kind, as the link watcher reports it, is a guest's.
#[must_use]
pub fn is_guest_kind(kind: &str) -> bool {
    matches!(kind, "tap" | "macvtap")
}

/// The label KubeVirt sets to `virt-launcher` on the pod running a guest.
pub const KUBEVIRT_APP_LABEL: &str = "kubevirt.io";
/// The label carrying the name of the `VirtualMachine` the guest belongs to.
pub const KUBEVIRT_VM_LABEL: &str = "vm.kubevirt.io/name";
/// The label carrying the name of the `VirtualMachineInstance`.
pub const KUBEVIRT_DOMAIN_LABEL: &str = "kubevirt.io/domain";
/// The label carrying the UID of the `VirtualMachineInstance`.
pub const KUBEVIRT_CREATED_BY_LABEL: &str = "kubevirt.io/created-by";

/// The guest a KubeVirt launcher pod runs, or `None` for any other pod.
///
/// The name is the `VirtualMachine`'s, else the instance's, prefixed with the
/// namespace because the cluster only keeps a name unique within one; the
/// identifier is the instance's UID. A launcher pod carrying neither name is
/// a guest without one, never a guest named after its pod.
#[must_use]
pub fn kubevirt_guest(pod: &PodSubject) -> Option<GuestNaming> {
    let label = |key: &str| {
        pod.labels
            .get(key)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
    };
    if label(KUBEVIRT_APP_LABEL) != Some("virt-launcher") {
        return None;
    }
    let Some(name) = label(KUBEVIRT_VM_LABEL).or_else(|| label(KUBEVIRT_DOMAIN_LABEL)) else {
        return Some(GuestNaming::Unnamed(UnnamedReason::RecordWithoutName {
            path: format!("pod {}/{}", pod.namespace, pod.name),
        }));
    };
    Some(GuestNaming::Named(GuestIdentity {
        name: format!("{}/{name}", pod.namespace),
        id: label(KUBEVIRT_CREATED_BY_LABEL)
            .unwrap_or_default()
            .to_owned(),
        source: GuestSource::Kubevirt,
        tags: Vec::new(),
    }))
}

/// The KubeVirt guests among `pods`, by pod UID.
#[must_use]
pub fn kubevirt_guests(pods: &[PodSubject]) -> BTreeMap<String, GuestNaming> {
    pods.iter()
        .filter_map(|pod| kubevirt_guest(pod).map(|naming| (pod.uid.clone(), naming)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(attached: bool) -> GuestLink {
        GuestLink {
            ifindex: 9,
            interface: "vnet0".into(),
            kind: "tap".into(),
            attached,
            naming: GuestNaming::Unnamed(UnnamedReason::NoRecord),
        }
    }

    #[test]
    fn an_attached_guest_is_protected_on_the_network_only() {
        let protection = link(true).protection();
        assert_eq!(protection.covered, ["network"]);
        assert_eq!(protection.not_covered, ["process", "dlp"]);
        assert!(
            protection
                .reason
                .starts_with("network only: the guest runs its own kernel")
        );
    }

    #[test]
    fn a_guest_whose_device_is_not_attached_is_not_protected() {
        let protection = link(false).protection();
        assert_eq!(protection.covered.len(), 0);
        assert_eq!(protection.not_covered, ["network", "process", "dlp"]);
        assert!(protection.reason.contains("not even its packets"));
    }

    fn launcher(labels: &[(&str, &str)]) -> PodSubject {
        PodSubject {
            uid: "pod-uid".into(),
            name: "virt-launcher-db-x7k2p".into(),
            namespace: "prod".into(),
            host_network: false,
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn a_launcher_pod_names_its_guest_by_namespace_and_vm() {
        let pod = launcher(&[
            ("kubevirt.io", "virt-launcher"),
            ("vm.kubevirt.io/name", "db"),
            ("kubevirt.io/domain", "db-instance"),
            ("kubevirt.io/created-by", "9d1e7c4a"),
        ]);
        assert_eq!(
            kubevirt_guest(&pod),
            Some(GuestNaming::Named(GuestIdentity {
                name: "prod/db".into(),
                id: "9d1e7c4a".into(),
                source: GuestSource::Kubevirt,
                tags: Vec::new(),
            }))
        );
    }

    #[test]
    fn a_launcher_without_a_vm_falls_back_to_the_instance_name() {
        let pod = launcher(&[
            ("kubevirt.io", "virt-launcher"),
            ("kubevirt.io/domain", "scratch"),
        ]);
        let Some(GuestNaming::Named(identity)) = kubevirt_guest(&pod) else {
            panic!("named");
        };
        assert_eq!(identity.name, "prod/scratch");
        assert_eq!(identity.id, "");
    }

    #[test]
    fn a_launcher_carrying_no_name_is_unnamed_and_never_named_after_its_pod() {
        let pod = launcher(&[("kubevirt.io", "virt-launcher")]);
        assert_eq!(
            kubevirt_guest(&pod),
            Some(GuestNaming::Unnamed(UnnamedReason::RecordWithoutName {
                path: "pod prod/virt-launcher-db-x7k2p".into(),
            }))
        );
    }

    #[test]
    fn a_pod_that_is_not_a_launcher_is_no_guest() {
        assert_eq!(kubevirt_guest(&launcher(&[("app", "db")])), None);
        assert_eq!(
            kubevirt_guest(&launcher(&[
                ("kubevirt.io", "virt-handler"),
                ("vm.kubevirt.io/name", "db")
            ])),
            None
        );
        let guests = kubevirt_guests(&[
            launcher(&[("app", "db")]),
            launcher(&[
                ("kubevirt.io", "virt-launcher"),
                ("vm.kubevirt.io/name", "db"),
            ]),
        ]);
        assert_eq!(guests.len(), 1);
        assert!(guests.contains_key("pod-uid"));
    }

    #[test]
    fn a_guest_key_never_collides_with_a_cgroup_id() {
        assert_eq!(guest_scope_key(7), (1 << 63) | 7);
        assert_ne!(guest_scope_key(7) & GUEST_SCOPE_KEY_BIT, 0);
    }

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
        assert_eq!(GuestSource::Kubevirt.as_str(), "kubevirt");
    }
}
