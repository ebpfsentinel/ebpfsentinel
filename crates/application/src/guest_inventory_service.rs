//! The virtual machines whose devices the link watcher found on this host.
//!
//! The link watcher reports every workload link; this service keeps the tap
//! and macvtap devices among them and names each guest when asked, from the
//! hypervisor records as they stand at that moment. Naming is never done at
//! the moment the device appears, because libvirt writes the record naming
//! the guest after it made the device.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use domain::coverage::{LinkAttachment, WorkloadLink};
use domain::guest::{GuestLink, is_guest_kind};
use ports::secondary::guest_naming_port::GuestNamingPort;
use ports::secondary::pod_coverage_port::LinkCoverageSink;

/// Holds the guests' devices and names them on demand.
pub struct GuestInventoryService {
    namer: Arc<dyn GuestNamingPort>,
    links: Mutex<HashMap<u32, WorkloadLink>>,
}

impl GuestInventoryService {
    #[must_use]
    pub fn new(namer: Arc<dyn GuestNamingPort>) -> Self {
        Self {
            namer,
            links: Mutex::new(HashMap::new()),
        }
    }

    /// Every guest device held, by interface name, each with the guest it
    /// belongs to or the reason none is named.
    #[must_use]
    pub fn guests(&self) -> Vec<GuestLink> {
        let links: Vec<WorkloadLink> = self
            .links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .cloned()
            .collect();
        let mut guests: Vec<GuestLink> = links
            .into_iter()
            .map(|link| GuestLink {
                naming: self.namer.name_guest(&link.name),
                attached: link.attachment == LinkAttachment::Attached,
                ifindex: link.ifindex,
                interface: link.name,
                kind: link.kind,
            })
            .collect();
        guests.sort_by(|a, b| a.interface.cmp(&b.interface));
        guests
    }
}

impl LinkCoverageSink for GuestInventoryService {
    fn link_seen(&self, link: WorkloadLink) {
        let mut links = self.links.lock().unwrap_or_else(PoisonError::into_inner);
        if is_guest_kind(&link.kind) {
            links.insert(link.ifindex, link);
        } else {
            // An index reused by a device of another kind is no longer a
            // guest's.
            links.remove(&link.ifindex);
        }
    }

    fn link_forgotten(&self, ifindex: u32) {
        self.links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ifindex);
    }

    fn node_encapsulates(&self, _encapsulated: bool) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain::coverage::LinkRefusal;
    use domain::guest::{GuestIdentity, GuestNaming, GuestSource, UnnamedReason};

    struct Namer;

    impl GuestNamingPort for Namer {
        fn name_guest(&self, interface: &str) -> GuestNaming {
            if interface == "tap101i0" {
                GuestNaming::Named(GuestIdentity {
                    name: "web-01".into(),
                    id: "101".into(),
                    source: GuestSource::Proxmox,
                    tags: vec!["prod".into()],
                })
            } else {
                GuestNaming::Unnamed(UnnamedReason::NoRecord)
            }
        }
    }

    fn link(ifindex: u32, name: &str, kind: &str, attachment: LinkAttachment) -> WorkloadLink {
        WorkloadLink {
            ifindex,
            name: name.into(),
            kind: kind.into(),
            attachment,
            pod_uid: None,
        }
    }

    #[test]
    fn only_guest_devices_are_held_and_each_is_named_when_asked() {
        let service = GuestInventoryService::new(Arc::new(Namer));
        service.link_seen(link(5, "vethab12", "veth", LinkAttachment::Attached));
        service.link_seen(link(7, "tap101i0", "tap", LinkAttachment::Attached));
        service.link_seen(link(
            9,
            "macvtap0",
            "macvtap",
            LinkAttachment::Refused(LinkRefusal::ProgramsRefused { attached: 1, of: 2 }),
        ));

        let guests = service.guests();
        assert_eq!(guests.len(), 2);
        assert_eq!(guests[0].interface, "macvtap0");
        assert!(!guests[0].attached);
        assert_eq!(
            guests[0].naming,
            GuestNaming::Unnamed(UnnamedReason::NoRecord)
        );
        assert_eq!(guests[1].interface, "tap101i0");
        assert!(guests[1].attached);
        assert!(matches!(&guests[1].naming, GuestNaming::Named(g) if g.name == "web-01"));

        service.link_forgotten(7);
        service.link_seen(link(9, "veth9", "veth", LinkAttachment::Attached));
        assert_eq!(service.guests().len(), 0);
    }
}
