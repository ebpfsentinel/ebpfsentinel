//! The virtual machines whose devices the link watcher found on this host.
//!
//! The link watcher reports every workload link; this service keeps the tap
//! and macvtap devices among them and names each guest from the hypervisor
//! records as they stand when asked. A name read when the device appeared is
//! never the last word, because libvirt writes the record naming the guest
//! after it made the device: whatever enforces a policy naming a guest is
//! told the named guests again on a timer, so a record written late is
//! picked up on the next refresh.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use domain::coverage::{LinkAttachment, WorkloadLink};
use domain::guest::{GuestLink, GuestNaming, is_guest_kind};
use ports::secondary::guest_naming_port::GuestNamingPort;
use ports::secondary::ids_workload_scope_port::GuestScopeSink;
use ports::secondary::pod_coverage_port::LinkCoverageSink;

/// Holds the guests' devices and names them on demand.
pub struct GuestInventoryService {
    namer: Arc<dyn GuestNamingPort>,
    links: Mutex<HashMap<u32, WorkloadLink>>,
    scope: Option<Arc<dyn GuestScopeSink>>,
}

impl GuestInventoryService {
    #[must_use]
    pub fn new(namer: Arc<dyn GuestNamingPort>) -> Self {
        Self {
            namer,
            links: Mutex::new(HashMap::new()),
            scope: None,
        }
    }

    /// Tell `scope` which guest each device belongs to, on every change and
    /// every [`Self::refresh_scope`].
    #[must_use]
    pub fn with_scope(mut self, scope: Arc<dyn GuestScopeSink>) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Name every guest device again and tell the scope the result.
    ///
    /// The hypervisor writes the record naming a guest after it made the
    /// device, and renames happen, so a name read when the device appeared
    /// is not trusted for long: this is called when a device comes and goes
    /// and on a timer.
    pub fn refresh_scope(&self) {
        let Some(scope) = &self.scope else {
            return;
        };
        let named = self
            .guests()
            .into_iter()
            .filter_map(|guest| match guest.naming {
                GuestNaming::Named(identity) => Some((guest.ifindex, identity)),
                GuestNaming::Unnamed(_) => None,
            })
            .collect();
        scope.guests_named(named);
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
        let changed = if is_guest_kind(&link.kind) {
            links.insert(link.ifindex, link).is_none()
        } else {
            // An index reused by a device of another kind is no longer a
            // guest's.
            links.remove(&link.ifindex).is_some()
        };
        drop(links);
        if changed {
            self.refresh_scope();
        }
    }

    fn link_forgotten(&self, ifindex: u32) {
        let removed = self
            .links
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ifindex)
            .is_some();
        if removed {
            self.refresh_scope();
        }
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

    #[derive(Default)]
    struct Scope(Mutex<Vec<Vec<(u32, String)>>>);

    impl GuestScopeSink for Scope {
        fn guests_named(&self, guests: Vec<(u32, GuestIdentity)>) {
            self.0
                .lock()
                .unwrap()
                .push(guests.into_iter().map(|(i, g)| (i, g.name)).collect());
        }
    }

    #[test]
    fn the_scope_is_told_the_named_guests_only_and_again_on_refresh() {
        let scope = Arc::new(Scope::default());
        let service = GuestInventoryService::new(Arc::new(Namer))
            .with_scope(Arc::clone(&scope) as Arc<dyn GuestScopeSink>);
        service.link_seen(link(5, "vethab12", "veth", LinkAttachment::Attached));
        assert_eq!(scope.0.lock().unwrap().len(), 0);
        service.link_seen(link(7, "tap101i0", "tap", LinkAttachment::Attached));
        service.link_seen(link(9, "tap9", "tap", LinkAttachment::Attached));
        service.refresh_scope();
        service.link_forgotten(7);
        let told = scope.0.lock().unwrap();
        assert_eq!(told.len(), 4);
        assert_eq!(told[0], vec![(7, "web-01".to_string())]);
        assert_eq!(told[2], vec![(7, "web-01".to_string())]);
        assert_eq!(told[3].len(), 0);
    }
}
