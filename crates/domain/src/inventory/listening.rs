//! What sits behind a listening socket, and who may reach it.
//!
//! A listener is bound by one process, and that process maps a program and
//! its libraries: the packages owning those files are the packages behind
//! the listener. Whether anything off the node may reach it comes from the
//! effective firewall policy, and whether those sources are only private
//! ranges is what separates a listener open to the internet from one open
//! east-west.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::loaded::{LoadedObjects, PackageRef};
use crate::exposure::entity::ListenerScope;
use crate::exposure::reach::Reach;

/// Who may reach a listener, as the policy reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// Some source outside the private ranges is let through.
    Anywhere,
    /// Only sources inside the private and link-local ranges are let through.
    PrivateOnly,
    /// Every packet bound for it is dropped.
    Blocked,
    /// Bound on the loopback: nothing off the node reaches it.
    Loopback,
}

impl Origin {
    /// From the listener's scope and the policy's reading of it.
    #[must_use]
    pub fn of(scope: ListenerScope, reach: &Reach) -> Self {
        if scope == ListenerScope::Loopback {
            return Self::Loopback;
        }
        if !reach.open {
            return Self::Blocked;
        }
        if !reach.allowed_from.is_empty() && reach.allowed_from.iter().all(|s| private(s)) {
            return Self::PrivateOnly;
        }
        Self::Anywhere
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anywhere => "anywhere",
            Self::PrivateOnly => "private_only",
            Self::Blocked => "blocked",
            Self::Loopback => "loopback",
        }
    }
}

/// The ranges no packet from the internet carries as its source.
const PRIVATE_V4: [(Ipv4Addr, u8); 6] = [
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
];

const PRIVATE_V6: [(Ipv6Addr, u8); 3] = [
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
    (Ipv6Addr::LOCALHOST, 128),
];

/// Whether `source`, as the policy writes an allowed source, lies wholly
/// inside a private range. A negated source, an alias or a rule narrowed by
/// something other than its source cannot be shown to, and is not.
fn private(source: &str) -> bool {
    let Some((addr, len)) = source.split_once('/') else {
        return false;
    };
    let (Ok(addr), Ok(len)) = (addr.parse::<IpAddr>(), len.parse::<u8>()) else {
        return false;
    };
    match addr {
        IpAddr::V4(a) => PRIVATE_V4
            .iter()
            .any(|&(net, n)| len >= n && len <= 32 && mask_v4(a, n) == u32::from(net)),
        IpAddr::V6(a) => PRIVATE_V6
            .iter()
            .any(|&(net, n)| len >= n && len <= 128 && mask_v6(a, n) == u128::from(net)),
    }
}

fn mask_v4(addr: Ipv4Addr, len: u8) -> u32 {
    u32::from(addr) & u32::MAX.checked_shl(32 - u32::from(len)).unwrap_or(0)
}

fn mask_v6(addr: Ipv6Addr, len: u8) -> u128 {
    u128::from(addr) & u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0)
}

/// What the process behind a listener maps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Behind {
    /// Whether that process's mappings were read at all.
    pub read: bool,
    /// The packages owning a file it maps, each once, by name.
    pub packages: Vec<PackageRef>,
    /// Files it maps that no package read in its root owns.
    pub unowned: Vec<String>,
}

/// What `pid` maps, by package.
#[must_use]
pub fn behind(loaded: &LoadedObjects, pid: u32) -> Behind {
    let Some(objects) = loaded.of_pid(pid) else {
        return Behind::default();
    };
    let mut out = Behind {
        read: true,
        ..Behind::default()
    };
    for object in objects {
        match &object.owner {
            Some(owner) => {
                if !out.packages.contains(owner) {
                    out.packages.push(owner.clone());
                }
            }
            None => out.unowned.push(object.path.clone()),
        }
    }
    out.packages
        .sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    out.unowned.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exposure::reach::ReachDecision;
    use crate::inventory::entity::{
        DatabaseOutcome, DatabaseReading, Package, PackageManager, PackageState, RootInventory,
        RootScope,
    };
    use crate::inventory::loaded::{MappedObject, ProcessObjects, loaded_objects};
    use std::sync::Arc;

    fn reach(open: bool, allowed_from: &[&str]) -> Reach {
        Reach {
            open,
            allowed_from: allowed_from.iter().map(ToString::to_string).collect(),
            decided_by: ReachDecision::DefaultPolicy { drop: !open },
        }
    }

    #[test]
    fn a_listener_open_to_private_ranges_only_is_east_west() {
        let all = ListenerScope::AllAddresses;
        assert_eq!(Origin::of(all, &reach(true, &[])), Origin::Anywhere);
        assert_eq!(
            Origin::of(
                all,
                &reach(true, &["10.0.0.0/8", "192.168.4.0/24", "fd00::/8"])
            ),
            Origin::PrivateOnly
        );
        assert_eq!(
            Origin::of(all, &reach(true, &["10.0.0.0/8", "203.0.113.0/24"])),
            Origin::Anywhere
        );
        // Wider than a private range is not inside it.
        assert_eq!(
            Origin::of(all, &reach(true, &["10.0.0.0/7"])),
            Origin::Anywhere
        );
        assert_eq!(
            Origin::of(all, &reach(true, &["172.32.0.0/16"])),
            Origin::Anywhere
        );
        // What cannot be shown to be private is not.
        for source in ["not 10.0.0.0/8", "alias office", "any (rule r1)"] {
            assert_eq!(
                Origin::of(all, &reach(true, &[source])),
                Origin::Anywhere,
                "{source}"
            );
        }
        assert_eq!(Origin::of(all, &reach(false, &[])), Origin::Blocked);
        assert_eq!(
            Origin::of(ListenerScope::Loopback, &reach(true, &[])),
            Origin::Loopback
        );
    }

    fn package(name: &str, files: &[&str]) -> Package {
        Package {
            manager: PackageManager::Dpkg,
            name: name.into(),
            version: "1.0".into(),
            arch: None,
            state: PackageState::Installed,
            files: Some(files.iter().map(ToString::to_string).collect()),
        }
    }

    fn object(ino: u64, path: &str) -> Arc<MappedObject> {
        Arc::new(MappedObject {
            dev: 1,
            ino,
            path: path.into(),
            deleted: false,
        })
    }

    #[test]
    fn the_packages_behind_a_listener_are_those_its_process_maps() {
        let roots = [RootInventory {
            scope: RootScope::Host,
            pid: 1,
            databases: vec![DatabaseReading {
                manager: PackageManager::Dpkg,
                path: "/var/lib/dpkg/status".into(),
                outcome: DatabaseOutcome::Read {
                    packages: vec![
                        package("nginx", &["/usr/sbin/nginx"]),
                        package(
                            "libc6",
                            &[
                                "/lib/x86_64-linux-gnu/libc.so.6",
                                "/lib/x86_64-linux-gnu/libm.so.6",
                            ],
                        ),
                        package("libssl3t64", &["/usr/lib/x86_64-linux-gnu/libssl.so.3"]),
                    ],
                },
            }],
            error: None,
        }];
        let libc = object(2, "/usr/lib/x86_64-linux-gnu/libc.so.6");
        let libm = object(3, "/usr/lib/x86_64-linux-gnu/libm.so.6");
        let processes = [
            ProcessObjects {
                pid: 80,
                root_pid: Some(1),
                objects: vec![
                    object(1, "/usr/sbin/nginx"),
                    Arc::clone(&libc),
                    libm,
                    object(9, "/opt/module.so"),
                ],
            },
            ProcessObjects {
                pid: 81,
                root_pid: Some(1),
                objects: vec![libc, object(4, "/usr/lib/x86_64-linux-gnu/libssl.so.3")],
            },
        ];
        let loaded = loaded_objects(&roots, &processes);
        let nginx = behind(&loaded, 80);
        assert!(nginx.read);
        let names: Vec<_> = nginx.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["libc6", "nginx"], "libc6 once for two of its files");
        assert_eq!(nginx.unowned, ["/opt/module.so"]);
        let other: Vec<_> = behind(&loaded, 81)
            .packages
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(other, ["libc6", "libssl3t64"]);
        assert_eq!(behind(&loaded, 82), Behind::default(), "not read");
    }
}
