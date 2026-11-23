//! What the warden serves on this node.
//!
//! The policy is read once, at start, from the file `--policy` names, and is
//! never changed afterwards: an agent that is compromised cannot widen what
//! its warden does for it, because nothing it sends reaches the policy. The
//! file is written before the warden starts by `ebpfsentinel-agent
//! warden-policy`, run by the deployment from the same configuration the
//! agent reads, never by the agent the warden serves.
//!
//! Every command belongs to one [`Family`] or to none. A command in no family
//! is served to any agent (see [`Family`] for which those are). A command in a
//! family is served only when the family is on, and the families that carry
//! an address, an interface, a port or a path are fenced by the values the
//! configuration names: a Multi-WAN agent may move the default route to one
//! of its own gateways, never to another.
//!
//! Without `--policy` the warden serves the commands in no family and nothing
//! else.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

pub use ebpfsentinel_warden_proto::Family;
use ebpfsentinel_warden_proto::{Command, RootRuntime, RouteSpec};
use serde::{Deserialize, Serialize};

/// The default route a Multi-WAN agent may install: through `gateway` on
/// `interface`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteFence {
    pub interface: String,
    pub gateway: IpAddr,
}

/// A VIP the announcer may claim, `address` on `interface`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnnounceFence {
    pub interface: String,
    pub address: IpAddr,
}

/// The container runtimes the agent reads for attribution.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RuntimeFence {
    /// Root's Docker API, through the relay that forwards reads only.
    pub docker: bool,
    /// Root's Podman API through the same relay, and the container stores.
    pub podman: bool,
    /// The rootless Podman API of each user.
    pub podman_rootless: bool,
}

/// What one warden serves. Every field off or empty is the policy of a
/// warden started without one.
// One switch per family, as the file writes them: an enum per switch would
// only rename `true`.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WardenPolicy {
    /// The default routes the Multi-WAN failover may install; none turns
    /// routing off.
    pub routes: Vec<RouteFence>,
    /// The VIPs the announcer may claim; none turns announcing off.
    pub announces: Vec<AnnounceFence>,
    /// Whether flows taken over from a failed HA peer are written into the
    /// conntrack table.
    pub conntrack_restore: bool,
    /// The container runtimes read.
    pub runtimes: RuntimeFence,
    /// Whether the file watch is opened.
    pub file_watch: bool,
    /// The only paths a canary may be planted at.
    pub canaries: Vec<String>,
    /// Whether the fanotify write refusal group is handed over.
    pub write_refusal: bool,
    /// Whether uprobes are attached and the TLS libraries looked for.
    pub uprobe: bool,
    /// The only addresses the DNS allow-list resolver may be bound on; none
    /// turns the resolver off.
    pub resolver: Vec<SocketAddr>,
    /// The only ports the hidden port sweep may bind; `None` turns it off.
    pub hidden_ports: Option<Vec<u16>>,
    /// Whether the hidden process sweep runs.
    pub hidden_processes: bool,
    /// Whether the package inventory reads the package databases.
    pub package_inventory: bool,
    /// Whether the network inventory lists packet sockets and programs.
    pub network_inventory: bool,
    /// The extension kinds a downstream warden build serves.
    pub extensions: Vec<String>,
}

/// Why a command was not served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub family: Family,
    pub reason: String,
}

impl Refusal {
    fn off(family: Family) -> Self {
        Self {
            family,
            reason: format!("the {family} family is off in this warden's policy"),
        }
    }

    fn fence(family: Family, reason: String) -> Self {
        Self { family, reason }
    }
}

impl WardenPolicy {
    /// Read the policy file at `path`.
    ///
    /// # Errors
    ///
    /// The file cannot be read, is not a policy, or names a field this
    /// warden does not know: a policy is refused whole rather than read in
    /// part, so a field a newer agent writes never goes silently unenforced.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("read policy {}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("parse policy {}: {e}", path.display()))
    }

    /// The families this policy switches on, for the start-up log.
    #[must_use]
    pub fn families(&self) -> Vec<Family> {
        let mut on = Vec::new();
        let mut push = |cond: bool, family| {
            if cond {
                on.push(family);
            }
        };
        push(!self.routes.is_empty(), Family::Routing);
        push(!self.announces.is_empty(), Family::Neighbour);
        push(self.conntrack_restore, Family::ConntrackRestore);
        push(
            self.runtimes.docker || self.runtimes.podman || self.runtimes.podman_rootless,
            Family::Runtime,
        );
        push(self.file_watch, Family::FileWatch);
        push(self.write_refusal, Family::WriteRefusal);
        push(self.uprobe, Family::Uprobe);
        push(!self.resolver.is_empty(), Family::Resolver);
        push(self.hidden_ports.is_some(), Family::HiddenPorts);
        push(self.hidden_processes, Family::HiddenProcesses);
        push(self.package_inventory, Family::PackageInventory);
        push(self.network_inventory, Family::NetworkInventory);
        push(!self.extensions.is_empty(), Family::Extension);
        on
    }

    /// Whether `cmd` is served, and if not, why.
    ///
    /// # Errors
    ///
    /// The command's family is off, or one of its parameters lies outside
    /// what the policy names.
    pub fn check(&self, cmd: &Command) -> Result<(), Refusal> {
        let Some(family) = cmd.family() else {
            return Ok(());
        };
        match cmd {
            Command::RouteAdd { route } => self.check_route(route, family),
            Command::ArpAnnounce { iface, ip } => self.check_announce(iface, ip, family),
            Command::ConntrackRestore { .. } => on(self.conntrack_restore, family),
            Command::ConnectRootRuntime { runtime } => match runtime {
                RootRuntime::Docker => fenced(
                    self.runtimes.docker,
                    family,
                    "the Docker runtime is not configured",
                ),
                RootRuntime::Podman => fenced(
                    self.runtimes.podman,
                    family,
                    "the Podman runtime is not configured",
                ),
            },
            Command::ConnectPodman { .. } => fenced(
                self.runtimes.podman_rootless,
                family,
                "rootless Podman is not configured",
            ),
            Command::ReadPodmanRecord { .. } => fenced(
                self.runtimes.podman,
                family,
                "the Podman runtime is not configured",
            ),
            Command::FimCanaries { paths } => {
                on(self.file_watch, family)?;
                match paths.iter().find(|p| !self.canaries.contains(p)) {
                    None => Ok(()),
                    Some(path) => Err(Refusal::fence(
                        family,
                        format!("{path} is not a configured canary"),
                    )),
                }
            }
            Command::FimOpen { .. } | Command::FimRead { .. } | Command::FimFacts { .. } => {
                on(self.file_watch, family)
            }
            Command::WriteRefusalGroup => on(self.write_refusal, family),
            Command::AttachUprobe { .. } | Command::DlpScan => on(self.uprobe, family),
            Command::ResolverSocket { listen, .. } => {
                if self.resolver.is_empty() {
                    return Err(Refusal::off(family));
                }
                if self.resolver.contains(listen) {
                    Ok(())
                } else {
                    Err(Refusal::fence(
                        family,
                        format!("{listen} is not the configured resolver address"),
                    ))
                }
            }
            Command::HiddenPorts { ports } => {
                let Some(allowed) = &self.hidden_ports else {
                    return Err(Refusal::off(family));
                };
                match ports.iter().find(|p| !allowed.contains(p)) {
                    None => Ok(()),
                    Some(port) => Err(Refusal::fence(
                        family,
                        format!("port {port} is not among the configured probed ports"),
                    )),
                }
            }
            Command::HiddenProcesses { .. } => on(self.hidden_processes, family),
            Command::FileRoots
            | Command::ReadRootedFile { .. }
            | Command::GoExecutables
            | Command::ProcessMappings { .. } => on(self.package_inventory, family),
            Command::PacketSockets | Command::NetworkPrograms => on(self.network_inventory, family),
            Command::Extension { kind, .. } => {
                if self.extensions.is_empty() {
                    return Err(Refusal::off(family));
                }
                if self.extensions.iter().any(|k| k == kind) {
                    Ok(())
                } else {
                    Err(Refusal::fence(
                        family,
                        format!("extension {kind:?} is not served"),
                    ))
                }
            }
            // Every other command is in no family and returned above.
            _ => Ok(()),
        }
    }
}

impl WardenPolicy {
    fn check_route(&self, route: &RouteSpec, family: Family) -> Result<(), Refusal> {
        if self.routes.is_empty() {
            return Err(Refusal::off(family));
        }
        let gateway = route.gateway.parse::<IpAddr>().ok();
        let named = self
            .routes
            .iter()
            .any(|r| r.interface == route.iface && Some(r.gateway) == gateway);
        if named {
            Ok(())
        } else {
            Err(Refusal::fence(
                family,
                format!(
                    "gateway {} on {} is not a configured WAN gateway",
                    route.gateway, route.iface
                ),
            ))
        }
    }

    fn check_announce(&self, iface: &str, ip: &str, family: Family) -> Result<(), Refusal> {
        if self.announces.is_empty() {
            return Err(Refusal::off(family));
        }
        let address = ip.parse::<IpAddr>().ok();
        let named = self
            .announces
            .iter()
            .any(|a| a.interface == iface && Some(a.address) == address);
        if named {
            Ok(())
        } else {
            Err(Refusal::fence(
                family,
                format!("{ip} on {iface} is not a configured VIP"),
            ))
        }
    }
}

fn on(cond: bool, family: Family) -> Result<(), Refusal> {
    if cond {
        Ok(())
    } else {
        Err(Refusal::off(family))
    }
}

fn fenced(cond: bool, family: Family, reason: &str) -> Result<(), Refusal> {
    if cond {
        Ok(())
    } else {
        Err(Refusal::fence(family, reason.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpfsentinel_warden_proto::{ConntrackRestore, ConntrackTuple};

    fn route(iface: &str, gateway: &str) -> Command {
        Command::RouteAdd {
            route: RouteSpec {
                dst_cidr: "0.0.0.0/0".into(),
                gateway: gateway.into(),
                iface: iface.into(),
                table: 254,
            },
        }
    }

    fn restore() -> Command {
        let tuple = ConntrackTuple {
            proto: 6,
            src_ip: "10.0.0.1".into(),
            dst_ip: "10.0.0.2".into(),
            src_port: 1000,
            dst_port: 80,
        };
        Command::ConntrackRestore {
            restore: ConntrackRestore {
                flow: tuple.clone(),
                reply: Some(tuple),
            },
        }
    }

    /// A policy with every family on, each fence naming one value.
    fn full() -> WardenPolicy {
        WardenPolicy {
            routes: vec![RouteFence {
                interface: "wan1".into(),
                gateway: "192.0.2.1".parse().expect("ip"),
            }],
            announces: vec![AnnounceFence {
                interface: "eth0".into(),
                address: "198.51.100.10".parse().expect("ip"),
            }],
            conntrack_restore: true,
            runtimes: RuntimeFence {
                docker: true,
                podman: true,
                podman_rootless: true,
            },
            file_watch: true,
            canaries: vec!["/srv/data/.canary".into()],
            write_refusal: true,
            uprobe: true,
            resolver: vec!["10.0.0.53:53".parse().expect("addr")],
            hidden_ports: Some(vec![22, 443]),
            hidden_processes: true,
            package_inventory: true,
            network_inventory: true,
            extensions: vec!["vendor.op.v1".into()],
        }
    }

    /// One command of each family, inside every fence `full` sets.
    fn inside() -> Vec<Command> {
        vec![
            route("wan1", "192.0.2.1"),
            Command::ArpAnnounce {
                iface: "eth0".into(),
                ip: "198.51.100.10".into(),
            },
            restore(),
            Command::ConnectRootRuntime {
                runtime: RootRuntime::Docker,
            },
            Command::ConnectRootRuntime {
                runtime: RootRuntime::Podman,
            },
            Command::ConnectPodman { uid: 1000 },
            Command::ReadPodmanRecord {
                uid: None,
                store: "/var/lib/containers/storage".into(),
                id: "a".repeat(64),
            },
            Command::FimOpen {
                paths: vec!["/".into()],
            },
            Command::FimRead { max_wait_ms: 10 },
            Command::FimFacts {
                paths: vec!["/etc/passwd".into()],
                max_hash_bytes: 1,
            },
            Command::FimCanaries {
                paths: vec!["/srv/data/.canary".into()],
            },
            Command::WriteRefusalGroup,
            Command::AttachUprobe {
                path: "/usr/lib/libssl.so.3".into(),
                offset: 0,
                is_ret: false,
            },
            Command::DlpScan,
            Command::ResolverSocket {
                listen: "10.0.0.53:53".parse().expect("addr"),
                stream: false,
            },
            Command::HiddenPorts {
                ports: vec![22, 443],
            },
            Command::HiddenProcesses { rate: 100 },
            Command::FileRoots,
            Command::GoExecutables,
            Command::ProcessMappings { known: vec![] },
            Command::PacketSockets,
            Command::NetworkPrograms,
            Command::Extension {
                kind: "vendor.op.v1".into(),
                payload: vec![],
            },
        ]
    }

    #[test]
    fn every_family_is_served_inside_its_fence() {
        let policy = full();
        for cmd in inside() {
            assert_eq!(policy.check(&cmd), Ok(()), "{cmd:?}");
        }
    }

    #[test]
    fn every_family_is_refused_by_an_empty_policy() {
        let policy = WardenPolicy::default();
        for cmd in inside() {
            let family = cmd.family().expect("in a family");
            let refusal = policy.check(&cmd).expect_err("refused");
            assert_eq!(refusal.family, family, "{cmd:?}");
        }
    }

    #[test]
    fn a_command_in_no_family_is_served_by_an_empty_policy() {
        let policy = WardenPolicy::default();
        for cmd in [
            Command::Delegate,
            Command::Identity,
            Command::NamespaceIds,
            Command::ConntrackDump,
            Command::ConntrackFlush,
            Command::PinnedLinks,
            Command::ReadExecutable { pid: 1 },
            Command::TcxChain {
                iface: "eth0".into(),
                egress: false,
            },
        ] {
            assert_eq!(policy.check(&cmd), Ok(()), "{cmd:?}");
        }
    }

    #[test]
    fn a_parameter_outside_its_fence_is_refused_with_the_family_on() {
        let policy = full();
        let outside = [
            (route("wan1", "203.0.113.1"), Family::Routing),
            (route("eth9", "192.0.2.1"), Family::Routing),
            (route("wan1", "not-an-address"), Family::Routing),
            (
                Command::ArpAnnounce {
                    iface: "eth0".into(),
                    ip: "198.51.100.11".into(),
                },
                Family::Neighbour,
            ),
            (
                Command::ArpAnnounce {
                    iface: "eth1".into(),
                    ip: "198.51.100.10".into(),
                },
                Family::Neighbour,
            ),
            (
                Command::FimCanaries {
                    paths: vec!["/srv/data/.canary".into(), "/etc/cron.d/x".into()],
                },
                Family::FileWatch,
            ),
            (
                Command::ResolverSocket {
                    listen: "10.0.0.54:53".parse().expect("addr"),
                    stream: true,
                },
                Family::Resolver,
            ),
            (
                Command::HiddenPorts {
                    ports: vec![22, 8080],
                },
                Family::HiddenPorts,
            ),
            (
                Command::Extension {
                    kind: "vendor.other.v1".into(),
                    payload: vec![],
                },
                Family::Extension,
            ),
        ];
        for (cmd, family) in outside {
            let refusal = policy.check(&cmd).expect_err("outside the fence");
            assert_eq!(refusal.family, family, "{cmd:?}");
            assert!(!refusal.reason.contains("is off"), "{}", refusal.reason);
        }
    }

    #[test]
    fn each_runtime_is_switched_on_its_own() {
        let policy = WardenPolicy {
            runtimes: RuntimeFence {
                docker: true,
                podman: false,
                podman_rootless: false,
            },
            ..WardenPolicy::default()
        };
        assert_eq!(
            policy.check(&Command::ConnectRootRuntime {
                runtime: RootRuntime::Docker
            }),
            Ok(())
        );
        assert!(
            policy
                .check(&Command::ConnectRootRuntime {
                    runtime: RootRuntime::Podman
                })
                .is_err()
        );
        assert!(policy.check(&Command::ConnectPodman { uid: 1000 }).is_err());
    }

    #[test]
    fn an_ipv6_gateway_is_matched_whatever_its_spelling() {
        let policy = WardenPolicy {
            routes: vec![RouteFence {
                interface: "wan1".into(),
                gateway: "2001:db8::1".parse().expect("ip"),
            }],
            ..WardenPolicy::default()
        };
        assert_eq!(policy.check(&route("wan1", "2001:0db8:0::1")), Ok(()));
    }

    #[test]
    fn a_policy_naming_an_unknown_field_is_refused_whole() {
        let dir = std::env::temp_dir().join(format!("warden-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("policy.json");
        std::fs::write(&path, r#"{"file_watch": true, "everything": true}"#).expect("write");
        assert!(WardenPolicy::load(&path).is_err());
        std::fs::write(&path, r#"{"file_watch": true}"#).expect("write");
        let policy = WardenPolicy::load(&path).expect("loads");
        assert_eq!(policy.families(), vec![Family::FileWatch]);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_full_policy_names_every_family() {
        assert_eq!(full().families().len(), 13);
        assert!(WardenPolicy::default().families().is_empty());
    }
}
