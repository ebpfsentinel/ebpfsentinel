//! The warden's policy, read off the agent's configuration.
//!
//! `ebpfsentinel-agent warden-policy` is run by the deployment before the
//! warden starts (a systemd `ExecStartPre`, a chart init container, a compose
//! one-shot service), from the same file the agent will read: the families
//! the configuration needs are switched on, fenced by the values it names,
//! and everything else stays off. The agent the warden then serves never
//! writes or reads the policy, so a compromised agent cannot widen it.

use std::net::IpAddr;
use std::path::Path;

use anyhow::Context;
use domain::loadbalancer::vip::AnnounceRole;
use ebpfsentinel_warden::policy::{AnnounceFence, RouteFence, RuntimeFence, WardenPolicy};
use infrastructure::config::AgentConfig;

/// The policy `config` needs.
///
/// Public so a downstream agent build derives the same base and adds the
/// families only it uses.
#[must_use]
pub fn derive(config: &AgentConfig) -> WardenPolicy {
    let file_watch = config.file_watch.enabled;
    let container = &config.container;
    WardenPolicy {
        routes: routes(config),
        announces: announces(config),
        conntrack_restore: false,
        runtimes: RuntimeFence {
            // The DNS allow-list reads the governed containers off Docker,
            // and refuses to load without it.
            docker: container.docker.enabled,
            podman: container.podman.enabled,
            podman_rootless: container.podman.enabled && container.podman.rootless,
        },
        file_watch,
        canaries: if file_watch && config.file_watch.canaries.enabled {
            config.file_watch.canaries.paths()
        } else {
            Vec::new()
        },
        write_refusal: file_watch && config.file_watch.write_refusal.enabled,
        // The DLP probes, and the crypto-call probes the mass encryption
        // engine reads, which runs with the file watch.
        uprobe: config.dlp.enabled || file_watch,
        resolver: if config.dns.allowlist.enabled {
            config.dns.allowlist.listen.into_iter().collect()
        } else {
            Vec::new()
        },
        hidden_ports: config
            .hidden_checks
            .ports
            .enabled
            .then(|| config.hidden_checks.ports.probed_ports()),
        hidden_processes: config.hidden_checks.processes.enabled,
        package_inventory: config.package_inventory.enabled,
        network_inventory: config.network_inventory.enabled,
        extensions: Vec::new(),
    }
}

/// Every configured WAN gateway, enabled or not: a gateway switched on
/// through the API is still one the configuration names.
fn routes(config: &AgentConfig) -> Vec<RouteFence> {
    if !config.routing.enabled {
        return Vec::new();
    }
    config
        .routing
        .gateways
        .iter()
        .filter_map(|g| {
            let gateway = g.gateway_ip.parse::<IpAddr>().ok()?;
            Some(RouteFence {
                interface: g.interface.clone(),
                gateway,
            })
        })
        .collect()
}

/// The VIPs on the announce interface, when this node announces at all.
fn announces(config: &AgentConfig) -> Vec<AnnounceFence> {
    let Ok(announce) = config.loadbalancer.announce.to_domain() else {
        return Vec::new();
    };
    if announce.role == AnnounceRole::Disabled {
        return Vec::new();
    }
    announce
        .vips
        .iter()
        .map(|vip| AnnounceFence {
            interface: announce.interface.clone(),
            address: vip.addr,
        })
        .collect()
}

/// Load the configuration at `config_path` and derive its policy.
///
/// # Errors
///
/// The configuration does not load.
pub fn derive_from_file(config_path: &Path) -> anyhow::Result<WardenPolicy> {
    let config = AgentConfig::load(config_path)
        .with_context(|| format!("load {}", config_path.display()))?;
    Ok(derive(&config))
}

/// Write `policy` to `output`, or to standard output when there is none. The
/// file is replaced in one rename, so a warden starting beside the writer
/// reads the old policy or the new one, never half of one.
///
/// # Errors
///
/// The policy cannot be written.
pub fn write(policy: &WardenPolicy, output: Option<&Path>) -> anyhow::Result<()> {
    let text = serde_json::to_string_pretty(policy).context("encode the warden policy")?;
    let Some(path) = output else {
        println!("{text}");
        return Ok(());
    };
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{text}\n"))
        .with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpfsentinel_warden::policy::Family;

    fn config(yaml: &str) -> AgentConfig {
        AgentConfig::from_yaml(&format!("agent:\n  interfaces: [eth0]\n{yaml}")).expect("config")
    }

    #[test]
    fn a_default_configuration_switches_on_only_what_runs_by_default() {
        let policy = derive(&config(""));
        for family in [
            Family::Routing,
            Family::Neighbour,
            Family::ConntrackRestore,
            Family::Runtime,
            Family::FileWatch,
            Family::WriteRefusal,
            Family::Resolver,
            Family::Extension,
        ] {
            assert!(!policy.families().contains(&family), "{family}");
        }
    }

    #[test]
    fn multi_wan_fences_the_route_to_its_own_gateways() {
        let policy = derive(&config(
            "routing:\n  enabled: true\n  gateways:\n    - id: 1\n      name: a\n      interface: wan1\n      gateway_ip: 192.0.2.1\n    - id: 2\n      name: b\n      interface: wan2\n      gateway_ip: 198.51.100.1\n      enabled: false\n",
        ));
        assert_eq!(
            policy.routes,
            vec![
                RouteFence {
                    interface: "wan1".into(),
                    gateway: "192.0.2.1".parse().expect("ip"),
                },
                RouteFence {
                    interface: "wan2".into(),
                    gateway: "198.51.100.1".parse().expect("ip"),
                },
            ]
        );
        assert!(policy.families().contains(&Family::Routing));
    }

    #[test]
    fn the_announcer_fences_arp_to_its_vips() {
        let policy = derive(&config(
            "loadbalancer:\n  announce:\n    role: primary\n    interface: eth0\n    vips:\n      - name: web\n        addr: 198.51.100.10\n",
        ));
        assert_eq!(
            policy.announces,
            vec![AnnounceFence {
                interface: "eth0".into(),
                address: "198.51.100.10".parse().expect("ip"),
            }]
        );
    }

    #[test]
    fn the_file_watch_brings_the_crypto_probes_and_nothing_it_does_not_name() {
        let policy = derive(&config("file_watch:\n  enabled: true\n"));
        assert!(policy.file_watch);
        assert!(policy.uprobe);
        assert!(policy.canaries.is_empty());
        assert!(!policy.write_refusal);
        assert!(policy.routes.is_empty());
    }

    #[test]
    fn the_allow_list_fences_the_resolver_to_its_address_and_reads_docker() {
        let policy = derive(&config(
            "container:\n  docker:\n    enabled: true\ndns:\n  allowlist:\n    enabled: true\n    listen: 172.17.0.1:53\n    upstream: [9.9.9.9:53]\n",
        ));
        assert_eq!(
            policy.resolver,
            vec!["172.17.0.1:53".parse().expect("addr")]
        );
        assert!(policy.runtimes.docker);
        assert!(!policy.runtimes.podman);
    }

    #[test]
    fn the_hidden_port_sweep_is_fenced_to_its_probed_ports() {
        let cfg = config("hidden_checks:\n  ports:\n    enabled: true\n");
        let policy = derive(&cfg);
        assert_eq!(
            policy.hidden_ports,
            Some(cfg.hidden_checks.ports.probed_ports())
        );
    }

    #[test]
    fn a_written_policy_is_read_back_by_the_warden() {
        let dir = tempfile::tempdir().expect("dir");
        let path = dir.path().join("policy.json");
        let policy = derive(&config(
            "dlp:\n  enabled: true\nnetwork_inventory:\n  enabled: true\n",
        ));
        write(&policy, Some(&path)).expect("write");
        assert_eq!(WardenPolicy::load(&path).expect("load"), policy);
    }
}
