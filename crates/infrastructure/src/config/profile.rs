//! The profile an agent runs under: beside a node, or inside the pods a
//! selector names.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::AgentConfig;
use super::common::ConfigError;

/// Where this agent attaches.
///
/// `node` is the agent as it has always been: the node's uplinks and the host
/// side of every workload link. `pod` attaches inside the network namespace of
/// each pod its selector names, which is the only place a pod's loopback and a
/// link the host side refused are visible. It runs beside a node agent, never
/// instead of one, so everything that belongs to the node is refused rather
/// than silently loaded twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProfile {
    #[default]
    Node,
    Pod,
}

impl AgentProfile {
    /// The name the configuration and the API use.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Pod => "pod",
        }
    }
}

/// The pods a `pod` profile agent attaches inside.
///
/// Both halves narrow: a pod is selected when it is in one of `namespaces`
/// (any namespace when empty) and carries every label in `match_labels`. At
/// least one of the two must say something, because a selector naming nothing
/// would put a program in every pod on the node, which is the node agent's
/// job done at a far higher cost.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PodSelectorConfig {
    #[serde(default)]
    pub namespaces: Vec<String>,

    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

impl PodSelectorConfig {
    /// Whether a pod in `namespace` carrying `labels` is selected.
    #[must_use]
    pub fn selects(&self, namespace: &str, labels: &BTreeMap<String, String>) -> bool {
        (self.namespaces.is_empty() || self.namespaces.iter().any(|n| n == namespace))
            && self
                .match_labels
                .iter()
                .all(|(key, value)| labels.get(key) == Some(value))
    }
}

/// Top-level sections that belong to the node and have no meaning inside a
/// pod: the XDP programs sit on the uplink, NAT, routing and shaping decide
/// for the node, and the cgroup, tracepoint and uprobe programs are node-wide,
/// so a second copy would see every event the node agent already sees.
pub const POD_REFUSED_SECTIONS: &[&str] = &[
    "firewall",
    "ratelimit",
    "ddos",
    "loadbalancer",
    "nat",
    "routing",
    "qos",
    "zones",
    "interface_groups",
    "dlp",
    "attribution",
    "process_table",
    "auto_capture",
];

impl AgentConfig {
    /// The node sections and whether each is on, in the order of
    /// [`POD_REFUSED_SECTIONS`].
    fn node_sections(&self) -> [(&'static str, bool); 13] {
        [
            ("firewall", self.firewall.enabled),
            ("ratelimit", self.ratelimit.enabled),
            ("ddos", self.ddos.enabled),
            ("loadbalancer", self.loadbalancer.enabled),
            ("nat", self.nat.enabled),
            ("routing", self.routing.enabled),
            ("qos", self.qos.enabled),
            ("zones", self.zones.enabled),
            ("interface_groups", !self.interface_groups.is_empty()),
            ("dlp", self.dlp.enabled),
            ("attribution", self.attribution.enabled),
            ("process_table", self.process_table.enabled),
            ("auto_capture", self.auto_capture.enabled),
        ]
    }

    /// Refuse a node section written in a `pod` profile file, then turn off
    /// the ones left at their defaults, several of which are on.
    ///
    /// A section in the file is refused rather than ignored: somebody wrote a
    /// firewall into a configuration that would never load it, and saying so
    /// at startup is the difference between a rule they know is absent and
    /// one they believe is enforced.
    pub(super) fn apply_pod_profile(
        &mut self,
        raw: &serde_norway::Value,
    ) -> Result<(), ConfigError> {
        if let Some(map) = raw.as_mapping() {
            for section in POD_REFUSED_SECTIONS {
                if map.contains_key(*section) {
                    return Err(refused(section));
                }
            }
        }
        if let Some(response) = raw.get("response")
            && response.get("kill_process").is_some()
        {
            return Err(refused("response.kill_process"));
        }
        self.firewall.enabled = false;
        self.ratelimit.enabled = false;
        self.ddos.enabled = false;
        self.loadbalancer.enabled = false;
        self.nat.enabled = false;
        self.routing.enabled = false;
        self.qos.enabled = false;
        self.zones.enabled = false;
        self.dlp.enabled = false;
        self.attribution.enabled = false;
        self.process_table.enabled = false;
        self.auto_capture.enabled = false;
        self.response.kill_process.enabled = false;
        Ok(())
    }

    /// What each profile requires of the agent block, and in a `pod` profile
    /// that no node section came back on through a reload.
    pub(super) fn validate_profile(&self) -> Result<(), ConfigError> {
        if let Some(dir) = &self.agent.pod_claims_dir
            && !std::path::Path::new(dir).is_absolute()
        {
            return Err(ConfigError::Validation {
                field: "agent.pod_claims_dir".to_string(),
                message: "the pod claims directory must be an absolute path, the same one \
                          on every agent of the node"
                    .to_string(),
            });
        }
        match self.agent.profile {
            AgentProfile::Node => {
                if self.agent.interfaces.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "agent.interfaces".to_string(),
                        message: "at least one interface is required".to_string(),
                    });
                }
                if self.agent.pod_selector.is_some() {
                    return Err(ConfigError::Validation {
                        field: "agent.pod_selector".to_string(),
                        message: "a pod selector is read only with profile: pod".to_string(),
                    });
                }
            }
            AgentProfile::Pod => {
                if !self.agent.interfaces.is_empty() {
                    return Err(ConfigError::Validation {
                        field: "agent.interfaces".to_string(),
                        message: "a pod profile attaches inside each selected pod and names \
                                  no interface of its own; the node's uplinks belong to the \
                                  node agent"
                            .to_string(),
                    });
                }
                let named = self.agent.pod_selector.as_ref().is_some_and(|selector| {
                    !selector.namespaces.is_empty() || !selector.match_labels.is_empty()
                });
                if !named {
                    return Err(ConfigError::Validation {
                        field: "agent.pod_selector".to_string(),
                        message: "a pod profile must name the pods it attaches inside, by \
                                  namespace, by label or both"
                            .to_string(),
                    });
                }
                if let Some((section, _)) = self.node_sections().into_iter().find(|(_, on)| *on) {
                    return Err(refused(section));
                }
                if self.response.kill_process.enabled {
                    return Err(refused("response.kill_process"));
                }
                if !self.container.kubernetes.enabled {
                    return Err(ConfigError::Validation {
                        field: "container.kubernetes.enabled".to_string(),
                        message: "a pod profile selects its pods from the Kubernetes pod \
                                  inventory, which is read only with the Kubernetes enricher on"
                            .to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn refused(section: &str) -> ConfigError {
    ConfigError::Validation {
        field: section.to_string(),
        message: "belongs to the node agent and is refused under profile: pod, which runs \
                  beside it inside the selected pods"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POD: &str = "agent:\n  profile: pod\n  interfaces: []\n  pod_selector:\n    \
                       namespaces: [shop]\ncontainer:\n  kubernetes:\n    enabled: true\n";

    #[test]
    fn the_pod_claims_directory_is_read_under_both_profiles_and_must_be_absolute() {
        let config = AgentConfig::from_yaml(&POD.replace(
            "profile: pod\n",
            "profile: pod\n  pod_claims_dir: /run/ebpfsentinel-claims\n",
        ))
        .unwrap();
        assert_eq!(
            config.agent.pod_claims_dir.as_deref(),
            Some("/run/ebpfsentinel-claims")
        );
        let node = AgentConfig::from_yaml(
            "agent:\n  interfaces: [eth0]\n  pod_claims_dir: /run/ebpfsentinel-claims\n",
        )
        .unwrap();
        assert!(node.agent.pod_claims_dir.is_some());
        let err =
            AgentConfig::from_yaml("agent:\n  interfaces: [eth0]\n  pod_claims_dir: claims\n")
                .unwrap_err()
                .to_string();
        assert!(err.contains("agent.pod_claims_dir"), "{err}");
    }

    #[test]
    fn a_pod_profile_loads_with_every_node_section_off() {
        let config = AgentConfig::from_yaml(POD).unwrap();
        assert_eq!(config.agent.profile, AgentProfile::Pod);
        assert!(config.node_sections().iter().all(|(_, on)| !on));
        assert!(!config.response.kill_process.enabled);
    }

    #[test]
    fn every_refused_section_is_named_when_written() {
        for section in POD_REFUSED_SECTIONS {
            let yaml = format!("{POD}{section}: {{}}\n");
            let err = AgentConfig::from_yaml(&yaml).unwrap_err().to_string();
            assert!(err.contains(section), "{section}: {err}");
        }
    }

    #[test]
    fn a_section_written_off_is_still_refused() {
        let err = AgentConfig::from_yaml(&format!("{POD}firewall:\n  enabled: false\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("firewall"), "{err}");
    }

    #[test]
    fn killing_a_process_is_refused_inside_a_pod() {
        let err = AgentConfig::from_yaml(&format!(
            "{POD}response:\n  kill_process:\n    enabled: true\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("response.kill_process"), "{err}");
    }

    #[test]
    fn the_pod_sections_stay_available() {
        let config = AgentConfig::from_yaml(&format!(
            "{POD}ids:\n  enabled: true\ndns:\n  enabled: true\nconntrack:\n  enabled: true\n"
        ))
        .unwrap();
        assert!(config.ids.enabled);
        assert!(config.dns.enabled);
        assert!(config.conntrack.enabled);
    }

    #[test]
    fn a_pod_profile_names_no_interface() {
        let yaml = POD.replace("interfaces: []", "interfaces: [eth0]");
        let err = AgentConfig::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("agent.interfaces"), "{err}");
    }

    #[test]
    fn a_pod_profile_without_a_selector_is_refused() {
        for yaml in [
            "agent:\n  profile: pod\n  interfaces: []\n",
            "agent:\n  profile: pod\n  interfaces: []\n  pod_selector: {}\n",
        ] {
            let err = AgentConfig::from_yaml(yaml).unwrap_err().to_string();
            assert!(err.contains("agent.pod_selector"), "{err}");
        }
    }

    #[test]
    fn a_node_profile_carries_no_selector() {
        let yaml = "agent:\n  interfaces: [eth0]\n  pod_selector:\n    namespaces: [shop]\n";
        let err = AgentConfig::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("agent.pod_selector"), "{err}");
    }

    #[test]
    fn a_node_section_turned_on_after_load_fails_validation() {
        let mut config = AgentConfig::from_yaml(POD).unwrap();
        config.firewall.enabled = true;
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("firewall"), "{err}");
    }

    #[test]
    fn the_selector_narrows_by_namespace_and_label() {
        let selector = PodSelectorConfig {
            namespaces: vec!["shop".into()],
            match_labels: BTreeMap::from([("app".into(), "cart".into())]),
        };
        let cart = BTreeMap::from([
            ("app".to_string(), "cart".to_string()),
            ("tier".to_string(), "web".to_string()),
        ]);
        assert!(selector.selects("shop", &cart));
        assert!(!selector.selects("bank", &cart));
        assert!(!selector.selects("shop", &BTreeMap::new()));
        let any_namespace = PodSelectorConfig {
            namespaces: Vec::new(),
            ..selector
        };
        assert!(any_namespace.selects("bank", &cart));
    }

    #[test]
    fn a_pod_profile_without_the_pod_inventory_is_refused() {
        let yaml = POD.replace("enabled: true", "enabled: false");
        let err = AgentConfig::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("container.kubernetes.enabled"), "{err}");
    }
}
