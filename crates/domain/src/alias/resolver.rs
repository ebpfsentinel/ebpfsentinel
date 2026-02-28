use std::collections::{HashMap, HashSet};

use crate::firewall::entity::{IpNetwork, PortRange};

use super::entity::{Alias, AliasKind};
use super::error::AliasError;

/// Resolves aliases recursively with cycle detection.
#[derive(Debug)]
pub struct AliasResolver {
    aliases: HashMap<String, Alias>,
}

impl AliasResolver {
    pub fn new() -> Self {
        Self {
            aliases: HashMap::new(),
        }
    }

    /// Load a set of aliases, validating each.
    pub fn load(&mut self, aliases: Vec<Alias>) -> Result<(), AliasError> {
        for alias in &aliases {
            alias.validate()?;
        }

        // Check for duplicates
        let mut seen = HashSet::new();
        for alias in &aliases {
            if !seen.insert(&alias.id.0) {
                return Err(AliasError::Duplicate {
                    id: alias.id.0.clone(),
                });
            }
        }

        self.aliases.clear();
        for alias in aliases {
            self.aliases.insert(alias.id.0.clone(), alias);
        }
        Ok(())
    }

    /// Add a single alias.
    pub fn add(&mut self, alias: Alias) -> Result<(), AliasError> {
        alias.validate()?;
        if self.aliases.contains_key(&alias.id.0) {
            return Err(AliasError::Duplicate {
                id: alias.id.0.clone(),
            });
        }
        self.aliases.insert(alias.id.0.clone(), alias);
        Ok(())
    }

    /// Resolve an alias to a flat list of IP networks.
    pub fn resolve_ips(&self, id: &str) -> Result<Vec<IpNetwork>, AliasError> {
        let mut visited = HashSet::new();
        self.resolve_ips_recursive(id, &mut visited)
    }

    /// Resolve an alias to a flat list of port ranges.
    pub fn resolve_ports(&self, id: &str) -> Result<Vec<PortRange>, AliasError> {
        let mut visited = HashSet::new();
        self.resolve_ports_recursive(id, &mut visited)
    }

    /// Get an alias by ID.
    pub fn get(&self, id: &str) -> Option<&Alias> {
        self.aliases.get(id)
    }

    /// Return all loaded aliases.
    pub fn aliases(&self) -> &HashMap<String, Alias> {
        &self.aliases
    }

    fn resolve_ips_recursive(
        &self,
        id: &str,
        visited: &mut HashSet<String>,
    ) -> Result<Vec<IpNetwork>, AliasError> {
        if !visited.insert(id.to_string()) {
            return Err(AliasError::CircularReference {
                path: format!("{id} -> ... -> {id}"),
            });
        }

        let alias = self
            .aliases
            .get(id)
            .ok_or_else(|| AliasError::NotFound { id: id.to_string() })?;

        match &alias.kind {
            AliasKind::IpSet { values } => Ok(values.clone()),
            AliasKind::Nested { aliases } => {
                let mut result = Vec::new();
                for child_id in aliases {
                    let ips = self.resolve_ips_recursive(child_id, visited)?;
                    result.extend(ips);
                }
                Ok(result)
            }
            AliasKind::UrlTable { .. }
            | AliasKind::GeoIp { .. }
            | AliasKind::DynamicDns { .. }
            | AliasKind::InterfaceGroup { .. } => {
                // These need external resolution — return empty for now,
                // the adapter will populate them.
                Ok(Vec::new())
            }
            AliasKind::PortSet { .. } => Err(AliasError::NotIpSet { id: id.to_string() }),
        }
    }

    fn resolve_ports_recursive(
        &self,
        id: &str,
        visited: &mut HashSet<String>,
    ) -> Result<Vec<PortRange>, AliasError> {
        if !visited.insert(id.to_string()) {
            return Err(AliasError::CircularReference {
                path: format!("{id} -> ... -> {id}"),
            });
        }

        let alias = self
            .aliases
            .get(id)
            .ok_or_else(|| AliasError::NotFound { id: id.to_string() })?;

        match &alias.kind {
            AliasKind::PortSet { values } => Ok(values.clone()),
            AliasKind::Nested { aliases } => {
                let mut result = Vec::new();
                for child_id in aliases {
                    let ports = self.resolve_ports_recursive(child_id, visited)?;
                    result.extend(ports);
                }
                Ok(result)
            }
            AliasKind::IpSet { .. }
            | AliasKind::UrlTable { .. }
            | AliasKind::GeoIp { .. }
            | AliasKind::DynamicDns { .. }
            | AliasKind::InterfaceGroup { .. } => {
                Err(AliasError::NotPortSet { id: id.to_string() })
            }
        }
    }
}

impl Default for AliasResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alias::entity::AliasId;

    fn ip_set_alias(id: &str, ips: Vec<IpNetwork>) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::IpSet { values: ips },
            description: None,
        }
    }

    fn port_set_alias(id: &str, ports: Vec<PortRange>) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::PortSet { values: ports },
            description: None,
        }
    }

    fn nested_alias(id: &str, refs: Vec<&str>) -> Alias {
        Alias {
            id: AliasId(id.to_string()),
            kind: AliasKind::Nested {
                aliases: refs.into_iter().map(String::from).collect(),
            },
            description: None,
        }
    }

    #[test]
    fn resolve_simple_ip_set() {
        let mut resolver = AliasResolver::new();
        let net = IpNetwork::V4 {
            addr: 0xC0A80000,
            prefix_len: 16,
        };
        resolver.add(ip_set_alias("rfc1918", vec![net])).unwrap();
        let ips = resolver.resolve_ips("rfc1918").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], net);
    }

    #[test]
    fn resolve_simple_port_set() {
        let mut resolver = AliasResolver::new();
        let range = PortRange {
            start: 80,
            end: 443,
        };
        resolver
            .add(port_set_alias("http-ports", vec![range]))
            .unwrap();
        let ports = resolver.resolve_ports("http-ports").unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0], range);
    }

    #[test]
    fn resolve_nested_ip_set() {
        let mut resolver = AliasResolver::new();
        let net1 = IpNetwork::V4 {
            addr: 0xC0A80000,
            prefix_len: 16,
        };
        let net2 = IpNetwork::V4 {
            addr: 0x0A000000,
            prefix_len: 8,
        };
        resolver.add(ip_set_alias("set-a", vec![net1])).unwrap();
        resolver.add(ip_set_alias("set-b", vec![net2])).unwrap();
        resolver
            .add(nested_alias("combined", vec!["set-a", "set-b"]))
            .unwrap();

        let ips = resolver.resolve_ips("combined").unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], net1);
        assert_eq!(ips[1], net2);
    }

    #[test]
    fn resolve_deeply_nested() {
        let mut resolver = AliasResolver::new();
        let net = IpNetwork::V4 {
            addr: 0xC0A80000,
            prefix_len: 16,
        };
        resolver.add(ip_set_alias("leaf", vec![net])).unwrap();
        resolver.add(nested_alias("mid", vec!["leaf"])).unwrap();
        resolver.add(nested_alias("top", vec!["mid"])).unwrap();

        let ips = resolver.resolve_ips("top").unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], net);
    }

    #[test]
    fn resolve_circular_reference_detected() {
        let mut resolver = AliasResolver::new();
        resolver.add(nested_alias("a", vec!["b"])).unwrap();
        resolver.add(nested_alias("b", vec!["a"])).unwrap();

        let result = resolver.resolve_ips("a");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AliasError::CircularReference { .. }));
    }

    #[test]
    fn resolve_self_reference_detected() {
        let mut resolver = AliasResolver::new();
        resolver
            .add(nested_alias("self-ref", vec!["self-ref"]))
            .unwrap();

        let result = resolver.resolve_ips("self-ref");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_not_found() {
        let resolver = AliasResolver::new();
        assert!(resolver.resolve_ips("nonexistent").is_err());
    }

    #[test]
    fn resolve_ip_from_port_set_fails() {
        let mut resolver = AliasResolver::new();
        resolver
            .add(port_set_alias(
                "ports",
                vec![PortRange { start: 80, end: 80 }],
            ))
            .unwrap();
        assert!(resolver.resolve_ips("ports").is_err());
    }

    #[test]
    fn resolve_ports_from_ip_set_fails() {
        let mut resolver = AliasResolver::new();
        resolver
            .add(ip_set_alias(
                "ips",
                vec![IpNetwork::V4 {
                    addr: 0,
                    prefix_len: 0,
                }],
            ))
            .unwrap();
        assert!(resolver.resolve_ports("ips").is_err());
    }

    #[test]
    fn load_replaces_all() {
        let mut resolver = AliasResolver::new();
        let net = IpNetwork::V4 {
            addr: 0,
            prefix_len: 0,
        };
        resolver.add(ip_set_alias("old", vec![net])).unwrap();

        let new_net = IpNetwork::V4 {
            addr: 1,
            prefix_len: 32,
        };
        resolver
            .load(vec![ip_set_alias("new", vec![new_net])])
            .unwrap();

        assert!(resolver.resolve_ips("old").is_err());
        assert!(resolver.resolve_ips("new").is_ok());
    }

    #[test]
    fn load_rejects_duplicates() {
        let mut resolver = AliasResolver::new();
        let net = IpNetwork::V4 {
            addr: 0,
            prefix_len: 0,
        };
        let result = resolver.load(vec![
            ip_set_alias("dup", vec![net]),
            ip_set_alias("dup", vec![net]),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn add_rejects_duplicate() {
        let mut resolver = AliasResolver::new();
        let net = IpNetwork::V4 {
            addr: 0,
            prefix_len: 0,
        };
        resolver.add(ip_set_alias("a", vec![net])).unwrap();
        assert!(resolver.add(ip_set_alias("a", vec![net])).is_err());
    }
}
