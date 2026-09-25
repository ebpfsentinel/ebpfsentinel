use domain::auth::entity::JwtClaims;
use std::collections::HashMap;
use std::hash::BuildHasher;

use domain::auth::rbac::Role;
use domain::firewall::entity::{FirewallRule, IpNetwork, Scope};

use crate::http::error::ApiError;

/// Require at least Operator role (rejects Viewer with 403).
pub fn require_write_access(claims: &JwtClaims) -> Result<(), ApiError> {
    if claims.role() == Role::Viewer {
        return Err(ApiError::Forbidden {
            code: "INSUFFICIENT_ROLE",
            message: "viewer role cannot perform write operations".to_string(),
        });
    }
    Ok(())
}

/// Require Admin role OR Operator with matching namespace.
///
/// - `Scope::Global` or `Scope::Interface(_)` requires Admin.
/// - `Scope::Namespace(ns)` requires Admin OR (Operator with matching namespace claim).
/// - Viewer is always rejected.
/// - Operator without matching namespace returns `NAMESPACE_FORBIDDEN`.
pub fn require_namespace_write(claims: &JwtClaims, scope: &Scope) -> Result<(), ApiError> {
    let role = claims.role();

    if role == Role::Viewer {
        return Err(ApiError::Forbidden {
            code: "INSUFFICIENT_ROLE",
            message: "viewer role cannot perform write operations".to_string(),
        });
    }

    if role == Role::Admin {
        return Ok(());
    }

    // Operator: check scope
    match scope {
        Scope::Global | Scope::Interface(_) => Err(ApiError::Forbidden {
            code: "INSUFFICIENT_ROLE",
            message: "global and interface scopes require admin role".to_string(),
        }),
        Scope::Namespace(ns) => {
            if claims.has_namespace(ns) {
                Ok(())
            } else {
                Err(ApiError::Forbidden {
                    code: "NAMESPACE_FORBIDDEN",
                    message: format!("access denied for namespace '{ns}'"),
                })
            }
        }
    }
}

/// Require an Operator's namespace-scoped rule to stay inside the CIDRs
/// that namespace is declared with under `namespaces`.
///
/// A namespace scope is an owner label, not a place in the kernel, so
/// without this bound an operator holding one namespace could write a rule
/// that drops traffic for the whole node. Admin is not bound, and a scope
/// other than a namespace is left to [`require_namespace_write`].
pub fn require_namespace_traffic<S: BuildHasher>(
    claims: &JwtClaims,
    rule: &FirewallRule,
    namespaces: &HashMap<String, Vec<IpNetwork>, S>,
) -> Result<(), ApiError> {
    if claims.role() == Role::Admin {
        return Ok(());
    }
    let Scope::Namespace(ns) = &rule.scope else {
        return Ok(());
    };
    let Some(networks) = namespaces.get(ns) else {
        return Err(ApiError::Forbidden {
            code: "NAMESPACE_TRAFFIC_FORBIDDEN",
            message: format!(
                "namespace '{ns}' declares no CIDR under namespaces, so an operator rule \
                 cannot be bounded to it"
            ),
        });
    };
    if rule.stays_within(networks) {
        Ok(())
    } else {
        Err(ApiError::Forbidden {
            code: "NAMESPACE_TRAFFIC_FORBIDDEN",
            message: format!(
                "the rule must match a source or destination address inside the CIDRs of \
                 namespace '{ns}', without negation or alias"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_claims(role: Option<&str>, namespaces: Option<Vec<&str>>) -> JwtClaims {
        JwtClaims {
            sub: "test-user".to_string(),
            exp: 9_999_999_999,
            iat: 0,
            iss: None,
            aud: None,
            role: role.map(String::from),
            namespaces: namespaces.map(|ns| ns.into_iter().map(String::from).collect()),
            tenant_id: None,
            roles: None,
        }
    }

    // ── require_write_access ─────────────────────────────────────────

    #[test]
    fn admin_can_write() {
        let claims = make_claims(Some("admin"), None);
        assert!(require_write_access(&claims).is_ok());
    }

    #[test]
    fn operator_can_write() {
        let claims = make_claims(Some("operator"), None);
        assert!(require_write_access(&claims).is_ok());
    }

    #[test]
    fn viewer_cannot_write() {
        let claims = make_claims(Some("viewer"), None);
        let err = require_write_access(&claims).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Forbidden {
                code: "INSUFFICIENT_ROLE",
                ..
            }
        ));
    }

    #[test]
    fn no_role_defaults_to_viewer_rejected() {
        let claims = make_claims(None, None);
        assert!(require_write_access(&claims).is_err());
    }

    // ── require_namespace_write: Admin ────────────────────────────────

    #[test]
    fn admin_can_write_global() {
        let claims = make_claims(Some("admin"), None);
        assert!(require_namespace_write(&claims, &Scope::Global).is_ok());
    }

    #[test]
    fn admin_can_write_interface() {
        let claims = make_claims(Some("admin"), None);
        assert!(require_namespace_write(&claims, &Scope::Interface("eth0".to_string())).is_ok());
    }

    #[test]
    fn admin_can_write_namespace() {
        let claims = make_claims(Some("admin"), None);
        assert!(require_namespace_write(&claims, &Scope::Namespace("prod".to_string())).is_ok());
    }

    // ── require_namespace_write: Operator ─────────────────────────────

    #[test]
    fn operator_cannot_write_global() {
        let claims = make_claims(Some("operator"), Some(vec!["prod"]));
        let err = require_namespace_write(&claims, &Scope::Global).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Forbidden {
                code: "INSUFFICIENT_ROLE",
                ..
            }
        ));
    }

    #[test]
    fn operator_cannot_write_interface() {
        let claims = make_claims(Some("operator"), Some(vec!["prod"]));
        let err =
            require_namespace_write(&claims, &Scope::Interface("eth0".to_string())).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Forbidden {
                code: "INSUFFICIENT_ROLE",
                ..
            }
        ));
    }

    #[test]
    fn operator_can_write_own_namespace() {
        let claims = make_claims(Some("operator"), Some(vec!["prod", "staging"]));
        assert!(require_namespace_write(&claims, &Scope::Namespace("prod".to_string())).is_ok());
        assert!(require_namespace_write(&claims, &Scope::Namespace("staging".to_string())).is_ok());
    }

    #[test]
    fn operator_cannot_write_other_namespace() {
        let claims = make_claims(Some("operator"), Some(vec!["staging"]));
        let err =
            require_namespace_write(&claims, &Scope::Namespace("prod".to_string())).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Forbidden {
                code: "NAMESPACE_FORBIDDEN",
                ..
            }
        ));
    }

    // ── require_namespace_write: Viewer ───────────────────────────────

    #[test]
    fn viewer_cannot_write_any_scope() {
        let claims = make_claims(Some("viewer"), Some(vec!["prod"]));
        assert!(require_namespace_write(&claims, &Scope::Global).is_err());
        assert!(require_namespace_write(&claims, &Scope::Namespace("prod".to_string())).is_err());
        assert!(require_namespace_write(&claims, &Scope::Interface("eth0".to_string())).is_err());
    }

    // ── require_namespace_traffic ─────────────────────────────────────

    fn prod_networks() -> HashMap<String, Vec<IpNetwork>> {
        HashMap::from([(
            "prod".to_string(),
            vec![IpNetwork::V4 {
                addr: 0x0A01_0000, // 10.1.0.0/16
                prefix_len: 16,
            }],
        )])
    }

    fn prod_rule(dst: Option<IpNetwork>, namespace: &str) -> FirewallRule {
        FirewallRule {
            id: domain::common::entity::RuleId("r".to_string()),
            priority: 10,
            action: domain::firewall::entity::FirewallAction::Deny,
            protocol: domain::common::entity::Protocol::Any,
            src_ip: None,
            dst_ip: dst,
            src_port: None,
            dst_port: None,
            scope: Scope::Namespace(namespace.to_string()),
            enabled: true,
            vlan_id: None,
            src_alias: None,
            dst_alias: None,
            src_port_alias: None,
            dst_port_alias: None,
            src_mac_alias: None,
            dst_mac_alias: None,
            ct_states: None,
            tcp_flags: None,
            icmp_type: None,
            icmp_code: None,
            negate_src: false,
            negate_dst: false,
            dscp_match: None,
            dscp_mark: None,
            max_states: None,
            src_mac: None,
            dst_mac: None,
            schedule: None,
            system: false,
            route_action: None,
            group_mask: 0,
            tenant_id: 0,
        }
    }

    const INSIDE: IpNetwork = IpNetwork::V4 {
        addr: 0x0A01_0005,
        prefix_len: 32,
    };

    #[test]
    fn operator_rule_inside_its_namespace_cidrs_is_allowed() {
        let claims = make_claims(Some("operator"), Some(vec!["prod"]));
        let rule = prod_rule(Some(INSIDE), "prod");
        assert!(require_namespace_traffic(&claims, &rule, &prod_networks()).is_ok());
    }

    #[test]
    fn operator_rule_reaching_past_its_namespace_is_refused() {
        let claims = make_claims(Some("operator"), Some(vec!["prod"]));
        for dst in [
            None,
            Some(IpNetwork::V4 {
                addr: 0x0A00_0000,
                prefix_len: 8,
            }),
        ] {
            let rule = prod_rule(dst, "prod");
            let err = require_namespace_traffic(&claims, &rule, &prod_networks()).unwrap_err();
            assert!(matches!(
                err,
                ApiError::Forbidden {
                    code: "NAMESPACE_TRAFFIC_FORBIDDEN",
                    ..
                }
            ));
        }
    }

    #[test]
    fn operator_rule_in_an_undeclared_namespace_is_refused() {
        let claims = make_claims(Some("operator"), Some(vec!["staging"]));
        let rule = prod_rule(Some(INSIDE), "staging");
        assert!(require_namespace_traffic(&claims, &rule, &prod_networks()).is_err());
    }

    #[test]
    fn admin_is_not_bound_to_namespace_cidrs() {
        let claims = make_claims(Some("admin"), None);
        let rule = prod_rule(None, "staging");
        assert!(require_namespace_traffic(&claims, &rule, &HashMap::new()).is_ok());
    }
}
