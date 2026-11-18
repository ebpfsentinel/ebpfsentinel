use axum::extract::{MatchedPath, Request};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use domain::auth::entity::JwtClaims;
use std::collections::HashMap;
use std::hash::BuildHasher;

use domain::auth::rbac::Role;
use domain::firewall::entity::{FirewallRule, IpNetwork, Scope};

use crate::http::error::ApiError;

/// The least a caller must be to perform a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteRole {
    /// Any role but `viewer`. The handler may narrow it further, the way a
    /// firewall rule is held to the caller's namespaces.
    Operator,
    /// `admin` only: the write changes the whole node.
    Admin,
}

/// The role every write route needs, by method and mounted path.
///
/// This table is the one place the decision is made: the router asserts that
/// every route it mounts outside `GET` has exactly one row here and that every
/// row is mounted, and the documentation's role column is read off it. A
/// write that changes no namespaced object and acts on the whole node (its
/// datapath, its configuration, its addresses or its traffic) is `admin`;
/// what an operator keeps is namespaced firewall rules, alert triage and the
/// writes that observe or enrich without changing what the node enforces
/// beyond its own policy lists.
pub const WRITE_ROLES: &[(&str, &str, WriteRole)] = &[
    ("POST", "/api/v1/firewall/rules", WriteRole::Operator),
    ("DELETE", "/api/v1/firewall/rules/{id}", WriteRole::Operator),
    ("POST", "/api/v1/learning/sessions", WriteRole::Operator),
    (
        "POST",
        "/api/v1/learning/sessions/{id}/stop",
        WriteRole::Operator,
    ),
    ("POST", "/api/v1/netpol/replay", WriteRole::Operator),
    ("POST", "/api/v1/trace", WriteRole::Operator),
    ("PATCH", "/api/v1/ips/rules/{id}", WriteRole::Operator),
    (
        "POST",
        "/api/v1/alerts/{id}/false-positive",
        WriteRole::Operator,
    ),
    ("PATCH", "/api/v1/alerts/{id}/triage", WriteRole::Operator),
    ("POST", "/api/v1/alerts/triage", WriteRole::Operator),
    (
        "POST",
        "/api/v1/threatintel/feeds/refresh",
        WriteRole::Operator,
    ),
    ("PUT", "/api/v1/aliases/{id}/content", WriteRole::Operator),
    ("DELETE", "/api/v1/dns/cache", WriteRole::Operator),
    ("POST", "/api/v1/domains/blocklist", WriteRole::Operator),
    (
        "DELETE",
        "/api/v1/domains/blocklist/{domain}",
        WriteRole::Operator,
    ),
    // An L7 rule carries no namespace and holds every flow the node parses.
    ("POST", "/api/v1/firewall/l7-rules", WriteRole::Admin),
    ("DELETE", "/api/v1/firewall/l7-rules/{id}", WriteRole::Admin),
    ("POST", "/api/v1/ips/blacklist", WriteRole::Admin),
    ("DELETE", "/api/v1/ips/blacklist/{ip}", WriteRole::Admin),
    ("POST", "/api/v1/ratelimit/rules", WriteRole::Admin),
    ("DELETE", "/api/v1/ratelimit/rules/{id}", WriteRole::Admin),
    ("POST", "/api/v1/nat/nptv6", WriteRole::Admin),
    ("DELETE", "/api/v1/nat/nptv6/{id}", WriteRole::Admin),
    ("POST", "/api/v1/ddos/policies", WriteRole::Admin),
    ("DELETE", "/api/v1/ddos/policies/{id}", WriteRole::Admin),
    ("POST", "/api/v1/config/reload", WriteRole::Admin),
    ("POST", "/api/v1/agent/stop", WriteRole::Admin),
    ("PUT", "/api/v1/config/{section}", WriteRole::Admin),
    ("POST", "/api/v1/conntrack/flush", WriteRole::Admin),
    ("POST", "/api/v1/routing/gateways", WriteRole::Admin),
    ("DELETE", "/api/v1/routing/gateways/{id}", WriteRole::Admin),
    ("POST", "/api/v1/zones", WriteRole::Admin),
    ("DELETE", "/api/v1/zones/{id}", WriteRole::Admin),
    ("POST", "/api/v1/zones/policies", WriteRole::Admin),
    ("DELETE", "/api/v1/zones/policies/{id}", WriteRole::Admin),
    ("POST", "/api/v1/lb/services", WriteRole::Admin),
    ("DELETE", "/api/v1/lb/services/{id}", WriteRole::Admin),
    ("POST", "/api/v1/lb/vips", WriteRole::Admin),
    ("POST", "/api/v1/lb/vips/grant", WriteRole::Admin),
    ("POST", "/api/v1/qos/pipes", WriteRole::Admin),
    ("DELETE", "/api/v1/qos/pipes/{id}", WriteRole::Admin),
    ("POST", "/api/v1/qos/queues", WriteRole::Admin),
    ("DELETE", "/api/v1/qos/queues/{id}", WriteRole::Admin),
    ("POST", "/api/v1/qos/classifiers", WriteRole::Admin),
    ("DELETE", "/api/v1/qos/classifiers/{id}", WriteRole::Admin),
    ("POST", "/api/v1/responses/manual", WriteRole::Admin),
    ("DELETE", "/api/v1/responses/{id}", WriteRole::Admin),
    ("POST", "/api/v1/captures/manual", WriteRole::Admin),
    ("DELETE", "/api/v1/captures/{id}", WriteRole::Admin),
];

/// The role a write needs. A write missing from [`WRITE_ROLES`] needs
/// `admin`, so a route mounted without a row fails closed.
#[must_use]
pub fn write_role(method: &str, path: &str) -> WriteRole {
    WRITE_ROLES
        .iter()
        .find(|(m, p, _)| *m == method && *p == path)
        .map_or(WriteRole::Admin, |(_, _, role)| *role)
}

/// Refuse a caller whose role is below what the write needs.
pub fn require_write_role(claims: &JwtClaims, needed: WriteRole) -> Result<(), ApiError> {
    match (claims.role(), needed) {
        (Role::Viewer, _) => Err(ApiError::Forbidden {
            code: "INSUFFICIENT_ROLE",
            message: "viewer role cannot perform write operations".to_string(),
        }),
        (Role::Operator, WriteRole::Admin) => Err(ApiError::Forbidden {
            code: "INSUFFICIENT_ROLE",
            message: "this write changes the whole node and requires the admin role".to_string(),
        }),
        _ => Ok(()),
    }
}

/// Hold every write to the role [`WRITE_ROLES`] gives its route.
///
/// Reads the verified claims the authentication layer put on the request;
/// with authentication off there are none and nothing is refused here, which
/// is what turning authentication off means.
pub async fn enforce_write_roles(request: Request, next: Next) -> Response {
    if !request.method().is_safe()
        && let Some(claims) = request.extensions().get::<JwtClaims>()
    {
        let path = request
            .extensions()
            .get::<MatchedPath>()
            .map_or_else(|| request.uri().path(), MatchedPath::as_str);
        if let Err(refusal) =
            require_write_role(claims, write_role(request.method().as_str(), path))
        {
            return refusal.into_response();
        }
    }
    next.run(request).await
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

    // ── require_write_role ───────────────────────────────────────────

    #[test]
    fn admin_can_write() {
        let claims = make_claims(Some("admin"), None);
        assert!(require_write_role(&claims, WriteRole::Operator).is_ok());
        assert!(require_write_role(&claims, WriteRole::Admin).is_ok());
    }

    #[test]
    fn operator_can_write_what_an_operator_may() {
        let claims = make_claims(Some("operator"), None);
        assert!(require_write_role(&claims, WriteRole::Operator).is_ok());
    }

    #[test]
    fn operator_cannot_write_the_whole_node() {
        let claims = make_claims(Some("operator"), Some(vec!["prod"]));
        let err = require_write_role(&claims, WriteRole::Admin).unwrap_err();
        assert!(matches!(
            err,
            ApiError::Forbidden {
                code: "INSUFFICIENT_ROLE",
                ..
            }
        ));
    }

    #[test]
    fn a_write_with_no_row_needs_admin() {
        assert_eq!(write_role("POST", "/api/v1/nowhere"), WriteRole::Admin);
        assert_eq!(
            write_role("PUT", "/api/v1/config/{section}"),
            WriteRole::Admin
        );
        assert_eq!(
            write_role("PATCH", "/api/v1/alerts/{id}/triage"),
            WriteRole::Operator
        );
    }

    #[test]
    fn viewer_cannot_write() {
        let claims = make_claims(Some("viewer"), None);
        let err = require_write_role(&claims, WriteRole::Operator).unwrap_err();
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
        assert!(require_write_role(&claims, WriteRole::Operator).is_err());
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
            mode: domain::firewall::entity::RuleMode::Enforce,
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
            group_mask: 0,
            tenant_id: 0,
            workload: None,
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
