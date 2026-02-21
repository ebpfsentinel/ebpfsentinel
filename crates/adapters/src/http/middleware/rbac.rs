use domain::auth::entity::JwtClaims;
use domain::auth::rbac::Role;
use domain::firewall::entity::Scope;

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
}
