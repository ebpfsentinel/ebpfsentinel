use serde::Deserialize;

use super::rbac::Role;

/// JWT claims extracted from a validated token.
///
/// Contains standard JWT claims plus RBAC fields for namespace-scoped
/// access control (role, namespaces).
#[derive(Debug, Clone, Deserialize)]
pub struct JwtClaims {
    /// Subject — the authenticated identity (required).
    pub sub: String,

    /// Expiration time (Unix timestamp, required).
    pub exp: u64,

    /// Issued-at time (Unix timestamp).
    #[serde(default)]
    pub iat: u64,

    /// Issuer — optional, validated when configured.
    pub iss: Option<String>,

    /// Audience — optional, validated when configured.
    pub aud: Option<String>,

    /// RBAC role claim: "admin", "operator", or "viewer".
    #[serde(default)]
    pub role: Option<String>,

    /// Namespace scoping: list of namespaces the identity may access.
    #[serde(default)]
    pub namespaces: Option<Vec<String>>,

    /// Multi-tenant identifier minted by the dashboard for per-tenant
    /// JWTs. Surfaced for the dashboard's cross-tenant scoping; the OSS
    /// agent's RBAC middleware ignores it (tenants are an Enterprise
    /// concern).
    #[serde(default)]
    pub tenant_id: Option<String>,

    /// Multi-role claim list. The legacy `role` field carries a single
    /// string for backwards compat; `roles` allows the dashboard to
    /// emit several roles at once (e.g. `["analyst", "compliance"]`).
    /// `Self::role()` falls back to the first entry of `roles` when
    /// `role` is unset.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

impl JwtClaims {
    /// Parse the role claim, defaulting to `Viewer` (least privilege).
    ///
    /// Prefers `role` (legacy single-string claim) when set; otherwise
    /// falls back to the first entry of `roles` so dashboards that mint
    /// multi-role JWTs still drive the OSS RBAC layer.
    pub fn role(&self) -> Role {
        let raw = self.role.as_deref().or_else(|| {
            self.roles
                .as_ref()
                .and_then(|list| list.first().map(String::as_str))
        });
        raw.and_then(|r| r.parse().ok()).unwrap_or(Role::Viewer)
    }

    /// Effective role list: `roles` if set, else a single-element list
    /// from `role`, else empty. Used by the dashboard layer to surface
    /// every active role on the audit trail.
    #[must_use]
    pub fn effective_roles(&self) -> Vec<String> {
        if let Some(ref roles) = self.roles {
            return roles.clone();
        }
        self.role.clone().map(|r| vec![r]).unwrap_or_default()
    }

    /// Optional tenant identifier minted by the dashboard.
    #[must_use]
    pub fn tenant(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Check whether the claims grant access to the given namespace.
    ///
    /// - `None` → no namespaces granted (deny all — secure default).
    /// - `Some(list)` → access granted if `ns` is in the list.
    ///
    /// Admin role bypasses this check entirely in the RBAC middleware,
    /// so `None` only restricts Operator tokens without explicit namespaces.
    pub fn has_namespace(&self, ns: &str) -> bool {
        match &self.namespaces {
            None => false,
            Some(list) => list.iter().any(|n| n == ns),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_from_json() {
        let json = r#"{"sub":"user-1","exp":9999999999,"iat":1000000000}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.exp, 9_999_999_999);
        assert_eq!(claims.iat, 1_000_000_000);
        assert!(claims.iss.is_none());
        assert!(claims.aud.is_none());
        assert!(claims.role.is_none());
        assert!(claims.namespaces.is_none());
    }

    #[test]
    fn claims_with_optional_fields() {
        let json = r#"{"sub":"svc","exp":1,"iat":0,"iss":"idp","aud":"agent"}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.iss.as_deref(), Some("idp"));
        assert_eq!(claims.aud.as_deref(), Some("agent"));
    }

    #[test]
    fn claims_with_rbac_fields() {
        let json = r#"{"sub":"svc","exp":1,"role":"admin","namespaces":["prod","staging"]}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.role(), Role::Admin);
        assert!(claims.has_namespace("prod"));
        assert!(claims.has_namespace("staging"));
        assert!(!claims.has_namespace("dev"));
    }

    #[test]
    fn role_defaults_to_viewer() {
        let json = r#"{"sub":"svc","exp":1}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.role(), Role::Viewer);
    }

    #[test]
    fn unknown_role_defaults_to_viewer() {
        let json = r#"{"sub":"svc","exp":1,"role":"superadmin"}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.role(), Role::Viewer);
    }

    #[test]
    fn has_namespace_denied_when_none() {
        let json = r#"{"sub":"svc","exp":1}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert!(!claims.has_namespace("anything"));
    }

    #[test]
    fn has_namespace_restricted_when_set() {
        let json = r#"{"sub":"svc","exp":1,"namespaces":["prod"]}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert!(claims.has_namespace("prod"));
        assert!(!claims.has_namespace("staging"));
    }

    #[test]
    fn has_namespace_empty_list_denies_all() {
        let json = r#"{"sub":"svc","exp":1,"namespaces":[]}"#;
        let claims: JwtClaims = serde_json::from_str(json).unwrap();
        assert!(!claims.has_namespace("prod"));
    }
}
