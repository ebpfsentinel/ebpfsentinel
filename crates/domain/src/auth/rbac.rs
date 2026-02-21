use std::fmt;
use std::str::FromStr;

/// RBAC roles for namespace-scoped access control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Full access to all namespaces and global/interface scopes.
    Admin,
    /// Write access limited to assigned namespaces.
    Operator,
    /// Read-only access across assigned namespaces.
    Viewer,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admin => write!(f, "admin"),
            Self::Operator => write!(f, "operator"),
            Self::Viewer => write!(f, "viewer"),
        }
    }
}

impl FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "admin" => Ok(Self::Admin),
            "operator" => Ok(Self::Operator),
            "viewer" => Ok(Self::Viewer),
            other => Err(format!(
                "unknown role '{other}': expected admin|operator|viewer"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_admin() {
        assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("Admin".parse::<Role>().unwrap(), Role::Admin);
        assert_eq!("ADMIN".parse::<Role>().unwrap(), Role::Admin);
    }

    #[test]
    fn parse_operator() {
        assert_eq!("operator".parse::<Role>().unwrap(), Role::Operator);
    }

    #[test]
    fn parse_viewer() {
        assert_eq!("viewer".parse::<Role>().unwrap(), Role::Viewer);
    }

    #[test]
    fn parse_unknown_fails() {
        assert!("unknown".parse::<Role>().is_err());
        assert!("".parse::<Role>().is_err());
    }

    #[test]
    fn display() {
        assert_eq!(Role::Admin.to_string(), "admin");
        assert_eq!(Role::Operator.to_string(), "operator");
        assert_eq!(Role::Viewer.to_string(), "viewer");
    }
}
