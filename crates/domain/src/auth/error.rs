use thiserror::Error;

/// Authentication errors.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("authentication required: no token provided")]
    TokenMissing,

    #[error("invalid token: {0}")]
    TokenInvalid(String),

    #[error("token expired")]
    TokenExpired,

    #[error("failed to load auth key: {0}")]
    KeyLoadFailed(String),

    #[error("access denied: {0}")]
    Forbidden(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        assert_eq!(
            AuthError::TokenMissing.to_string(),
            "authentication required: no token provided"
        );
        assert_eq!(
            AuthError::TokenInvalid("bad sig".to_string()).to_string(),
            "invalid token: bad sig"
        );
        assert_eq!(AuthError::TokenExpired.to_string(), "token expired");
        assert_eq!(
            AuthError::KeyLoadFailed("not found".to_string()).to_string(),
            "failed to load auth key: not found"
        );
        assert_eq!(
            AuthError::Forbidden("namespace denied".to_string()).to_string(),
            "access denied: namespace denied"
        );
    }
}
