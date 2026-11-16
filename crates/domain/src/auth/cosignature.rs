//! The post-quantum half of a bearer token.
//!
//! A token the dashboard mints is an Ed25519 JWT, which a quantum computer
//! could forge. Beside it travels an ML-DSA-65 signature over the whole
//! compact token, published under the same key id. Whether a request must
//! carry that second signature is the agent's policy, and the rule is the
//! one the licence follows: where both are present both must hold.

use super::error::AuthError;

/// What the agent asks of the second signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CosignaturePolicy {
    /// Checked when present; a token without one is still accepted.
    #[default]
    Prefer,
    /// A token without a cosignature that verifies is refused.
    Require,
    /// Never read.
    Disable,
}

/// What the verifier found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cosignature {
    /// None was sent.
    Absent,
    /// One was sent and no ML-DSA key is published under the token's key id.
    NoKey,
    /// One was sent and it verifies against the key under the token's key id.
    Verified,
    /// One was sent and it does not verify.
    Invalid,
}

/// Why a token was refused for its second signature. Kept apart from the
/// reasons a classical token is refused, so the log says which half failed.
pub const COSIGNATURE_REQUIRED: &str =
    "a post-quantum cosignature is required (auth.pq_tokens: require)";
pub const COSIGNATURE_INVALID: &str = "the post-quantum cosignature does not verify";

/// Whether a token whose classical signature already holds is admitted.
///
/// A cosignature that does not verify is refused under every policy that
/// reads it: it is a forgery or a substitution, never a downgrade to
/// tolerate. An absent one, or one the agent has no key for, is refused only
/// under `require`.
pub fn admit(policy: CosignaturePolicy, found: Cosignature) -> Result<(), AuthError> {
    match (policy, found) {
        (CosignaturePolicy::Require, Cosignature::Absent | Cosignature::NoKey) => {
            Err(AuthError::TokenInvalid(COSIGNATURE_REQUIRED.to_string()))
        }
        (CosignaturePolicy::Prefer | CosignaturePolicy::Require, Cosignature::Invalid) => {
            Err(AuthError::TokenInvalid(COSIGNATURE_INVALID.to_string()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verified_cosignature_is_admitted_under_every_policy() {
        for policy in [
            CosignaturePolicy::Prefer,
            CosignaturePolicy::Require,
            CosignaturePolicy::Disable,
        ] {
            assert!(admit(policy, Cosignature::Verified).is_ok());
        }
    }

    #[test]
    fn a_cosignature_that_does_not_verify_is_never_tolerated() {
        assert!(admit(CosignaturePolicy::Prefer, Cosignature::Invalid).is_err());
        assert!(admit(CosignaturePolicy::Require, Cosignature::Invalid).is_err());
        assert!(admit(CosignaturePolicy::Disable, Cosignature::Invalid).is_ok());
    }

    #[test]
    fn a_classical_only_token_is_refused_only_under_require() {
        assert!(admit(CosignaturePolicy::Prefer, Cosignature::Absent).is_ok());
        assert!(admit(CosignaturePolicy::Prefer, Cosignature::NoKey).is_ok());
        let refused = admit(CosignaturePolicy::Require, Cosignature::Absent)
            .expect_err("require refuses a classical-only token");
        assert!(refused.to_string().contains("auth.pq_tokens: require"));
        assert!(admit(CosignaturePolicy::Require, Cosignature::NoKey).is_err());
    }
}
