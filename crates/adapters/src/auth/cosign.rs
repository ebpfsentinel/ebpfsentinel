//! ML-DSA-65 cosignatures of bearer tokens.
//!
//! The dashboard signs every token it mints twice: the JWT carries Ed25519,
//! and beside it an ML-DSA-65 signature over the whole compact token travels
//! in [`ports::secondary::auth_provider::COSIGNATURE_HEADER`]. The public half
//! is published in the same JWKS as the classical key and under the same key
//! id, as an `AKP` entry (`alg: ML-DSA-65`, raw key in `pub`), the shape the
//! IETF JOSE work on ML-DSA gives it. A JWKS consumer that knows nothing of it
//! reads past it.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use domain::auth::cosignature::{Cosignature, CosignaturePolicy};
use domain::auth::error::AuthError;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk};
use ml_dsa::MlDsa65;

/// Domain separation: a cosignature made for a token is never a valid
/// signature of anything else the same key might sign.
pub const CONTEXT: &[u8] = b"ebpfsentinel-agent-token";

/// The JWK `kty` and `alg` of a published ML-DSA-65 key.
pub const JWK_KTY: &str = "AKP";
pub const JWK_ALG: &str = "ML-DSA-65";

/// Encoded length of an ML-DSA-65 public key.
pub const PUBLIC_KEY_BYTES: usize = 1952;

/// An ML-DSA-65 public key a cosignature is checked against.
#[derive(Clone)]
pub struct MlDsaKey(ml_dsa::VerifyingKey<MlDsa65>);

impl std::fmt::Debug for MlDsaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MlDsaKey(ML-DSA-65)")
    }
}

impl MlDsaKey {
    /// The key from its raw encoding; `None` when the length is wrong.
    #[must_use]
    pub fn from_raw(bytes: &[u8]) -> Option<Self> {
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(bytes).ok()?;
        Some(Self(ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded)))
    }

    /// The key from base64 of its raw encoding, standard or url-safe, which
    /// is how a key file and a JWK both write it.
    pub fn from_base64(text: &str) -> Result<Self, AuthError> {
        let text = text.trim();
        let bytes = STANDARD
            .decode(text)
            .or_else(|_| URL_SAFE_NO_PAD.decode(text.trim_end_matches('=')))
            .map_err(|e| AuthError::KeyLoadFailed(format!("ML-DSA-65 key is not base64: {e}")))?;
        Self::from_raw(&bytes).ok_or_else(|| {
            AuthError::KeyLoadFailed(format!(
                "ML-DSA-65 key is {} bytes, expected {PUBLIC_KEY_BYTES}",
                bytes.len()
            ))
        })
    }

    /// The key a JWK publishes, when it is an ML-DSA-65 `AKP` entry.
    ///
    /// `jsonwebtoken` reads `alg` into a closed enum where `ML-DSA-65` lands
    /// on its catch-all, so the algorithm is held by the key itself: only an
    /// ML-DSA-65 public key is 1952 bytes among the `AKP` algorithms, and a
    /// key of any other length is not one this agent verifies with.
    #[must_use]
    pub fn from_jwk(jwk: &Jwk) -> Option<Self> {
        let AlgorithmParameters::Other(other) = &jwk.algorithm else {
            return None;
        };
        let field = |name: &str| other.fields.get(name).and_then(|v| v.as_str());
        if field("kty") != Some(JWK_KTY) {
            return None;
        }
        Self::from_base64(field("pub")?).ok()
    }

    /// Whether `cosignature` (base64url) is this key's signature of `token`.
    /// Bytes that are not a signature and a wrong signature are one refusal.
    #[must_use]
    pub fn verifies(&self, token: &str, cosignature: &str) -> bool {
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(cosignature.trim().trim_end_matches('=')) else {
            return false;
        };
        let Ok(encoded) = ml_dsa::EncodedSignature::<MlDsa65>::try_from(bytes.as_slice()) else {
            return false;
        };
        let Some(signature) = ml_dsa::Signature::<MlDsa65>::decode(&encoded) else {
            return false;
        };
        self.0
            .verify_with_context(token.as_bytes(), CONTEXT, &signature)
    }
}

/// The ML-DSA-65 key a JWKS publishes under `kid`, if any.
#[must_use]
pub fn key_for_kid(keys: &[Jwk], kid: &str) -> Option<MlDsaKey> {
    keys.iter()
        .filter(|k| k.common.key_id.as_deref() == Some(kid))
        .find_map(MlDsaKey::from_jwk)
}

/// What a token's cosignature amounts to under `policy`, given the key the
/// agent holds for the token's key id.
#[must_use]
pub fn inspect(
    policy: CosignaturePolicy,
    key: Option<&MlDsaKey>,
    token: &str,
    cosignature: Option<&str>,
) -> Cosignature {
    if policy == CosignaturePolicy::Disable {
        return Cosignature::Absent;
    }
    match (cosignature.filter(|c| !c.is_empty()), key) {
        (None, _) => Cosignature::Absent,
        (Some(_), None) => Cosignature::NoKey,
        (Some(sig), Some(key)) if key.verifies(token, sig) => Cosignature::Verified,
        (Some(_), Some(_)) => Cosignature::Invalid,
    }
}

#[cfg(test)]
pub(crate) mod test_signer {
    //! A dashboard's half, for tests: an ML-DSA-65 key from a fixed seed and
    //! the cosignature it makes.

    use super::{CONTEXT, MlDsaKey, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use ml_dsa::MlDsa65;

    pub struct Signer(ml_dsa::ExpandedSigningKey<MlDsa65>);

    impl Signer {
        pub fn from_seed(byte: u8) -> Self {
            let seed = ml_dsa::Seed::try_from([byte; 32].as_slice()).expect("32 bytes");
            Self(ml_dsa::ExpandedSigningKey::<MlDsa65>::from_seed(&seed))
        }

        pub fn public_raw(&self) -> Vec<u8> {
            self.0.verifying_key().encode().as_slice().to_vec()
        }

        pub fn public(&self) -> MlDsaKey {
            MlDsaKey::from_raw(&self.public_raw()).expect("a well formed key")
        }

        pub fn cosign(&self, token: &str) -> String {
            let signature = self
                .0
                .sign_deterministic(token.as_bytes(), CONTEXT)
                .expect("a short context");
            URL_SAFE_NO_PAD.encode(signature.encode().as_slice())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_signer::Signer;
    use super::*;

    #[test]
    fn a_cosignature_verifies_only_for_its_token_and_its_key() {
        let signer = Signer::from_seed(7);
        let key = signer.public();
        let sig = signer.cosign("h.p.s");
        assert!(key.verifies("h.p.s", &sig));
        assert!(!key.verifies("h.p.t", &sig));
        assert!(!Signer::from_seed(8).public().verifies("h.p.s", &sig));
        assert!(!key.verifies("h.p.s", "not base64 !"));
        assert!(!key.verifies("h.p.s", "AAAA"));
    }

    #[test]
    fn the_key_is_read_off_an_akp_entry_under_the_token_kid() {
        let signer = Signer::from_seed(3);
        let raw = URL_SAFE_NO_PAD.encode(signer.public_raw());
        let set: jsonwebtoken::jwk::JwkSet = serde_json::from_value(serde_json::json!({
            "keys": [
                {"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": "k1",
                 "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"},
                {"kty": "AKP", "use": "sig", "alg": "ML-DSA-65", "kid": "k1", "pub": raw}
            ]
        }))
        .expect("a JWKS with an AKP entry parses");
        let key = key_for_kid(&set.keys, "k1").expect("the ML-DSA key under k1");
        assert!(key.verifies("t", &signer.cosign("t")));
        assert!(key_for_kid(&set.keys, "k2").is_none());
    }

    #[test]
    fn inspect_says_what_was_found() {
        let signer = Signer::from_seed(1);
        let key = signer.public();
        let good = signer.cosign("t");
        let p = CosignaturePolicy::Prefer;
        assert_eq!(inspect(p, Some(&key), "t", None), Cosignature::Absent);
        assert_eq!(inspect(p, Some(&key), "t", Some("")), Cosignature::Absent);
        assert_eq!(inspect(p, None, "t", Some(&good)), Cosignature::NoKey);
        assert_eq!(
            inspect(p, Some(&key), "t", Some(&good)),
            Cosignature::Verified
        );
        assert_eq!(
            inspect(p, Some(&key), "u", Some(&good)),
            Cosignature::Invalid
        );
        assert_eq!(
            inspect(CosignaturePolicy::Disable, Some(&key), "u", Some(&good)),
            Cosignature::Absent
        );
    }
}
