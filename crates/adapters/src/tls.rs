//! The key-exchange policy every TLS surface of the agent is built from.
//!
//! One module decides which groups go on the wire, because a listener and a
//! client that disagree about it is a posture nobody can state. The hybrid
//! group `X25519MLKEM768` leads the list by default, so a client that knows it
//! gets post-quantum confidentiality without being asked, and the classical
//! groups stay behind it so a client that does not keeps connecting.

use std::sync::Arc;

use infrastructure::config::PqMode;
use tokio_rustls::rustls::crypto::{CryptoProvider, aws_lc_rs};

/// Install the PQ-aware [`CryptoProvider`] as the process-wide default.
///
/// Call once at startup, before any rustls or reqwest client is created, so
/// that every outbound connection built without an explicit provider - a feed
/// fetch, a webhook, an OIDC discovery, an mTLS cluster call - offers the
/// hybrid group too.
pub fn install_pq_provider(pq_mode: PqMode) {
    let outbound = outbound_mode(pq_mode);
    let provider = build_crypto_provider(outbound);
    let _ = provider.install_default();
    tracing::info!(
        ?pq_mode,
        ?outbound,
        "PQ CryptoProvider installed for outbound TLS"
    );
}

/// Translate the listener's PQ policy into the one the agent's own clients use.
///
/// `pq_mode` states which clients the listener accepts. Outbound connections
/// are the opposite side of that decision: threat-intel feeds, webhooks, SIEM
/// endpoints and the OIDC provider are servers this agent dials, and offering
/// `X25519MLKEM768` alone would make every one of them that lacks hybrid key
/// exchange unreachable, which today is nearly all of them. `require` therefore
/// keeps the classical fallback on the way out while still preferring hybrid;
/// only `disable`, which is a statement about PQ itself rather than about
/// inbound clients, takes the hybrid group off the wire in both directions.
#[must_use]
pub fn outbound_mode(pq_mode: PqMode) -> PqMode {
    match pq_mode {
        PqMode::Require => PqMode::Prefer,
        other => other,
    }
}

/// Build a [`CryptoProvider`] with key exchange groups ordered by PQ mode.
///
/// - `Prefer`: `X25519MLKEM768` > `X25519` > `SECP256R1`
/// - `Require`: `X25519MLKEM768` only
/// - `Disable`: `X25519` > `SECP256R1`
///
/// Public so that the enterprise crate builds its mTLS `ServerConfig` and
/// `ClientConfig` for HA replication, multi-cluster federation and SIEM export
/// from the same policy.
#[must_use]
pub fn build_crypto_provider(pq_mode: PqMode) -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();

    provider.kx_groups = match pq_mode {
        PqMode::Prefer => vec![
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        PqMode::Require => vec![aws_lc_rs::kx_group::X25519MLKEM768],
        PqMode::Disable => vec![aws_lc_rs::kx_group::X25519, aws_lc_rs::kx_group::SECP256R1],
    };

    provider
}

/// The provider the agent's own clients dial with, as an [`Arc`] ready for a
/// `*_with_provider` builder.
#[must_use]
pub fn client_provider(pq_mode: PqMode) -> Arc<CryptoProvider> {
    Arc::new(build_crypto_provider(outbound_mode(pq_mode)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::ProtocolVersion;

    fn group_names(pq_mode: PqMode) -> Vec<&'static str> {
        build_crypto_provider(pq_mode)
            .kx_groups
            .iter()
            .map(|g| {
                let name = g.name();
                match name {
                    tokio_rustls::rustls::NamedGroup::X25519MLKEM768 => "X25519MLKEM768",
                    tokio_rustls::rustls::NamedGroup::X25519 => "X25519",
                    tokio_rustls::rustls::NamedGroup::secp256r1 => "SECP256R1",
                    _ => "other",
                }
            })
            .collect()
    }

    #[test]
    fn the_hybrid_group_leads_the_default_list() {
        assert_eq!(
            group_names(PqMode::default()),
            vec!["X25519MLKEM768", "X25519", "SECP256R1"]
        );
    }

    #[test]
    fn requiring_the_hybrid_group_leaves_nothing_classical_on_the_wire() {
        assert_eq!(group_names(PqMode::Require), vec!["X25519MLKEM768"]);
    }

    #[test]
    fn disabling_takes_the_hybrid_group_off_both_directions() {
        assert_eq!(group_names(PqMode::Disable), vec!["X25519", "SECP256R1"]);
        assert_eq!(outbound_mode(PqMode::Disable), PqMode::Disable);
    }

    #[test]
    fn a_required_listener_still_dials_a_classical_server() {
        assert_eq!(outbound_mode(PqMode::Require), PqMode::Prefer);
        assert_eq!(
            group_names(outbound_mode(PqMode::Require)),
            vec!["X25519MLKEM768", "X25519", "SECP256R1"]
        );
    }

    /// The hybrid group exists in TLS 1.3 alone, which is what makes
    /// `allow_tls12` with `require` an unreachable listener and why the
    /// configuration refuses that pair rather than serving it.
    #[test]
    fn the_hybrid_group_is_offered_for_tls13_only() {
        let hybrid = aws_lc_rs::kx_group::X25519MLKEM768;
        assert!(hybrid.usable_for_version(ProtocolVersion::TLSv1_3));
        assert!(!hybrid.usable_for_version(ProtocolVersion::TLSv1_2));
    }
}
