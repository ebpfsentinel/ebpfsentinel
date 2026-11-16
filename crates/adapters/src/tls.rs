//! The key-exchange policy every TLS surface of the agent is built from, and
//! the record of what each of those surfaces actually negotiated.
//!
//! A provider built here does two things. It orders the groups by
//! [`PqMode`], so the hybrid `X25519MLKEM768` leads unless it was turned off.
//! And every group in it is wrapped so that the one key exchange the
//! handshake completes is counted under the link that built the provider:
//! the group a peer and this process agreed on is the only fact that says a
//! link is post-quantum, and offering a group says nothing about whether it
//! was picked. The counts are read by `/metrics` as
//! `tls_handshakes_total{link, group}` and by the crypto posture endpoint as
//! the last group each link negotiated.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use infrastructure::config::PqMode;
use tokio_rustls::rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup,
    aws_lc_rs,
};
use tokio_rustls::rustls::ffdhe_groups::FfdheGroup;
use tokio_rustls::rustls::{
    AlertDescription, Error, NamedGroup, PeerIncompatible, ProtocolVersion,
    SupportedProtocolVersion,
};

/// The link every client built without a provider of its own is counted
/// under: feeds, webhooks, OIDC discovery and JWKS, cluster calls.
pub const LINK_OUTBOUND: &str = "outbound";
/// The REST and Prometheus listener.
pub const LINK_API: &str = "api";
/// The gRPC listener.
pub const LINK_GRPC: &str = "grpc";
/// Flow records shipped to a text collector.
pub const LINK_FLOW_EXPORT: &str = "flow-export";

/// Install the PQ-aware [`CryptoProvider`] as the process-wide default.
///
/// Call once at startup, before any rustls or reqwest client is created, so
/// that every outbound connection built without an explicit provider - a feed
/// fetch, a webhook, an OIDC discovery, an mTLS cluster call - offers the
/// hybrid group too, and is counted under [`LINK_OUTBOUND`].
///
/// `outbound` is the policy the agent's own clients dial with, as
/// `TlsConfig::effective_outbound_pq_mode` derives it: `require` here means a
/// server without hybrid key exchange is refused.
pub fn install_pq_provider(outbound: PqMode) {
    *INSTALLED_OUTBOUND
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Some(outbound);
    let provider = build_crypto_provider(LINK_OUTBOUND, outbound);
    let _ = provider.install_default();
    tracing::info!(?outbound, "PQ CryptoProvider installed for outbound TLS");
}

static INSTALLED_OUTBOUND: Mutex<Option<PqMode>> = Mutex::new(None);

/// The mode the process-default provider was installed with, or `Prefer`
/// where nothing installed one (a unit test that never ran start-up).
///
/// A client that builds its own configuration under a link of its own - a
/// SIEM exporter, a flow collector, the interception proxy's upstream half -
/// takes this, so it offers what the process default offers and is still
/// counted apart.
#[must_use]
pub fn installed_outbound_mode() -> PqMode {
    INSTALLED_OUTBOUND
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .unwrap_or(PqMode::Prefer)
}

/// Build a [`CryptoProvider`] with key exchange groups ordered by PQ mode,
/// each counted under `link` when a handshake completes on it.
///
/// - `Prefer`: `X25519MLKEM768` > `X25519` > `SECP256R1`
/// - `Require`: `X25519MLKEM768` only
/// - `Disable`: `X25519` > `SECP256R1`
///
/// Public so that the enterprise crate builds its mTLS `ServerConfig` and
/// `ClientConfig` for HA replication, multi-cluster federation and SIEM export
/// from the same policy and the same ledger.
#[must_use]
pub fn build_crypto_provider(link: &'static str, pq_mode: PqMode) -> CryptoProvider {
    let mut provider = aws_lc_rs::default_provider();

    let groups: &[&'static dyn SupportedKxGroup] = match pq_mode {
        PqMode::Prefer => &[
            aws_lc_rs::kx_group::X25519MLKEM768,
            aws_lc_rs::kx_group::X25519,
            aws_lc_rs::kx_group::SECP256R1,
        ],
        PqMode::Require => &[aws_lc_rs::kx_group::X25519MLKEM768],
        PqMode::Disable => &[aws_lc_rs::kx_group::X25519, aws_lc_rs::kx_group::SECP256R1],
    };
    provider.kx_groups = groups.iter().map(|g| recorded(link, *g)).collect();
    MODES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(link, pq_mode);

    provider
}

/// The provider a client of the agent's dials with under `link`, as an
/// [`Arc`] ready for a `*_with_provider` builder. `outbound` is the client
/// policy itself, usually [`installed_outbound_mode`].
#[must_use]
pub fn client_provider(link: &'static str, outbound: PqMode) -> Arc<CryptoProvider> {
    Arc::new(build_crypto_provider(link, outbound))
}

/// Whether a failed handshake is a peer turning down every group offered,
/// which is what a classical-only server does when this side offered
/// `X25519MLKEM768` alone.
///
/// Reads the rustls error out of the I/O error `tokio-rustls` hands back.
#[must_use]
pub fn refused_for_want_of_a_shared_group(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<Error>())
        .is_some_and(|inner| {
            matches!(
                inner,
                Error::AlertReceived(
                    AlertDescription::HandshakeFailure
                        | AlertDescription::IllegalParameter
                        | AlertDescription::InsufficientSecurity
                ) | Error::PeerIncompatible(PeerIncompatible::NoKxGroupsInCommon)
            )
        })
}

/// What a handshake failure means to the operator, said in the link's terms.
///
/// Under `require` a peer that answered with a refusal is taken to have no
/// hybrid key exchange, and the message names the setting that refused it;
/// anything else is the error as rustls put it.
#[must_use]
pub fn explain_handshake_failure(mode: PqMode, error: &std::io::Error) -> String {
    if mode == PqMode::Require && refused_for_want_of_a_shared_group(error) {
        format!(
            "the peer offers no post-quantum key exchange and this link requires \
             X25519MLKEM768 (outbound_pq_mode: require), so it was refused: {error}"
        )
    } else {
        format!("tls handshake failed: {error}")
    }
}

/// The name a group is reported under: the IANA name rustls knows it by, or
/// its code point when rustls has no name for it.
#[must_use]
pub fn group_name(group: NamedGroup) -> String {
    group
        .as_str()
        .map_or_else(|| format!("0x{:04x}", u16::from(group)), str::to_owned)
}

/// Whether a group carries a post-quantum component.
#[must_use]
pub fn is_post_quantum(group: NamedGroup) -> bool {
    group
        .as_str()
        .is_some_and(|name| name.to_ascii_uppercase().contains("MLKEM"))
}

/// One link's handshakes on one group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeCount {
    /// The link the provider was built for.
    pub link: &'static str,
    /// The group the handshake completed on.
    pub group: NamedGroup,
    /// How many handshakes completed on it since the process started.
    pub count: u64,
}

/// The last handshake a link completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastHandshake {
    /// The group it completed on.
    pub group: NamedGroup,
    /// When, in seconds since the Unix epoch.
    pub at_unix: u64,
}

#[derive(Default)]
struct Ledger {
    counts: BTreeMap<(&'static str, u16), u64>,
    last: BTreeMap<&'static str, LastHandshake>,
}

static LEDGER: Mutex<Ledger> = Mutex::new(Ledger {
    counts: BTreeMap::new(),
    last: BTreeMap::new(),
});

pub(crate) fn record(link: &'static str, group: NamedGroup) {
    let at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    // Counters stay valid after a partial write: the worst a poisoned lock
    // hides is one handshake that was not counted.
    let mut ledger = LEDGER.lock().unwrap_or_else(PoisonError::into_inner);
    *ledger.counts.entry((link, u16::from(group))).or_insert(0) += 1;
    ledger.last.insert(link, LastHandshake { group, at_unix });
}

/// Every link and group a handshake completed on since the process started.
#[must_use]
pub fn handshake_counts() -> Vec<HandshakeCount> {
    let ledger = LEDGER.lock().unwrap_or_else(PoisonError::into_inner);
    ledger
        .counts
        .iter()
        .map(|(&(link, code), &count)| HandshakeCount {
            link,
            group: NamedGroup::from(code),
            count,
        })
        .collect()
}

/// One link as this process built it and as it has run since.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPosture {
    /// The link.
    pub link: &'static str,
    /// The policy its provider was built with; `None` for a link that
    /// counted a handshake without this process recording its policy.
    pub mode: Option<PqMode>,
    /// The last handshake it completed.
    pub last: Option<LastHandshake>,
    /// Its handshakes by group since the process started.
    pub handshakes: Vec<(NamedGroup, u64)>,
}

/// Every link a provider was built for or a handshake completed on, sorted
/// by name: the agent's own crypto posture.
#[must_use]
pub fn link_posture() -> Vec<LinkPosture> {
    let modes = MODES.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let ledger = LEDGER.lock().unwrap_or_else(PoisonError::into_inner);
    let mut links: BTreeMap<&'static str, LinkPosture> = modes
        .into_iter()
        .map(|(link, mode)| {
            (
                link,
                LinkPosture {
                    link,
                    mode: Some(mode),
                    last: None,
                    handshakes: Vec::new(),
                },
            )
        })
        .collect();
    for (&(link, code), &count) in &ledger.counts {
        links
            .entry(link)
            .or_insert_with(|| LinkPosture {
                link,
                mode: None,
                last: None,
                handshakes: Vec::new(),
            })
            .handshakes
            .push((NamedGroup::from(code), count));
    }
    for (&link, &last) in &ledger.last {
        if let Some(posture) = links.get_mut(link) {
            posture.last = Some(last);
        }
    }
    links.into_values().collect()
}

/// The policy each link's provider was last built with.
static MODES: Mutex<BTreeMap<&'static str, PqMode>> = Mutex::new(BTreeMap::new());

/// The last handshake a link completed, if it completed one.
#[must_use]
pub fn last_handshake(link: &str) -> Option<LastHandshake> {
    LEDGER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .last
        .get(link)
        .copied()
}

/// One wrapped group per link, built once: providers are rebuilt per
/// connection on some links, and a group the provider list holds must live
/// for the life of the process.
static WRAPPED: Mutex<Vec<&'static RecordedGroup>> = Mutex::new(Vec::new());

fn recorded(
    link: &'static str,
    inner: &'static dyn SupportedKxGroup,
) -> &'static dyn SupportedKxGroup {
    let mut wrapped = WRAPPED.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(existing) = wrapped
        .iter()
        .find(|w| w.link == link && w.inner.name() == inner.name())
    {
        return *existing;
    }
    let fresh: &'static RecordedGroup = Box::leak(Box::new(RecordedGroup { link, inner }));
    wrapped.push(fresh);
    fresh
}

/// A key-exchange group that counts the handshakes completed on it.
///
/// A server completes through [`SupportedKxGroup::start_and_complete`]; a
/// client through [`ActiveKeyExchange::complete`], or through
/// [`ActiveKeyExchange::complete_hybrid_component`] when it offered the hybrid
/// group and the server took only its classical half. Each path counts the
/// group it actually completed and nothing else, so offering a group is never
/// counted as negotiating it.
#[derive(Debug)]
struct RecordedGroup {
    link: &'static str,
    inner: &'static dyn SupportedKxGroup,
}

impl SupportedKxGroup for RecordedGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(RecordedExchange {
            link: self.link,
            inner: self.inner.start()?,
        }))
    }

    fn start_and_complete(&self, peer_pub_key: &[u8]) -> Result<CompletedKeyExchange, Error> {
        let completed = self.inner.start_and_complete(peer_pub_key)?;
        record(self.link, completed.group);
        Ok(completed)
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        self.inner.ffdhe_group()
    }

    fn name(&self) -> NamedGroup {
        self.inner.name()
    }

    fn fips(&self) -> bool {
        self.inner.fips()
    }

    fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        self.inner.usable_for_version(version)
    }
}

struct RecordedExchange {
    link: &'static str,
    inner: Box<dyn ActiveKeyExchange>,
}

impl ActiveKeyExchange for RecordedExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let group = self.inner.group();
        let secret = self.inner.complete(peer_pub_key)?;
        record(self.link, group);
        Ok(secret)
    }

    fn complete_for_tls_version(
        self: Box<Self>,
        peer_pub_key: &[u8],
        tls_version: &SupportedProtocolVersion,
    ) -> Result<SharedSecret, Error> {
        let group = self.inner.group();
        let secret = self
            .inner
            .complete_for_tls_version(peer_pub_key, tls_version)?;
        record(self.link, group);
        Ok(secret)
    }

    fn hybrid_component(&self) -> Option<(NamedGroup, &[u8])> {
        self.inner.hybrid_component()
    }

    fn complete_hybrid_component(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> Result<SharedSecret, Error> {
        let group = self.inner.hybrid_component().map(|(group, _)| group);
        let secret = self.inner.complete_hybrid_component(peer_pub_key)?;
        if let Some(group) = group {
            record(self.link, group);
        }
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        self.inner.pub_key()
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        self.inner.ffdhe_group()
    }

    fn group(&self) -> NamedGroup {
        self.inner.group()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::rustls::ProtocolVersion;

    fn group_names(pq_mode: PqMode) -> Vec<&'static str> {
        build_crypto_provider("test-names", pq_mode)
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
    fn disabling_takes_the_hybrid_group_off_the_wire() {
        assert_eq!(group_names(PqMode::Disable), vec!["X25519", "SECP256R1"]);
    }

    #[test]
    fn a_link_reports_the_policy_it_was_built_with() {
        let _ = build_crypto_provider("test-posture", PqMode::Require);
        let posture = link_posture();
        let link = posture
            .iter()
            .find(|l| l.link == "test-posture")
            .expect("the link is listed once its provider exists");
        assert_eq!(link.mode, Some(PqMode::Require));
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

    // ── The group a handshake completes on ──────────────────────────

    use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio_rustls::rustls::{
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection,
    };

    fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("a self-signed certificate for the test peer");
        (
            cert.cert.der().clone(),
            PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
        )
    }

    /// Complete a handshake in memory between a client and a server built
    /// from this module's providers, and return the group the client says
    /// it negotiated.
    fn handshake(
        client: (&'static str, PqMode),
        server: (&'static str, PqMode),
    ) -> Result<NamedGroup, Error> {
        let (cert, key) = self_signed();
        let mut roots = RootCertStore::empty();
        roots
            .add(cert.clone())
            .expect("the test certificate is an authority");
        let client_config = ClientConfig::builder_with_provider(Arc::new(build_crypto_provider(
            client.0, client.1,
        )))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let server_config = ServerConfig::builder_with_provider(Arc::new(build_crypto_provider(
            server.0, server.1,
        )))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

        let name = ServerName::try_from("localhost").expect("a valid server name");
        let mut client = ClientConnection::new(Arc::new(client_config), name)?;
        let mut server = ServerConnection::new(Arc::new(server_config))?;
        for _ in 0..16 {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).expect("an in-memory write");
            server
                .read_tls(&mut wire.as_slice())
                .expect("an in-memory read");
            server.process_new_packets()?;
            let mut wire = Vec::new();
            server.write_tls(&mut wire).expect("an in-memory write");
            client
                .read_tls(&mut wire.as_slice())
                .expect("an in-memory read");
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking(), "the handshake never completed");
        Ok(client
            .negotiated_key_exchange_group()
            .expect("a completed TLS 1.3 handshake names its group")
            .name())
    }

    fn counted(link: &str, group: NamedGroup) -> u64 {
        handshake_counts()
            .iter()
            .filter(|c| c.link == link && c.group == group)
            .map(|c| c.count)
            .sum()
    }

    #[test]
    fn two_default_peers_negotiate_the_hybrid_group_and_both_count_it() {
        let group = handshake(
            ("test-default-client", PqMode::Prefer),
            ("test-default-server", PqMode::Prefer),
        )
        .expect("two default peers agree");
        assert_eq!(group, NamedGroup::X25519MLKEM768);
        assert_eq!(
            counted("test-default-client", NamedGroup::X25519MLKEM768),
            1
        );
        assert_eq!(
            counted("test-default-server", NamedGroup::X25519MLKEM768),
            1
        );
        assert_eq!(
            last_handshake("test-default-client").map(|l| l.group),
            Some(NamedGroup::X25519MLKEM768)
        );
    }

    /// The client offers the hybrid share and its classical half; a server
    /// that disabled the hybrid group takes the half, and the client counts
    /// what it completed, not what it led with.
    #[test]
    fn a_classical_server_is_counted_classical_on_the_client_side() {
        let group = handshake(
            ("test-hybrid-half-client", PqMode::Prefer),
            ("test-hybrid-half-server", PqMode::Disable),
        )
        .expect("a classical server still answers a preferring client");
        assert_eq!(group, NamedGroup::X25519);
        assert_eq!(counted("test-hybrid-half-client", NamedGroup::X25519), 1);
        assert_eq!(
            counted("test-hybrid-half-client", NamedGroup::X25519MLKEM768),
            0
        );
        assert_eq!(counted("test-hybrid-half-server", NamedGroup::X25519), 1);
    }

    #[test]
    fn a_requiring_server_refuses_a_classical_client_and_counts_nothing() {
        let refused = handshake(
            ("test-refused-client", PqMode::Disable),
            ("test-refused-server", PqMode::Require),
        );
        assert!(
            refused.is_err(),
            "a classical client reached a require listener"
        );
        assert!(last_handshake("test-refused-client").is_none());
        assert!(last_handshake("test-refused-server").is_none());
    }

    #[test]
    fn group_names_are_the_iana_names_and_ml_kem_is_post_quantum() {
        assert_eq!(group_name(NamedGroup::X25519MLKEM768), "X25519MLKEM768");
        assert_eq!(group_name(NamedGroup::from(0xfafa)), "0xfafa");
        assert!(is_post_quantum(NamedGroup::X25519MLKEM768));
        assert!(!is_post_quantum(NamedGroup::X25519));
    }
}
