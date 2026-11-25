//! The agent's own crypto posture: every TLS link it opened or accepted, the
//! key exchange policy each was built with, and the group each last
//! negotiated. This is about the agent's own connections, not the traffic it
//! watches; that is `/api/v1/tls/posture`.

use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use domain::prog_signing::{SigningPosture, SigningState};

use super::error::ErrorBody;

/// Handshakes one link completed on one group.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkGroupCount {
    /// The group, by its IANA name.
    pub group: String,
    /// Whether it carries a post-quantum component.
    pub post_quantum: bool,
    /// Handshakes completed on it since the process started.
    pub handshakes: u64,
}

/// One link.
#[derive(Debug, Serialize, ToSchema)]
pub struct LinkPostureBody {
    /// `api`, `grpc`, `outbound`, `flow-export`, or a link the enterprise
    /// layer adds (`ha-peer`, `federation`, `siem-syslog`, ...).
    pub link: String,
    /// `prefer`, `require` or `disable`; `null` when the link counted a
    /// handshake but its policy was not recorded.
    pub mode: Option<String>,
    /// The group the last handshake completed on, `null` before the first.
    pub last_group: Option<String>,
    /// Whether that group carries a post-quantum component.
    pub last_post_quantum: bool,
    /// When it completed, in seconds since the Unix epoch.
    pub last_at_unix: Option<u64>,
    /// Every group it completed a handshake on.
    pub groups: Vec<LinkGroupCount>,
}

/// What the agent does about BPF program signatures on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SigningStateBody {
    /// Start-up has not asked the kernel, so nothing is claimed.
    NotProbed,
    /// The kernel does not verify program signatures; the agent's programs
    /// load unsigned.
    Unsupported,
    /// The kernel could verify, and the agent's programs load unsigned.
    Unsigned,
    /// The agent's programs load through loaders signed at build, checked by
    /// the kernel against the warden's keyring, and nothing refuses an
    /// unsigned load through the token: see `not_enforced_because`.
    VerifiedNotEnforced,
    /// The kernel checks signatures against the warden's keyring and the
    /// warden's guard refuses every unsigned load through the token. Holds
    /// only with `bpf` in `lsm=` at boot and a kernel that verifies
    /// signatures.
    Enforced,
}

impl From<SigningState> for SigningStateBody {
    fn from(state: SigningState) -> Self {
        match state {
            SigningState::NotProbed => Self::NotProbed,
            SigningState::Unsupported => Self::Unsupported,
            SigningState::Unsigned => Self::Unsigned,
            SigningState::VerifiedNotEnforced => Self::VerifiedNotEnforced,
            SigningState::Enforced => Self::Enforced,
        }
    }
}

/// Whether the kernel verifies the agent's programs, and what could refuse
/// an unsigned one.
#[derive(Debug, Serialize, ToSchema)]
pub struct SigningPostureBody {
    /// The kernel reads a signature in a program load and checks it against
    /// a keyring, as start-up asked it. False when nobody asked.
    pub kernel_verifies_signatures: bool,
    /// The BPF LSM is among the active security modules.
    pub bpf_lsm_active: bool,
    /// What the agent does about it.
    pub state: SigningStateBody,
    /// The warden's guard on program loads is attached: every load through
    /// a BPF token on this host passes only signed against its keyring.
    pub load_guard_attached: bool,
    /// The serial of the keyring the kernel checked the signed loaders
    /// against; `null` unless the state is `verified_not_enforced` or
    /// `enforced`.
    pub keyring_serial: Option<i32>,
    /// SHA-256 of the DER certificate the loaders verify against, the digest
    /// the release's measurements record; `null` unless the state is
    /// `verified_not_enforced` or `enforced`.
    pub certificate_sha256: Option<String>,
    /// Programs loaded through a signed loader.
    pub signed_programs: u64,
    /// Programs loaded unsigned while the kernel could have checked them.
    pub unsigned_programs: u64,
    /// Programs the guard refused because they had no signed loader.
    pub refused_programs: u64,
    /// The first condition `enforced` lacks on this host; `null` when
    /// enforced.
    pub not_enforced_because: Option<String>,
    /// The state in one sentence.
    pub reason: String,
}

impl From<SigningPosture> for SigningPostureBody {
    fn from(posture: SigningPosture) -> Self {
        let reason = posture.reason().to_string();
        Self {
            kernel_verifies_signatures: posture.kernel_verifies_signatures,
            bpf_lsm_active: posture.bpf_lsm_active,
            state: posture.state.into(),
            load_guard_attached: posture.load_guard_attached,
            keyring_serial: posture.keyring_serial,
            certificate_sha256: posture.certificate_sha256,
            signed_programs: posture.signed_programs,
            unsigned_programs: posture.unsigned_programs,
            refused_programs: posture.refused_programs,
            not_enforced_because: posture.not_enforced_because,
            reason,
        }
    }
}

/// The agent's own links, and whether the kernel verifies its programs.
#[derive(Debug, Serialize, ToSchema)]
pub struct CryptoPostureResponse {
    /// The policy the agent's own clients dial with:
    /// `agent.tls.outbound_pq_mode`, or what it derives from `pq_mode`.
    pub outbound_mode: String,
    /// Whether every link with a recorded policy requires the hybrid group.
    pub all_required: bool,
    /// Every link, sorted by name.
    pub links: Vec<LinkPostureBody>,
    /// Whether the kernel verifies BPF program signatures here, whether the
    /// BPF LSM is active, and what the agent does about it.
    pub signing: SigningPostureBody,
}

/// `GET /api/v1/crypto/posture` - the key exchange each of the agent's own
/// links is built to accept and the one it last negotiated, and where the
/// agent stands on signed BPF programs.
#[utoipa::path(
    get, path = "/api/v1/crypto/posture",
    tag = "TLS",
    responses(
        (status = 200, description = "Each link, its key exchange policy and the group it last negotiated, and the program signing posture", body = CryptoPostureResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn crypto_posture() -> Json<CryptoPostureResponse> {
    Json(posture_body(
        adapters::tls::installed_outbound_mode(),
        &adapters::tls::link_posture(),
        host_signing_posture(),
    ))
}

/// The signing posture from what start-up probed, the BPF LSM as the host
/// reports it now, and what the signed loaders did. Issues no load: an
/// unprobed kernel is reported as such.
fn host_signing_posture() -> SigningPosture {
    SigningPosture::derive(
        adapters::ebpf::prog_signing_probe::cached().and_then(|s| s.verifies),
        adapters::ebpf::lsm_probe::status().active,
    )
    .with_loads(adapters::ebpf::signed_loader::signed_loads())
}

fn posture_body(
    outbound: infrastructure::config::PqMode,
    links: &[adapters::tls::LinkPosture],
    signing: SigningPosture,
) -> CryptoPostureResponse {
    use adapters::tls::{group_name, is_post_quantum};
    use infrastructure::config::PqMode;

    let links: Vec<LinkPostureBody> = links
        .iter()
        .map(|l| LinkPostureBody {
            link: l.link.to_string(),
            mode: l.mode.map(|m| m.as_str().to_string()),
            last_group: l.last.map(|h| group_name(h.group)),
            last_post_quantum: l.last.is_some_and(|h| is_post_quantum(h.group)),
            last_at_unix: l.last.map(|h| h.at_unix),
            groups: l
                .handshakes
                .iter()
                .map(|&(group, handshakes)| LinkGroupCount {
                    group: group_name(group),
                    post_quantum: is_post_quantum(group),
                    handshakes,
                })
                .collect(),
        })
        .collect();
    let all_required = outbound == PqMode::Require
        && links
            .iter()
            .filter(|l| l.mode.is_some())
            .all(|l| l.mode.as_deref() == Some(PqMode::Require.as_str()));
    CryptoPostureResponse {
        outbound_mode: outbound.as_str().to_string(),
        all_required,
        links,
        signing: signing.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapters::tls::{LastHandshake, LinkPosture};
    use domain::prog_signing::{LoadGuardReport, SignedLoads};
    use infrastructure::config::PqMode;
    use tokio_rustls::rustls::NamedGroup;

    fn link(name: &'static str, mode: PqMode, last: Option<NamedGroup>) -> LinkPosture {
        LinkPosture {
            link: name,
            mode: Some(mode),
            last: last.map(|group| LastHandshake {
                group,
                at_unix: 1_700_000_000,
            }),
            handshakes: last.map_or_else(Vec::new, |g| vec![(g, 3)]),
        }
    }

    #[test]
    fn each_link_says_its_policy_and_what_it_last_negotiated() {
        let body = posture_body(
            PqMode::Prefer,
            &[
                link("api", PqMode::Require, Some(NamedGroup::X25519MLKEM768)),
                link("outbound", PqMode::Prefer, Some(NamedGroup::X25519)),
                link("grpc", PqMode::Require, None),
            ],
            SigningPosture::derive(None, false),
        );
        assert_eq!(body.outbound_mode, "prefer");
        assert!(!body.all_required);
        assert_eq!(body.links[0].mode.as_deref(), Some("require"));
        assert_eq!(body.links[0].last_group.as_deref(), Some("X25519MLKEM768"));
        assert!(body.links[0].last_post_quantum);
        assert_eq!(body.links[0].groups[0].handshakes, 3);
        assert_eq!(body.links[1].last_group.as_deref(), Some("X25519"));
        assert!(!body.links[1].last_post_quantum);
        assert!(body.links[2].last_group.is_none());
    }

    #[test]
    fn require_everywhere_is_said_once() {
        let body = posture_body(
            PqMode::Require,
            &[
                link("api", PqMode::Require, None),
                link("outbound", PqMode::Require, None),
            ],
            SigningPosture::derive(None, false),
        );
        assert!(body.all_required);
    }

    #[test]
    fn the_signing_block_carries_both_host_facts_and_the_derived_state() {
        let body = posture_body(
            PqMode::Prefer,
            &[],
            SigningPosture::derive(Some(true), true),
        );
        assert!(body.signing.kernel_verifies_signatures);
        assert!(body.signing.bpf_lsm_active);
        assert_eq!(body.signing.state, SigningStateBody::Unsigned);

        let body = posture_body(
            PqMode::Prefer,
            &[],
            SigningPosture::derive(Some(false), false),
        );
        assert!(!body.signing.kernel_verifies_signatures);
        assert!(!body.signing.bpf_lsm_active);
        assert_eq!(body.signing.state, SigningStateBody::Unsupported);

        let body = posture_body(PqMode::Prefer, &[], SigningPosture::derive(None, true));
        assert!(!body.signing.kernel_verifies_signatures);
        assert_eq!(body.signing.state, SigningStateBody::NotProbed);
    }

    #[test]
    fn the_signing_block_serializes_as_booleans_a_state_word_and_a_reason() {
        let body = posture_body(
            PqMode::Prefer,
            &[],
            SigningPosture::derive(Some(true), false),
        );
        let json = serde_json::to_value(&body).expect("serializes");
        let signing = &json["signing"];
        assert_eq!(
            signing["kernel_verifies_signatures"],
            serde_json::json!(true)
        );
        assert_eq!(signing["bpf_lsm_active"], serde_json::json!(false));
        assert_eq!(signing["state"], serde_json::json!("unsigned"));
        assert!(signing["reason"].as_str().is_some_and(|r| !r.is_empty()));
        assert_eq!(signing["load_guard_attached"], serde_json::json!(false));
        assert!(
            signing["not_enforced_because"]
                .as_str()
                .is_some_and(|w| w.contains("lsm=")),
            "a node booted without the BPF LSM says so"
        );
        assert_eq!(signing["keyring_serial"], serde_json::Value::Null);
        assert_eq!(signing["certificate_sha256"], serde_json::Value::Null);
    }

    #[test]
    fn a_signed_load_reports_the_keyring_serial_and_the_certificate_digest() {
        let posture = SigningPosture::derive(Some(true), true).with_loads(SignedLoads {
            keyring_serial: Some(123_456),
            certificate_sha256: Some("0f".repeat(32)),
            signed_programs: 12,
            unsigned_programs: 0,
            refused_programs: 0,
            load_guard: LoadGuardReport::NotReported,
        });
        let body = posture_body(PqMode::Prefer, &[], posture);
        let json = serde_json::to_value(&body).expect("serializes");
        let signing = &json["signing"];
        assert_eq!(signing["state"], serde_json::json!("verified_not_enforced"));
        assert_eq!(signing["keyring_serial"], serde_json::json!(123_456));
        assert_eq!(
            signing["certificate_sha256"],
            serde_json::json!("0f".repeat(32))
        );
        assert_eq!(signing["signed_programs"], serde_json::json!(12));
        assert_eq!(signing["load_guard_attached"], serde_json::json!(false));
    }

    #[test]
    fn an_attached_guard_reports_enforced_and_what_it_refused() {
        let posture = SigningPosture::derive(Some(true), true).with_loads(SignedLoads {
            keyring_serial: Some(123_456),
            certificate_sha256: Some("0f".repeat(32)),
            signed_programs: 12,
            unsigned_programs: 0,
            refused_programs: 1,
            load_guard: LoadGuardReport::Attached,
        });
        let body = posture_body(PqMode::Prefer, &[], posture);
        let json = serde_json::to_value(&body).expect("serializes");
        let signing = &json["signing"];
        assert_eq!(signing["state"], serde_json::json!("enforced"));
        assert_eq!(signing["load_guard_attached"], serde_json::json!(true));
        assert_eq!(signing["refused_programs"], serde_json::json!(1));
        assert_eq!(signing["not_enforced_because"], serde_json::Value::Null);
    }

    #[test]
    fn the_state_word_is_the_domain_word() {
        for state in [
            SigningState::NotProbed,
            SigningState::Unsupported,
            SigningState::Unsigned,
            SigningState::VerifiedNotEnforced,
            SigningState::Enforced,
        ] {
            assert_eq!(
                serde_json::to_value(SigningStateBody::from(state)).expect("serializes"),
                serde_json::json!(state.as_str())
            );
        }
    }
}
