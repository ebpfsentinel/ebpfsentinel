//! The agent's own crypto posture: every TLS link it opened or accepted, the
//! key exchange policy each was built with, and the group each last
//! negotiated. This is about the agent's own connections, not the traffic it
//! watches; that is `/api/v1/tls/posture`.

use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

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

/// The agent's own links.
#[derive(Debug, Serialize, ToSchema)]
pub struct CryptoPostureResponse {
    /// The policy the agent's own clients dial with:
    /// `agent.tls.outbound_pq_mode`, or what it derives from `pq_mode`.
    pub outbound_mode: String,
    /// Whether every link with a recorded policy requires the hybrid group.
    pub all_required: bool,
    /// Every link, sorted by name.
    pub links: Vec<LinkPostureBody>,
}

/// `GET /api/v1/crypto/posture` - the key exchange each of the agent's own
/// links is built to accept and the one it last negotiated.
#[utoipa::path(
    get, path = "/api/v1/crypto/posture",
    tag = "TLS",
    responses(
        (status = 200, description = "Each link, its key exchange policy and the group it last negotiated", body = CryptoPostureResponse),
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
    ))
}

fn posture_body(
    outbound: infrastructure::config::PqMode,
    links: &[adapters::tls::LinkPosture],
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adapters::tls::{LastHandshake, LinkPosture};
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
        );
        assert!(body.all_required);
    }
}
