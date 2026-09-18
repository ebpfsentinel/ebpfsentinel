use std::collections::HashMap;
use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use domain::auth::entity::JwtClaims;
use domain::firewall::entity::PortRange;
use domain::nat::entity::{NatRule, NatType};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use infrastructure::config::group_mask_words;

use super::error::{ApiError, ErrorBody};
use super::middleware::rbac::require_write_access;
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct NatStatusResponse {
    pub enabled: bool,
    pub rule_count: usize,
}

#[derive(Serialize, ToSchema)]
pub struct NatRuleResponse {
    pub id: String,
    /// The translation this rule performs, spelled as the configuration file
    /// spells it: `snat`, `dnat`, `masquerade`, `one_to_one`, `redirect` or
    /// `port_forward`.
    pub nat_type: String,
    pub direction: String,
    pub priority: u32,
    pub enabled: bool,
    /// What the rule rewrites to. The fields are the type's own, so a reader
    /// sees the address and the ports the rule was written with rather than
    /// the type word alone.
    pub translation: NatTranslation,
    /// What the rule is narrowed to. A rule carrying none of these translates
    /// every packet the direction carries, so each is absent rather than an
    /// empty value a reader would take for a restriction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_dst: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_dst_port: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_protocol: Option<String>,
    /// The alias a rule still names, which is a rule whose match criteria the
    /// alias service has not resolved into CIDRs yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_src_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub match_dst_alias: Option<String>,
    /// The interface groups this rule is scoped to, in the words the
    /// configuration file used, `!` prefix included. Empty is a floating
    /// rule, which translates on every interface the programs are on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
}

/// The addresses and ports a translation rewrites to.
///
/// Tagged with the same word `nat_type` carries, since a reader deciding what
/// a rule does reads the two together.
#[derive(Serialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NatTranslation {
    Snat {
        addr: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        port_range: Option<String>,
    },
    Dnat {
        addr: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },
    Masquerade {
        interface: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        port_range: Option<String>,
    },
    OneToOne {
        external: String,
        internal: String,
    },
    Redirect {
        port: u16,
    },
    PortForward {
        ext_port: String,
        int_addr: String,
        int_port: String,
    },
}

/// A port range as the configuration file writes one: a single port where
/// both ends are the same, the two ends otherwise.
fn port_range_words(range: PortRange) -> String {
    if range.start == range.end {
        range.start.to_string()
    } else {
        format!("{}-{}", range.start, range.end)
    }
}

/// The type word and the values behind it, read off the rule itself.
///
/// The word is the one the configuration file uses rather than the Rust
/// variant's own rendering, which ran the words together and carried the
/// addresses along inside it as a debug dump.
fn translation_of(nat_type: &NatType) -> (String, NatTranslation) {
    match nat_type {
        NatType::Snat { addr, port_range } => (
            "snat".to_string(),
            NatTranslation::Snat {
                addr: addr.to_string(),
                port_range: port_range.map(port_range_words),
            },
        ),
        NatType::Dnat { addr, port } => (
            "dnat".to_string(),
            NatTranslation::Dnat {
                addr: addr.to_string(),
                port: *port,
            },
        ),
        NatType::Masquerade {
            interface,
            port_range,
        } => (
            "masquerade".to_string(),
            NatTranslation::Masquerade {
                interface: interface.clone(),
                port_range: port_range.map(port_range_words),
            },
        ),
        NatType::OneToOne { external, internal } => (
            "one_to_one".to_string(),
            NatTranslation::OneToOne {
                external: external.to_string(),
                internal: internal.to_string(),
            },
        ),
        NatType::Redirect { port } => (
            "redirect".to_string(),
            NatTranslation::Redirect { port: *port },
        ),
        NatType::PortForward {
            ext_port,
            int_addr,
            int_port,
        } => (
            "port_forward".to_string(),
            NatTranslation::PortForward {
                ext_port: port_range_words(*ext_port),
                int_addr: int_addr.to_string(),
                int_port: port_range_words(*int_port),
            },
        ),
    }
}

/// One rule read into the shape the listing answers with.
fn rule_response(
    rule: &NatRule,
    direction: &str,
    group_bits: &HashMap<String, u32>,
) -> NatRuleResponse {
    let (nat_type, translation) = translation_of(&rule.nat_type);
    NatRuleResponse {
        id: rule.id.0.clone(),
        nat_type,
        direction: direction.to_string(),
        priority: rule.priority,
        enabled: rule.enabled,
        translation,
        match_src: rule.match_src.clone(),
        match_dst: rule.match_dst.clone(),
        match_dst_port: rule.match_dst_port.map(port_range_words),
        match_protocol: rule.match_protocol.clone(),
        match_src_alias: rule.match_src_alias.clone(),
        match_dst_alias: rule.match_dst_alias.clone(),
        interfaces: group_mask_words(rule.group_mask, group_bits),
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/nat/status` - NAT status.
#[utoipa::path(
    get, path = "/api/v1/nat/status",
    tag = "NAT",
    responses((status = 200, description = "NAT status", body = NatStatusResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn nat_status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<NatStatusResponse>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let svc = nat.read().await;
    Ok(Json(NatStatusResponse {
        enabled: svc.enabled(),
        rule_count: svc.rule_count(),
    }))
}

/// `GET /api/v1/nat/rules` - list NAT rules.
#[utoipa::path(
    get, path = "/api/v1/nat/rules",
    tag = "NAT",
    responses((status = 200, description = "NAT rules", body = Vec<NatRuleResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_nat_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NatRuleResponse>>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    // A rule scoped to one interface group does not translate everywhere, so
    // the listing names the groups rather than leaving the reader to assume
    // the widest of them.
    let group_bits = state.config.read().await.interface_group_bitmasks();
    let svc = nat.read().await;
    let mut rules: Vec<NatRuleResponse> = svc
        .dnat_rules()
        .iter()
        .map(|r| rule_response(r, "dnat", &group_bits))
        .collect();
    rules.extend(
        svc.snat_rules()
            .iter()
            .map(|r| rule_response(r, "snat", &group_bits)),
    );
    Ok(Json(rules))
}

// ── NPTv6 DTOs ───────────────────────────────────────────────────

/// Response DTO for an `NPTv6` prefix translation rule.
#[derive(Serialize, ToSchema)]
pub struct NptV6RuleResponse {
    pub id: String,
    pub enabled: bool,
    pub internal_prefix: String,
    pub external_prefix: String,
    pub prefix_len: u8,
    /// The interface groups this rule is scoped to, in the words the
    /// configuration file used, `!` prefix included. Empty is a floating
    /// rule, which translates on every interface the programs are on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<String>,
}

/// Request DTO for creating an `NPTv6` prefix translation rule.
#[derive(Deserialize, ToSchema)]
pub struct CreateNptV6RuleRequest {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub internal_prefix: String,
    pub external_prefix: String,
    pub prefix_len: u8,
}

fn default_true() -> bool {
    true
}

// ── NPTv6 Handlers ──────────────────────────────────────────────

/// `GET /api/v1/nat/nptv6` -- list `NPTv6` rules.
#[utoipa::path(
    get, path = "/api/v1/nat/nptv6",
    tag = "NAT",
    responses((status = 200, description = "NPTv6 rules", body = Vec<NptV6RuleResponse>),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn list_nptv6_rules(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<NptV6RuleResponse>>, ApiError> {
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let group_bits = state.config.read().await.interface_group_bitmasks();
    let svc = nat.read().await;
    let rules: Vec<NptV6RuleResponse> = svc
        .nptv6_rules()
        .iter()
        .map(|r| NptV6RuleResponse {
            id: r.id.clone(),
            enabled: r.enabled,
            internal_prefix: r.internal_prefix.to_string(),
            external_prefix: r.external_prefix.to_string(),
            prefix_len: r.prefix_len,
            interfaces: group_mask_words(r.group_mask, &group_bits),
        })
        .collect();
    Ok(Json(rules))
}

/// `POST /api/v1/nat/nptv6` -- create an `NPTv6` rule.
#[utoipa::path(
    post, path = "/api/v1/nat/nptv6",
    tag = "NAT",
    request_body = CreateNptV6RuleRequest,
    responses(
        (status = 201, description = "NPTv6 rule created", body = NptV6RuleResponse),
        (status = 400, description = "Invalid rule", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn create_nptv6_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Json(req): Json<CreateNptV6RuleRequest>,
) -> Result<(StatusCode, Json<NptV6RuleResponse>), ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;

    let internal_prefix: std::net::Ipv6Addr =
        req.internal_prefix
            .parse()
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_PREFIX",
                message: format!("invalid internal_prefix: {e}"),
            })?;
    let external_prefix: std::net::Ipv6Addr =
        req.external_prefix
            .parse()
            .map_err(|e| ApiError::BadRequest {
                code: "INVALID_PREFIX",
                message: format!("invalid external_prefix: {e}"),
            })?;

    let rule = domain::nat::entity::NptV6Rule {
        id: req.id.clone(),
        enabled: req.enabled,
        internal_prefix,
        external_prefix,
        prefix_len: req.prefix_len,
        group_mask: 0,
    };

    let mut svc = nat.write().await;
    svc.add_nptv6_rule(rule).map_err(|e| ApiError::BadRequest {
        code: "INVALID_RULE",
        message: e.to_string(),
    })?;

    Ok((
        StatusCode::CREATED,
        Json(NptV6RuleResponse {
            id: req.id,
            enabled: req.enabled,
            internal_prefix: internal_prefix.to_string(),
            external_prefix: external_prefix.to_string(),
            prefix_len: req.prefix_len,
            // A rule created here is floating: the request carries no group.
            interfaces: Vec::new(),
        }),
    ))
}

/// `DELETE /api/v1/nat/nptv6/{id}` -- delete an `NPTv6` rule.
#[utoipa::path(
    delete, path = "/api/v1/nat/nptv6/{id}",
    tag = "NAT",
    params(("id" = String, Path, description = "NPTv6 rule ID")),
    responses(
        (status = 204, description = "NPTv6 rule deleted"),
        (status = 404, description = "Rule not found", body = ErrorBody),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn delete_nptv6_rule(
    State(state): State<Arc<AppState>>,
    claims: Option<Extension<JwtClaims>>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if let Some(Extension(ref claims)) = claims {
        require_write_access(claims)?;
    }
    let nat = state.nat_service.as_ref().ok_or(ApiError::NotFound {
        code: "SERVICE_NOT_AVAILABLE",
        message: "NAT not enabled".to_string(),
    })?;
    let mut svc = nat.write().await;
    svc.remove_nptv6_rule(&id).map_err(|e| ApiError::NotFound {
        code: "RULE_NOT_FOUND",
        message: e.to_string(),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    use domain::common::entity::RuleId;
    use std::collections::HashMap;

    fn rule(nat_type: NatType) -> NatRule {
        NatRule {
            id: RuleId("nat-1".to_string()),
            priority: 10,
            nat_type,
            match_src: None,
            match_dst: None,
            match_dst_port: None,
            match_protocol: None,
            match_src_alias: None,
            match_dst_alias: None,
            enabled: true,
            group_mask: 0,
            tenant_id: 0,
            xfrm_if_id: 0,
            xfrm_link: 0,
            fou_sport: 0,
            fou_dport: 0,
            fou_type: 0,
        }
    }

    fn response(rule: &NatRule) -> serde_json::Value {
        serde_json::to_value(rule_response(rule, "dnat", &HashMap::new())).unwrap()
    }

    /// The word on the wire is the one the configuration file is written
    /// with, so a rule on screen matches the line that declared it.
    #[test]
    fn the_type_word_is_the_one_the_file_uses() {
        let words = [
            (
                NatType::Snat {
                    addr: "203.0.113.9".parse().unwrap(),
                    port_range: None,
                },
                "snat",
            ),
            (
                NatType::Dnat {
                    addr: "10.0.1.10".parse().unwrap(),
                    port: Some(8443),
                },
                "dnat",
            ),
            (
                NatType::Masquerade {
                    interface: "eth0".to_string(),
                    port_range: None,
                },
                "masquerade",
            ),
            (
                NatType::OneToOne {
                    external: "203.0.113.40".parse().unwrap(),
                    internal: "10.0.9.40".parse().unwrap(),
                },
                "one_to_one",
            ),
            (NatType::Redirect { port: 8080 }, "redirect"),
            (
                NatType::PortForward {
                    ext_port: PortRange {
                        start: 443,
                        end: 443,
                    },
                    int_addr: "10.0.1.10".parse().unwrap(),
                    int_port: PortRange {
                        start: 8443,
                        end: 8443,
                    },
                },
                "port_forward",
            ),
        ];
        for (nat_type, word) in words {
            let json = response(&rule(nat_type));
            assert_eq!(json["nat_type"], word);
            assert_eq!(json["translation"]["type"], word);
        }
    }

    /// The addresses are fields rather than something a reader has to pick
    /// out of a rendering, and a port range collapses to the port where both
    /// ends are the same.
    #[test]
    fn the_addresses_and_ports_are_fields() {
        let json = response(&rule(NatType::PortForward {
            ext_port: PortRange {
                start: 443,
                end: 443,
            },
            int_addr: "10.0.1.10".parse().unwrap(),
            int_port: PortRange {
                start: 8443,
                end: 8443,
            },
        }));
        assert_eq!(json["translation"]["ext_port"], "443");
        assert_eq!(json["translation"]["int_addr"], "10.0.1.10");
        assert_eq!(json["translation"]["int_port"], "8443");

        let json = response(&rule(NatType::Snat {
            addr: "203.0.113.9".parse().unwrap(),
            port_range: Some(PortRange {
                start: 1024,
                end: 2048,
            }),
        }));
        assert_eq!(json["translation"]["addr"], "203.0.113.9");
        assert_eq!(json["translation"]["port_range"], "1024-2048");
    }

    /// A rule restricted to nothing translates everything its direction
    /// carries, so the criteria are absent rather than empty values a reader
    /// would take for a restriction.
    #[test]
    fn a_rule_naming_no_restriction_carries_no_criterion() {
        let json = response(&rule(NatType::Redirect { port: 8080 }));
        for field in [
            "match_src",
            "match_dst",
            "match_dst_port",
            "match_protocol",
            "match_src_alias",
            "match_dst_alias",
        ] {
            assert!(json.get(field).is_none(), "{field} should be absent");
        }
    }

    /// What the rule is narrowed to is answered in the words the file used,
    /// including the alias a rule still names before expansion has run.
    #[test]
    fn what_a_rule_is_narrowed_to_is_answered() {
        let mut narrowed = rule(NatType::Dnat {
            addr: "10.0.1.10".parse().unwrap(),
            port: Some(8443),
        });
        narrowed.match_src = Some("10.0.0.0/8".to_string());
        narrowed.match_dst_port = Some(PortRange {
            start: 443,
            end: 443,
        });
        narrowed.match_protocol = Some("tcp".to_string());
        narrowed.match_dst_alias = Some("dmz-hosts".to_string());

        let json = response(&narrowed);
        assert_eq!(json["match_src"], "10.0.0.0/8");
        assert_eq!(json["match_dst_port"], "443");
        assert_eq!(json["match_protocol"], "tcp");
        assert_eq!(json["match_dst_alias"], "dmz-hosts");
    }

    /// A floating rule is every interface the programs are on, so the field
    /// is absent rather than an empty list a reader would take for a scope
    /// nothing is in.
    #[test]
    fn interface_scope_is_absent_on_a_floating_rule_and_named_otherwise() {
        let floating = NptV6RuleResponse {
            id: "npt-1".to_string(),
            enabled: true,
            internal_prefix: "fd00:1::".to_string(),
            external_prefix: "2001:db8:1::".to_string(),
            prefix_len: 48,
            interfaces: Vec::new(),
        };
        let json = serde_json::to_value(&floating).unwrap();
        assert!(json.get("interfaces").is_none());

        let scoped = NptV6RuleResponse {
            interfaces: vec!["wan".to_string(), "!dmz".to_string()],
            ..floating
        };
        let json = serde_json::to_value(&scoped).unwrap();
        assert_eq!(json["interfaces"], serde_json::json!(["wan", "!dmz"]));
    }
}
