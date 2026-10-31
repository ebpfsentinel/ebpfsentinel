use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use domain::guest::{GuestLink, GuestNaming};
use serde::Serialize;
use utoipa::ToSchema;

use super::error::{ApiError, ErrorBody};
use super::state::AppState;

// ── Response DTOs ─────────────────────────────────────────────────

/// A guest as its hypervisor names it.
#[derive(Serialize, ToSchema)]
pub struct GuestIdentityEntry {
    /// The libvirt domain name, or the Proxmox VM name.
    pub name: String,
    /// The libvirt UUID, or the Proxmox VMID.
    pub id: String,
    /// `libvirt` or `proxmox`.
    pub source: String,
    /// The hypervisor's tags for the guest; libvirt keeps none.
    pub tags: Vec<String>,
}

/// One guest device on this host.
#[derive(Serialize, ToSchema)]
pub struct GuestEntry {
    /// The device in the host namespace.
    pub interface: String,
    pub ifindex: u32,
    /// `tap` or `macvtap`.
    pub kind: String,
    /// Every program of the chain is on the device.
    pub attached: bool,
    /// The guest behind the device. Absent when no record names it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestIdentityEntry>,
    /// Why no guest is named, as a stable code: `no_source`, `no_record`,
    /// `record_without_name` or `record_unreadable`. Absent when named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unnamed: Option<String>,
    /// The same reason in a sentence. Absent when named.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct GuestsResponse {
    /// Devices whose guest is named.
    pub named: usize,
    /// Devices whose guest is not.
    pub unnamed: usize,
    /// One entry per guest device, by interface name.
    pub guests: Vec<GuestEntry>,
}

fn guest_entry(link: GuestLink) -> GuestEntry {
    let (guest, unnamed, reason) = match link.naming {
        GuestNaming::Named(g) => (
            Some(GuestIdentityEntry {
                name: g.name,
                id: g.id,
                source: g.source.as_str().to_owned(),
                tags: g.tags,
            }),
            None,
            None,
        ),
        GuestNaming::Unnamed(why) => (None, Some(why.code().to_owned()), Some(why.describe())),
    };
    GuestEntry {
        interface: link.interface,
        ifindex: link.ifindex,
        kind: link.kind,
        attached: link.attached,
        guest,
        unnamed,
        reason,
    }
}

fn guests_body(links: Vec<GuestLink>) -> GuestsResponse {
    let guests: Vec<GuestEntry> = links.into_iter().map(guest_entry).collect();
    let named = guests.iter().filter(|g| g.guest.is_some()).count();
    GuestsResponse {
        named,
        unnamed: guests.len() - named,
        guests,
    }
}

// ── Handlers ──────────────────────────────────────────────────────

/// `GET /api/v1/ebpf/guests` - the virtual machines whose tap or macvtap
/// devices the agent found on this host, each named from the hypervisor's
/// records or reported unnamed with the reason.
#[utoipa::path(
    get, path = "/api/v1/ebpf/guests",
    tag = "Operations",
    responses(
        (status = 200, description = "One entry per guest device on this host, by interface name", body = GuestsResponse),
        (status = 401, description = "Authentication required", body = ErrorBody),
        (status = 403, description = "Insufficient permissions", body = ErrorBody),
        (status = 404, description = "The link watcher does not run on this agent, so no guest device is watched", body = ErrorBody),
    ),
    security(
        ("bearer_auth" = []),
        ("api_key" = []),
    )
)]
pub async fn get_guests(
    State(state): State<Arc<AppState>>,
) -> Result<Json<GuestsResponse>, ApiError> {
    let inventory = state
        .guest_inventory
        .load_full()
        .ok_or(ApiError::NotFound {
            code: "SERVICE_NOT_AVAILABLE",
            message: "the link watcher does not run on this agent: no TC program is loaded, \
                      or the pod profile attaches inside the pods instead"
                .to_string(),
        })?;
    Ok(Json(guests_body(inventory.guests())))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use domain::guest::{GuestIdentity, GuestSource, UnnamedReason};

    #[test]
    fn a_named_guest_carries_its_identity_and_an_unnamed_one_its_reason() {
        let body = guests_body(vec![
            GuestLink {
                ifindex: 7,
                interface: "tap101i0".into(),
                kind: "tap".into(),
                attached: true,
                naming: GuestNaming::Named(GuestIdentity {
                    name: "web-01".into(),
                    id: "101".into(),
                    source: GuestSource::Proxmox,
                    tags: vec!["prod".into()],
                }),
            },
            GuestLink {
                ifindex: 9,
                interface: "vnet3".into(),
                kind: "tap".into(),
                attached: true,
                naming: GuestNaming::Unnamed(UnnamedReason::NoRecord),
            },
        ]);
        assert_eq!((body.named, body.unnamed), (1, 1));
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["guests"][0]["guest"]["source"], "proxmox");
        assert_eq!(json["guests"][0]["guest"]["tags"][0], "prod");
        assert!(json["guests"][0].get("unnamed").is_none());
        assert!(json["guests"][1].get("guest").is_none());
        assert_eq!(json["guests"][1]["unnamed"], "no_record");
        assert!(
            json["guests"][1]["reason"]
                .as_str()
                .unwrap()
                .contains("no libvirt domain")
        );
    }
}
