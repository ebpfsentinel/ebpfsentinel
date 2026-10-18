//! Reading the kernel's socket attribution tables from userspace.
//!
//! Two maps, two questions. `SOCKET_IDENTITY` answers a reader holding the
//! socket cookie that a packet event already carries, which is the kernel's
//! own handle and therefore the exact join. `SOCKET_FLOW` answers a reader
//! holding only a five-tuple, which is all a row of `/proc/net/nf_conntrack`
//! ever is.
//!
//! Every lookup can legitimately miss, and a miss is returned rather than
//! smoothed over: the hooks may not be attached, the socket may predate the
//! agent, the LRU may have evicted the entry, and an entry older than the
//! table's time-to-live is treated as gone even when the kernel still holds
//! it, because a cookie is reused and a stale record names the wrong process.

use aya::maps::{HashMap as AyaHashMap, MapData};
use domain::workload::entity::WorkloadSource;
use ebpf_common::attribution::{
    ATTRIBUTION_FAMILY_IPV4, ATTRIBUTION_FAMILY_IPV6, ATTRIBUTION_IDENTITY_TTL_NS, FlowIdentityKey,
    SocketIdentity,
};
use ports::secondary::socket_identity_port::{FlowEndpoints, SocketIdentityReader, SocketOwner};
use std::net::IpAddr;
use tracing::info;

use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::boottime_now_ns;

/// Reads `SOCKET_IDENTITY` and `SOCKET_FLOW`.
pub struct EbpfSocketIdentityReader {
    sockets: AyaHashMap<MapData, u64, SocketIdentity>,
    flows: AyaHashMap<MapData, FlowIdentityKey, SocketIdentity>,
}

impl EbpfSocketIdentityReader {
    /// Take both tables out of a loaded attribution object.
    ///
    /// Both or neither: a reader holding one of the two would answer one kind
    /// of caller and silently fail the other, which is exactly the asymmetry
    /// the flow index was added to remove.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let sockets = AyaHashMap::try_from(
            ebpf.take_map("SOCKET_IDENTITY")
                .ok_or_else(|| anyhow::anyhow!("map 'SOCKET_IDENTITY' not found"))?,
        )?;
        let flows = AyaHashMap::try_from(
            ebpf.take_map("SOCKET_FLOW")
                .ok_or_else(|| anyhow::anyhow!("map 'SOCKET_FLOW' not found"))?,
        )?;
        info!("socket attribution tables acquired (SOCKET_IDENTITY, SOCKET_FLOW)");
        Ok(Self { sockets, flows })
    }

    /// An entry is usable when the clock agrees it is recent.
    ///
    /// The kernel stamps `at_ns` with the boot clock, and so does this, so the
    /// two are comparable across a suspend. A stamp in the future is a clock
    /// that moved rather than a fresh socket, and it is refused for the same
    /// reason as an expired one: the alternative is naming a process on the
    /// strength of a number nobody can explain.
    fn fresh(identity: SocketIdentity, now_ns: u64) -> Option<SocketIdentity> {
        if identity.at_ns == 0 || now_ns < identity.at_ns {
            return None;
        }
        if now_ns - identity.at_ns >= ATTRIBUTION_IDENTITY_TTL_NS {
            return None;
        }
        Some(identity)
    }
}

/// The owner a lookup resolved to, with the source that lookup proves.
fn owner_of(identity: SocketIdentity, source: WorkloadSource) -> Option<SocketOwner> {
    if identity.tgid == 0 {
        return None;
    }
    Some(SocketOwner {
        pid: identity.tgid,
        tgid: identity.tgid,
        uid: identity.uid,
        cgroup_id: identity.cgroup_id,
        source,
    })
}

/// The `[u32; 4]` encoding both maps use: the host-order value of each
/// big-endian word, IPv4 in the first word and the rest zero.
fn addr_words(addr: IpAddr) -> [u32; 4] {
    match addr {
        IpAddr::V4(v4) => [u32::from(v4), 0, 0, 0],
        IpAddr::V6(v6) => {
            let b = v6.octets();
            let mut words = [0u32; 4];
            for (i, word) in words.iter_mut().enumerate() {
                *word = u32::from_be_bytes([b[i * 4], b[i * 4 + 1], b[i * 4 + 2], b[i * 4 + 3]]);
            }
            words
        }
    }
}

/// The family byte the kernel side writes, or `None` for a mixed pair, which
/// is not a connection and has no key.
fn family_of(local: IpAddr, remote: IpAddr) -> Option<u8> {
    match (local, remote) {
        (IpAddr::V4(_), IpAddr::V4(_)) => Some(ATTRIBUTION_FAMILY_IPV4),
        (IpAddr::V6(_), IpAddr::V6(_)) => Some(ATTRIBUTION_FAMILY_IPV6),
        _ => None,
    }
}

/// The key as the `sockops` hook would have written it for this orientation.
#[must_use]
pub fn flow_key(flow: &FlowEndpoints) -> Option<FlowIdentityKey> {
    Some(FlowIdentityKey {
        local_addr: addr_words(flow.local_addr),
        remote_addr: addr_words(flow.remote_addr),
        local_port: flow.local_port,
        remote_port: flow.remote_port,
        protocol: flow.protocol,
        family: family_of(flow.local_addr, flow.remote_addr)?,
        _pad: [0; 2],
    })
}

/// The same connection read from the other end.
///
/// A conntrack row names an originator and a responder, not a local and a
/// remote, so half the rows on a node have this node on the side the caller
/// passed as remote. Trying the mirrored key is cheaper than teaching every
/// caller which of its own addresses is local.
#[must_use]
pub fn mirrored(flow: &FlowEndpoints) -> FlowEndpoints {
    FlowEndpoints {
        local_addr: flow.remote_addr,
        remote_addr: flow.local_addr,
        local_port: flow.remote_port,
        remote_port: flow.local_port,
        protocol: flow.protocol,
    }
}

impl SocketIdentityReader for EbpfSocketIdentityReader {
    fn by_cookie(&self, cookie: u64) -> Option<SocketOwner> {
        if cookie == 0 {
            return None;
        }
        let identity = self.sockets.get(&cookie, 0).ok()?;
        let identity = Self::fresh(identity, boottime_now_ns())?;
        owner_of(identity, WorkloadSource::Socket)
    }

    fn by_flow(&self, flow: &FlowEndpoints) -> Option<SocketOwner> {
        let now = boottime_now_ns();
        for candidate in [flow_key(flow), flow_key(&mirrored(flow))]
            .into_iter()
            .flatten()
        {
            if let Ok(identity) = self.flows.get(&candidate, 0)
                && let Some(identity) = Self::fresh(identity, now)
                && let Some(owner) = owner_of(identity, WorkloadSource::Flow)
            {
                return Some(owner);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn flow() -> FlowEndpoints {
        FlowEndpoints {
            local_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
            remote_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            local_port: 45_112,
            remote_port: 443,
            protocol: 6,
        }
    }

    #[test]
    fn an_ipv4_address_is_the_host_order_value_of_its_big_endian_word() {
        assert_eq!(
            addr_words(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
            [0x0A00_0007, 0, 0, 0]
        );
    }

    #[test]
    fn an_ipv6_address_fills_all_four_words_in_order() {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(addr_words(addr), [0x2001_0db8, 0, 0, 1]);
    }

    #[test]
    fn a_mixed_pair_builds_no_key_at_all() {
        let mixed = FlowEndpoints {
            remote_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            ..flow()
        };
        assert!(flow_key(&mixed).is_none());
    }

    #[test]
    fn the_mirrored_key_swaps_both_ends_and_nothing_else() {
        let key = flow_key(&flow()).unwrap();
        let other = flow_key(&mirrored(&flow())).unwrap();
        assert_eq!(other.local_addr, key.remote_addr);
        assert_eq!(other.remote_addr, key.local_addr);
        assert_eq!(other.local_port, key.remote_port);
        assert_eq!(other.remote_port, key.local_port);
        assert_eq!(other.protocol, key.protocol);
        assert_eq!(other.family, key.family);
    }

    #[test]
    fn an_entry_older_than_the_table_lifetime_is_not_fresh() {
        let identity = SocketIdentity {
            at_ns: 1_000,
            tgid: 42,
            ..SocketIdentity::default()
        };
        let now = 1_000 + ATTRIBUTION_IDENTITY_TTL_NS;
        assert!(EbpfSocketIdentityReader::fresh(identity, now).is_none());
        assert!(EbpfSocketIdentityReader::fresh(identity, now - 1).is_some());
    }

    #[test]
    fn an_unstamped_or_future_entry_is_refused() {
        let unstamped = SocketIdentity {
            tgid: 42,
            ..SocketIdentity::default()
        };
        assert!(EbpfSocketIdentityReader::fresh(unstamped, 10_000).is_none());
        let future = SocketIdentity {
            at_ns: 20_000,
            tgid: 42,
            ..SocketIdentity::default()
        };
        assert!(EbpfSocketIdentityReader::fresh(future, 10_000).is_none());
    }

    #[test]
    fn an_identity_with_no_process_resolves_to_no_owner() {
        let empty = SocketIdentity {
            at_ns: 1,
            ..SocketIdentity::default()
        };
        assert!(owner_of(empty, WorkloadSource::Socket).is_none());
    }

    #[test]
    fn an_owner_carries_the_thread_group_because_that_is_what_a_table_keys_on() {
        let identity = SocketIdentity {
            at_ns: 1,
            pid: 4_243,
            tgid: 4_242,
            uid: 1_000,
            cgroup_id: 77,
            ..SocketIdentity::default()
        };
        let owner = owner_of(identity, WorkloadSource::Flow).unwrap();
        assert_eq!(owner.pid, 4_242);
        assert_eq!(owner.tgid, 4_242);
        assert_eq!(owner.uid, 1_000);
        assert_eq!(owner.cgroup_id, 77);
        assert_eq!(owner.source, WorkloadSource::Flow);
    }
}
