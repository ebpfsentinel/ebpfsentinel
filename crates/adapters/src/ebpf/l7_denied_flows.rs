//! The `L7_DENIED_FLOWS` table of a loaded tc-ids object: connections an L7
//! rule refused, shot by the classifier in both directions.

use aya::maps::{HashMap as AyaHashMap, MapData};
use domain::common::error::DomainError;
use ebpf_common::ids::{L7_DENIED_FLOW_TTL_NS, L7FlowKey, L7FlowVerdict};
use ports::secondary::l7_flow_refusal_port::{L7FlowRefusalMapPort, RefusedL7Flow};
use tracing::info;

use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::boottime_now_ns;

/// Owns `L7_DENIED_FLOWS`, taken out of the loaded object so it outlives the
/// loader's borrow, the way the other tc-ids tables are.
pub struct L7DeniedFlowsMap {
    map: AyaHashMap<MapData, L7FlowKey, L7FlowVerdict>,
}

impl L7DeniedFlowsMap {
    /// Take the table out of a loaded tc-ids object.
    ///
    /// # Errors
    ///
    /// Returns an error when the object carries no such table, or one of
    /// another shape.
    pub fn new(ebpf: &mut dyn MapStore) -> anyhow::Result<Self> {
        let map = AyaHashMap::try_from(
            ebpf.take_map("L7_DENIED_FLOWS")
                .ok_or_else(|| anyhow::anyhow!("map 'L7_DENIED_FLOWS' not found"))?,
        )?;
        info!("L7_DENIED_FLOWS map acquired");
        Ok(Self { map })
    }
}

/// The key of the direction the refused request travelled.
#[must_use]
pub fn forward_key(flow: &RefusedL7Flow) -> L7FlowKey {
    L7FlowKey {
        src_addr: flow.src_addr,
        dst_addr: flow.dst_addr,
        src_port: flow.src_port,
        dst_port: flow.dst_port,
        ipv6: u8::from(flow.ipv6),
        _padding: [0; 3],
    }
}

/// The verdict written for a refusal made at `now_boot_ns`.
#[must_use]
pub fn verdict_at(flow: &RefusedL7Flow, now_boot_ns: u64) -> L7FlowVerdict {
    L7FlowVerdict {
        expires_boot_ns: now_boot_ns.saturating_add(L7_DENIED_FLOW_TTL_NS),
        rule_hash: flow.rule_hash,
        _padding: 0,
    }
}

impl L7FlowRefusalMapPort for L7DeniedFlowsMap {
    fn refuse(&mut self, flow: &RefusedL7Flow) -> Result<(), DomainError> {
        let key = forward_key(flow);
        let verdict = verdict_at(flow, boottime_now_ns());
        for key in [key, key.reversed()] {
            self.map.insert(&key, &verdict, 0).map_err(|e| {
                DomainError::EngineError(format!("L7_DENIED_FLOWS insert failed: {e}"))
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow() -> RefusedL7Flow {
        RefusedL7Flow {
            src_addr: [0x0a00_0001, 0, 0, 0],
            dst_addr: [0x0a00_0002, 0, 0, 0],
            src_port: 40_000,
            dst_port: 8888,
            ipv6: false,
            rule_hash: 9,
        }
    }

    #[test]
    fn the_key_is_the_request_direction_as_the_packet_carries_it() {
        let key = forward_key(&flow());
        assert_eq!(key.src_addr, [0x0a00_0001, 0, 0, 0]);
        assert_eq!(key.dst_port, 8888);
        assert_eq!(key.ipv6, 0);
        let reply = key.reversed();
        assert_eq!(reply.src_port, 8888);
        assert_eq!(reply.dst_addr, [0x0a00_0001, 0, 0, 0]);
    }

    #[test]
    fn an_ipv6_flow_is_keyed_apart_from_ipv4() {
        let mut v6 = flow();
        v6.ipv6 = true;
        assert_ne!(forward_key(&v6), forward_key(&flow()));
    }

    #[test]
    fn the_verdict_expires_one_ttl_after_the_refusal() {
        let verdict = verdict_at(&flow(), 1_000);
        assert_eq!(verdict.expires_boot_ns, 1_000 + L7_DENIED_FLOW_TTL_NS);
        assert_eq!(verdict.rule_hash, 9);
        assert_eq!(verdict_at(&flow(), u64::MAX).expires_boot_ns, u64::MAX);
    }
}
