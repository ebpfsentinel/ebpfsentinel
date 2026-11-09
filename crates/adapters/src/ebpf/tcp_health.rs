//! TCP health per edge, counted by four tracepoints the TCP stack already
//! fires: a segment sent again, a reset sent or received, and a socket
//! changing state.
//!
//! Every structure read the program makes is placed from the running
//! kernel's BTF before anything attaches, so a kernel that moves a field of
//! `sock_common` is read where it put it, and a kernel missing one is refused
//! here in one sentence.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{OwnedFd, RawFd};
use std::sync::{Mutex, OnceLock, PoisonError};

use aya::maps::{Array, HashMap, MapData, PerCpuArray, PerCpuHashMap, PerCpuValues};
use domain::common::error::DomainError;
use domain::tcp_health::{
    EdgeRole, RTT_BUCKETS, RTT_FIRST_BOUND_US, RawTcpEdge, TcpCounts, TcpEdgeId, TcpRtt,
};
use ebpf_common::tcp_health::{
    TCP_HEALTH_AF_INET6, TCP_HEALTH_METRIC_KEYS_FULL, TCP_HEALTH_METRIC_UNCONFIGURED,
    TCP_HEALTH_METRIC_UNREADABLE, TCP_RTT_BUCKETS, TCP_RTT_FIRST_BOUND_US, TcpEdgeCounts,
    TcpEdgeKey, TcpEdgeRtt, TcpHealthConfig,
};
use ports::secondary::tcp_health_port::TcpHealthPort;
use tracing::{info, warn};

use super::kfunc::vmlinux_struct_member_offsets;
use super::kfunc_attach;
use super::loader::EbpfLoader;
use super::map_store::MapStore;

// The domain reads the kernel's buckets one for one.
const _: () =
    assert!(RTT_BUCKETS == TCP_RTT_BUCKETS && RTT_FIRST_BOUND_US == TCP_RTT_FIRST_BOUND_US);

/// Each program of the object and the tracepoint it attaches to.
pub const TCP_HEALTH_HOOKS: [(&str, &str); 4] = [
    ("tcp_health_retransmit", "tcp_retransmit_skb"),
    ("tcp_health_send_reset", "tcp_send_reset"),
    ("tcp_health_receive_reset", "tcp_receive_reset"),
    ("tcp_health_set_state", "inet_sock_set_state"),
];

/// What the agent can say about the TCP health counter.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpHealthStatus {
    /// Every tracepoint is attached and edges are counted.
    pub attached: bool,
    /// Why it is off, in one sentence. `None` when it is on.
    pub reason: Option<String>,
}

static STATUS: OnceLock<Mutex<TcpHealthStatus>> = OnceLock::new();

fn status_cell() -> &'static Mutex<TcpHealthStatus> {
    STATUS.get_or_init(|| Mutex::new(TcpHealthStatus::default()))
}

/// Publish what the agent can say about the TCP health counter.
pub fn publish_status(status: TcpHealthStatus) {
    *status_cell().lock().unwrap_or_else(PoisonError::into_inner) = status;
}

/// What the agent can currently say about the TCP health counter.
#[must_use]
pub fn status() -> TcpHealthStatus {
    status_cell()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

fn offsets(struct_name: &str, members: &[&str]) -> Result<Vec<u32>, String> {
    let found = vmlinux_struct_member_offsets(struct_name, members)
        .map_err(|e| format!("`struct {struct_name}` could not be read: {e}"))?;
    members
        .iter()
        .zip(found)
        .map(|(name, offset)| {
            offset.ok_or_else(|| format!("`struct {struct_name}` has no `{name}`"))
        })
        .collect()
}

/// Read the layout the program needs off the running kernel's BTF.
///
/// # Errors
///
/// Returns why the counter cannot run on this kernel, in one sentence.
pub fn resolve_from_btf() -> Result<TcpHealthConfig, String> {
    let sock = offsets("sock", &["__sk_common", "sk_protocol", "sk_cgrp_data"])?;
    let common = offsets(
        "sock_common",
        &[
            "skc_family",
            "skc_num",
            "skc_dport",
            "skc_rcv_saddr",
            "skc_daddr",
            "skc_v6_rcv_saddr",
            "skc_v6_daddr",
            "skc_state",
        ],
    )?;
    let cgrp_data = offsets("sock_cgroup_data", &["cgroup"])?;
    let cgroup = offsets("cgroup", &["kn"])?;
    let kn = offsets("kernfs_node", &["id"])?;
    let skb = offsets("sk_buff", &["head", "network_header", "transport_header"])?;
    let inet = offsets("inet_sock", &["inet_sport"])?;
    let tcp = offsets("tcp_sock", &["srtt_us"])?;
    Ok(TcpHealthConfig {
        ready: 1,
        sk_common: sock[0],
        sk_protocol: sock[1],
        sk_cgrp_data: sock[2],
        skc_family: common[0],
        skc_num: common[1],
        skc_dport: common[2],
        skc_rcv_saddr: common[3],
        skc_daddr: common[4],
        skc_v6_rcv_saddr: common[5],
        skc_v6_daddr: common[6],
        skc_state: common[7],
        cgrp_data_cgroup: cgrp_data[0],
        cgroup_kn: cgroup[0],
        kn_id: kn[0],
        skb_head: skb[0],
        skb_network_header: skb[1],
        skb_transport_header: skb[2],
        inet_sport: inet[0],
        tcp_srtt_us: tcp[0],
    })
}

/// The address a key carries, in the datapath's word order.
fn key_address(family: u8, words: &[u32; 4]) -> IpAddr {
    if family == TCP_HEALTH_AF_INET6 {
        let mut bytes = [0_u8; 16];
        for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
            *chunk = word.to_be_bytes();
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        IpAddr::V4(Ipv4Addr::from(words[0]))
    }
}

/// One kernel key, its counts summed over the CPUs and its round-trip time
/// samples, in domain words.
#[must_use]
pub fn raw_edge(
    key: &TcpEdgeKey,
    per_cpu: &[TcpEdgeCounts],
    rtt: Option<&TcpEdgeRtt>,
) -> RawTcpEdge {
    let mut counts = TcpCounts::default();
    for c in per_cpu {
        counts.add(&TcpCounts {
            retransmits: c.retransmits,
            resets_sent: c.resets_sent,
            resets_received: c.resets_received,
            opened: c.opened,
            closed: c.closed,
            failed: c.failed,
            rtt: TcpRtt::default(),
        });
    }
    if let Some(rtt) = rtt {
        counts.rtt = TcpRtt {
            buckets: rtt.buckets,
            sum_us: rtt.sum_us,
            count: rtt.count,
        };
    }
    RawTcpEdge {
        id: TcpEdgeId {
            local: key_address(key.family, &key.local),
            remote: key_address(key.family, &key.remote),
            port: key.port,
            role: if key.port_is_local == 1 {
                EdgeRole::Server
            } else {
                EdgeRole::Client
            },
            cgroup: key.cgroup,
        },
        counts,
    }
}

/// The maps of the TCP health object the agent reads.
pub struct TcpHealthCounter {
    edges: PerCpuHashMap<MapData, TcpEdgeKey, TcpEdgeCounts>,
    rtt: HashMap<MapData, TcpEdgeKey, TcpEdgeRtt>,
    metrics: PerCpuArray<MapData, u64>,
}

impl TcpHealthCounter {
    /// Take the maps out of a loaded object and write the layout the program
    /// reads, before anything attaches.
    ///
    /// # Errors
    ///
    /// Returns an error when a map is missing or the configuration write is
    /// refused.
    pub fn new(ebpf: &mut dyn MapStore, config: TcpHealthConfig) -> Result<Self, anyhow::Error> {
        let mut config_map: Array<MapData, TcpHealthConfig> = Array::try_from(
            ebpf.take_map("TCP_HEALTH_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'TCP_HEALTH_CONFIG' not found"))?,
        )?;
        config_map.set(0, &config, 0)?;
        let edges = PerCpuHashMap::try_from(
            ebpf.take_map("TCP_EDGES")
                .ok_or_else(|| anyhow::anyhow!("map 'TCP_EDGES' not found"))?,
        )?;
        let rtt = HashMap::try_from(
            ebpf.take_map("TCP_RTT")
                .ok_or_else(|| anyhow::anyhow!("map 'TCP_RTT' not found"))?,
        )?;
        let metrics = PerCpuArray::try_from(
            ebpf.take_map("TCP_HEALTH_METRICS")
                .ok_or_else(|| anyhow::anyhow!("map 'TCP_HEALTH_METRICS' not found"))?,
        )?;
        Ok(Self {
            edges,
            rtt,
            metrics,
        })
    }

    fn metric(&self, slot: u32) -> u64 {
        self.metrics
            .get(&slot, 0)
            .map_or(0, |values: PerCpuValues<u64>| values.iter().sum())
    }
}

impl TcpHealthPort for TcpHealthCounter {
    fn read(&self) -> Result<(Vec<RawTcpEdge>, u64), DomainError> {
        let mut rtts = BTreeMap::new();
        for entry in &self.rtt {
            let (key, rtt) =
                entry.map_err(|e| DomainError::EngineError(format!("TCP_RTT read failed: {e}")))?;
            rtts.insert(key, rtt);
        }
        let mut raw = Vec::new();
        for entry in &self.edges {
            let (key, values) = entry
                .map_err(|e| DomainError::EngineError(format!("TCP_EDGES read failed: {e}")))?;
            let per_cpu: Vec<TcpEdgeCounts> = values.iter().copied().collect();
            raw.push(raw_edge(&key, &per_cpu, rtts.remove(&key).as_ref()));
        }
        // An edge sampled for its round-trip time after the counter map was
        // full still carries its samples.
        for (key, rtt) in &rtts {
            raw.push(raw_edge(key, &[], Some(rtt)));
        }
        let uncounted = self
            .metric(TCP_HEALTH_METRIC_KEYS_FULL)
            .saturating_add(self.metric(TCP_HEALTH_METRIC_UNCONFIGURED))
            .saturating_add(self.metric(TCP_HEALTH_METRIC_UNREADABLE));
        Ok((raw, uncounted))
    }
}

/// Holds the four tracepoint links alive.
#[derive(Default)]
pub struct TcpHealthAttacher {
    links: Vec<OwnedFd>,
}

impl TcpHealthAttacher {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach every tracepoint of `loader`, publishing what happened. Either
    /// all four hold or none does: an edge counted for its resets and not
    /// its state changes would read as connections that never opened.
    pub fn attach(&mut self, loader: &EbpfLoader) -> TcpHealthStatus {
        let mut links = Vec::with_capacity(TCP_HEALTH_HOOKS.len());
        let mut refused = None;
        for (program, tracepoint) in TCP_HEALTH_HOOKS {
            match Self::attach_one(loader, program, tracepoint) {
                Ok(link) => links.push(link),
                Err(reason) => {
                    refused = Some(format!("`{tracepoint}`: {reason}"));
                    break;
                }
            }
        }
        let status = if let Some(reason) = refused {
            // Dropping the links taken so far detaches them.
            drop(links);
            warn!(
                reason,
                "TCP health not counted: a tracepoint attach was refused"
            );
            TcpHealthStatus {
                attached: false,
                reason: Some(reason),
            }
        } else {
            self.links = links;
            info!("TCP health counted per edge");
            TcpHealthStatus {
                attached: true,
                reason: None,
            }
        };
        publish_status(status.clone());
        status
    }

    fn attach_one(loader: &EbpfLoader, program: &str, tracepoint: &str) -> Result<OwnedFd, String> {
        let prog_fd: RawFd = loader
            .program_fd(program)
            .ok_or_else(|| format!("program `{program}` is not in the loaded object"))?;
        kfunc_attach::attach_raw_tracepoint(program, prog_fd, tracepoint).map_err(|e| e.to_string())
    }

    /// Whether this attacher holds every link.
    #[must_use]
    pub fn attached(&self) -> bool {
        self.links.len() == TCP_HEALTH_HOOKS.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::tcp_health::TCP_HEALTH_AF_INET;

    #[test]
    fn a_key_reads_back_as_its_addresses_role_and_summed_counts() {
        let key = TcpEdgeKey {
            local: [u32::from(Ipv4Addr::new(10, 0, 0, 1)), 0, 0, 0],
            remote: [u32::from(Ipv4Addr::new(10, 0, 0, 2)), 0, 0, 0],
            cgroup: 42,
            port: 443,
            family: TCP_HEALTH_AF_INET,
            port_is_local: 1,
            _pad: [0; 4],
        };
        let per_cpu = [
            TcpEdgeCounts {
                opened: 2,
                retransmits: 1,
                ..TcpEdgeCounts::default()
            },
            TcpEdgeCounts {
                opened: 1,
                resets_sent: 4,
                ..TcpEdgeCounts::default()
            },
        ];
        let mut buckets = [0; TCP_RTT_BUCKETS];
        buckets[2] = 3;
        let rtt = TcpEdgeRtt {
            buckets,
            sum_us: 600,
            count: 3,
        };
        let edge = raw_edge(&key, &per_cpu, Some(&rtt));
        assert_eq!(edge.counts.rtt.buckets[2], 3);
        assert_eq!(edge.counts.rtt.sum_us, 600);
        assert_eq!(edge.counts.rtt.count, 3);
        assert_eq!(edge.id.local, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(edge.id.remote, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(edge.id.role, EdgeRole::Server);
        assert_eq!(edge.id.port, 443);
        assert_eq!(edge.id.cgroup, 42);
        assert_eq!(edge.counts.opened, 3);
        assert_eq!(edge.counts.retransmits, 1);
        assert_eq!(edge.counts.resets_sent, 4);
    }

    #[test]
    fn an_ipv6_key_keeps_its_word_order_and_a_client_end_is_named_so() {
        let addr: Ipv6Addr = "2001:db8::1".parse().expect("valid");
        let bytes = addr.octets();
        let mut words = [0_u32; 4];
        for (word, chunk) in words.iter_mut().zip(bytes.as_chunks::<4>().0) {
            *word = u32::from_be_bytes(*chunk);
        }
        let key = TcpEdgeKey {
            local: words,
            remote: words,
            port: 5432,
            family: TCP_HEALTH_AF_INET6,
            port_is_local: 0,
            ..TcpEdgeKey::default()
        };
        let edge = raw_edge(&key, &[], None);
        assert_eq!(edge.id.local, IpAddr::V6(addr));
        assert_eq!(edge.id.role, EdgeRole::Client);
        assert!(edge.counts.is_zero());
    }

    #[test]
    fn the_hooks_are_the_tcp_stacks_own_tracepoints() {
        let tracepoints: Vec<&str> = TCP_HEALTH_HOOKS.iter().map(|(_, tp)| *tp).collect();
        assert_eq!(
            tracepoints,
            [
                "tcp_retransmit_skb",
                "tcp_send_reset",
                "tcp_receive_reset",
                "inet_sock_set_state"
            ]
        );
    }
}
