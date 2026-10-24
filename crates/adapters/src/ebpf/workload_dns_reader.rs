#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ebpf::event_reader::{drain_tick, watch_ringbuf};
use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::{DrainTrigger, RingBufObserver};
use aya::maps::{MapData, RingBuf};
use domain::firewall::fqdn::{DnsCapture, DnsDirection};
use ebpf_common::workload_policy::{
    WORKLOAD_DNS_MAX_PAYLOAD, WORKLOAD_DNS_QUERY, WORKLOAD_DNS_RESPONSE, WORKLOAD_FAMILY_IPV6,
    WorkloadDnsEvent,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// The source name this reader's records are counted under.
pub const RINGBUF_SOURCE: &str = "cgroup-workload-dns";

/// Reads the DNS packets of named workloads from the `WORKLOAD_DNS_EVENTS`
/// ring buffer of the workload firewall object.
///
/// The hook copies what it saw and decides nothing: pairing an answer with
/// its query, checking who sent it and reading the records are done by the
/// policy service, where a name can be compared. This reader turns bytes into
/// a capture and stops there.
pub struct WorkloadDnsReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl WorkloadDnsReader {
    /// Take the `WORKLOAD_DNS_EVENTS` map from the loaded workload firewall
    /// object.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf.take_map("WORKLOAD_DNS_EVENTS").ok_or_else(|| {
            anyhow::anyhow!(
                "map 'WORKLOAD_DNS_EVENTS' not found in cgroup-workload-firewall eBPF object"
            )
        })?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = watch_ringbuf(ring_buf)?;
        info!("WORKLOAD_DNS_EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Drain the ring buffer into `tx` until `cancel` fires or the buffer
    /// errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<DnsCapture>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let mut async_fd = self.ring_buf;
        let mut tick = drain_tick();

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("workload DNS reader cancelled");
                    break;
                }
                result = async_fd.readable_mut() => {
                    match result {
                        Ok(mut guard) => {
                            let drained = drain(guard.get_inner_mut(), &tx, &observer);
                            guard.clear_ready();
                            observer.drain_pass(DrainTrigger::Wakeup, drained);
                        }
                        Err(e) => {
                            error!("workload DNS RingBuf readable error: {e}");
                            break;
                        }
                    }
                }
                _ = tick.tick() => {
                    let drained = drain(async_fd.get_mut(), &tx, &observer);
                    observer.drain_pass(DrainTrigger::Tick, drained);
                }
            }
        }
    }
}

/// Drain every record currently in `rb`, returning how many were read.
fn drain(
    rb: &mut RingBuf<MapData>,
    tx: &mpsc::Sender<DnsCapture>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<WorkloadDnsEvent>() {
            observer.dropped("truncated_record");
            continue;
        }
        let raw = unsafe { bytes.as_ptr().cast::<WorkloadDnsEvent>().read_unaligned() };
        let Some(capture) = parse(&raw) else {
            observer.dropped("unknown_kind");
            continue;
        };
        observer.drained(now_ns, raw.at_ns);
        if tx.try_send(capture).is_err() {
            // An answer lost here teaches nothing, so the connection that
            // follows it is refused: the loss lands on the closed side.
            observer.dropped("channel_full");
            debug!("workload DNS channel full, dropping a packet");
        }
    }
    drained
}

/// Turn a kernel record into a capture, oriented from the workload's side.
#[must_use]
fn parse(raw: &WorkloadDnsEvent) -> Option<DnsCapture> {
    let (direction, client_port, resolver) = match raw.direction {
        WORKLOAD_DNS_QUERY => (DnsDirection::Query, raw.src_port, raw.dst_addr),
        WORKLOAD_DNS_RESPONSE => (DnsDirection::Response, raw.dst_port, raw.src_addr),
        _ => return None,
    };
    let length = usize::from(raw.payload_len).min(WORKLOAD_DNS_MAX_PAYLOAD);
    Some(DnsCapture {
        at_ns: raw.at_ns,
        cgroup_id: raw.cgroup_id,
        direction,
        client_port,
        resolver: address_of(raw.family, &resolver),
        payload: raw.payload[..length].to_vec(),
    })
}

/// An address the hook wrote as host-order words.
#[must_use]
fn address_of(family: u8, words: &[u32; 4]) -> IpAddr {
    if family != WORKLOAD_FAMILY_IPV6 {
        return IpAddr::V4(Ipv4Addr::from(words[0]));
    }
    let mut octets = [0u8; 16];
    for (group, word) in words.iter().enumerate() {
        octets[group * 4..group * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    IpAddr::V6(Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::workload_policy::WORKLOAD_FAMILY_IPV4;

    fn raw(direction: u8) -> WorkloadDnsEvent {
        let mut event = WorkloadDnsEvent {
            at_ns: 1_000,
            cgroup_id: 77,
            src_addr: [0x0a00_0005, 0, 0, 0],
            dst_addr: [0x0a60_000a, 0, 0, 0],
            src_port: 40_000,
            dst_port: 53,
            payload_len: 3,
            family: WORKLOAD_FAMILY_IPV4,
            direction,
            ..WorkloadDnsEvent::default()
        };
        event.payload[..3].copy_from_slice(&[1, 2, 3]);
        event
    }

    #[test]
    fn a_query_is_read_from_the_workload_towards_the_resolver() {
        let capture = parse(&raw(WORKLOAD_DNS_QUERY)).expect("a known direction");
        assert_eq!(capture.direction, DnsDirection::Query);
        assert_eq!(capture.client_port, 40_000);
        assert_eq!(capture.resolver, IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)));
        assert_eq!(capture.cgroup_id, 77);
        assert_eq!(capture.payload, vec![1, 2, 3]);
    }

    #[test]
    fn an_answer_is_read_from_the_resolver_towards_the_workload() {
        let mut event = raw(WORKLOAD_DNS_RESPONSE);
        std::mem::swap(&mut event.src_addr, &mut event.dst_addr);
        event.src_port = 53;
        event.dst_port = 40_000;
        let capture = parse(&event).expect("a known direction");
        assert_eq!(capture.direction, DnsDirection::Response);
        assert_eq!(capture.client_port, 40_000);
        assert_eq!(capture.resolver, IpAddr::V4(Ipv4Addr::new(10, 96, 0, 10)));
    }

    #[test]
    fn an_unknown_direction_and_an_overlong_length_are_contained() {
        assert!(parse(&raw(9)).is_none());
        let mut event = raw(WORKLOAD_DNS_QUERY);
        event.payload_len = u16::MAX;
        let capture = parse(&event).expect("a known direction");
        assert_eq!(capture.payload.len(), WORKLOAD_DNS_MAX_PAYLOAD);
    }

    #[test]
    fn an_ipv6_resolver_is_read_back_from_four_words() {
        let mut event = raw(WORKLOAD_DNS_QUERY);
        event.family = WORKLOAD_FAMILY_IPV6;
        event.dst_addr = [0xfd00_0000, 0, 0, 0x0000_000a];
        let capture = parse(&event).expect("a known direction");
        assert_eq!(
            capture.resolver,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x000a))
        );
    }
}
