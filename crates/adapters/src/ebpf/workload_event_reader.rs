#![allow(unsafe_code)] // Required for eBPF RingBuf record parsing (read_unaligned)

use crate::ebpf::event_reader::{drain_tick, watch_ringbuf};
use crate::ebpf::map_store::MapStore;
use crate::ebpf::ringbuf_observer::{DrainTrigger, RingBufObserver};
use aya::maps::{MapData, RingBuf};
use domain::common::entity::Protocol;
use domain::firewall::workload::{
    DestinationAddr, WorkloadDenialRecord, WorkloadDestination, WorkloadHook,
};
use ebpf_common::workload_policy::{WORKLOAD_FAMILY_IPV6, WorkloadDenialEvent};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// The source name this reader's records are counted under, which is the
/// object they come out of.
pub const RINGBUF_SOURCE: &str = "cgroup-workload-firewall";

/// Reads refusals from the `WORKLOAD_EVENTS` ring buffer of the workload
/// firewall object.
///
/// The record carries a rule slot rather than a rule identifier, because the
/// hook has no string to send. Naming it is the policy service's job: this
/// reader turns bytes into a record and stops there, so a reload that
/// renumbered the slots is one decision taken in one place.
pub struct WorkloadEventReader {
    ring_buf: AsyncFd<RingBuf<MapData>>,
}

impl WorkloadEventReader {
    /// Take the `WORKLOAD_EVENTS` map from the loaded workload firewall
    /// object.
    pub fn new(ebpf: &mut dyn MapStore) -> Result<Self, anyhow::Error> {
        let map = ebpf.take_map("WORKLOAD_EVENTS").ok_or_else(|| {
            anyhow::anyhow!(
                "map 'WORKLOAD_EVENTS' not found in cgroup-workload-firewall eBPF object"
            )
        })?;
        let ring_buf = RingBuf::try_from(map)?;
        let async_fd = watch_ringbuf(ring_buf)?;
        info!("WORKLOAD_EVENTS RingBuf reader initialized");
        Ok(Self { ring_buf: async_fd })
    }

    /// Drain the ring buffer into `tx` until `cancel` fires or the buffer
    /// errors.
    pub async fn run(
        self,
        tx: mpsc::Sender<WorkloadDenialRecord>,
        cancel: CancellationToken,
        observer: RingBufObserver,
    ) {
        let mut async_fd = self.ring_buf;
        let mut tick = drain_tick();

        loop {
            tokio::select! {
                () = cancel.cancelled() => {
                    info!("workload denial reader cancelled");
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
                            error!("workload RingBuf readable error: {e}");
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
    tx: &mpsc::Sender<WorkloadDenialRecord>,
    observer: &RingBufObserver,
) -> usize {
    let now_ns = observer.now_ns();
    let mut drained = 0usize;
    while let Some(item) = rb.next() {
        drained += 1;
        let bytes: &[u8] = &item;
        if bytes.len() < size_of::<WorkloadDenialEvent>() {
            observer.dropped("truncated_record");
            continue;
        }
        // SAFETY: the length was checked against `size_of::<WorkloadDenialEvent>()` above, the
        // type is `#[repr(C)]` integers only so every bit pattern is a value, and
        // `read_unaligned` asks nothing of the ring's alignment.
        let raw = unsafe {
            bytes
                .as_ptr()
                .cast::<WorkloadDenialEvent>()
                .read_unaligned()
        };
        let Some(record) = parse(&raw) else {
            observer.dropped("unknown_kind");
            continue;
        };
        observer.drained(now_ns, raw.at_ns);
        if tx.try_send(record).is_err() {
            observer.dropped("channel_full");
            debug!("workload denial channel full, dropping a refusal");
        }
    }
    drained
}

/// Turn a kernel record into the domain record, or nothing when it names a
/// hook this build does not know.
#[must_use]
fn parse(raw: &WorkloadDenialEvent) -> Option<WorkloadDenialRecord> {
    let hook = WorkloadHook::from_kernel(raw.hook)?;
    Some(WorkloadDenialRecord {
        slot: raw.rule,
        hook,
        destination: WorkloadDestination {
            addr: address_of(raw),
            port: raw.dst_port,
            protocol: Protocol::from_u8(raw.protocol),
        },
        enforced: raw.enforced != 0,
        tgid: raw.tgid,
        uid: raw.uid,
        cgroup_id: raw.cgroup_id,
        at_ns: raw.at_ns,
    })
}

/// The destination in the width the hook decided it under.
///
/// The kernel unmaps `::ffff:a.b.c.d` before it matches a rule, so a record
/// carrying the v4 family is about an IPv4 address whatever the socket was
/// opened as, and reading it back as v6 here would print an address no rule
/// was written about.
#[must_use]
fn address_of(raw: &WorkloadDenialEvent) -> DestinationAddr {
    if raw.family != WORKLOAD_FAMILY_IPV6 {
        return DestinationAddr::V4(raw.dst_addr[0]);
    }
    let mut octets = [0u8; 16];
    for (group, word) in raw.dst_addr.iter().enumerate() {
        octets[group * 4..group * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    DestinationAddr::V6(octets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ebpf_common::workload_policy::{
        WORKLOAD_FAMILY_IPV4, WORKLOAD_HOOK_BIND, WORKLOAD_HOOK_CONNECT,
    };

    fn raw() -> WorkloadDenialEvent {
        WorkloadDenialEvent {
            at_ns: 1_000,
            cgroup_id: 77,
            dst_addr: [0x0a00_0001, 0, 0, 0],
            tgid: 4242,
            uid: 1000,
            dst_port: 443,
            rule: 3,
            family: WORKLOAD_FAMILY_IPV4,
            protocol: 6,
            hook: WORKLOAD_HOOK_CONNECT,
            enforced: 1,
        }
    }

    #[test]
    fn a_refusal_keeps_the_slot_the_task_and_the_destination() {
        let record = parse(&raw()).expect("a known hook");

        assert_eq!(record.slot, 3);
        assert_eq!(record.hook, WorkloadHook::Connect);
        assert_eq!(record.tgid, 4242);
        assert_eq!(record.uid, 1000);
        assert_eq!(record.cgroup_id, 77);
        assert!(record.enforced);
        assert_eq!(record.destination.port, 443);
        assert_eq!(record.destination.protocol, Protocol::Tcp);
        assert_eq!(record.destination.addr, DestinationAddr::V4(0x0a00_0001));
    }

    #[test]
    fn an_observing_rule_comes_back_as_a_refusal_that_did_not_happen() {
        let mut event = raw();
        event.enforced = 0;
        event.hook = WORKLOAD_HOOK_BIND;

        let record = parse(&event).expect("a known hook");

        assert!(!record.enforced);
        assert_eq!(record.hook, WorkloadHook::Bind);
    }

    #[test]
    fn a_v6_record_is_read_back_in_the_order_it_was_written() {
        let mut event = raw();
        event.family = WORKLOAD_FAMILY_IPV6;
        event.dst_addr = [0x2001_0db8, 0, 0, 0x35];

        let record = parse(&event).expect("a known hook");

        assert_eq!(
            record.destination.addr,
            DestinationAddr::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35
            ])
        );
    }

    #[test]
    fn a_hook_this_build_does_not_know_is_refused_rather_than_guessed() {
        let mut event = raw();
        event.hook = 9;

        assert!(parse(&event).is_none());
    }
}
