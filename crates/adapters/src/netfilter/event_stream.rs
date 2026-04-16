//! Conntrack event stream via `/proc/net/nf_conntrack` snapshot diffs.
//!
//! Every `poll_interval` the poller reads the proc file, diffs against
//! the previous snapshot, and emits [`ConntrackEvent`] messages into a
//! `broadcast::Sender`. Latency is bounded by the poll interval
//! (default 2 s) — acceptable for admin observability.

use std::collections::HashMap;
use std::time::Duration;

use domain::conntrack::entity::{Connection, ConntrackEvent, ConntrackEventType};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use super::conntrack::ProcNetfilterConntrackPort;
use ports::secondary::conntrack_map_port::ConnTrackMapPort;

/// 5-tuple key for diffing successive snapshots.
type FlowKey = (String, String, u16, u16, u8);

fn flow_key(c: &Connection) -> FlowKey {
    (
        c.src_ip.clone(),
        c.dst_ip.clone(),
        c.src_port,
        c.dst_port,
        c.protocol,
    )
}

/// Returns `true` when the connection changed meaningfully between
/// snapshots (state, packet/byte counters).
fn connection_changed(old: &Connection, new: &Connection) -> bool {
    old.state != new.state
        || old.packets_fwd != new.packets_fwd
        || old.packets_rev != new.packets_rev
        || old.bytes_fwd != new.bytes_fwd
        || old.bytes_rev != new.bytes_rev
}

/// Long-running poller task that diffs `/proc/net/nf_conntrack`
/// snapshots and emits lifecycle events into the broadcast channel.
///
/// Stops when `cancel` fires. Best-effort: dropped events on channel
/// lag are silently ignored (admin monitoring is not critical path).
pub async fn run_conntrack_event_poller(
    port: ProcNetfilterConntrackPort,
    tx: broadcast::Sender<ConntrackEvent>,
    poll_interval: Duration,
    cancel: CancellationToken,
) {
    let mut prev: HashMap<FlowKey, Connection> = HashMap::new();
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                debug!("conntrack event poller cancelled");
                break;
            }
            _ = ticker.tick() => {
                let current = match port.get_connections(usize::MAX) {
                    Ok(conns) => conns,
                    Err(e) => {
                        warn!("conntrack snapshot failed: {e}");
                        continue;
                    }
                };

                let mut curr_map: HashMap<FlowKey, Connection> = HashMap::with_capacity(current.len());
                for conn in current {
                    let key = flow_key(&conn);
                    // Emit New or Update
                    match prev.get(&key) {
                        None => {
                            let _ = tx.send(ConntrackEvent {
                                event_type: ConntrackEventType::New,
                                connection: conn.clone(),
                            });
                        }
                        Some(old) if connection_changed(old, &conn) => {
                            let _ = tx.send(ConntrackEvent {
                                event_type: ConntrackEventType::Update,
                                connection: conn.clone(),
                            });
                        }
                        _ => {}
                    }
                    curr_map.insert(key, conn);
                }

                // Emit Destroy for flows that disappeared
                for (key, conn) in &prev {
                    if !curr_map.contains_key(key) {
                        let _ = tx.send(ConntrackEvent {
                            event_type: ConntrackEventType::Destroy,
                            connection: conn.clone(),
                        });
                    }
                }

                let total = curr_map.len();
                trace!(flows = total, "conntrack snapshot diffed");
                prev = curr_map;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(src: &str, dst: &str, sport: u16, dport: u16, proto: u8) -> Connection {
        use domain::conntrack::entity::ConnectionState;
        Connection {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: sport,
            dst_port: dport,
            protocol: proto,
            state: ConnectionState::Established,
            packets_fwd: 10,
            packets_rev: 5,
            bytes_fwd: 1000,
            bytes_rev: 500,
            first_seen_ns: 0,
            last_seen_ns: 0,
        }
    }

    #[test]
    fn flow_key_deterministic() {
        let c = make_conn("1.2.3.4", "5.6.7.8", 100, 200, 6);
        let k1 = flow_key(&c);
        let k2 = flow_key(&c);
        assert_eq!(k1, k2);
    }

    #[test]
    fn connection_changed_detects_counter_change() {
        let c1 = make_conn("1.2.3.4", "5.6.7.8", 100, 200, 6);
        let mut c2 = c1.clone();
        assert!(!connection_changed(&c1, &c2));
        c2.packets_fwd = 20;
        assert!(connection_changed(&c1, &c2));
    }

    #[test]
    fn connection_changed_detects_state_change() {
        let c1 = make_conn("1.2.3.4", "5.6.7.8", 100, 200, 6);
        let mut c2 = c1.clone();
        c2.state = domain::conntrack::entity::ConnectionState::FinWait;
        assert!(connection_changed(&c1, &c2));
    }

    #[tokio::test]
    async fn poller_emits_new_events_from_proc_file() {
        let dir = tempfile::tempdir().unwrap();
        let ct_path = dir.path().join("nf_conntrack");
        let count_path = dir.path().join("nf_conntrack_count");

        // Write initial state
        std::fs::write(
            &ct_path,
            "ipv4     2 tcp      6 100 ESTABLISHED src=1.2.3.4 dst=5.6.7.8 sport=111 dport=222 src=5.6.7.8 dst=1.2.3.4 sport=222 dport=111 [ASSURED] mark=0 use=2\n",
        ).unwrap();
        std::fs::write(&count_path, "1\n").unwrap();

        let port = ProcNetfilterConntrackPort::with_paths(ct_path, count_path);
        let (tx, mut rx) = broadcast::channel(64);
        let cancel = CancellationToken::new();
        let cancel2 = cancel.clone();

        let handle = tokio::spawn(async move {
            run_conntrack_event_poller(port, tx, Duration::from_millis(50), cancel2).await;
        });

        // Wait for first poll
        tokio::time::sleep(Duration::from_millis(120)).await;

        // Should have a New event
        let event = rx.try_recv().unwrap();
        assert_eq!(event.event_type, ConntrackEventType::New);
        assert_eq!(event.connection.src_ip, "1.2.3.4");

        cancel.cancel();
        let _ = handle.await;
    }
}
