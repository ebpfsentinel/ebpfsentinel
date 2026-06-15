//! Host-network ops over the real `warden serve` binary. The happy paths need
//! `CAP_NET_ADMIN`/`CAP_NET_RAW` and live in the VM lane; here we assert the
//! deterministic error paths (a non-existent interface fails cleanly) and that the
//! connection stays in sync across a run of control commands.

use std::process::{Child, Command as Proc, Stdio};

use ebpfsentinel_warden_client::WardenClient;
use ebpfsentinel_warden_proto::RouteSpec;

fn spawn_warden(sock: &str, uid: u32) -> Child {
    Proc::new(env!("CARGO_BIN_EXE_warden"))
        .args(["serve", sock, "--uid", &uid.to_string()])
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn warden")
}

fn connect(sock: &str) -> WardenClient {
    for _ in 0..200 {
        if let Ok(c) = WardenClient::connect(sock) {
            return c;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("warden socket {sock} never came up");
}

fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it only reads the caller's real uid.
    unsafe { libc::getuid() }
}

struct Guard {
    child: Child,
    sock: String,
}
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

const NO_SUCH_IFACE: &str = "wrdn-no-such0";

#[test]
fn host_network_ops_error_cleanly_and_keep_the_stream_in_sync() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir
        .path()
        .join("warden.sock")
        .to_string_lossy()
        .into_owned();

    let guard = Guard {
        child: spawn_warden(&sock, current_uid()),
        sock: sock.clone(),
    };
    let mut client = connect(&sock);

    // Gratuitous ARP on a non-existent interface: ifindex resolution fails.
    assert!(
        client.arp_announce(NO_SUCH_IFACE, "192.0.2.10").is_err(),
        "ARP on a missing interface must error"
    );

    // Opening a capture socket on a non-existent interface fails, with no fd sent.
    assert!(
        client.pcap_open(NO_SUCH_IFACE, "tcp port 443").is_err(),
        "pcap open on a missing interface must error"
    );

    // Route deletion against a bogus spec returns a typed result (either `ip`
    // fails or is absent) — never a desync. We only require it to round-trip.
    let route = RouteSpec {
        dst_cidr: "203.0.113.0/24".to_owned(),
        gateway: "192.0.2.254".to_owned(),
        iface: NO_SUCH_IFACE.to_owned(),
        table: 200,
    };
    let _ = client.route_del(route);

    // Conntrack flush likewise round-trips (Ok when privileged + tooled, Err
    // otherwise); we only require the stream to survive it.
    let _ = client.conntrack_flush();

    // After all of the above, the stream is still aligned: a fresh command parses.
    assert!(
        client.arp_announce(NO_SUCH_IFACE, "192.0.2.11").is_err(),
        "stream desynced after a run of control commands"
    );

    drop(guard);
}
