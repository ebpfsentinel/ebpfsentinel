//! End-to-end test of the map-control RPC through the pure `WardenClient`:
//! spawn the real `warden serve` binary against an empty pin directory, complete
//! the handshake, and assert that map ops over the socket reach the registry and
//! that unknown maps are refused with a typed error before any syscall.
//!
//! A real-kernel round-trip (create + pin a map, drive it through the warden)
//! requires `CAP_SYS_ADMIN` to create the map and is covered in the VM bats lane;
//! this test proves the client/server/framing path with no privilege.

use std::process::{Child, Command as Proc, Stdio};

use ebpfsentinel_warden_client::WardenClient;

/// Spawn `warden serve <sock> --uid <uid> --maps-dir <dir>` and return the child.
fn spawn_warden(sock: &str, uid: u32, maps_dir: &str) -> Child {
    Proc::new(env!("CARGO_BIN_EXE_warden"))
        .args([
            "serve",
            sock,
            "--uid",
            &uid.to_string(),
            "--maps-dir",
            maps_dir,
        ])
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn warden")
}

/// Connect a `WardenClient`, retrying until the socket is bound (or timing out).
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

/// Kills the child and removes the socket on drop so a panic never leaks state.
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

#[test]
fn map_ops_round_trip_through_client() {
    // An empty pin dir → empty registry → every map name is "unknown".
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir
        .path()
        .join("warden.sock")
        .to_string_lossy()
        .into_owned();
    let maps_dir = dir.path().to_string_lossy().into_owned();

    let guard = Guard {
        child: spawn_warden(&sock, current_uid(), &maps_dir),
        sock: sock.clone(),
    };
    let mut client = connect(&sock);

    // Unknown map is refused (the allowlist is the pinned-map set, which is empty).
    let err = client
        .map_update("FIREWALL_RULES", vec![0, 0, 0, 0], vec![1], 0)
        .expect_err("update of unknown map must fail");
    assert!(err.to_string().contains("unknown map"), "{err}");

    let err = client
        .map_lookup("IPS_BLACKLIST", vec![0, 0, 0, 0])
        .expect_err("lookup of unknown map must fail");
    assert!(err.to_string().contains("unknown map"), "{err}");

    let err = client
        .map_delete("IPS_BLACKLIST", vec![0, 0, 0, 0])
        .expect_err("delete of unknown map must fail");
    assert!(err.to_string().contains("unknown map"), "{err}");

    // The same connection keeps serving: conntrack still answers (empty table when
    // the proc file is unreadable as a test user) — proving the stream survives a
    // run of error responses without desync.
    let table = client.conntrack_dump().expect("conntrack dump");
    let _ = table;

    drop(guard);
}
