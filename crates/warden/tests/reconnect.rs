//! The `ReconnectingClient` survives a warden restart: a control call made after
//! the serving warden is replaced transparently reconnects and succeeds, and an
//! unreachable warden surfaces a clear error rather than hanging.

use std::process::{Child, Command as Proc, Stdio};
use std::time::{Duration, Instant};

use ebpfsentinel_warden_client::ReconnectingClient;

fn spawn_warden(sock: &str, uid: u32) -> Child {
    Proc::new(env!("CARGO_BIN_EXE_warden"))
        .args(["serve", sock, "--uid", &uid.to_string()])
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn warden")
}

fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it only reads the caller's real uid.
    unsafe { libc::getuid() }
}

/// Poll a conntrack dump until it succeeds (the warden is up + reachable) or the
/// deadline passes.
fn dump_until_ok(client: &mut ReconnectingClient, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if client.conntrack_dump().is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

struct Kill(Child);
impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn reconnects_transparently_after_warden_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir
        .path()
        .join("warden.sock")
        .to_string_lossy()
        .into_owned();

    let mut client = ReconnectingClient::new(&sock);

    // First warden: the client connects on the first call.
    let warden_a = Kill(spawn_warden(&sock, current_uid()));
    assert!(
        dump_until_ok(&mut client, Duration::from_secs(2)),
        "first warden never answered"
    );

    // Kill it; the client is now holding a dead connection.
    drop(warden_a);

    // A replacement warden binds the same socket. The next call must transparently
    // reconnect + retry and ultimately succeed.
    let _warden_b = Kill(spawn_warden(&sock, current_uid()));
    assert!(
        dump_until_ok(&mut client, Duration::from_secs(2)),
        "client did not recover after warden restart"
    );
}

#[test]
fn unreachable_warden_errors_clearly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir
        .path()
        .join("no-warden.sock")
        .to_string_lossy()
        .into_owned();

    let mut client = ReconnectingClient::new(&sock);
    // No warden was ever started: the call fails fast with an error, not a hang.
    assert!(client.conntrack_dump().is_err());
}
