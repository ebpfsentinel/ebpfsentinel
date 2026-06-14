//! `GetRingbufFd` over the real `warden serve` binary: assert that asking for a
//! map that is not a pinned ring buffer is refused with a typed error and that no
//! descriptor is handed back.
//!
//! The happy path (a real `BPF_MAP_TYPE_RINGBUF` pinned, passed, and drained)
//! needs `CAP_SYS_ADMIN` to create the map and is covered in the VM bats lane.

use std::process::{Child, Command as Proc, Stdio};

use ebpfsentinel_warden_client::WardenClient;

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

#[test]
fn ringbuf_fd_for_non_ringbuf_is_refused() {
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

    let err = client
        .get_ringbuf_fd("EVENTS")
        .expect_err("unknown ring buffer must be refused");
    assert!(err.to_string().contains("ring-buffer map"), "{err}");

    // The stream stays usable after a refusal (no stray sentinel byte / fd was
    // sent), so a following control call still answers.
    let _ = client.conntrack_dump().expect("conntrack still works");

    drop(guard);
}
