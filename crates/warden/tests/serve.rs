//! End-to-end test of `warden serve`: spawn the real binary, complete the
//! protocol handshake over the `AF_UNIX` socket, and assert the peer-credential
//! and protocol-version gates reject mismatched clients.

use std::io::ErrorKind;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command as Proc, Stdio};
use std::thread::sleep;
use std::time::Duration;

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

/// Spawn `warden serve <sock> --uid <uid>` and return the child handle.
fn spawn_warden(sock: &str, uid: u32) -> Child {
    Proc::new(env!("CARGO_BIN_EXE_warden"))
        .args(["serve", sock, "--uid", &uid.to_string()])
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn warden")
}

/// Connect to the warden socket, retrying until it is bound (or timing out).
fn connect(sock: &str) -> UnixStream {
    for _ in 0..200 {
        if let Ok(s) = UnixStream::connect(sock) {
            return s;
        }
        sleep(Duration::from_millis(10));
    }
    panic!("warden socket {sock} never came up");
}

fn sock_path(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("warden-it-{}-{tag}.sock", std::process::id()))
        .to_string_lossy()
        .into_owned()
}

/// A child that is killed and whose socket is removed when the guard drops, so a
/// panicking assertion never leaks the warden process.
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

fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it only reads the caller's real uid.
    unsafe { libc::getuid() }
}

#[test]
fn handshake_then_conntrack_and_unimplemented() {
    let sock = sock_path("ok");
    let guard = Guard {
        child: spawn_warden(&sock, current_uid()),
        sock: sock.clone(),
    };
    let mut s = connect(&sock);

    write_frame(
        &mut s,
        &Command::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .unwrap();
    let resp: Response = read_frame(&mut s).unwrap();
    assert_eq!(
        resp,
        Response::HelloOk {
            version: PROTOCOL_VERSION
        }
    );

    // ConntrackDump is wired: a Conntrack reply (table may be empty when the proc
    // file is unreadable as a test user) — never an error.
    write_frame(&mut s, &Command::ConntrackDump).unwrap();
    let resp: Response = read_frame(&mut s).unwrap();
    assert!(matches!(resp, Response::Conntrack { .. }), "got {resp:?}");

    // A command not wired in `warden serve` (attach/detach ride the in-process
    // loader, not this map-serving socket) returns the typed Unimplemented.
    write_frame(
        &mut s,
        &Command::Detach {
            program: "tc-ids".into(),
            iface: "eth0".into(),
        },
    )
    .unwrap();
    let resp: Response = read_frame(&mut s).unwrap();
    assert_eq!(resp, Response::Unimplemented);

    drop(guard);
}

#[test]
fn version_mismatch_is_rejected() {
    let sock = sock_path("ver");
    let guard = Guard {
        child: spawn_warden(&sock, current_uid()),
        sock: sock.clone(),
    };
    let mut s = connect(&sock);

    write_frame(&mut s, &Command::Hello { version: 0xFFFF }).unwrap();
    let resp: Response = read_frame(&mut s).unwrap();
    match resp {
        Response::Error { message } => assert!(message.contains("version mismatch"), "{message}"),
        other => panic!("expected version-mismatch error, got {other:?}"),
    }
    drop(guard);
}

#[test]
fn wrong_peer_uid_is_rejected() {
    // Serve for an impossible peer uid so our connection's real uid never matches;
    // the warden must drop the connection without answering the handshake.
    let serve_uid = current_uid().wrapping_add(1);
    let sock = sock_path("uid");
    let guard = Guard {
        child: spawn_warden(&sock, serve_uid),
        sock: sock.clone(),
    };
    let mut s = connect(&sock);

    let _ = write_frame(
        &mut s,
        &Command::Hello {
            version: PROTOCOL_VERSION,
        },
    );
    // The warden closed the connection after the peer-cred check; the read sees
    // EOF (UnexpectedEof) rather than a framed response.
    let err = read_frame::<_, Response>(&mut s).expect_err("expected closed connection");
    assert!(
        matches!(
            err.kind(),
            ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset
        ),
        "unexpected error kind: {err:?}"
    );
    drop(guard);
}
