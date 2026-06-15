//! `warden serve` handles the `Delegate` bpffs handshake. The happy path needs a real
//! `fsopen("bpf")` fd from a child user namespace and `CAP_SYS_ADMIN`, so it runs
//! in the VM lane; here we drive the protocol with a non-bpffs fd and assert the
//! delegation is refused cleanly — proving the command frame is read, the
//! `SCM_RIGHTS` fd is received (not swallowed by buffering), and a failure is
//! reported as a typed error.

use std::mem;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command as Proc, Stdio};
use std::ptr;

use ebpfsentinel_warden_proto::{Command, PROTOCOL_VERSION, Response, read_frame, write_frame};

fn spawn_warden(sock: &str, uid: u32) -> Child {
    Proc::new(env!("CARGO_BIN_EXE_warden"))
        .args(["serve", sock, "--uid", &uid.to_string()])
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn warden")
}

fn connect(sock: &str) -> UnixStream {
    for _ in 0..200 {
        if let Ok(s) = UnixStream::connect(sock) {
            return s;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("warden socket {sock} never came up");
}

fn current_uid() -> u32 {
    // SAFETY: getuid() only reads the caller's real uid.
    unsafe { libc::getuid() }
}

/// Send one fd alongside a single sentinel byte (the warden's `Delegate` fd wire
/// shape — what the agent launcher does after the `Delegate` frame).
fn send_one_fd(sock: RawFd, fd: RawFd) -> bool {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    let mut cbuf = [0u8; unsafe { libc::CMSG_SPACE(mem::size_of::<RawFd>() as u32) } as usize];
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    msg.msg_control = cbuf.as_mut_ptr().cast();
    msg.msg_controllen = cbuf.len() as _;
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(ptr::from_ref(&msg));
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<RawFd>() as u32) as _;
        ptr::copy_nonoverlapping(
            ptr::from_ref(&fd).cast(),
            libc::CMSG_DATA(cmsg),
            mem::size_of::<RawFd>(),
        );
        libc::sendmsg(sock, ptr::from_ref(&msg), 0) >= 0
    }
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
fn delegate_with_non_bpffs_fd_is_refused() {
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
    let mut s = connect(&sock);

    write_frame(
        &mut s,
        &Command::Hello {
            version: PROTOCOL_VERSION,
        },
    )
    .unwrap();
    assert!(matches!(
        read_frame::<_, Response>(&mut s).unwrap(),
        Response::HelloOk { .. }
    ));

    // A pipe read end stands in for the bpffs fd: delegation must fail on it.
    let mut fds = [0 as RawFd; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let (read_fd, write_fd) = (fds[0], fds[1]);

    write_frame(&mut s, &Command::Delegate).unwrap();
    assert!(send_one_fd(s.as_raw_fd(), read_fd));

    match read_frame::<_, Response>(&mut s).unwrap() {
        Response::Error { message } => assert!(message.contains("delegation"), "{message}"),
        other => panic!("expected delegation error, got {other:?}"),
    }

    unsafe {
        libc::close(read_fd);
        libc::close(write_fd);
    }
    drop(guard);
}
