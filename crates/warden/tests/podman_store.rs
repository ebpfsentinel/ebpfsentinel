//! A Podman container's record read over the real `warden serve` binary.
//! A store the test can write is never root's, so the warden refuses it as
//! root's store: what is asserted here is that the request crosses, that a
//! store not owned by its owner and a path that climbs answer `NoStore`
//! rather than an error, and that the connection stays in sync after them.

#![allow(clippy::panic)]

use std::process::{Child, Command as Proc, Stdio};

use ebpfsentinel_warden::policy::{RuntimeFence, WardenPolicy};
use ebpfsentinel_warden_client::{PodmanStoreRead, WardenClient};

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid() is always safe; it only reads the caller's real uid.
    unsafe { libc::getuid() }
}

#[test]
fn a_store_that_is_not_its_owners_answers_no_store_over_the_wire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sock = dir.path().join("warden.sock");
    // The Podman reads are served only to a deployment configured for them,
    // the executable list only to one that keeps a package inventory.
    let policy = dir.path().join("policy.json");
    let allowed = WardenPolicy {
        runtimes: RuntimeFence {
            podman: true,
            podman_rootless: true,
            ..RuntimeFence::default()
        },
        package_inventory: true,
        ..WardenPolicy::default()
    };
    std::fs::write(
        &policy,
        serde_json::to_string(&allowed).expect("encode the policy"),
    )
    .expect("write the policy");
    let _guard = Guard(
        Proc::new(env!("CARGO_BIN_EXE_warden"))
            .args([
                "serve",
                sock.to_str().expect("utf-8 path"),
                "--uid",
                &current_uid().to_string(),
                "--policy",
                policy.to_str().expect("utf-8 path"),
            ])
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn warden"),
    );
    let mut client = (0..200)
        .find_map(|_| {
            WardenClient::connect(&sock).ok().or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(10));
                None
            })
        })
        .expect("warden socket came up");

    let store = dir.path().join("storage");
    std::fs::create_dir_all(&store).expect("store");
    let id = "ab".repeat(32);
    let store = store.to_str().expect("utf-8 path");
    if current_uid() != 0 {
        assert_eq!(
            client.read_podman_record(None, store, &id).expect("answer"),
            PodmanStoreRead::NoStore
        );
    }
    assert_eq!(
        client
            .read_podman_record(Some(current_uid().max(1)), "../../etc", &id)
            .expect("answer"),
        PodmanStoreRead::NoStore
    );
    assert_eq!(
        client
            .read_podman_record(None, "relative", &id)
            .expect("answer"),
        PodmanStoreRead::NoStore
    );
    // Still in step after the refusals.
    assert!(client.go_executables().is_ok());
}
