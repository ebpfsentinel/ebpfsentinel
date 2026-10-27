#![allow(clippy::unwrap_used)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use ebpfsentinel_warden::prepare_state_dir;

fn own_uid() -> u32 {
    std::fs::metadata("/proc/self").unwrap().uid()
}

#[test]
fn a_missing_state_directory_is_created_closed_and_owned() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("k8s/kube-system/edge");
    prepare_state_dir(&state, own_uid()).unwrap();
    let metadata = std::fs::metadata(&state).unwrap();
    assert!(metadata.is_dir());
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
    assert_eq!(metadata.uid(), own_uid());
    assert_eq!(metadata.gid(), own_uid());
}

#[test]
fn an_existing_state_directory_keeps_what_the_agent_wrote() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    std::fs::create_dir(&state).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(state.join("installation"), "3f8a1c9d").unwrap();
    prepare_state_dir(&state, own_uid()).unwrap();
    prepare_state_dir(&state, own_uid()).unwrap();
    assert_eq!(
        std::fs::metadata(&state).unwrap().permissions().mode() & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::read_to_string(state.join("installation")).unwrap(),
        "3f8a1c9d"
    );
}
