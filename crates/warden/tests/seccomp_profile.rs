#![allow(clippy::unwrap_used)]
use std::os::unix::fs::PermissionsExt;

use ebpfsentinel_warden::{AGENT_SECCOMP_PROFILE_FILE, ProfileInstall, install_seccomp_profile};

const PROFILE: &[u8] = br#"{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[]}"#;

#[test]
fn a_missing_profile_is_written_world_readable() {
    let root = tempfile::tempdir().unwrap();
    let dir = root.path().join("seccomp/ebpfsentinel");
    assert_eq!(
        install_seccomp_profile(&dir, PROFILE).unwrap(),
        ProfileInstall::Written
    );
    let target = dir.join(AGENT_SECCOMP_PROFILE_FILE);
    assert_eq!(std::fs::read(&target).unwrap(), PROFILE);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        1,
        "no staging file left"
    );
}

#[test]
fn the_same_profile_is_left_alone() {
    let root = tempfile::tempdir().unwrap();
    install_seccomp_profile(root.path(), PROFILE).unwrap();
    assert_eq!(
        install_seccomp_profile(root.path(), PROFILE).unwrap(),
        ProfileInstall::Unchanged
    );
}

#[test]
fn a_profile_that_drifted_is_replaced() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join(AGENT_SECCOMP_PROFILE_FILE);
    std::fs::write(&target, b"{}").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        install_seccomp_profile(root.path(), PROFILE).unwrap(),
        ProfileInstall::Written
    );
    assert_eq!(std::fs::read(&target).unwrap(), PROFILE);
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777,
        0o644
    );
}
