//! The `ebpfsentinel-token-launch` binary: the privileged single-container /
//! systemd launcher (all-in-one, broker-serve and broker-connect modes). It is a
//! thin wrapper over the shared `ebpfsentinel-warden` library, which also backs
//! the `warden` control-plane binary.

fn main() -> std::process::ExitCode {
    ebpfsentinel_warden::run()
}
