//! The `warden-token` binary: the privileged single-container / systemd
//! all-in-one launcher. It is a thin wrapper over the shared `ebpfsentinel-warden`
//! library, which also backs the `warden` control-plane binary.

fn main() -> std::process::ExitCode {
    ebpfsentinel_warden::run()
}
