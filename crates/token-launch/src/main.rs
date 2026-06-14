//! Thin binary wrapper around the `ebpfsentinel-token-launch` library, whose
//! privileged primitives are shared with the `warden` binary.

fn main() -> std::process::ExitCode {
    ebpfsentinel_token_launch::run()
}
