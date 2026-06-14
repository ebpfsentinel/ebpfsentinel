//! Adapters backed by the warden control plane, for the rootless (warden-client)
//! deployment where the agent loads no eBPF and proxies kernel operations to the
//! privileged warden over its typed `AF_UNIX` protocol.

pub mod map_write;
