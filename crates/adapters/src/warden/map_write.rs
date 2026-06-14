//! `EbpfMapWritePort` backed by the warden control plane.
//!
//! In the rootless (warden-client) deployment the agent loads no eBPF and holds
//! no map fds, so it cannot write the threat-intel maps directly. It instead asks
//! the warden — which loaded the programs and holds the maps — to perform the
//! element write over the typed protocol. The key/value bytes are built to be
//! byte-identical to what the in-process [`super::super::ebpf::EbpfMapWriteAdapter`]
//! writes through aya, so the eBPF program reads them the same way.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;

use domain::common::error::DomainError;
use ebpf_common::threatintel::THREATINTEL_ACTION_DROP;
use ebpfsentinel_warden_client::ReconnectingClient;
use ports::secondary::ebpf_map_write_port::{EbpfMapWritePort, IocMetadata};
use tracing::{debug, warn};

/// Pinned/ELF names of the threat-intel IOC hash maps the warden serves.
const THREATINTEL_IOCS_V4: &str = "THREATINTEL_IOCS";
const THREATINTEL_IOCS_V6: &str = "THREATINTEL_IOCS_V6";

/// `EbpfMapWritePort` that proxies threat-intel map writes to the warden.
pub struct WardenMapWriteAdapter {
    client: Mutex<ReconnectingClient>,
}

impl WardenMapWriteAdapter {
    /// Build an adapter talking to the warden at `sock`.
    #[must_use]
    pub fn new(sock: PathBuf) -> Self {
        Self {
            client: Mutex::new(ReconnectingClient::new(sock)),
        }
    }

    /// Run `op` against the locked client, mapping a poisoned lock to a domain error.
    fn with_client<T>(
        &self,
        op: impl FnOnce(&mut ReconnectingClient) -> std::io::Result<T>,
    ) -> Result<T, DomainError> {
        let mut client = self
            .client
            .lock()
            .map_err(|_| DomainError::EngineError("warden client lock poisoned".into()))?;
        op(&mut client)
            .map_err(|e| DomainError::EngineError(format!("warden map write failed: {e}")))
    }
}

/// The 4-byte threat-intel map value (`ThreatIntelValue`: `action`, `feed_id`,
/// `confidence`, `threat_type`), matching the `#[repr(C)]` layout aya writes.
fn threatintel_value(confidence: u8) -> [u8; 4] {
    [THREATINTEL_ACTION_DROP, 0, confidence, 0]
}

/// The IPv6 map key bytes (`ThreatIntelKeyV6`: four native-endian `u32` words, in
/// the same order the in-process adapter builds them from the address octets).
fn v6_key_bytes(v6: std::net::Ipv6Addr) -> [u8; 16] {
    let o = v6.octets();
    let mut key = [0u8; 16];
    for (word, chunk) in o.chunks_exact(4).enumerate() {
        let w = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        key[word * 4..word * 4 + 4].copy_from_slice(&w.to_ne_bytes());
    }
    key
}

impl EbpfMapWritePort for WardenMapWriteAdapter {
    fn inject_threatintel_ip(&self, ip: IpAddr, metadata: &IocMetadata) -> Result<(), DomainError> {
        let value = threatintel_value(metadata.confidence);
        match ip {
            IpAddr::V4(v4) => self.with_client(|c| {
                c.map_update(THREATINTEL_IOCS_V4, &u32::from(v4).to_ne_bytes(), &value, 0)
            }),
            IpAddr::V6(v6) => {
                // The v6 map is optional; a "not pinned" warden error means v6 is
                // disabled, so degrade to a warn rather than failing the inject.
                if let Err(e) = self.with_client(|c| {
                    c.map_update(THREATINTEL_IOCS_V6, &v6_key_bytes(v6), &value, 0)
                }) {
                    warn!(ip = %ip, error = %e, "warden v6 threatintel inject skipped");
                }
                Ok(())
            }
        }
    }

    fn remove_threatintel_ip(&self, ip: IpAddr) -> Result<(), DomainError> {
        match ip {
            IpAddr::V4(v4) => self
                .with_client(|c| c.map_delete(THREATINTEL_IOCS_V4, &u32::from(v4).to_ne_bytes())),
            IpAddr::V6(v6) => {
                if let Err(e) =
                    self.with_client(|c| c.map_delete(THREATINTEL_IOCS_V6, &v6_key_bytes(v6)))
                {
                    debug!(ip = %ip, error = %e, "warden v6 threatintel remove skipped");
                }
                Ok(())
            }
        }
    }

    fn inject_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError> {
        // The firewall uses Array maps with an atomic bulk-load protocol, not
        // single-IP element writes — a no-op here, mirroring the in-process adapter.
        warn!(ip = %ip, "inject_firewall_drop is a no-op: firewall uses Array maps");
        Ok(())
    }

    fn remove_firewall_drop(&self, ip: IpAddr) -> Result<(), DomainError> {
        warn!(ip = %ip, "remove_firewall_drop is a no-op: firewall uses Array maps");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{threatintel_value, v6_key_bytes};

    #[test]
    fn value_bytes_match_repr_c_layout() {
        // action=DROP(1), feed_id=0, confidence, threat_type=0.
        assert_eq!(threatintel_value(90), [1, 0, 90, 0]);
    }

    #[test]
    fn v6_key_is_sixteen_native_endian_words() {
        let v6 = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        let key = v6_key_bytes(v6);
        // Four words: 0x20010db8, 0, 0, 1 — each stored native-endian, matching
        // ThreatIntelKeyV6 { ip: [u32; 4] } as aya serializes it.
        let mut expected = [0u8; 16];
        expected[0..4].copy_from_slice(&0x2001_0db8u32.to_ne_bytes());
        expected[12..16].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(key, expected);
    }
}
