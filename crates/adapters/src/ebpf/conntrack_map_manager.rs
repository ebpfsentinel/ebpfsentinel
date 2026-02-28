use std::net::{Ipv4Addr, Ipv6Addr};

use aya::Ebpf;
use aya::maps::{Array, HashMap, MapData};
use domain::common::error::DomainError;
use domain::conntrack::entity::{ConnTrackSettings, Connection, ConnectionState};
use ebpf_common::conntrack::{ConnKey, ConnKeyV6, ConnTrackConfig, ConnValue, ConnValueV6};
use ports::secondary::conntrack_map_port::ConnTrackMapPort;
use tracing::info;

/// Manages the eBPF conntrack maps.
///
/// Uses 3 maps:
/// - `CT_TABLE_V4`: `HashMap<ConnKey, ConnValue>` (IPv4 connections)
/// - `CT_TABLE_V6`: `HashMap<ConnKeyV6, ConnValueV6>` (IPv6 connections)
/// - `CT_CONFIG`: `Array<ConnTrackConfig>` (single element: global config)
pub struct ConnTrackMapManager {
    table_v4: HashMap<MapData, ConnKey, ConnValue>,
    table_v6: HashMap<MapData, ConnKeyV6, ConnValueV6>,
    config: Array<MapData, ConnTrackConfig>,
}

impl ConnTrackMapManager {
    /// Create a new `ConnTrackMapManager` by taking ownership of the
    /// conntrack maps from the loaded eBPF program.
    pub fn new(ebpf: &mut Ebpf) -> Result<Self, anyhow::Error> {
        let table_v4 = HashMap::try_from(
            ebpf.take_map("CT_TABLE_V4")
                .ok_or_else(|| anyhow::anyhow!("map 'CT_TABLE_V4' not found"))?,
        )?;
        let table_v6 = HashMap::try_from(
            ebpf.take_map("CT_TABLE_V6")
                .ok_or_else(|| anyhow::anyhow!("map 'CT_TABLE_V6' not found"))?,
        )?;
        let config = Array::try_from(
            ebpf.take_map("CT_CONFIG")
                .ok_or_else(|| anyhow::anyhow!("map 'CT_CONFIG' not found"))?,
        )?;

        info!("conntrack maps acquired (CT_TABLE_V4, CT_TABLE_V6, CT_CONFIG)");
        Ok(Self {
            table_v4,
            table_v6,
            config,
        })
    }
}

impl ConnTrackMapPort for ConnTrackMapManager {
    fn get_connections(&self, limit: usize) -> Result<Vec<Connection>, DomainError> {
        let mut conns = Vec::new();

        // Iterate V4
        for item in self.table_v4.iter() {
            if conns.len() >= limit {
                break;
            }
            if let Ok((key, val)) = item {
                conns.push(conn_from_v4(&key, &val));
            }
        }

        // Iterate V6
        for item in self.table_v6.iter() {
            if conns.len() >= limit {
                break;
            }
            if let Ok((key, val)) = item {
                conns.push(conn_from_v6(&key, &val));
            }
        }

        Ok(conns)
    }

    fn flush_all(&mut self) -> Result<u64, DomainError> {
        let mut count: u64 = 0;

        // Collect V4 keys and remove
        let v4_keys: Vec<ConnKey> = self.table_v4.keys().filter_map(Result::ok).collect();
        for key in &v4_keys {
            if self.table_v4.remove(key).is_ok() {
                count += 1;
            }
        }

        // Collect V6 keys and remove
        let v6_keys: Vec<ConnKeyV6> = self.table_v6.keys().filter_map(Result::ok).collect();
        for key in &v6_keys {
            if self.table_v6.remove(key).is_ok() {
                count += 1;
            }
        }

        info!(count, "conntrack table flushed");
        Ok(count)
    }

    fn set_config(&mut self, settings: &ConnTrackSettings) -> Result<(), DomainError> {
        let cfg = settings.to_ebpf_config();
        self.config
            .set(0, cfg, 0)
            .map_err(|e| DomainError::EngineError(format!("set CT_CONFIG failed: {e}")))?;
        info!(
            enabled = settings.enabled,
            "conntrack config synced to eBPF"
        );
        Ok(())
    }

    fn connection_count(&self) -> Result<u64, DomainError> {
        let v4_count = self.table_v4.keys().filter_map(Result::ok).count();
        let v6_count = self.table_v6.keys().filter_map(Result::ok).count();
        Ok((v4_count + v6_count) as u64)
    }
}

fn conn_from_v4(key: &ConnKey, val: &ConnValue) -> Connection {
    let src_ip = Ipv4Addr::from(key.src_ip.to_be()).to_string();
    let dst_ip = Ipv4Addr::from(key.dst_ip.to_be()).to_string();
    Connection {
        src_ip,
        dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        protocol: key.protocol,
        state: ConnectionState::from_u8(val.state),
        packets_fwd: val.packets_fwd,
        packets_rev: val.packets_rev,
        bytes_fwd: val.bytes_fwd,
        bytes_rev: val.bytes_rev,
        first_seen_ns: val.first_seen_ns,
        last_seen_ns: val.last_seen_ns,
    }
}

fn u32x4_to_ipv6_bytes(words: &[u32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, w) in words.iter().enumerate() {
        let b = w.to_be_bytes();
        bytes[i * 4..i * 4 + 4].copy_from_slice(&b);
    }
    bytes
}

fn conn_from_v6(key: &ConnKeyV6, val: &ConnValueV6) -> Connection {
    let src_ip = Ipv6Addr::from(u32x4_to_ipv6_bytes(&key.src_addr)).to_string();
    let dst_ip = Ipv6Addr::from(u32x4_to_ipv6_bytes(&key.dst_addr)).to_string();
    Connection {
        src_ip,
        dst_ip,
        src_port: key.src_port,
        dst_port: key.dst_port,
        protocol: key.protocol,
        state: ConnectionState::from_u8(val.state),
        packets_fwd: val.packets_fwd,
        packets_rev: val.packets_rev,
        bytes_fwd: val.bytes_fwd,
        bytes_rev: val.bytes_rev,
        first_seen_ns: val.first_seen_ns,
        last_seen_ns: val.last_seen_ns,
    }
}
