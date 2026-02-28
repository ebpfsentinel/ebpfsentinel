use serde::{Deserialize, Serialize};

use super::error::ConnTrackError;

/// Domain-level connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    New,
    Established,
    Related,
    Invalid,
    SynSent,
    SynRecv,
    FinWait,
    CloseWait,
    TimeWait,
}

impl ConnectionState {
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => Self::New,
            1 => Self::Established,
            2 => Self::Related,
            4 => Self::SynSent,
            5 => Self::SynRecv,
            6 => Self::FinWait,
            7 => Self::CloseWait,
            8 => Self::TimeWait,
            // 3 = Invalid, and anything else is also Invalid
            _ => Self::Invalid,
        }
    }

    pub fn to_u8(self) -> u8 {
        match self {
            Self::New => 0,
            Self::Established => 1,
            Self::Related => 2,
            Self::Invalid => 3,
            Self::SynSent => 4,
            Self::SynRecv => 5,
            Self::FinWait => 6,
            Self::CloseWait => 7,
            Self::TimeWait => 8,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Established => "established",
            Self::Related => "related",
            Self::Invalid => "invalid",
            Self::SynSent => "syn_sent",
            Self::SynRecv => "syn_recv",
            Self::FinWait => "fin_wait",
            Self::CloseWait => "close_wait",
            Self::TimeWait => "time_wait",
        }
    }
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Domain-level connection entry (userspace view).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub state: ConnectionState,
    pub packets_fwd: u32,
    pub packets_rev: u32,
    pub bytes_fwd: u32,
    pub bytes_rev: u32,
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
}

/// Conntrack configuration (domain-level).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnTrackSettings {
    pub enabled: bool,
    /// TCP ESTABLISHED timeout in seconds.
    pub tcp_established_timeout_secs: u64,
    /// TCP SYN timeout in seconds.
    pub tcp_syn_timeout_secs: u64,
    /// TCP FIN/`TIME_WAIT` timeout in seconds.
    pub tcp_fin_timeout_secs: u64,
    /// UDP timeout in seconds.
    pub udp_timeout_secs: u64,
    /// UDP bidirectional stream timeout in seconds.
    pub udp_stream_timeout_secs: u64,
    /// ICMP timeout in seconds.
    pub icmp_timeout_secs: u64,
    /// Max concurrent connections per source IP (0 = unlimited).
    #[serde(default)]
    pub max_src_states: u32,
    /// Max connection rate per source within the rate window (0 = unlimited).
    #[serde(default)]
    pub max_src_conn_rate: u32,
    /// Rate window duration in seconds (default: 5).
    #[serde(default = "default_rate_window")]
    pub conn_rate_window_secs: u32,
    /// TTL in seconds for overloaded source IPs in the blacklist (default: 3600).
    #[serde(default = "default_overload_ttl")]
    pub overload_ttl_secs: u32,
}

fn default_rate_window() -> u32 {
    5
}

fn default_overload_ttl() -> u32 {
    3600
}

impl Default for ConnTrackSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            tcp_established_timeout_secs: 432_000, // 5 days
            tcp_syn_timeout_secs: 120,
            tcp_fin_timeout_secs: 120,
            udp_timeout_secs: 30,
            udp_stream_timeout_secs: 120,
            icmp_timeout_secs: 30,
            max_src_states: 0,
            max_src_conn_rate: 0,
            conn_rate_window_secs: 5,
            overload_ttl_secs: 3600,
        }
    }
}

impl ConnTrackSettings {
    pub fn validate(&self) -> Result<(), ConnTrackError> {
        if self.tcp_established_timeout_secs == 0 {
            return Err(ConnTrackError::InvalidTimeout {
                field: "tcp_established_timeout_secs",
            });
        }
        if self.tcp_syn_timeout_secs == 0 {
            return Err(ConnTrackError::InvalidTimeout {
                field: "tcp_syn_timeout_secs",
            });
        }
        if self.tcp_fin_timeout_secs == 0 {
            return Err(ConnTrackError::InvalidTimeout {
                field: "tcp_fin_timeout_secs",
            });
        }
        if self.udp_timeout_secs == 0 {
            return Err(ConnTrackError::InvalidTimeout {
                field: "udp_timeout_secs",
            });
        }
        if self.udp_stream_timeout_secs == 0 {
            return Err(ConnTrackError::InvalidTimeout {
                field: "udp_stream_timeout_secs",
            });
        }
        if self.icmp_timeout_secs == 0 {
            return Err(ConnTrackError::InvalidTimeout {
                field: "icmp_timeout_secs",
            });
        }
        Ok(())
    }

    /// Convert to eBPF `ConnTrackConfig` (nanoseconds).
    pub fn to_ebpf_config(&self) -> ebpf_common::conntrack::ConnTrackConfig {
        ebpf_common::conntrack::ConnTrackConfig {
            enabled: u8::from(self.enabled),
            _pad: [0; 3],
            max_src_states: self.max_src_states,
            tcp_established_timeout_ns: self.tcp_established_timeout_secs * 1_000_000_000,
            tcp_syn_timeout_ns: self.tcp_syn_timeout_secs * 1_000_000_000,
            tcp_fin_timeout_ns: self.tcp_fin_timeout_secs * 1_000_000_000,
            udp_timeout_ns: self.udp_timeout_secs * 1_000_000_000,
            udp_stream_timeout_ns: self.udp_stream_timeout_secs * 1_000_000_000,
            icmp_timeout_ns: self.icmp_timeout_secs * 1_000_000_000,
            max_src_conn_rate: self.max_src_conn_rate,
            conn_rate_window_secs: self.conn_rate_window_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_state_roundtrip() {
        for val in 0..=8 {
            let state = ConnectionState::from_u8(val);
            assert_eq!(state.to_u8(), val);
        }
    }

    #[test]
    fn connection_state_unknown_maps_to_invalid() {
        assert_eq!(ConnectionState::from_u8(255), ConnectionState::Invalid);
    }

    #[test]
    fn default_settings_valid() {
        let settings = ConnTrackSettings::default();
        assert!(settings.validate().is_ok());
    }

    #[test]
    fn zero_timeout_rejected() {
        let mut settings = ConnTrackSettings::default();
        settings.tcp_established_timeout_secs = 0;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn to_ebpf_config_conversion() {
        let settings = ConnTrackSettings {
            enabled: true,
            tcp_established_timeout_secs: 100,
            tcp_syn_timeout_secs: 10,
            tcp_fin_timeout_secs: 20,
            udp_timeout_secs: 5,
            udp_stream_timeout_secs: 15,
            icmp_timeout_secs: 3,
            max_src_states: 0,
            max_src_conn_rate: 0,
            conn_rate_window_secs: 5,
            overload_ttl_secs: 3600,
        };
        let cfg = settings.to_ebpf_config();
        assert_eq!(cfg.enabled, 1);
        assert_eq!(cfg.tcp_established_timeout_ns, 100_000_000_000);
        assert_eq!(cfg.tcp_syn_timeout_ns, 10_000_000_000);
        assert_eq!(cfg.udp_timeout_ns, 5_000_000_000);
        assert_eq!(cfg.icmp_timeout_ns, 3_000_000_000);
    }

    #[test]
    fn disabled_config() {
        let settings = ConnTrackSettings {
            enabled: false,
            ..Default::default()
        };
        let cfg = settings.to_ebpf_config();
        assert_eq!(cfg.enabled, 0);
    }

    #[test]
    fn connection_state_display() {
        assert_eq!(format!("{}", ConnectionState::Established), "established");
        assert_eq!(format!("{}", ConnectionState::SynSent), "syn_sent");
    }
}
